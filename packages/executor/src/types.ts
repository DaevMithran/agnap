/**
 * The executor's pluggable parts. A deployment chooses a connector per
 * operation, a grant state store, and an introspector for the
 * grant server; the request handling in `executor.ts` is the same for all.
 */
import type { Scalar } from '@agnap/access-types';
import type { IntrospectionResponse } from '@agnap/gnap-core';

export type JsonValue =
  string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

/** One operation the agent asked the executor to perform. */
export interface OperationCall {
  operation: string;
  arguments: Record<string, Scalar>;
}

export interface ConnectorContext {
  /** The root grant the call is counted against. */
  rootGrant: string | undefined;
  signal: AbortSignal;
}

/**
 * What a connector reports. `effect` on a failure says whether the
 * downstream may have acted anyway: `none` releases the reservation,
 * `unknown` keeps it counted until reconciled.
 */
export type ConnectorOutcome =
  | { kind: 'done'; result: JsonValue }
  | { kind: 'failed'; message: string; effect: 'none' | 'unknown' };

/**
 * Performs operations against one downstream service, with credentials only
 * the executor holds. A throw is treated as a failure with unknown effect.
 */
export interface Connector {
  /** Operations this connector serves. Each operation has exactly one connector. */
  readonly operations: readonly string[];
  call(call: OperationCall, context: ConnectorContext): Promise<ConnectorOutcome>;
}

/** One counted ceiling: the calls of one operation under one root grant. */
export interface GrantStateKey {
  rootGrant: string;
  operation: string;
}

export type ReserveOutcome =
  | { kind: 'reserved'; reservation: string }
  | { kind: 'exhausted'; counted: number; ceiling: number };

/**
 * How a reservation ends. `used` counts it; `released` returns it; `held`
 * keeps it counted because the outcome is unknown.
 */
export type Settlement = 'used' | 'released' | 'held';

export interface GrantStateSnapshot {
  /** Calls that completed. */
  used: number;
  /** Calls in flight. */
  pending: number;
  /** Calls whose outcome is unknown; counted until reconciled. */
  held: number;
}

/**
 * The grant state record behind counted ceilings. One record per key; every
 * token and every child of a root grant counts against the same record.
 * `reserve` must be atomic with respect to every other `reserve` on the
 * same key, across all processes that share the store.
 */
export interface GrantStateStore {
  /**
   * Set `amount` aside if `used + pending + held + amount <= ceiling`.
   * @returns the reservation, or `exhausted` with the current count.
   */
  reserve(key: GrantStateKey, ceiling: number, amount: number): Promise<ReserveOutcome>;
  /** End a reservation. Settling an unknown or already settled reservation does nothing. */
  settle(reservation: string, settlement: Settlement): Promise<void>;
  /** The record's current counts; all zero when nothing was reserved yet. */
  snapshot(key: GrantStateKey): Promise<GrantStateSnapshot>;
}

/** Looks a token up at the grant server (RFC 9767). */
export interface Introspector {
  introspect(token: string, signal?: AbortSignal): Promise<IntrospectionResponse>;
}

/** One line of the executor's decision log. Never contains tokens or credentials. */
export type ExecutorEvent =
  | { kind: 'refused'; operation: string; status: number; code: string; reason: string }
  | { kind: 'performed'; operation: string; rootGrant: string | undefined; counted: boolean }
  | {
      kind: 'failed';
      operation: string;
      rootGrant: string | undefined;
      effect: 'none' | 'unknown';
    };
