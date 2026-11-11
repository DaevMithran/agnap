/**
 * Storage, written as the protocol's state transitions rather than CRUD, so a
 * database implementation has the same atomicity to meet as the in-memory one.
 */
import type { AccessItem, Clock, Ed25519PublicJwk, NonceClaim } from '@agnap/gnap-core';
import type { DenyCode, GrantRecord, GrantState, TokenRecord } from './records.js';

export class StoreCapacityError extends Error {
  override readonly name = 'StoreCapacityError';
}

export type ContinuationOutcome =
  | { kind: 'too_fast'; retryAfterSeconds: number }
  | { kind: 'pending'; record: GrantRecord }
  | { kind: 'issued'; token: TokenRecord }
  | { kind: 'denied'; code: DenyCode }
  | { kind: 'invalid' };

export interface ContinuationAdvance {
  /** Hash of the continuation token the client presented. */
  oldHash: string;
  now: number;
  /** New `notBefore` when the grant stays pending. */
  nextNotBefore: number;
  /** Called inside the transition when the grant is approved, to build the token that gets stored. */
  mint: (record: GrantRecord) => TokenRecord;
}

export type Resolution =
  { kind: 'approve'; access: AccessItem[]; audiences: string[] } | { kind: 'deny'; code: DenyCode };

export interface Store {
  /** New grant. When `token` is given the grant is already issued (no owner in the loop). */
  createGrant(record: GrantRecord, token?: TokenRecord): Promise<void>;

  /** Lookup for signature verification. Implementations may lazily remove expired state. */
  getGrantForVerification(id: string): Promise<{
    boundKey: Ed25519PublicJwk;
    state: GrantState;
    continuationHash: string | null;
  } | null>;

  getGrant(id: string): Promise<GrantRecord | null>;
  listGrants(state?: GrantState): Promise<GrantRecord[]>;

  /**
   * One atomic step. `oldHash` mismatch: invalid, nothing changes. Early:
   * too_fast, credential kept. Pending: keep credential and set notBefore.
   * Approved: mint, store the token, clear the credential, state issued.
   * Denied: clear the credential. Issued: invalid.
   */
  advanceContinuation(id: string, advance: ContinuationAdvance): Promise<ContinuationOutcome>;

  /**
   * Pending to approved or denied. Succeeds once. Clears `notBefore`: the
   * client's next continuation is answered at once, because the polling
   * interval only paces requests while nothing has been decided.
   */
  resolvePendingGrant(id: string, resolution: Resolution): Promise<boolean>;

  /** Read-only, for signature verification of a token management request. */
  getTokenForVerification(
    id: string,
  ): Promise<{ boundKey: Ed25519PublicJwk; managementHash: string; revoked: boolean } | null>;

  /** Revoke when `managementHash` matches. False otherwise or when already revoked. */
  revokeToken(id: string, managementHash: string): Promise<boolean>;

  getTokenByAccessHash(hash: string): Promise<TokenRecord | null>;

  /** `fresh` records the nonce atomically. `seen` is a replay. `full` fails closed on capacity. */
  claimNonce(keyThumbprint: string, nonce: string, expiresAt: number): Promise<NonceClaim>;
}

export interface MemoryStoreOptions {
  clock?: Clock;
  /** Live nonces kept at most. When full after sweeping expired ones, new nonces are refused: fail closed. */
  maxNonces?: number;
  /** Live pending/approved grants kept at most. Defaults to 10,000. */
  maxPendingGrants?: number;
}
