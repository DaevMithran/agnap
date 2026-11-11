/**
 * The executor's request handling, as a Fetch handler:
 *
 *   POST /operations/{operation}
 *   Authorization: GNAP <access token>
 *   Signature-Input, Signature, Content-Digest   (RFC 9421, the agent's key)
 *   { "arguments": { "repository": "acme/docs" } }
 *
 * In order: introspect the token at the grant server; verify the request
 * signature against the key the token is bound to, with a replay check;
 * check the grant covers the operation and its arguments; reserve one call
 * on the root grant's grant state record when the grant ceilings the operation;
 * perform the operation through its connector; settle the reservation.
 * Nothing reaches a connector before every check passes.
 */
import { AGENT_OPERATION, callCeiling, covers } from '@agnap/access-types';
import type { AgentOperationAccess, Scalar } from '@agnap/access-types';
import { gnapAuthorizationValue, HttpSigError, systemClock, verifyRequest } from '@agnap/gnap-core';
import type { AccessItem, Clock, NonceClaim } from '@agnap/gnap-core';
import type {
  Connector,
  ExecutorEvent,
  Introspector,
  OperationCall,
  Settlement,
  GrantStateStore,
} from './types.js';

export interface ExecutorOptions {
  introspector: Introspector;
  connectors: readonly Connector[];
  grantState: GrantStateStore;
  /**
   * Public origin agents sign against, when the executor runs behind a proxy.
   * Defaults to the request's own URL.
   */
  publicUrl?: string;
  clock?: Clock;
  /** Decision log. Never receives tokens, credentials or arguments. */
  log?: (event: ExecutorEvent) => void;
  /** Largest request body accepted, in bytes. Defaults to 64 KiB. */
  maxBodyBytes?: number;
}

export type FetchHandler = (request: Request) => Promise<Response>;

const ROUTE = /^\/operations\/([^/]+)$/;

const isScalar = (value: unknown): value is Scalar =>
  typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';

/** Replay cache for agent request signatures, keyed by key thumbprint and nonce. */
class NonceCache {
  readonly #seen = new Map<string, number>();
  claim(keyThumbprint: string, nonce: string, expiresAt: number, now: number): NonceClaim {
    if (this.#seen.size > 50_000) {
      for (const [k, exp] of this.#seen) if (exp < now) this.#seen.delete(k);
      if (this.#seen.size > 50_000) return 'full';
    }
    const key = `${keyThumbprint}\u0000${nonce}`;
    const existing = this.#seen.get(key);
    if (existing !== undefined && existing >= now) return 'seen';
    this.#seen.set(key, expiresAt + 1000);
    return 'fresh';
  }
}

/**
 * Build the executor's Fetch handler.
 * @param options - introspector, connectors, grant state store and logging.
 * @returns the handler.
 * @throws when two connectors claim the same operation.
 */
export function createExecutor(options: ExecutorOptions): FetchHandler {
  const clock = options.clock ?? systemClock;
  const maxBody = options.maxBodyBytes ?? 64 * 1024;
  const byOperation = new Map<string, Connector>();
  for (const connector of options.connectors) {
    for (const operation of connector.operations) {
      if (byOperation.has(operation)) throw new Error(`two connectors serve ${operation}`);
      byOperation.set(operation, connector);
    }
  }
  const nonces = new NonceCache();
  const log = options.log ?? (() => undefined);

  const refuse = (operation: string, status: number, code: string, reason: string, extra = {}) => {
    log({ kind: 'refused', operation, status, code, reason });
    return Response.json({ error: { code, description: reason, ...extra } }, { status });
  };

  return async function handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const match = ROUTE.exec(url.pathname);
    if (request.method !== 'POST' || match === null) {
      return Response.json({ error: { code: 'not_found' } }, { status: 404 });
    }
    const operation = decodeURIComponent(match[1] as string);

    const bytes = new Uint8Array(await request.arrayBuffer());
    if (bytes.byteLength > maxBody) {
      return refuse(operation, 413, 'invalid_request', `body exceeds ${maxBody} bytes`);
    }
    const call = parseCall(operation, bytes);
    if (call === null) {
      return refuse(
        operation,
        400,
        'invalid_request',
        'body must be {"arguments": {name: scalar}}',
      );
    }
    const connector = byOperation.get(operation);
    if (connector === undefined) {
      return refuse(operation, 404, 'unknown_operation', `no connector serves ${operation}`);
    }

    const token = gnapAuthorizationValue(request.headers.get('authorization'));
    if (token === null)
      return refuse(operation, 401, 'invalid_token', 'GNAP access token required');
    let introspection;
    try {
      introspection = await options.introspector.introspect(token, request.signal);
    } catch (error) {
      return refuse(operation, 503, 'introspection_failed', message(error));
    }
    if (!introspection.active) {
      return refuse(operation, 401, 'invalid_token', 'token is not active');
    }
    if (introspection.key === undefined) {
      return refuse(operation, 401, 'invalid_token', 'token is not bound to a key');
    }

    const target =
      options.publicUrl === undefined
        ? request.url
        : new URL(url.pathname + url.search, options.publicUrl).toString();
    try {
      await verifyRequest(
        { method: request.method, url: target, headers: request.headers, body: bytes },
        {
          publicJwk: introspection.key.jwk,
          clock,
          nonceCheck: ({ keyThumbprint, nonce, expiresAt }) =>
            nonces.claim(keyThumbprint, nonce, expiresAt, clock.now()),
        },
      );
    } catch (error) {
      if (error instanceof HttpSigError) {
        return refuse(operation, 401, 'invalid_signature', error.detail);
      }
      throw error;
    }

    const covering = coveringItem(introspection.access, call);
    if (covering === null) {
      return refuse(operation, 403, 'insufficient_access', 'the grant does not cover this call');
    }

    const rootGrant = introspection.root_grant;
    const ceiling = callCeiling(covering, operation);
    let reservation: string | undefined;
    if (ceiling !== undefined) {
      if (rootGrant === undefined) {
        return refuse(operation, 403, 'insufficient_access', 'a counted call needs root_grant');
      }
      const reserved = await options.grantState.reserve({ rootGrant, operation }, ceiling, 1);
      if (reserved.kind === 'exhausted') {
        return refuse(
          operation,
          403,
          'ceiling_reached',
          `${ceiling} calls allowed, ${reserved.counted} counted`,
          {
            ceiling,
            counted: reserved.counted,
          },
        );
      }
      reservation = reserved.reservation;
    }

    const settle = async (settlement: Settlement) => {
      if (reservation !== undefined) await options.grantState.settle(reservation, settlement);
    };
    let outcome;
    try {
      outcome = await connector.call(call, { rootGrant, signal: request.signal });
    } catch (error) {
      outcome = { kind: 'failed' as const, message: message(error), effect: 'unknown' as const };
    }
    if (outcome.kind === 'done') {
      await settle('used');
      log({ kind: 'performed', operation, rootGrant, counted: reservation !== undefined });
      return Response.json({ result: outcome.result });
    }
    await settle(outcome.effect === 'none' ? 'released' : 'held');
    log({ kind: 'failed', operation, rootGrant, effect: outcome.effect });
    return Response.json(
      { error: { code: 'operation_failed', description: outcome.message, effect: outcome.effect } },
      { status: 502 },
    );
  };
}

function parseCall(operation: string, bytes: Uint8Array): OperationCall | null {
  let body: unknown;
  try {
    body = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
  const args = (body as { arguments?: unknown } | null)?.arguments ?? {};
  if (typeof args !== 'object' || args === null || Array.isArray(args)) return null;
  const entries = Object.entries(args);
  if (!entries.every(([, v]) => isScalar(v))) return null;
  return { operation, arguments: Object.fromEntries(entries) };
}

/** The first agent_operation item that covers the call; its ceilings apply. */
function coveringItem(
  items: readonly AccessItem[],
  call: OperationCall,
): AgentOperationAccess | null {
  for (const item of items) {
    if (item.type !== AGENT_OPERATION) continue;
    const access = item as AgentOperationAccess;
    if (covers(access, call.operation, call.arguments).allow) return access;
  }
  return null;
}

const message = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);
