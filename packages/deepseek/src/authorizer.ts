import { coversAny } from '@agnap/access-types';
import type { AgentOperationAccess } from '@agnap/access-types';
import type { AccessToken } from '@agnap/gnap-core';
import { GnapHttpError, tokenFingerprint } from './client.js';
import { mapToolCall, ToolProfileError, ToolProfileRegistry } from './profiles.js';
import type {
  ApprovalPort,
  AuthorizationDecision,
  AuthorizeToolInput,
  OwnerDecisionPort,
  SessionClientProvider,
  SessionGrantStore,
  StoredGrant,
  ToolProfile,
} from './types.js';

export class MemorySessionGrantStore implements SessionGrantStore {
  readonly #grants = new Map<string, StoredGrant[]>();
  list(sessionId: string): readonly StoredGrant[] {
    return [...(this.#grants.get(sessionId) ?? [])];
  }
  add(sessionId: string, grant: StoredGrant): void {
    const grants = [...(this.#grants.get(sessionId) ?? [])];
    const existing = grants.findIndex((item) => item.fingerprint === grant.fingerprint);
    if (existing >= 0) grants[existing] = grant;
    else grants.push(grant);
    this.#grants.set(sessionId, grants);
  }
  delete(sessionId: string, fingerprint: string): void {
    const grants = this.#grants.get(sessionId);
    if (grants === undefined) return;
    const remaining = grants.filter((grant) => grant.fingerprint !== fingerprint);
    if (remaining.length === 0) this.#grants.delete(sessionId);
    else this.#grants.set(sessionId, remaining);
  }
  clear(sessionId: string): void {
    this.#grants.delete(sessionId);
  }
}

export interface GnapToolAuthorizerOptions {
  profiles: readonly ToolProfile[];
  clients: SessionClientProvider;
  owner: OwnerDecisionPort;
  grants?: SessionGrantStore;
  sleep?: (milliseconds: number, signal: AbortSignal) => Promise<void>;
  /** Expected AS token lifetime, shown to the owner before approval. */
  tokenTtlSeconds?: number;
  /** Bounds malformed or perpetually pending servers. Defaults to 20 polls. */
  maxContinuationAttempts?: number;
}

const defaultSleep = (milliseconds: number, signal: AbortSignal): Promise<void> =>
  new Promise((resolve, reject) => {
    const aborted = () =>
      signal.reason instanceof Error
        ? signal.reason
        : new Error('authorization was aborted', { cause: signal.reason });
    if (signal.aborted) return reject(aborted());
    const onAbort = () => {
      clearTimeout(timer);
      reject(aborted());
    };
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, milliseconds);
    signal.addEventListener('abort', onAbort, { once: true });
  });

const grantIdFrom = (uri: string): string => {
  const parts = new URL(uri).pathname.split('/').filter(Boolean);
  const id = parts.at(-1);
  if (id === undefined) throw new Error('continuation URI has no grant id');
  return id;
};

const describeScope = (access: AgentOperationAccess, operation: string): string => {
  const constraints = access.operations[operation] ?? {};
  const argumentsDescription = Object.entries(constraints)
    .map(([name, constraint]) =>
      'wildcard' in constraint ? `${name} = any` : `${name} = ${JSON.stringify(constraint.exact)}`,
    )
    .join(', ');
  return argumentsDescription.length === 0 ? operation : `${operation} (${argumentsDescription})`;
};

export class GnapToolAuthorizer {
  readonly #profiles: ToolProfileRegistry;
  readonly #clients: SessionClientProvider;
  readonly #owner: OwnerDecisionPort;
  readonly #grants: SessionGrantStore;
  readonly #sleep: (milliseconds: number, signal: AbortSignal) => Promise<void>;
  readonly #tokenTtlSeconds: number;
  readonly #maxContinuationAttempts: number;
  readonly #tails = new Map<string, Promise<void>>();

  constructor(options: GnapToolAuthorizerOptions) {
    this.#profiles = new ToolProfileRegistry(options.profiles);
    this.#clients = options.clients;
    this.#owner = options.owner;
    this.#grants = options.grants ?? new MemorySessionGrantStore();
    this.#sleep = options.sleep ?? defaultSleep;
    this.#tokenTtlSeconds = options.tokenTtlSeconds ?? 600;
    this.#maxContinuationAttempts = options.maxContinuationAttempts ?? 20;
    if (!Number.isInteger(this.#tokenTtlSeconds) || this.#tokenTtlSeconds <= 0) {
      throw new RangeError('tokenTtlSeconds must be a positive integer');
    }
    if (!Number.isInteger(this.#maxContinuationAttempts) || this.#maxContinuationAttempts <= 0) {
      throw new RangeError('maxContinuationAttempts must be a positive integer');
    }
  }

  async authorize(
    input: AuthorizeToolInput,
    approval: ApprovalPort,
  ): Promise<AuthorizationDecision> {
    try {
      return await this.#serialized(input.sessionId, () => this.#authorize(input, approval));
    } catch (error) {
      if (input.signal.aborted) return { kind: 'cancel' };
      throw error;
    }
  }

  async revoke(sessionId: string, signal?: AbortSignal): Promise<void> {
    return this.#serialized(sessionId, () => this.#revoke(sessionId, signal));
  }

  async #revoke(sessionId: string, signal?: AbortSignal): Promise<void> {
    const stored = this.#grants.list(sessionId);
    if (stored.length === 0) {
      this.#grants.clear(sessionId);
      return;
    }
    const client = this.#clients.get(sessionId);
    const failures: unknown[] = [];
    for (const grant of stored) {
      try {
        await client.revoke(grant.token, signal);
      } catch (error) {
        failures.push(error);
      }
    }
    this.#grants.clear(sessionId);
    if (failures.length > 0)
      throw new AggregateError(failures, 'one or more GNAP grants failed to revoke');
  }

  /** Host lifecycle hook: revoke every live grant before discarding session state. */
  disposeSession(sessionId: string, signal?: AbortSignal): Promise<void> {
    return this.revoke(sessionId, signal);
  }

  async #authorize(
    input: AuthorizeToolInput,
    approval: ApprovalPort,
  ): Promise<AuthorizationDecision> {
    const profile = this.#profiles.get(input.toolName);
    if (profile === null) return { kind: 'unprofiled' };

    let call;
    try {
      call = mapToolCall(profile, input.arguments);
    } catch (error) {
      return {
        kind: 'deny',
        reason: error instanceof ToolProfileError ? error.message : 'tool arguments are invalid',
      };
    }

    const client = this.#clients.get(input.sessionId);
    for (const existing of this.#grants.list(input.sessionId)) {
      const localDecision = coversAny(existing.token.access, call.operation, call.arguments);
      if (!localDecision.allow) continue;
      const introspection = await client.introspect(
        existing.token.value,
        [call.requiredAccess],
        input.signal,
      );
      if (!introspection.active) {
        this.#grants.delete(input.sessionId, existing.fingerprint);
      } else {
        const decision = coversAny(introspection.access, call.operation, call.arguments);
        if (decision.allow) return { kind: 'allow', fingerprint: existing.fingerprint };
      }
    }

    const pending = await client.requestGrant([call.access], input.signal);
    if (pending.access_token !== undefined) {
      return this.#acceptIssued(input.sessionId, pending.access_token);
    }
    if (pending.continue === undefined)
      return { kind: 'deny', reason: 'grant response is incomplete' };

    const grantId = grantIdFrom(pending.continue.uri);
    let issuedSuccessfully = false;
    try {
      const reason = `Request scope ${describeScope(call.access, call.operation)}; current call ${JSON.stringify(call.arguments)}; token expires in up to ${this.#tokenTtlSeconds} seconds`;
      const outcome = await approval.request({
        sessionId: input.sessionId,
        agent: input.agent,
        toolName: input.toolName,
        ...(input.callId !== undefined ? { callId: input.callId } : {}),
        reason,
        signal: input.signal,
      });
      if (outcome !== 'allowed-once') {
        if (outcome === 'cancelled') return { kind: 'cancel' };
        return { kind: 'deny', reason: `grant ${outcome}` };
      }

      await this.#owner.resolve(grantId, 'approve', input.signal);
      let continuation = pending.continue;
      let waitSeconds = continuation.wait ?? 0;
      let token: AccessToken | undefined;
      for (let attempt = 0; attempt < this.#maxContinuationAttempts; attempt += 1) {
        const waitMilliseconds = waitSeconds * 1000;
        if (waitMilliseconds > 0) await this.#sleep(waitMilliseconds, input.signal);
        waitSeconds = 0;
        try {
          const response = await client.continueGrant(
            continuation.uri,
            continuation.access_token.value,
            input.signal,
          );
          if (response.access_token !== undefined) {
            token = response.access_token;
            break;
          }
          if (response.continue === undefined) {
            return { kind: 'deny', reason: 'approved grant response is incomplete' };
          }
          continuation = response.continue;
          waitSeconds = continuation.wait ?? 0;
        } catch (error) {
          if (!(error instanceof GnapHttpError) || error.code !== 'too_fast') throw error;
          waitSeconds = error.retryAfterSeconds ?? continuation.wait ?? 1;
        }
      }
      if (token === undefined) {
        return { kind: 'deny', reason: 'approved grant did not issue an access token' };
      }
      const decision = this.#acceptIssued(input.sessionId, token);
      issuedSuccessfully = true;
      return decision;
    } finally {
      if (!issuedSuccessfully && !input.signal.aborted) {
        // Best effort. An approved grant no longer accepts a deny transition,
        // so the server's grant expiry remains the final cleanup bound.
        await this.#owner.resolve(grantId, 'deny', input.signal).catch(() => undefined);
      }
    }
  }

  #acceptIssued(sessionId: string, token: AccessToken) {
    const fingerprint = tokenFingerprint(token.value);
    this.#grants.add(sessionId, { token, fingerprint });
    return { kind: 'allow' as const, fingerprint };
  }

  async #serialized<T>(sessionId: string, work: () => Promise<T>): Promise<T> {
    const previous = this.#tails.get(sessionId) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    const queued = previous.then(() => current);
    this.#tails.set(sessionId, queued);
    await previous;
    try {
      return await work();
    } finally {
      release();
      if (this.#tails.get(sessionId) === queued) this.#tails.delete(sessionId);
    }
  }
}
