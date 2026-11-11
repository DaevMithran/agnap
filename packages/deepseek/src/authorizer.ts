import { coversAny } from '@agnap/access-types';
import type { AgentOperationAccess, Scalar } from '@agnap/access-types';
import type { AccessToken, GrantResponse, Signer } from '@agnap/gnap-core';
import { GnapHttpError, tokenFingerprint } from './client.js';
import { mapToolCall, ToolProfileError, ToolProfileRegistry } from './profiles.js';
import type {
  ApprovalPort,
  AuthorizationDecision,
  AuthorizeToolInput,
  GrantClient,
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
  sessionIds(): readonly string[] {
    return [...this.#grants.keys()];
  }
}

export interface GnapToolAuthorizerOptions {
  profiles: readonly ToolProfile[];
  clients: SessionClientProvider;
  /**
   * Programmatic owner, for hosts that collect the decision through the
   * Harness approval prompt. Omit it in deployments: the owner then decides
   * in a separate process (`agnap-owner`) and the authorizer only waits for
   * the server's answer, so nothing in the agent's process can approve.
   */
  owner?: OwnerDecisionPort;
  /** How long a call waits for an external owner's decision. Defaults to 300. */
  ownerWaitSeconds?: number;
  grants?: SessionGrantStore;
  sleep?: (milliseconds: number, signal: AbortSignal) => Promise<void>;
  /** Expected AS token lifetime, shown to the owner before approval. */
  tokenTtlSeconds?: number;
  /** Bounds malformed or perpetually pending servers. Defaults to 20 polls. */
  maxContinuationAttempts?: number;
  /**
   * Introspect a stored grant before reusing it, to notice revocation.
   * Defaults to true. Set it to false when an executor performs the calls:
   * the executor introspects every call, and the plugin then needs no
   * resource-server key.
   */
  introspect?: boolean;
}

/** The stored grant that covers one tool call, and the call as the executor sees it. */
export interface CoveredCall {
  token: AccessToken;
  /** The session's client key, which the token is bound to. */
  signer: Signer;
  fingerprint: string;
  operation: string;
  arguments: Record<string, Scalar>;
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
  readonly #owner: OwnerDecisionPort | undefined;
  readonly #ownerWaitSeconds: number;
  readonly #grants: SessionGrantStore;
  readonly #sleep: (milliseconds: number, signal: AbortSignal) => Promise<void>;
  readonly #tokenTtlSeconds: number;
  readonly #maxContinuationAttempts: number;
  readonly #introspect: boolean;
  readonly #tails = new Map<string, Promise<void>>();

  constructor(options: GnapToolAuthorizerOptions) {
    this.#profiles = new ToolProfileRegistry(options.profiles);
    this.#clients = options.clients;
    this.#owner = options.owner;
    this.#grants = options.grants ?? new MemorySessionGrantStore();
    this.#sleep = options.sleep ?? defaultSleep;
    this.#tokenTtlSeconds = options.tokenTtlSeconds ?? 600;
    this.#maxContinuationAttempts = options.maxContinuationAttempts ?? 20;
    this.#ownerWaitSeconds = options.ownerWaitSeconds ?? 300;
    this.#introspect = options.introspect ?? true;
    if (!Number.isInteger(this.#ownerWaitSeconds) || this.#ownerWaitSeconds <= 0) {
      throw new RangeError('ownerWaitSeconds must be a positive integer');
    }
    if (!Number.isInteger(this.#tokenTtlSeconds) || this.#tokenTtlSeconds <= 0) {
      throw new RangeError('tokenTtlSeconds must be a positive integer');
    }
    if (!Number.isInteger(this.#maxContinuationAttempts) || this.#maxContinuationAttempts <= 0) {
      throw new RangeError('maxContinuationAttempts must be a positive integer');
    }
  }

  /**
   * Decide one tool call. `approval` is used only with a programmatic owner;
   * with an external owner it may be omitted.
   */
  async authorize(
    input: AuthorizeToolInput,
    approval?: ApprovalPort,
  ): Promise<AuthorizationDecision> {
    try {
      return await this.#serialized(input.sessionId, () => this.#authorize(input, approval));
    } catch (error) {
      if (input.signal.aborted) return { kind: 'cancel' };
      throw error;
    }
  }

  /**
   * Find the stored grant that covers a tool call, after `authorize` allowed
   * it. Only the grant's own access is consulted; the executor checks it
   * again with the grant server.
   * @returns the grant and the mapped call, `null` when no stored grant
   * covers it, or `unprofiled`.
   */
  coveredCall(
    sessionId: string,
    toolName: string,
    args: unknown,
  ): CoveredCall | null | 'unprofiled' {
    const profile = this.#profiles.get(toolName);
    if (profile === null) return 'unprofiled';
    let call;
    try {
      call = mapToolCall(profile, args);
    } catch {
      return null;
    }
    for (const existing of this.#grants.list(sessionId)) {
      if (coversAny(existing.token.access, call.operation, call.arguments).allow) {
        return {
          token: existing.token,
          signer: this.#clients.get(sessionId).clientSigner,
          fingerprint: existing.fingerprint,
          operation: call.operation,
          arguments: call.arguments,
        };
      }
    }
    return null;
  }

  /** Drop a stored grant the executor reported as no longer active. */
  forget(sessionId: string, fingerprint: string): void {
    this.#grants.delete(sessionId, fingerprint);
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

  /**
   * Revoke the grants of every session, for plugin unload. Every session is
   * attempted even when some fail; the failures are thrown together.
   */
  async revokeAll(signal?: AbortSignal): Promise<void> {
    const results = await Promise.allSettled(
      this.#grants.sessionIds().map((sessionId) => this.revoke(sessionId, signal)),
    );
    const failures = results.flatMap((result): unknown[] =>
      result.status === 'rejected' ? [result.reason] : [],
    );
    if (failures.length > 0)
      throw new AggregateError(failures, 'one or more sessions failed to revoke');
  }

  async #authorize(
    input: AuthorizeToolInput,
    approval: ApprovalPort | undefined,
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
      if (!this.#introspect) return { kind: 'allow', fingerprint: existing.fingerprint };
      // Coverage is checked here, not by the server: a requested access
      // without the grant's ceilings is not contained in it.
      const introspection = await client.introspect(existing.token.value, undefined, input.signal);
      if (!introspection.active) {
        this.#grants.delete(input.sessionId, existing.fingerprint);
      } else {
        const decision = coversAny(introspection.access, call.operation, call.arguments);
        if (decision.allow) return { kind: 'allow', fingerprint: existing.fingerprint };
      }
    }

    const pending = await client.requestGrant(
      [call.access],
      input.signal,
      input.agentLabel !== undefined ? { name: input.agentLabel } : undefined,
    );
    if (pending.access_token !== undefined) {
      return this.#acceptIssued(input.sessionId, pending.access_token);
    }
    if (pending.continue === undefined)
      return { kind: 'deny', reason: 'grant response is incomplete' };

    if (this.#owner === undefined) {
      // The owner decides in their own channel (agnap-owner); wait for the server's answer.
      const outcome = await this.#continueUntilDecided(client, pending.continue, input.signal, {
        firstWaitSeconds: pending.continue.wait ?? 0,
        deadline: Date.now() + this.#ownerWaitSeconds * 1000,
        maxAttempts: Number.POSITIVE_INFINITY,
      });
      if (outcome.kind === 'token') return this.#acceptIssued(input.sessionId, outcome.token);
      if (outcome.kind === 'timeout') {
        return {
          kind: 'deny',
          reason: `the owner did not decide within ${this.#ownerWaitSeconds} seconds`,
        };
      }
      return outcome;
    }

    const owner = this.#owner;
    if (approval === undefined) {
      return { kind: 'deny', reason: 'GNAP authorization requires an approval service' };
    }
    const grantId = grantIdFrom(pending.continue.uri);
    let issuedSuccessfully = false;
    try {
      // The Harness only offers "allow once"; say plainly that approval covers later calls in scope.
      const reason = `Approving lets this agent use ${describeScope(call.access, call.operation)} for up to ${this.#tokenTtlSeconds} seconds, not only this call. Current call: ${JSON.stringify(call.arguments)}`;
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

      await owner.resolve(grantId, 'approve', input.signal);
      // The owner has decided, so the first continuation does not wait out the
      // polling interval; a server that still paces it answers too_fast.
      const continued = await this.#continueUntilDecided(client, pending.continue, input.signal, {
        firstWaitSeconds: 0,
        deadline: Number.POSITIVE_INFINITY,
        maxAttempts: this.#maxContinuationAttempts,
      });
      if (continued.kind !== 'token') {
        return continued.kind === 'timeout'
          ? { kind: 'deny', reason: 'approved grant did not issue an access token' }
          : continued;
      }
      const decision = this.#acceptIssued(input.sessionId, continued.token);
      issuedSuccessfully = true;
      return decision;
    } finally {
      if (!issuedSuccessfully && !input.signal.aborted) {
        // Best effort. An approved grant no longer accepts a deny transition,
        // so the server's grant expiry remains the final cleanup bound.
        await owner.resolve(grantId, 'deny', input.signal).catch(() => undefined);
      }
    }
  }

  /**
   * Continue a pending grant until the server issues a token or refuses it,
   * honouring `wait` and `too_fast`. Stops at `deadline` or after `maxAttempts`.
   */
  async #continueUntilDecided(
    client: GrantClient,
    first: NonNullable<GrantResponse['continue']>,
    signal: AbortSignal,
    limits: { firstWaitSeconds: number; deadline: number; maxAttempts: number },
  ): Promise<
    { kind: 'token'; token: AccessToken } | { kind: 'deny'; reason: string } | { kind: 'timeout' }
  > {
    let continuation = first;
    let waitSeconds = limits.firstWaitSeconds;
    for (let attempt = 0; attempt < limits.maxAttempts; attempt += 1) {
      const waitMilliseconds = Math.min(
        waitSeconds * 1000,
        Math.max(0, limits.deadline - Date.now()),
      );
      if (waitMilliseconds > 0) await this.#sleep(waitMilliseconds, signal);
      if (Date.now() > limits.deadline) return { kind: 'timeout' };
      try {
        const response = await client.continueGrant(
          continuation.uri,
          continuation.access_token.value,
          signal,
        );
        if (response.access_token !== undefined)
          return { kind: 'token', token: response.access_token };
        if (response.continue === undefined) {
          return { kind: 'deny', reason: 'grant response is incomplete' };
        }
        continuation = response.continue;
        waitSeconds = continuation.wait ?? 0;
      } catch (error) {
        if (!(error instanceof GnapHttpError)) throw error;
        if (error.code === 'too_fast') {
          waitSeconds = error.retryAfterSeconds ?? continuation.wait ?? 1;
          continue;
        }
        if (error.code === 'user_denied' || error.code === 'request_denied') {
          return { kind: 'deny', reason: 'the owner denied the grant' };
        }
        if (error.code === 'invalid_continuation') {
          return { kind: 'deny', reason: 'the grant expired before the owner decided' };
        }
        throw error;
      }
    }
    return { kind: 'timeout' };
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
