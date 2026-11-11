import { readFileSync } from 'node:fs';
import { Ed25519Signer } from '@agnap/gnap-core';
import { parsePublicJwk } from '@agnap/gnap-core';
import type { Ed25519PrivateJwk } from '@agnap/gnap-core';
import { GnapToolAuthorizer } from './authorizer.js';
import { InMemorySessionClientProvider } from './client.js';
import type { ApprovalPort, ToolProfile } from './types.js';

export interface HarnessToolExecution {
  readonly name: string;
  readonly arguments: unknown;
  readonly callId?: unknown;
  readonly agent?: unknown;
  readonly signal: AbortSignal;
}

export type HarnessPreToolDecision =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string }
  | { kind: 'cancel' }
  | { kind: 'ask'; reason?: string };

export interface HarnessApprovalService {
  request(request: {
    agent: unknown;
    toolName: string;
    callId?: unknown;
    reason?: string;
    signal: AbortSignal;
  }): Promise<'allowed-once' | 'rejected' | 'cancelled' | 'unavailable'>;
}

export interface HarnessContext {
  on(
    event: 'tools/pre-execute',
    listener: (
      execution: HarnessToolExecution,
      next: () => Promise<HarnessPreToolDecision>,
    ) => Promise<HarnessPreToolDecision>,
  ): unknown;
  on(event: 'agent/disposed', listener: (payload: { agent: unknown }) => void): unknown;
  get(name: 'approval'): HarnessApprovalService | undefined;
  /** Cordis effect; the returned disposer runs, and is awaited, when the plugin unloads. */
  effect?(execute: () => () => Promise<void>, label?: string): unknown;
  logger?: { error(message: string, error?: unknown): void };
}

/** Default bound on revoking every grant when the plugin unloads. */
export const DEFAULT_UNLOAD_REVOKE_TIMEOUT_MS = 3000;

export interface DeepSeekHarnessPluginOptions {
  authorizer: GnapToolAuthorizer;
  sessionId(execution: HarnessToolExecution): string;
  /** Deny tools without a profile instead of delegating to later policies. */
  denyUnprofiledTools?: boolean;
  /** Enables revocation when the pinned Harness emits `agent/disposed`. */
  disposedSessionId?(agent: unknown): string | null;
  /**
   * How long plugin unload waits for every grant to be revoked. The Harness
   * tears this plugin down before its agents on shutdown, so `agent/disposed`
   * alone would leave tokens live until they expire. Defaults to 3000.
   */
  unloadRevokeTimeoutMs?: number;
}

/** Serializable development configuration accepted by the Cordis `apply` export. */
export interface Config {
  issuer: string;
  resourceServerId: string;
  /** Development-only: path to a private JWK file. Never place the key inline in config. */
  resourceServerPrivateJwkFile: string;
  profiles: ToolProfile[];
  /**
   * How long a call that needs a new grant waits for the owner, who decides
   * in a separate process (`agnap-owner`). Defaults to 300.
   */
  ownerWaitSeconds?: number;
  /** Must match the AS setting. Defaults to 600 and is shown in approval text. */
  tokenTtlSeconds?: number;
  /** Deny tools without a profile. Defaults to the Harness-compatible permissive mode. */
  denyUnprofiledTools?: boolean;
  /** Bound on revoking every grant at plugin unload, in milliseconds. Defaults to 3000. */
  unloadRevokeTimeoutMs?: number;
}

export const name = '@agnap/deepseek';
/** The approval service is not needed: the owner decides outside the Harness. */
export const inject: string[] = [];

function loadPrivateJwk(path: string): Ed25519PrivateJwk {
  const value = JSON.parse(readFileSync(path, 'utf8')) as unknown;
  if (typeof value !== 'object' || value === null) throw new Error('RS JWK must be an object');
  const raw = value as Record<string, unknown>;
  const publicJwk = parsePublicJwk({
    kid: raw.kid,
    alg: raw.alg,
    kty: raw.kty,
    crv: raw.crv,
    x: raw.x,
    ...(raw.use !== undefined ? { use: raw.use } : {}),
  });
  if (publicJwk === null || typeof raw.d !== 'string' || raw.d.length === 0) {
    throw new Error('RS JWK must be a private Ed25519 signing key');
  }
  return { ...publicJwk, d: raw.d };
}

const sessionIdFromAgent = (agent: unknown): string => {
  const id = (agent as { id?: unknown } | undefined)?.id;
  if (typeof id !== 'string' || id.length === 0) {
    throw new Error('GNAP authorization requires agent.id');
  }
  return id;
};

const agentSessionId = (execution: HarnessToolExecution): string =>
  sessionIdFromAgent(execution.agent);

/**
 * The owner's label for the calling agent: its session id, and its parent's
 * when the Harness recorded one (`session.header.parentSession`).
 * @param agent - the Harness agent on the tool execution.
 * @returns for example `agent child (subagent of parent)`.
 */
export function agentLabelOf(agent: unknown): string | undefined {
  const value = agent as
    { id?: unknown; session?: { header?: { parentSession?: unknown } } } | undefined;
  if (typeof value?.id !== 'string') return undefined;
  const parent = value.session?.header?.parentSession;
  return typeof parent === 'string'
    ? `agent ${value.id} (subagent of ${parent})`
    : `agent ${value.id}`;
}

/** Conventional Cordis plugin entry point for the local PoC deployment. */
export function apply(context: HarnessContext, config: Config): void {
  const resourceServerSigner = Ed25519Signer.fromJwk(
    loadPrivateJwk(config.resourceServerPrivateJwkFile),
  );
  const clients = new InMemorySessionClientProvider({
    issuer: config.issuer,
    resourceServer: { id: config.resourceServerId, signer: resourceServerSigner },
  });
  const authorizer = new GnapToolAuthorizer({
    profiles: config.profiles,
    clients,
    ...(config.ownerWaitSeconds !== undefined ? { ownerWaitSeconds: config.ownerWaitSeconds } : {}),
    ...(config.tokenTtlSeconds !== undefined ? { tokenTtlSeconds: config.tokenTtlSeconds } : {}),
  });
  applyDeepSeekHarnessPlugin(context, {
    authorizer,
    sessionId: agentSessionId,
    ...(config.denyUnprofiledTools !== undefined
      ? { denyUnprofiledTools: config.denyUnprofiledTools }
      : {}),
    disposedSessionId: sessionIdFromAgent,
    ...(config.unloadRevokeTimeoutMs !== undefined
      ? { unloadRevokeTimeoutMs: config.unloadRevokeTimeoutMs }
      : {}),
  });
}

/**
 * Structural adapter for DeepSeek Harness 0.2.1-alpha.1 at commit
 * 5badb15009ae1756c3afe0ae0cef1faafc290ccc. No runtime Harness dependency.
 */
export function applyDeepSeekHarnessPlugin(
  context: HarnessContext,
  options: DeepSeekHarnessPluginOptions,
): void {
  const logError = (message: string, error: unknown) => {
    if (context.logger !== undefined) context.logger.error(message, error);
    else console.error(message, error);
  };
  const unloadTimeout = options.unloadRevokeTimeoutMs ?? DEFAULT_UNLOAD_REVOKE_TIMEOUT_MS;
  if (!Number.isInteger(unloadTimeout) || unloadTimeout <= 0) {
    throw new RangeError('unloadRevokeTimeoutMs must be a positive integer');
  }
  context.effect?.(
    () => () => {
      // Bounds the whole step: revocation queues behind any authorization still in flight.
      const signal = AbortSignal.timeout(unloadTimeout);
      const timedOut = new Promise<never>((_, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason as Error), { once: true });
      });
      return Promise.race([options.authorizer.revokeAll(signal), timedOut]).catch(
        (error: unknown) => logError('GNAP revocation at plugin unload failed', error),
      );
    },
    'agnap: revoke grants on unload',
  );
  if (options.disposedSessionId !== undefined) {
    context.on('agent/disposed', ({ agent }) => {
      const sessionId = options.disposedSessionId?.(agent);
      if (sessionId === null || sessionId === undefined) return;
      void options.authorizer
        .disposeSession(sessionId)
        .catch((error: unknown) => logError('GNAP session revocation failed', error));
    });
  }
  context.on('tools/pre-execute', async (execution, next) => {
    if (execution.agent === undefined) {
      return { kind: 'deny', reason: 'GNAP authorization requires an agent session' };
    }
    const service = context.get('approval');
    const approval: ApprovalPort | undefined =
      service === undefined
        ? undefined
        : {
            request: (request) =>
              service.request({
                agent: request.agent,
                toolName: request.toolName,
                ...(request.callId !== undefined ? { callId: request.callId } : {}),
                reason: request.reason,
                signal: request.signal,
              }),
          };
    const agentLabel = agentLabelOf(execution.agent);
    let decision;
    try {
      decision = await options.authorizer.authorize(
        {
          sessionId: options.sessionId(execution),
          agent: execution.agent,
          toolName: execution.name,
          ...(execution.callId !== undefined ? { callId: execution.callId } : {}),
          arguments: execution.arguments,
          signal: execution.signal,
          ...(agentLabel !== undefined ? { agentLabel } : {}),
        },
        approval,
      );
    } catch (error) {
      if (execution.signal.aborted) return { kind: 'cancel' };
      if (context.logger !== undefined) context.logger.error('GNAP authorization failed', error);
      else console.error('GNAP authorization failed', error);
      return { kind: 'deny', reason: 'GNAP authorization failed' };
    }
    if (decision.kind === 'deny' || decision.kind === 'cancel') return decision;
    if (decision.kind === 'unprofiled' && options.denyUnprofiledTools === true) {
      return { kind: 'deny', reason: `tool ${execution.name} has no GNAP profile` };
    }
    // Authorization never short-circuits other Harness policies.
    return next();
  });
}
