import { readFileSync } from 'node:fs';
import { Ed25519Signer } from '@agnap/gnap-core';
import { parsePublicJwk } from '@agnap/gnap-core';
import type { Ed25519PrivateJwk } from '@agnap/gnap-core';
import { GnapToolAuthorizer } from './authorizer.js';
import { InMemorySessionClientProvider } from './client.js';
import { LocalOwnerClient } from './owner.js';
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
  logger?: { error(message: string, error?: unknown): void };
}

export interface DeepSeekHarnessPluginOptions {
  authorizer: GnapToolAuthorizer;
  sessionId(execution: HarnessToolExecution): string;
  /** Deny tools without a profile instead of delegating to later policies. */
  denyUnprofiledTools?: boolean;
  /** Enables revocation when the pinned Harness emits `agent/disposed`. */
  disposedSessionId?(agent: unknown): string | null;
}

/** Serializable development configuration accepted by the Cordis `apply` export. */
export interface Config {
  issuer: string;
  resourceServerId: string;
  /** Development-only: path to a private JWK file. Never place the key inline in config. */
  resourceServerPrivateJwkFile: string;
  /** Development-only: environment variable containing the local-owner secret. */
  simulateOwnerSecretEnv: string;
  profiles: ToolProfile[];
  /** Must match the AS setting. Defaults to 600 and is shown in approval text. */
  tokenTtlSeconds?: number;
  /** Deny tools without a profile. Defaults to the Harness-compatible permissive mode. */
  denyUnprofiledTools?: boolean;
}

export const name = '@agnap/deepseek';
export const inject = ['approval'];

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

/** Conventional Cordis plugin entry point for the local PoC deployment. */
export function apply(context: HarnessContext, config: Config): void {
  const secret = process.env[config.simulateOwnerSecretEnv];
  if (secret === undefined || secret.length === 0) {
    throw new Error(`owner secret environment variable ${config.simulateOwnerSecretEnv} is empty`);
  }
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
    owner: new LocalOwnerClient({
      issuer: config.issuer,
      secret,
    }),
    ...(config.tokenTtlSeconds !== undefined ? { tokenTtlSeconds: config.tokenTtlSeconds } : {}),
  });
  applyDeepSeekHarnessPlugin(context, {
    authorizer,
    sessionId: agentSessionId,
    ...(config.denyUnprofiledTools !== undefined
      ? { denyUnprofiledTools: config.denyUnprofiledTools }
      : {}),
    disposedSessionId: sessionIdFromAgent,
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
  if (options.disposedSessionId !== undefined) {
    context.on('agent/disposed', ({ agent }) => {
      const sessionId = options.disposedSessionId?.(agent);
      if (sessionId === null || sessionId === undefined) return;
      void options.authorizer.disposeSession(sessionId).catch((error: unknown) => {
        if (context.logger !== undefined)
          context.logger.error('GNAP session revocation failed', error);
        else console.error('GNAP session revocation failed', error);
      });
    });
  }
  context.on('tools/pre-execute', async (execution, next) => {
    if (execution.agent === undefined) {
      return { kind: 'deny', reason: 'GNAP authorization requires an agent session' };
    }
    const service = context.get('approval');
    if (service === undefined) {
      return { kind: 'deny', reason: 'GNAP authorization requires an approval service' };
    }
    const approval: ApprovalPort = {
      request: (request) =>
        service.request({
          agent: request.agent,
          toolName: request.toolName,
          ...(request.callId !== undefined ? { callId: request.callId } : {}),
          reason: request.reason,
          signal: request.signal,
        }),
    };
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
