import { agentOperationHandler } from '@agnap/access-types';
import { Ed25519Signer } from '@agnap/gnap-core';
import type { Clock } from '@agnap/gnap-core';
import {
  MemoryStore,
  StaticResourceServerRegistry,
  createHandler,
  createServer,
  pendingOwner,
} from '@agnap/gnap-server';
import { describe, expect, it } from 'vitest';

import {
  GnapHttpError,
  GnapToolAuthorizer,
  InMemorySessionClientProvider,
  LocalOwnerClient,
  MemorySessionGrantStore,
} from '../src/index.js';
import type {
  ApprovalPort,
  AuthorizeToolInput,
  GrantClient,
  OwnerDecisionPort,
} from '../src/index.js';

const ISSUER = 'https://as.test/';
const OWNER_SECRET = 'test-owner-secret';

class ManualClock implements Clock {
  value = 1_800_000_000_000;
  now(): number {
    return this.value;
  }
  advance(milliseconds: number): void {
    this.value += milliseconds;
  }
}

function fixture(
  options: {
    tokenTtlSeconds?: number;
    continueWaitSeconds?: number;
    sleep?: (milliseconds: number, signal: AbortSignal) => Promise<void>;
  } = {},
) {
  const rs = Ed25519Signer.generate('harness-plugin-rs');
  const clock = new ManualClock();
  const store = new MemoryStore({ clock });
  const registry = new StaticResourceServerRegistry([
    { id: 'harness-plugin', key: rs.publicJwk, accessTypes: ['agent_operation'] },
  ]);
  const handler = createHandler({
    server: createServer(
      {
        issuer: ISSUER,
        registry,
        accessTypes: [agentOperationHandler],
        decision: pendingOwner,
        continueWaitSeconds: options.continueWaitSeconds ?? 0,
        tokenTtlSeconds: options.tokenTtlSeconds ?? 600,
      },
      store,
    ),
    store,
    rsRegistry: registry,
    publicUrl: ISSUER,
    localOwner: { secret: OWNER_SECRET },
    clock,
  });
  let introspections = 0;
  const injectedFetch = (request: Request) => {
    if (new URL(request.url).pathname === '/introspect') introspections += 1;
    return handler(request);
  };
  const grants = new MemorySessionGrantStore();
  const clients = new InMemorySessionClientProvider({
    issuer: ISSUER,
    resourceServer: { id: 'harness-plugin', signer: rs },
    fetch: injectedFetch,
    clock,
  });
  const ownerDecisions: Array<{ grantId: string; decision: 'approve' | 'deny' }> = [];
  const localOwner = new LocalOwnerClient({
    issuer: ISSUER,
    secret: OWNER_SECRET,
    fetch: injectedFetch,
  });
  const owner: OwnerDecisionPort = {
    resolve: (grantId, decision, signal) => {
      ownerDecisions.push({ grantId, decision });
      return localOwner.resolve(grantId, decision, signal);
    },
  };
  const authorizer = new GnapToolAuthorizer({
    profiles: [
      {
        toolName: 'github.pull_request.create',
        arguments: {
          repository: { authority: 'identity' },
          title: { authority: 'free', required: false },
        },
      },
      { toolName: 'shell.exec', arguments: { argv: { encoding: 'json' } } },
    ],
    clients,
    owner,
    grants,
    tokenTtlSeconds: options.tokenTtlSeconds ?? 600,
    ...(options.sleep !== undefined ? { sleep: options.sleep } : {}),
  });
  return {
    authorizer,
    grants,
    clients,
    clock,
    ownerDecisions,
    introspections: () => introspections,
  };
}

const input = (overrides: Partial<AuthorizeToolInput> = {}): AuthorizeToolInput => ({
  sessionId: 'session-1',
  agent: { id: 'agent-1' },
  toolName: 'github.pull_request.create',
  callId: 'call-1',
  arguments: { repository: 'acme/app', title: 'Fix login' },
  signal: new AbortController().signal,
  ...overrides,
});

describe('GNAP tool authorizer', () => {
  it('prompts, approves, continues, caches and introspects a key-bound grant', async () => {
    const { authorizer, grants, introspections } = fixture();
    let prompts = 0;
    const reasons: string[] = [];
    const approval: ApprovalPort = {
      request: (request) => {
        prompts += 1;
        reasons.push(request.reason);
        return Promise.resolve('allowed-once');
      },
    };

    const first = await authorizer.authorize(input(), approval);
    expect(first.kind).toBe('allow');
    expect(reasons[0]).toContain('github.pull_request.create');
    expect(reasons[0]).toContain('acme/app');
    expect(reasons[0]).toContain('title = any');
    expect(reasons[0]).toContain('600 seconds');
    expect(grants.list('session-1')[0]?.token.value).toBeTruthy();
    expect(grants.list('session-1')[0]?.fingerprint).not.toBe(
      grants.list('session-1')[0]?.token.value,
    );

    const second = await authorizer.authorize(
      input({ callId: 'call-2', arguments: { repository: 'acme/app', title: 'Another PR' } }),
      approval,
    );
    expect(second).toEqual(first);
    expect(prompts).toBe(1);

    const outside = await authorizer.authorize(
      input({
        callId: 'call-3',
        arguments: { repository: 'other/repo', title: 'Other repository' },
      }),
      approval,
    );
    expect(outside).toMatchObject({ kind: 'allow' });
    expect(prompts).toBe(2);

    const secondOperation = await authorizer.authorize(
      input({ toolName: 'shell.exec', callId: 'call-4', arguments: { argv: ['git', 'status'] } }),
      approval,
    );
    expect(secondOperation.kind).toBe('allow');
    expect(grants.list('session-1')).toHaveLength(3);
    expect(prompts).toBe(3);
    expect(reasons[2]).toContain('shell.exec');

    const before = introspections();
    expect(await authorizer.authorize(input({ callId: 'call-5' }), approval)).toEqual(first);
    expect(introspections() - before).toBe(1);
    expect(prompts).toBe(3);
  });

  it('reuses a wildcard when the optional free argument was absent from the first call', async () => {
    const { authorizer } = fixture();
    let prompts = 0;
    const approval: ApprovalPort = {
      request: () => {
        prompts += 1;
        return Promise.resolve('allowed-once');
      },
    };
    expect(
      await authorizer.authorize(
        input({ sessionId: 'optional-free', arguments: { repository: 'acme/app' } }),
        approval,
      ),
    ).toMatchObject({ kind: 'allow' });
    expect(
      await authorizer.authorize(
        input({
          sessionId: 'optional-free',
          callId: 'with-title',
          arguments: { repository: 'acme/app', title: 'Added later' },
        }),
        approval,
      ),
    ).toMatchObject({ kind: 'allow' });
    expect(prompts).toBe(1);
  });

  it('introspects narrowed grants with exact access required by the current call', async () => {
    const grants = new MemorySessionGrantStore();
    const narrowedAccess = {
      type: 'agent_operation' as const,
      operations: {
        'github.pull_request.create': {
          repository: { exact: 'acme/app' as const },
          title: { exact: 'Fix login' as const },
        },
      },
    };
    grants.add('session-1', {
      fingerprint: 'narrowed',
      token: {
        value: 'narrowed-token',
        access: [narrowedAccess],
        expires_in: 600,
        manage: { uri: 'https://as.test/token/narrowed', access_token: { value: 'management' } },
      },
    });
    let introspectedAccess: unknown;
    const client: GrantClient = {
      clientSigner: Ed25519Signer.generate('narrowed-client'),
      requestGrant: () => Promise.reject(new Error('not expected')),
      continueGrant: () => Promise.reject(new Error('not expected')),
      introspect: (_token, access) => {
        introspectedAccess = access;
        return Promise.resolve({
          active: true,
          access: [narrowedAccess],
          iss: 'https://as.test/',
        });
      },
      revoke: () => Promise.resolve(),
    };
    const authorizer = new GnapToolAuthorizer({
      profiles: [
        {
          toolName: 'github.pull_request.create',
          arguments: { repository: {}, title: { authority: 'free', required: false } },
        },
      ],
      clients: { get: () => client },
      owner: { resolve: () => Promise.reject(new Error('not expected')) },
      grants,
    });
    expect(
      await authorizer.authorize(input(), {
        request: () => Promise.reject(new Error('not expected')),
      }),
    ).toEqual({ kind: 'allow', fingerprint: 'narrowed' });
    expect(introspectedAccess).toEqual([narrowedAccess]);
  });

  it('denies rejected approval, fails closed on bad arguments, and ignores unprofiled tools', async () => {
    const { authorizer, grants, ownerDecisions } = fixture();
    const rejected: ApprovalPort = { request: () => Promise.resolve('rejected') };
    expect(await authorizer.authorize(input(), rejected)).toEqual({
      kind: 'deny',
      reason: 'grant rejected',
    });
    expect(grants.list('session-1')).toEqual([]);
    expect(ownerDecisions).toHaveLength(1);
    expect(ownerDecisions[0]?.decision).toBe('deny');

    expect(
      await authorizer.authorize(
        input({ arguments: { repository: [], title: 'Bad repository' } }),
        rejected,
      ),
    ).toMatchObject({ kind: 'deny' });
    expect(await authorizer.authorize(input({ toolName: 'unprofiled.tool' }), rejected)).toEqual({
      kind: 'unprofiled',
    });
  });

  it('serializes concurrent first calls so they share one prompt and grant', async () => {
    const { authorizer } = fixture();
    let prompts = 0;
    const approval: ApprovalPort = {
      request: () => {
        prompts += 1;
        return Promise.resolve('allowed-once');
      },
    };
    const [a, b] = await Promise.all([
      authorizer.authorize(input({ callId: 'a' }), approval),
      authorizer.authorize(input({ callId: 'b' }), approval),
    ]);
    expect(a.kind).toBe('allow');
    expect(b.kind).toBe('allow');
    expect(prompts).toBe(1);
  });

  it('prompts again after server-side revocation and expiry', async () => {
    const approval: ApprovalPort = { request: () => Promise.resolve('allowed-once') };

    const revoked = fixture();
    await revoked.authorizer.authorize(input(), approval);
    const revokedToken = revoked.grants.list('session-1')[0]?.token;
    expect(revokedToken).toBeDefined();
    await revoked.clients.get('session-1').revoke(revokedToken!);
    await revoked.authorizer.authorize(input({ callId: 'after-revoke' }), approval);
    expect(revoked.ownerDecisions.filter((item) => item.decision === 'approve')).toHaveLength(2);

    const expired = fixture({ tokenTtlSeconds: 1 });
    await expired.authorizer.authorize(input(), approval);
    expired.clock.advance(1_100);
    await expired.authorizer.authorize(input({ callId: 'after-expiry' }), approval);
    expect(expired.ownerDecisions.filter((item) => item.decision === 'approve')).toHaveLength(2);
  });

  it('preserves cancellation and best-effort denies abandoned grants', async () => {
    const cancelled = fixture();
    expect(
      await cancelled.authorizer.authorize(input(), {
        request: () => Promise.resolve('cancelled'),
      }),
    ).toEqual({ kind: 'cancel' });
    expect(cancelled.ownerDecisions.map((item) => item.decision)).toEqual(['deny']);

    const controller = new AbortController();
    const duringWait = fixture({
      continueWaitSeconds: 1,
      sleep: () => {
        controller.abort();
        return Promise.reject(new Error('aborted during wait'));
      },
    });
    expect(
      await duringWait.authorizer.authorize(input({ signal: controller.signal }), {
        request: () => Promise.resolve('allowed-once'),
      }),
    ).toEqual({ kind: 'cancel' });
    expect(duringWait.ownerDecisions.map((item) => item.decision)).toEqual(['approve']);

    const thrown = fixture();
    await expect(
      thrown.authorizer.authorize(input(), {
        request: () => Promise.reject(new Error('approval channel failed')),
      }),
    ).rejects.toThrow(/approval channel failed/);
    expect(thrown.ownerDecisions.map((item) => item.decision)).toEqual(['deny']);
  });

  it('retries too_fast and repeated pending continuation responses', async () => {
    const signer = Ed25519Signer.generate('retry-client');
    let attempts = 0;
    const client: GrantClient = {
      clientSigner: signer,
      requestGrant: () =>
        Promise.resolve({
          continue: {
            uri: 'https://as.test/continue/grant-1',
            wait: 0,
            access_token: { value: 'first' },
          },
        }),
      continueGrant: () => {
        attempts += 1;
        if (attempts === 1) {
          return Promise.reject(new GnapHttpError(400, 'too_fast', 'too fast', 0));
        }
        if (attempts === 2) {
          return Promise.resolve({
            continue: {
              uri: 'https://as.test/continue/grant-1',
              wait: 0,
              access_token: { value: 'second' },
            },
          });
        }
        return Promise.resolve({
          access_token: {
            value: 'issued',
            access: [
              {
                type: 'agent_operation',
                operations: {
                  'github.pull_request.create': {
                    repository: { exact: 'acme/app' },
                    title: { wildcard: true },
                  },
                },
              },
            ],
            expires_in: 600,
            manage: { uri: 'https://as.test/token/issued', access_token: { value: 'management' } },
          },
        });
      },
      introspect: () => Promise.reject(new Error('not expected')),
      revoke: () => Promise.resolve(),
    };
    const authorizer = new GnapToolAuthorizer({
      profiles: [
        {
          toolName: 'github.pull_request.create',
          arguments: { repository: {}, title: { authority: 'free' } },
        },
      ],
      clients: { get: () => client },
      owner: { resolve: () => Promise.resolve() },
      sleep: () => Promise.resolve(),
    });
    expect(
      await authorizer.authorize(input(), { request: () => Promise.resolve('allowed-once') }),
    ).toMatchObject({ kind: 'allow' });
    expect(attempts).toBe(3);
  });

  it('serializes revocation behind an in-flight authorization', async () => {
    const signer = Ed25519Signer.generate('revoke-race-client');
    let markApprovalReached!: () => void;
    const approvalReached = new Promise<void>((resolve) => {
      markApprovalReached = resolve;
    });
    let allow!: (outcome: 'allowed-once') => void;
    const approvalResult = new Promise<'allowed-once'>((resolve) => {
      allow = resolve;
    });
    let revocations = 0;
    const grants = new MemorySessionGrantStore();
    const client: GrantClient = {
      clientSigner: signer,
      requestGrant: () =>
        Promise.resolve({
          continue: {
            uri: 'https://as.test/continue/grant-1',
            wait: 0,
            access_token: { value: 'continuation' },
          },
        }),
      continueGrant: () =>
        Promise.resolve({
          access_token: {
            value: 'issued',
            access: [
              {
                type: 'agent_operation',
                operations: {
                  'github.pull_request.create': {
                    repository: { exact: 'acme/app' },
                    title: { wildcard: true },
                  },
                },
              },
            ],
            expires_in: 600,
            manage: {
              uri: 'https://as.test/token/token-1',
              access_token: { value: 'management' },
            },
          },
        }),
      introspect: () => Promise.reject(new Error('not expected')),
      revoke: () => {
        revocations += 1;
        return Promise.resolve();
      },
    };
    const authorizer = new GnapToolAuthorizer({
      profiles: [
        {
          toolName: 'github.pull_request.create',
          arguments: { repository: {}, title: { authority: 'free', required: false } },
        },
      ],
      clients: { get: () => client },
      owner: { resolve: () => Promise.resolve() },
      grants,
    });
    const authorization = authorizer.authorize(input(), {
      request: () => {
        markApprovalReached();
        return approvalResult;
      },
    });
    await approvalReached;
    const revocation = authorizer.revoke('session-1');
    allow('allowed-once');
    expect(await authorization).toMatchObject({ kind: 'allow' });
    await revocation;
    expect(revocations).toBe(1);
    expect(grants.list('session-1')).toEqual([]);
  });
});
