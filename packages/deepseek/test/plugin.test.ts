import { Ed25519Signer } from '@agnap/gnap-core';
import { describe, expect, it } from 'vitest';

import {
  GnapToolAuthorizer,
  MemorySessionGrantStore,
  applyDeepSeekHarnessPlugin,
} from '../src/index.js';
import type {
  GrantClient,
  HarnessContext,
  HarnessPreToolDecision,
  HarnessToolExecution,
  SessionClientProvider,
} from '../src/index.js';

const unusedClient: GrantClient = {
  clientSigner: Ed25519Signer.generate('unused'),
  requestGrant: () => Promise.reject(new Error('not expected')),
  continueGrant: () => Promise.reject(new Error('not expected')),
  introspect: () => Promise.reject(new Error('not expected')),
  revoke: () => Promise.reject(new Error('not expected')),
};

describe('DeepSeek Harness adapter', () => {
  it('delegates unprofiled tools and denies malformed profiled calls without short-circuiting', async () => {
    const clients: SessionClientProvider = { get: () => unusedClient };
    const authorizer = new GnapToolAuthorizer({
      profiles: [{ toolName: 'protected', arguments: { repository: {} } }],
      clients,
      owner: { resolve: () => Promise.reject(new Error('not expected')) },
    });
    let listener:
      | ((
          execution: HarnessToolExecution,
          next: () => Promise<HarnessPreToolDecision>,
        ) => Promise<HarnessPreToolDecision>)
      | undefined;
    const context: HarnessContext = {
      on: (event, registered) => {
        if (event === 'tools/pre-execute') {
          listener = registered as typeof listener;
        }
      },
      get: () => ({ request: () => Promise.resolve('allowed-once') }),
      logger: { error: () => undefined },
    };
    applyDeepSeekHarnessPlugin(context, { authorizer, sessionId: () => 'session-1' });
    expect(listener).toBeDefined();
    const execution = {
      name: 'other',
      arguments: {},
      agent: {},
      signal: new AbortController().signal,
    };
    expect(await listener!(execution, () => Promise.resolve({ kind: 'allow' }))).toEqual({
      kind: 'allow',
    });

    const denied = await listener!({ ...execution, name: 'protected', arguments: {} }, () =>
      Promise.resolve({ kind: 'allow' }),
    );
    expect(denied).toMatchObject({ kind: 'deny' });

    const unreachable = await listener!(
      { ...execution, name: 'protected', arguments: { repository: 'acme/app' } },
      () => Promise.resolve({ kind: 'allow' }),
    );
    expect(unreachable).toEqual({ kind: 'deny', reason: 'GNAP authorization failed' });

    applyDeepSeekHarnessPlugin(context, {
      authorizer,
      sessionId: () => 'session-1',
      denyUnprofiledTools: true,
    });
    expect(await listener!(execution, () => Promise.resolve({ kind: 'allow' }))).toEqual({
      kind: 'deny',
      reason: 'tool other has no GNAP profile',
    });
  });

  it('maps a cancelled approval to Harness cancellation', async () => {
    const pendingClient: GrantClient = {
      clientSigner: Ed25519Signer.generate('client'),
      requestGrant: () =>
        Promise.resolve({
          continue: {
            uri: 'https://as.test/continue/grant-1',
            wait: 0,
            access_token: { value: 'continuation' },
          },
        }),
      continueGrant: () => Promise.reject(new Error('not expected')),
      introspect: () => Promise.reject(new Error('not expected')),
      revoke: () => Promise.reject(new Error('not expected')),
    };
    const authorizer = new GnapToolAuthorizer({
      profiles: [{ toolName: 'protected', arguments: { repository: {} } }],
      clients: { get: () => pendingClient },
      owner: { resolve: () => Promise.resolve() },
    });
    let listener:
      | ((
          execution: HarnessToolExecution,
          next: () => Promise<HarnessPreToolDecision>,
        ) => Promise<HarnessPreToolDecision>)
      | undefined;
    applyDeepSeekHarnessPlugin(
      {
        on: (event, registered) => {
          if (event === 'tools/pre-execute') {
            listener = registered as typeof listener;
          }
        },
        get: () => ({ request: () => Promise.resolve('cancelled') }),
      },
      { authorizer, sessionId: () => 'session-1' },
    );
    expect(
      await listener!(
        {
          name: 'protected',
          arguments: { repository: 'acme/app' },
          agent: {},
          signal: new AbortController().signal,
        },
        () => Promise.resolve({ kind: 'allow' }),
      ),
    ).toEqual({ kind: 'cancel' });
  });

  it('revokes live grants when the Harness disposes the agent', async () => {
    const grants = new MemorySessionGrantStore();
    grants.add('agent-1', {
      fingerprint: 'fingerprint',
      token: {
        value: 'access-token',
        access: [],
        expires_in: 600,
        manage: { uri: 'https://as.test/token/1', access_token: { value: 'management-token' } },
      },
    });
    let revocations = 0;
    const client: GrantClient = {
      ...unusedClient,
      revoke: () => {
        revocations += 1;
        return Promise.resolve();
      },
    };
    const authorizer = new GnapToolAuthorizer({
      profiles: [{ toolName: 'protected', arguments: { repository: {} } }],
      clients: { get: () => client },
      owner: { resolve: () => Promise.reject(new Error('not expected')) },
      grants,
    });
    let disposed: ((payload: { agent: unknown }) => void) | undefined;
    const context: HarnessContext = {
      on: (event: string, listener: unknown) => {
        if (event === 'agent/disposed') {
          disposed = listener as (payload: { agent: unknown }) => void;
        }
      },
      get: () => ({ request: () => Promise.resolve('allowed-once') }),
    };
    applyDeepSeekHarnessPlugin(context, {
      authorizer,
      sessionId: () => 'agent-1',
      disposedSessionId: (agent) => (agent as { id: string }).id,
    });
    disposed?.({ agent: { id: 'agent-1' } });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(revocations).toBe(1);
    expect(grants.list('agent-1')).toEqual([]);
  });
});
