/**
 * Profiled tools performed through the executor: the plugin requests the
 * grant, the executor performs the call with its own credential and counts
 * it, and the in-process tool body never runs.
 */
import { agentOperationHandler } from '@agnap/access-types';
import { Ed25519Signer } from '@agnap/gnap-core';
import {
  GnapIntrospector,
  HttpConnector,
  MemoryGrantStateStore,
  createExecutor,
} from '@agnap/executor';
import {
  MemoryStore,
  StaticResourceServerRegistry,
  createHandler,
  createServer,
} from '@agnap/gnap-server';
import { describe, expect, it } from 'vitest';
import {
  ExecutorClient,
  GnapToolAuthorizer,
  InMemorySessionClientProvider,
  applyDeepSeekHarnessPlugin,
} from '../src/index.js';
import type {
  HarnessContext,
  HarnessPreToolDecision,
  HarnessToolExecution,
  HarnessToolResult,
} from '../src/index.js';

const ISSUER = 'http://as.test/';

type PreListener = (
  execution: HarnessToolExecution,
  next: () => Promise<HarnessPreToolDecision>,
) => Promise<HarnessPreToolDecision>;
type ExecuteListener = (
  execution: HarnessToolExecution,
  next: () => Promise<HarnessToolResult>,
) => Promise<HarnessToolResult>;

function setup(downstreamStatus = 200) {
  const rs = Ed25519Signer.generate('agnapd');
  const registry = new StaticResourceServerRegistry([
    { id: 'agnapd', key: rs.publicJwk, accessTypes: ['agent_operation'] },
  ]);
  const store = new MemoryStore();
  const as = createHandler({
    server: createServer(
      {
        issuer: ISSUER,
        registry,
        accessTypes: [agentOperationHandler],
        decision: { decide: ({ requestedAccess }) => ({ kind: 'issue', access: requestedAccess }) },
      },
      store,
    ),
    store,
    rsRegistry: registry,
    publicUrl: ISSUER,
  });
  const effects: { url: string; auth: string | null; body: string }[] = [];
  const executor = createExecutor({
    introspector: new GnapIntrospector({
      issuer: ISSUER,
      resourceServerId: 'agnapd',
      signer: rs,
      fetch: (r) => as(r),
    }),
    connectors: [
      new HttpConnector({
        baseUrl: 'http://api.test/',
        credential: { header: 'authorization', value: () => 'Bearer downstream-secret' },
        fetch: async (request) => {
          effects.push({
            url: request.url,
            auth: request.headers.get('authorization'),
            body: await request.text(),
          });
          return Response.json({ id: effects.length }, { status: downstreamStatus });
        },
        operations: {
          'github.comment.create': {
            method: 'POST',
            path: '/repos/{+repository}/comments',
            body: ['body'],
          },
        },
      }),
    ],
    grantState: new MemoryGrantStateStore(),
  });

  const authorizer = new GnapToolAuthorizer({
    profiles: [
      {
        toolName: 'comment',
        operation: 'github.comment.create',
        arguments: { repository: {}, body: { authority: 'free' } },
        ceiling: { calls: 3 },
      },
    ],
    // No resource-server identity: the plugin cannot introspect, only the executor can.
    clients: new InMemorySessionClientProvider({ issuer: ISSUER, fetch: (r) => as(r) }),
    introspect: false,
  });
  let pre: PreListener | undefined;
  let execute: ExecuteListener | undefined;
  const context: HarnessContext = {
    on: (event: string, listener: unknown) => {
      if (event === 'tools/pre-execute') pre = listener as PreListener;
      if (event === 'tools/execute') execute = listener as ExecuteListener;
    },
    get: () => undefined,
    logger: { error: () => undefined },
  };
  applyDeepSeekHarnessPlugin(context, {
    authorizer,
    sessionId: () => 'session-1',
    executor: new ExecutorClient({ url: 'http://agnapd.test', fetch: (r) => executor(r) }),
  });

  let bodyRuns = 0;
  const localBody = (): Promise<HarnessToolResult> => {
    bodyRuns += 1;
    return Promise.resolve({ isError: false, value: 'local', content: [] });
  };
  async function run(name: string, args: Record<string, unknown>) {
    const execution = {
      name,
      arguments: args,
      agent: { id: 'a' },
      signal: AbortSignal.timeout(5000),
    };
    const decision = await pre!(execution, () => Promise.resolve({ kind: 'allow' }));
    if (decision.kind !== 'allow') return decision;
    return execute!(execution, localBody);
  }
  return { run, effects, bodyRuns: () => bodyRuns, authorizer };
}

describe('profiled tools through the executor', () => {
  it('performs the call with the executor credential and never runs the tool body', async () => {
    const t = setup();
    expect(await t.run('comment', { repository: 'acme/docs', body: 'hello' })).toEqual({
      isError: false,
      value: { id: 1 },
      content: [],
    });
    expect(t.effects).toEqual([
      {
        url: 'http://api.test/repos/acme/docs/comments',
        auth: 'Bearer downstream-secret',
        body: '{"body":"hello"}',
      },
    ]);
    expect(t.bodyRuns()).toBe(0);
  });

  it('holds the profile ceiling across parallel calls', async () => {
    const t = setup();
    // The first call obtains the grant; the rest reuse it in parallel.
    await t.run('comment', { repository: 'acme/docs', body: '0' });
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        t.run('comment', { repository: 'acme/docs', body: `${i + 1}` }),
      ),
    );
    const done = results.filter((r) => 'isError' in r && !r.isError);
    expect(done).toHaveLength(2);
    expect(results.find((r) => 'isError' in r && r.isError)).toMatchObject({
      error: { info: { code: 'AGNAP_CEILING_REACHED' } },
    });
    expect(t.effects).toHaveLength(3);
  });

  it('passes unprofiled tools to their own body', async () => {
    const t = setup();
    expect(await t.run('read_file', { path: 'x' })).toEqual({
      isError: false,
      value: 'local',
      content: [],
    });
    expect(t.bodyRuns()).toBe(1);
  });

  it('reports a downstream failure with an unknown effect, which stays counted', async () => {
    const t = setup(503);
    expect(await t.run('comment', { repository: 'acme/docs', body: 'x' })).toMatchObject({
      isError: true,
      error: {
        message: expect.stringContaining('may have had an effect') as unknown,
        info: { code: 'AGNAP_OPERATION_FAILED' },
      },
    });
  });
});
