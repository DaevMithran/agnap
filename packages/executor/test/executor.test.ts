/**
 * The executor against the real grant server (in-process handler) and a
 * canary service that records every effect it receives.
 */
import { agentOperationHandler } from '@agnap/access-types';
import { Ed25519Signer, signedFetchRequest, utf8 } from '@agnap/gnap-core';
import type { AccessItem, GrantResponse, Signer } from '@agnap/gnap-core';
import {
  MemoryStore,
  StaticResourceServerRegistry,
  createHandler,
  createServer,
} from '@agnap/gnap-server';
import { describe, expect, it } from 'vitest';
import {
  GnapIntrospector,
  HttpConnector,
  MemoryGrantStateStore,
  createExecutor,
} from '../src/index.js';
import type { ExecutorEvent } from '../src/index.js';

const ISSUER = 'http://as.test/';
const EXECUTOR = 'http://agnapd.test';
const CREDENTIAL = 'downstream-secret';

/** The executor's response body, loosely typed for assertions. */
interface CallBody {
  result?: unknown;
  error?: { code: string; effect?: string; ceiling?: number; counted?: number };
}

interface Effect {
  method: string;
  path: string;
  query: string;
  body: string;
  authorization: string | null;
}

/** A downstream service that records every request it receives. */
function canary(status = (_: Request) => 200) {
  const effects: Effect[] = [];
  const fetch = async (request: Request) => {
    const url = new URL(request.url);
    effects.push({
      method: request.method,
      path: url.pathname,
      query: url.search,
      body: await request.text(),
      authorization: request.headers.get('authorization'),
    });
    return Response.json({ ok: true, n: effects.length }, { status: status(request) });
  };
  return { effects, fetch };
}

function fixture(options: { downstreamStatus?: (r: Request) => number } = {}) {
  const rs = Ed25519Signer.generate('agnapd');
  const store = new MemoryStore();
  const registry = new StaticResourceServerRegistry([
    { id: 'agnapd', key: rs.publicJwk, accessTypes: ['agent_operation'] },
  ]);
  const server = createServer(
    {
      issuer: ISSUER,
      registry,
      accessTypes: [agentOperationHandler],
      // Issue whatever is asked: these tests are about the executor.
      decision: { decide: ({ requestedAccess }) => ({ kind: 'issue', access: requestedAccess }) },
    },
    store,
  );
  const as = createHandler({ server, store, rsRegistry: registry, publicUrl: ISSUER });
  const downstream = canary(options.downstreamStatus);
  const events: ExecutorEvent[] = [];
  const credentialRequests: { operation: string; rootGrant: string | undefined }[] = [];
  const executor = createExecutor({
    introspector: new GnapIntrospector({
      issuer: ISSUER,
      resourceServerId: 'agnapd',
      signer: rs,
      fetch: (r) => as(r),
    }),
    connectors: [
      new HttpConnector({
        baseUrl: 'http://canary.test/',
        credential: {
          header: 'authorization',
          value: ({ operation, rootGrant }) => {
            credentialRequests.push({ operation, rootGrant });
            return `Bearer ${CREDENTIAL}`;
          },
        },
        fetch: downstream.fetch,
        operations: {
          'github.issues.list': {
            method: 'GET',
            path: '/repos/{+repository}/issues',
            query: ['state'],
          },
          'github.comment.create': {
            method: 'POST',
            path: '/repos/{+repository}/comments',
            body: ['body'],
          },
        },
      }),
    ],
    grantState: new MemoryGrantStateStore(),
    log: (e) => events.push(e),
  });

  async function grant(access: AccessItem[], signer: Signer = Ed25519Signer.generate('agent')) {
    const body = {
      access_token: { access },
      client: { key: { proof: 'httpsig', jwk: signer.publicJwk } },
    };
    const res = await as(
      await signedFetchRequest(
        {
          method: 'POST',
          url: ISSUER,
          headers: new Headers({ 'content-type': 'application/json' }),
          body: utf8(JSON.stringify(body)),
        },
        { signer },
      ),
    );
    const token = ((await res.json()) as GrantResponse).access_token!;
    return { signer, token: token.value, manage: token.manage };
  }

  async function signedCall(
    signer: Signer,
    token: string,
    operation: string,
    args: Record<string, unknown>,
  ) {
    return signedFetchRequest(
      {
        method: 'POST',
        url: `${EXECUTOR}/operations/${operation}`,
        headers: new Headers({
          'content-type': 'application/json',
          authorization: `GNAP ${token}`,
        }),
        body: utf8(JSON.stringify({ arguments: args })),
      },
      { signer },
    );
  }

  async function call(
    signer: Signer,
    token: string,
    operation: string,
    args: Record<string, unknown>,
  ) {
    const res = await executor(await signedCall(signer, token, operation, args));
    return { status: res.status, body: (await res.json()) as CallBody };
  }

  async function revoke(signer: Signer, manage: { uri: string; access_token: { value: string } }) {
    const res = await as(
      await signedFetchRequest(
        {
          method: 'DELETE',
          url: manage.uri,
          headers: new Headers({ authorization: `GNAP ${manage.access_token.value}` }),
          body: new Uint8Array(),
        },
        { signer },
      ),
    );
    expect(res.status).toBe(204);
  }

  return { executor, downstream, events, credentialRequests, grant, call, signedCall, revoke };
}

const docs = (ceiling?: number): AccessItem[] => [
  {
    type: 'agent_operation',
    operations: {
      'github.issues.list': { repository: { exact: 'acme/docs' }, state: { wildcard: true } },
      'github.comment.create': { repository: { exact: 'acme/docs' }, body: { wildcard: true } },
    },
    ...(ceiling !== undefined ? { ceilings: { 'github.comment.create': { calls: ceiling } } } : {}),
  },
];

describe('executor', () => {
  it('performs a covered call with the credential only it holds', async () => {
    const f = fixture();
    const g = await f.grant(docs());
    const res = await f.call(g.signer, g.token, 'github.issues.list', {
      repository: 'acme/docs',
      state: 'open',
    });
    expect(res.status).toBe(200);
    expect(res.body.result).toEqual({ ok: true, n: 1 });
    expect(f.downstream.effects).toEqual([
      {
        method: 'GET',
        path: '/repos/acme/docs/issues',
        query: '?state=open',
        body: '',
        authorization: `Bearer ${CREDENTIAL}`,
      },
    ]);
    // The credential is requested only for the checked call, with its root grant.
    expect(f.credentialRequests).toEqual([
      { operation: 'github.issues.list', rootGrant: expect.any(String) as unknown },
    ]);
  });

  it('checks the grant state record: exactly the ceiling reaches the service', async () => {
    const f = fixture();
    const g = await f.grant(docs(3));
    const statuses = [];
    for (let i = 0; i < 5; i += 1) {
      const res = await f.call(g.signer, g.token, 'github.comment.create', {
        repository: 'acme/docs',
        body: `comment ${i}`,
      });
      statuses.push(res.status);
      if (i === 4)
        expect(res.body.error).toMatchObject({ code: 'ceiling_reached', ceiling: 3, counted: 3 });
    }
    expect(statuses).toEqual([200, 200, 200, 403, 403]);
    expect(f.downstream.effects).toHaveLength(3);
  });

  it('holds the ceiling under parallel calls', async () => {
    const f = fixture();
    const g = await f.grant(docs(3));
    const results = await Promise.all(
      Array.from({ length: 12 }, (_, i) =>
        f.call(g.signer, g.token, 'github.comment.create', {
          repository: 'acme/docs',
          body: `${i}`,
        }),
      ),
    );
    expect(results.filter((r) => r.status === 200)).toHaveLength(3);
    expect(f.downstream.effects).toHaveLength(3);
  });

  it('keeps separate grants on separate records', async () => {
    const f = fixture();
    const one = await f.grant(docs(1));
    const two = await f.grant(docs(1));
    const args = { repository: 'acme/docs', body: 'x' };
    expect((await f.call(one.signer, one.token, 'github.comment.create', args)).status).toBe(200);
    expect((await f.call(two.signer, two.token, 'github.comment.create', args)).status).toBe(200);
    expect((await f.call(one.signer, one.token, 'github.comment.create', args)).status).toBe(403);
  });

  it('refuses calls the grant does not cover, before anything reaches the service', async () => {
    const f = fixture();
    const g = await f.grant(docs());
    const other = await f.call(g.signer, g.token, 'github.issues.list', {
      repository: 'acme/secrets',
    });
    expect(other).toMatchObject({ status: 403, body: { error: { code: 'insufficient_access' } } });
    const extra = await f.call(g.signer, g.token, 'github.issues.list', {
      repository: 'acme/docs',
      label: 'x',
    });
    expect(extra.status).toBe(403);
    const unknown = await f.call(g.signer, g.token, 'github.repo.delete', {
      repository: 'acme/docs',
    });
    expect(unknown.status).toBe(404);
    expect(f.downstream.effects).toEqual([]);
    expect(f.credentialRequests).toEqual([]);
  });

  it('refuses a stolen token signed by another key, a replayed request, and a revoked token', async () => {
    const f = fixture();
    const g = await f.grant(docs());
    const args = { repository: 'acme/docs' };
    const thief = Ed25519Signer.generate(g.signer.kid);
    expect(await f.call(thief, g.token, 'github.issues.list', args)).toMatchObject({
      status: 401,
      body: { error: { code: 'invalid_signature' } },
    });

    const once = await f.signedCall(g.signer, g.token, 'github.issues.list', args);
    const replay = once.clone();
    expect((await f.executor(once)).status).toBe(200);
    expect((await f.executor(replay)).status).toBe(401);

    await f.revoke(g.signer, g.manage);
    expect(await f.call(g.signer, g.token, 'github.issues.list', args)).toMatchObject({
      status: 401,
      body: { error: { code: 'invalid_token' } },
    });
    expect(f.downstream.effects).toHaveLength(1);
  });

  it('refuses a request without a token or with a body that is not arguments', async () => {
    const f = fixture();
    const noToken = await f.executor(
      new Request(`${EXECUTOR}/operations/github.issues.list`, {
        method: 'POST',
        body: JSON.stringify({ arguments: {} }),
      }),
    );
    expect(noToken.status).toBe(401);
    const g = await f.grant(docs());
    const nested = await f.call(g.signer, g.token, 'github.issues.list', { repository: { a: 1 } });
    expect(nested.status).toBe(400);
  });

  it('releases a call the service refused, and keeps counting one whose outcome is unknown', async () => {
    let next = 400;
    const f = fixture({ downstreamStatus: () => next });
    const g = await f.grant(docs(1));
    const args = { repository: 'acme/docs', body: 'x' };
    expect(await f.call(g.signer, g.token, 'github.comment.create', args)).toMatchObject({
      status: 502,
      body: { error: { effect: 'none' } },
    });
    next = 503;
    expect(await f.call(g.signer, g.token, 'github.comment.create', args)).toMatchObject({
      status: 502,
      body: { error: { effect: 'unknown' } },
    });
    next = 200;
    expect(await f.call(g.signer, g.token, 'github.comment.create', args)).toMatchObject({
      status: 403,
      body: { error: { code: 'ceiling_reached' } },
    });
    expect(f.events.map((e) => e.kind)).toEqual(['failed', 'failed', 'refused']);
  });
});
