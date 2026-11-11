/**
 * End to end over a loopback socket through the Node adapter: a client that
 * signs with gnap-core drives grant, early continue, owner approval,
 * continue, introspection, revocation. Then the negative cases that only
 * the HTTP layer can produce: wrong key, missing signature, replay, wrong
 * owner secret, body swapped after signing.
 */
import { agentOperationHandler } from '@agnap/access-types';
import {
  Ed25519Signer,
  signedFetchRequest,
  utf8,
  validateErrorResponse,
  validateGrantResponse,
  validateIntrospectionResponse,
} from '@agnap/gnap-core';
import type { GrantResponse, SignableRequest, Signer, ValidateFunction } from '@agnap/gnap-core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  MemoryStore,
  StaticResourceServerRegistry,
  createHandler,
  createServer,
  pendingOwner,
  serve,
} from '../src/index.js';
import type { RunningServer } from '../src/index.js';
import { validateOwnerResolutionResult, validatePendingGrantList } from '../src/schemas/index.js';

const SECRET = 'owner-secret-for-tests';
const client = Ed25519Signer.generate('client-1');
const rs = Ed25519Signer.generate('rs-1');
const impostor = Ed25519Signer.generate('client-1');

const access = [
  { type: 'agent_operation', operations: { 'shell.exec': { argv: { exact: 'git status' } } } },
];

let running: RunningServer;
let base: string;

beforeAll(async () => {
  const store = new MemoryStore();
  const rsRegistry = new StaticResourceServerRegistry([
    { id: 'rs-1', key: rs.publicJwk, accessTypes: ['agent_operation'] },
  ]);
  running = await serve(
    createHandler({
      server: createServer(
        {
          issuer: 'http://127.0.0.1:0/',
          registry: rsRegistry,
          accessTypes: [agentOperationHandler],
          decision: pendingOwner,
          continueWaitSeconds: 1,
        },
        store,
      ),
      store,
      rsRegistry,
      localOwner: { secret: SECRET },
    }),
  );
  base = running.url;
});
afterAll(() => running.close());

async function call(
  signer: Signer,
  method: string,
  path: string,
  body?: unknown,
  token?: string,
  nonce?: string,
) {
  const headers = new Headers();
  if (body !== undefined) headers.set('content-type', 'application/json');
  if (token !== undefined) headers.set('authorization', `GNAP ${token}`);
  const signable: SignableRequest = {
    method,
    url: `${base}${path}`,
    headers,
    body: body === undefined ? new Uint8Array() : utf8(JSON.stringify(body)),
  };
  const req = await signedFetchRequest(signable, {
    signer,
    ...(nonce !== undefined ? { nonce } : {}),
  });
  const res = await fetch(req);
  const text = await res.text();
  return {
    status: res.status,
    headers: res.headers,
    body: text.length > 0 ? (JSON.parse(text) as unknown) : undefined,
  };
}

const grantBody = (signer: Signer) => ({
  access_token: { access },
  client: { key: { proof: 'httpsig', jwk: signer.publicJwk } },
});

async function owner(method: string, path: string, body?: unknown, secret = SECRET) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { authorization: `Bearer ${secret}`, 'content-type': 'application/json' },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  return { status: res.status, body: await res.json() };
}

function expectValid(validate: ValidateFunction, body: unknown): void {
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
}

describe('end to end over loopback', () => {
  it('grant, too_fast, owner approves, continue, introspect, revoke, introspect inactive', async () => {
    const pending = await call(client, 'POST', '/', grantBody(client));
    expect(pending.status).toBe(200);
    expectValid(validateGrantResponse, pending.body);
    const cont = (pending.body as GrantResponse).continue!;
    // The continue URI is absolute and points back at this server.
    expect(cont.uri.startsWith('http://127.0.0.1:')).toBe(true);
    const grantId = cont.uri.split('/').pop() as string;

    const early = await call(
      client,
      'POST',
      `/continue/${grantId}`,
      undefined,
      cont.access_token.value,
    );
    expect(early.status).toBe(400);
    expectValid(validateErrorResponse, early.body);
    expect(early.body).toMatchObject({ error: { code: 'too_fast' } });
    expect(early.headers.get('retry-after')).toBe('1');

    const list = await owner('GET', '/local/grants');
    expectValid(validatePendingGrantList, list.body);
    expect(list.body).toMatchObject({
      grants: [{ id: grantId, client_kid: 'client-1', requested_access: access }],
    });
    expect((await owner('GET', '/local/grants', undefined, 'wrong')).status).toBe(401);

    const approved = await owner('POST', `/local/grants/${grantId}`, { decision: 'approve' });
    expectValid(validateOwnerResolutionResult, approved.body);
    expect(approved.body).toEqual({ state: 'approved' });

    await new Promise((r) => setTimeout(r, 1_100));
    const issued = await call(
      client,
      'POST',
      `/continue/${grantId}`,
      undefined,
      cont.access_token.value,
    );
    expect(issued.status).toBe(200);
    expectValid(validateGrantResponse, issued.body);
    const token = (issued.body as GrantResponse).access_token!;
    expect(token.manage?.uri.startsWith('http://127.0.0.1:')).toBe(true);

    const active = await call(rs, 'POST', '/introspect', {
      access_token: token.value,
      resource_server: 'rs-1',
    });
    expectValid(validateIntrospectionResponse, active.body);
    expect(active.body).toMatchObject({ active: true, access, key: { jwk: client.publicJwk } });

    // Wrong RS key for the named resource server
    const bad = await call(client, 'POST', '/introspect', {
      access_token: token.value,
      resource_server: 'rs-1',
    });
    expect(bad.status).toBe(401);
    expectValid(validateErrorResponse, bad.body);
    expect(bad.body).toMatchObject({ error: { code: 'invalid_resource_server' } });
    // Unknown RS
    expect(
      (
        await call(rs, 'POST', '/introspect', {
          access_token: token.value,
          resource_server: 'nope',
        })
      ).status,
    ).toBe(401);

    const tokenId = token.manage.uri.split('/').pop();
    if (tokenId === undefined) throw new Error('management URI has no token id');
    expect((await call(client, 'DELETE', `/token/${tokenId}`, undefined, token.value)).status).toBe(
      401,
    );
    expect(
      (
        await call(
          impostor,
          'DELETE',
          `/token/${tokenId}`,
          undefined,
          token.manage.access_token.value,
        )
      ).status,
    ).toBe(401);
    expect(
      (
        await call(
          client,
          'DELETE',
          `/token/${tokenId}`,
          undefined,
          token.manage.access_token.value,
        )
      ).status,
    ).toBe(204);

    const inactive = await call(rs, 'POST', '/introspect', {
      access_token: token.value,
      resource_server: 'rs-1',
    });
    expectValid(validateIntrospectionResponse, inactive.body);
    expect(inactive.body).toEqual({ active: false });

    // The grant's continuation credential is gone.
    expect(
      (await call(client, 'POST', `/continue/${grantId}`, undefined, cont.access_token.value)).body,
    ).toMatchObject({ error: { code: 'invalid_continuation' } });
  });

  it('refuses a grant signed by a key other than client.key, an unsigned grant, and a replayed nonce', async () => {
    const body = grantBody(client);
    const wrongKey = await call(impostor, 'POST', '/', body);
    expect(wrongKey.status).toBe(401);
    expect(wrongKey.body).toMatchObject({ error: { code: 'invalid_client' } });

    const unsigned = await fetch(`${base}/`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    expect(unsigned.status).toBe(401);

    const first = await call(client, 'POST', '/', body, undefined, 'fixed-nonce');
    expect(first.status).toBe(200);
    const replay = await call(client, 'POST', '/', body, undefined, 'fixed-nonce');
    expect(replay.status).toBe(401);
    expect((replay.body as { error: { description: string } }).error.description).toMatch(
      /replayed/,
    );
  });

  it('refuses a body swapped after signing, and a continue by a different key', async () => {
    const signable: SignableRequest = {
      method: 'POST',
      url: `${base}/`,
      headers: new Headers({ 'content-type': 'application/json' }),
      body: utf8(JSON.stringify(grantBody(client))),
    };
    const signed = await signedFetchRequest(signable, { signer: client });
    const swapped = new Request(signed.url, {
      method: 'POST',
      headers: signed.headers,
      body: JSON.stringify(grantBody(impostor)),
    });
    expect((await fetch(swapped)).status).toBe(401);

    const pending = await call(client, 'POST', '/', grantBody(client));
    const cont = (pending.body as GrantResponse).continue!;
    const grantId = cont.uri.split('/').pop() as string;
    await new Promise((r) => setTimeout(r, 1_100));
    const stolen = await call(
      impostor,
      'POST',
      `/continue/${grantId}`,
      undefined,
      cont.access_token.value,
    );
    expect(stolen.status).toBe(401);
    expect(stolen.body).toMatchObject({ error: { code: 'invalid_client' } });
    expect((await call(client, 'POST', '/continue/unknown', undefined, 'x')).body).toMatchObject({
      error: { code: 'invalid_continuation' },
    });
  });

  it('refuses oversized bodies with 413 before any route logic', async () => {
    const big = JSON.stringify({ pad: 'x'.repeat(70 * 1024) });
    const res = await fetch(`${base}/`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: big,
    });
    expect(res.status).toBe(413);
    const owner = await fetch(`${base}/local/grants/x`, {
      method: 'POST',
      headers: { authorization: `Bearer ${SECRET}`, 'content-type': 'application/json' },
      body: big,
    });
    expect(owner.status).toBe(413);
  });

  it('refuses an empty owner secret and a non-integer body limit at construction', () => {
    const store = new MemoryStore();
    const rsRegistry = new StaticResourceServerRegistry();
    const server = createServer(
      {
        issuer: 'http://127.0.0.1:0/',
        registry: rsRegistry,
        accessTypes: [agentOperationHandler],
        decision: pendingOwner,
      },
      store,
    );
    expect(() => createHandler({ server, store, rsRegistry, localOwner: { secret: '' } })).toThrow(
      /secret/,
    );
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, 0, -1, 1.5]) {
      expect(
        () => createHandler({ server, store, rsRegistry, maxBodyBytes: bad }),
        String(bad),
      ).toThrow(RangeError);
    }
  });

  it('owner routes refuse a missing or empty bearer value even when a secret is set', async () => {
    expect(
      (await fetch(`${base}/local/grants`, { headers: { authorization: 'Bearer ' } })).status,
    ).toBe(401);
    expect(
      (await fetch(`${base}/local/grants`, { headers: { authorization: 'Basic abc' } })).status,
    ).toBe(401);
  });

  it('a full replay cache answers 503 with Retry-After, not 401 replay', async () => {
    const store = new MemoryStore({ maxNonces: 1 });
    const rsRegistry = new StaticResourceServerRegistry();
    const local = await serve(
      createHandler({
        server: createServer(
          {
            issuer: 'http://127.0.0.1:0/',
            registry: rsRegistry,
            accessTypes: [agentOperationHandler],
            decision: pendingOwner,
          },
          store,
        ),
        store,
        rsRegistry,
      }),
    );
    try {
      const body = grantBody(client);
      const sign = (nonce: string) =>
        signedFetchRequest(
          {
            method: 'POST',
            url: `${local.url}/`,
            headers: new Headers({ 'content-type': 'application/json' }),
            body: utf8(JSON.stringify(body)),
          },
          { signer: client, nonce },
        );
      expect((await fetch(await sign('n1'))).status).toBe(200);
      const second = await fetch(await sign('n2'));
      expect(second.status).toBe(503);
      expect(second.headers.get('retry-after')).toBe('1');
      const secondBody = (await second.json()) as { error: { description: string } };
      expectValid(validateErrorResponse, secondBody);
      expect(secondBody.error.description).toMatch(/full/);
    } finally {
      await local.close();
    }
  });

  it('unknown routes are 404 and the owner extension needs the secret', async () => {
    expect((await fetch(`${base}/nope`)).status).toBe(404);
    expect((await fetch(`${base}/local/grants`)).status).toBe(401);
  });
});
