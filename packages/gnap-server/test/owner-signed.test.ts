/**
 * The owner extension authenticated by the owner's key: every request is an
 * RFC 9421 signature by that key, with the same replay check as client
 * requests. No shared secret is configured.
 */
import { agentOperationHandler } from '@agnap/access-types';
import { Ed25519Signer, signedFetchRequest, utf8 } from '@agnap/gnap-core';
import type { GrantResponse, SignableRequest, Signer } from '@agnap/gnap-core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  MemoryStore,
  StaticResourceServerRegistry,
  createHandler,
  createServer,
  pendingOwner,
  serve,
} from '../src/index.js';
import type { PendingGrantList, RunningServer } from '../src/index.js';
import { validatePendingGrantList } from '../src/schemas/index.js';

const client = Ed25519Signer.generate('client-1');
const ownerKey = Ed25519Signer.generate('owner-1');
const notOwner = Ed25519Signer.generate('owner-1');

const access = [
  { type: 'agent_operation', operations: { 'shell.exec': { argv: { exact: 'git status' } } } },
];

let running: RunningServer;
let base: string;

beforeAll(async () => {
  const store = new MemoryStore();
  const rsRegistry = new StaticResourceServerRegistry([]);
  running = await serve(
    createHandler({
      server: createServer(
        {
          issuer: 'http://127.0.0.1:0/',
          registry: rsRegistry,
          accessTypes: [agentOperationHandler],
          decision: pendingOwner,
          continueWaitSeconds: 5,
        },
        store,
      ),
      store,
      rsRegistry,
      owner: { key: ownerKey.publicJwk },
    }),
  );
  base = running.url;
});
afterAll(() => running.close());

async function signed(
  signer: Signer,
  method: string,
  path: string,
  body?: unknown,
  nonce?: string,
) {
  const headers = new Headers();
  if (body !== undefined) headers.set('content-type', 'application/json');
  const signable: SignableRequest = {
    method,
    url: `${base}${path}`,
    headers,
    body: body === undefined ? new Uint8Array() : utf8(JSON.stringify(body)),
  };
  return signedFetchRequest(signable, { signer, ...(nonce !== undefined ? { nonce } : {}) });
}

async function send(request: Request) {
  const res = await fetch(request);
  const text = await res.text();
  return { status: res.status, body: text.length > 0 ? (JSON.parse(text) as unknown) : undefined };
}

async function requestGrant(display?: { name?: string; uri?: string }) {
  const res = await send(
    await signed(client, 'POST', '/', {
      access_token: { access },
      client: {
        key: { proof: 'httpsig', jwk: client.publicJwk },
        ...(display !== undefined ? { display } : {}),
      },
    }),
  );
  expect(res.status).toBe(200);
  const pending = (res.body as GrantResponse).continue!;
  const uri = pending.uri;
  return {
    id: uri.split('/').at(-1)!,
    continuePath: new URL(uri).pathname,
    token: pending.access_token.value,
  };
}

describe('owner extension signed by the owner key', () => {
  it('lists the client display name and approves; the grant is issued without waiting', async () => {
    const grant = await requestGrant({ name: 'agent child (subagent of parent)' });

    const list = await send(await signed(ownerKey, 'GET', '/local/grants'));
    expect(list.status).toBe(200);
    expect(
      validatePendingGrantList(list.body),
      JSON.stringify(validatePendingGrantList.errors),
    ).toBe(true);
    const listed = (list.body as PendingGrantList).grants.find((g) => g.id === grant.id);
    expect(listed?.client_display).toEqual({ name: 'agent child (subagent of parent)' });

    const decided = await send(
      await signed(ownerKey, 'POST', `/local/grants/${grant.id}`, { decision: 'approve' }),
    );
    expect(decided).toEqual({ status: 200, body: { state: 'approved' } });

    const headers = new Headers({ authorization: `GNAP ${grant.token}` });
    const issued = await send(
      await signedFetchRequest(
        { method: 'POST', url: `${base}${grant.continuePath}`, headers, body: new Uint8Array() },
        { signer: client },
      ),
    );
    expect(issued.status).toBe(200);
    expect((issued.body as GrantResponse).access_token?.value).toBeTruthy();
  });

  it('refuses unsigned, bearer, wrong-key and replayed owner requests', async () => {
    const grant = await requestGrant();
    expect((await fetch(`${base}/local/grants`)).status).toBe(401);
    expect(
      (await fetch(`${base}/local/grants`, { headers: { authorization: 'Bearer anything' } }))
        .status,
    ).toBe(401);
    expect((await send(await signed(notOwner, 'GET', '/local/grants'))).status).toBe(401);
    expect(
      (
        await send(
          await signed(client, 'POST', `/local/grants/${grant.id}`, { decision: 'approve' }),
        )
      ).status,
    ).toBe(401);

    const once = await signed(
      ownerKey,
      'POST',
      `/local/grants/${grant.id}`,
      { decision: 'deny' },
      'n-1',
    );
    const replay = once.clone();
    expect((await send(once)).status).toBe(200);
    expect((await send(replay)).status).toBe(401);
  });
});
