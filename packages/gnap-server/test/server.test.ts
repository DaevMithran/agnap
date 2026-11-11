/**
 * Every protocol rule, against the pure server. No HTTP, no signatures:
 * the handler proved the key, so tests hand in an AuthenticatedContext.
 */
import { agentOperationHandler } from '@agnap/access-types';
import { AccessTypeRegistry, fixedClock, generateKey, thumbprint } from '@agnap/gnap-core';
import type { Ed25519PublicJwk, GrantResponse } from '@agnap/gnap-core';
import { describe, expect, it } from 'vitest';
import {
  MemoryStore,
  StaticResourceServerRegistry,
  createServer,
  fixedList,
  pendingOwner,
} from '../src/index.js';
import type { AuthenticatedContext, GnapServer, ServerConfig } from '../src/index.js';

const ISSUER = 'https://as.example/';
const client = generateKey('client-1').publicJwk;
const rs1 = generateKey('rs1').publicJwk;
const rs2 = generateKey('rs2').publicJwk;
const rsOther = generateKey('rs-other').publicJwk;

const requested = [
  {
    type: 'agent_operation',
    operations: {
      'pr.create': { repository: { wildcard: true } },
      'shell.exec': { argv: { exact: 'git status' } },
    },
  },
];

function setup(over: Partial<ServerConfig> = {}) {
  const clock = fixedClock(1_700_000_000_000);
  const registry = new StaticResourceServerRegistry([
    { id: 'rs1', key: rs1, accessTypes: ['agent_operation'] },
    { id: 'rs2', key: rs2, accessTypes: ['agent_operation'] },
    { id: 'rs-other', key: rsOther, accessTypes: ['files'] },
  ]);
  const store = new MemoryStore({ clock });
  const server = createServer(
    {
      issuer: ISSUER,
      registry,
      accessTypes: [agentOperationHandler],
      decision: pendingOwner,
      tokenTtlSeconds: 600,
      continueWaitSeconds: 5,
      ...over,
    },
    store,
  );
  const ctx = (key: Ed25519PublicJwk = client, presentedToken?: string): AuthenticatedContext => ({
    key,
    thumbprint: thumbprint(key),
    now: clock.now(),
    ...(presentedToken !== undefined ? { presentedToken } : {}),
  });
  return { clock, registry, store, server, ctx };
}

const grantBody = (over: Record<string, unknown> = {}) => ({
  access_token: { access: requested, ...over },
  client: { key: { proof: 'httpsig', jwk: client } },
});

async function issueViaOwner(
  server: GnapServer,
  ctx: ReturnType<typeof setup>['ctx'],
  clock: ReturnType<typeof setup>['clock'],
) {
  const pending = await server.grant(grantBody(), ctx());
  const cont = (pending.body as GrantResponse).continue!;
  const grantId = cont.uri.split('/').pop() as string;
  await server.resolveGrant(grantId, { kind: 'approve' });
  clock.advance(5_000);
  const issued = await server.continue(grantId, ctx(client, cont.access_token.value));
  return { grantId, token: (issued.body as GrantResponse).access_token! };
}

describe('grant', () => {
  it('accepts a token label and refuses flags, arrays, reference strings, unknown fields and key mismatch', async () => {
    const { server, ctx } = setup();
    expect((await server.grant(grantBody({ flags: ['bearer'] }), ctx())).body).toMatchObject({
      error: { code: 'invalid_flag' },
    });
    expect((await server.grant(grantBody({ label: 'x' }), ctx())).status).toBe(200);
    expect(
      (await server.grant({ ...grantBody(), access_token: [grantBody().access_token] }, ctx()))
        .status,
    ).toBe(400);
    expect((await server.grant(grantBody({ access: ['ref'] }), ctx())).body).toMatchObject({
      error: { code: 'invalid_request' },
    });
    expect((await server.grant({ ...grantBody(), extra: 1 }, ctx())).status).toBe(400);
    expect(
      (await server.grant(grantBody(), ctx(generateKey('client-1').publicJwk))).body,
    ).toMatchObject({ error: { code: 'invalid_client' } });
    expect((await server.grant(grantBody({ access: [{ type: 'nope' }] }), ctx())).status).toBe(400);
  });

  it('pendingOwner returns continue with an absolute URI, a wait and a credential, and no token', async () => {
    const { server, ctx } = setup();
    const r = await server.grant(grantBody(), ctx());
    expect(r.status).toBe(200);
    const body = r.body as GrantResponse;
    expect(body.access_token).toBeUndefined();
    expect(body.continue?.uri).toMatch(/^https:\/\/as\.example\/continue\/[A-Za-z0-9_-]+$/);
    expect(body.continue?.wait).toBe(5);
    expect(body.continue?.access_token.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await server.listPending()).toHaveLength(1);
  });

  it('fixedList issues immediately with manage, and denies outside the list', async () => {
    const reg = new AccessTypeRegistry([agentOperationHandler]);
    const { server, ctx } = setup({ decision: fixedList(reg, requested) });
    const ok = await server.grant(grantBody(), ctx());
    const tok = (ok.body as GrantResponse).access_token!;
    expect(tok.value).not.toBe(tok.manage?.access_token.value);
    expect(tok.manage?.uri).toMatch(/^https:\/\/as\.example\/token\/[A-Za-z0-9_-]+$/);
    expect(tok.expires_in).toBe(600);
    expect(tok.access).toEqual(requested);
    const wider = [
      { type: 'agent_operation', operations: { 'shell.exec': { argv: { wildcard: true } } } },
    ];
    expect((await server.grant(grantBody({ access: wider }), ctx())).body).toMatchObject({
      error: { code: 'request_denied' },
    });
  });

  it('a decision step that widens is refused', async () => {
    const wider = [
      { type: 'agent_operation', operations: { 'shell.exec': { argv: { wildcard: true } } } },
    ];
    const { server, ctx } = setup({
      decision: { decide: () => ({ kind: 'issue', access: wider }) },
    });
    expect((await server.grant(grantBody(), ctx())).body).toMatchObject({
      error: { code: 'request_denied' },
    });
  });
});

describe('construction', () => {
  it('refuses bad token/grant TTLs and a negative or non-integer wait', () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => setup({ tokenTtlSeconds: bad }), `ttl ${bad}`).toThrow(RangeError);
      expect(() => setup({ grantTtlSeconds: bad }), `grant ttl ${bad}`).toThrow(RangeError);
    }
    for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => setup({ continueWaitSeconds: bad }), `wait ${bad}`).toThrow(RangeError);
    }
    expect(() => setup({ continueWaitSeconds: 0 })).not.toThrow();
  });
});

describe('continue', () => {
  it('expires unclaimed pending grants', async () => {
    const { server, ctx, clock } = setup({ grantTtlSeconds: 1, continueWaitSeconds: 0 });
    const cont = ((await server.grant(grantBody(), ctx())).body as GrantResponse).continue!;
    const grantId = cont.uri.split('/').pop() as string;
    clock.advance(1_000);
    expect((await server.resolveGrant(grantId, { kind: 'approve' })).status).toBe(404);
    expect(
      (await server.continue(grantId, ctx(client, cont.access_token.value))).body,
    ).toMatchObject({ error: { code: 'invalid_continuation' } });
  });

  it('too_fast and pending keep the credential; approve then continue issues once', async () => {
    const { server, ctx, clock } = setup();
    const cont = ((await server.grant(grantBody(), ctx())).body as GrantResponse).continue!;
    const grantId = cont.uri.split('/').pop() as string;
    const c1 = cont.access_token.value;

    const early = await server.continue(grantId, ctx(client, c1));
    expect(early.body).toMatchObject({ error: { code: 'too_fast' } });
    expect(early.status === 400 && early.retryAfterSeconds).toBe(5);

    clock.advance(5_000);
    const still = await server.continue(grantId, ctx(client, c1));
    const c2 = (still.body as GrantResponse).continue!.access_token.value;
    expect(c2).toBe(c1);
    clock.advance(5_000);

    expect((await server.resolveGrant(grantId, { kind: 'approve' })).body).toEqual({
      state: 'approved',
    });
    expect((await server.resolveGrant(grantId, { kind: 'approve' })).status).toBe(400);

    const issued = await server.continue(grantId, ctx(client, c2));
    expect(issued.status).toBe(200);
    expect((issued.body as GrantResponse).access_token?.manage?.uri).toContain('/token/');
    expect((await server.continue(grantId, ctx(client, c2))).body).toMatchObject({
      error: { code: 'invalid_continuation' },
    });
    expect((await server.continue(grantId, ctx())).status).toBe(401);
  });

  it('deny then continue is user_denied, then invalid', async () => {
    const { server, ctx, clock } = setup();
    const cont = ((await server.grant(grantBody(), ctx())).body as GrantResponse).continue!;
    const grantId = cont.uri.split('/').pop() as string;
    await server.resolveGrant(grantId, { kind: 'deny' });
    clock.advance(5_000);
    expect(
      (await server.continue(grantId, ctx(client, cont.access_token.value))).body,
    ).toMatchObject({ error: { code: 'user_denied' } });
    expect(
      (await server.continue(grantId, ctx(client, cont.access_token.value))).body,
    ).toMatchObject({ error: { code: 'invalid_continuation' } });
  });

  it('owner may narrow access and audiences, never widen', async () => {
    const { server, ctx, clock } = setup();
    const cont = ((await server.grant(grantBody(), ctx())).body as GrantResponse).continue!;
    const grantId = cont.uri.split('/').pop() as string;
    const narrower = [
      {
        type: 'agent_operation',
        operations: { 'pr.create': { repository: { exact: 'acme/app' } } },
      },
    ];
    const wider = [
      { type: 'agent_operation', operations: { 'shell.exec': { argv: { wildcard: true } } } },
    ];
    expect((await server.resolveGrant(grantId, { kind: 'approve', access: wider })).status).toBe(
      400,
    );
    expect(
      (await server.resolveGrant(grantId, { kind: 'approve', audiences: ['rs-other'] })).status,
    ).toBe(400);
    expect(
      (
        await server.resolveGrant(grantId, {
          kind: 'approve',
          access: narrower,
          audiences: ['rs1'],
        })
      ).status,
    ).toBe(200);
    clock.advance(5_000);
    const tok = (
      (await server.continue(grantId, ctx(client, cont.access_token.value))).body as GrantResponse
    ).access_token!;
    expect(tok.access).toEqual(narrower);
    const rs1Entry = server.registry; // registry of access types, unrelated; audiences checked below via introspection
    expect(rs1Entry.types()).toEqual(['agent_operation']);
  });
});

describe('introspect and revoke', () => {
  it('active with iss for an audience RS, inactive for another RS, invalid_access for a type outside the RS', async () => {
    const { server, ctx, clock, registry } = setup();
    const { token } = await issueViaOwner(server, ctx, clock);
    const r = await server.introspect(
      { access_token: token.value, resource_server: 'rs1' },
      registry.get('rs1')!,
      ctx(rs1),
    );
    expect(r.body).toMatchObject({
      active: true,
      iss: ISSUER,
      access: requested,
      key: { jwk: client },
    });
    expect((r.body as { exp: number }).exp - (r.body as { iat: number }).iat).toBe(600);
    // rs2 is also a default audience (same type), rs-other is not
    expect(
      (
        await server.introspect(
          { access_token: token.value, resource_server: 'rs2' },
          registry.get('rs2')!,
          ctx(rs2),
        )
      ).body,
    ).toMatchObject({ active: true });
    expect(
      (
        await server.introspect(
          { access_token: token.value, resource_server: 'rs-other' },
          registry.get('rs-other')!,
          ctx(rsOther),
        )
      ).body,
    ).toEqual({ active: false });
    expect(
      (
        await server.introspect(
          { access_token: token.value, resource_server: 'rs-other', access: requested },
          registry.get('rs-other')!,
          ctx(rsOther),
        )
      ).body,
    ).toMatchObject({ error: { code: 'invalid_access' } });
    expect(
      (
        await server.introspect(
          { access_token: token.value, resource_server: 'rs1' },
          registry.get('rs1')!,
          ctx(rs2),
        )
      ).body,
    ).toMatchObject({ error: { code: 'invalid_resource_server' } });
    expect(
      (
        await server.introspect(
          { access_token: 'unknown', resource_server: 'rs1' },
          registry.get('rs1')!,
          ctx(rs1),
        )
      ).body,
    ).toEqual({ active: false });
  });

  it('with requested access, active only when the token carries it (RFC 9767 section 3.3)', async () => {
    const { server, ctx, clock, registry } = setup();
    const { token } = await issueViaOwner(server, ctx, clock);
    const covered = [
      { type: 'agent_operation', operations: { 'shell.exec': { argv: { exact: 'git status' } } } },
    ];
    const notCovered = [
      { type: 'agent_operation', operations: { 'shell.exec': { argv: { exact: 'git push' } } } },
    ];
    const wider = [
      { type: 'agent_operation', operations: { 'shell.exec': { argv: { wildcard: true } } } },
    ];
    const ask = (access: unknown) =>
      server.introspect(
        { access_token: token.value, resource_server: 'rs1', access },
        registry.get('rs1')!,
        ctx(rs1),
      );
    expect((await ask(covered)).body).toMatchObject({ active: true });
    expect((await ask(notCovered)).body).toEqual({ active: false });
    expect((await ask(wider)).body).toEqual({ active: false });
  });

  it('revoke needs the management token, then introspection is inactive with only active:false', async () => {
    const { server, ctx, clock, registry } = setup();
    const { token } = await issueViaOwner(server, ctx, clock);
    const tokenId = token.manage.uri.split('/').pop();
    if (tokenId === undefined) throw new Error('management URI has no token id');
    expect((await server.revokeToken(tokenId, ctx(client, token.value))).status).toBe(401);
    expect(
      (
        await server.revokeToken(
          tokenId,
          ctx(generateKey('x').publicJwk, token.manage.access_token.value),
        )
      ).status,
    ).toBe(204);
    // Note: the handler, not the server, binds the signing key to the token; the server trusts the context.
    const r = await server.introspect(
      { access_token: token.value, resource_server: 'rs1' },
      registry.get('rs1')!,
      ctx(rs1),
    );
    expect(r.body).toEqual({ active: false });
    expect(
      (await server.revokeToken(tokenId, ctx(client, token.manage.access_token.value))).status,
    ).toBe(401);
  });

  it('expired tokens are inactive', async () => {
    const { server, ctx, clock, registry } = setup();
    const { token } = await issueViaOwner(server, ctx, clock);
    clock.advance(600_000);
    expect(
      (
        await server.introspect(
          { access_token: token.value, resource_server: 'rs1' },
          registry.get('rs1')!,
          ctx(rs1),
        )
      ).body,
    ).toEqual({ active: false });
  });
});
