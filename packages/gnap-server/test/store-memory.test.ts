import { fixedClock, generateKey } from '@agnap/gnap-core';
import { describe, expect, it } from 'vitest';
import { MemoryStore } from '../src/index.js';
import type { ContinuationAdvance, GrantRecord, TokenRecord } from '../src/index.js';

const key = generateKey('c').publicJwk;
const access = [{ type: 't', x: 1 }];

function grant(over: Partial<GrantRecord> = {}): GrantRecord {
  return {
    id: 'g1',
    clientKey: key,
    requestedAccess: access,
    state: 'pending',
    createdAt: 1000,
    expiresAt: Number.MAX_SAFE_INTEGER,
    continuationHash: 'h1',
    notBefore: 2000,
    ...over,
  };
}

const mint = (g: GrantRecord): TokenRecord => ({
  id: 'tok',
  accessHash: 'ah',
  managementHash: 'mh',
  grantId: g.id,
  boundKey: g.clientKey,
  access: g.decidedAccess ?? g.requestedAccess,
  audiences: g.decidedAudiences ?? [],
  issuedAt: 5000,
  expiresAt: Number.MAX_SAFE_INTEGER,
  revoked: false,
});

const adv = (over: Partial<ContinuationAdvance> = {}): ContinuationAdvance => ({
  oldHash: 'h1',
  now: 3000,
  nextNotBefore: 8000,
  mint,
  ...over,
});

describe('MemoryStore.advanceContinuation', () => {
  it('wrong hash is invalid and changes nothing', async () => {
    const s = new MemoryStore();
    await s.createGrant(grant());
    expect(await s.advanceContinuation('g1', adv({ oldHash: 'nope' }))).toEqual({
      kind: 'invalid',
    });
    expect((await s.getGrant('g1'))?.continuationHash).toBe('h1');
    expect(await s.advanceContinuation('missing', adv())).toEqual({ kind: 'invalid' });
  });

  it('early is too_fast and keeps the credential', async () => {
    const s = new MemoryStore();
    await s.createGrant(grant());
    expect(await s.advanceContinuation('g1', adv({ now: 1500 }))).toEqual({
      kind: 'too_fast',
      retryAfterSeconds: 1,
    });
    expect((await s.getGrant('g1'))?.continuationHash).toBe('h1');
  });

  it('pending keeps the credential and advances notBefore', async () => {
    const s = new MemoryStore();
    await s.createGrant(grant());
    const out = await s.advanceContinuation('g1', adv());
    expect(out.kind).toBe('pending');
    const g = await s.getGrant('g1');
    expect(g?.continuationHash).toBe('h1');
    expect(g?.notBefore).toBe(8000);
    expect(await s.advanceContinuation('g1', adv({ now: 7000 }))).toMatchObject({
      kind: 'too_fast',
    });
  });

  it('a decided grant is answered before its polling time', async () => {
    const approved = new MemoryStore();
    await approved.createGrant(grant());
    await approved.resolvePendingGrant('g1', { kind: 'approve', access, audiences: [] });
    expect(await approved.advanceContinuation('g1', adv({ now: 1500 }))).toMatchObject({
      kind: 'issued',
    });

    const denied = new MemoryStore();
    await denied.createGrant(grant());
    await denied.resolvePendingGrant('g1', { kind: 'deny', code: 'user_denied' });
    expect(await denied.advanceContinuation('g1', adv({ now: 1500 }))).toEqual({
      kind: 'denied',
      code: 'user_denied',
    });
  });

  it('expires pending and approved grants before resolution or continuation', async () => {
    const clock = fixedClock(9_999);
    const s = new MemoryStore({ clock });
    await s.createGrant(grant({ expiresAt: 10_000 }));
    clock.advance(1);
    expect(await s.getGrant('g1')).toBeNull();
    expect(await s.resolvePendingGrant('g1', { kind: 'approve', access, audiences: [] })).toBe(
      false,
    );
    expect(await s.advanceContinuation('g1', adv({ now: clock.now() }))).toEqual({
      kind: 'invalid',
    });
  });

  it('approved mints once, clears the credential, and a racing second call is invalid', async () => {
    const s = new MemoryStore();
    await s.createGrant(grant());
    expect(await s.resolvePendingGrant('g1', { kind: 'approve', access, audiences: ['rs1'] })).toBe(
      true,
    );
    const [a, b] = await Promise.all([
      s.advanceContinuation('g1', adv()),
      s.advanceContinuation('g1', adv()),
    ]);
    const kinds = [a.kind, b.kind].sort();
    expect(kinds).toEqual(['invalid', 'issued']);
    const g = await s.getGrant('g1');
    expect(g?.state).toBe('issued');
    expect(g?.continuationHash).toBeNull();
    expect(g?.tokenId).toBe('tok');
    expect((await s.getTokenByAccessHash('ah'))?.audiences).toEqual(['rs1']);
  });

  it('denied reports the code and clears the credential', async () => {
    const s = new MemoryStore();
    await s.createGrant(grant());
    await s.resolvePendingGrant('g1', { kind: 'deny', code: 'user_denied' });
    expect(await s.advanceContinuation('g1', adv())).toEqual({
      kind: 'denied',
      code: 'user_denied',
    });
    expect(await s.advanceContinuation('g1', adv())).toEqual({ kind: 'invalid' });
  });

  it('resolve succeeds once', async () => {
    const s = new MemoryStore();
    await s.createGrant(grant());
    const [a, b] = await Promise.all([
      s.resolvePendingGrant('g1', { kind: 'approve', access, audiences: [] }),
      s.resolvePendingGrant('g1', { kind: 'deny', code: 'user_denied' }),
    ]);
    expect([a, b]).toEqual([true, false]);
    expect((await s.getGrant('g1'))?.state).toBe('approved');
  });
});

describe('MemoryStore tokens and nonces', () => {
  it('sweeps expired tokens and their issued grant records', async () => {
    const clock = fixedClock(1_000);
    const s = new MemoryStore({ clock });
    const issuedGrant = grant({
      state: 'issued',
      continuationHash: null,
      tokenId: 'tok',
    });
    await s.createGrant(issuedGrant, { ...mint(issuedGrant), expiresAt: 2_000 });
    clock.advance(1_000);
    expect(await s.getTokenByAccessHash('ah')).toBeNull();
    expect(await s.getTokenForVerification('tok')).toBeNull();
    expect(await s.getGrant('g1')).toBeNull();
  });

  it('revoke needs the management hash and works once', async () => {
    const s = new MemoryStore();
    await s.createGrant(grant({ state: 'issued', continuationHash: null }), mint(grant()));
    expect(await s.revokeToken('tok', 'ah')).toBe(false);
    expect(await s.revokeToken('tok', 'mh')).toBe(true);
    expect(await s.revokeToken('tok', 'mh')).toBe(false);
    expect((await s.getTokenByAccessHash('ah'))?.revoked).toBe(true);
    expect(await s.getTokenForVerification('tok')).toMatchObject({
      managementHash: 'mh',
      revoked: true,
    });
  });

  it('nonce claims are per key, use the injected clock, and hold through the final accepted second', async () => {
    const clock = fixedClock(1_000_000);
    const s = new MemoryStore({ clock });
    const expiresAt = clock.now() + 60_000;
    expect(await s.claimNonce('k1', 'n', expiresAt)).toBe('fresh');
    expect(await s.claimNonce('k1', 'n', expiresAt)).toBe('seen');
    expect(await s.claimNonce('k2', 'n', expiresAt)).toBe('fresh');
    clock.set(expiresAt);
    expect(await s.claimNonce('k1', 'n', expiresAt)).toBe('seen');
    clock.set(expiresAt + 999);
    expect(await s.claimNonce('k1', 'n', expiresAt)).toBe('seen');
    clock.set(expiresAt + 1001);
    expect(await s.claimNonce('k1', 'n', expiresAt + 1001 + 60_000)).toBe('fresh');
  });

  it('nonce map is bounded: sweeps expired entries, then reports full rather than seen', async () => {
    const clock = fixedClock(1_000_000);
    const s = new MemoryStore({ clock, maxNonces: 3 });
    const soon = clock.now() + 1_000;
    expect(await s.claimNonce('k', 'a', soon)).toBe('fresh');
    expect(await s.claimNonce('k', 'b', soon)).toBe('fresh');
    expect(await s.claimNonce('k', 'c', soon)).toBe('fresh');
    expect(await s.claimNonce('k', 'd', soon)).toBe('full');
    expect(await s.claimNonce('k', 'a', soon)).toBe('seen');
    clock.advance(2_001);
    expect(await s.claimNonce('k', 'd', clock.now() + 1_000)).toBe('fresh');
  });

  it('refuses a non-positive or fractional nonce capacity', () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => new MemoryStore({ maxNonces: bad }), String(bad)).toThrow(RangeError);
    }
  });

  it('bounds live pending grants and reclaims expired capacity', async () => {
    const clock = fixedClock(1_000);
    const s = new MemoryStore({ clock, maxPendingGrants: 1 });
    await s.createGrant(grant({ expiresAt: 2_000 }));
    await expect(s.createGrant(grant({ id: 'g2', expiresAt: 3_000 }))).rejects.toThrow(/capacity/);
    clock.advance(1_000);
    await expect(s.createGrant(grant({ id: 'g2', expiresAt: 3_000 }))).resolves.toBeUndefined();
  });

  it('refuses a non-positive or fractional pending-grant capacity', () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => new MemoryStore({ maxPendingGrants: bad }), String(bad)).toThrow(RangeError);
    }
  });
});
