import { systemClock } from '@agnap/gnap-core';
import type { Clock, Ed25519PublicJwk, NonceClaim } from '@agnap/gnap-core';

import type { GrantRecord, GrantState, TokenRecord } from '../types/records.js';
import { StoreCapacityError } from '../types/store.js';
import type {
  ContinuationAdvance,
  ContinuationOutcome,
  MemoryStoreOptions,
  Resolution,
  Store,
} from '../types/store.js';

/* eslint-disable @typescript-eslint/require-await -- the Store interface is async for database implementations; the memory one has nothing to await and must not, so each method stays atomic */

/**
 * In memory. Node runs one JavaScript thread, so each method body below is
 * atomic as long as it does not await between read and write. None does.
 */
export class MemoryStore implements Store {
  readonly #grants = new Map<string, GrantRecord>();
  readonly #tokens = new Map<string, TokenRecord>();
  readonly #tokensByAccessHash = new Map<string, string>();
  readonly #nonces = new Map<string, number>();
  readonly #clock: Clock;
  readonly #maxNonces: number;
  readonly #maxPendingGrants: number;

  constructor(options: MemoryStoreOptions = {}) {
    this.#clock = options.clock ?? systemClock;
    const max = options.maxNonces ?? 100_000;
    if (!Number.isInteger(max) || max <= 0) {
      throw new RangeError(`maxNonces must be a positive integer, got ${String(max)}`);
    }
    this.#maxNonces = max;
    const maxPendingGrants = options.maxPendingGrants ?? 10_000;
    if (!Number.isInteger(maxPendingGrants) || maxPendingGrants <= 0) {
      throw new RangeError(
        `maxPendingGrants must be a positive integer, got ${String(maxPendingGrants)}`,
      );
    }
    this.#maxPendingGrants = maxPendingGrants;
  }

  async createGrant(record: GrantRecord, token?: TokenRecord): Promise<void> {
    this.#sweepExpiredState();
    if (this.#grants.has(record.id)) throw new Error(`grant ${record.id} exists`);
    if (
      record.state === 'pending' &&
      [...this.#grants.values()].filter(
        (grant) => grant.state === 'pending' || grant.state === 'approved',
      ).length >= this.#maxPendingGrants
    ) {
      throw new StoreCapacityError('pending grant capacity reached');
    }
    this.#grants.set(record.id, { ...record });
    if (token !== undefined) this.#putToken(token);
  }

  async getGrantForVerification(id: string): Promise<{
    boundKey: Ed25519PublicJwk;
    state: GrantState;
    continuationHash: string | null;
  } | null> {
    this.#sweepExpiredState();
    const g = this.#grants.get(id);
    return g === undefined
      ? null
      : { boundKey: g.clientKey, state: g.state, continuationHash: g.continuationHash };
  }

  async getGrant(id: string): Promise<GrantRecord | null> {
    this.#sweepExpiredState();
    const g = this.#grants.get(id);
    return g === undefined ? null : { ...g };
  }

  async listGrants(state?: GrantState): Promise<GrantRecord[]> {
    this.#sweepExpiredState();
    return [...this.#grants.values()]
      .filter((g) => state === undefined || g.state === state)
      .map((g) => ({ ...g }));
  }

  async advanceContinuation(id: string, a: ContinuationAdvance): Promise<ContinuationOutcome> {
    this.#sweepExpiredTokens(a.now);
    const g = this.#grants.get(id);
    if (g !== undefined && this.#isExpired(g, a.now)) {
      this.#grants.delete(id);
      return { kind: 'invalid' };
    }
    if (g === undefined || g.continuationHash === null || g.continuationHash !== a.oldHash)
      return { kind: 'invalid' };
    if (a.now < g.notBefore)
      return { kind: 'too_fast', retryAfterSeconds: Math.ceil((g.notBefore - a.now) / 1000) };
    switch (g.state) {
      case 'pending':
        g.notBefore = a.nextNotBefore;
        return { kind: 'pending', record: { ...g } };
      case 'approved': {
        const token = a.mint({ ...g });
        this.#putToken(token);
        g.state = 'issued';
        g.tokenId = token.id;
        g.continuationHash = null;
        return { kind: 'issued', token: { ...token } };
      }
      case 'denied':
        g.continuationHash = null;
        return { kind: 'denied', code: g.denyCode ?? 'request_denied' };
      case 'issued':
        return { kind: 'invalid' };
    }
  }

  async resolvePendingGrant(id: string, r: Resolution): Promise<boolean> {
    this.#sweepExpiredState();
    const g = this.#grants.get(id);
    if (g === undefined || g.state !== 'pending') return false;
    g.notBefore = 0;
    if (r.kind === 'approve') {
      g.state = 'approved';
      g.decidedAccess = r.access;
      g.decidedAudiences = r.audiences;
    } else {
      g.state = 'denied';
      g.denyCode = r.code;
    }
    return true;
  }

  async getTokenForVerification(
    id: string,
  ): Promise<{ boundKey: Ed25519PublicJwk; managementHash: string; revoked: boolean } | null> {
    this.#sweepExpiredState();
    const t = this.#tokens.get(id);
    return t === undefined
      ? null
      : { boundKey: t.boundKey, managementHash: t.managementHash, revoked: t.revoked };
  }

  async revokeToken(id: string, managementHash: string): Promise<boolean> {
    this.#sweepExpiredState();
    const t = this.#tokens.get(id);
    if (t === undefined || t.managementHash !== managementHash || t.revoked) return false;
    t.revoked = true;
    return true;
  }

  async getTokenByAccessHash(hash: string): Promise<TokenRecord | null> {
    this.#sweepExpiredState();
    const id = this.#tokensByAccessHash.get(hash);
    const t = id === undefined ? undefined : this.#tokens.get(id);
    return t === undefined ? null : { ...t };
  }

  async claimNonce(keyThumbprint: string, nonce: string, expiresAt: number): Promise<NonceClaim> {
    const now = this.#clock.now();
    this.#sweepExpiredState(now);
    // The verifier accepts `created` at whole-second granularity, so a signature stays valid
    // through the end of the second in which it expires. Keep the nonce one second longer.
    const keepUntil = expiresAt + 1000;
    const key = `${keyThumbprint}\u0000${nonce}`;
    const existing = this.#nonces.get(key);
    if (existing !== undefined && existing >= now) return 'seen';
    if (this.#nonces.size >= this.#maxNonces) {
      for (const [k, exp] of this.#nonces) if (exp < now) this.#nonces.delete(k);
      if (this.#nonces.size >= this.#maxNonces) return 'full';
    }
    this.#nonces.set(key, keepUntil);
    return 'fresh';
  }

  #putToken(token: TokenRecord): void {
    if (this.#tokens.has(token.id)) throw new Error(`token ${token.id} exists`);
    this.#tokens.set(token.id, { ...token });
    this.#tokensByAccessHash.set(token.accessHash, token.id);
  }

  #isExpired(grant: GrantRecord, now = this.#clock.now()): boolean {
    return grant.state !== 'issued' && grant.expiresAt <= now;
  }

  #sweepExpiredState(now = this.#clock.now()): void {
    this.#sweepExpiredTokens(now);
    for (const [id, grant] of this.#grants) {
      if (this.#isExpired(grant, now)) this.#grants.delete(id);
    }
  }

  #sweepExpiredTokens(now: number): void {
    for (const [id, token] of this.#tokens) {
      if (token.expiresAt > now) continue;
      this.#tokens.delete(id);
      if (this.#tokensByAccessHash.get(token.accessHash) === id) {
        this.#tokensByAccessHash.delete(token.accessHash);
      }
      const grant = this.#grants.get(token.grantId);
      if (grant?.state === 'issued' && grant.tokenId === id) this.#grants.delete(grant.id);
    }
  }
}
