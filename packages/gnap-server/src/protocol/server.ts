/**
 * The protocol, with no HTTP in it. Every function takes a parsed message
 * and an `AuthenticatedContext` the handler built after verifying the
 * request signature. Results carry an HTTP status only so the handler does
 * not have to map codes a second time.
 */
import {
  AccessParseError,
  AccessTypeRegistry,
  errorResponse,
  formatIssues,
  randomToken,
  sameKey,
  sha256Base64url,
  typesOf,
  validateGrantRequest,
  validateIntrospectionRequest,
} from '@agnap/gnap-core';
import type {
  AccessItem,
  GnapErrorCode,
  GrantResponse,
  IntrospectionErrorCode,
  IntrospectionResponse,
} from '@agnap/gnap-core';

import {
  DEFAULT_CONTINUE_WAIT_SECONDS,
  DEFAULT_GRANT_TTL_SECONDS,
  DEFAULT_TOKEN_TTL_SECONDS,
} from '../config.js';
import type { GrantRecord, TokenRecord } from '../types/records.js';
import type { ResourceServerRegistry } from '../types/registry.js';
import type { GnapServer, Result, ServerConfig } from '../types/server.js';
import { StoreCapacityError } from '../types/store.js';
import type { Resolution, Store } from '../types/store.js';

const err = (
  status: 400 | 401 | 403 | 404 | 503,
  code: GnapErrorCode | IntrospectionErrorCode,
  description?: string,
  retryAfterSeconds?: number,
): Result<never> => {
  const body = errorResponse(code, description);
  return retryAfterSeconds === undefined ? { status, body } : { status, body, retryAfterSeconds };
};

export function createServer(config: ServerConfig, store: Store): GnapServer {
  const registry = new AccessTypeRegistry(config.accessTypes);
  const ttlSeconds = config.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
    throw new RangeError(`tokenTtlSeconds must be a positive integer, got ${String(ttlSeconds)}`);
  }
  const waitSeconds = config.continueWaitSeconds ?? DEFAULT_CONTINUE_WAIT_SECONDS;
  if (!Number.isInteger(waitSeconds) || waitSeconds < 0) {
    throw new RangeError(
      `continueWaitSeconds must be a non-negative integer, got ${String(waitSeconds)}`,
    );
  }
  const grantTtlSeconds = config.grantTtlSeconds ?? DEFAULT_GRANT_TTL_SECONDS;
  if (!Number.isInteger(grantTtlSeconds) || grantTtlSeconds <= 0) {
    throw new RangeError(
      `grantTtlSeconds must be a positive integer, got ${String(grantTtlSeconds)}`,
    );
  }
  const ttlMs = ttlSeconds * 1000;
  const grantTtlMs = grantTtlSeconds * 1000;
  const origin = new URL(config.issuer).origin;
  const selectAudiences = config.selectAudiences ?? defaultSelectAudiences;

  const continueUri = (grantId: string) => `${origin}/continue/${grantId}`;
  const manageUri = (tokenId: string) => `${origin}/token/${tokenId}`;

  /** Build a token record plus the two secrets. The secrets leave in the response and are never stored. */
  function mintToken(grant: GrantRecord, access: AccessItem[], audiences: string[], now: number) {
    const value = randomToken(32);
    const management = randomToken(32);
    const token: TokenRecord = {
      id: randomToken(12),
      accessHash: sha256Base64url(value),
      managementHash: sha256Base64url(management),
      grantId: grant.id,
      boundKey: grant.clientKey,
      access,
      audiences,
      issuedAt: now,
      expiresAt: now + ttlMs,
      revoked: false,
    };
    return { token, value, management };
  }

  function tokenResponse(
    token: TokenRecord,
    value: string,
    management: string,
    now: number,
  ): GrantResponse {
    return {
      access_token: {
        value,
        access: token.access,
        expires_in: Math.max(1, Math.floor((token.expiresAt - now) / 1000)),
        manage: { uri: manageUri(token.id), access_token: { value: management } },
      },
    };
  }

  function pendingResponse(grantId: string, continuation: string): GrantResponse {
    return {
      continue: {
        uri: continueUri(grantId),
        wait: waitSeconds,
        access_token: { value: continuation },
      },
    };
  }

  return {
    registry,
    issuer: config.issuer,

    async grant(body, ctx) {
      if (!validateGrantRequest(body)) {
        return err(400, 'invalid_request', formatIssues(validateGrantRequest.errors));
      }
      const { access_token: at, client } = body;
      if (at.flags !== undefined && at.flags.length > 0) {
        return err(400, 'invalid_flag', `flags are not supported: ${at.flags.join(', ')}`);
      }
      // The handler verified the signature against the key it found in the body. Check it is the same one.
      if (!sameKey(client.key.jwk, ctx.key)) {
        return err(401, 'invalid_client', 'client.key does not match the signing key');
      }

      let requestedAccess: AccessItem[];
      try {
        requestedAccess = registry.parseAll(at.access);
      } catch (e) {
        if (e instanceof AccessParseError) return err(400, 'invalid_request', e.message);
        throw e;
      }

      const decision = await config.decision.decide({
        requestedAccess,
        clientKey: ctx.key,
        clientThumbprint: ctx.thumbprint,
        now: ctx.now,
      });

      const grant: GrantRecord = {
        id: randomToken(12),
        clientKey: ctx.key,
        requestedAccess,
        state: 'pending',
        createdAt: ctx.now,
        expiresAt: ctx.now + grantTtlMs,
        continuationHash: null,
        notBefore: ctx.now,
      };
      const display = client.display;
      if (display?.name !== undefined || display?.uri !== undefined) {
        grant.clientDisplay = {
          ...(display.name !== undefined ? { name: display.name } : {}),
          ...(display.uri !== undefined ? { uri: display.uri } : {}),
        };
      }

      switch (decision.kind) {
        case 'deny':
          return err(403, decision.code, decision.description);
        case 'issue': {
          if (!registry.containsAll(requestedAccess, decision.access)) {
            return err(403, 'request_denied', 'decision step tried to widen the request');
          }
          const audiences = selectAudiences(decision.access, config.registry);
          const { token, value, management } = mintToken(
            grant,
            decision.access,
            audiences,
            ctx.now,
          );
          await store.createGrant(
            {
              ...grant,
              state: 'issued',
              decidedAccess: decision.access,
              decidedAudiences: audiences,
              tokenId: token.id,
            },
            token,
          );
          return { status: 200, body: tokenResponse(token, value, management, ctx.now) };
        }
        case 'pending': {
          const continuation = randomToken(32);
          try {
            await store.createGrant({
              ...grant,
              continuationHash: sha256Base64url(continuation),
              notBefore: ctx.now + waitSeconds * 1000,
            });
          } catch (error) {
            if (error instanceof StoreCapacityError) {
              // RFC 9635 has no overload-specific grant error. `too_many_attempts`
              // is the closest registered code, though its intended meaning is
              // excessive interaction attempts rather than store capacity.
              return err(503, 'too_many_attempts', error.message);
            }
            throw error;
          }
          return { status: 200, body: pendingResponse(grant.id, continuation) };
        }
      }
    },

    async continue(grantId, ctx) {
      if (ctx.presentedToken === undefined)
        return err(401, 'invalid_continuation', 'continuation token is required');
      const minted: { current: { value: string; management: string } | null } = { current: null };
      const outcome = await store.advanceContinuation(grantId, {
        oldHash: sha256Base64url(ctx.presentedToken),
        now: ctx.now,
        nextNotBefore: ctx.now + waitSeconds * 1000,
        mint: (record) => {
          const access = record.decidedAccess ?? record.requestedAccess;
          const audiences = record.decidedAudiences ?? selectAudiences(access, config.registry);
          const m = mintToken(record, access, audiences, ctx.now);
          minted.current = { value: m.value, management: m.management };
          return m.token;
        },
      });
      switch (outcome.kind) {
        case 'invalid':
          return err(400, 'invalid_continuation');
        case 'too_fast':
          return err(400, 'too_fast', undefined, outcome.retryAfterSeconds);
        case 'denied':
          return err(403, outcome.code);
        case 'pending':
          return { status: 200, body: pendingResponse(grantId, ctx.presentedToken) };
        case 'issued': {
          const m = minted.current;
          if (m === null) throw new Error('store reported issued without calling mint');
          return {
            status: 200,
            body: tokenResponse(outcome.token, m.value, m.management, ctx.now),
          };
        }
      }
    },

    async revokeToken(tokenId, ctx) {
      if (ctx.presentedToken === undefined)
        return err(401, 'invalid_client', 'token management access token is required');
      const ok = await store.revokeToken(tokenId, sha256Base64url(ctx.presentedToken));
      return ok ? { status: 204, body: undefined } : err(401, 'invalid_client');
    },

    async introspect(body, rs, ctx) {
      if (!validateIntrospectionRequest(body)) {
        return err(400, 'invalid_request', formatIssues(validateIntrospectionRequest.errors));
      }
      const request = body;
      if (!sameKey(rs.key, ctx.key)) return err(401, 'invalid_resource_server');

      let requested: AccessItem[] | null = null;
      if (request.access !== undefined) {
        try {
          requested = registry.parseAll(request.access);
        } catch (e) {
          if (e instanceof AccessParseError) return err(400, 'invalid_request', e.message);
          throw e;
        }
        for (const t of typesOf(requested)) {
          if (!rs.accessTypes.includes(t))
            return err(403, 'invalid_access', `this resource server may not introspect for ${t}`);
        }
      }

      const inactive: Result<IntrospectionResponse> = { status: 200, body: { active: false } };
      const token = await store.getTokenByAccessHash(sha256Base64url(request.access_token));
      if (token === null || token.revoked || token.expiresAt <= ctx.now) return inactive;
      if (!token.audiences.includes(rs.id)) return inactive;
      if (![...typesOf(token.access)].every((t) => rs.accessTypes.includes(t))) return inactive;
      // RFC 9767 section 3.3: when the RS states the access it needs, the token is active only if it carries it.
      if (requested !== null && !registry.containsAll(token.access, requested)) return inactive;

      return {
        status: 200,
        body: {
          active: true,
          access: token.access,
          key: { proof: 'httpsig', jwk: token.boundKey },
          iss: config.issuer,
          exp: Math.floor(token.expiresAt / 1000),
          iat: Math.floor(token.issuedAt / 1000),
          // Until child grants exist every grant is its own root.
          root_grant: token.grantId,
        },
      };
    },

    async resolveGrant(grantId, resolution) {
      const grant = await store.getGrant(grantId);
      if (grant === null) return err(404, 'invalid_request', 'unknown grant');
      if (grant.state !== 'pending') return err(400, 'invalid_request', `grant is ${grant.state}`);
      let r: Resolution;
      if (resolution.kind === 'deny') {
        r = { kind: 'deny', code: 'user_denied' };
      } else {
        const access = resolution.access ?? grant.requestedAccess;
        if (!registry.containsAll(grant.requestedAccess, access)) {
          return err(
            400,
            'invalid_request',
            'approved access must be contained in the requested access',
          );
        }
        const allowed = selectAudiences(access, config.registry);
        const audiences = resolution.audiences ?? allowed;
        if (!audiences.every((a) => allowed.includes(a))) {
          return err(
            400,
            'invalid_request',
            'audiences must be resource servers that can serve this access',
          );
        }
        r = { kind: 'approve', access, audiences };
      }
      const ok = await store.resolvePendingGrant(grantId, r);
      return ok
        ? { status: 200, body: { state: r.kind === 'approve' ? 'approved' : 'denied' } }
        : err(400, 'invalid_request', 'grant is no longer pending');
    },

    listPending() {
      return store.listGrants('pending');
    },
  };
}

/** Every registered resource server whose permitted types cover every item in the access. */
export function defaultSelectAudiences(
  access: AccessItem[],
  registry: ResourceServerRegistry,
): string[] {
  const types = [...typesOf(access)];
  return registry
    .all()
    .filter((rs) => types.every((t) => rs.accessTypes.includes(t)))
    .map((rs) => rs.id);
}
