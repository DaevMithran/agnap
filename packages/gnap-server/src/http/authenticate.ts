/**
 * Signature verification for a route. The route chooses the key (from the
 * body for grant, from the stored grant or token for continue and revoke,
 * from the registry for introspection) and the error code to use when the
 * signature fails. Nothing semantic happens before this succeeds.
 */
import { gnapAuthorizationValue, HttpSigError, systemClock, verifyRequest } from '@agnap/gnap-core';
import { error } from './respond.js';
import type { Authenticate, AuthenticateOptions } from '../types/http.js';
import type { AuthenticatedContext } from '../types/server.js';

export function makeAuthenticate(opts: AuthenticateOptions): Authenticate {
  const clock = opts.clock ?? systemClock;
  return async (signable, key, failureCode) => {
    try {
      const verified = await verifyRequest(signable, {
        publicJwk: key,
        clock,
        ...(opts.createdWindowSeconds !== undefined
          ? { createdWindowSeconds: opts.createdWindowSeconds }
          : {}),
        nonceCheck: async ({ nonce, keyThumbprint, expiresAt }) =>
          opts.store.claimNonce(keyThumbprint, nonce, expiresAt),
      });
      const presented = gnapAuthorizationValue(signable.headers.get('authorization'));
      const ctx: AuthenticatedContext = {
        key,
        thumbprint: verified.keyThumbprint,
        now: clock.now(),
      };
      if (presented !== null) ctx.presentedToken = presented;
      return ctx;
    } catch (e) {
      if (e instanceof HttpSigError) {
        // A full replay cache is the server's problem, not the client's: 503 with a hint to retry.
        if (e.code === 'overloaded') {
          return error(503, 'invalid_request', e.message, { 'retry-after': '1' });
        }
        return error(401, failureCode, e.message);
      }
      throw e;
    }
  };
}
