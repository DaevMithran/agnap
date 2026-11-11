/**
 * Every HTTP route of the server, in one place, Express style. Each callback
 * does the same four things in order: find the key without trusting the
 * body, authenticate, parse, call one server function.
 *
 *   POST   /                     grant request            RFC 9635 §2
 *   POST   /continue/:id         continue a grant         RFC 9635 §5
 *   DELETE /token/:id            revoke a token           RFC 9635 §6.2
 *   POST   /introspect           introspection            RFC 9767 §3.3
 */
import { parsePublicJwk, thumbprint } from '@agnap/gnap-core';
import { parseJson, peek } from './body.js';
import { error, respond } from './respond.js';
import type { Router } from './router.js';
import type { RouteDeps } from '../types/http.js';
import type { ResourceServerEntry, ResourceServerRegistry } from '../types/registry.js';

export function registerRoutes(router: Router, deps: RouteDeps): void {
  const { server, store, rsRegistry, authenticate } = deps;

  // RFC 9635 §2. The untrusted key is used only as the candidate verification key.
  router.post('/', async ({ bytes, signable }) => {
    const body = parseJson(bytes);
    const key = parsePublicJwk(peek(body, ['client', 'key', 'jwk']));
    if (key === null) {
      return error(400, 'invalid_request', 'client.key.jwk is required and must be an Ed25519 JWK');
    }
    const ctx = await authenticate(signable, key, 'invalid_client');
    if (ctx instanceof Response) return ctx;
    return respond(await server.grant(body, ctx));
  });

  // RFC 9635 §5. Signed by the key bound to the grant; continuation token in Authorization.
  router.post('/continue/:id', async ({ params, signable }) => {
    const grantId = params.id as string;
    const found = await store.getGrantForVerification(grantId);
    if (found === null) return error(400, 'invalid_continuation');
    const ctx = await authenticate(signable, found.boundKey, 'invalid_client');
    if (ctx instanceof Response) return ctx;
    return respond(await server.continue(grantId, ctx));
  });

  // RFC 9635 §6.2. Signed by the bound key; the token management token, not the access token, in Authorization.
  router.delete('/token/:id', async ({ params, signable }) => {
    const tokenId = params.id as string;
    const found = await store.getTokenForVerification(tokenId);
    if (found === null) return error(401, 'invalid_client');
    const ctx = await authenticate(signable, found.boundKey, 'invalid_client');
    if (ctx instanceof Response) return ctx;
    return respond(await server.revokeToken(tokenId, ctx));
  });

  // RFC 9767 §3.3. Signed by the registered key of the named resource server.
  router.post('/introspect', async ({ bytes, signable }) => {
    const body = parseJson(bytes);
    const rs = lookupResourceServer(peek(body, ['resource_server']), rsRegistry);
    if (rs === null) return error(401, 'invalid_resource_server');
    const ctx = await authenticate(signable, rs.key, 'invalid_resource_server');
    if (ctx instanceof Response) return ctx;
    return respond(await server.introspect(body, rs, ctx));
  });
}

function lookupResourceServer(
  value: unknown,
  registry: ResourceServerRegistry,
): ResourceServerEntry | null {
  if (typeof value === 'string') return registry.get(value);
  if (typeof value === 'object' && value !== null) {
    const key = parsePublicJwk((value as { key?: { jwk?: unknown } }).key?.jwk);
    return key === null ? null : registry.byThumbprint(thumbprint(key));
  }
  return null;
}
