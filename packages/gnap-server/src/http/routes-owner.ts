/** Local owner extension routes. These are implementation-specific and not part of GNAP. */
import { timingSafeEqual } from 'node:crypto';
import { thumbprint } from '@agnap/gnap-core';
import { parseJson } from './body.js';
import { error, json, respond } from './respond.js';
import type { Router } from './router.js';
import { validateOwnerResolution } from '../schemas/index.js';
import type { RouteDeps } from '../types/http.js';
import type { OwnerResolution } from '../types/server.js';

export function registerOwnerRoutes(router: Router, deps: RouteDeps): void {
  if (deps.localOwner === undefined) return;
  const { server } = deps;
  const secret = deps.localOwner.secret;
  // An empty secret would compare equal to a missing Authorization header.
  if (secret.length === 0) throw new RangeError('localOwner.secret must not be empty');

  router.get('/local/grants', async ({ request }) => {
    if (!ownerAuthorized(request, secret))
      return error(401, 'invalid_request', 'owner secret required');
    const pending = await server.listPending();
    return json(200, {
      grants: pending.map((grant) => ({
        id: grant.id,
        created_at: new Date(grant.createdAt).toISOString(),
        expires_at: new Date(grant.expiresAt).toISOString(),
        client_kid: grant.clientKey.kid,
        client_thumbprint: thumbprint(grant.clientKey),
        requested_access: grant.requestedAccess,
      })),
    });
  });

  router.post('/local/grants/:id', async ({ request, params, bytes }) => {
    if (!ownerAuthorized(request, secret))
      return error(401, 'invalid_request', 'owner secret required');
    const body = parseJson(bytes);
    if (body === undefined) return error(400, 'invalid_request', 'JSON body expected');
    const resolution = parseOwnerResolution(body);
    if (resolution === null)
      return error(400, 'invalid_request', 'decision must be approve or deny');
    return respond(await server.resolveGrant(params.id as string, resolution));
  });
}

function ownerAuthorized(request: Request, secret: string): boolean {
  const header = request.headers.get('authorization');
  if (header === null || secret.length === 0) return false;
  const presented = header.replace(/^Bearer\s+/i, '');
  if (presented.length === 0) return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(secret);
  return a.length === b.length && timingSafeEqual(a, b);
}

function parseOwnerResolution(body: unknown): OwnerResolution | null {
  if (!validateOwnerResolution(body)) return null;
  if (body.decision === 'deny') return { kind: 'deny' };
  const resolution: OwnerResolution = { kind: 'approve' };
  if (body.access !== undefined) resolution.access = body.access;
  if (body.audiences !== undefined) resolution.audiences = body.audiences;
  return resolution;
}
