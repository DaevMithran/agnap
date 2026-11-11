/**
 * The fetch handler: `(Request) => Promise<Response>`. Any framework that
 * speaks the web Request can mount it. The package targets Node today: it
 * uses `node:crypto` and `Buffer`, so other runtimes need those shims. This
 * file only wires things: bound the body, build the signable request,
 * dispatch to the routes in `routes.ts`.
 */
import { DEFAULT_MAX_BODY_BYTES } from '../config.js';
import { makeAuthenticate } from './authenticate.js';
import { readBodyLimited, resolveTargetUri } from './body.js';
import { error } from './respond.js';
import { Router } from './router.js';
import { registerRoutes } from './routes.js';
import { registerOwnerRoutes } from './routes-owner.js';
import type { FetchHandler, HandlerOptions, Method } from '../types/http.js';

const METHODS: ReadonlySet<string> = new Set<Method>(['GET', 'POST', 'DELETE']);

/** A body limit must be a positive finite integer, or the comparisons that enforce it silently pass. */
export function checkBodyLimit(limit: number): number {
  if (!Number.isInteger(limit) || limit <= 0) {
    throw new RangeError(`maxBodyBytes must be a positive integer, got ${String(limit)}`);
  }
  return limit;
}

export function createHandler(opts: HandlerOptions): FetchHandler {
  const maxBody = checkBodyLimit(opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES);
  if (opts.localOwner !== undefined && opts.localOwner.secret.length === 0) {
    throw new RangeError('localOwner.secret must not be empty');
  }
  const router = new Router();
  const routeDeps = {
    server: opts.server,
    store: opts.store,
    rsRegistry: opts.rsRegistry,
    authenticate: makeAuthenticate({
      store: opts.store,
      ...(opts.clock !== undefined ? { clock: opts.clock } : {}),
      ...(opts.createdWindowSeconds !== undefined
        ? { createdWindowSeconds: opts.createdWindowSeconds }
        : {}),
    }),
    ...(opts.localOwner !== undefined ? { localOwner: opts.localOwner } : {}),
  };
  registerRoutes(router, routeDeps);
  registerOwnerRoutes(router, routeDeps);

  return async function handle(request: Request): Promise<Response> {
    const method = request.method.toUpperCase();
    if (!METHODS.has(method)) return error(404, 'invalid_request', 'not found');
    const path = new URL(request.url).pathname.replace(/\/+$/, '') || '/';

    // Bound the body before any route logic, signed or not.
    const bytes = await readBodyLimited(request, maxBody);
    if (bytes === null) {
      return error(413, 'invalid_request', `request body exceeds ${maxBody} bytes`);
    }

    const response = await router.dispatch({
      request,
      method: method as Method,
      path,
      bytes,
      signable: {
        method,
        url: resolveTargetUri(request.url, opts.publicUrl),
        headers: request.headers,
        body: bytes,
      },
    });
    return response ?? error(404, 'invalid_request', 'not found');
  };
}
