import { errorResponse } from '@agnap/gnap-core';
import type { ErrorResponse } from '@agnap/gnap-core';
import type { Result } from '../types/server.js';

export function json(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers },
  });
}

export function error(
  status: number,
  code: ErrorResponse['error']['code'],
  description?: string,
  headers: Record<string, string> = {},
): Response {
  return json(status, errorResponse(code, description), headers);
}

/** Serialize a protocol result. 204 has no body; `too_fast` carries Retry-After. */
export function respond(result: Result<unknown>): Response {
  if (result.status === 204) return new Response(null, { status: 204 });
  const headers: Record<string, string> = {};
  if ('retryAfterSeconds' in result && result.retryAfterSeconds !== undefined) {
    headers['retry-after'] = String(result.retryAfterSeconds);
  }
  return json(result.status, result.body, headers);
}
