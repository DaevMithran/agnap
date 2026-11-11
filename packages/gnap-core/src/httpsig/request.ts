import type { SignableRequest } from '../types/httpsig.js';

/** The web `Request` the RFC 9421 library signs or verifies. Body only when there is one. */
export function toRequest(request: SignableRequest): Request {
  const init: RequestInit = { method: request.method, headers: request.headers };
  if (request.body.byteLength > 0) init.body = request.body;
  return new Request(request.url, init);
}
