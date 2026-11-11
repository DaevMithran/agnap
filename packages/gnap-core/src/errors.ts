/** The two error classes the package throws. Everything else returns null or a typed result. */
import type { HttpSigFailure } from './types/httpsig.js';
import type { ErrorResponse, GnapErrorCode, IntrospectionErrorCode } from './types/messages.js';

/** Build the common GNAP error wire shape for protocol and HTTP adapters. */
export function errorResponse(
  code: GnapErrorCode | IntrospectionErrorCode,
  description?: string,
): ErrorResponse {
  return { error: description === undefined ? { code } : { code, description } };
}

export class AccessParseError extends Error {
  override readonly name = 'AccessParseError';
  constructor(
    readonly type: string | null,
    readonly detail: string,
  ) {
    super(type === null ? detail : `${type}: ${detail}`);
  }
}

export class HttpSigError extends Error {
  override readonly name = 'HttpSigError';
  constructor(
    readonly code: HttpSigFailure,
    readonly detail: string,
  ) {
    super(`${code}: ${detail}`);
  }
}
