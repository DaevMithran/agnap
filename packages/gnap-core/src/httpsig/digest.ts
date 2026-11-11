import { timingSafeEqual } from 'node:crypto';
import { parseDictionary } from 'structured-headers';
import { sha256 } from '../util/encoding.js';

export const DIGEST_ALGORITHM = 'sha-256';

/** RFC 9530 `Content-Digest` over the exact bytes on the wire: `sha-256=:<base64>:`. */
export function contentDigest(body: Uint8Array): string {
  return `${DIGEST_ALGORITHM}=:${Buffer.from(sha256(body)).toString('base64')}:`;
}

/**
 * Check a received `Content-Digest` against the body. The header is an RFC
 * 8941 dictionary, parsed as one, so a malformed member or a byte sequence
 * with characters outside base64 is a failure rather than something a
 * lenient decoder quietly skips. Several algorithms may be listed; SHA-256
 * must be one of them and must match. Others are ignored, as RFC 9530
 * permits.
 */
export function verifyContentDigest(header: string, body: Uint8Array): boolean {
  let dict: ReturnType<typeof parseDictionary>;
  try {
    dict = parseDictionary(header);
  } catch {
    return false;
  }
  const member = dict.get(DIGEST_ALGORITHM);
  if (member === undefined) return false;
  const [value] = member;
  if (!(value instanceof ArrayBuffer)) return false;
  const received = new Uint8Array(value);
  const expected = sha256(body);
  return received.length === expected.length && timingSafeEqual(received, expected);
}
