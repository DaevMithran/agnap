import { createHash, randomBytes } from 'node:crypto';

export function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function fromBase64url(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, 'base64url'));
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function sha256(data: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

/** SHA-256 of `data`, base64url without padding. The form used for token hashes and thumbprints. */
export function sha256Base64url(data: Uint8Array | string): string {
  return base64url(sha256(data));
}

/** `bytes` random bytes as base64url. Used for token values, nonces and ids. */
export function randomToken(bytes = 32): string {
  return base64url(randomBytes(bytes));
}
