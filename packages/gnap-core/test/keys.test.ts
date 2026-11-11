import { describe, expect, it } from 'vitest';
import {
  Ed25519Signer,
  generateKey,
  parsePublicJwk,
  sameKey,
  thumbprint,
  utf8,
  verifyEd25519,
} from '../src/index.js';

describe('keys', () => {
  it('signs and verifies, and a different key fails', async () => {
    const a = Ed25519Signer.generate('a');
    const b = Ed25519Signer.generate('a');
    const sig = await a.sign(utf8('hello'));
    expect(verifyEd25519(a.publicJwk, utf8('hello'), sig)).toBe(true);
    expect(verifyEd25519(b.publicJwk, utf8('hello'), sig)).toBe(false);
    expect(verifyEd25519(a.publicJwk, utf8('hello'), new Uint8Array(3))).toBe(false);
  });

  it('thumbprint ignores kid, sameKey compares thumbprints', () => {
    const { publicJwk } = generateKey('k1');
    const renamed = { ...publicJwk, kid: 'k2' };
    expect(thumbprint(renamed)).toBe(thumbprint(publicJwk));
    expect(sameKey(publicJwk, { ...publicJwk, kid: 'other' })).toBe(true);
    expect(thumbprint(publicJwk)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('parsePublicJwk accepts only the profile shape and never a private key', () => {
    const { publicJwk, privateJwk } = generateKey('k');
    expect(parsePublicJwk(publicJwk)).toEqual(publicJwk);
    expect(parsePublicJwk(privateJwk)).toBeNull();
    expect(parsePublicJwk({ ...publicJwk, kid: '' })).toBeNull();
    expect(parsePublicJwk({ ...publicJwk, crv: 'P-256' })).toBeNull();
    expect(parsePublicJwk({ ...publicJwk, x: 'short' })).toBeNull();
    expect(parsePublicJwk('string')).toBeNull();
  });

  it('refuses a non-canonical x so one key cannot have two thumbprints', () => {
    const { publicJwk } = generateKey('k');
    // Flip an unused trailing bit in the last base64url character: same 32 bytes, different string.
    const last = publicJwk.x.slice(-1);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const idx = alphabet.indexOf(last);
    const variant = alphabet[idx ^ 1] as string;
    const alias = { ...publicJwk, x: publicJwk.x.slice(0, -1) + variant };
    expect(Buffer.from(alias.x, 'base64url').equals(Buffer.from(publicJwk.x, 'base64url'))).toBe(
      true,
    );
    expect(thumbprint(alias)).not.toBe(thumbprint(publicJwk));
    expect(parsePublicJwk(alias)).toBeNull();
    expect(parsePublicJwk(publicJwk)).not.toBeNull();
  });
});
