/**
 * Ed25519 keys as RFC 9635 section 7.1.1 wants them: a JWK with `kid` and
 * `alg` present. The private scalar never leaves the process that made it.
 */
import { createPublicKey, generateKeyPairSync, verify as cryptoVerify } from 'node:crypto';
import type { KeyObject as NodeKeyObject } from 'node:crypto';
import { validateEd25519PublicJwk } from '../schemas/index.js';
import { sha256Base64url } from '../util/encoding.js';
import type { Ed25519KeyPair, Ed25519PrivateJwk, Ed25519PublicJwk } from '../types/keys.js';

/** Generate a fresh pair. The caller chooses the `kid`. */
export function generateKey(kid: string): Ed25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'jwk' });
  const priv = privateKey.export({ format: 'jwk' });
  if (typeof pub.x !== 'string' || typeof priv.d !== 'string') {
    throw new Error('unexpected JWK export from node:crypto');
  }
  const publicJwk: Ed25519PublicJwk = { kid, alg: 'EdDSA', kty: 'OKP', crv: 'Ed25519', x: pub.x };
  return { publicJwk, privateJwk: { ...publicJwk, d: priv.d } };
}

export function toPublicJwk(jwk: Ed25519PublicJwk | Ed25519PrivateJwk): Ed25519PublicJwk {
  const { kid, alg, kty, crv, x } = jwk;
  const out: Ed25519PublicJwk = { kid, alg, kty, crv, x };
  if (jwk.use !== undefined) out.use = jwk.use;
  return out;
}

/** Structural check for a public JWK received on the wire. Null when it is not one of ours or carries a private scalar. */
export function parsePublicJwk(value: unknown): Ed25519PublicJwk | null {
  return validateEd25519PublicJwk(value) ? value : null;
}

/**
 * RFC 7638 thumbprint: SHA-256 over the required members in lexicographic
 * order with no whitespace. For OKP keys those are `crv`, `kty`, `x`.
 */
export function thumbprint(jwk: Pick<Ed25519PublicJwk, 'crv' | 'kty' | 'x'>): string {
  return sha256Base64url(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }));
}

/** Two public keys are the same key if their thumbprints match, whatever their `kid`. */
export function sameKey(a: Ed25519PublicJwk, b: Ed25519PublicJwk): boolean {
  return thumbprint(a) === thumbprint(b);
}

export function publicKeyFromJwk(jwk: Ed25519PublicJwk): NodeKeyObject {
  return createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, format: 'jwk' });
}

/** Verify an Ed25519 signature. Never throws on malformed input; returns false. */
export function verifyEd25519(
  jwk: Ed25519PublicJwk,
  data: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    return cryptoVerify(null, data, publicKeyFromJwk(jwk), signature);
  } catch {
    return false;
  }
}
