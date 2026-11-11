/** Ed25519 keys as RFC 9635 section 7.1.1 wants them: JWK with `kid` and `alg`. */
import type { components } from '../generated/as.js';

export type Ed25519PublicJwk = components['schemas']['Ed25519PublicJwk'];

export interface Ed25519PrivateJwk extends Ed25519PublicJwk {
  d: string;
}

export interface Ed25519KeyPair {
  publicJwk: Ed25519PublicJwk;
  privateJwk: Ed25519PrivateJwk;
}

/**
 * Something that can produce Ed25519 signatures with a known public key.
 * The seam behind which key custody lives: OS keychain, KMS and HSM
 * implementations plug in here without touching the signature profile.
 */
export interface Signer {
  readonly kid: string;
  readonly publicJwk: Ed25519PublicJwk;
  sign(data: Uint8Array): Promise<Uint8Array>;
}
