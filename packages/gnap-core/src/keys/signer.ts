import { createPrivateKey, sign as cryptoSign } from 'node:crypto';
import type { KeyObject as NodeKeyObject } from 'node:crypto';

import { generateKey, toPublicJwk } from './jwk.js';
import type { Ed25519PrivateJwk, Ed25519PublicJwk, Signer } from '../types/keys.js';

/** Holds the private key in process memory. OS keychain, KMS and HSM signers implement the same `Signer`. */
export class Ed25519Signer implements Signer {
  readonly kid: string;
  readonly publicJwk: Ed25519PublicJwk;
  readonly #key: NodeKeyObject;

  private constructor(privateJwk: Ed25519PrivateJwk) {
    this.kid = privateJwk.kid;
    this.publicJwk = toPublicJwk(privateJwk);
    this.#key = createPrivateKey({
      key: { kty: privateJwk.kty, crv: privateJwk.crv, x: privateJwk.x, d: privateJwk.d },
      format: 'jwk',
    });
  }

  static generate(kid: string): Ed25519Signer {
    return new Ed25519Signer(generateKey(kid).privateJwk);
  }

  static fromJwk(privateJwk: Ed25519PrivateJwk): Ed25519Signer {
    return new Ed25519Signer(privateJwk);
  }

  /** Import a PKCS#8 PEM, as RFC 9421 test vectors ship them. */
  static fromPem(kid: string, pem: string): Ed25519Signer {
    const key = createPrivateKey(pem);
    const jwk = key.export({ format: 'jwk' });
    if (typeof jwk.x !== 'string' || typeof jwk.d !== 'string')
      throw new Error('not an Ed25519 key');
    return new Ed25519Signer({ kid, alg: 'EdDSA', kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d });
  }

  sign(data: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(new Uint8Array(cryptoSign(null, data, this.#key)));
  }
}
