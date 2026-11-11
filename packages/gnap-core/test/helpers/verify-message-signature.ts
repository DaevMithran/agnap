/** Minimal RFC 9421 verifier used only by the RFC vector tests. */
import { isSignatureError, verifySignature } from 'http-message-sig';
import type { VerifiedSignature, Verifier } from 'http-message-sig';
import { HttpSigError } from '../../src/errors.js';
import { verifyEd25519 } from '../../src/keys/jwk.js';
import { SIGNATURE_ALG } from '../../src/httpsig/profile.js';
import { toRequest } from '../../src/httpsig/request.js';
import type { SignableRequest } from '../../src/types/httpsig.js';
import type { Ed25519PublicJwk } from '../../src/types/keys.js';

export async function verifyMessageSignature(
  request: SignableRequest,
  publicJwk: Ed25519PublicJwk,
  label?: string,
): Promise<VerifiedSignature> {
  const verifier: Verifier = {
    algorithm: SIGNATURE_ALG,
    verify: (data, signature) => verifyEd25519(publicJwk, data, signature),
  };
  try {
    return await verifySignature(toRequest(request), {
      ...(label !== undefined ? { label } : {}),
      policy: { algorithms: [SIGNATURE_ALG], requiredComponents: [], requiredParameters: [] },
      resolveVerifier: () => verifier,
    });
  } catch (error) {
    if (isSignatureError(error)) {
      throw new HttpSigError('invalid_proof', `${error.code}: ${error.message}`);
    }
    throw error;
  }
}
