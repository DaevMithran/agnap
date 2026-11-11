/**
 * Verification. `http-message-sig` parses the signature fields, rebuilds the
 * RFC 9421 base, enforces an explicit policy and checks the signature. This
 * file supplies the GNAP policy, the key, the content digest check (RFC
 * 9530, outside the library's scope) and replay protection.
 */
import { isSignatureError, verifySignature } from 'http-message-sig';
import type { VerifiedSignature as LibVerified, Verifier as LibVerifier } from 'http-message-sig';
import { HttpSigError } from '../errors.js';
import { verifyContentDigest } from './digest.js';
import {
  DEFAULT_CREATED_WINDOW_SECONDS,
  OPTIONAL_PARAMETERS,
  REQUIRED_PARAMETERS,
  SIGNATURE_ALG,
  SIGNATURE_TAG,
  coveredComponentsFor,
  sameComponentSet,
} from './profile.js';
import { toRequest } from './request.js';
import { thumbprint, verifyEd25519 } from '../keys/jwk.js';
import { nowSeconds } from '../util/clock.js';
import type { SignableRequest, VerifiedSignature, VerifyOptions } from '../types/httpsig.js';
import type { Ed25519PublicJwk } from '../types/keys.js';

function toLibVerifier(publicJwk: Ed25519PublicJwk): LibVerifier {
  return { algorithm: SIGNATURE_ALG, verify: (data, sig) => verifyEd25519(publicJwk, data, sig) };
}

/** Translate library failures. Freshness problems are `expired`, everything else `invalid_proof`. */
function translate(e: unknown): never {
  if (e instanceof HttpSigError) throw e;
  if (isSignatureError(e)) {
    if (e.cause instanceof HttpSigError) throw e.cause;
    const fresh = /future|too old|expired/i.test(e.message);
    throw new HttpSigError(fresh ? 'expired' : 'invalid_proof', `${e.code}: ${e.message}`);
  }
  throw e;
}

/**
 * Verify a GNAP request under the fixed profile. Throws `HttpSigError` with
 * `invalid_proof` for any structural or cryptographic failure, `expired`
 * when `created` or `expires` is outside the window, `replayed` when the
 * nonce has been seen. The digest is checked before the signature, the
 * nonce is recorded last and only after the signature has verified.
 */
export async function verifyRequest(
  request: SignableRequest,
  options: VerifyOptions,
): Promise<VerifiedSignature> {
  if (!request.headers.has('signature-input') || !request.headers.has('signature')) {
    throw new HttpSigError('invalid_proof', 'signature-input and signature headers are required');
  }

  const hasBody = request.body.byteLength > 0;
  const digestHeader = request.headers.get('content-digest');
  if (hasBody && digestHeader === null) {
    throw new HttpSigError('invalid_proof', 'content-digest is required when a body is present');
  }
  if (digestHeader !== null && !verifyContentDigest(digestHeader, request.body)) {
    throw new HttpSigError('invalid_proof', 'content-digest does not match the body');
  }
  const expected = coveredComponentsFor({
    hasBody: hasBody || digestHeader !== null,
    hasAuthorization: request.headers.has('authorization'),
  });

  const now = nowSeconds(options.clock);
  const window = options.createdWindowSeconds ?? DEFAULT_CREATED_WINDOW_SECONDS;
  const allowed = new Set<string>([...REQUIRED_PARAMETERS, ...OPTIONAL_PARAMETERS]);

  let verified: LibVerified;
  try {
    verified = await verifySignature(toRequest(request), {
      policy: {
        algorithms: [SIGNATURE_ALG],
        requiredComponents: expected,
        requiredParameters: [...REQUIRED_PARAMETERS],
        // `created` accepted within +/- window: no age allowance beyond the skew in either direction.
        maxAge: 0,
        clockSkew: window,
        now,
        validate: (sig) => {
          const names = sig.components.map((c) => c.name);
          if (sig.components.some((c) => Object.keys(c.parameters).length > 0)) {
            throw new HttpSigError('invalid_proof', 'component parameters are outside the profile');
          }
          if (!sameComponentSet(expected, names)) {
            throw new HttpSigError(
              'invalid_proof',
              `covered components must be exactly ${expected.join(' ')}`,
            );
          }
          for (const name of Object.keys(sig.parameters)) {
            if (!allowed.has(name))
              throw new HttpSigError(
                'invalid_proof',
                `signature parameter ${name} is outside the profile`,
              );
          }
          const { created, keyid, nonce, tag, alg, expires } = sig.parameters;
          if (typeof created !== 'number')
            throw new HttpSigError('invalid_proof', 'created must be an integer');
          if (typeof keyid !== 'string' || keyid.length === 0)
            throw new HttpSigError('invalid_proof', 'keyid is required');
          if (typeof nonce !== 'string' || nonce.length === 0)
            throw new HttpSigError('invalid_proof', 'nonce is required');
          if (tag !== SIGNATURE_TAG)
            throw new HttpSigError('invalid_proof', `tag must be "${SIGNATURE_TAG}"`);
          if (alg !== undefined && alg !== SIGNATURE_ALG) {
            throw new HttpSigError('invalid_proof', `alg must be "${SIGNATURE_ALG}" when present`);
          }
          if (expires !== undefined && (typeof expires !== 'number' || now >= expires)) {
            throw new HttpSigError('expired', 'signature has expired');
          }
        },
      },
      resolveVerifier: (candidate) => {
        if (candidate.parameters.keyid !== options.publicJwk.kid) {
          throw new HttpSigError('invalid_proof', 'keyid does not name the expected key');
        }
        return toLibVerifier(options.publicJwk);
      },
    });
  } catch (e) {
    translate(e);
  }

  const keyThumbprint = thumbprint(options.publicJwk);
  const created = verified.parameters.created as number;
  const nonce = verified.parameters.nonce as string;
  if (options.nonceCheck !== undefined) {
    const outcome = await options.nonceCheck({
      nonce,
      keyThumbprint,
      expiresAt: (created + window) * 1000,
    });
    if (outcome === 'seen') throw new HttpSigError('replayed', 'nonce has already been used');
    if (outcome === 'full')
      throw new HttpSigError('overloaded', 'replay cache is full, retry later');
  }

  return {
    keyid: verified.parameters.keyid as string,
    keyThumbprint,
    created,
    nonce,
    coveredComponents: verified.components.map((c) => c.name),
  };
}
