/**
 * Signing. RFC 9421 itself (signature base, structured fields, dictionary
 * merging) comes from `http-message-sig`. This file fixes the GNAP profile
 * on top: which components, which parameters, which algorithm.
 */
import { createSignature } from 'http-message-sig';
import type {
  SignatureComponent,
  SignatureParameters as LibParameters,
  Signer as LibSigner,
} from 'http-message-sig';
import { contentDigest } from './digest.js';
import { SIGNATURE_ALG, SIGNATURE_LABEL, SIGNATURE_TAG, coveredComponentsFor } from './profile.js';
import { toRequest } from './request.js';
import { nowSeconds, systemClock } from '../util/clock.js';
import { randomToken } from '../util/encoding.js';
import type { SignOptions, SignableRequest, SignatureHeaders } from '../types/httpsig.js';
import type { Signer } from '../types/keys.js';

export function toLibSigner(signer: Signer): LibSigner {
  return { algorithm: SIGNATURE_ALG, sign: (data) => signer.sign(data) };
}

/**
 * RFC 9421 with no GNAP profile: sign exactly these components with exactly
 * these parameters. Used by the profile below and by the RFC vector tests.
 */
export async function signComponents(
  request: SignableRequest,
  options: {
    label: string;
    components: readonly SignatureComponent[];
    parameters: LibParameters;
    signer: Signer;
  },
): Promise<{ 'signature-input': string; signature: string }> {
  const fields = await createSignature(toRequest(request), {
    label: options.label,
    components: options.components,
    parameters: options.parameters,
    signer: toLibSigner(options.signer),
  });
  return { 'signature-input': fields.signatureInput, signature: fields.signature };
}

/**
 * Produce the headers that make `request` a signed GNAP request. The caller
 * adds them before sending; `request.headers` is not mutated. If the request
 * has a body, `content-digest` is computed here and must be sent as returned.
 */
export async function signRequest(
  request: SignableRequest,
  options: SignOptions,
): Promise<SignatureHeaders> {
  const clock = options.clock ?? systemClock;
  const headers = new Headers(request.headers);
  const out: SignatureHeaders = { 'signature-input': '', signature: '' };

  const hasBody = request.body.byteLength > 0;
  if (hasBody) {
    out['content-digest'] = contentDigest(request.body);
    headers.set('content-digest', out['content-digest']);
  }

  const components = coveredComponentsFor({
    hasBody,
    hasAuthorization: headers.has('authorization'),
  });
  const parameters: LibParameters = {
    created: nowSeconds(clock),
    keyid: options.signer.kid,
    nonce: options.nonce ?? randomToken(16),
    tag: SIGNATURE_TAG,
    ...(options.includeAlg ? { alg: SIGNATURE_ALG } : {}),
  };

  const signed = await signComponents(
    { ...request, headers },
    {
      label: SIGNATURE_LABEL,
      components,
      parameters,
      signer: options.signer,
    },
  );
  out['signature-input'] = signed['signature-input'];
  out.signature = signed.signature;
  return out;
}

/** Apply `signRequest()` output to a `Headers` instance. */
export function applySignatureHeaders(headers: Headers, signed: SignatureHeaders): void {
  if (signed['content-digest'] !== undefined)
    headers.set('content-digest', signed['content-digest']);
  headers.set('signature-input', signed['signature-input']);
  headers.set('signature', signed.signature);
}

/** Convenience: a fully signed `Request` for `fetch`. */
export async function signedFetchRequest(
  request: SignableRequest,
  options: SignOptions,
): Promise<Request> {
  const headers = new Headers(request.headers);
  applySignatureHeaders(headers, await signRequest(request, options));
  return toRequest({ ...request, headers });
}
