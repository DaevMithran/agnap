/**
 * The fixed `httpsig` profile for every GNAP message this implementation
 * sends or accepts. RFC 9635 section 7.3.1 requires covering `@method`,
 * `@target-uri`, `content-digest` when there is a body and `authorization`
 * when present, with `created`, `nonce` and `tag="gnap"`. This profile also
 * requires `keyid`, equal to the JWK `kid`, so a verifier can pick the key
 * before it trusts anything else, and fixes the algorithm to Ed25519.
 */
export const SIGNATURE_LABEL = 'sig1';
export const SIGNATURE_TAG = 'gnap';
export const SIGNATURE_ALG = 'ed25519';

/** Accept `created` within this many seconds of the verifier's clock, in either direction. */
export const DEFAULT_CREATED_WINDOW_SECONDS = 300;

export const REQUIRED_PARAMETERS = ['created', 'keyid', 'nonce', 'tag'] as const;
export const OPTIONAL_PARAMETERS = ['alg', 'expires'] as const;
/** Serialization order the signer uses. The verifier accepts any order. */
export const PARAMETER_ORDER = ['created', 'keyid', 'nonce', 'tag', 'alg', 'expires'] as const;

/** The covered components a request with these properties must carry, in profile order. */
export function coveredComponentsFor(request: {
  hasBody: boolean;
  hasAuthorization: boolean;
}): string[] {
  const components = ['@method', '@target-uri'];
  if (request.hasBody) components.push('content-digest');
  if (request.hasAuthorization) components.push('authorization');
  return components;
}

export function sameComponentSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const set = new Set(a);
  return b.every((c) => set.has(c));
}
