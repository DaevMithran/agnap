/** Shapes shared by the GNAP httpsig profile's signer and verifier. */
import type { Clock } from './clock.js';
import type { Ed25519PublicJwk, Signer } from './keys.js';

export interface SignatureParameters {
  created: number;
  keyid: string;
  nonce: string;
  tag: string;
  alg?: string;
  expires?: number;
}

export interface SignOptions {
  signer: Signer;
  clock?: Clock;
  /** Override for tests. Production callers let this be random. */
  nonce?: string;
  /** Include `alg="ed25519"`. Off by default; the key type already says so. */
  includeAlg?: boolean;
}

export interface SignatureHeaders {
  'content-digest'?: string;
  'signature-input': string;
  signature: string;
}

/**
 * Replay protection. Called once per request after the signature has been
 * proven genuine, so an attacker cannot poison the cache with forged nonces.
 * Must be atomic: two concurrent calls with the same entry return one
 * `fresh` and one `seen`.
 */
/** `full`: the cache could not record the nonce. The request must fail closed, as overload rather than replay. */
export type NonceClaim = 'fresh' | 'seen' | 'full';

export type NonceCheck = (entry: {
  nonce: string;
  keyThumbprint: string;
  /** Milliseconds since epoch after which the entry can be forgotten. */
  expiresAt: number;
}) => Promise<NonceClaim> | NonceClaim;

export interface VerifyOptions {
  /** The key the request must have been signed with. Its `kid` must equal the `keyid` parameter. */
  publicJwk: Ed25519PublicJwk;
  clock: Clock;
  createdWindowSeconds?: number;
  nonceCheck?: NonceCheck;
}

export interface VerifiedSignature {
  keyid: string;
  keyThumbprint: string;
  created: number;
  nonce: string;
  coveredComponents: string[];
}

/** A request as the signer and the verifier both see it. */
export interface SignableRequest {
  method: string;
  /** The absolute target URI exactly as the client requests it. */
  url: string;
  headers: Headers;
  /** Raw body bytes as sent or received. Empty for no body. */
  body: Uint8Array;
}

/** `overloaded` is not a client fault: the replay cache refused to record a fresh nonce. Map it to 503, not 401. */
export type HttpSigFailure = 'invalid_proof' | 'expired' | 'replayed' | 'overloaded';
