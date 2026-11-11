/** What the server stores: grants and the tokens issued from them. Secrets are never stored, only hashes. */
import type { AccessItem, Ed25519PublicJwk } from '@agnap/gnap-core';

export type GrantState = 'pending' | 'approved' | 'denied' | 'issued';

export type DenyCode = 'user_denied' | 'request_denied';

export interface GrantRecord {
  id: string;
  clientKey: Ed25519PublicJwk;
  /** RFC 9635 §2.3.2 `client.display`, as the client stated it. Unverified; shown to the owner as a label. */
  clientDisplay?: { name?: string; uri?: string };
  requestedAccess: AccessItem[];
  state: GrantState;
  /** Set when the decision is made. Contained in `requestedAccess`. */
  decidedAccess?: AccessItem[];
  decidedAudiences?: string[];
  denyCode?: DenyCode;
  /** Milliseconds since epoch. */
  createdAt: number;
  /** Milliseconds since epoch. Pending and approved grants are invalid after this time. */
  expiresAt: number;
  /** SHA-256 (base64url) of the live continuation token. Null once the grant reached a final state. */
  continuationHash: string | null;
  /** Earliest time, in ms, a continuation is accepted. Before it: `too_fast`, credential kept. */
  notBefore: number;
  tokenId?: string;
}

export interface TokenRecord {
  id: string;
  /** SHA-256 (base64url) of the access token value. The value itself is never stored. */
  accessHash: string;
  /** SHA-256 of the token management access token. A different value from the access token. */
  managementHash: string;
  grantId: string;
  boundKey: Ed25519PublicJwk;
  access: AccessItem[];
  /** Resource server ids this token is intended for. Introspection is active only for these. */
  audiences: string[];
  issuedAt: number;
  expiresAt: number;
  revoked: boolean;
}
