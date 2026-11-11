/** Resource servers the authorization server knows, RFC 9767. */
import type { Ed25519PublicJwk } from '@agnap/gnap-core';

export interface ResourceServerEntry {
  id: string;
  key: Ed25519PublicJwk;
  /** Access types this resource server may introspect for. */
  accessTypes: string[];
}

export interface ResourceServerRegistry {
  get(id: string): ResourceServerEntry | null;
  /** Lookup by key, for an `resource_server: { key }` request form. */
  byThumbprint(thumbprint: string): ResourceServerEntry | null;
  all(): ResourceServerEntry[];
}
