/** The protocol server's configuration, inputs and results. */
import type {
  AccessItem,
  AccessTypeHandler,
  AccessTypeRegistry,
  Ed25519PublicJwk,
  ErrorResponse,
  GrantResponse,
  IntrospectionResponse,
} from '@agnap/gnap-core';
import type { DecisionStep } from './decision.js';
import type { GrantRecord } from './records.js';
import type { ResourceServerEntry, ResourceServerRegistry } from './registry.js';

export interface ServerConfig {
  /** The grant endpoint URL. Returned as `iss` and used as the origin for continuation and management URIs. */
  issuer: string;
  tokenTtlSeconds?: number;
  /** Lifetime of pending and approved grants. Defaults to 600 seconds. */
  grantTtlSeconds?: number;
  continueWaitSeconds?: number;
  registry: ResourceServerRegistry;
  accessTypes: AccessTypeHandler[];
  decision: DecisionStep;
  /** Which resource servers an issued token is for. Default: every registered RS whose types cover the access. */
  selectAudiences?: (access: AccessItem[], registry: ResourceServerRegistry) => string[];
}

export interface AuthenticatedContext {
  /** The key the request signature verified against. */
  key: Ed25519PublicJwk;
  thumbprint: string;
  /** Milliseconds since epoch at the server. */
  now: number;
  /** Raw value from `Authorization: GNAP <value>`, when present. */
  presentedToken?: string;
}

export type Result<T> =
  | { status: 200 | 204; body: T }
  | { status: 400 | 401 | 403 | 404 | 503; body: ErrorResponse; retryAfterSeconds?: number };

export interface GnapServer {
  grant(body: unknown, ctx: AuthenticatedContext): Promise<Result<GrantResponse>>;
  continue(grantId: string, ctx: AuthenticatedContext): Promise<Result<GrantResponse>>;
  revokeToken(tokenId: string, ctx: AuthenticatedContext): Promise<Result<undefined>>;
  introspect(
    body: unknown,
    rs: ResourceServerEntry,
    ctx: AuthenticatedContext,
  ): Promise<Result<IntrospectionResponse>>;
  /** Owner-side resolution of a pending grant. Not an RFC operation. */
  resolveGrant(grantId: string, resolution: OwnerResolution): Promise<Result<{ state: string }>>;
  listPending(): Promise<GrantRecord[]>;
  readonly registry: AccessTypeRegistry;
  readonly issuer: string;
}

export type OwnerResolution =
  { kind: 'approve'; access?: AccessItem[]; audiences?: string[] } | { kind: 'deny' };
