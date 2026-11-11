import type {
  AccessToken,
  Clock,
  GrantResponse,
  IntrospectionResponse,
  Signer,
} from '@agnap/gnap-core';
import type { AgentOperationAccess, Scalar } from '@agnap/access-types';

export type Fetch = (request: Request) => Promise<Response>;

export interface ResourceServerIdentity {
  id: string;
  signer: Signer;
}

export interface GnapClientOptions {
  issuer: string;
  clientSigner: Signer;
  /**
   * Needed only to introspect. Leave it out when an executor checks tokens:
   * the agent's process then holds no resource-server key.
   */
  resourceServer?: ResourceServerIdentity;
  fetch?: Fetch;
  clock?: Clock;
}

export interface StoredGrant {
  token: AccessToken;
  fingerprint: string;
}

export interface SessionGrantStore {
  list(sessionId: string): readonly StoredGrant[];
  add(sessionId: string, grant: StoredGrant): void;
  delete(sessionId: string, fingerprint: string): void;
  clear(sessionId: string): void;
  /** Sessions that currently hold at least one grant. */
  sessionIds(): readonly string[];
}

export interface GrantClient {
  readonly clientSigner: Signer;
  /**
   * Request a grant. `display` is RFC 9635 `client.display`, shown to the
   * owner as an unverified label for the agent.
   */
  requestGrant(
    access: AgentOperationAccess[],
    signal?: AbortSignal,
    display?: { name: string },
  ): Promise<GrantResponse>;
  continueGrant(
    uri: string,
    continuationToken: string,
    signal?: AbortSignal,
  ): Promise<GrantResponse>;
  introspect(
    token: string,
    access?: AgentOperationAccess[],
    signal?: AbortSignal,
  ): Promise<IntrospectionResponse>;
  revoke(token: AccessToken, signal?: AbortSignal): Promise<void>;
}

export interface SessionClientProvider {
  get(sessionId: string): GrantClient;
}

export interface ApprovalRequest {
  sessionId: string;
  agent: unknown;
  toolName: string;
  callId?: unknown;
  reason: string;
  signal: AbortSignal;
}

export type ApprovalOutcome = 'allowed-once' | 'rejected' | 'cancelled' | 'unavailable';

export interface ApprovalPort {
  request(request: ApprovalRequest): Promise<ApprovalOutcome>;
}

export interface OwnerDecisionPort {
  resolve(grantId: string, decision: 'approve' | 'deny', signal?: AbortSignal): Promise<void>;
}

export interface ArgumentRule {
  /** Tool argument name. Defaults to the authority argument name. */
  from?: string;
  /** Required unless explicitly false. */
  required?: boolean;
  /** JSON encodes arrays/objects into the scalar authority grammar. */
  encoding?: 'scalar' | 'json';
  /**
   * `identity` binds the grant to this call's value. `free` requests a
   * wildcard so later values remain covered. Defaults to `identity`.
   */
  authority?: 'identity' | 'free';
}

export interface ToolProfile {
  toolName: string;
  /** Authority operation name. Defaults to toolName. */
  operation?: string;
  arguments: Record<string, ArgumentRule>;
  /** Defaults to true. */
  rejectUnknownArguments?: boolean;
  /**
   * Ask for a ceiling on this operation, checked against the grant state record. The executor enforces it
   * against one grant state record per root grant, so it holds across tokens and
   * parallel calls.
   */
  ceiling?: { calls: number };
}

export interface MappedToolCall {
  operation: string;
  arguments: Record<string, Scalar>;
  /** Scope requested from the AS; free arguments are wildcards. */
  access: AgentOperationAccess;
  /** Access required by this concrete invocation; supplied values are exact. */
  requiredAccess: AgentOperationAccess;
}

export type AuthorizationDecision =
  | { kind: 'unprofiled' }
  | { kind: 'allow'; fingerprint: string }
  | { kind: 'cancel' }
  | { kind: 'deny'; reason: string };

export interface AuthorizeToolInput {
  sessionId: string;
  agent: unknown;
  toolName: string;
  callId?: unknown;
  arguments: unknown;
  signal: AbortSignal;
  /** How the owner should see this agent, for example `agent child (subagent of parent)`. */
  agentLabel?: string;
}
