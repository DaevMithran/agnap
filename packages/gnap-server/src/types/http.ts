/** HTTP layer shapes: handler options, router context, authentication, the Node adapter. */
import type { Clock, Ed25519PublicJwk, ErrorResponse, SignableRequest } from '@agnap/gnap-core';
import type { ResourceServerRegistry } from './registry.js';
import type { AuthenticatedContext, GnapServer } from './server.js';
import type { Store } from './store.js';

export interface RouteDeps {
  server: GnapServer;
  store: Store;
  rsRegistry: ResourceServerRegistry;
  authenticate: Authenticate;
  localOwner?: { secret: string };
  owner?: { key: Ed25519PublicJwk };
}

export interface HandlerOptions {
  server: GnapServer;
  store: Store;
  rsRegistry: ResourceServerRegistry;
  clock?: Clock;
  createdWindowSeconds?: number;
  /**
   * Behind a TLS-terminating proxy the scheme and host the client signed
   * differ from what the process sees. Set this to the public origin.
   */
  publicUrl?: string;
  /**
   * Mount the non-RFC owner extension under `/local/grants`, accepting
   * requests signed with this owner key (RFC 9421, the same profile and
   * replay check as client requests). Run the owner's tool in a process the
   * agent cannot reach.
   */
  owner?: { key: Ed25519PublicJwk };
  /**
   * Mount the owner extension guarded by a shared bearer secret. Tests only:
   * whoever can read the secret can approve.
   */
  localOwner?: { secret: string };
  /** Largest request body accepted on any route, in bytes. Larger bodies are refused with 413 before anything else runs. */
  maxBodyBytes?: number;
}

export type FetchHandler = (request: Request) => Promise<Response>;

export interface ServeOptions {
  port?: number;
  host?: string;
  /** Refuse requests declaring or streaming more than this many body bytes. Should match the handler's limit. */
  maxBodyBytes?: number;
}

export interface RunningServer {
  url: string;
  close(): Promise<void>;
}

export type Method = 'GET' | 'POST' | 'DELETE';

export interface RouteContext {
  request: Request;
  method: Method;
  path: string;
  /** Values for `:name` segments in the matched pattern. */
  params: Record<string, string>;
  /** Raw body bytes, already bounded. Empty when there is no body. */
  bytes: Uint8Array;
  /** The request as the signer saw it, for signature verification. */
  signable: SignableRequest;
}

export type RouteCallback = (ctx: RouteContext) => Promise<Response> | Response;

export interface AuthenticateOptions {
  store: Store;
  clock?: Clock;
  createdWindowSeconds?: number;
}

export type Authenticate = (
  signable: SignableRequest,
  key: Ed25519PublicJwk,
  failureCode: ErrorResponse['error']['code'],
) => Promise<AuthenticatedContext | Response>;
