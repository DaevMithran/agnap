import {
  Ed25519Signer,
  applySignatureHeaders,
  randomToken,
  sha256Base64url,
  signRequest,
  utf8,
} from '@agnap/gnap-core';
import type {
  AccessToken,
  ErrorResponse,
  GrantResponse,
  IntrospectionResponse,
  SignableRequest,
} from '@agnap/gnap-core';
import type { AgentOperationAccess } from '@agnap/access-types';
import type {
  Fetch,
  GnapClientOptions,
  GrantClient,
  ResourceServerIdentity,
  SessionClientProvider,
} from './types.js';

export class GnapHttpError extends Error {
  override readonly name = 'GnapHttpError';
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
  }
}

export class GnapHttpClient implements GrantClient {
  readonly issuer: string;
  readonly clientSigner: GnapClientOptions['clientSigner'];
  readonly resourceServer: ResourceServerIdentity;
  readonly #fetch: Fetch;
  readonly #clock: GnapClientOptions['clock'];

  constructor(options: GnapClientOptions) {
    this.issuer = new URL(options.issuer).toString();
    this.clientSigner = options.clientSigner;
    this.resourceServer = options.resourceServer;
    this.#fetch = options.fetch ?? fetch;
    this.#clock = options.clock;
  }

  requestGrant(access: AgentOperationAccess[], signal?: AbortSignal): Promise<GrantResponse> {
    return this.#json<GrantResponse>(
      this.issuer,
      'POST',
      {
        access_token: { access },
        client: { key: { proof: 'httpsig', jwk: this.clientSigner.publicJwk } },
      },
      this.clientSigner,
      undefined,
      signal,
    );
  }

  continueGrant(
    uri: string,
    continuationToken: string,
    signal?: AbortSignal,
  ): Promise<GrantResponse> {
    return this.#json<GrantResponse>(
      uri,
      'POST',
      undefined,
      this.clientSigner,
      continuationToken,
      signal,
    );
  }

  introspect(
    token: string,
    access?: AgentOperationAccess[],
    signal?: AbortSignal,
  ): Promise<IntrospectionResponse> {
    return this.#json<IntrospectionResponse>(
      new URL('introspect', this.issuer).toString(),
      'POST',
      {
        access_token: token,
        resource_server: this.resourceServer.id,
        ...(access !== undefined ? { access } : {}),
      },
      this.resourceServer.signer,
      undefined,
      signal,
    );
  }

  async revoke(token: AccessToken, signal?: AbortSignal): Promise<void> {
    if (token.manage === undefined) throw new Error('token has no management handle');
    await this.#json<undefined>(
      token.manage.uri,
      'DELETE',
      undefined,
      this.clientSigner,
      token.manage.access_token.value,
      signal,
    );
  }

  async #json<T>(
    url: string,
    method: string,
    body: unknown,
    signer: GnapClientOptions['clientSigner'],
    token?: string,
    signal?: AbortSignal,
  ): Promise<T> {
    const bytes = body === undefined ? new Uint8Array() : utf8(JSON.stringify(body));
    const headers = new Headers();
    if (body !== undefined) headers.set('content-type', 'application/json');
    if (token !== undefined) headers.set('authorization', `GNAP ${token}`);
    const signable: SignableRequest = { method, url, headers, body: bytes };
    applySignatureHeaders(
      headers,
      await signRequest(signable, {
        signer,
        ...(this.#clock !== undefined ? { clock: this.#clock } : {}),
      }),
    );
    const init: RequestInit = {
      method,
      headers,
      ...(signal !== undefined ? { signal } : {}),
    };
    if (bytes.byteLength > 0) init.body = bytes;
    const response = await this.#fetch(new Request(url, init));
    const text = await response.text();
    const parsed = text.length === 0 ? undefined : (JSON.parse(text) as unknown);
    if (!response.ok) {
      const error = parsed as ErrorResponse | undefined;
      const code = error?.error?.code ?? 'http_error';
      const retryAfter = response.headers.get('retry-after');
      const retryAfterSeconds = retryAfter === null ? undefined : Number(retryAfter);
      throw new GnapHttpError(
        response.status,
        code,
        error?.error?.description ?? code,
        Number.isFinite(retryAfterSeconds) ? retryAfterSeconds : undefined,
      );
    }
    return parsed as T;
  }
}

export interface InMemorySessionClientProviderOptions {
  issuer: string;
  resourceServer: ResourceServerIdentity;
  fetch?: Fetch;
  clock?: GnapClientOptions['clock'];
}

export class InMemorySessionClientProvider implements SessionClientProvider {
  readonly #options: InMemorySessionClientProviderOptions;
  readonly #clients = new Map<string, GnapHttpClient>();

  constructor(options: InMemorySessionClientProviderOptions) {
    this.#options = options;
  }

  get(sessionId: string): GnapHttpClient {
    const existing = this.#clients.get(sessionId);
    if (existing !== undefined) return existing;
    const client = new GnapHttpClient({
      issuer: this.#options.issuer,
      clientSigner: Ed25519Signer.generate(`client-${randomToken(8)}`),
      resourceServer: this.#options.resourceServer,
      ...(this.#options.fetch !== undefined ? { fetch: this.#options.fetch } : {}),
      ...(this.#options.clock !== undefined ? { clock: this.#options.clock } : {}),
    });
    this.#clients.set(sessionId, client);
    return client;
  }
}

export const tokenFingerprint = (token: string): string => sha256Base64url(token);
