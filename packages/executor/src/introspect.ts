/** RFC 9767 token introspection, signed with the executor's resource-server key. */
import {
  applySignatureHeaders,
  signRequest,
  utf8,
  validateIntrospectionResponse,
} from '@agnap/gnap-core';
import type { IntrospectionResponse, SignableRequest, Signer } from '@agnap/gnap-core';
import type { Introspector } from './types.js';

export interface GnapIntrospectorOptions {
  /** The grant server's issuer URL. */
  issuer: string;
  /** This executor's id in the grant server's resource-server registry. */
  resourceServerId: string;
  signer: Signer;
  fetch?: (request: Request) => Promise<Response>;
}

export class GnapIntrospector implements Introspector {
  readonly #url: string;
  readonly #options: GnapIntrospectorOptions;
  readonly #fetch: (request: Request) => Promise<Response>;

  constructor(options: GnapIntrospectorOptions) {
    this.#url = new URL('introspect', options.issuer).toString();
    this.#options = options;
    this.#fetch = options.fetch ?? fetch;
  }

  async introspect(token: string, signal?: AbortSignal): Promise<IntrospectionResponse> {
    const body = utf8(
      JSON.stringify({ access_token: token, resource_server: this.#options.resourceServerId }),
    );
    const headers = new Headers({ 'content-type': 'application/json' });
    const signable: SignableRequest = { method: 'POST', url: this.#url, headers, body };
    applySignatureHeaders(headers, await signRequest(signable, { signer: this.#options.signer }));
    const response = await this.#fetch(
      new Request(this.#url, {
        method: 'POST',
        headers,
        body,
        ...(signal !== undefined ? { signal } : {}),
      }),
    );
    const parsed = await response.json();
    if (!response.ok || !validateIntrospectionResponse(parsed)) {
      throw new Error(`introspection failed with HTTP ${response.status}`);
    }
    return parsed;
  }
}
