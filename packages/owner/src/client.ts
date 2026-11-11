/** Owner requests to the server's `/local/grants` extension, each signed with the owner key. */
import { applySignatureHeaders, signRequest, utf8 } from '@agnap/gnap-core';
import type { AccessItem, Clock, SignableRequest, Signer } from '@agnap/gnap-core';
import { validateOwnerResolutionResult, validatePendingGrantList } from '@agnap/gnap-server';
import type { PendingGrant } from '@agnap/gnap-server';

export type Fetch = (request: Request) => Promise<Response>;

export interface OwnerClientOptions {
  /** The server's issuer URL, for example `http://127.0.0.1:4000/`. */
  issuer: string;
  signer: Signer;
  fetch?: Fetch;
  clock?: Clock;
}

export class OwnerRequestError extends Error {
  override readonly name = 'OwnerRequestError';
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export class OwnerClient {
  readonly #issuer: string;
  readonly #signer: Signer;
  readonly #fetch: Fetch;
  readonly #clock: Clock | undefined;

  constructor(options: OwnerClientOptions) {
    this.#issuer = new URL(options.issuer).toString();
    this.#signer = options.signer;
    this.#fetch = options.fetch ?? fetch;
    this.#clock = options.clock;
  }

  /**
   * Grants waiting for the owner.
   * @param signal - cancels the request.
   * @returns the pending grants, oldest first.
   */
  async listPending(signal?: AbortSignal): Promise<PendingGrant[]> {
    const body = await this.#send('GET', 'local/grants', undefined, signal);
    if (!validatePendingGrantList(body)) {
      throw new OwnerRequestError(200, 'server returned an invalid pending grant list');
    }
    return [...body.grants].sort((a, b) => a.created_at.localeCompare(b.created_at));
  }

  /**
   * Approve a pending grant, optionally narrowed. The server rejects any
   * `access` not contained in what the client requested.
   * @param grantId - the grant's id.
   * @param access - narrowed access, or omitted to approve as requested.
   * @param signal - cancels the request.
   */
  async approve(grantId: string, access?: AccessItem[], signal?: AbortSignal): Promise<void> {
    await this.#resolve(
      grantId,
      { decision: 'approve', ...(access !== undefined ? { access } : {}) },
      signal,
    );
  }

  /**
   * Deny a pending grant.
   * @param grantId - the grant's id.
   * @param signal - cancels the request.
   */
  async deny(grantId: string, signal?: AbortSignal): Promise<void> {
    await this.#resolve(grantId, { decision: 'deny' }, signal);
  }

  async #resolve(grantId: string, body: unknown, signal?: AbortSignal): Promise<void> {
    const result = await this.#send(
      'POST',
      `local/grants/${encodeURIComponent(grantId)}`,
      body,
      signal,
    );
    if (!validateOwnerResolutionResult(result)) {
      throw new OwnerRequestError(200, 'server returned an invalid resolution result');
    }
  }

  async #send(method: string, path: string, body: unknown, signal?: AbortSignal): Promise<unknown> {
    const url = new URL(path, this.#issuer).toString();
    const bytes = body === undefined ? new Uint8Array() : utf8(JSON.stringify(body));
    const headers = new Headers();
    if (body !== undefined) headers.set('content-type', 'application/json');
    const signable: SignableRequest = { method, url, headers, body: bytes };
    applySignatureHeaders(
      headers,
      await signRequest(signable, {
        signer: this.#signer,
        ...(this.#clock !== undefined ? { clock: this.#clock } : {}),
      }),
    );
    const init: RequestInit = { method, headers, ...(signal !== undefined ? { signal } : {}) };
    if (bytes.byteLength > 0) init.body = bytes;
    const response = await this.#fetch(new Request(url, init));
    const text = await response.text();
    const parsed = text.length === 0 ? undefined : (JSON.parse(text) as unknown);
    if (!response.ok) {
      const description = (parsed as { error?: { description?: string } } | undefined)?.error
        ?.description;
      throw new OwnerRequestError(
        response.status,
        `${method} /${path} failed with HTTP ${response.status}${description !== undefined ? `: ${description}` : ''}`,
      );
    }
    return parsed;
  }
}
