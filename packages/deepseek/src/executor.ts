/**
 * Calls the AGNAP executor (`agnapd`). The request carries the grant's token
 * and is signed with the session's client key, the key the token is bound
 * to; the executor holds the downstream credential and enforces the grant.
 */
import { applySignatureHeaders, signRequest, utf8 } from '@agnap/gnap-core';
import type { Clock, SignableRequest, Signer } from '@agnap/gnap-core';
import type { Scalar } from '@agnap/access-types';
import type { Fetch } from './types.js';

export type ExecutorCallOutcome =
  | { kind: 'done'; result: unknown }
  | {
      kind: 'refused';
      status: number;
      /** For example `ceiling_reached`, `insufficient_access` or `invalid_token`. */
      code: string;
      description: string;
    }
  | { kind: 'failed'; status: number; description: string; effect: 'none' | 'unknown' };

export interface ExecutorClientOptions {
  /** The executor's base URL, for example `http://127.0.0.1:4100`. */
  url: string;
  fetch?: Fetch;
  clock?: Clock;
}

interface ErrorBody {
  error?: { code?: string; description?: string; effect?: string };
}

export class ExecutorClient {
  readonly #base: string;
  readonly #fetch: Fetch;
  readonly #clock: Clock | undefined;

  constructor(options: ExecutorClientOptions) {
    this.#base = options.url.replace(/\/?$/, '/');
    this.#fetch = options.fetch ?? fetch;
    this.#clock = options.clock;
  }

  /**
   * Perform one operation.
   * @param token - the GNAP access token for the grant that covers the call.
   * @param signer - the key the token is bound to.
   * @returns the result, or why the executor refused or the call failed.
   */
  async call(
    token: string,
    signer: Signer,
    operation: string,
    args: Record<string, Scalar>,
    signal?: AbortSignal,
  ): Promise<ExecutorCallOutcome> {
    const url = new URL(`operations/${encodeURIComponent(operation)}`, this.#base).toString();
    const body = utf8(JSON.stringify({ arguments: args }));
    const headers = new Headers({
      'content-type': 'application/json',
      authorization: `GNAP ${token}`,
    });
    const signable: SignableRequest = { method: 'POST', url, headers, body };
    applySignatureHeaders(
      headers,
      await signRequest(signable, {
        signer,
        ...(this.#clock !== undefined ? { clock: this.#clock } : {}),
      }),
    );
    const response = await this.#fetch(
      new Request(url, {
        method: 'POST',
        headers,
        body,
        ...(signal !== undefined ? { signal } : {}),
      }),
    );
    const text = await response.text();
    let parsed: unknown;
    try {
      parsed = text.length === 0 ? undefined : JSON.parse(text);
    } catch {
      parsed = undefined;
    }
    if (response.ok) return { kind: 'done', result: (parsed as { result?: unknown })?.result };
    const error = (parsed as ErrorBody | undefined)?.error;
    const description = error?.description ?? `executor answered HTTP ${response.status}`;
    if (response.status === 502) {
      return {
        kind: 'failed',
        status: response.status,
        description,
        effect: error?.effect === 'none' ? 'none' : 'unknown',
      };
    }
    return {
      kind: 'refused',
      status: response.status,
      code: error?.code ?? 'http_error',
      description,
    };
  }
}
