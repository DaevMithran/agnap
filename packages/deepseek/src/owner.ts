import type { Fetch, OwnerDecisionPort } from './types.js';

export interface LocalOwnerClientOptions {
  issuer: string;
  secret: string;
  fetch?: Fetch;
}

/** Development-only bridge. A production client must never hold the owner's credential. */
export class LocalOwnerClient implements OwnerDecisionPort {
  readonly #issuer: string;
  readonly #secret: string;
  readonly #fetch: Fetch;

  constructor(options: LocalOwnerClientOptions) {
    if (options.secret.length === 0) throw new RangeError('owner secret must not be empty');
    this.#issuer = options.issuer;
    this.#secret = options.secret;
    this.#fetch = options.fetch ?? fetch;
  }

  async resolve(
    grantId: string,
    decision: 'approve' | 'deny',
    signal?: AbortSignal,
  ): Promise<void> {
    const response = await this.#fetch(
      new Request(new URL(`local/grants/${encodeURIComponent(grantId)}`, this.#issuer), {
        method: 'POST',
        headers: {
          authorization: `Bearer ${this.#secret}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ decision }),
        ...(signal !== undefined ? { signal } : {}),
      }),
    );
    if (!response.ok) throw new Error(`owner decision failed with HTTP ${response.status}`);
  }
}
