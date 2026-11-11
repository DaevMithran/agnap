/**
 * A connector for an HTTP API. Each operation maps to a method and a path
 * template; arguments fill `{name}` (percent-encoded) or `{+name}` (kept
 * as is, for values such as `owner/repo`), and named arguments go into the
 * query string or a JSON body. The credential is added by the executor and
 * never leaves it.
 */
import type { Scalar } from '@agnap/access-types';
import type {
  Connector,
  ConnectorContext,
  ConnectorOutcome,
  JsonValue,
  OperationCall,
} from '../types.js';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface HttpOperation {
  method: HttpMethod;
  /** Path template, for example `/repos/{+repository}/issues`. */
  path: string;
  /** Arguments sent as query parameters. */
  query?: string[];
  /** Arguments sent as fields of a JSON body. */
  body?: string[];
}

export interface HttpCredential {
  /** Header to set, for example `authorization`. */
  header: string;
  /** Resolves the header value at call time, so a rotated secret is picked up. */
  value: () => string | Promise<string>;
}

export interface HttpConnectorOptions {
  baseUrl: string;
  operations: Record<string, HttpOperation>;
  credential?: HttpCredential;
  fetch?: (request: Request) => Promise<Response>;
}

const SAFE_METHODS: ReadonlySet<HttpMethod> = new Set(['GET']);

const TEMPLATE = /\{(\+?)([A-Za-z0-9_.-]+)\}/g;

export class HttpConnector implements Connector {
  readonly operations: readonly string[];
  readonly #options: HttpConnectorOptions;
  readonly #fetch: (request: Request) => Promise<Response>;

  constructor(options: HttpConnectorOptions) {
    for (const [name, op] of Object.entries(options.operations)) {
      if (!op.path.startsWith('/')) throw new Error(`${name}: path must start with /`);
    }
    this.operations = Object.keys(options.operations);
    this.#options = options;
    this.#fetch = options.fetch ?? fetch;
  }

  async call(call: OperationCall, context: ConnectorContext): Promise<ConnectorOutcome> {
    const op = this.#options.operations[call.operation];
    if (op === undefined) {
      return { kind: 'failed', message: `no HTTP mapping for ${call.operation}`, effect: 'none' };
    }
    const value = (name: string): Scalar | undefined => call.arguments[name];
    let missing: string | undefined;
    const path = op.path.replace(TEMPLATE, (_, raw: string, name: string) => {
      const v = value(name);
      if (v === undefined) {
        missing = name;
        return '';
      }
      return raw === '+' ? String(v) : encodeURIComponent(String(v));
    });
    if (missing !== undefined) {
      return { kind: 'failed', message: `argument ${missing} is required`, effect: 'none' };
    }
    const url = new URL(path.replace(/^\//, ''), this.#options.baseUrl.replace(/\/?$/, '/'));
    for (const name of op.query ?? []) {
      const v = value(name);
      if (v !== undefined) url.searchParams.set(name, String(v));
    }
    const headers = new Headers({ accept: 'application/json' });
    let body: string | undefined;
    if (op.body !== undefined) {
      const fields: Record<string, Scalar> = {};
      for (const name of op.body) {
        const v = value(name);
        if (v !== undefined) fields[name] = v;
      }
      body = JSON.stringify(fields);
      headers.set('content-type', 'application/json');
    }
    const credential = this.#options.credential;
    if (credential !== undefined) {
      try {
        headers.set(credential.header, await credential.value());
      } catch (error) {
        // Nothing was sent, so the call had no effect.
        return {
          kind: 'failed',
          message: `credential unavailable: ${error instanceof Error ? error.message : String(error)}`,
          effect: 'none',
        };
      }
    }

    const effectIfUnsure = SAFE_METHODS.has(op.method) ? 'none' : 'unknown';
    let response: Response;
    try {
      response = await this.#fetch(
        new Request(url, {
          method: op.method,
          headers,
          signal: context.signal,
          ...(body !== undefined ? { body } : {}),
        }),
      );
    } catch (error) {
      return {
        kind: 'failed',
        message: error instanceof Error ? error.message : String(error),
        effect: effectIfUnsure,
      };
    }
    const text = await response.text();
    if (!response.ok) {
      return {
        kind: 'failed',
        message: `downstream answered HTTP ${response.status}`,
        // A 4xx means the service refused the request; a 5xx may have acted.
        effect: response.status < 500 ? 'none' : effectIfUnsure,
      };
    }
    let result: JsonValue = text;
    if (text.length > 0 && (response.headers.get('content-type') ?? '').includes('json')) {
      result = JSON.parse(text) as JsonValue;
    }
    return { kind: 'done', result };
  }
}
