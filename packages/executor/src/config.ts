/**
 * `agnapd.json`: what one executor deployment needs. Connectors are built by
 * type through a registry, so a deployment can add types (UTCP, MCP, a
 * payment API) without changing the executor.
 *
 *   {
 *     "port": 4100,
 *     "issuer": "http://127.0.0.1:4000/",
 *     "resourceServer": { "id": "agnapd", "privateJwkFile": "agnapd-rs.jwk" },
 *     "grantState": { "sqlite": "grant-state.db" },
 *     "connectors": [
 *       { "type": "http", "baseUrl": "https://api.github.com",
 *         "credential": { "header": "authorization", "prefix": "Bearer ", "env": "GITHUB_TOKEN" },
 *         "operations": {
 *           "github.issues.list": { "method": "GET", "path": "/repos/{+repository}/issues", "query": ["state"] }
 *         } }
 *     ]
 *   }
 *
 * Relative file paths resolve against the config file's directory.
 */
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { Ed25519Signer, parsePublicJwk } from '@agnap/gnap-core';
import { serve } from '@agnap/gnap-server';
import { HttpConnector } from './connectors/http.js';
import type { HttpMethod, HttpOperation } from './connectors/http.js';
import { createExecutor } from './executor.js';
import { GnapIntrospector } from './introspect.js';
import type { Connector, ExecutorEvent, GrantStateStore } from './types.js';
import { MemoryGrantStateStore } from './grant-state/memory.js';
import { SqliteGrantStateStore } from './grant-state/sqlite.js';

export interface ConnectorConfig {
  type: string;
  [field: string]: unknown;
}

export interface ExecutorConfig {
  port?: number;
  host?: string;
  publicUrl?: string;
  issuer: string;
  resourceServer: { id: string; privateJwkFile: string };
  grantState: { sqlite: string } | { memory: true };
  connectors: ConnectorConfig[];
}

/** Builds a connector from its config entry. `baseDir` resolves relative paths. */
export type ConnectorFactory = (config: ConnectorConfig, baseDir: string) => Connector;

export class ConfigError extends Error {
  override readonly name = 'ConfigError';
}

const METHODS: readonly HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const isStringArray = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every((x) => typeof x === 'string');

/** The built-in `http` connector type. */
export const httpConnectorFactory: ConnectorFactory = (config, baseDir) => {
  if (typeof config.baseUrl !== 'string') throw new ConfigError('http connector: baseUrl required');
  if (!isObject(config.operations)) throw new ConfigError('http connector: operations required');
  const operations: Record<string, HttpOperation> = {};
  for (const [name, raw] of Object.entries(config.operations)) {
    if (
      !isObject(raw) ||
      typeof raw.path !== 'string' ||
      !METHODS.includes(raw.method as HttpMethod)
    ) {
      throw new ConfigError(`http connector: ${name} needs method and path`);
    }
    if (raw.query !== undefined && !isStringArray(raw.query))
      throw new ConfigError(`http connector: ${name}.query must be a list of argument names`);
    if (raw.body !== undefined && !isStringArray(raw.body))
      throw new ConfigError(`http connector: ${name}.body must be a list of argument names`);
    operations[name] = {
      method: raw.method as HttpMethod,
      path: raw.path,
      ...(raw.query !== undefined ? { query: raw.query } : {}),
      ...(raw.body !== undefined ? { body: raw.body } : {}),
    };
  }
  const credential = config.credential;
  if (credential !== undefined && !isObject(credential))
    throw new ConfigError('http connector: credential must be an object');
  return new HttpConnector({
    baseUrl: config.baseUrl,
    operations,
    ...(credential !== undefined ? { credential: credentialFrom(credential, baseDir) } : {}),
  });
};

/** A credential is read from an environment variable or a file at call time, never from the config itself. */
function credentialFrom(raw: Record<string, unknown>, baseDir: string) {
  if (typeof raw.header !== 'string') throw new ConfigError('credential.header required');
  const prefix = typeof raw.prefix === 'string' ? raw.prefix : '';
  if (typeof raw.env === 'string') {
    const name = raw.env;
    return {
      header: raw.header,
      value: () => {
        const v = process.env[name];
        if (v === undefined || v.length === 0) throw new Error(`credential ${name} is not set`);
        return prefix + v;
      },
    };
  }
  if (typeof raw.file === 'string') {
    const path = resolve(baseDir, raw.file);
    return {
      header: raw.header,
      value: async () => prefix + (await readFile(path, 'utf8')).trim(),
    };
  }
  throw new ConfigError('credential needs env or file; inline secrets are not accepted');
}

export const defaultConnectorFactories: Readonly<Record<string, ConnectorFactory>> = {
  http: httpConnectorFactory,
};

/**
 * Validate a parsed config file.
 * @param value - parsed JSON.
 * @returns the config.
 * @throws ConfigError naming the first problem.
 */
export function parseConfig(value: unknown): ExecutorConfig {
  if (!isObject(value)) throw new ConfigError('config must be an object');
  if (typeof value.issuer !== 'string') throw new ConfigError('issuer required');
  const rs = value.resourceServer;
  if (!isObject(rs) || typeof rs.id !== 'string' || typeof rs.privateJwkFile !== 'string')
    throw new ConfigError('resourceServer needs id and privateJwkFile');
  const grantState = value.grantState;
  if (
    !isObject(grantState) ||
    (typeof grantState.sqlite !== 'string' && grantState.memory !== true)
  )
    throw new ConfigError('grantState must be {"sqlite": path} or {"memory": true}');
  if (!Array.isArray(value.connectors) || value.connectors.length === 0)
    throw new ConfigError('connectors must be a non-empty list');
  for (const [i, c] of value.connectors.entries()) {
    if (!isObject(c) || typeof c.type !== 'string')
      throw new ConfigError(`connectors[${i}].type required`);
  }
  if (value.port !== undefined && (!Number.isInteger(value.port) || (value.port as number) < 0))
    throw new ConfigError('port must be a non-negative integer');
  return value as unknown as ExecutorConfig;
}

export interface StartOptions {
  /** Directory relative paths in the config resolve against. */
  baseDir: string;
  factories?: Readonly<Record<string, ConnectorFactory>>;
  log?: (event: ExecutorEvent) => void;
  fetch?: (request: Request) => Promise<Response>;
}

/**
 * Start an executor from config.
 * @returns its URL and a close function that also closes the grant state store.
 */
export async function startExecutor(
  config: ExecutorConfig,
  options: StartOptions,
): Promise<{ url: string; close: () => Promise<void> }> {
  const factories = { ...defaultConnectorFactories, ...options.factories };
  const connectors = config.connectors.map((c, i) => {
    const factory = factories[c.type];
    if (factory === undefined) throw new ConfigError(`connectors[${i}]: unknown type ${c.type}`);
    return factory(c, options.baseDir);
  });
  const keyFile = resolve(options.baseDir, config.resourceServer.privateJwkFile);
  const raw = JSON.parse(await readFile(keyFile, 'utf8')) as Record<string, unknown>;
  const publicJwk = parsePublicJwk({
    kid: raw.kid,
    alg: raw.alg,
    kty: raw.kty,
    crv: raw.crv,
    x: raw.x,
  });
  if (publicJwk === null || typeof raw.d !== 'string')
    throw new ConfigError(`${keyFile} is not an Ed25519 private JWK`);
  const grantState: GrantStateStore & { close?: () => void } =
    'sqlite' in config.grantState
      ? new SqliteGrantStateStore(resolve(options.baseDir, config.grantState.sqlite))
      : new MemoryGrantStateStore();
  const handler = createExecutor({
    introspector: new GnapIntrospector({
      issuer: config.issuer,
      resourceServerId: config.resourceServer.id,
      signer: Ed25519Signer.fromJwk({ ...publicJwk, d: raw.d }),
      ...(options.fetch !== undefined ? { fetch: options.fetch } : {}),
    }),
    connectors,
    grantState,
    ...(config.publicUrl !== undefined ? { publicUrl: config.publicUrl } : {}),
    ...(options.log !== undefined ? { log: options.log } : {}),
  });
  const running = await serve(handler, {
    ...(config.port !== undefined ? { port: config.port } : {}),
    ...(config.host !== undefined ? { host: config.host } : {}),
  });
  return {
    url: running.url,
    close: async () => {
      await running.close();
      grantState.close?.();
    },
  };
}

/**
 * Read and validate a config file.
 * @param path - the JSON file.
 * @returns the config and the directory its relative paths resolve against.
 */
export async function loadConfig(
  path: string,
): Promise<{ config: ExecutorConfig; baseDir: string }> {
  const config = parseConfig(JSON.parse(await readFile(path, 'utf8')) as unknown);
  return { config, baseDir: dirname(resolve(path)) };
}
