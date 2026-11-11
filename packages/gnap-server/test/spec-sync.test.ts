/**
 * The canonical contract lives in `packages/specs/openapi`. This server
 * carries no copy. The routes it registers must be exactly the paths and
 * methods those two documents declare, so neither can drift from the other.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { agentOperationHandler } from '@agnap/access-types';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import { Router } from '../src/http/router.js';
import { registerRoutes } from '../src/http/routes.js';
import { registerOwnerRoutes } from '../src/http/routes-owner.js';
import {
  createHandler,
  createServer,
  MemoryStore,
  pendingOwner,
  StaticResourceServerRegistry,
} from '../src/index.js';
import { makeAuthenticate } from '../src/http/authenticate.js';

const SPECS = resolve(import.meta.dirname, '../../specs/openapi');

function document(file: string): {
  paths: Record<string, Record<string, { responses?: Record<string, unknown> }>>;
} {
  return parse(readFileSync(resolve(SPECS, file), 'utf8')) as {
    paths: Record<string, Record<string, { responses?: Record<string, unknown> }>>;
  };
}

function declared(file: string): Set<string> {
  const doc = document(file);
  const out = new Set<string>();
  for (const [path, ops] of Object.entries(doc.paths)) {
    for (const method of Object.keys(ops)) out.add(`${method.toUpperCase()} ${path}`);
  }
  return out;
}

function registered(): Set<string> {
  const store = new MemoryStore();
  const rsRegistry = new StaticResourceServerRegistry();
  const server = createServer(
    {
      issuer: 'http://127.0.0.1:0/',
      registry: rsRegistry,
      accessTypes: [agentOperationHandler],
      decision: pendingOwner,
    },
    store,
  );
  const router = new Router();
  const deps = {
    server,
    store,
    rsRegistry,
    authenticate: makeAuthenticate({ store }),
    localOwner: { secret: 'test' },
  };
  registerRoutes(router, deps);
  registerOwnerRoutes(router, deps);
  return new Set(
    router.table().map((r) => `${r.method} ${r.pattern.replaceAll(/:([A-Za-z]+)/g, '{$1}')}`),
  );
}

describe('OpenAPI contract and registered routes agree', () => {
  it('as.yaml plus local-owner.yaml declare exactly the routes the server registers', () => {
    const spec = new Set([...declared('as.yaml'), ...declared('local-owner.yaml')]);
    expect([...registered()].sort()).toEqual([...spec].sort());
  });

  it('declares transport-level overload and body-limit responses', () => {
    const as = document('as.yaml');
    for (const [path, method] of [
      ['/', 'post'],
      ['/continue/{id}', 'post'],
      ['/token/{id}', 'delete'],
      ['/introspect', 'post'],
    ] as const) {
      expect(as.paths[path]?.[method]?.responses, `${method.toUpperCase()} ${path}`).toHaveProperty(
        '503',
      );
      expect(as.paths[path]?.[method]?.responses, `${method.toUpperCase()} ${path}`).toHaveProperty(
        '413',
      );
    }
    expect(
      document('local-owner.yaml').paths['/local/grants/{id}']?.post?.responses,
    ).toHaveProperty('413');
  });

  it('the handler answers every declared route with something other than 404', async () => {
    const store = new MemoryStore();
    const rsRegistry = new StaticResourceServerRegistry();
    const handler = createHandler({
      server: createServer(
        {
          issuer: 'http://127.0.0.1:0/',
          registry: rsRegistry,
          accessTypes: [agentOperationHandler],
          decision: pendingOwner,
        },
        store,
      ),
      store,
      rsRegistry,
      localOwner: { secret: 'test' },
    });
    for (const entry of [...declared('as.yaml'), ...declared('local-owner.yaml')]) {
      const [method, path] = entry.split(' ') as [string, string];
      const res = await handler(
        new Request(`http://127.0.0.1${path.replaceAll(/\{[a-z]+\}/g, 'abc')}`, { method }),
      );
      expect(res.status, entry).not.toBe(404);
    }
  });
});
