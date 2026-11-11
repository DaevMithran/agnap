#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { agentOperationHandler } from '@agnap/access-types';
import { parsePublicJwk } from '@agnap/gnap-core';
import { createHandler } from './http/handler.js';
import { serve } from './http/node.js';
import { pendingOwner } from './protocol/decision.js';
import { StaticResourceServerRegistry } from './protocol/registry.js';
import { createServer } from './protocol/server.js';
import { MemoryStore } from './store/memory.js';
import type { ResourceServerEntry } from './types/registry.js';

/**
 * GNAP_OWNER_SECRET=... gnap-server serve --port 4000 --issuer http://127.0.0.1:4000/ --rs-registry rs.json
 *                    [--continue-wait <seconds>]   polling interval for pending grants (default 5)
 * gnap-server owner  list | approve <grant-id> [--access-file f.json] [--audiences rs1,rs2] | deny <grant-id>
 *                    --url http://127.0.0.1:4000 --secret S
 *
 * `serve` registers the agent_operation access type and waits for the owner
 * on every request. `owner` is the helper that holds the local secret; the
 * client never does.
 */

function loadRegistry(path: string | undefined): StaticResourceServerRegistry {
  if (path === undefined) return new StaticResourceServerRegistry();
  const raw = JSON.parse(readFileSync(path, 'utf8')) as unknown;
  if (!Array.isArray(raw)) throw new Error('rs registry file must be a JSON array');
  const entries: ResourceServerEntry[] = raw.map(
    (e: { id?: unknown; key?: unknown; accessTypes?: unknown }, i) => {
      const key = parsePublicJwk(e.key);
      if (typeof e.id !== 'string' || key === null || !Array.isArray(e.accessTypes)) {
        throw new Error(`rs registry entry ${i} needs id, key (Ed25519 JWK) and accessTypes`);
      }
      return { id: e.id, key, accessTypes: e.accessTypes as string[] };
    },
  );
  return new StaticResourceServerRegistry(entries);
}

async function serveCommand(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      port: { type: 'string' },
      issuer: { type: 'string' },
      'rs-registry': { type: 'string' },
      'continue-wait': { type: 'string' },
    },
    strict: true,
  });
  const port = Number(values.port ?? 4000);
  const issuer = values.issuer ?? `http://127.0.0.1:${port}/`;
  const secret = process.env.GNAP_OWNER_SECRET;
  const store = new MemoryStore();
  const rsRegistry = loadRegistry(values['rs-registry']);
  const continueWait = values['continue-wait'];
  const server = createServer(
    {
      issuer,
      registry: rsRegistry,
      accessTypes: [agentOperationHandler],
      decision: pendingOwner,
      ...(continueWait !== undefined ? { continueWaitSeconds: Number(continueWait) } : {}),
    },
    store,
  );
  const handler = createHandler({
    server,
    store,
    rsRegistry,
    publicUrl: issuer,
    ...(secret !== undefined ? { localOwner: { secret } } : {}),
  });
  const running = await serve(handler, { port });
  console.log(
    `gnap-server listening on ${running.url}  issuer=${issuer}  owner-extension=${secret !== undefined ? 'on' : 'off'}`,
  );
  if (!issuer.startsWith('https://'))
    console.log('loopback HTTP: fine for development, non-conformant for anything else');
}

async function ownerCommand(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    options: {
      url: { type: 'string' },
      secret: { type: 'string' },
      'access-file': { type: 'string' },
      audiences: { type: 'string' },
    },
    allowPositionals: true,
    strict: true,
  });
  const url = (values.url ?? 'http://127.0.0.1:4000').replace(/\/+$/, '');
  const secret = values.secret ?? process.env.GNAP_OWNER_SECRET;
  if (secret === undefined) throw new Error('--secret or GNAP_OWNER_SECRET is required');
  const headers = { authorization: `Bearer ${secret}`, 'content-type': 'application/json' };
  const sub = positionals[0];
  if (sub === 'list') {
    const r = await fetch(`${url}/local/grants`, { headers });
    console.log(JSON.stringify(await r.json(), null, 2));
    return;
  }
  const id = positionals[1];
  if ((sub !== 'approve' && sub !== 'deny') || id === undefined)
    throw new Error('usage: owner list | approve <id> | deny <id>');
  const body: Record<string, unknown> = { decision: sub };
  const accessFile = values['access-file'];
  if (accessFile !== undefined) body.access = JSON.parse(readFileSync(accessFile, 'utf8'));
  const audiences = values.audiences;
  if (audiences !== undefined) body.audiences = audiences.split(',');
  const r = await fetch(`${url}/local/grants/${id}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  console.log(r.status, JSON.stringify(await r.json()));
}

const [command, ...rest] = process.argv.slice(2);
const run =
  command === 'serve'
    ? serveCommand(rest)
    : command === 'owner'
      ? ownerCommand(rest)
      : Promise.reject(new Error('usage: gnap-server serve | owner'));
run.catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
