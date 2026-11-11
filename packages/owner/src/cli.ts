#!/usr/bin/env node
/**
 * agnap-owner keygen [dir]
 * agnap-owner list                          [--url U] [--key F]
 * agnap-owner approve <grant-id> [--keep 1,3] [--url U] [--key F]
 * agnap-owner deny <grant-id>               [--url U] [--key F]
 * agnap-owner watch [--rules rules.json] [--interval ms] [--once] [--url U] [--key F]
 *
 * --url  the GNAP server (default $AGNAP_URL, else http://127.0.0.1:4000/)
 * --key  the owner's private JWK (default $AGNAP_OWNER_KEY, else ~/.config/agnap-owner/owner.jwk)
 *
 * Start the server with the matching public key:
 *   gnap-server serve --owner-key ~/.config/agnap-owner/owner.pub.jwk
 */
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { parseArgs } from 'node:util';
import { OwnerClient } from './client.js';
import { keepOperations, renderGrant } from './describe.js';
import { generateOwnerKey, loadOwnerSigner, PRIVATE_KEY_FILE } from './keys.js';
import { parseRules } from './rules.js';
import { interactiveDecider, rulesDecider, watch } from './watch.js';

const DEFAULT_DIR = join(homedir(), '.config', 'agnap-owner');
const log = (line: string) => console.log(line);

async function client(values: { url?: string; key?: string }): Promise<OwnerClient> {
  const issuer = values.url ?? process.env.AGNAP_URL ?? 'http://127.0.0.1:4000/';
  const keyPath = values.key ?? process.env.AGNAP_OWNER_KEY ?? join(DEFAULT_DIR, PRIVATE_KEY_FILE);
  return new OwnerClient({ issuer, signer: await loadOwnerSigner(keyPath) });
}

async function main(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      url: { type: 'string' },
      key: { type: 'string' },
      keep: { type: 'string' },
      rules: { type: 'string' },
      interval: { type: 'string' },
      once: { type: 'boolean' },
    },
    allowPositionals: true,
    strict: true,
  });
  const [command, argument] = positionals;

  switch (command) {
    case 'keygen': {
      const written = await generateOwnerKey(argument ?? DEFAULT_DIR);
      log(`private key  ${written.privateKeyPath}  (keep it away from agents)`);
      log(`public key   ${written.publicKeyPath}`);
      log(`start the server with: gnap-server serve --owner-key ${written.publicKeyPath}`);
      return;
    }
    case 'list': {
      const pending = await (await client(values)).listPending();
      if (pending.length === 0) log('no pending grants');
      for (const grant of pending) {
        log('');
        for (const line of renderGrant(grant)) log(line);
      }
      return;
    }
    case 'approve': {
      if (argument === undefined)
        throw new Error('usage: agnap-owner approve <grant-id> [--keep 1,3]');
      const owner = await client(values);
      let access;
      if (values.keep !== undefined) {
        const grant = (await owner.listPending()).find((g) => g.id === argument);
        if (grant === undefined) throw new Error(`no pending grant ${argument}`);
        access = keepOperations(
          grant.requested_access,
          new Set(values.keep.split(',').map(Number)),
        );
        if (access === null) throw new Error('--keep must name at least one operation');
      }
      await owner.approve(argument, access ?? undefined);
      log(`approved ${argument}`);
      return;
    }
    case 'deny': {
      if (argument === undefined) throw new Error('usage: agnap-owner deny <grant-id>');
      await (await client(values)).deny(argument);
      log(`denied ${argument}`);
      return;
    }
    case 'watch': {
      const owner = await client(values);
      const intervalMs = Number(values.interval ?? 1000);
      if (!Number.isInteger(intervalMs) || intervalMs <= 0)
        throw new Error('--interval must be a positive number of milliseconds');
      const controller = new AbortController();
      process.once('SIGINT', () => controller.abort());
      process.once('SIGTERM', () => controller.abort());
      if (values.rules !== undefined) {
        const rules = parseRules(JSON.parse(await readFile(values.rules, 'utf8')) as unknown);
        await watch({
          client: owner,
          decide: rulesDecider(rules, log),
          log,
          signal: controller.signal,
          intervalMs,
          ...(values.once === true ? { once: true } : {}),
        });
        return;
      }
      const terminal = createInterface({ input: process.stdin });
      // Buffered, so answers typed or piped ahead of a prompt are not lost.
      const lines = terminal[Symbol.asyncIterator]();
      const ask = async (prompt: string): Promise<string | null> => {
        process.stdout.write(prompt);
        const next = await lines.next();
        if (next.done === true) {
          log('\ninput closed; stopping');
          controller.abort();
          return null;
        }
        return next.value;
      };
      controller.signal.addEventListener('abort', () => terminal.close(), { once: true });
      log('watching for pending grants; Ctrl-C to stop');
      try {
        await watch({
          client: owner,
          decide: interactiveDecider(ask, log),
          log,
          signal: controller.signal,
          intervalMs,
          ...(values.once === true ? { once: true } : {}),
        });
      } finally {
        terminal.close();
      }
      return;
    }
    case undefined:
    default:
      throw new Error('usage: agnap-owner keygen | list | approve <id> | deny <id> | watch');
  }
}

main(process.argv.slice(2)).catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
