#!/usr/bin/env node
/**
 * agnapd keygen [agnapd-rs.jwk] [--id agnapd]
 * agnapd serve --config agnapd.json
 *
 * `keygen` writes the executor's resource-server key (mode 0600) and prints
 * the entry to add to the grant server's `--rs-registry` file.
 *
 * Starts the executor. It answers POST /operations/{operation} for the
 * operations its connectors serve, and logs one line per decision. Register
 * its resource-server public key with the grant server, and keep the
 * downstream credentials readable only by the user agnapd runs as.
 */
import { chmod, writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { generateKey } from '@agnap/gnap-core';
import { loadConfig, startExecutor } from './config.js';

async function main(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    options: { config: { type: 'string' }, id: { type: 'string' } },
    allowPositionals: true,
    strict: true,
  });
  if (positionals[0] === 'keygen') {
    const path = positionals[1] ?? 'agnapd-rs.jwk';
    const id = values.id ?? 'agnapd';
    const { privateJwk, publicJwk } = generateKey(id);
    await writeFile(path, `${JSON.stringify(privateJwk, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    await chmod(path, 0o600);
    console.error(`wrote ${path}; add this entry to the grant server's --rs-registry file:`);
    console.log(JSON.stringify({ id, key: publicJwk, accessTypes: ['agent_operation'] }, null, 2));
    return;
  }
  if (positionals[0] !== 'serve' || values.config === undefined) {
    throw new Error(
      'usage: agnapd keygen [file] [--id agnapd] | agnapd serve --config agnapd.json',
    );
  }
  const { config, baseDir } = await loadConfig(values.config);
  const running = await startExecutor(config, {
    baseDir,
    log: (event) => console.log(JSON.stringify({ at: new Date().toISOString(), ...event })),
  });
  console.log(`agnapd listening on ${running.url}  issuer=${config.issuer}`);
  const stop = () => {
    void running.close().then(() => process.exit(0));
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}

main(process.argv.slice(2)).catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
