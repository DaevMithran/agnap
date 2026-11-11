#!/usr/bin/env node
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import process from 'node:process';

const outputArgument = process.argv[2];
if (outputArgument === undefined) {
  throw new Error('usage: node create-demo-keys.mjs <output-directory>');
}

const outputDirectory = resolve(outputArgument);
await mkdir(outputDirectory, { recursive: true, mode: 0o700 });

const id = 'deepseek-harness';
const kid = 'deepseek-harness-rs';
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privateJwk = { kid, alg: 'EdDSA', ...privateKey.export({ format: 'jwk' }) };
const publicJwk = { kid, alg: 'EdDSA', ...publicKey.export({ format: 'jwk' }) };
const registry = [{ id, key: publicJwk, accessTypes: ['agent_operation'] }];

const privateKeyPath = resolve(outputDirectory, 'deepseek-rs-private.jwk');
const registryPath = resolve(outputDirectory, 'deepseek-rs-registry.json');
const ownerSecretPath = resolve(outputDirectory, 'owner-secret');

await writeFile(privateKeyPath, `${JSON.stringify(privateJwk, null, 2)}\n`, {
  mode: 0o600,
  flag: 'wx',
});
await writeFile(registryPath, `${JSON.stringify(registry, null, 2)}\n`, {
  mode: 0o644,
  flag: 'wx',
});
await writeFile(ownerSecretPath, `${randomBytes(32).toString('base64url')}\n`, {
  mode: 0o600,
  flag: 'wx',
});

process.stdout.write(
  `private JWK: ${privateKeyPath}\nRS registry: ${registryPath}\nowner secret: ${ownerSecretPath}\n`,
);
