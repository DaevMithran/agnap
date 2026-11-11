/** The owner key pair on disk: a private JWK only this process reads, and its public half for the server. */
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Ed25519Signer, generateKey, parsePublicJwk } from '@agnap/gnap-core';
import type { Ed25519PrivateJwk } from '@agnap/gnap-core';

export const PRIVATE_KEY_FILE = 'owner.jwk';
export const PUBLIC_KEY_FILE = 'owner.pub.jwk';

/**
 * Write a new owner key pair into `directory`. Refuses to overwrite an
 * existing key. The private key is written with mode 0600.
 * @param directory - where to write `owner.jwk` and `owner.pub.jwk`.
 * @param kid - the key id the server will see in signatures.
 * @returns the paths written.
 */
export async function generateOwnerKey(
  directory: string,
  kid = 'agnap-owner',
): Promise<{ privateKeyPath: string; publicKeyPath: string }> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const { privateJwk, publicJwk } = generateKey(kid);
  const privateKeyPath = join(directory, PRIVATE_KEY_FILE);
  const publicKeyPath = join(directory, PUBLIC_KEY_FILE);
  await writeFile(privateKeyPath, `${JSON.stringify(privateJwk, null, 2)}\n`, {
    mode: 0o600,
    flag: 'wx',
  });
  await chmod(privateKeyPath, 0o600);
  await writeFile(publicKeyPath, `${JSON.stringify(publicJwk, null, 2)}\n`, { flag: 'wx' });
  return { privateKeyPath, publicKeyPath };
}

/**
 * Load the owner's signer from a private JWK file.
 * @param path - the `owner.jwk` written by {@link generateOwnerKey}.
 * @returns a signer for owner requests.
 * @throws when the file is not an Ed25519 private JWK.
 */
export async function loadOwnerSigner(path: string): Promise<Ed25519Signer> {
  const raw = JSON.parse(await readFile(path, 'utf8')) as Record<string, unknown>;
  const publicJwk = parsePublicJwk({
    kid: raw.kid,
    alg: raw.alg,
    kty: raw.kty,
    crv: raw.crv,
    x: raw.x,
  });
  if (publicJwk === null || typeof raw.d !== 'string' || raw.d.length === 0) {
    throw new Error(`${path} is not an Ed25519 private JWK`);
  }
  return Ed25519Signer.fromJwk({ ...publicJwk, d: raw.d } satisfies Ed25519PrivateJwk);
}
