/**
 * RFC 9421 comes from `http-message-sig`. These tests are the acceptance
 * gate for that dependency: the RFC's own Ed25519 vector (Appendix B.2.6,
 * key B.1.4) must come out byte for byte through our wrapper. Then the GNAP
 * profile on top: fixed components, fixed parameters, digest, time window,
 * nonce.
 */
import { describe, expect, it } from 'vitest';
import {
  Ed25519Signer,
  HttpSigError,
  applySignatureHeaders,
  contentDigest,
  fixedClock,
  signComponents,
  signRequest,
  utf8,
  verifyRequest,
} from '../src/index.js';
import type { NonceCheck, SignableRequest } from '../src/index.js';
import { verifyMessageSignature } from './helpers/verify-message-signature.js';

// RFC 9421 Appendix B.1.4
const RFC_PRIVATE_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----`;
const RFC_X = 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs';
const RFC_D = 'n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU';

// RFC 9421 Appendix B.2 test request and B.2.6 vector
const RFC_REQUEST: SignableRequest = {
  method: 'POST',
  url: 'http://example.com/foo?param=Value&Pet=dog',
  headers: new Headers({
    host: 'example.com',
    date: 'Tue, 20 Apr 2021 02:07:55 GMT',
    'content-type': 'application/json',
    'content-digest':
      'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
    'content-length': '18',
  }),
  body: utf8('{"hello": "world"}'),
};
const RFC_SIGNATURE_INPUT =
  'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"';
const RFC_SIGNATURE =
  'sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:';
describe('RFC 9421 Appendix B.2.6 Ed25519 vector', () => {
  const rfcSigner = Ed25519Signer.fromPem('test-key-ed25519', RFC_PRIVATE_PEM);

  it('imports the B.1.4 key to the JWK the RFC prints', () => {
    expect(rfcSigner.publicJwk.x).toBe(RFC_X);
    expect(Ed25519Signer.fromJwk({ ...rfcSigner.publicJwk, d: RFC_D }).publicJwk.x).toBe(RFC_X);
  });

  it('reproduces the RFC signature-input and signature byte for byte (Ed25519 is deterministic)', async () => {
    const signed = await signComponents(RFC_REQUEST, {
      label: 'sig-b26',
      components: ['date', '@method', '@path', '@authority', 'content-type', 'content-length'],
      parameters: { created: 1618884473, keyid: 'test-key-ed25519' },
      signer: rfcSigner,
    });
    expect(signed['signature-input']).toBe(RFC_SIGNATURE_INPUT);
    expect(signed.signature).toBe(RFC_SIGNATURE);
  });

  it('verifies the RFC message with the RFC key, and not with another key', async () => {
    const headers = new Headers(RFC_REQUEST.headers);
    headers.set('signature-input', RFC_SIGNATURE_INPUT);
    headers.set('signature', RFC_SIGNATURE);
    const req = { ...RFC_REQUEST, headers };
    expect((await verifyMessageSignature(req, rfcSigner.publicJwk)).components).toHaveLength(6);
    const other = Ed25519Signer.generate('test-key-ed25519');
    await expect(verifyMessageSignature(req, other.publicJwk)).rejects.toThrow(HttpSigError);
  });

  it('picks the right member when several signatures are present', async () => {
    const headers = new Headers(RFC_REQUEST.headers);
    headers.set('signature-input', `sig-x=("@method");created=1;keyid="x", ${RFC_SIGNATURE_INPUT}`);
    headers.set('signature', `sig-x=:AAAA:, ${RFC_SIGNATURE}`);
    const req = { ...RFC_REQUEST, headers };
    expect((await verifyMessageSignature(req, rfcSigner.publicJwk, 'sig-b26')).label).toBe(
      'sig-b26',
    );
    await expect(verifyMessageSignature(req, rfcSigner.publicJwk)).rejects.toThrow(/LabelRequired/);
  });
});

const clock = fixedClock(1_700_000_000_000);
const signer = Ed25519Signer.generate('client-key-1');
const other = Ed25519Signer.generate('client-key-1'); // same kid, different key

function request(overrides: Partial<SignableRequest> = {}): SignableRequest {
  return {
    method: 'POST',
    url: 'http://localhost:4000/continue/abc',
    headers: new Headers({
      'content-type': 'application/json',
      authorization: 'GNAP OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0',
    }),
    body: utf8(JSON.stringify({ hello: 'world' })),
    ...overrides,
  };
}

async function signed(
  req: SignableRequest = request(),
  nonce = 'nonce-1',
): Promise<SignableRequest> {
  const headers = new Headers(req.headers);
  applySignatureHeaders(headers, await signRequest(req, { signer, clock, nonce }));
  return { ...req, headers };
}

async function failure(promise: Promise<unknown>): Promise<HttpSigError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof HttpSigError) return error;
    throw error;
  }
  throw new Error('expected verification to fail');
}

describe('GNAP profile: sign', () => {
  it('produces the fixed covered components and parameters', async () => {
    const req = await signed();
    expect(req.headers.get('signature-input')).toBe(
      'sig1=("@method" "@target-uri" "content-digest" "authorization");created=1700000000;keyid="client-key-1";nonce="nonce-1";tag="gnap"',
    );
    expect(req.headers.get('content-digest')).toMatch(/^sha-256=:[A-Za-z0-9+/]+=*:$/);
    expect(req.headers.get('signature')).toMatch(/^sig1=:[A-Za-z0-9+/]+=*:$/);
  });

  it('omits content-digest and authorization when absent', async () => {
    const req = await signed(
      request({ method: 'GET', headers: new Headers(), body: new Uint8Array() }),
    );
    expect(req.headers.get('signature-input')).toMatch(/^sig1=\("@method" "@target-uri"\);/);
    expect(req.headers.has('content-digest')).toBe(false);
    await expect(verifyRequest(req, { publicJwk: signer.publicJwk, clock })).resolves.toMatchObject(
      { nonce: 'nonce-1' },
    );
  });
});

describe('GNAP profile: verify', () => {
  it('verifies a request it signed', async () => {
    const result = await verifyRequest(await signed(), { publicJwk: signer.publicJwk, clock });
    expect(result.created).toBe(1_700_000_000);
    expect(result.keyThumbprint).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('fails when one byte of the body changes', async () => {
    const req = await signed();
    const body = new Uint8Array(req.body);
    body[body.length - 3] = (body[body.length - 3] ?? 0) ^ 0x01;
    const error = await failure(
      verifyRequest({ ...req, body }, { publicJwk: signer.publicJwk, clock }),
    );
    expect(error.detail).toMatch(/content-digest/);
  });

  it('fails when the body is replaced along with a matching digest', async () => {
    const req = await signed();
    const body = utf8(JSON.stringify({ hello: 'mars' }));
    const headers = new Headers(req.headers);
    headers.set('content-digest', contentDigest(body));
    const error = await failure(
      verifyRequest({ ...req, body, headers }, { publicJwk: signer.publicJwk, clock }),
    );
    expect(error.detail).toMatch(/verification failed/i);
  });

  it('rejects a malformed content-digest instead of decoding it leniently', async () => {
    const req = await signed();
    const good = req.headers.get('content-digest') as string;
    const cases = [
      good.replace(/^sha-256=:(.)/, 'sha-256=:!'), // character outside base64
      good.slice(0, -1), // unterminated byte sequence
      good.replace('sha-256=', 'sha-256='), // unchanged control: still valid
      `sha-512=:AAAA:, ${good}`, // other algorithm first, ours still present and valid
      'sha-512=:AAAA:', // ours absent
      'sha-256="not bytes"', // wrong item type
    ];
    const expected = [false, false, true, true, false, false];
    const { verifyContentDigest } = await import('../src/httpsig/index.js');
    cases.forEach((h, i) => expect(verifyContentDigest(h, req.body), h).toBe(expected[i]));
  });

  it('fails when the method, target or authorization header changes', async () => {
    const req = await signed();
    for (const mutated of [
      { ...req, method: 'PUT' },
      { ...req, url: 'http://localhost:4000/continue/xyz' },
      { ...req, url: 'http://evil.example/continue/abc' },
    ]) {
      expect(
        (await failure(verifyRequest(mutated, { publicJwk: signer.publicJwk, clock }))).code,
      ).toBe('invalid_proof');
    }
    const headers = new Headers(req.headers);
    headers.set('authorization', 'GNAP OTHERTOKEN');
    expect(
      (await failure(verifyRequest({ ...req, headers }, { publicJwk: signer.publicJwk, clock })))
        .code,
    ).toBe('invalid_proof');
  });

  it('fails with a different key under the same kid, and when keyid does not match kid', async () => {
    const req = await signed();
    expect((await failure(verifyRequest(req, { publicJwk: other.publicJwk, clock }))).code).toBe(
      'invalid_proof',
    );
    const renamed = { ...signer.publicJwk, kid: 'some-other-kid' };
    expect((await failure(verifyRequest(req, { publicJwk: renamed, clock }))).detail).toMatch(
      /keyid/,
    );
  });

  it('fails when a body is present without a content-digest', async () => {
    const req = await signed();
    const headers = new Headers(req.headers);
    headers.delete('content-digest');
    const error = await failure(
      verifyRequest({ ...req, headers }, { publicJwk: signer.publicJwk, clock }),
    );
    expect(error.code).toBe('invalid_proof');
  });

  it('fails when created is outside the window, in either direction', async () => {
    const req = await signed();
    expect(
      (
        await failure(
          verifyRequest(req, {
            publicJwk: signer.publicJwk,
            clock: fixedClock(clock.now() + 301_000),
          }),
        )
      ).code,
    ).toBe('expired');
    expect(
      (
        await failure(
          verifyRequest(req, {
            publicJwk: signer.publicJwk,
            clock: fixedClock(clock.now() - 301_000),
          }),
        )
      ).code,
    ).toBe('expired');
    await expect(
      verifyRequest(req, { publicJwk: signer.publicJwk, clock: fixedClock(clock.now() + 300_000) }),
    ).resolves.toBeDefined();
  });

  it('rejects a replayed nonce and records the nonce only after the signature verifies', async () => {
    const seen = new Set<string>();
    const nonceCheck: NonceCheck = ({ nonce, keyThumbprint }) => {
      const key = `${keyThumbprint}:${nonce}`;
      if (seen.has(key)) return 'seen';
      seen.add(key);
      return 'fresh';
    };
    const req = await signed();
    await expect(
      verifyRequest(req, { publicJwk: signer.publicJwk, clock, nonceCheck }),
    ).resolves.toBeDefined();
    expect(
      (await failure(verifyRequest(req, { publicJwk: signer.publicJwk, clock, nonceCheck }))).code,
    ).toBe('replayed');
    const forged = await signed(request(), 'nonce-2');
    expect(
      (await failure(verifyRequest(forged, { publicJwk: other.publicJwk, clock, nonceCheck })))
        .code,
    ).toBe('invalid_proof');
    expect(seen.size).toBe(1);
  });

  it('rejects signature headers outside the profile', async () => {
    const req = await signed();
    const ok = '("@method" "@target-uri" "content-digest" "authorization")';
    const cases: Array<[string, string]> = [
      [
        'signature-input',
        `sig1=("@method" "@target-uri");created=1700000000;keyid="client-key-1";nonce="n";tag="gnap"`,
      ],
      [
        'signature-input',
        `sig1=${ok};created=1700000000;keyid="client-key-1";nonce="n";tag="other"`,
      ],
      ['signature-input', `sig1=${ok};keyid="client-key-1";nonce="n";tag="gnap"`],
      ['signature-input', `sig1=${ok};created=1700000000;keyid="client-key-1";tag="gnap"`],
      [
        'signature-input',
        `sig1=${ok};created=1700000000;keyid="client-key-1";nonce="n";tag="gnap";alg="rsa-pss-sha512"`,
      ],
      [
        'signature-input',
        `sig1=${ok};created=1700000000;keyid="client-key-1";nonce="n";tag="gnap";custom=1`,
      ],
      [
        'signature-input',
        `sig1=("@method" "@target-uri" "content-digest" "authorization";key="x");created=1700000000;keyid="client-key-1";nonce="n";tag="gnap"`,
      ],
      [
        'signature-input',
        `sig1=${ok};created=1700000000;keyid="client-key-1";nonce="n";tag="gnap", sig2=("@method");created=1;keyid="k";nonce="n";tag="gnap"`,
      ],
      ['signature', 'sig2=:AAAA:'],
      ['signature', 'sig1=AAAA'],
      ['signature-input', 'garbage'],
    ];
    for (const [name, value] of cases) {
      const headers = new Headers(req.headers);
      headers.set(name, value);
      const error = await failure(
        verifyRequest({ ...req, headers }, { publicJwk: signer.publicJwk, clock }),
      );
      expect(error.code, `${name}: ${value}`).toBe('invalid_proof');
    }
  });

  it('accepts a signature-input serialized in a different parameter order', async () => {
    const req = request();
    const headers = new Headers(req.headers);
    headers.set('content-digest', contentDigest(req.body));
    const other = await signComponents(
      { ...req, headers },
      {
        label: 'sig1',
        components: ['@method', '@target-uri', 'content-digest', 'authorization'],
        parameters: { tag: 'gnap', nonce: 'n', keyid: 'client-key-1', created: 1_700_000_000 },
        signer,
      },
    );
    expect(other['signature-input']).toMatch(
      /;tag="gnap";nonce="n";keyid="client-key-1";created=1700000000$/,
    );
    headers.set('signature-input', other['signature-input']);
    headers.set('signature', other.signature);
    await expect(
      verifyRequest({ ...req, headers }, { publicJwk: signer.publicJwk, clock }),
    ).resolves.toBeDefined();
  });
});
