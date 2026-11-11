import { mkdtemp, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { agentOperationHandler } from '@agnap/access-types';
import { Ed25519Signer, signedFetchRequest, utf8 } from '@agnap/gnap-core';
import type { AccessItem } from '@agnap/gnap-core';
import {
  MemoryStore,
  StaticResourceServerRegistry,
  createHandler,
  createServer,
  pendingOwner,
} from '@agnap/gnap-server';
import type { PendingGrant } from '@agnap/gnap-server';
import { describe, expect, it } from 'vitest';
import {
  OwnerClient,
  OwnerRequestError,
  RulesError,
  decideByRules,
  generateOwnerKey,
  interactiveDecider,
  keepOperations,
  loadOwnerSigner,
  numberOperations,
  parseRules,
  renderGrant,
  rulesDecider,
  watch,
} from '../src/index.js';

const ISSUER = 'http://as.test/';

const access: AccessItem[] = [
  {
    type: 'agent_operation',
    operations: {
      'github.issues.list': { repository: { exact: 'acme/docs' }, state: { wildcard: true } },
      'github.comment.create': { repository: { exact: 'acme/docs' } },
    },
  },
];

const pendingGrant = (over: Partial<PendingGrant> = {}): PendingGrant => ({
  id: 'g1',
  created_at: new Date(0).toISOString(),
  expires_at: new Date(600_000).toISOString(),
  client_kid: 'client-1',
  client_thumbprint: 'abcdefghijklmnopqrstuvwxyz',
  client_display: { name: 'agent child (subagent of parent)' },
  requested_access: access,
  ...over,
});

function fixture() {
  const owner = Ed25519Signer.generate('owner');
  const store = new MemoryStore();
  const rsRegistry = new StaticResourceServerRegistry([]);
  const handler = createHandler({
    server: createServer(
      {
        issuer: ISSUER,
        registry: rsRegistry,
        accessTypes: [agentOperationHandler],
        decision: pendingOwner,
      },
      store,
    ),
    store,
    rsRegistry,
    publicUrl: ISSUER,
    owner: { key: owner.publicJwk },
  });
  const fetch = (request: Request) => handler(request);
  const client = Ed25519Signer.generate('agent');
  const requestGrant = async (name: string) => {
    const body = {
      access_token: { access },
      client: { key: { proof: 'httpsig', jwk: client.publicJwk }, display: { name } },
    };
    const response = await fetch(
      await signedFetchRequest(
        {
          method: 'POST',
          url: ISSUER,
          headers: new Headers({ 'content-type': 'application/json' }),
          body: utf8(JSON.stringify(body)),
        },
        { signer: client },
      ),
    );
    expect(response.status).toBe(200);
  };
  return {
    owner: new OwnerClient({ issuer: ISSUER, signer: owner, fetch }),
    impostor: new OwnerClient({ issuer: ISSUER, signer: Ed25519Signer.generate('owner'), fetch }),
    store,
    requestGrant,
  };
}

describe('describe', () => {
  it('numbers operations and renders a card from the grant alone', () => {
    expect(numberOperations(access).map((op) => `${op.number} ${op.operation}`)).toEqual([
      '1 github.issues.list',
      '2 github.comment.create',
    ]);
    const card = renderGrant(pendingGrant(), 1_000).join('\n');
    expect(card).toContain('agent child (subagent of parent)');
    expect(card).toContain('unverified');
    expect(card).toContain('1. github.issues.list  repository = "acme/docs", state = any');
    expect(card).toContain('in 9m 59s');
  });

  it('keeps only the chosen operations, and refuses to keep none', () => {
    expect(keepOperations(access, new Set([2]))).toEqual([
      {
        type: 'agent_operation',
        operations: { 'github.comment.create': { repository: { exact: 'acme/docs' } } },
      },
    ]);
    expect(keepOperations(access, new Set())).toBeNull();
  });
});

describe('rules', () => {
  const rules = parseRules({
    rules: [
      { operation: 'github.issues.*', decision: 'approve' },
      { operation: 'github.comment.create', client: 'agent child*', decision: 'deny' },
    ],
    default: 'skip',
  });

  it('approves only when every operation is approved, denies on any deny, else the default', () => {
    expect(decideByRules(rules, pendingGrant())).toBe('deny');
    expect(decideByRules(rules, pendingGrant({ client_display: { name: 'root' } }))).toBe('skip');
    expect(
      decideByRules(
        rules,
        pendingGrant({ requested_access: keepOperations(access, new Set([1]))! }),
      ),
    ).toBe('approve');
  });

  it('rejects malformed rules', () => {
    expect(() => parseRules({ rules: [{ operation: '', decision: 'approve' }] })).toThrow(
      RulesError,
    );
    expect(() => parseRules({ rules: [{ operation: 'x', decision: 'maybe' }] })).toThrow(
      RulesError,
    );
    expect(() => parseRules({ rules: [], default: 'later' })).toThrow(RulesError);
  });
});

describe('keys', () => {
  it('writes a 0600 private key, refuses to overwrite it, and loads it back', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'agnap-owner-'));
    const written = await generateOwnerKey(dir);
    expect((await stat(written.privateKeyPath)).mode & 0o777).toBe(0o600);
    expect(JSON.parse(await readFile(written.publicKeyPath, 'utf8'))).not.toHaveProperty('d');
    await expect(generateOwnerKey(dir)).rejects.toThrow();
    const signer = await loadOwnerSigner(written.privateKeyPath);
    expect(signer.kid).toBe('agnap-owner');
    await expect(loadOwnerSigner(written.publicKeyPath)).rejects.toThrow(/private JWK/);
  });
});

describe('owner client and watch against the server', () => {
  it('lists with the display name, and the server refuses another key', async () => {
    const f = fixture();
    await f.requestGrant('agent root');
    const [grant] = await f.owner.listPending();
    expect(grant?.client_display).toEqual({ name: 'agent root' });
    await expect(f.impostor.listPending()).rejects.toBeInstanceOf(OwnerRequestError);
  });

  it('watch --once with rules approves, denies and skips', async () => {
    const f = fixture();
    await f.requestGrant('approve-me');
    await f.requestGrant('deny-me');
    await f.requestGrant('skip-me');
    const lines: string[] = [];
    const rules = parseRules({
      rules: [
        { operation: '*', client: 'approve-me', decision: 'approve' },
        { operation: '*', client: 'deny-me', decision: 'deny' },
      ],
      default: 'skip',
    });
    await watch({
      client: f.owner,
      decide: rulesDecider(rules, (line) => lines.push(line)),
      log: (line) => lines.push(line),
      signal: new AbortController().signal,
      intervalMs: 10,
      once: true,
    });
    const states = (await f.store.listGrants())
      .map((g) => `${g.clientDisplay?.name}:${g.state}`)
      .sort();
    expect(states).toEqual(['approve-me:approved', 'deny-me:denied', 'skip-me:pending']);
    expect(lines.filter((line) => line.startsWith('→ rules'))).toHaveLength(3);
  });

  it('the interactive decider narrows to the chosen operations', async () => {
    const f = fixture();
    await f.requestGrant('agent');
    const answers = ['?', 'n', '9', 'n', '1'];
    const asked: string[] = [];
    await watch({
      client: f.owner,
      decide: interactiveDecider(
        (prompt) => {
          asked.push(prompt);
          return Promise.resolve(answers.shift() ?? 'd');
        },
        () => undefined,
      ),
      log: () => undefined,
      signal: new AbortController().signal,
      intervalMs: 10,
      once: true,
    });
    const [grant] = await f.store.listGrants();
    expect(grant?.state).toBe('approved');
    expect(grant?.decidedAccess).toEqual(keepOperations(access, new Set([1])));
    expect(asked.filter((prompt) => prompt.startsWith('[a]pprove'))).toHaveLength(3);
  });

  it('keeps polling after a server error and stops on abort', async () => {
    let calls = 0;
    const failing = new OwnerClient({
      issuer: ISSUER,
      signer: Ed25519Signer.generate('owner'),
      fetch: () => {
        calls += 1;
        return Promise.resolve(new Response('{}', { status: 503 }));
      },
    });
    const controller = new AbortController();
    const lines: string[] = [];
    const running = watch({
      client: failing,
      decide: () => Promise.resolve({ kind: 'skip' }),
      log: (line) => lines.push(line),
      signal: controller.signal,
      intervalMs: 5,
    });
    await new Promise((resolve) => setTimeout(resolve, 40));
    controller.abort();
    await running;
    expect(calls).toBeGreaterThan(1);
    expect(lines[0]).toMatch(/cannot list pending grants: .*HTTP 503/);
  });
});
