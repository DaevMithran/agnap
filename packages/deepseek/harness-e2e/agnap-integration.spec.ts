/**
 * The AGNAP plugin inside the real DeepSeek Harness (0.2.1-alpha.1 @ 5badb15).
 *
 * Real AgentLoop, tool registry and ApprovalService; a scripted model; the
 * plugin mounted through its Cordis entry point; the real gnap-server over
 * loopback HTTP. The tools are fakes that record whether they ran: there is
 * no executor yet, so this covers the in-process gate, not credential
 * isolation.
 *
 * Run with ./run.sh, which places this file in the Harness tree at
 * packages/test-support/agent-loop-testkit/tests/ and sets AGNAP_ROOT.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Context } from '@deepseek-ai/cordis';
import AgentLoop from '@deepseek-ai/dsh-agent-loop';
import { createUserMessage } from '@deepseek-ai/dsh-llm';
import { SessionId, type SessionEvent } from '@deepseek-ai/dsh-session';
import { defineContentToolFixture } from '@deepseek-ai/dsh-tools';
import type { Agent } from '@deepseek-ai/dsh-agent';
import { mountAgentLoopTestDependencies } from '../src/index.ts';
import ApprovalService from '../../../interaction/user-approval/src/index.ts';
import {
  MockAdapter,
  textResponse,
  toolCallResponse,
} from '../../../core/agent-loop/tests/mock-adapter.ts';

const root = process.env.AGNAP_ROOT;
if (root === undefined) throw new Error('AGNAP_ROOT must point at a built agnap checkout');
const AgnapDeepseek = await import(`${root}/packages/deepseek/dist/index.js`);
const {
  createHandler,
  createServer,
  MemoryStore,
  pendingOwner,
  serve,
  StaticResourceServerRegistry,
} = await import(`${root}/packages/gnap-server/dist/index.js`);
const { agentOperationHandler } = await import(`${root}/packages/access-types/dist/index.js`);
const { parsePublicJwk } = await import(`${root}/packages/gnap-core/dist/index.js`);

const contexts: Context[] = [];
const closers: (() => Promise<void> | void)[] = [];
afterEach(async () => {
  for (const ctx of contexts.splice(0)) await ctx.fiber.dispose();
  for (const close of closers.splice(0)) await close();
});

interface AsLog {
  method: string;
  path: string;
  status: number;
  at: number;
}

async function startAs() {
  const port = 40000 + Math.floor(Math.random() * 20000);
  const issuer = `http://127.0.0.1:${port}/`;
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const kid = 'deepseek-harness-rs';
  const privateJwk = { kid, alg: 'EdDSA', ...privateKey.export({ format: 'jwk' }) };
  const publicJwk = { kid, alg: 'EdDSA', ...publicKey.export({ format: 'jwk' }) };
  const rsRegistry = new StaticResourceServerRegistry([
    { id: 'deepseek-harness', key: parsePublicJwk(publicJwk), accessTypes: ['agent_operation'] },
  ]);
  const store = new MemoryStore();
  // The default 5-second polling interval: approval must not have to wait it out.
  const server = createServer(
    { issuer, registry: rsRegistry, accessTypes: [agentOperationHandler], decision: pendingOwner },
    store,
  );
  const secret = randomBytes(24).toString('hex');
  const inner = createHandler({
    server,
    store,
    rsRegistry,
    publicUrl: issuer,
    localOwner: { secret },
  });
  const log: AsLog[] = [];
  const handler = async (req: Request) => {
    const res = await inner(req);
    log.push({
      method: req.method,
      path: new URL(req.url).pathname,
      status: res.status,
      at: Date.now(),
    });
    return res;
  };
  const running = await serve(handler, { port });
  closers.push(() => running.close());
  const dir = mkdtempSync(join(tmpdir(), 'agnap-'));
  const keyFile = join(dir, 'rs.jwk');
  writeFileSync(keyFile, JSON.stringify(privateJwk));
  process.env.AGNAP_TEST_OWNER_SECRET = secret;
  return { issuer, keyFile, log };
}

const listIssuesProfile = {
  toolName: 'list_issues',
  operation: 'github.issues.list',
  arguments: {
    repository: { authority: 'identity' },
    state: { authority: 'free', required: false },
  },
};

type Answer = 'allowed-once' | 'rejected';

async function harness(script: unknown[], answers: Answer[]) {
  const as = await startAs();
  const ctx = new Context();
  contexts.push(ctx);
  await mountAgentLoopTestDependencies(ctx);
  await ctx.plugin(AgentLoop, { agents: [] });
  await ctx.plugin(ApprovalService, {});
  const asked: { toolName: string; reason?: string; at: number }[] = [];
  ctx.on('approval/request', async (req: { toolName: string; reason?: string }) => {
    asked.push({ toolName: req.toolName, reason: req.reason, at: Date.now() });
    return answers.shift() ?? 'rejected';
  });
  await ctx.plugin(AgnapDeepseek, {
    issuer: as.issuer,
    resourceServerId: 'deepseek-harness',
    resourceServerPrivateJwkFile: as.keyFile,
    simulateOwnerSecretEnv: 'AGNAP_TEST_OWNER_SECRET',
    profiles: [listIssuesProfile],
    denyUnprofiledTools: true,
  });
  const ran: unknown[] = [];
  ctx.tools.register(
    defineContentToolFixture({
      name: 'list_issues',
      description: 'List issues',
      parameters: { repository: { type: 'string' }, state: { type: 'string' } },
      async execute(args: unknown) {
        ran.push(args);
        return [{ type: 'text', text: 'issue #1' }];
      },
    }),
  );
  let rogueRan = false;
  ctx.tools.register(
    defineContentToolFixture({
      name: 'delete_repo',
      description: 'Delete a repository',
      parameters: { repository: { type: 'string' } },
      async execute() {
        rogueRan = true;
        return [{ type: 'text', text: 'deleted' }];
      },
    }),
  );
  ctx.llm.registerAdapter(['mock'], new MockAdapter(script as never));
  return { ctx, as, asked, ran, rogue: () => rogueRan };
}

function events(agent: Agent): readonly SessionEvent[] {
  return agent.session.snapshotEvents();
}
function toolResults(agent: Agent) {
  return events(agent)
    .filter((e) => e.type === 'tool/result')
    .map((e) => {
      const message = (
        e as { data: { message: { isError: boolean; content: { text?: string }[] } } }
      ).data.message;
      return { isError: message.isError, text: message.content.map((b) => b.text ?? '').join('') };
    });
}
const go = () =>
  createUserMessage({ content: [{ type: 'text', text: 'go' }], source: { kind: 'user' } });

async function rootAgent(ctx: Context, id: string) {
  const handle = await ctx.agents.create({
    sessionId: SessionId(id),
    agentOptions: { provider: 'mock', model: 'mock' },
  } as never);
  handle.agent.followup(go());
  await handle.agent.whenIdle();
  return handle;
}

describe('AGNAP plugin in the real DeepSeek Harness', { timeout: 30_000 }, () => {
  it('an uncovered call asks the owner, gets a key-bound grant, then runs', async () => {
    const h = await harness(
      [
        toolCallResponse('c1', 'list_issues', { repository: 'acme/docs', state: 'open' }),
        textResponse('done'),
      ],
      ['allowed-once'],
    );
    const { agent } = await rootAgent(h.ctx, 'a1');
    expect(h.asked).toHaveLength(1);
    expect(h.asked[0]?.reason).toContain('not only this call');
    expect(h.ran).toHaveLength(1);
    expect(toolResults(agent)[0]?.isError).toBe(false);
  });

  it('the grant arrives within a second of approval, despite a 5-second polling interval', async () => {
    const h = await harness(
      [toolCallResponse('c1', 'list_issues', { repository: 'acme/docs' }), textResponse('done')],
      ['allowed-once'],
    );
    await rootAgent(h.ctx, 'latency');
    const approved = h.asked[0]!.at;
    const issued = h.as.log.find((l) => l.path.startsWith('/continue/') && l.status === 200)!.at;
    expect(issued - approved).toBeLessThan(1000);
  });

  it('a second covered call in the same session runs without asking', async () => {
    const h = await harness(
      [
        toolCallResponse('c1', 'list_issues', { repository: 'acme/docs', state: 'open' }),
        toolCallResponse('c2', 'list_issues', { repository: 'acme/docs', state: 'closed' }),
        textResponse('done'),
      ],
      ['allowed-once'],
    );
    const { agent } = await rootAgent(h.ctx, 'a2');
    expect(h.asked).toHaveLength(1);
    expect(h.ran).toHaveLength(2);
    expect(toolResults(agent).every((r) => !r.isError)).toBe(true);
  });

  it('a call outside the grant asks again; when the owner rejects, the tool does not run', async () => {
    const h = await harness(
      [
        toolCallResponse('c1', 'list_issues', { repository: 'acme/docs' }),
        toolCallResponse('c2', 'list_issues', { repository: 'acme/secrets' }),
        textResponse('done'),
      ],
      ['allowed-once', 'rejected'],
    );
    const { agent } = await rootAgent(h.ctx, 'a3');
    expect(h.asked).toHaveLength(2);
    expect(h.ran).toEqual([{ repository: 'acme/docs' }]);
    expect(toolResults(agent)[1]?.isError).toBe(true);
  });

  it('an unprofiled tool is denied without asking', async () => {
    const h = await harness(
      [toolCallResponse('c1', 'delete_repo', { repository: 'acme/docs' }), textResponse('done')],
      [],
    );
    const { agent } = await rootAgent(h.ctx, 'a4');
    expect(h.rogue()).toBe(false);
    expect(h.asked).toHaveLength(0);
    expect(toolResults(agent)[0]?.isError).toBe(true);
  });

  it('an argument the profile does not map is denied', async () => {
    const h = await harness(
      [
        toolCallResponse('c1', 'list_issues', { repository: 'acme/docs', label: 'x' }),
        textResponse('done'),
      ],
      ['allowed-once'],
    );
    const { agent } = await rootAgent(h.ctx, 'a5');
    expect(h.ran).toHaveLength(0);
    expect(toolResults(agent)[0]?.isError).toBe(true);
  });

  it('disposing one agent revokes its token', async () => {
    const h = await harness(
      [toolCallResponse('c1', 'list_issues', { repository: 'acme/docs' }), textResponse('done')],
      ['allowed-once'],
    );
    const handle = await rootAgent(h.ctx, 'a6');
    const before = h.as.log.length;
    await handle.dispose();
    await new Promise((r) => setTimeout(r, 300));
    expect(h.as.log.slice(before).some((l) => l.method === 'DELETE' && l.status === 204)).toBe(
      true,
    );
  });

  it('shutting down the whole Harness revokes every live token', async () => {
    const h = await harness(
      [
        toolCallResponse('c1', 'list_issues', { repository: 'acme/docs' }),
        textResponse('one done'),
        toolCallResponse('c2', 'list_issues', { repository: 'acme/app' }),
        textResponse('two done'),
      ],
      ['allowed-once', 'allowed-once'],
    );
    await rootAgent(h.ctx, 'one');
    await rootAgent(h.ctx, 'two');
    const before = h.as.log.length;
    contexts.splice(contexts.indexOf(h.ctx), 1);
    await h.ctx.fiber.dispose();
    const deletes = h.as.log.slice(before).filter((l) => l.method === 'DELETE' && l.status === 204);
    expect(deletes).toHaveLength(2);
  });

  it('a child agent exposes its parent through session.header, and gets its own key', async () => {
    const h = await harness(
      [
        toolCallResponse('p1', 'list_issues', { repository: 'acme/docs' }),
        textResponse('parent done'),
        toolCallResponse('k1', 'list_issues', { repository: 'acme/docs' }),
        textResponse('child done'),
      ],
      ['allowed-once', 'allowed-once'],
    );
    const parent = await rootAgent(h.ctx, 'parent');
    const child = await h.ctx.agents.create({
      sessionId: SessionId('child'),
      parentAgent: parent.agent,
      meta: { parentSession: SessionId('parent'), origin: 'subagent', delegationDepth: 1 },
      agentOptions: { provider: 'mock', model: 'mock' },
    } as never);
    child.agent.followup(go());
    await child.agent.whenIdle();
    const header = (child.agent as unknown as { session: { header: Record<string, unknown> } })
      .session.header;
    expect(header.parentSession).toBe('parent');
    expect(header.delegationDepth).toBe(1);
    // Today the child is treated as a new root: a second grant request and a second owner prompt.
    expect(h.as.log.filter((l) => l.path === '/')).toHaveLength(2);
    expect(h.asked).toHaveLength(2);
    await child.dispose();
    await parent.dispose();
  });

  it('KNOWN GAP: a child with the delegation-pinned "never" approval policy cannot use any profiled tool', async () => {
    const h = await harness(
      [
        toolCallResponse('p1', 'list_issues', { repository: 'acme/docs' }),
        textResponse('parent done'),
        toolCallResponse('k1', 'list_issues', { repository: 'acme/docs' }),
        textResponse('child done'),
      ],
      ['allowed-once', 'allowed-once'],
    );
    const parent = await rootAgent(h.ctx, 'parent8');
    const child = await h.ctx.agents.create({
      sessionId: SessionId('child8'),
      parentAgent: parent.agent,
      meta: { parentSession: SessionId('parent8'), origin: 'subagent', delegationDepth: 1 },
      agentOptions: { provider: 'mock', model: 'mock' },
    } as never);
    // The event dsh-subagent's appendDelegatedPolicyOverrides writes for every delegated child.
    (
      child.agent as unknown as { session: { append(type: string, data: unknown): void } }
    ).session.append('approval/policy', { policy: 'never', source: 'delegation' });
    child.agent.followup(go());
    await child.agent.whenIdle();
    // Flips when child grants are derived from the parent instead of asking the owner.
    expect(toolResults(child.agent)[0]).toEqual({ isError: true, text: 'Error: grant rejected' });
    expect(h.ran).toHaveLength(1);
    await child.dispose();
    await parent.dispose();
  });
});
