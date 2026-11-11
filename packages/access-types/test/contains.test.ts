import { describe, expect, it } from 'vitest';

import { contains, parseAgentOperation } from '../src/index.js';
import type { AgentOperationAccess } from '../src/index.js';

const p = (operations: Record<string, Record<string, unknown>>): AgentOperationAccess =>
  parseAgentOperation({ type: 'agent_operation', operations });

const wider = p({
  'pr.create': { repository: { wildcard: true }, title: { wildcard: true } },
  'shell.exec': { argv: { exact: 'git status' } },
});

describe('contains', () => {
  it('a copy, dropping an operation, dropping an argument, wildcard to exact all narrow', () => {
    expect(contains(wider, wider)).toBe(true);
    expect(
      contains(
        wider,
        p({ 'pr.create': { repository: { wildcard: true }, title: { wildcard: true } } }),
      ),
    ).toBe(true);
    expect(contains(wider, p({ 'pr.create': { repository: { wildcard: true } } }))).toBe(true);
    expect(contains(wider, p({ 'pr.create': { repository: { exact: 'acme/app' } } }))).toBe(true);
  });
  it('adding an operation, adding an argument, exact to wildcard, exact to other exact all widen', () => {
    expect(contains(wider, p({ 'issue.create': { repository: { exact: 'a' } } }))).toBe(false);
    expect(
      contains(wider, p({ 'pr.create': { repository: { exact: 'a' }, draft: { exact: true } } })),
    ).toBe(false);
    expect(contains(wider, p({ 'shell.exec': { argv: { wildcard: true } } }))).toBe(false);
    expect(contains(wider, p({ 'shell.exec': { argv: { exact: 'git push' } } }))).toBe(false);
  });
});
