import { describe, expect, it } from 'vitest';

import { covers, coversAny, parseAgentOperation } from '../src/index.js';

const access = parseAgentOperation({
  type: 'agent_operation',
  operations: {
    'github.pull_request.create': { repository: { exact: 'acme/app' }, title: { wildcard: true } },
    'shell.exec': { argv: { exact: 'git status' } },
  },
});

describe('covers', () => {
  it('allows a call inside the grant', () => {
    expect(
      covers(access, 'github.pull_request.create', { repository: 'acme/app', title: 'x' }),
    ).toEqual({ allow: true });
    expect(covers(access, 'github.pull_request.create', { repository: 'acme/app' })).toEqual({
      allow: true,
    });
  });
  it('denies an unknown operation, naming it', () => {
    const d = covers(access, 'github.issue.create', {});
    expect(d.allow).toBe(false);
    if (!d.allow) expect(d.reason).toMatch(/github.issue.create/);
  });
  it('denies an argument the grant does not name', () => {
    const d = covers(access, 'github.pull_request.create', { repository: 'acme/app', draft: true });
    if (!d.allow) expect(d.reason).toMatch(/draft/);
    expect(d.allow).toBe(false);
  });
  it('denies an exact mismatch, including type confusion', () => {
    expect(covers(access, 'github.pull_request.create', { repository: 'other/x' }).allow).toBe(
      false,
    );
    expect(covers(access, 'shell.exec', { argv: ['git', 'status'] }).allow).toBe(false);
    expect(covers(access, 'shell.exec', { argv: 'git status' }).allow).toBe(true);
  });
  it('coversAny ignores other types and reports the last reason', () => {
    const d = coversAny([{ type: 'other' }, access], 'shell.exec', { argv: 'rm -rf /' });
    expect(d.allow).toBe(false);
    expect(coversAny([{ type: 'other' }], 'shell.exec', {}).allow).toBe(false);
  });
});

describe('parse', () => {
  it('refuses unknown fields, empty operations, bad constraints', () => {
    expect(() =>
      parseAgentOperation({ type: 'agent_operation', operations: {}, extra: 1 }),
    ).toThrow(/unknown field/);
    expect(() => parseAgentOperation({ type: 'agent_operation', operations: {} })).toThrow(
      /non-empty/,
    );
    expect(() =>
      parseAgentOperation({ type: 'agent_operation', operations: { a: { x: { exact: {} } } } }),
    ).toThrow(/scalar/);
    expect(() =>
      parseAgentOperation({
        type: 'agent_operation',
        operations: { a: { x: { wildcard: false } } },
      }),
    ).toThrow(/wildcard/);
    expect(() =>
      parseAgentOperation({
        type: 'agent_operation',
        operations: { a: { x: { exact: 1, wildcard: true } } },
      }),
    ).toThrow(/exactly one/);
    expect(() =>
      parseAgentOperation({ type: 'agent_operation', operations: { a: { x: { prefix: 'a' } } } }),
    ).toThrow(/unknown constraint/);
    expect(() =>
      parseAgentOperation({ type: 'agent_operation', operations: { a: {} } }),
    ).not.toThrow();
  });
});
