import { describe, expect, it } from 'vitest';

import { ToolProfileError, ToolProfileRegistry, mapToolCall } from '../src/index.js';

describe('tool profiles', () => {
  it('maps identity arguments to exact constraints and free arguments to wildcards', () => {
    const mapped = mapToolCall(
      {
        toolName: 'github.pull_request.create',
        arguments: {
          repository: { authority: 'identity' },
          title: { authority: 'free' },
          draft: { required: false },
        },
      },
      { repository: 'acme/app', title: 'Fix login' },
    );
    expect(mapped).toEqual({
      operation: 'github.pull_request.create',
      arguments: { repository: 'acme/app', title: 'Fix login' },
      access: {
        type: 'agent_operation',
        operations: {
          'github.pull_request.create': {
            repository: { exact: 'acme/app' },
            title: { wildcard: true },
          },
        },
      },
      requiredAccess: {
        type: 'agent_operation',
        operations: {
          'github.pull_request.create': {
            repository: { exact: 'acme/app' },
            title: { exact: 'Fix login' },
          },
        },
      },
    });
  });

  it('includes an omitted optional free argument in grant scope but not call access', () => {
    const mapped = mapToolCall(
      {
        toolName: 'github.pull_request.create',
        arguments: {
          repository: {},
          title: { authority: 'free', required: false },
        },
      },
      { repository: 'acme/app' },
    );
    expect(mapped.access.operations['github.pull_request.create']).toEqual({
      repository: { exact: 'acme/app' },
      title: { wildcard: true },
    });
    expect(mapped.requiredAccess.operations['github.pull_request.create']).toEqual({
      repository: { exact: 'acme/app' },
    });
  });

  it('JSON-encodes argv and fails closed for missing, unknown and non-scalar arguments', () => {
    const shell = {
      toolName: 'shell.exec',
      arguments: { argv: { encoding: 'json' as const } },
    };
    expect(mapToolCall(shell, { argv: ['git', 'status'] }).arguments).toEqual({
      argv: '["git","status"]',
    });
    expect(() => mapToolCall(shell, {})).toThrow(/required argument argv/);
    expect(() => mapToolCall(shell, { argv: [], cwd: '/tmp' })).toThrow(/cwd/);
    expect(() => mapToolCall({ toolName: 'x', arguments: { value: {} } }, { value: [] })).toThrow(
      /string, number or boolean/,
    );
  });

  it('rejects duplicate and empty registries entries', () => {
    expect(
      () =>
        new ToolProfileRegistry([
          { toolName: 'x', arguments: { a: {} } },
          { toolName: 'x', arguments: { a: {} } },
        ]),
    ).toThrow(ToolProfileError);
    expect(() => new ToolProfileRegistry([{ toolName: 'x', arguments: {} }])).toThrow(
      /declare arguments/,
    );
  });
});
