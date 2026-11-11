import type { AgentOperationAccess, Constraint, Scalar } from '@agnap/access-types';
import type { MappedToolCall, ToolProfile } from './types.js';

export class ToolProfileError extends Error {
  override readonly name = 'ToolProfileError';
}

export class ToolProfileRegistry {
  readonly #profiles = new Map<string, ToolProfile>();

  constructor(profiles: readonly ToolProfile[]) {
    for (const profile of profiles) {
      if (profile.toolName.length === 0) throw new ToolProfileError('toolName must not be empty');
      if (this.#profiles.has(profile.toolName)) {
        throw new ToolProfileError(`duplicate profile for ${profile.toolName}`);
      }
      if (Object.keys(profile.arguments).length === 0) {
        throw new ToolProfileError(`profile ${profile.toolName} must declare arguments`);
      }
      if (
        profile.ceiling !== undefined &&
        (!Number.isInteger(profile.ceiling.calls) || profile.ceiling.calls < 1)
      ) {
        throw new ToolProfileError(`profile ${profile.toolName}: ceiling.calls must be at least 1`);
      }
      this.#profiles.set(profile.toolName, profile);
    }
  }

  get(toolName: string): ToolProfile | null {
    return this.#profiles.get(toolName) ?? null;
  }
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isScalar = (value: unknown): value is Scalar =>
  typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';

export function mapToolCall(profile: ToolProfile, input: unknown): MappedToolCall {
  if (!isObject(input))
    throw new ToolProfileError(`${profile.toolName} arguments must be an object`);

  const knownSources = new Set(
    Object.entries(profile.arguments).map(([authorityName, rule]) => rule.from ?? authorityName),
  );
  if (profile.rejectUnknownArguments !== false) {
    const unknown = Object.keys(input).find((name) => !knownSources.has(name));
    if (unknown !== undefined) {
      throw new ToolProfileError(`argument ${unknown} is not mapped by ${profile.toolName}`);
    }
  }

  const mapped: Record<string, Scalar> = {};
  for (const [authorityName, rule] of Object.entries(profile.arguments)) {
    const source = rule.from ?? authorityName;
    const value = input[source];
    if (value === undefined) {
      if (rule.required !== false) {
        throw new ToolProfileError(`required argument ${source} is missing`);
      }
      continue;
    }
    if (rule.encoding === 'json') {
      const encoded = JSON.stringify(value);
      if (encoded === undefined) throw new ToolProfileError(`argument ${source} is not JSON`);
      mapped[authorityName] = encoded;
    } else if (isScalar(value)) {
      mapped[authorityName] = value;
    } else {
      throw new ToolProfileError(`argument ${source} must be a string, number or boolean`);
    }
  }

  const operation = profile.operation ?? profile.toolName;
  const constraints: Record<string, Constraint> = {};
  for (const [name, rule] of Object.entries(profile.arguments)) {
    if (rule.authority === 'free') constraints[name] = { wildcard: true };
    else if (mapped[name] !== undefined) constraints[name] = { exact: mapped[name] };
  }
  const requiredConstraints: Record<string, Constraint> = {};
  for (const [name, value] of Object.entries(mapped)) {
    requiredConstraints[name] = { exact: value };
  }
  const access: AgentOperationAccess = {
    type: 'agent_operation',
    operations: { [operation]: constraints },
    ...(profile.ceiling !== undefined
      ? { ceilings: { [operation]: { calls: profile.ceiling.calls } } }
      : {}),
  };
  const requiredAccess: AgentOperationAccess = {
    type: 'agent_operation',
    operations: { [operation]: requiredConstraints },
  };
  return { operation, arguments: mapped, access, requiredAccess };
}
