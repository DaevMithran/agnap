/**
 * The `agent_operation` GNAP access type. One object names operations and,
 * for each, the arguments it may be called with and the constraint each
 * argument must satisfy. Closed world: an operation not listed is denied,
 * an argument not listed is denied, an argument whose value fails its
 * constraint is denied.
 *
 *   { "type": "agent_operation",
 *     "operations": { "github.pull_request.create": { "repository": { "exact": "acme/app" } } } }
 */
import { AccessParseError, createAjv } from '@agnap/gnap-core';
import type { AccessItem, AccessTypeHandler } from '@agnap/gnap-core';
import { agentOperationSchema } from './generated/agent-operation-schema.js';
import type { components } from './generated/agent-operation.js';

export const AGENT_OPERATION = 'agent_operation';

type Schemas = components['schemas'];

export type Scalar = Schemas['Scalar'];

/** The constraint kinds this version evaluates. */
export type Constraint = Schemas['Constraint'];

/** Arguments of one operation, by name. Arguments not named are not permitted. */
export type OperationConstraints = Schemas['AgentOperationAccess']['operations'][string];

export type AgentOperationAccess = Schemas['AgentOperationAccess'] & AccessItem;

const isScalar = (v: unknown): v is Scalar =>
  typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean';

/** Allow, or deny with a reason. Never a bare boolean. */
export type Decision = { allow: true } | { allow: false; reason: string };

const ajv = createAjv();
export const validateAgentOperation = ajv.compile<AgentOperationAccess>(agentOperationSchema);

export function parseAgentOperation(value: unknown): AgentOperationAccess {
  if (validateAgentOperation(value)) return value;
  throw new AccessParseError(AGENT_OPERATION, diagnoseAgentOperation(value));
}

/** Improve Ajv's union errors without participating in the validity decision. */
function diagnoseAgentOperation(value: unknown): string {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return 'object expected';
  const root = value as Record<string, unknown>;
  const extras = Object.keys(root).filter((key) => key !== 'type' && key !== 'operations');
  if (extras.length > 0) return `unknown field ${extras.join(', ')}`;
  const operations = root.operations;
  if (typeof operations !== 'object' || operations === null || Array.isArray(operations)) {
    return 'operations must be a non-empty object';
  }
  if (Object.keys(operations).length === 0) return 'operations must be a non-empty object';
  for (const [operation, args] of Object.entries(operations as Record<string, unknown>)) {
    if (typeof args !== 'object' || args === null || Array.isArray(args)) {
      return `${operation}: arguments must be an object`;
    }
    for (const [argument, constraint] of Object.entries(args as Record<string, unknown>)) {
      if (typeof constraint !== 'object' || constraint === null || Array.isArray(constraint)) {
        return `${operation}.${argument}: constraint must be an object`;
      }
      const record = constraint as Record<string, unknown>;
      const keys = Object.keys(record);
      if (keys.length !== 1) return `${operation}.${argument}: exactly one constraint kind`;
      if (keys[0] === 'exact') {
        if (!isScalar(record.exact)) return `${operation}.${argument}: exact must be a scalar`;
      } else if (keys[0] === 'wildcard') {
        if (record.wildcard !== true) return `${operation}.${argument}: wildcard must be true`;
      } else {
        return `${operation}.${argument}: unknown constraint kind ${String(keys[0])}`;
      }
    }
  }
  const first = validateAgentOperation.errors?.[0];
  return first === undefined
    ? 'invalid'
    : `${first.instancePath || '$'}: ${first.message ?? first.keyword}`;
}

function satisfies(constraint: Constraint, value: unknown): boolean {
  if ('wildcard' in constraint) return true;
  return isScalar(value) && value === constraint.exact;
}

/**
 * Does one access item cover a call to `operation` with `args`? Every
 * supplied argument must be named and satisfied. Arguments the grant names
 * but the call omits are fine: the grant bounds what may be passed, it does
 * not require passing it.
 */
export function covers(
  access: AgentOperationAccess,
  operation: string,
  args: Record<string, unknown>,
): Decision {
  const constraints = access.operations[operation];
  if (constraints === undefined)
    return { allow: false, reason: `operation ${operation} is not in the grant` };
  for (const [name, value] of Object.entries(args)) {
    const c = constraints[name];
    if (c === undefined)
      return { allow: false, reason: `argument ${name} is not permitted for ${operation}` };
    if (!satisfies(c, value)) {
      return {
        allow: false,
        reason: `argument ${name} does not satisfy its constraint for ${operation}`,
      };
    }
  }
  return { allow: true };
}

/** Covered by any item in a list, as a token carries several. */
export function coversAny(
  items: readonly AccessItem[],
  operation: string,
  args: Record<string, unknown>,
): Decision {
  let last: Decision = { allow: false, reason: 'no agent_operation access in the token' };
  for (const item of items) {
    if (item.type !== AGENT_OPERATION) continue;
    last = covers(item as AgentOperationAccess, operation, args);
    if (last.allow) return last;
  }
  return last;
}

/** One constraint is at least as narrow as another. */
function constraintContained(wider: Constraint, narrower: Constraint): boolean {
  if ('wildcard' in wider) return true;
  if ('wildcard' in narrower) return false;
  return wider.exact === narrower.exact;
}

/**
 * Every right in `narrower` is in `wider`: each operation exists in the
 * wider item, each argument it names is named there, and each constraint is
 * at least as tight. Dropping operations or arguments narrows. Adding either
 * widens, because an unnamed argument is a denied argument.
 */
export function contains(wider: AgentOperationAccess, narrower: AgentOperationAccess): boolean {
  for (const [op, narrowArgs] of Object.entries(narrower.operations)) {
    const wideArgs = wider.operations[op];
    if (wideArgs === undefined) return false;
    for (const [name, c] of Object.entries(narrowArgs)) {
      const w = wideArgs[name];
      if (w === undefined || !constraintContained(w, c)) return false;
    }
  }
  return true;
}

export const agentOperationHandler: AccessTypeHandler<AgentOperationAccess> = {
  type: AGENT_OPERATION,
  parse: parseAgentOperation,
  contains,
};
