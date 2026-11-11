/**
 * Scripted owner decisions, for tests and benchmarks. A rules file:
 *
 *   { "rules": [ { "operation": "github.issues.list", "decision": "approve" },
 *                { "operation": "github.*", "decision": "deny" } ],
 *     "default": "deny" }
 *
 * Each requested operation takes the decision of the first rule whose
 * pattern matches it. A grant is approved only when every operation is
 * approved; any denied operation denies it; otherwise `default` applies.
 * A pattern is an exact name, `*`, or a prefix ending in `*`.
 */
import type { PendingGrant } from '@agnap/gnap-server';
import { numberOperations } from './describe.js';

export type RuleDecision = 'approve' | 'deny';

export interface Rule {
  operation: string;
  decision: RuleDecision;
  /** Optional pattern on the client's display name; same syntax. */
  client?: string;
}

export interface Rules {
  rules: Rule[];
  /** Decision when no rule decides. `skip` leaves the grant pending. Defaults to `deny`. */
  default?: RuleDecision | 'skip';
}

export class RulesError extends Error {
  override readonly name = 'RulesError';
}

const matches = (pattern: string, value: string): boolean =>
  pattern.endsWith('*') ? value.startsWith(pattern.slice(0, -1)) : pattern === value;

/**
 * Validate a parsed rules file.
 * @param value - parsed JSON.
 * @returns the rules.
 * @throws RulesError naming the first problem.
 */
export function parseRules(value: unknown): Rules {
  if (typeof value !== 'object' || value === null) throw new RulesError('rules must be an object');
  const raw = value as { rules?: unknown; default?: unknown };
  if (!Array.isArray(raw.rules)) throw new RulesError('rules.rules must be an array');
  const rules = raw.rules.map((entry: unknown, i): Rule => {
    const rule = entry as Partial<Rule> | null;
    if (typeof rule?.operation !== 'string' || rule.operation.length === 0)
      throw new RulesError(`rules[${i}].operation must be a non-empty string`);
    if (rule.decision !== 'approve' && rule.decision !== 'deny')
      throw new RulesError(`rules[${i}].decision must be approve or deny`);
    if (rule.client !== undefined && typeof rule.client !== 'string')
      throw new RulesError(`rules[${i}].client must be a string`);
    return {
      operation: rule.operation,
      decision: rule.decision,
      ...(rule.client !== undefined ? { client: rule.client } : {}),
    };
  });
  const fallback = raw.default ?? 'deny';
  if (fallback !== 'approve' && fallback !== 'deny' && fallback !== 'skip')
    throw new RulesError('rules.default must be approve, deny or skip');
  return { rules, default: fallback };
}

/**
 * Decide a pending grant by rules.
 * @param rules - parsed rules.
 * @param grant - the pending grant.
 * @returns the decision, or `skip` to leave it pending.
 */
export function decideByRules(rules: Rules, grant: PendingGrant): RuleDecision | 'skip' {
  const client = grant.client_display?.name ?? '';
  const operations = numberOperations(grant.requested_access);
  if (operations.length === 0) return rules.default ?? 'deny';
  let undecided = false;
  for (const op of operations) {
    const rule = rules.rules.find(
      (r) =>
        matches(r.operation, op.operation) && (r.client === undefined || matches(r.client, client)),
    );
    if (rule === undefined) undecided = true;
    else if (rule.decision === 'deny') return 'deny';
  }
  return undecided ? (rules.default ?? 'deny') : 'approve';
}
