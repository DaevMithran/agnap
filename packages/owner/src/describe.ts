/** What the owner reads before deciding: a pending grant as a plain-text card, and its operations by number. */
import { AGENT_OPERATION } from '@agnap/access-types';
import type { AgentOperationAccess } from '@agnap/access-types';
import type { AccessItem } from '@agnap/gnap-core';
import type { PendingGrant } from '@agnap/gnap-server';

/** One operation of one `agent_operation` item, numbered from 1 across the whole request. */
export interface NumberedOperation {
  number: number;
  itemIndex: number;
  operation: string;
  /** `name = "value"` or `name = any` per argument. */
  constraints: string[];
}

const isAgentOperation = (item: AccessItem): item is AgentOperationAccess =>
  item.type === AGENT_OPERATION &&
  typeof (item as { operations?: unknown }).operations === 'object';

/**
 * Number every operation in the request, in order.
 * @param access - the requested access items.
 * @returns the operations; items of other types are not listed.
 */
export function numberOperations(access: readonly AccessItem[]): NumberedOperation[] {
  const numbered: NumberedOperation[] = [];
  access.forEach((item, itemIndex) => {
    if (!isAgentOperation(item)) return;
    for (const [operation, args] of Object.entries(item.operations)) {
      const constraints = Object.entries(args).map(([name, constraint]) =>
        'wildcard' in constraint
          ? `${name} = any`
          : `${name} = ${JSON.stringify(constraint.exact)}`,
      );
      numbered.push({ number: numbered.length + 1, itemIndex, operation, constraints });
    }
  });
  return numbered;
}

const formatRemaining = (milliseconds: number): string => {
  if (milliseconds <= 0) return 'expired';
  const seconds = Math.floor(milliseconds / 1000);
  return seconds >= 60 ? `${Math.floor(seconds / 60)}m ${seconds % 60}s` : `${seconds}s`;
};

/**
 * Render a pending grant for the terminal. Everything shown comes from the
 * grant itself; the client's display name is labelled as unverified.
 * @param grant - the pending grant.
 * @param now - current time in milliseconds, for the expiry countdown.
 * @returns the card's lines.
 */
export function renderGrant(grant: PendingGrant, now = Date.now()): string[] {
  const operations = numberOperations(grant.requested_access);
  const lines = [
    `Grant    ${grant.id}`,
    `Agent    ${grant.client_display?.name ?? '(no name given)'}   [name stated by the agent, unverified]`,
    `Key      ${grant.client_kid}  ${grant.client_thumbprint.slice(0, 12)}…`,
  ];
  if (operations.length === 0) lines.push('Asks     (no agent_operation access)');
  for (const op of operations) {
    const prefix = op.number === 1 ? 'Asks     ' : '         ';
    const args = op.constraints.length > 0 ? `  ${op.constraints.join(', ')}` : '';
    lines.push(`${prefix}${op.number}. ${op.operation}${args}`);
  }
  const other = grant.requested_access.filter((item) => !isAgentOperation(item));
  for (const item of other) lines.push(`Also     ${JSON.stringify(item)}`);
  lines.push(`Expires  in ${formatRemaining(Date.parse(grant.expires_at) - now)} if undecided`);
  return lines;
}

/**
 * Keep only the chosen operations. Items left with no operation are dropped;
 * items of other types are kept unchanged. The result is contained in the
 * request, which the server checks again.
 * @param access - the requested access items.
 * @param keep - operation numbers from {@link numberOperations} to keep.
 * @returns the narrowed access, or `null` when nothing would remain.
 */
export function keepOperations(
  access: readonly AccessItem[],
  keep: ReadonlySet<number>,
): AccessItem[] | null {
  const kept = new Map<number, Set<string>>();
  for (const op of numberOperations(access)) {
    if (!keep.has(op.number)) continue;
    const names = kept.get(op.itemIndex) ?? new Set<string>();
    names.add(op.operation);
    kept.set(op.itemIndex, names);
  }
  const narrowed: AccessItem[] = [];
  access.forEach((item, itemIndex) => {
    if (!isAgentOperation(item)) {
      narrowed.push(item);
      return;
    }
    const names = kept.get(itemIndex);
    if (names === undefined) return;
    const operations = Object.fromEntries(
      Object.entries(item.operations).filter(([name]) => names.has(name)),
    );
    narrowed.push({ ...item, operations });
  });
  return narrowed.some(isAgentOperation) ? narrowed : null;
}
