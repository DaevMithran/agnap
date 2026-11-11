/** The watch loop: poll for pending grants and put each new one to a decider, one at a time. */
import type { AccessItem } from '@agnap/gnap-core';
import type { PendingGrant } from '@agnap/gnap-server';
import type { OwnerClient } from './client.js';
import { keepOperations, numberOperations, renderGrant } from './describe.js';
import { decideByRules } from './rules.js';
import type { Rules } from './rules.js';

export type OwnerDecision =
  { kind: 'approve'; access?: AccessItem[] } | { kind: 'deny' } | { kind: 'skip' };

export type Decider = (grant: PendingGrant) => Promise<OwnerDecision>;

export interface WatchOptions {
  client: OwnerClient;
  decide: Decider;
  log: (line: string) => void;
  signal: AbortSignal;
  /** Polling interval. */
  intervalMs: number;
  /** Process the grants pending now, then return. */
  once?: boolean;
}

const sleep = (milliseconds: number, signal: AbortSignal) =>
  new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, milliseconds);
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });

const message = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

/**
 * Watch until `signal` aborts (or once). Each grant is offered to the decider
 * at most once per run; a skipped grant stays pending on the server.
 * Server errors are logged and the loop keeps polling.
 * @param options - client, decider, output and timing.
 */
export async function watch(options: WatchOptions): Promise<void> {
  const seen = new Set<string>();
  while (!options.signal.aborted) {
    let pending: PendingGrant[] = [];
    try {
      pending = await options.client.listPending(options.signal);
    } catch (error) {
      if (options.signal.aborted) return;
      options.log(`cannot list pending grants: ${message(error)}`);
    }
    for (const grant of pending) {
      if (options.signal.aborted) return;
      if (seen.has(grant.id)) continue;
      seen.add(grant.id);
      const decision = await options.decide(grant);
      try {
        if (decision.kind === 'approve') {
          await options.client.approve(grant.id, decision.access, options.signal);
          options.log(`approved ${grant.id}${decision.access !== undefined ? ' (narrowed)' : ''}`);
        } else if (decision.kind === 'deny') {
          await options.client.deny(grant.id, options.signal);
          options.log(`denied ${grant.id}`);
        } else {
          options.log(`skipped ${grant.id}; it stays pending`);
        }
      } catch (error) {
        options.log(`could not resolve ${grant.id}: ${message(error)}`);
      }
    }
    if (options.once === true) return;
    await sleep(options.intervalMs, options.signal);
  }
}

/**
 * A decider that applies a rules file and logs each grant with its decision.
 * @param rules - parsed rules.
 * @param log - output.
 * @returns the decider.
 */
export function rulesDecider(rules: Rules, log: (line: string) => void): Decider {
  return (grant) => {
    for (const line of renderGrant(grant)) log(line);
    const decision = decideByRules(rules, grant);
    log(`→ rules: ${decision}`);
    return Promise.resolve({ kind: decision });
  };
}

/**
 * A decider that asks the person at the terminal.
 * @param ask - prints a prompt and resolves with the typed answer, or `null`
 *   once input has ended; the grant is then skipped and stays pending.
 * @param log - output.
 * @returns the decider.
 */
export function interactiveDecider(
  ask: (prompt: string) => Promise<string | null>,
  log: (line: string) => void,
): Decider {
  return async (grant) => {
    log('');
    for (const line of renderGrant(grant)) log(line);
    const count = numberOperations(grant.requested_access).length;
    for (;;) {
      const typed = await ask('[a]pprove  [n]arrow  [d]eny  [s]kip > ');
      if (typed === null) return { kind: 'skip' };
      const answer = typed.trim().toLowerCase();
      if (answer === 'a') return { kind: 'approve' };
      if (answer === 'd') return { kind: 'deny' };
      if (answer === 's') return { kind: 'skip' };
      if (answer !== 'n') continue;
      if (count === 0) {
        log('nothing to narrow: this grant has no numbered operations');
        continue;
      }
      const picked = await ask(`keep which operations? (1-${count}, e.g. 1,3) > `);
      if (picked === null) return { kind: 'skip' };
      const keep = new Set(
        picked
          .split(/[\s,]+/)
          .filter((part) => part.length > 0)
          .map(Number),
      );
      if ([...keep].some((n) => !Number.isInteger(n) || n < 1 || n > count)) {
        log(`choose numbers between 1 and ${count}`);
        continue;
      }
      const access = keepOperations(grant.requested_access, keep);
      if (access === null) {
        log('keep at least one operation, or deny');
        continue;
      }
      return { kind: 'approve', access };
    }
  };
}
