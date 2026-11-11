import type { AccessItem, AccessTypeRegistry } from '@agnap/gnap-core';
import type { DecisionStep } from '../types/decision.js';

/** Every request waits for the owner. The server itself decides nothing. */
export const pendingOwner: DecisionStep = {
  decide: () => ({ kind: 'pending' }),
};

/**
 * Issue when every requested item is contained in the configured list,
 * otherwise deny. For tests and for deployments with no owner in the loop.
 */
export function fixedList(registry: AccessTypeRegistry, allowed: AccessItem[]): DecisionStep {
  return {
    decide: ({ requestedAccess }) =>
      registry.containsAll(allowed, requestedAccess)
        ? { kind: 'issue', access: requestedAccess }
        : {
            kind: 'deny',
            code: 'request_denied',
            description: 'requested access is outside the allowed list',
          },
  };
}
