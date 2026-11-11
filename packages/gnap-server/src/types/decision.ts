/** The step between "request received" and "token issued". Policy lives behind this interface and nowhere else. */
import type { AccessItem, Ed25519PublicJwk } from '@agnap/gnap-core';
import type { DenyCode } from './records.js';

export type Decision =
  | { kind: 'issue'; access: AccessItem[] }
  | { kind: 'deny'; code: DenyCode; description?: string }
  | { kind: 'pending' };

export interface DecisionInput {
  requestedAccess: AccessItem[];
  clientKey: Ed25519PublicJwk;
  clientThumbprint: string;
  now: number;
}

/** The step between "request received" and "token issued". Policy lives here and nowhere else. */
export interface DecisionStep {
  decide(input: DecisionInput): Promise<Decision> | Decision;
}
