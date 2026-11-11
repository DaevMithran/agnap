/** Grant state records in one process's memory. Every method body is synchronous, so each is atomic. */
import { randomUUID } from 'node:crypto';
import type {
  ReserveOutcome,
  Settlement,
  GrantStateKey,
  GrantStateSnapshot,
  GrantStateStore,
} from '../types.js';

/* eslint-disable @typescript-eslint/require-await -- async for the interface; nothing here awaits between read and write */

interface Reservation {
  record: string;
  amount: number;
  state: 'pending' | 'held';
}

const recordOf = (key: GrantStateKey): string => `${key.rootGrant}\u0000${key.operation}`;

export class MemoryGrantStateStore implements GrantStateStore {
  readonly #used = new Map<string, number>();
  readonly #reservations = new Map<string, Reservation>();

  async reserve(key: GrantStateKey, ceiling: number, amount: number): Promise<ReserveOutcome> {
    const record = recordOf(key);
    const counted = this.#counted(record);
    if (counted + amount > ceiling) return { kind: 'exhausted', counted, ceiling };
    const reservation = randomUUID();
    this.#reservations.set(reservation, { record, amount, state: 'pending' });
    return { kind: 'reserved', reservation };
  }

  async settle(reservation: string, settlement: Settlement): Promise<void> {
    const entry = this.#reservations.get(reservation);
    if (entry === undefined) return;
    if (settlement === 'held') {
      entry.state = 'held';
      return;
    }
    this.#reservations.delete(reservation);
    if (settlement === 'used') {
      this.#used.set(entry.record, (this.#used.get(entry.record) ?? 0) + entry.amount);
    }
  }

  async snapshot(key: GrantStateKey): Promise<GrantStateSnapshot> {
    const record = recordOf(key);
    const snapshot: GrantStateSnapshot = { used: this.#used.get(record) ?? 0, pending: 0, held: 0 };
    for (const entry of this.#reservations.values()) {
      if (entry.record !== record) continue;
      if (entry.state === 'pending') snapshot.pending += entry.amount;
      else snapshot.held += entry.amount;
    }
    return snapshot;
  }

  #counted(record: string): number {
    let counted = this.#used.get(record) ?? 0;
    for (const entry of this.#reservations.values()) {
      if (entry.record === record) counted += entry.amount;
    }
    return counted;
  }
}
