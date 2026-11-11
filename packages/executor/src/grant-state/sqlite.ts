/**
 * Grant state records in SQLite (`node:sqlite`, Node 22.13 or later). `reserve`
 * runs in a `BEGIN IMMEDIATE` transaction, so it is atomic across every
 * process that opens the same database file.
 */
import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import type {
  ReserveOutcome,
  Settlement,
  GrantStateKey,
  GrantStateSnapshot,
  GrantStateStore,
} from '../types.js';

/* eslint-disable @typescript-eslint/require-await -- node:sqlite is synchronous; the interface is async for other stores */

const SCHEMA = `
CREATE TABLE IF NOT EXISTS grant_state_record (
  root_grant TEXT NOT NULL,
  operation  TEXT NOT NULL,
  used       INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (root_grant, operation)
);
CREATE TABLE IF NOT EXISTS reservation (
  id         TEXT PRIMARY KEY,
  root_grant TEXT NOT NULL,
  operation  TEXT NOT NULL,
  amount     INTEGER NOT NULL,
  state      TEXT NOT NULL CHECK (state IN ('pending', 'held')),
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS reservation_record ON reservation (root_grant, operation);
`;

export class SqliteGrantStateStore implements GrantStateStore {
  readonly #db: DatabaseSync;

  /**
   * @param path - database file, or `:memory:`.
   */
  constructor(path: string) {
    this.#db = new DatabaseSync(path);
    this.#db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
    this.#db.exec(SCHEMA);
  }

  async reserve(key: GrantStateKey, ceiling: number, amount: number): Promise<ReserveOutcome> {
    return this.#transaction(() => {
      const counted = this.#counted(key);
      if (counted + amount > ceiling) return { kind: 'exhausted', counted, ceiling };
      const reservation = randomUUID();
      this.#db
        .prepare(
          `INSERT INTO reservation (id, root_grant, operation, amount, state, created_at)
           VALUES (?, ?, ?, ?, 'pending', ?)`,
        )
        .run(reservation, key.rootGrant, key.operation, amount, Date.now());
      return { kind: 'reserved', reservation };
    });
  }

  async settle(reservation: string, settlement: Settlement): Promise<void> {
    this.#transaction(() => {
      const row = this.#db
        .prepare('SELECT root_grant, operation, amount FROM reservation WHERE id = ?')
        .get(reservation) as { root_grant: string; operation: string; amount: number } | undefined;
      if (row === undefined) return;
      if (settlement === 'held') {
        this.#db.prepare(`UPDATE reservation SET state = 'held' WHERE id = ?`).run(reservation);
        return;
      }
      this.#db.prepare('DELETE FROM reservation WHERE id = ?').run(reservation);
      if (settlement === 'used') {
        this.#db
          .prepare(
            `INSERT INTO grant_state_record (root_grant, operation, used) VALUES (?, ?, ?)
             ON CONFLICT (root_grant, operation) DO UPDATE SET used = used + excluded.used`,
          )
          .run(row.root_grant, row.operation, row.amount);
      }
    });
  }

  async snapshot(key: GrantStateKey): Promise<GrantStateSnapshot> {
    const used = this.#db
      .prepare('SELECT used FROM grant_state_record WHERE root_grant = ? AND operation = ?')
      .get(key.rootGrant, key.operation) as { used: number } | undefined;
    const rows = this.#db
      .prepare(
        `SELECT state, COALESCE(SUM(amount), 0) AS total FROM reservation
         WHERE root_grant = ? AND operation = ? GROUP BY state`,
      )
      .all(key.rootGrant, key.operation) as { state: string; total: number }[];
    return {
      used: used?.used ?? 0,
      pending: rows.find((r) => r.state === 'pending')?.total ?? 0,
      held: rows.find((r) => r.state === 'held')?.total ?? 0,
    };
  }

  close(): void {
    this.#db.close();
  }

  #counted(key: GrantStateKey): number {
    const row = this.#db
      .prepare(
        `SELECT
           COALESCE((SELECT used FROM grant_state_record WHERE root_grant = ?1 AND operation = ?2), 0)
         + COALESCE((SELECT SUM(amount) FROM reservation WHERE root_grant = ?1 AND operation = ?2), 0)
           AS counted`,
      )
      .get(key.rootGrant, key.operation) as { counted: number };
    return row.counted;
  }

  #transaction<T>(work: () => T): T {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const result = work();
      this.#db.exec('COMMIT');
      return result;
    } catch (error) {
      this.#db.exec('ROLLBACK');
      throw error;
    }
  }
}
