import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { MemoryGrantStateStore, SqliteGrantStateStore } from '../src/index.js';
import type { GrantStateStore } from '../src/index.js';

const key = { rootGrant: 'grant-1', operation: 'comment.create' };

const stores: [string, () => GrantStateStore][] = [
  ['memory', () => new MemoryGrantStateStore()],
  ['sqlite', () => new SqliteGrantStateStore(':memory:')],
];

describe.each(stores)('%s grant state store', (_, make) => {
  it('counts used, pending and held calls against the ceiling; released calls return', async () => {
    const store = make();
    const a = await store.reserve(key, 3, 1);
    const b = await store.reserve(key, 3, 1);
    const c = await store.reserve(key, 3, 1);
    expect([a.kind, b.kind, c.kind]).toEqual(['reserved', 'reserved', 'reserved']);
    expect(await store.reserve(key, 3, 1)).toEqual({ kind: 'exhausted', counted: 3, ceiling: 3 });

    if (a.kind !== 'reserved' || b.kind !== 'reserved' || c.kind !== 'reserved') throw new Error();
    await store.settle(a.reservation, 'used');
    await store.settle(b.reservation, 'held');
    await store.settle(c.reservation, 'released');
    expect(await store.snapshot(key)).toEqual({ used: 1, pending: 0, held: 1 });
    expect((await store.reserve(key, 3, 1)).kind).toBe('reserved');
    expect((await store.reserve(key, 3, 1)).kind).toBe('exhausted');
  });

  it('keeps one record per root grant and operation', async () => {
    const store = make();
    expect((await store.reserve(key, 1, 1)).kind).toBe('reserved');
    expect((await store.reserve({ ...key, rootGrant: 'grant-2' }, 1, 1)).kind).toBe('reserved');
    expect((await store.reserve({ ...key, operation: 'issue.list' }, 1, 1)).kind).toBe('reserved');
    expect((await store.reserve(key, 1, 1)).kind).toBe('exhausted');
  });

  it('never over-reserves under concurrent calls', async () => {
    const store = make();
    const results = await Promise.all(Array.from({ length: 25 }, () => store.reserve(key, 4, 1)));
    expect(results.filter((r) => r.kind === 'reserved')).toHaveLength(4);
  });

  it('ignores unknown and repeated settlements', async () => {
    const store = make();
    await store.settle('nope', 'used');
    const r = await store.reserve(key, 2, 1);
    if (r.kind !== 'reserved') throw new Error();
    await store.settle(r.reservation, 'used');
    await store.settle(r.reservation, 'used');
    expect(await store.snapshot(key)).toEqual({ used: 1, pending: 0, held: 0 });
  });
});

describe('sqlite grant state store across handles', () => {
  it('two handles on one database file share the ceiling', async () => {
    const file = join(mkdtempSync(join(tmpdir(), 'agnap-store-')), 'store.db');
    const one = new SqliteGrantStateStore(file);
    const two = new SqliteGrantStateStore(file);
    const results = [];
    for (let i = 0; i < 6; i += 1) {
      results.push(await (i % 2 === 0 ? one : two).reserve(key, 3, 1));
    }
    expect(results.filter((r) => r.kind === 'reserved')).toHaveLength(3);
    one.close();
    two.close();
  });
});
