import { describe, expect, it } from 'vitest';
import { AccessParseError, AccessTypeRegistry } from '../src/index.js';
import type { AccessItem, AccessTypeHandler } from '../src/index.js';

/** A toy type: `{ type: "files", paths: string[] }`, contained when paths are a subset. */
type Files = AccessItem & { type: 'files'; paths: string[] };
const files: AccessTypeHandler<Files> = {
  type: 'files',
  parse(value) {
    const v = value as Record<string, unknown>;
    if (!Array.isArray(v.paths) || !v.paths.every((p) => typeof p === 'string')) {
      throw new AccessParseError('files', 'paths must be string[]');
    }
    return { type: 'files', paths: v.paths };
  },
  contains(wider, narrower) {
    return narrower.paths.every((p) => wider.paths.includes(p));
  },
};

describe('AccessTypeRegistry', () => {
  const registry = new AccessTypeRegistry([files]);

  it('parses known objects and refuses strings, unknown types and malformed items', () => {
    expect(registry.parseAll([{ type: 'files', paths: ['/a'] }])).toEqual([
      { type: 'files', paths: ['/a'] },
    ]);
    expect(() => registry.parseAll(['ref'])).toThrow(/reference strings/);
    expect(() => registry.parseAll([{ type: 'other' }])).toThrow(/unknown type/);
    expect(() => registry.parseAll([{ type: 'files', paths: [1] }])).toThrow(AccessParseError);
    expect(() => registry.parseAll([])).toThrow(/non-empty/);
    expect(() => registry.parseAll([{ paths: [] }])).toThrow(/string type/);
  });

  it('list containment: every narrower item is inside some wider item of the same type', () => {
    const wider = [
      { type: 'files', paths: ['/a', '/b'] },
      { type: 'files', paths: ['/c'] },
    ];
    expect(
      registry.containsAll(wider, [
        { type: 'files', paths: ['/a'] },
        { type: 'files', paths: ['/c'] },
      ]),
    ).toBe(true);
    expect(registry.containsAll(wider, [{ type: 'files', paths: ['/a', '/c'] }])).toBe(false);
    expect(registry.containsAll(wider, [{ type: 'other' }])).toBe(false);
    expect(registry.containsAll(wider, [])).toBe(true);
  });

  it('refuses a duplicate registration', () => {
    expect(() => registry.register(files as AccessTypeHandler)).toThrow(/already registered/);
  });
});
