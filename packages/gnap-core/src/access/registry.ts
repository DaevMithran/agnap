/**
 * RFC 9635 section 8: an access object is `{ "type": ... }` plus whatever
 * fields that type defines. The server knows nothing about any type. A
 * handler registered per type parses the object and decides containment,
 * which is all issuance needs: an issued item must be contained in some
 * requested item of the same type.
 *
 * Reference strings (section 8.1) are not supported in this profile and are
 * refused at parse time.
 */
import { AccessParseError } from '../errors.js';
import { validateRawAccessItem } from '../schemas/index.js';
import type { AccessItem, AccessTypeHandler } from '../types/access.js';

export class AccessTypeRegistry {
  readonly #handlers = new Map<string, AccessTypeHandler>();

  constructor(handlers: readonly AccessTypeHandler[] = []) {
    for (const h of handlers) this.register(h);
  }

  register(handler: AccessTypeHandler): void {
    if (this.#handlers.has(handler.type)) {
      throw new Error(`access type ${handler.type} is already registered`);
    }
    this.#handlers.set(handler.type, handler);
  }

  types(): string[] {
    return [...this.#handlers.keys()];
  }

  handlerFor(type: string): AccessTypeHandler | null {
    return this.#handlers.get(type) ?? null;
  }

  /** Parse a received `access` array. Strings, unknown types and malformed objects all throw. */
  parseAll(value: unknown): AccessItem[] {
    if (!Array.isArray(value) || value.length === 0) {
      throw new AccessParseError(null, 'access must be a non-empty array');
    }
    return value.map((item, i) => {
      if (typeof item === 'string') {
        throw new AccessParseError(null, `access[${i}]: reference strings are not supported`);
      }
      if (!validateRawAccessItem(item)) {
        throw new AccessParseError(null, `access[${i}]: object with a string type expected`);
      }
      const type = item.type;
      const handler = this.#handlers.get(type);
      if (handler === undefined) throw new AccessParseError(type, `access[${i}]: unknown type`);
      return handler.parse(item);
    });
  }

  /** Every item in `narrower` is contained in at least one item of the same type in `wider`. */
  containsAll(wider: readonly AccessItem[], narrower: readonly AccessItem[]): boolean {
    return narrower.every((n) => {
      const handler = this.#handlers.get(n.type);
      if (handler === undefined) return false;
      return wider.some((w) => w.type === n.type && handler.contains(w, n));
    });
  }
}

export function typesOf(items: readonly AccessItem[]): Set<string> {
  return new Set(items.map((i) => i.type));
}
