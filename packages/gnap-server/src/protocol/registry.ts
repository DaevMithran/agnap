import { thumbprint } from '@agnap/gnap-core';

import type { ResourceServerEntry, ResourceServerRegistry } from '../types/registry.js';

export class StaticResourceServerRegistry implements ResourceServerRegistry {
  readonly #byId = new Map<string, ResourceServerEntry>();
  readonly #byThumbprint = new Map<string, ResourceServerEntry>();

  constructor(entries: readonly ResourceServerEntry[] = []) {
    for (const e of entries) this.add(e);
  }

  add(entry: ResourceServerEntry): void {
    if (this.#byId.has(entry.id))
      throw new Error(`resource server ${entry.id} is already registered`);
    this.#byId.set(entry.id, entry);
    this.#byThumbprint.set(thumbprint(entry.key), entry);
  }

  get(id: string): ResourceServerEntry | null {
    return this.#byId.get(id) ?? null;
  }

  byThumbprint(tp: string): ResourceServerEntry | null {
    return this.#byThumbprint.get(tp) ?? null;
  }

  all(): ResourceServerEntry[] {
    return [...this.#byId.values()];
  }
}
