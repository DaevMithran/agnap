/** The access object seam, RFC 9635 section 8. */
import type { components } from '../generated/as.js';

export type AccessItem = components['schemas']['AccessObject'];

export interface AccessTypeHandler<T extends AccessItem = AccessItem> {
  readonly type: string;
  /** Validate one object of this type. Throw `AccessParseError` on any defect. */
  parse(value: unknown): T;
  /** True when every right in `narrower` is also in `wider`. */
  contains(wider: T, narrower: T): boolean;
}
