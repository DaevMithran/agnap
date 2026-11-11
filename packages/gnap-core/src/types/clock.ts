/**
 * Time is injected everywhere expiry or `created` is compared, so every
 * time-dependent test is deterministic.
 */
export interface Clock {
  /** Milliseconds since the Unix epoch. */
  now(): number;
}

export interface FixedClock extends Clock {
  advance(ms: number): void;
  set(at: number | Date): void;
}
