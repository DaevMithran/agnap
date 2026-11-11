import type { Clock, FixedClock } from '../types/clock.js';

export const systemClock: Clock = { now: () => Date.now() };

/** A clock that only moves when told to. For tests. */
export function fixedClock(at: number | Date = 1_700_000_000_000): FixedClock {
  let current = typeof at === 'number' ? at : at.getTime();
  return {
    now: () => current,
    advance(ms) {
      current += ms;
    },
    set(next) {
      current = typeof next === 'number' ? next : next.getTime();
    },
  };
}

/** Whole seconds since the Unix epoch, as RFC 9421 parameters and `exp` use. */
export function nowSeconds(clock: Clock): number {
  return Math.floor(clock.now() / 1000);
}
