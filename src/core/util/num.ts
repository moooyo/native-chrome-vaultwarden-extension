// Small numeric helpers shared across the codebase.

/**
 * Clamp `value` into the inclusive range [min, max]. For a degenerate range (min > max) the lower
 * bound wins, so the result collapses to `min` — matching the behavior of the local clamp helpers this
 * replaces.
 */
export function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}
