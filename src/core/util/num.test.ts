import { describe, it, expect } from 'vitest';
import { clamp } from './num.js';

describe('clamp', () => {
  it('returns the value when it is inside the range', () => {
    expect(clamp(5, 0, 10)).toBe(5);
  });

  it('clamps up to the lower bound', () => {
    expect(clamp(-3, 0, 10)).toBe(0);
  });

  it('clamps down to the upper bound', () => {
    expect(clamp(42, 0, 10)).toBe(10);
  });

  it('returns the shared bound when min === max', () => {
    expect(clamp(7, 3, 3)).toBe(3);
  });

  it('collapses a degenerate range (min > max) to min', () => {
    expect(clamp(5, 10, 0)).toBe(10);
    expect(clamp(-5, 10, 0)).toBe(10);
    expect(clamp(50, 10, 0)).toBe(10);
  });
});
