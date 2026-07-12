import { describe, expect, it } from 'vitest';
import { tileColor, tileInitial } from './tile-color.js';

describe('tile-color', () => {
  it('is deterministic for the same seed', () => {
    expect(tileColor('abc')).toBe(tileColor('abc'));
  });

  it('returns a hex color from the palette', () => {
    expect(tileColor('nebula')).toMatch(/^#[0-9A-Fa-f]{6}$/);
  });

  it('takes the first alphanumeric char uppercased as the initial', () => {
    expect(tileInitial('nebula')).toBe('N');
    expect(tileInitial('  hello')).toBe('H');
    expect(tileInitial('张之航')).toBe('张');
  });

  it('falls back to a bullet for empty / symbol-only names', () => {
    expect(tileInitial('')).toBe('•');
    expect(tileInitial('!!!')).toBe('•');
  });
});
