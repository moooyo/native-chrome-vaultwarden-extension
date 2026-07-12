// @vitest-environment happy-dom
import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, onChanged: { addListener: vi.fn() } } },
}));

import { getTheme, setTheme, getDensity, setDensity } from './theme.js';

describe('appearance (theme + density)', () => {
  it('defaults to light + comfortable', () => {
    expect(getTheme()).toBe('light');
    expect(getDensity()).toBe('comfortable');
  });

  it('switches theme and density', () => {
    setTheme('dark', false);
    expect(getTheme()).toBe('dark');
    setDensity('compact', false);
    expect(getDensity()).toBe('compact');
    setTheme('light', false);
    setDensity('comfortable', false);
  });

  it('ignores invalid values', () => {
    // @ts-expect-error invalid theme rejected at runtime
    setTheme('neon', false);
    expect(['light', 'dark', 'system']).toContain(getTheme());
  });
});
