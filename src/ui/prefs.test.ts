// @vitest-environment happy-dom
import { describe, expect, it, vi, beforeEach } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, onChanged: { addListener: vi.fn() } } },
}));

import { getPrefs, setPref, subscribePrefs, DEFAULT_PREFS } from './prefs.js';

describe('prefs', () => {
  beforeEach(() => {
    // reset to defaults between tests
    setPref('genLength', DEFAULT_PREFS.genLength, false);
    setPref('genNumbers', DEFAULT_PREFS.genNumbers, false);
  });

  it('exposes defaults', () => {
    expect(getPrefs().genLength).toBe(20);
    expect(getPrefs().autoSync).toBe(true);
  });

  it('updates a pref and notifies subscribers', () => {
    const fn = vi.fn();
    const unsub = subscribePrefs(fn);
    setPref('genLength', 32, false);
    expect(getPrefs().genLength).toBe(32);
    expect(fn).toHaveBeenCalled();
    unsub();
  });

  it('ignores a no-op set', () => {
    const fn = vi.fn();
    const unsub = subscribePrefs(fn);
    setPref('genNumbers', getPrefs().genNumbers, false);
    expect(fn).not.toHaveBeenCalled();
    unsub();
  });
});
