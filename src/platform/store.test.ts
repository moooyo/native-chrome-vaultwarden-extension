import { describe, it, expect, vi, afterEach } from 'vitest';
import browser from 'webextension-polyfill';
import { createMemoryStore, hardenSessionAccessLevel } from './store.js';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: {
        get: vi.fn(),
        set: vi.fn(),
        remove: vi.fn(),
        clear: vi.fn(),
      },
      session: {
        get: vi.fn(),
        set: vi.fn(),
        remove: vi.fn(),
        clear: vi.fn(),
      },
    },
  },
}));

describe('memory store', () => {
  it('round-trips values and isolates keys', async () => {
    const s = createMemoryStore();
    expect(await s.get('missing')).toBeUndefined();
    await s.set('a', { n: 1 });
    expect(await s.get<{ n: number }>('a')).toEqual({ n: 1 });
    await s.remove('a');
    expect(await s.get('a')).toBeUndefined();
  });

  it('clear empties the store', async () => {
    const s = createMemoryStore();
    await s.set('a', 1);
    await s.set('b', 2);
    await s.clear();
    expect(await s.get('a')).toBeUndefined();
    expect(await s.get('b')).toBeUndefined();
  });

  it('deep-clones on write so later mutation does not leak in', async () => {
    const s = createMemoryStore();
    const obj = { n: 1 };
    await s.set('a', obj);
    obj.n = 99;
    expect(await s.get<{ n: number }>('a')).toEqual({ n: 1 });
  });
});

describe('hardenSessionAccessLevel', () => {
  const session = browser.storage.session as unknown as Record<string, unknown>;
  afterEach(() => {
    delete session.setAccessLevel;
  });

  it('calls setAccessLevel with TRUSTED_CONTEXTS when the API is available', async () => {
    const spy = vi.fn().mockResolvedValue(undefined);
    session.setAccessLevel = spy;
    await hardenSessionAccessLevel();
    expect(spy).toHaveBeenCalledWith({ accessLevel: 'TRUSTED_CONTEXTS' });
  });

  it('no-ops without throwing when setAccessLevel is unavailable (feature-detect)', async () => {
    delete session.setAccessLevel;
    await expect(hardenSessionAccessLevel()).resolves.toBeUndefined();
  });

  it('propagates a rejection to the caller (so index.ts must wrap it in catch)', async () => {
    session.setAccessLevel = vi.fn().mockRejectedValue(new Error('nope'));
    await expect(hardenSessionAccessLevel()).rejects.toThrow('nope');
  });
});
