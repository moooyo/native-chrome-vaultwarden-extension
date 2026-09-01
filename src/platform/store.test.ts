import { describe, it, expect, vi, afterEach } from 'vitest';
import browser from 'webextension-polyfill';
import {
  createBrowserStore,
  createMemoryStore,
  hardenSessionAccessLevel,
  hardenStorageAccessLevels,
} from './store.js';

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

  it('writes a batch atomically from the caller perspective', async () => {
    const s = createMemoryStore();
    const first = { n: 1 };
    await s.setMany({ first, second: { n: 2 } });
    first.n = 99;
    expect(await s.get('first')).toEqual({ n: 1 });
    expect(await s.get('second')).toEqual({ n: 2 });
  });
});

describe('browser store', () => {
  it('sends a multi-key update in one storage.set call', async () => {
    const set = vi.mocked(browser.storage.local.set);
    set.mockResolvedValue(undefined);
    const store = createBrowserStore('local');

    await store.setMany({ auth: { refreshToken: 'new' }, accounts: { user: 'new' } });

    expect(set).toHaveBeenCalledOnce();
    expect(set).toHaveBeenCalledWith({
      auth: { refreshToken: 'new' },
      accounts: { user: 'new' },
    });
    set.mockClear();
  });
});

describe('hardenStorageAccessLevels', () => {
  const local = browser.storage.local as unknown as Record<string, unknown>;
  const session = browser.storage.session as unknown as Record<string, unknown>;
  afterEach(() => {
    delete local.setAccessLevel;
    delete session.setAccessLevel;
  });

  it('restricts local and session storage when the API is available', async () => {
    const localSpy = vi.fn().mockResolvedValue(undefined);
    const sessionSpy = vi.fn().mockResolvedValue(undefined);
    local.setAccessLevel = localSpy;
    session.setAccessLevel = sessionSpy;

    await hardenStorageAccessLevels();

    expect(localSpy).toHaveBeenCalledOnce();
    expect(localSpy).toHaveBeenCalledWith({ accessLevel: 'TRUSTED_CONTEXTS' });
    expect(sessionSpy).toHaveBeenCalledOnce();
    expect(sessionSpy).toHaveBeenCalledWith({ accessLevel: 'TRUSTED_CONTEXTS' });
  });

  it('feature-detects each storage area independently', async () => {
    const localSpy = vi.fn().mockResolvedValue(undefined);
    local.setAccessLevel = localSpy;
    delete session.setAccessLevel;

    await expect(hardenStorageAccessLevels()).resolves.toBeUndefined();
    expect(localSpy).toHaveBeenCalledWith({ accessLevel: 'TRUSTED_CONTEXTS' });
  });

  it('no-ops when the Chromium-only API is unavailable', async () => {
    delete local.setAccessLevel;
    delete session.setAccessLevel;
    await expect(hardenStorageAccessLevels()).resolves.toBeUndefined();
  });

  it('propagates API failures instead of silently weakening the boundary', async () => {
    const sessionSpy = vi.fn().mockResolvedValue(undefined);
    local.setAccessLevel = vi.fn().mockRejectedValue(new Error('local access denied'));
    session.setAccessLevel = sessionSpy;

    await expect(hardenStorageAccessLevels()).rejects.toThrow('local access denied');
    expect(sessionSpy).toHaveBeenCalledWith({ accessLevel: 'TRUSTED_CONTEXTS' });
  });

  it('keeps the old entry point wired to the unified hardening', async () => {
    const localSpy = vi.fn().mockResolvedValue(undefined);
    const sessionSpy = vi.fn().mockResolvedValue(undefined);
    local.setAccessLevel = localSpy;
    session.setAccessLevel = sessionSpy;

    await hardenSessionAccessLevel();

    expect(localSpy).toHaveBeenCalledOnce();
    expect(sessionSpy).toHaveBeenCalledOnce();
  });
});
