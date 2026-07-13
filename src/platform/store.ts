import browser from 'webextension-polyfill';

export interface KeyValueStore {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
  remove(key: string): Promise<void>;
  clear(): Promise<void>;
}

export function createMemoryStore(): KeyValueStore {
  const map = new Map<string, string>();
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const raw = map.get(key);
      return raw === undefined ? undefined : (JSON.parse(raw) as T);
    },
    async set(key, value) {
      map.set(key, JSON.stringify(value));
    },
    async remove(key) {
      map.delete(key);
    },
    async clear() {
      map.clear();
    },
  };
}

export function createBrowserStore(area: 'local' | 'session'): KeyValueStore {
  const storage = browser.storage[area];
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const result = await storage.get(key);
      return result[key] as T | undefined;
    },
    async set(key, value) {
      await storage.set({ [key]: value });
    },
    async remove(key) {
      await storage.remove(key);
    },
    async clear() {
      await storage.clear();
    },
  };
}

/**
 * Pin chrome.storage.session to TRUSTED_CONTEXTS so the UserKey / private key cached there can
 * never be read from a content script. Chrome's default is already TRUSTED_CONTEXTS; this makes
 * the boundary explicit and survives a future default change. Feature-detected because the method
 * is Chromium-only and absent from the polyfill types / non-browser test environments.
 *
 * Callers must wrap this in `.catch()` — it is left un-swallowed so it stays unit-testable.
 */
export async function hardenSessionAccessLevel(): Promise<void> {
  const sessionArea = browser.storage.session as unknown as {
    setAccessLevel?: (opts: { accessLevel: 'TRUSTED_CONTEXTS' | 'TRUSTED_AND_UNTRUSTED_CONTEXTS' }) => Promise<void>;
  };
  if (typeof sessionArea?.setAccessLevel !== 'function') return;
  await sessionArea.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
}
