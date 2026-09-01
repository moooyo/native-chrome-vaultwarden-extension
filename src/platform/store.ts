import browser from 'webextension-polyfill';

export interface KeyValueStore {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
  /** Atomically replace every supplied key within this storage area. */
  setMany?(values: Readonly<Record<string, unknown>>): Promise<void>;
  remove(key: string): Promise<void>;
  clear(): Promise<void>;
}

export interface AtomicKeyValueStore extends KeyValueStore {
  setMany(values: Readonly<Record<string, unknown>>): Promise<void>;
}

export function createMemoryStore(): AtomicKeyValueStore {
  const map = new Map<string, string>();
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const raw = map.get(key);
      return raw === undefined ? undefined : (JSON.parse(raw) as T);
    },
    async set(key, value) {
      map.set(key, JSON.stringify(value));
    },
    async setMany(values) {
      // Serialize the complete batch before mutating the map so a serialization failure cannot
      // expose a partial write in tests that model browser.storage.set's all-or-nothing call.
      const serialized = Object.entries(values).map(([key, value]) => [key, JSON.stringify(value)] as const);
      for (const [key, value] of serialized) map.set(key, value);
    },
    async remove(key) {
      map.delete(key);
    },
    async clear() {
      map.clear();
    },
  };
}

export function createBrowserStore(area: 'local' | 'session'): AtomicKeyValueStore {
  const storage = browser.storage[area];
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const result = await storage.get(key);
      return result[key] as T | undefined;
    },
    async set(key, value) {
      await storage.set({ [key]: value });
    },
    async setMany(values) {
      await storage.set(values);
    },
    async remove(key) {
      await storage.remove(key);
    },
    async clear() {
      await storage.clear();
    },
  };
}

type StorageAreaWithAccessLevel = {
  setAccessLevel?: (opts: {
    accessLevel: 'TRUSTED_CONTEXTS' | 'TRUSTED_AND_UNTRUSTED_CONTEXTS';
  }) => Promise<void>;
};

/**
 * Restrict persistent and session storage to extension-owned contexts. The API is feature-detected
 * because it is Chromium-only and absent from the polyfill types and some test environments.
 * Actual API failures intentionally propagate so callers can report or handle a failed hardening.
 */
export async function hardenStorageAccessLevels(): Promise<void> {
  const areas = [browser.storage.local, browser.storage.session] as unknown as StorageAreaWithAccessLevel[];
  await Promise.all(areas.map(async (area) => {
    if (typeof area?.setAccessLevel !== 'function') return;
    await area.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
  }));
}

/** @deprecated Use hardenStorageAccessLevels. Kept for existing callers. */
export async function hardenSessionAccessLevel(): Promise<void> {
  await hardenStorageAccessLevels();
}
