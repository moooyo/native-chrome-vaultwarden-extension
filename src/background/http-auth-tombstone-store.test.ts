import { describe, expect, it } from 'vitest';
import type { KeyValueStore } from '../platform/store.js';
import {
  DEFAULT_HTTP_AUTH_TOMBSTONE_TTL_MS,
  HTTP_AUTH_TOMBSTONE_SCHEMA_VERSION,
  HTTP_AUTH_TOMBSTONE_STORAGE_KEY,
  HttpAuthTombstoneStore,
  MAX_HTTP_AUTH_TOMBSTONE_CAPACITY,
} from './http-auth-tombstone-store.js';

function fingerprint(value: number): string {
  return value.toString(16).padStart(64, '0');
}

function memoryStore(initial?: unknown): {
  readonly store: KeyValueStore;
  readonly values: Map<string, unknown>;
} {
  const values = new Map<string, unknown>();
  if (initial !== undefined) values.set(HTTP_AUTH_TOMBSTONE_STORAGE_KEY, structuredClone(initial));
  const store: KeyValueStore = {
    async get<T>(key: string): Promise<T | undefined> {
      const value = values.get(key);
      return value === undefined ? undefined : structuredClone(value) as T;
    },
    async set(key: string, value: unknown): Promise<void> {
      values.set(key, structuredClone(value));
    },
    async remove(key: string): Promise<void> { values.delete(key); },
    async clear(): Promise<void> { values.clear(); },
  };
  return { store, values };
}

describe('HttpAuthTombstoneStore', () => {
  it('persists only a SHA-256 fingerprint and timestamps across worker restarts', async () => {
    const { store } = memoryStore();
    const first = new HttpAuthTombstoneStore({ store, now: () => 1_000 });

    await expect(first.claim(fingerprint(1))).resolves.toBe(true);
    const persisted = await store.get<Record<string, unknown>>(HTTP_AUTH_TOMBSTONE_STORAGE_KEY);
    expect(persisted).toEqual({
      schemaVersion: HTTP_AUTH_TOMBSTONE_SCHEMA_VERSION,
      entries: [{
        fingerprint: fingerprint(1),
        claimedAt: 1_000,
        expiresAt: 1_000 + DEFAULT_HTTP_AUTH_TOMBSTONE_TTL_MS,
      }],
    });
    expect(Object.keys(persisted ?? {}).sort()).toEqual(['entries', 'schemaVersion']);
    expect(Object.keys((persisted?.entries as object[])[0]!).sort())
      .toEqual(['claimedAt', 'expiresAt', 'fingerprint']);

    const restarted = new HttpAuthTombstoneStore({ store, now: () => 1_001 });
    await expect(restarted.claim(fingerprint(1))).resolves.toBe(false);
  });

  it('prunes an expired fingerprint and permits a fresh claim at the exact deadline', async () => {
    const { store } = memoryStore();
    let now = 100;
    const tombstones = new HttpAuthTombstoneStore({ store, now: () => now });
    await expect(tombstones.claim(fingerprint(1))).resolves.toBe(true);

    now += DEFAULT_HTTP_AUTH_TOMBSTONE_TTL_MS;
    await expect(tombstones.claim(fingerprint(1))).resolves.toBe(true);
    const persisted = await store.get<{ entries: Array<{ claimedAt: number }> }>(
      HTTP_AUTH_TOMBSTONE_STORAGE_KEY,
    );
    expect(persisted?.entries).toEqual([expect.objectContaining({ claimedAt: now })]);
  });

  it('evicts the oldest live entry before appending a new claim at capacity', async () => {
    const entries = Array.from({ length: MAX_HTTP_AUTH_TOMBSTONE_CAPACITY }, (_, index) => ({
      fingerprint: fingerprint(index + 1),
      claimedAt: index + 1,
      expiresAt: index + 1 + DEFAULT_HTTP_AUTH_TOMBSTONE_TTL_MS,
    }));
    const { store } = memoryStore({
      schemaVersion: HTTP_AUTH_TOMBSTONE_SCHEMA_VERSION,
      entries,
    });
    const tombstones = new HttpAuthTombstoneStore({ store, now: () => 1_000 });

    await expect(tombstones.claim(fingerprint(10_000))).resolves.toBe(true);
    const persisted = await store.get<{ entries: Array<{ fingerprint: string }> }>(
      HTTP_AUTH_TOMBSTONE_STORAGE_KEY,
    );
    expect(persisted?.entries).toHaveLength(MAX_HTTP_AUTH_TOMBSTONE_CAPACITY);
    expect(persisted?.entries.some((entry) => entry.fingerprint === fingerprint(1))).toBe(false);
    expect(persisted?.entries.at(-1)?.fingerprint).toBe(fingerprint(10_000));
  });

  it('serializes concurrent claims so distinct fingerprints are not lost', async () => {
    const { store } = memoryStore();
    const tombstones = new HttpAuthTombstoneStore({ store, now: () => 1_000 });

    await expect(Promise.all([
      tombstones.claim(fingerprint(1)),
      tombstones.claim(fingerprint(2)),
      tombstones.claim(fingerprint(1)),
    ])).resolves.toEqual([true, true, false]);
    const persisted = await store.get<{ entries: unknown[] }>(HTTP_AUTH_TOMBSTONE_STORAGE_KEY);
    expect(persisted?.entries).toHaveLength(2);
  });

  it('fails closed when a concurrent writer changes the post-write envelope', async () => {
    const { store: base } = memoryStore();
    const external = {
      fingerprint: fingerprint(99),
      claimedAt: 900,
      expiresAt: 900 + DEFAULT_HTTP_AUTH_TOMBSTONE_TTL_MS,
    };
    const store: KeyValueStore = {
      get: <T>(key: string) => base.get<T>(key),
      async set(key: string, value: unknown): Promise<void> {
        const expected = structuredClone(value) as { schemaVersion: 1; entries: unknown[] };
        await base.set(key, { ...expected, entries: [...expected.entries, external] });
      },
      remove: (key: string) => base.remove(key),
      clear: () => base.clear(),
    };
    const tombstones = new HttpAuthTombstoneStore({ store, now: () => 1_000 });

    await expect(tombstones.claim(fingerprint(1))).resolves.toBe(false);
  });

  it('leaves corrupt or unsupported state untouched instead of resolving ambiguity', async () => {
    const corruptStates: unknown[] = [
      null,
      { schemaVersion: 2, entries: [] },
      { schemaVersion: 1, entries: [], requestId: 'must-not-be-accepted' },
      { schemaVersion: 1, entries: [{ fingerprint: 'not-a-digest', claimedAt: 1, expiresAt: 2 }] },
      { schemaVersion: 1, entries: [{
        fingerprint: fingerprint(1), claimedAt: 2_000, expiresAt: 2_100,
      }] },
      { schemaVersion: 1, entries: [{
        fingerprint: fingerprint(1),
        claimedAt: 1,
        expiresAt: 1 + DEFAULT_HTTP_AUTH_TOMBSTONE_TTL_MS + 1,
      }] },
      { schemaVersion: 1, entries: Array.from(
        { length: MAX_HTTP_AUTH_TOMBSTONE_CAPACITY + 1 },
        (_, index) => ({ fingerprint: fingerprint(index), claimedAt: 1, expiresAt: 2 }),
      ) },
    ];

    for (const corrupt of corruptStates) {
      const { store } = memoryStore(corrupt);
      const before = await store.get(HTTP_AUTH_TOMBSTONE_STORAGE_KEY);
      const tombstones = new HttpAuthTombstoneStore({ store, now: () => 1_000 });
      await expect(tombstones.claim(fingerprint(10_000))).resolves.toBe(false);
      await expect(store.get(HTTP_AUTH_TOMBSTONE_STORAGE_KEY)).resolves.toEqual(before);
    }
  });

  it('fails closed on read, write, ambiguous commit, and verification failures', async () => {
    const failure = new Error('session persistence failed');
    const readFailure = new HttpAuthTombstoneStore({
      store: { async get() { throw failure; }, async set() {} },
      now: () => 1_000,
    });
    await expect(readFailure.claim(fingerprint(1))).resolves.toBe(false);

    const writeFailure = new HttpAuthTombstoneStore({
      store: { async get() { return undefined; }, async set() { throw failure; } },
      now: () => 1_000,
    });
    await expect(writeFailure.claim(fingerprint(1))).resolves.toBe(false);

    const { store: base } = memoryStore();
    const ambiguousCommit = new HttpAuthTombstoneStore({
      store: {
        get: <T>(key: string) => base.get<T>(key),
        async set(key, value) {
          await base.set(key, value);
          throw failure;
        },
      },
      now: () => 1_000,
    });
    await expect(ambiguousCommit.claim(fingerprint(1))).resolves.toBe(false);

    let reads = 0;
    const verificationFailure = new HttpAuthTombstoneStore({
      store: {
        async get() {
          reads += 1;
          if (reads === 1) return undefined;
          throw failure;
        },
        async set() {},
      },
      now: () => 1_000,
    });
    await expect(verificationFailure.claim(fingerprint(2))).resolves.toBe(false);
  });

  it('rejects invalid fingerprints, clocks, and unbounded configuration', async () => {
    let touched = false;
    const store = {
      async get() { touched = true; return undefined; },
      async set() { touched = true; },
    };
    const invalidFingerprint = new HttpAuthTombstoneStore({ store, now: () => 1_000 });
    await expect(invalidFingerprint.claim('A'.repeat(64))).resolves.toBe(false);
    expect(touched).toBe(false);

    const invalidClock = new HttpAuthTombstoneStore({ store, now: () => Number.NaN });
    await expect(invalidClock.claim(fingerprint(1))).resolves.toBe(false);
    expect(() => new HttpAuthTombstoneStore({
      store,
      ttlMs: DEFAULT_HTTP_AUTH_TOMBSTONE_TTL_MS + 1,
    })).toThrow(/ttlMs/);
    expect(() => new HttpAuthTombstoneStore({
      store,
      maxEntries: MAX_HTTP_AUTH_TOMBSTONE_CAPACITY + 1,
    })).toThrow(/maxEntries/);
    expect(() => new HttpAuthTombstoneStore({ store, storageKey: ' bad ' }))
      .toThrow(/storageKey/);
  });
});
