import { describe, expect, it } from 'vitest';
import {
  MAX_PAGE_LOAD_CLAIM_CAPACITY,
  MAX_PAGE_LOAD_CLAIM_TTL_MS,
  PageLoadFillDeduper,
} from './page-load-fill-deduper.js';

const CLAIM = {
  tabId: 7,
  frameId: 0,
  documentId: 'doc-1',
  frameUrl: 'https://example.com/login',
};

describe('PageLoadFillDeduper', () => {
  it('allows one claim per exact browser document URL and rejects URL ABA replay', () => {
    const deduper = new PageLoadFillDeduper({ now: () => 100 });
    expect(deduper.claim(CLAIM)).toBe(true);
    expect(deduper.claim(CLAIM)).toBe(false);
    expect(deduper.claim({ ...CLAIM, frameUrl: 'https://example.com/account' })).toBe(true);
    expect(deduper.claim(CLAIM)).toBe(false);
    expect(deduper.claim({ ...CLAIM, documentId: 'doc-2' })).toBe(true);
  });

  it('reclaims old document ids after the bounded replay window', () => {
    let now = 0;
    const deduper = new PageLoadFillDeduper({ ttlMs: 100, maxEntries: 1, now: () => now });
    expect(deduper.claim(CLAIM)).toBe(true);
    now = 100;
    expect(deduper.claim({ ...CLAIM, documentId: 'doc-2' })).toBe(true);
  });

  it('fails closed at capacity and for malformed browser context', () => {
    const deduper = new PageLoadFillDeduper({ maxEntries: 1 });
    expect(deduper.claim(CLAIM)).toBe(true);
    expect(deduper.claim({ ...CLAIM, documentId: 'doc-2' })).toBe(false);
    expect(deduper.claim({ ...CLAIM, documentId: '' })).toBe(false);
    expect(deduper.claim({ ...CLAIM, tabId: -1 })).toBe(false);
    expect(deduper.claim({ ...CLAIM, frameUrl: 'not a URL' })).toBe(false);
  });

  it('persists a bounded tombstone across worker-local registry instances', async () => {
    const values = new Map<string, unknown>();
    const store = {
      get: async <T>(key: string) => values.get(key) as T | undefined,
      set: async (key: string, value: unknown) => { values.set(key, value); },
      remove: async (key: string) => { values.delete(key); },
      clear: async () => { values.clear(); },
    };
    const first = new PageLoadFillDeduper({ store, now: () => 100 });
    expect(first.claim(CLAIM)).toBe(true);
    await expect(first.persist(CLAIM)).resolves.toBe(true);

    const afterRestart = new PageLoadFillDeduper({ store, now: () => 101 });
    expect(afterRestart.claim(CLAIM)).toBe(true);
    await expect(afterRestart.persist(CLAIM)).resolves.toBe(false);
  });

  it('honors a stricter legacy document tombstone after upgrading to URL-scoped claims', async () => {
    const values = new Map<string, unknown>([[
      'autofill.pageLoadClaims',
      [{ key: '7:0:5:doc-1', expiresAt: 200 }],
    ]]);
    const store = {
      get: async <T>(key: string) => values.get(key) as T | undefined,
      set: async (key: string, value: unknown) => { values.set(key, value); },
      remove: async (key: string) => { values.delete(key); },
      clear: async () => { values.clear(); },
    };
    const deduper = new PageLoadFillDeduper({ store, now: () => 100 });

    expect(deduper.claim(CLAIM)).toBe(true);
    await expect(deduper.persist(CLAIM)).resolves.toBe(false);
  });

  it('rejects unbounded configuration and an overflowing expiry', () => {
    expect(() => new PageLoadFillDeduper({ ttlMs: MAX_PAGE_LOAD_CLAIM_TTL_MS + 1 })).toThrow(/ttlMs/);
    expect(() => new PageLoadFillDeduper({ maxEntries: MAX_PAGE_LOAD_CLAIM_CAPACITY + 1 })).toThrow(/maxEntries/);
    const overflowing = new PageLoadFillDeduper({ now: () => Number.MAX_SAFE_INTEGER });
    expect(overflowing.claim(CLAIM)).toBe(false);
  });

  it('validates persisted capacity against the configured instance limit', async () => {
    const values = new Map<string, unknown>([[
      'autofill.pageLoadClaims',
      [
        { key: '7:0:5:doc-a', expiresAt: 200 },
        { key: '7:0:5:doc-b', expiresAt: 200 },
      ],
    ]]);
    const store = {
      get: async <T>(key: string) => values.get(key) as T | undefined,
      set: async (key: string, value: unknown) => { values.set(key, value); },
      remove: async (key: string) => { values.delete(key); },
      clear: async () => { values.clear(); },
    };
    const deduper = new PageLoadFillDeduper({ store, maxEntries: 1, now: () => 100 });
    expect(deduper.claim(CLAIM)).toBe(true);
    await expect(deduper.persist(CLAIM)).resolves.toBe(false);
  });
});
