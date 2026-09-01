import { describe, expect, it, vi } from 'vitest';
import type { KeyValueStore } from '../platform/store.js';
import {
  canonicalizeHttpAuthOrigin,
  createHttpAuthSettingsService,
  DEFAULT_HTTP_AUTH_SETTINGS,
  HTTP_AUTH_SETTINGS_SCHEMA_VERSION,
  INVALID_HTTP_AUTH_SETTINGS_MESSAGE,
  MAX_HTTP_AUTH_ORIGINS,
  sanitizeHttpAuthSettings,
  type HttpAuthSettings,
} from './http-auth-settings.js';

const SETTINGS_KEY = 'httpAuthSettings';

interface TestStore extends KeyValueStore {
  readonly values: Map<string, unknown>;
}

function createTestStore(): TestStore {
  const values = new Map<string, unknown>();
  return {
    values,
    async get<T>(key: string): Promise<T | undefined> {
      return values.get(key) as T | undefined;
    },
    async set(key: string, value: unknown): Promise<void> {
      values.set(key, value);
    },
    async remove(key: string): Promise<void> {
      values.delete(key);
    },
    async clear(): Promise<void> {
      values.clear();
    },
  };
}

function record(overrides: Partial<HttpAuthSettings> = {}): HttpAuthSettings {
  return {
    schemaVersion: HTTP_AUTH_SETTINGS_SCHEMA_VERSION,
    enabled: true,
    allowedOrigins: [],
    ...overrides,
  };
}

describe('canonicalizeHttpAuthOrigin', () => {
  it.each([
    ['HTTPS://Example.COM:443', 'https://example.com'],
    ['https://B\u00dcCHER.Example/', 'https://xn--bcher-kva.example'],
    ['https://sub.example.com:8443/', 'https://sub.example.com:8443'],
    ['http://localhost:80/', 'http://localhost'],
    ['http://127.1', 'http://127.0.0.1'],
    ['http://127.0.0.2:8080/', 'http://127.0.0.2:8080'],
    ['http://[0:0:0:0:0:0:0:1]:8080', 'http://[::1]:8080'],
  ])('canonicalizes the exact origin %s', (input, expected) => {
    expect(canonicalizeHttpAuthOrigin(input)).toBe(expected);
  });

  it.each([
    ['remote plaintext HTTP', 'http://example.com'],
    ['localhost suffix', 'http://localhost.'],
    ['non-loopback IPv4', 'http://128.0.0.1'],
    ['non-loopback IPv6', 'http://[::2]'],
    ['non-HTTP scheme', 'ftp://example.com'],
    ['path', 'https://example.com/login'],
    ['dot path normalized by URL', 'https://example.com/a/..'],
    ['empty query', 'https://example.com?'],
    ['query', 'https://example.com/?tenant=one'],
    ['empty fragment', 'https://example.com#'],
    ['fragment', 'https://example.com/#login'],
    ['username', 'https://user@example.com'],
    ['password', 'https://user:secret@example.com'],
    ['wildcard host', 'https://*.example.com'],
    ['wildcard port', 'https://example.com:*'],
    ['leading whitespace', ' https://example.com'],
    ['backslash authority separator', 'https://example.com\\login'],
    ['invalid URL', 'not a URL'],
  ])('rejects %s', (_label, input) => {
    expect(() => canonicalizeHttpAuthOrigin(input)).toThrow(INVALID_HTTP_AUTH_SETTINGS_MESSAGE);
  });
});

describe('HTTP auth settings schema', () => {
  it('canonicalizes, deduplicates, sorts, and freezes a complete record', () => {
    const settings = sanitizeHttpAuthSettings(record({
      allowedOrigins: [
        'https://Z.example:443/',
        'HTTPS://a.example/',
        'https://z.example',
        'http://127.0.0.2:8080/',
      ],
    }));

    expect(settings).toEqual(record({
      allowedOrigins: ['http://127.0.0.2:8080', 'https://a.example', 'https://z.example'],
    }));
    expect(Object.isFrozen(settings)).toBe(true);
    expect(Object.isFrozen(settings.allowedOrigins)).toBe(true);
  });

  it.each([
    ['null record', null],
    ['array record', []],
    ['missing schema', { enabled: true, allowedOrigins: [] }],
    ['future schema', { schemaVersion: 2, enabled: true, allowedOrigins: [] }],
    ['missing enabled', { schemaVersion: 1, allowedOrigins: [] }],
    ['invalid enabled', { schemaVersion: 1, enabled: 'yes', allowedOrigins: [] }],
    ['missing allowed origins', { schemaVersion: 1, enabled: true }],
    ['non-array allowed origins', { schemaVersion: 1, enabled: true, allowedOrigins: 'https://example.com' }],
    ['non-string origin', { schemaVersion: 1, enabled: true, allowedOrigins: [42] }],
    ['invalid origin', { schemaVersion: 1, enabled: true, allowedOrigins: ['http://example.com'] }],
    ['extra field', { schemaVersion: 1, enabled: true, allowedOrigins: [], futureFlag: true }],
    ['too many allowed origins', {
      schemaVersion: 1,
      enabled: true,
      allowedOrigins: Array.from(
        { length: MAX_HTTP_AUTH_ORIGINS + 1 },
        (_, index) => `https://host-${index}.example`,
      ),
    }],
  ])('rejects a non-exact or corrupt record: %s', (_label, value) => {
    expect(() => sanitizeHttpAuthSettings(value)).toThrow(INVALID_HTTP_AUTH_SETTINGS_MESSAGE);
  });

  it('rejects sparse origin arrays', () => {
    const allowedOrigins = Array<string>(1);
    expect(() => sanitizeHttpAuthSettings(record({ allowedOrigins }))).toThrow(
      INVALID_HTTP_AUTH_SETTINGS_MESSAGE,
    );
  });

  it('accepts exactly the maximum number of configured origins', () => {
    const allowedOrigins = Array.from(
      { length: MAX_HTTP_AUTH_ORIGINS },
      (_, index) => `https://host-${index}.example`,
    );
    expect(sanitizeHttpAuthSettings(record({ allowedOrigins })).allowedOrigins)
      .toHaveLength(MAX_HTTP_AUTH_ORIGINS);
  });
});

describe('HTTP auth settings service', () => {
  it('returns a frozen, disabled default with a valid signal when storage is absent', async () => {
    const result = await createHttpAuthSettingsService(createTestStore()).get();

    expect(result).toEqual({
      settings: { schemaVersion: 1, enabled: false, allowedOrigins: [] },
      valid: true,
    });
    expect(result.settings).toBe(DEFAULT_HTTP_AUTH_SETTINGS);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.settings)).toBe(true);
    expect(Object.isFrozen(result.settings.allowedOrigins)).toBe(true);
  });

  it('returns canonical settings with a valid signal for a valid stored record', async () => {
    const store = createTestStore();
    store.values.set(SETTINGS_KEY, record({ allowedOrigins: ['HTTPS://Example.COM:443/'] }));

    await expect(createHttpAuthSettingsService(store).get()).resolves.toEqual({
      settings: record({ allowedOrigins: ['https://example.com'] }),
      valid: true,
    });
  });

  it('fails closed and signals invalid without repairing a corrupt stored record', async () => {
    const store = createTestStore();
    store.values.set(SETTINGS_KEY, {
      schemaVersion: 1,
      enabled: true,
      allowedOrigins: ['http://example.com'],
    });
    const set = vi.spyOn(store, 'set');

    const result = await createHttpAuthSettingsService(store).get();

    expect(result).toEqual({ settings: DEFAULT_HTTP_AUTH_SETTINGS, valid: false });
    expect(result.settings).toBe(DEFAULT_HTTP_AUTH_SETTINGS);
    expect(set).not.toHaveBeenCalled();
  });

  it('validates the entire save before a single canonical write', async () => {
    const store = createTestStore();
    const get = vi.spyOn(store, 'get');
    const set = vi.spyOn(store, 'set');
    const service = createHttpAuthSettingsService(store);

    await service.save(record({
      allowedOrigins: ['https://B.example:443/', 'HTTPS://a.example', 'https://b.example'],
    }));

    expect(get).not.toHaveBeenCalled();
    expect(set).toHaveBeenCalledOnce();
    expect(set).toHaveBeenCalledWith(SETTINGS_KEY, record({
      allowedOrigins: ['https://a.example', 'https://b.example'],
    }));
  });

  it('preserves the prior record when a strict save is invalid', async () => {
    const store = createTestStore();
    const service = createHttpAuthSettingsService(store);
    const original = record({ allowedOrigins: ['https://original.example'] });
    await service.save(original);

    await expect(service.save(record({
      allowedOrigins: ['https://valid.example', 'http://remote.example'],
    }))).rejects.toThrow(INVALID_HTTP_AUTH_SETTINGS_MESSAGE);
    await expect(service.get()).resolves.toEqual({ settings: original, valid: true });
  });

  it('propagates storage failures instead of misreporting them as corrupt data', async () => {
    const store = createTestStore();
    vi.spyOn(store, 'get').mockRejectedValue(new Error('storage unavailable'));

    await expect(createHttpAuthSettingsService(store).get()).rejects.toThrow('storage unavailable');
  });
});
