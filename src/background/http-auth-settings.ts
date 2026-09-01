import type { KeyValueStore } from '../platform/store.js';

const HTTP_AUTH_SETTINGS_KEY = 'httpAuthSettings';
const ORIGIN_ONLY_URL = /^https?:\/\/[^/?#\\]+\/?$/iu;

export const HTTP_AUTH_SETTINGS_SCHEMA_VERSION = 1 as const;
export const MAX_HTTP_AUTH_ORIGINS = 256;
export const INVALID_HTTP_AUTH_SETTINGS_MESSAGE = 'Invalid HTTP auth settings';

export interface HttpAuthSettings {
  readonly schemaVersion: typeof HTTP_AUTH_SETTINGS_SCHEMA_VERSION;
  readonly enabled: boolean;
  /** Complete user authorization list for HTTP-auth credential release. */
  readonly allowedOrigins: readonly string[];
}

export interface HttpAuthSettingsReadResult {
  readonly settings: Readonly<HttpAuthSettings>;
  readonly valid: boolean;
}

export const DEFAULT_HTTP_AUTH_SETTINGS: Readonly<HttpAuthSettings> = Object.freeze({
  schemaVersion: HTTP_AUTH_SETTINGS_SCHEMA_VERSION,
  enabled: false,
  allowedOrigins: Object.freeze([]),
});

/** Validate and reduce one configured URL to an exact HTTP(S) origin. */
export function canonicalizeHttpAuthOrigin(value: string): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.trim() !== value
    || containsControlCharacter(value)
    || value.includes('*')
    || !ORIGIN_ONLY_URL.test(value)
  ) {
    throw invalidHttpAuthSettings();
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw invalidHttpAuthSettings();
  }

  if (
    (parsed.protocol !== 'https:' && parsed.protocol !== 'http:')
    || parsed.username.length > 0
    || parsed.password.length > 0
    || parsed.pathname !== '/'
    || parsed.search.length > 0
    || parsed.hash.length > 0
    || value.includes('?')
    || value.includes('#')
    || (parsed.protocol === 'http:' && !isLoopbackHostname(parsed.hostname))
  ) {
    throw invalidHttpAuthSettings();
  }

  return parsed.origin;
}

/** Validate a complete v1 record. Invalid fields are never partially salvaged. */
export function sanitizeHttpAuthSettings(value: unknown): Readonly<HttpAuthSettings> {
  if (
    !isRecord(value)
    || !hasExactKeys(value, ['schemaVersion', 'enabled', 'allowedOrigins'])
    || value.schemaVersion !== HTTP_AUTH_SETTINGS_SCHEMA_VERSION
    || typeof value.enabled !== 'boolean'
    || !Array.isArray(value.allowedOrigins)
    || value.allowedOrigins.length > MAX_HTTP_AUTH_ORIGINS
  ) {
    throw invalidHttpAuthSettings();
  }

  const canonical = new Set<string>();
  for (let index = 0; index < value.allowedOrigins.length; index += 1) {
    if (!(index in value.allowedOrigins)) throw invalidHttpAuthSettings();
    const origin = value.allowedOrigins[index];
    if (typeof origin !== 'string') throw invalidHttpAuthSettings();
    canonical.add(canonicalizeHttpAuthOrigin(origin));
  }

  return Object.freeze({
    schemaVersion: HTTP_AUTH_SETTINGS_SCHEMA_VERSION,
    enabled: value.enabled,
    allowedOrigins: Object.freeze([...canonical].sort()),
  });
}

export function createHttpAuthSettingsService(store: KeyValueStore) {
  return {
    async get(): Promise<Readonly<HttpAuthSettingsReadResult>> {
      const stored = await store.get<unknown>(HTTP_AUTH_SETTINGS_KEY);
      if (stored === undefined) {
        return Object.freeze({ settings: DEFAULT_HTTP_AUTH_SETTINGS, valid: true });
      }

      try {
        return Object.freeze({ settings: sanitizeHttpAuthSettings(stored), valid: true });
      } catch {
        return Object.freeze({ settings: DEFAULT_HTTP_AUTH_SETTINGS, valid: false });
      }
    },

    async save(value: HttpAuthSettings): Promise<void> {
      const settings = sanitizeHttpAuthSettings(value);
      await store.set(HTTP_AUTH_SETTINGS_KEY, settings);
    },
  };
}

function isLoopbackHostname(hostname: string): boolean {
  if (hostname === 'localhost' || hostname === '[::1]') return true;
  const octets = hostname.split('.');
  return octets.length === 4
    && octets[0] === '127'
    && octets.every((octet) => /^\d{1,3}$/u.test(octet) && Number(octet) <= 255);
}

function invalidHttpAuthSettings(): Error {
  return new Error(INVALID_HTTP_AUTH_SETTINGS_MESSAGE);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
