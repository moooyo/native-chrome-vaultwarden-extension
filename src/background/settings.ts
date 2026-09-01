import type { KeyValueStore } from '../platform/store.js';
import { isUriMatchStrategySetting, UriMatchStrategy, type UriMatchStrategySetting } from '../core/vault/uri-match.js';
import {
  MAX_AUTOFILL_BLOCKLIST_ENTRIES,
  normalizeAutofillBlocklist,
} from '../core/vault/autofill-policy.js';

const SERVER_URL_KEY = 'serverUrl';
const DEFAULT_URI_MATCH_STRATEGY_KEY = 'defaultUriMatchStrategy';
const LOCK_TIMEOUT_KEY = 'lockTimeout';
const AUTOFILL_POLICY_SETTINGS_KEY = 'autofillPolicySettings';
// Read-only compatibility key. Every new write uses AUTOFILL_POLICY_SETTINGS_KEY.
const AUTOFILL_SETTINGS_KEY = 'autofillSettings';
const WEBSITE_PASSKEY_SETTINGS_KEY = 'websitePasskeySettings';
export const SHOW_MATCHING_LOGIN_COUNT_KEY = 'showMatchingLoginCount';
export const DEFAULT_SHOW_MATCHING_LOGIN_COUNT = true;

export const AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION = 4 as const;
const LEGACY_AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION = 1 as const;
const INTERMEDIATE_AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION = 2 as const;
const PREVIOUS_AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION = 3 as const;
export const MAX_BLOCKED_DOMAINS = MAX_AUTOFILL_BLOCKLIST_ENTRIES;
export const MAX_BLOCKED_DOMAIN_LENGTH = 2_048;
export const MAX_SAVE_PROMPT_EXCLUDED_DOMAINS = MAX_AUTOFILL_BLOCKLIST_ENTRIES;
export const INVALID_AUTOFILL_SETTINGS_MESSAGE = 'Invalid autofill settings';
export const WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION = 1 as const;
export const MAX_WEBSITE_PASSKEY_EXCLUDED_DOMAINS = 256;
export const MAX_WEBSITE_PASSKEY_EXCLUDED_DOMAIN_LENGTH = 253;
export const INVALID_WEBSITE_PASSKEY_SETTINGS_MESSAGE = 'Invalid website passkey settings';

export interface AutofillSettings {
  readonly inlineSuggestions: boolean;
  readonly pageLoadFill: boolean;
  readonly autoCopyTotp: boolean;
  readonly savePromptEnabled: boolean;
  readonly updatePromptEnabled: boolean;
  readonly savePromptExcludedDomains: readonly string[];
  readonly blockedDomains: readonly string[];
}

export interface AutofillPolicySettings extends AutofillSettings {
  readonly schemaVersion: typeof AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION;
  readonly defaultUriMatchStrategy: UriMatchStrategySetting;
  readonly pageLoadFillDefault: boolean;
}

export interface WebsitePasskeySettings {
  readonly schemaVersion: typeof WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION;
  readonly enabled: boolean;
  readonly excludedDomains: readonly string[];
}

export const DEFAULT_AUTOFILL_SETTINGS: Readonly<AutofillSettings> = Object.freeze({
  inlineSuggestions: true,
  pageLoadFill: false,
  autoCopyTotp: true,
  savePromptEnabled: true,
  updatePromptEnabled: true,
  savePromptExcludedDomains: Object.freeze([]),
  blockedDomains: Object.freeze([]),
});

export const DEFAULT_AUTOFILL_POLICY_SETTINGS: Readonly<AutofillPolicySettings> = Object.freeze({
  schemaVersion: AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
  defaultUriMatchStrategy: UriMatchStrategy.Domain,
  pageLoadFillDefault: true,
  ...DEFAULT_AUTOFILL_SETTINGS,
});

export const DEFAULT_WEBSITE_PASSKEY_SETTINGS: Readonly<WebsitePasskeySettings> = Object.freeze({
  schemaVersion: WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION,
  enabled: false,
  excludedDomains: Object.freeze([]),
});

/** Built-in local vault timeout choices. Canonical minute strings outside this list are custom. */
export const LOCK_TIMEOUT_VALUES = ['immediate', '1', '5', '15', '30', 'onLocked', 'onClose'] as const;
export const MAX_LOCK_TIMEOUT_MINUTES = 43_200;
export type CanonicalLockTimeoutMinutes = `${number}`;
export type SelectableLockTimeoutSetting =
  | (typeof LOCK_TIMEOUT_VALUES)[number]
  | CanonicalLockTimeoutMinutes;
export type LockTimeoutSetting = SelectableLockTimeoutSetting | 'never';
export const DEFAULT_LOCK_TIMEOUT: SelectableLockTimeoutSetting = '15';

/** Parse persisted settings, including the legacy local `never` value. */
export function isLockTimeoutSetting(value: unknown): value is LockTimeoutSetting {
  return value === 'never' || isSelectableLockTimeoutSetting(value);
}

export function isSelectableLockTimeoutSetting(
  value: unknown,
): value is SelectableLockTimeoutSetting {
  return typeof value === 'string'
    && ((LOCK_TIMEOUT_VALUES as readonly string[]).includes(value)
      || isCanonicalLockTimeoutMinutes(value));
}

export function isCanonicalLockTimeoutMinutes(
  value: unknown,
): value is CanonicalLockTimeoutMinutes {
  if (typeof value !== 'string' || !/^[1-9]\d{0,4}$/u.test(value)) return false;
  const minutes = Number(value);
  return Number.isSafeInteger(minutes) && minutes <= MAX_LOCK_TIMEOUT_MINUTES;
}

/** Idle window in ms, or null for browser-close, system-lock, and legacy disabled-idle settings. */
export function lockTimeoutToIdleMs(value: LockTimeoutSetting): number | null {
  if (value === 'never' || value === 'onClose' || value === 'onLocked') return null;
  if (value === 'immediate') return 0;
  if (!isCanonicalLockTimeoutMinutes(value)) throw new TypeError('invalid lock timeout');
  const milliseconds = Number(value) * 60_000;
  if (!Number.isSafeInteger(milliseconds)) throw new RangeError('lock timeout exceeds the safe range');
  return milliseconds;
}

const ON_IDLE_ACTION_KEY = 'onIdleAction';
export type OnIdleAction = 'lock' | 'logout';
export const DEFAULT_ON_IDLE_ACTION: OnIdleAction = 'lock';
export function isOnIdleAction(value: unknown): value is OnIdleAction {
  return value === 'lock' || value === 'logout';
}

const CLIPBOARD_CLEAR_KEY = 'clipboardClearSeconds';
/** Clipboard auto-clear options. Seconds ≥30 (Chrome clamps alarms to ~30s) plus 'never'. */
export const CLIPBOARD_CLEAR_VALUES = ['never', '30', '60', '120', '300'] as const;
export type ClipboardClearSetting = (typeof CLIPBOARD_CLEAR_VALUES)[number];
export const DEFAULT_CLIPBOARD_CLEAR: ClipboardClearSetting = '60';
export function isClipboardClearSetting(value: unknown): value is ClipboardClearSetting {
  return typeof value === 'string' && (CLIPBOARD_CLEAR_VALUES as readonly string[]).includes(value);
}
/** Clear delay in seconds, or null when 'never'. */
export function clipboardClearToSeconds(value: ClipboardClearSetting): number | null {
  return value === 'never' ? null : Number(value);
}

function isLoopbackHostname(hostname: string): boolean {
  if (hostname === 'localhost' || hostname === '[::1]') return true;
  const octets = hostname.split('.');
  return octets.length === 4
    && octets[0] === '127'
    && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

export function normalizeServerUrl(serverUrl: string): string {
  const url = new URL(serverUrl);
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('serverUrl must start with http:// or https://');
  }
  if (url.username || url.password) {
    throw new Error('serverUrl must not include credentials');
  }
  if (url.protocol === 'http:' && !isLoopbackHostname(url.hostname)) {
    throw new Error('serverUrl must use https:// unless it targets a loopback host');
  }
  if (url.search || url.hash || /[?#]/.test(url.href)) {
    throw new Error('serverUrl must not include query or fragment');
  }
  if (!url.pathname.endsWith('/')) url.pathname += '/';
  return url.toString();
}

/**
 * Validate and canonicalize one complete autofill policy record. A partially valid record is never
 * salvaged: callers must treat the fixed error as a fail-closed policy state.
 */
export function sanitizeAutofillSettings(value: unknown): Readonly<AutofillSettings> {
  if (
    !isRecord(value)
    || !hasExactKeys(value, [
      'inlineSuggestions',
      'pageLoadFill',
      'autoCopyTotp',
      'savePromptEnabled',
      'updatePromptEnabled',
      'savePromptExcludedDomains',
      'blockedDomains',
    ])
    || typeof value.inlineSuggestions !== 'boolean'
    || typeof value.pageLoadFill !== 'boolean'
    || typeof value.autoCopyTotp !== 'boolean'
    || typeof value.savePromptEnabled !== 'boolean'
    || typeof value.updatePromptEnabled !== 'boolean'
  ) {
    throw invalidAutofillSettings();
  }
  const blockedDomains = sanitizeAutofillDomainList(value.blockedDomains, MAX_BLOCKED_DOMAINS);
  const savePromptExcludedDomains = sanitizeAutofillDomainList(
    value.savePromptExcludedDomains,
    MAX_SAVE_PROMPT_EXCLUDED_DOMAINS,
  );
  return Object.freeze({
    inlineSuggestions: value.inlineSuggestions,
    pageLoadFill: value.pageLoadFill,
    autoCopyTotp: value.autoCopyTotp,
    savePromptEnabled: value.savePromptEnabled,
    updatePromptEnabled: value.updatePromptEnabled,
    savePromptExcludedDomains,
    blockedDomains,
  });
}

export function sanitizeAutofillPolicySettings(value: unknown): Readonly<AutofillPolicySettings> {
  if (
    !isRecord(value)
    || !hasExactKeys(value, [
      'schemaVersion',
      'defaultUriMatchStrategy',
      'inlineSuggestions',
      'pageLoadFill',
      'pageLoadFillDefault',
      'autoCopyTotp',
      'savePromptEnabled',
      'updatePromptEnabled',
      'savePromptExcludedDomains',
      'blockedDomains',
    ])
    || value.schemaVersion !== AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION
    || !isUriMatchStrategySetting(value.defaultUriMatchStrategy)
    || typeof value.pageLoadFillDefault !== 'boolean'
  ) {
    throw invalidAutofillSettings();
  }
  const autofill = sanitizeAutofillSettings({
    inlineSuggestions: value.inlineSuggestions,
    pageLoadFill: value.pageLoadFill,
    autoCopyTotp: value.autoCopyTotp,
    savePromptEnabled: value.savePromptEnabled,
    updatePromptEnabled: value.updatePromptEnabled,
    savePromptExcludedDomains: value.savePromptExcludedDomains,
    blockedDomains: value.blockedDomains,
  });
  return Object.freeze({
    schemaVersion: AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
    defaultUriMatchStrategy: value.defaultUriMatchStrategy,
    pageLoadFillDefault: value.pageLoadFillDefault,
    ...autofill,
  });
}

/** Canonicalize one exact hostname policy entry. URLs, ports, credentials, and paths are rejected. */
export function canonicalizeWebsitePasskeyHostname(value: string): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_WEBSITE_PASSKEY_EXCLUDED_DOMAIN_LENGTH
    || containsControlCharacter(value)
    || /\s/u.test(value)
    || value.includes('@')
    || value.includes('/')
    || value.includes('?')
    || value.includes('#')
  ) {
    throw invalidWebsitePasskeySettings();
  }

  let candidate = value;
  if (value.includes(':') && !(value.startsWith('[') && value.endsWith(']'))) {
    // A raw IPv6 address is a hostname; a single colon is instead a forbidden host:port pair.
    if (value.indexOf(':') === value.lastIndexOf(':')) throw invalidWebsitePasskeySettings();
    candidate = `[${value}]`;
  }

  let parsed: URL;
  try {
    parsed = new URL(`https://${candidate}/`);
  } catch {
    throw invalidWebsitePasskeySettings();
  }
  if (
    parsed.username
    || parsed.password
    || parsed.port
    || parsed.pathname !== '/'
    || parsed.search
    || parsed.hash
  ) {
    throw invalidWebsitePasskeySettings();
  }

  let hostname = parsed.hostname.toLowerCase();
  if (!hostname.startsWith('[') && hostname.endsWith('.')) hostname = hostname.slice(0, -1);
  if (!hostname || hostname.length > MAX_WEBSITE_PASSKEY_EXCLUDED_DOMAIN_LENGTH) {
    throw invalidWebsitePasskeySettings();
  }
  if (hostname.startsWith('[')) return hostname;
  if (/^\d+(?:\.\d+){3}$/u.test(hostname)) return hostname;
  if (hostname === 'localhost') return hostname;

  const labels = hostname.split('.');
  if (labels.some((label) => (
    label.length === 0
    || label.length > 63
    || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label)
  ))) {
    throw invalidWebsitePasskeySettings();
  }
  return hostname;
}

/** Validate one complete website-passkey record; corrupt records fail closed as a whole. */
export function sanitizeWebsitePasskeySettings(value: unknown): Readonly<WebsitePasskeySettings> {
  if (
    !isRecord(value)
    || !hasExactKeys(value, ['schemaVersion', 'enabled', 'excludedDomains'])
    || value.schemaVersion !== WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION
    || typeof value.enabled !== 'boolean'
    || !Array.isArray(value.excludedDomains)
    || value.excludedDomains.length > MAX_WEBSITE_PASSKEY_EXCLUDED_DOMAINS
  ) {
    throw invalidWebsitePasskeySettings();
  }

  const canonical = new Set<string>();
  for (let index = 0; index < value.excludedDomains.length; index += 1) {
    if (!(index in value.excludedDomains)) throw invalidWebsitePasskeySettings();
    const entry = value.excludedDomains[index];
    if (typeof entry !== 'string') throw invalidWebsitePasskeySettings();
    canonical.add(canonicalizeWebsitePasskeyHostname(entry));
  }
  const excludedDomains = [...canonical].sort((left, right) => left.localeCompare(right));
  return Object.freeze({
    schemaVersion: WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION,
    enabled: value.enabled,
    excludedDomains: Object.freeze(excludedDomains),
  });
}

export function createSettingsService(store: KeyValueStore) {
  let policyOperationTail: Promise<void> = Promise.resolve();
  let websitePasskeyOperationTail: Promise<void> = Promise.resolve();

  const serializePolicyOperation = <Result>(operation: () => Promise<Result>): Promise<Result> => {
    const result = policyOperationTail.then(operation);
    policyOperationTail = result.then(() => undefined, () => undefined);
    return result;
  };

  const serializeWebsitePasskeyOperation = <Result>(operation: () => Promise<Result>): Promise<Result> => {
    const result = websitePasskeyOperationTail.then(operation);
    websitePasskeyOperationTail = result.then(() => undefined, () => undefined);
    return result;
  };

  const readWebsitePasskeySettings = async (): Promise<Readonly<WebsitePasskeySettings>> => {
    const current = await store.get<unknown>(WEBSITE_PASSKEY_SETTINGS_KEY);
    return current === undefined ? DEFAULT_WEBSITE_PASSKEY_SETTINGS : sanitizeWebsitePasskeySettings(current);
  };

  const readAutofillPolicySettings = async (): Promise<Readonly<AutofillPolicySettings>> => {
    const current = await store.get<unknown>(AUTOFILL_POLICY_SETTINGS_KEY);
    if (current !== undefined) {
      const migrated = migrateAutofillPolicySettings(current);
      if (!migrated) return sanitizeAutofillPolicySettings(current);
      await store.set(AUTOFILL_POLICY_SETTINGS_KEY, migrated);
      return migrated;
    }

    const [legacyStrategy, legacyAutofill] = await Promise.all([
      store.get<unknown>(DEFAULT_URI_MATCH_STRATEGY_KEY),
      store.get<unknown>(AUTOFILL_SETTINGS_KEY),
    ]);
    const autofill = legacyAutofill === undefined
      ? DEFAULT_AUTOFILL_SETTINGS
      : migrateLegacyAutofillSettings(legacyAutofill);
    const migrated = Object.freeze({
      schemaVersion: AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
      defaultUriMatchStrategy: isUriMatchStrategySetting(legacyStrategy)
        ? legacyStrategy
        : UriMatchStrategy.Domain,
      pageLoadFillDefault: true,
      ...autofill,
    });
    if (legacyStrategy !== undefined || legacyAutofill !== undefined) {
      await store.set(AUTOFILL_POLICY_SETTINGS_KEY, migrated);
    }
    return migrated;
  };

  const writeAutofillPolicySettings = async (value: AutofillPolicySettings): Promise<void> => {
    await store.set(AUTOFILL_POLICY_SETTINGS_KEY, sanitizeAutofillPolicySettings(value));
  };

  const service = {
    async getServerUrl(): Promise<string | undefined> {
      return store.get<string>(SERVER_URL_KEY);
    },

    async saveServerUrl(serverUrl: string): Promise<void> {
      await store.set(SERVER_URL_KEY, normalizeServerUrl(serverUrl));
    },

    async getDefaultUriMatchStrategy(): Promise<UriMatchStrategySetting> {
      return (await service.getAutofillPolicySettings()).defaultUriMatchStrategy;
    },

    async saveDefaultUriMatchStrategy(strategy: UriMatchStrategySetting): Promise<void> {
      if (!isUriMatchStrategySetting(strategy)) {
        throw new Error('unsupported URI match strategy');
      }
      await serializePolicyOperation(async () => {
        const current = await readAutofillPolicySettings();
        await writeAutofillPolicySettings({ ...current, defaultUriMatchStrategy: strategy });
      });
    },

    async getAutofillPolicySettings(): Promise<Readonly<AutofillPolicySettings>> {
      return serializePolicyOperation(readAutofillPolicySettings);
    },

    async saveAutofillPolicySettings(
      value: AutofillPolicySettings,
      assertCurrent?: () => void,
    ): Promise<void> {
      const sanitized = sanitizeAutofillPolicySettings(value);
      await serializePolicyOperation(async () => {
        if (!assertCurrent) {
          await store.set(AUTOFILL_POLICY_SETTINGS_KEY, sanitized);
          return;
        }
        const previous = await readAutofillPolicySettings();
        assertCurrent();
        try {
          await store.set(AUTOFILL_POLICY_SETTINGS_KEY, sanitized);
          assertCurrent();
        } catch (error) {
          // Keep the rollback inside this queue entry so a later settings save cannot be overwritten.
          await store.set(AUTOFILL_POLICY_SETTINGS_KEY, previous);
          throw error;
        }
      });
    },

    async getAutofillSettings(): Promise<Readonly<AutofillSettings>> {
      const current = await service.getAutofillPolicySettings();
      return Object.freeze({
        inlineSuggestions: current.inlineSuggestions,
        pageLoadFill: current.pageLoadFill,
        autoCopyTotp: current.autoCopyTotp,
        savePromptEnabled: current.savePromptEnabled,
        updatePromptEnabled: current.updatePromptEnabled,
        savePromptExcludedDomains: current.savePromptExcludedDomains,
        blockedDomains: current.blockedDomains,
      });
    },

    async saveAutofillSettings(value: AutofillSettings): Promise<void> {
      const sanitized = sanitizeAutofillSettings(value);
      await serializePolicyOperation(async () => {
        const current = await readAutofillPolicySettings();
        await writeAutofillPolicySettings({ ...current, ...sanitized });
      });
    },

    async getWebsitePasskeySettings(): Promise<Readonly<WebsitePasskeySettings>> {
      return serializeWebsitePasskeyOperation(readWebsitePasskeySettings);
    },

    async getShowMatchingLoginCount(): Promise<boolean> {
      const value = await store.get<unknown>(SHOW_MATCHING_LOGIN_COUNT_KEY);
      return typeof value === 'boolean' ? value : DEFAULT_SHOW_MATCHING_LOGIN_COUNT;
    },

    async saveShowMatchingLoginCount(value: boolean): Promise<void> {
      if (typeof value !== 'boolean') throw new Error('unsupported toolbar match-count setting');
      await store.set(SHOW_MATCHING_LOGIN_COUNT_KEY, value);
    },

    async saveWebsitePasskeySettings(value: WebsitePasskeySettings): Promise<void> {
      const sanitized = sanitizeWebsitePasskeySettings(value);
      await serializeWebsitePasskeyOperation(() => store.set(WEBSITE_PASSKEY_SETTINGS_KEY, sanitized));
    },

    async addWebsitePasskeyExcludedDomain(hostname: string): Promise<Readonly<WebsitePasskeySettings>> {
      const canonical = canonicalizeWebsitePasskeyHostname(hostname);
      return serializeWebsitePasskeyOperation(async () => {
        const current = await readWebsitePasskeySettings();
        if (current.excludedDomains.includes(canonical)) return current;
        if (current.excludedDomains.length >= MAX_WEBSITE_PASSKEY_EXCLUDED_DOMAINS) {
          throw invalidWebsitePasskeySettings();
        }
        const next = sanitizeWebsitePasskeySettings({
          ...current,
          excludedDomains: [...current.excludedDomains, canonical],
        });
        await store.set(WEBSITE_PASSKEY_SETTINGS_KEY, next);
        return next;
      });
    },

    async removeWebsitePasskeyExcludedDomain(hostname: string): Promise<Readonly<WebsitePasskeySettings>> {
      const canonical = canonicalizeWebsitePasskeyHostname(hostname);
      return serializeWebsitePasskeyOperation(async () => {
        const current = await readWebsitePasskeySettings();
        if (!current.excludedDomains.includes(canonical)) return current;
        const next = sanitizeWebsitePasskeySettings({
          ...current,
          excludedDomains: current.excludedDomains.filter((entry) => entry !== canonical),
        });
        await store.set(WEBSITE_PASSKEY_SETTINGS_KEY, next);
        return next;
      });
    },

    async getLockTimeout(): Promise<LockTimeoutSetting> {
      const value = await store.get<unknown>(LOCK_TIMEOUT_KEY);
      if (value === 'never') {
        await store.set(LOCK_TIMEOUT_KEY, 'onClose');
        return 'onClose';
      }
      return isLockTimeoutSetting(value) ? value : DEFAULT_LOCK_TIMEOUT;
    },

    async saveLockTimeout(value: LockTimeoutSetting): Promise<void> {
      if (!isSelectableLockTimeoutSetting(value)) {
        throw new Error('unsupported lock timeout');
      }
      await store.set(LOCK_TIMEOUT_KEY, value);
    },

    async getIdleMs(): Promise<number | null> {
      return lockTimeoutToIdleMs(await service.getLockTimeout());
    },

    async getOnIdleAction(): Promise<OnIdleAction> {
      const value = await store.get<unknown>(ON_IDLE_ACTION_KEY);
      return isOnIdleAction(value) ? value : DEFAULT_ON_IDLE_ACTION;
    },
    async saveOnIdleAction(value: OnIdleAction): Promise<void> {
      if (!isOnIdleAction(value)) throw new Error('unsupported idle action');
      await store.set(ON_IDLE_ACTION_KEY, value);
    },
    async getClipboardClearSetting(): Promise<ClipboardClearSetting> {
      const value = await store.get<unknown>(CLIPBOARD_CLEAR_KEY);
      return isClipboardClearSetting(value) ? value : DEFAULT_CLIPBOARD_CLEAR;
    },
    async saveClipboardClearSetting(value: ClipboardClearSetting): Promise<void> {
      if (!isClipboardClearSetting(value)) throw new Error('unsupported clipboard clear setting');
      await store.set(CLIPBOARD_CLEAR_KEY, value);
    },
    async getClipboardClearSeconds(): Promise<number | null> {
      return clipboardClearToSeconds(await service.getClipboardClearSetting());
    },
  };
  return service;
}

function invalidAutofillSettings(): Error {
  return new Error(INVALID_AUTOFILL_SETTINGS_MESSAGE);
}

function sanitizeAutofillDomainList(value: unknown, maximum: number): readonly string[] {
  if (!Array.isArray(value) || value.length > maximum) throw invalidAutofillSettings();
  for (let index = 0; index < value.length; index += 1) {
    if (!(index in value)) throw invalidAutofillSettings();
    const entry = value[index];
    if (typeof entry !== 'string' || entry.length === 0 || entry.length > MAX_BLOCKED_DOMAIN_LENGTH) {
      throw invalidAutofillSettings();
    }
  }
  const normalized = normalizeAutofillBlocklist(value);
  if (!normalized.valid) throw invalidAutofillSettings();
  return Object.freeze(normalized.rules.map((rule) => rule.pattern));
}

function migrateLegacyAutofillSettings(value: unknown): Readonly<AutofillSettings> {
  if (
    !isRecord(value)
    || !hasExactKeys(value, ['inlineSuggestions', 'pageLoadFill', 'blockedDomains'])
    || typeof value.inlineSuggestions !== 'boolean'
    || typeof value.pageLoadFill !== 'boolean'
  ) throw invalidAutofillSettings();
  return Object.freeze({
    inlineSuggestions: value.inlineSuggestions,
    pageLoadFill: value.pageLoadFill,
    autoCopyTotp: true,
    savePromptEnabled: true,
    updatePromptEnabled: true,
    savePromptExcludedDomains: Object.freeze([]),
    blockedDomains: sanitizeAutofillDomainList(value.blockedDomains, MAX_BLOCKED_DOMAINS),
  });
}

function migrateAutofillPolicySettings(value: unknown): Readonly<AutofillPolicySettings> | undefined {
  if (!isRecord(value)) return undefined;
  if (value.schemaVersion === PREVIOUS_AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION) {
    if (!hasExactKeys(value, [
      'schemaVersion',
      'defaultUriMatchStrategy',
      'inlineSuggestions',
      'pageLoadFill',
      'pageLoadFillDefault',
      'savePromptEnabled',
      'updatePromptEnabled',
      'savePromptExcludedDomains',
      'blockedDomains',
    ])) throw invalidAutofillSettings();
    return sanitizeAutofillPolicySettings({
      ...value,
      schemaVersion: AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
      autoCopyTotp: true,
    });
  }
  if (value.schemaVersion === INTERMEDIATE_AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION) {
    if (!hasExactKeys(value, [
      'schemaVersion',
      'defaultUriMatchStrategy',
      'inlineSuggestions',
      'pageLoadFill',
      'savePromptEnabled',
      'updatePromptEnabled',
      'savePromptExcludedDomains',
      'blockedDomains',
    ])) throw invalidAutofillSettings();
    return sanitizeAutofillPolicySettings({
      ...value,
      schemaVersion: AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
      pageLoadFillDefault: true,
      autoCopyTotp: true,
    });
  }
  if (value.schemaVersion !== LEGACY_AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION) return undefined;
  if (
    !hasExactKeys(value, [
      'schemaVersion',
      'defaultUriMatchStrategy',
      'inlineSuggestions',
      'pageLoadFill',
      'blockedDomains',
    ])
    || !isUriMatchStrategySetting(value.defaultUriMatchStrategy)
  ) throw invalidAutofillSettings();
  const autofill = migrateLegacyAutofillSettings({
    inlineSuggestions: value.inlineSuggestions,
    pageLoadFill: value.pageLoadFill,
    blockedDomains: value.blockedDomains,
  });
  return Object.freeze({
    schemaVersion: AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
    defaultUriMatchStrategy: value.defaultUriMatchStrategy,
    pageLoadFillDefault: true,
    ...autofill,
  });
}

function invalidWebsitePasskeySettings(): Error {
  return new Error(INVALID_WEBSITE_PASSKEY_SETTINGS_MESSAGE);
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
