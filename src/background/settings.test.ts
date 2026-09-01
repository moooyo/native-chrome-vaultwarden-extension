import { describe, it, expect, vi } from 'vitest';
import {
  AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
  clipboardClearToSeconds,
  createSettingsService,
  DEFAULT_AUTOFILL_POLICY_SETTINGS,
  DEFAULT_AUTOFILL_SETTINGS,
  DEFAULT_CLIPBOARD_CLEAR,
  DEFAULT_ON_IDLE_ACTION,
  DEFAULT_SHOW_MATCHING_LOGIN_COUNT,
  INVALID_AUTOFILL_SETTINGS_MESSAGE,
  INVALID_WEBSITE_PASSKEY_SETTINGS_MESSAGE,
  isClipboardClearSetting,
  isCanonicalLockTimeoutMinutes,
  isLockTimeoutSetting,
  isOnIdleAction,
  isSelectableLockTimeoutSetting,
  lockTimeoutToIdleMs,
  MAX_BLOCKED_DOMAIN_LENGTH,
  MAX_BLOCKED_DOMAINS,
  MAX_LOCK_TIMEOUT_MINUTES,
  MAX_SAVE_PROMPT_EXCLUDED_DOMAINS,
  MAX_WEBSITE_PASSKEY_EXCLUDED_DOMAIN_LENGTH,
  MAX_WEBSITE_PASSKEY_EXCLUDED_DOMAINS,
  normalizeServerUrl,
  canonicalizeWebsitePasskeyHostname,
  DEFAULT_WEBSITE_PASSKEY_SETTINGS,
  sanitizeWebsitePasskeySettings,
  SHOW_MATCHING_LOGIN_COUNT_KEY,
  WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION,
  type AutofillPolicySettings,
  type AutofillSettings,
  type WebsitePasskeySettings,
} from './settings.js';
import { createMemoryStore } from '../platform/store.js';
import { pageLoadAutofillAllowed } from '../core/vault/autofill-policy.js';
import { UriMatchStrategy } from '../core/vault/uri-match.js';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: {}, session: {} } },
}));

describe('settings service', () => {
  it('normalizes serverUrl and stores it', async () => {
    const settings = createSettingsService(createMemoryStore());
    await settings.saveServerUrl('https://vw.example.com/base/');
    expect(await settings.getServerUrl()).toBe('https://vw.example.com/base/');
  });

  it('rejects non-http URLs', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.saveServerUrl('file:///tmp/x')).rejects.toThrow('serverUrl must start with http:// or https://');
  });

  it('defaults URI match strategy to Domain', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.getDefaultUriMatchStrategy()).resolves.toBe(UriMatchStrategy.Domain);
  });

  it('persists a supported URI match strategy', async () => {
    const settings = createSettingsService(createMemoryStore());
    await settings.saveDefaultUriMatchStrategy(UriMatchStrategy.Host);
    await expect(settings.getDefaultUriMatchStrategy()).resolves.toBe(UriMatchStrategy.Host);
  });

  it('rejects unsupported URI match strategy values', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.saveDefaultUriMatchStrategy(6 as never)).rejects.toThrow('unsupported URI match strategy');
  });

  it('defaults lock timeout to 15 minutes', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.getLockTimeout()).resolves.toBe('15');
  });

  it('persists every built-in mode and canonical custom minutes', async () => {
    const settings = createSettingsService(createMemoryStore());
    await settings.saveLockTimeout('5');
    await expect(settings.getLockTimeout()).resolves.toBe('5');
    await settings.saveLockTimeout('immediate');
    await expect(settings.getLockTimeout()).resolves.toBe('immediate');
    await settings.saveLockTimeout('onLocked');
    await expect(settings.getLockTimeout()).resolves.toBe('onLocked');
    await settings.saveLockTimeout('onClose');
    await expect(settings.getLockTimeout()).resolves.toBe('onClose');
    await settings.saveLockTimeout('10');
    await expect(settings.getLockTimeout()).resolves.toBe('10');
    await settings.saveLockTimeout(String(MAX_LOCK_TIMEOUT_MINUTES) as `${number}`);
    await expect(settings.getLockTimeout()).resolves.toBe('43200');
  });

  it('defaults the toolbar match counter on and persists an explicit opt-out', async () => {
    const store = createMemoryStore();
    const settings = createSettingsService(store);
    await expect(settings.getShowMatchingLoginCount()).resolves.toBe(true);
    expect(DEFAULT_SHOW_MATCHING_LOGIN_COUNT).toBe(true);

    await settings.saveShowMatchingLoginCount(false);
    await expect(store.get(SHOW_MATCHING_LOGIN_COUNT_KEY)).resolves.toBe(false);
    await expect(settings.getShowMatchingLoginCount()).resolves.toBe(false);
    await expect(settings.saveShowMatchingLoginCount('false' as never))
      .rejects.toThrow('unsupported toolbar match-count setting');
  });

  it('repairs a malformed display-only toolbar counter preference to its default', async () => {
    const store = createMemoryStore();
    await store.set(SHOW_MATCHING_LOGIN_COUNT_KEY, 'not-a-boolean');
    await expect(createSettingsService(store).getShowMatchingLoginCount()).resolves.toBe(true);
  });

  it('reads legacy never but rejects it for new local saves', async () => {
    expect(isLockTimeoutSetting('never')).toBe(true);
    expect(isSelectableLockTimeoutSetting('never')).toBe(false);
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.saveLockTimeout('never')).rejects.toThrow('unsupported lock timeout');
  });

  it.each(['immediate', '1', '37', '43200', 'onLocked', 'onClose'])(
    'recognizes a selectable canonical timeout: %s',
    (value) => {
      expect(isSelectableLockTimeoutSetting(value)).toBe(true);
      expect(isLockTimeoutSetting(value)).toBe(true);
    },
  );

  it('migrates a persisted legacy never value to onClose once', async () => {
    const store = createMemoryStore();
    await store.set('lockTimeout', 'never');
    const set = vi.spyOn(store, 'set');
    const settings = createSettingsService(store);

    await expect(settings.getLockTimeout()).resolves.toBe('onClose');
    expect(set).toHaveBeenCalledWith('lockTimeout', 'onClose');
    expect(await store.get('lockTimeout')).toBe('onClose');

    set.mockClear();
    await expect(settings.getLockTimeout()).resolves.toBe('onClose');
    expect(set).not.toHaveBeenCalled();
  });

  it.each([
    '0', '00', '01', '+1', '-1', '1.0', '1e3', '', ' 1', '1 ', '43201',
  ])('rejects a non-canonical or out-of-range timeout before persistence: %j', async (value) => {
    const settings = createSettingsService(createMemoryStore());
    expect(isCanonicalLockTimeoutMinutes(value)).toBe(false);
    expect(isSelectableLockTimeoutSetting(value)).toBe(false);
    await expect(settings.saveLockTimeout(value as never)).rejects.toThrow('unsupported lock timeout');
  });

  it('rejects non-string timeout values', async () => {
    const settings = createSettingsService(createMemoryStore());
    expect(isSelectableLockTimeoutSetting(15)).toBe(false);
    await expect(settings.saveLockTimeout(15 as never)).rejects.toThrow('unsupported lock timeout');
  });

  it('maps every timeout mode to exact idle milliseconds without NaN or overflow', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.getIdleMs()).resolves.toBe(15 * 60 * 1000); // default
    await settings.saveLockTimeout('immediate');
    await expect(settings.getIdleMs()).resolves.toBe(0);
    await settings.saveLockTimeout('1');
    await expect(settings.getIdleMs()).resolves.toBe(60 * 1000);
    await settings.saveLockTimeout('37');
    await expect(settings.getIdleMs()).resolves.toBe(37 * 60 * 1000);
    await settings.saveLockTimeout('43200');
    await expect(settings.getIdleMs()).resolves.toBe(43_200 * 60 * 1000);
    await settings.saveLockTimeout('onLocked');
    await expect(settings.getIdleMs()).resolves.toBeNull();
    await settings.saveLockTimeout('onClose');
    await expect(settings.getIdleMs()).resolves.toBeNull();
    expect(lockTimeoutToIdleMs('never')).toBeNull();
    expect(() => lockTimeoutToIdleMs('1e3' as never)).toThrow('invalid lock timeout');
  });
});

describe('server URL policy', () => {
  it.each([
    ['https://vault.example.com', 'https://vault.example.com/'],
    ['https://vault.example.com/base', 'https://vault.example.com/base/'],
    ['https://vault.example.com/base/', 'https://vault.example.com/base/'],
    ['http://localhost:8080', 'http://localhost:8080/'],
    ['http://127.0.0.0:8080', 'http://127.0.0.0:8080/'],
    ['http://127.255.255.255', 'http://127.255.255.255/'],
    ['http://127.1', 'http://127.0.0.1/'],
    ['http://[::1]:8080', 'http://[::1]:8080/'],
  ])('allows %s and normalizes it', (input, expected) => {
    expect(normalizeServerUrl(input)).toBe(expected);
  });

  it.each([
    'http://vault.example.com',
    'http://192.168.1.10',
    'http://localhost.example.com',
    'http://localhost.',
    'http://127.0.0.1.example.com',
    'http://[::ffff:127.0.0.1]',
  ])('rejects non-loopback plaintext endpoint %s', (input) => {
    expect(() => normalizeServerUrl(input)).toThrow(
      'serverUrl must use https:// unless it targets a loopback host',
    );
  });

  it.each([
    'https://user@vault.example.com',
    'https://user:password@vault.example.com',
    'http://localhost@evil.example.com',
    'http://user:password@127.0.0.1',
  ])('rejects URLs containing userinfo: %s', (input) => {
    expect(() => normalizeServerUrl(input)).toThrow('serverUrl must not include credentials');
  });

  it.each([
    'https://vault.example.com/base?tenant=one',
    'https://vault.example.com/base#settings',
    'https://vault.example.com/base?',
    'https://vault.example.com/base#',
  ])('rejects URLs containing a query or fragment: %s', (input) => {
    expect(() => normalizeServerUrl(input)).toThrow('serverUrl must not include query or fragment');
  });

  it.each([
    'file:///tmp/vault',
    'ftp://vault.example.com',
    'ws://vault.example.com',
    'javascript:alert(1)',
  ])('rejects non-HTTP(S) scheme: %s', (input) => {
    expect(() => normalizeServerUrl(input)).toThrow('serverUrl must start with http:// or https://');
  });

  it('does not persist a rejected remote HTTP endpoint', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.saveServerUrl('http://vault.example.com')).rejects.toThrow();
    await expect(settings.getServerUrl()).resolves.toBeUndefined();
  });
});

describe('autofill settings', () => {
  it('uses conservative feature defaults only when no stored record exists', async () => {
    const settings = createSettingsService(createMemoryStore());

    await expect(settings.getAutofillSettings()).resolves.toEqual({
      inlineSuggestions: true,
      pageLoadFill: false,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: [],
      blockedDomains: [],
    });
    expect(DEFAULT_AUTOFILL_SETTINGS.inlineSuggestions).toBe(true);
    expect(DEFAULT_AUTOFILL_SETTINGS.pageLoadFill).toBe(false);
  });

  it('atomically persists a complete record and canonicalizes blocked domains', async () => {
    const settings = createSettingsService(createMemoryStore());
    await settings.saveAutofillSettings({
      ...DEFAULT_AUTOFILL_SETTINGS,
      inlineSuggestions: false,
      pageLoadFill: true,
      updatePromptEnabled: false,
      savePromptExcludedDomains: [' Never.Example.COM. '],
      blockedDomains: [
        ' Accounts.Example.COM. ',
        'accounts.example.com',
        'HTTPS://Login.Example.COM:443/',
      ],
    });

    await expect(settings.getAutofillSettings()).resolves.toEqual({
      inlineSuggestions: false,
      pageLoadFill: true,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: false,
      savePromptExcludedDomains: ['never.example.com'],
      blockedDomains: ['accounts.example.com', 'https://login.example.com'],
    });
  });

  it.each([
    ['null record', null],
    ['missing field', { inlineSuggestions: true, pageLoadFill: false }],
    ['invalid inlineSuggestions', { inlineSuggestions: 1, pageLoadFill: false, blockedDomains: [] }],
    ['invalid pageLoadFill', { inlineSuggestions: true, pageLoadFill: 'yes', blockedDomains: [] }],
    ['non-array blocklist', { inlineSuggestions: true, pageLoadFill: false, blockedDomains: 'example.com' }],
    ['non-string entry', { inlineSuggestions: true, pageLoadFill: false, blockedDomains: [42] }],
    ['empty entry', { inlineSuggestions: true, pageLoadFill: false, blockedDomains: [''] }],
    ['invalid domain entry', { inlineSuggestions: true, pageLoadFill: false, blockedDomains: ['example.com/path'] }],
    ['object policy entry', { inlineSuggestions: true, pageLoadFill: false, blockedDomains: [{ pattern: 'example.com' }] }],
    ['oversized entry', { inlineSuggestions: true, pageLoadFill: false, blockedDomains: ['a'.repeat(MAX_BLOCKED_DOMAIN_LENGTH + 1)] }],
    ['oversized list', { inlineSuggestions: true, pageLoadFill: false, blockedDomains: Array.from({ length: MAX_BLOCKED_DOMAINS + 1 }, (_, index) => `host-${index}.example`) }],
  ])('fails closed for an existing malformed whole record: %s', async (_label, stored) => {
    const store = createMemoryStore();
    await store.set('autofillSettings', stored);
    const settings = createSettingsService(store);

    await expect(settings.getAutofillSettings()).rejects.toThrow(INVALID_AUTOFILL_SETTINGS_MESSAGE);
  });

  it('rejects sparse blocked-domain arrays instead of partially accepting them', async () => {
    const store = createMemoryStore();
    const blockedDomains = Array<string>(1);
    await store.set('autofillSettings', {
      inlineSuggestions: true,
      pageLoadFill: false,
      blockedDomains,
    });

    await expect(createSettingsService(store).getAutofillSettings())
      .rejects.toThrow(INVALID_AUTOFILL_SETTINGS_MESSAGE);
  });

  it('validates the entire update before preserving or replacing the prior record', async () => {
    const settings = createSettingsService(createMemoryStore());
    const original: AutofillSettings = {
      ...DEFAULT_AUTOFILL_SETTINGS,
      inlineSuggestions: false,
      pageLoadFill: false,
      blockedDomains: ['original.example'],
    };
    await settings.saveAutofillSettings(original);

    await expect(settings.saveAutofillSettings({
      ...DEFAULT_AUTOFILL_SETTINGS,
      inlineSuggestions: true,
      pageLoadFill: true,
      blockedDomains: ['valid.example', 'not a domain'],
    })).rejects.toThrow(INVALID_AUTOFILL_SETTINGS_MESSAGE);
    await expect(settings.getAutofillSettings()).resolves.toEqual(original);
  });

  it('accepts the maximum number of valid blocked domains', async () => {
    const settings = createSettingsService(createMemoryStore());
    const blockedDomains = Array.from(
      { length: MAX_BLOCKED_DOMAINS },
      (_, index) => `host-${index}.example`,
    );

    await settings.saveAutofillSettings({ ...DEFAULT_AUTOFILL_SETTINGS, blockedDomains });
    await expect(settings.getAutofillSettings()).resolves.toMatchObject({
      blockedDomains: [...blockedDomains].sort(),
    });
  });

  it('strictly validates the save-prompt settings as part of one atomic record', async () => {
    const settings = createSettingsService(createMemoryStore());

    await expect(settings.saveAutofillSettings({
      ...DEFAULT_AUTOFILL_SETTINGS,
      savePromptEnabled: 'yes',
    } as unknown as AutofillSettings)).rejects.toThrow(INVALID_AUTOFILL_SETTINGS_MESSAGE);
    await expect(settings.saveAutofillSettings({
      ...DEFAULT_AUTOFILL_SETTINGS,
      savePromptExcludedDomains: ['https://example.com/path'],
    })).rejects.toThrow(INVALID_AUTOFILL_SETTINGS_MESSAGE);
    await expect(settings.saveAutofillSettings({
      ...DEFAULT_AUTOFILL_SETTINGS,
      unexpected: true,
    } as unknown as AutofillSettings)).rejects.toThrow(INVALID_AUTOFILL_SETTINGS_MESSAGE);
    await expect(settings.getAutofillSettings()).resolves.toEqual(DEFAULT_AUTOFILL_SETTINGS);
  });

  it('rejects oversized and sparse save-prompt exclusion lists', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.saveAutofillSettings({
      ...DEFAULT_AUTOFILL_SETTINGS,
      savePromptExcludedDomains: Array.from(
        { length: MAX_SAVE_PROMPT_EXCLUDED_DOMAINS + 1 },
        (_, index) => `never-${index}.example`,
      ),
    })).rejects.toThrow(INVALID_AUTOFILL_SETTINGS_MESSAGE);

    const sparse = Array<string>(1);
    await expect(settings.saveAutofillSettings({
      ...DEFAULT_AUTOFILL_SETTINGS,
      savePromptExcludedDomains: sparse,
    })).rejects.toThrow(INVALID_AUTOFILL_SETTINGS_MESSAGE);
  });
});

describe('combined autofill policy settings', () => {
  const combined = (overrides: Partial<AutofillPolicySettings> = {}): AutofillPolicySettings => ({
    schemaVersion: AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
    defaultUriMatchStrategy: UriMatchStrategy.Host,
    pageLoadFillDefault: true,
    ...DEFAULT_AUTOFILL_SETTINGS,
    inlineSuggestions: false,
    pageLoadFill: true,
    blockedDomains: ['blocked.example'],
    ...overrides,
  });

  it('returns the versioned combined defaults when neither current nor legacy keys exist', async () => {
    const settings = createSettingsService(createMemoryStore());

    await expect(settings.getAutofillPolicySettings()).resolves.toEqual({
      schemaVersion: 4,
      defaultUriMatchStrategy: UriMatchStrategy.Domain,
      pageLoadFillDefault: true,
      inlineSuggestions: true,
      pageLoadFill: false,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: [],
      blockedDomains: [],
    });
    expect(DEFAULT_AUTOFILL_POLICY_SETTINGS.schemaVersion).toBe(4);
    expect(DEFAULT_AUTOFILL_POLICY_SETTINGS.pageLoadFillDefault).toBe(true);
  });

  it('reads an existing current record with exactly one storage get', async () => {
    const store = createMemoryStore();
    await store.set('autofillPolicySettings', combined());
    await store.set('defaultUriMatchStrategy', 'corrupt legacy value');
    await store.set('autofillSettings', null);
    const get = vi.spyOn(store, 'get');

    await expect(createSettingsService(store).getAutofillPolicySettings()).resolves.toEqual(combined());
    expect(get).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledWith('autofillPolicySettings');
  });

  it.each([
    ['missing schema', { ...combined(), schemaVersion: undefined }],
    ['future schema', { ...combined(), schemaVersion: 5 }],
    ['invalid strategy', { ...combined(), defaultUriMatchStrategy: 99 }],
    ['missing feature flag', { ...combined(), inlineSuggestions: undefined }],
    ['invalid page-load default', { ...combined(), pageLoadFillDefault: 'yes' }],
    ['invalid save prompt flag', { ...combined(), savePromptEnabled: 'yes' }],
    ['invalid update prompt flag', { ...combined(), updatePromptEnabled: null }],
    ['malformed save exclusions', { ...combined(), savePromptExcludedDomains: ['example.com/path'] }],
    ['extra field', { ...combined(), unexpected: true }],
    ['malformed domains', { ...combined(), blockedDomains: ['valid.example', 'not a domain'] }],
  ])('rejects a malformed current whole record: %s', async (_label, stored) => {
    const store = createMemoryStore();
    await store.set('autofillPolicySettings', stored);

    await expect(createSettingsService(store).getAutofillPolicySettings())
      .rejects.toThrow(INVALID_AUTOFILL_SETTINGS_MESSAGE);
  });

  it('migrates both legacy keys into one current record', async () => {
    const store = createMemoryStore();
    await store.set('defaultUriMatchStrategy', UriMatchStrategy.Exact);
    await store.set('autofillSettings', {
      inlineSuggestions: false,
      pageLoadFill: true,
      blockedDomains: ['Legacy.Example.COM.'],
    });
    const set = vi.spyOn(store, 'set');

    await expect(createSettingsService(store).getAutofillPolicySettings()).resolves.toEqual({
      schemaVersion: 4,
      defaultUriMatchStrategy: UriMatchStrategy.Exact,
      pageLoadFillDefault: true,
      inlineSuggestions: false,
      pageLoadFill: true,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: [],
      blockedDomains: ['legacy.example.com'],
    });
    expect(set).toHaveBeenCalledOnce();
    expect(set).toHaveBeenCalledWith('autofillPolicySettings', {
      schemaVersion: 4,
      defaultUriMatchStrategy: UriMatchStrategy.Exact,
      pageLoadFillDefault: true,
      inlineSuggestions: false,
      pageLoadFill: true,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: [],
      blockedDomains: ['legacy.example.com'],
    });
  });

  it('strictly migrates a schema-v1 combined record and persists the current snapshot', async () => {
    const store = createMemoryStore();
    await store.set('autofillPolicySettings', {
      schemaVersion: 1,
      defaultUriMatchStrategy: UriMatchStrategy.Host,
      inlineSuggestions: false,
      pageLoadFill: true,
      blockedDomains: ['Legacy.Example'],
    });
    const set = vi.spyOn(store, 'set');

    await expect(createSettingsService(store).getAutofillPolicySettings()).resolves.toEqual({
      schemaVersion: 4,
      defaultUriMatchStrategy: UriMatchStrategy.Host,
      pageLoadFillDefault: true,
      inlineSuggestions: false,
      pageLoadFill: true,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: [],
      blockedDomains: ['legacy.example'],
    });
    expect(set).toHaveBeenCalledOnce();
    expect(set.mock.calls[0]?.[1]).toMatchObject({
      schemaVersion: 4,
      pageLoadFillDefault: true,
      autoCopyTotp: true,
    });
  });

  it('rejects rather than partially migrating a schema-v1 record with unknown fields', async () => {
    const store = createMemoryStore();
    await store.set('autofillPolicySettings', {
      schemaVersion: 1,
      defaultUriMatchStrategy: UriMatchStrategy.Domain,
      inlineSuggestions: true,
      pageLoadFill: false,
      blockedDomains: [],
      savePromptEnabled: true,
    });

    await expect(createSettingsService(store).getAutofillPolicySettings())
      .rejects.toThrow(INVALID_AUTOFILL_SETTINGS_MESSAGE);
  });

  it('migrates every old disabled representation with a true item fallback that survives re-enable', async () => {
    const oldRecords: Array<readonly [string, (store: ReturnType<typeof createMemoryStore>) => Promise<void>]> = [
      ['split legacy keys', async (store) => {
        await store.set('autofillSettings', {
          inlineSuggestions: true,
          pageLoadFill: false,
          blockedDomains: [],
        });
      }],
      ['schema v1', async (store) => {
        await store.set('autofillPolicySettings', {
          schemaVersion: 1,
          defaultUriMatchStrategy: UriMatchStrategy.Domain,
          inlineSuggestions: true,
          pageLoadFill: false,
          blockedDomains: [],
        });
      }],
      ['schema v2', async (store) => {
        await store.set('autofillPolicySettings', {
          schemaVersion: 2,
          defaultUriMatchStrategy: UriMatchStrategy.Domain,
          inlineSuggestions: true,
          pageLoadFill: false,
          savePromptEnabled: true,
          updatePromptEnabled: true,
          savePromptExcludedDomains: [],
          blockedDomains: [],
        });
      }],
    ];

    for (const [label, seed] of oldRecords) {
      const store = createMemoryStore();
      await seed(store);
      const settings = createSettingsService(store);
      await expect(settings.getAutofillPolicySettings(), label).resolves.toMatchObject({
        schemaVersion: 4,
        pageLoadFill: false,
        pageLoadFillDefault: true,
      });
      await settings.saveAutofillSettings({
        ...DEFAULT_AUTOFILL_SETTINGS,
        pageLoadFill: true,
      });
      const reenabled = await settings.getAutofillPolicySettings();
      expect(reenabled, label).toMatchObject({
        pageLoadFill: true,
        pageLoadFillDefault: true,
      });
      expect(pageLoadAutofillAllowed(null, reenabled.pageLoadFillDefault), label).toBe(true);
      expect(pageLoadAutofillAllowed(undefined, reenabled.pageLoadFillDefault), label).toBe(true);
    }
  });

  it('uses the legacy URI default while still failing closed on malformed legacy autofill data', async () => {
    const invalidStrategyStore = createMemoryStore();
    await invalidStrategyStore.set('defaultUriMatchStrategy', 99);
    await expect(createSettingsService(invalidStrategyStore).getAutofillPolicySettings())
      .resolves.toEqual(DEFAULT_AUTOFILL_POLICY_SETTINGS);

    const invalidAutofillStore = createMemoryStore();
    await invalidAutofillStore.set('autofillSettings', { inlineSuggestions: true });
    await expect(createSettingsService(invalidAutofillStore).getAutofillPolicySettings())
      .rejects.toThrow(INVALID_AUTOFILL_SETTINGS_MESSAGE);
  });

  it('writes a fully validated current record with one set and no read', async () => {
    const store = createMemoryStore();
    const get = vi.spyOn(store, 'get');
    const set = vi.spyOn(store, 'set');
    const settings = createSettingsService(store);

    await settings.saveAutofillPolicySettings(combined({
      blockedDomains: ['HTTPS://Blocked.Example:443/', 'blocked.example'],
    }));

    expect(get).not.toHaveBeenCalled();
    expect(set).toHaveBeenCalledTimes(1);
    expect(set).toHaveBeenCalledWith('autofillPolicySettings', {
      schemaVersion: 4,
      defaultUriMatchStrategy: UriMatchStrategy.Host,
      pageLoadFillDefault: true,
      inlineSuggestions: false,
      pageLoadFill: true,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: [],
      blockedDomains: ['blocked.example', 'https://blocked.example'],
    });
  });

  it('migrates legacy state before applying a proxy save', async () => {
    const store = createMemoryStore();
    await store.set('defaultUriMatchStrategy', UriMatchStrategy.StartsWith);
    await store.set('autofillSettings', {
      inlineSuggestions: false,
      pageLoadFill: true,
      blockedDomains: ['legacy.example'],
    });
    const set = vi.spyOn(store, 'set');
    const settings = createSettingsService(store);

    await settings.saveDefaultUriMatchStrategy(UriMatchStrategy.Exact);

    expect(set).toHaveBeenCalledTimes(2);
    expect(set).toHaveBeenLastCalledWith('autofillPolicySettings', {
      schemaVersion: 4,
      defaultUriMatchStrategy: UriMatchStrategy.Exact,
      pageLoadFillDefault: true,
      inlineSuggestions: false,
      pageLoadFill: true,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: [],
      blockedDomains: ['legacy.example'],
    });
  });

  it('serializes legacy proxy updates so concurrent saves preserve both fields', async () => {
    const settings = createSettingsService(createMemoryStore());
    await settings.saveAutofillPolicySettings(combined({
      defaultUriMatchStrategy: UriMatchStrategy.Domain,
      inlineSuggestions: true,
      pageLoadFill: false,
      blockedDomains: [],
    }));

    await Promise.all([
      settings.saveDefaultUriMatchStrategy(UriMatchStrategy.Exact),
      settings.saveAutofillSettings({
        ...DEFAULT_AUTOFILL_SETTINGS,
        inlineSuggestions: false,
        pageLoadFill: true,
        blockedDomains: ['concurrent.example'],
      }),
    ]);

    await expect(settings.getAutofillPolicySettings()).resolves.toEqual(combined({
      defaultUriMatchStrategy: UriMatchStrategy.Exact,
      blockedDomains: ['concurrent.example'],
    }));
  });

  it('never exposes a mixed policy generation while the single-record write is paused', async () => {
    const backing = createMemoryStore();
    const oldPolicy = combined({
      defaultUriMatchStrategy: UriMatchStrategy.Domain,
      inlineSuggestions: true,
      pageLoadFill: false,
      blockedDomains: ['old.example'],
    });
    await backing.set('autofillPolicySettings', oldPolicy);
    let markWriteStarted!: () => void;
    const writeStarted = new Promise<void>((resolve) => { markWriteStarted = resolve; });
    let releaseWrite!: () => void;
    const writeGate = new Promise<void>((resolve) => { releaseWrite = resolve; });
    const store = {
      get: <T>(key: string) => backing.get<T>(key),
      set: async (key: string, value: unknown) => {
        if (key === 'autofillPolicySettings') {
          markWriteStarted();
          await writeGate;
        }
        await backing.set(key, value);
      },
      remove: (key: string) => backing.remove(key),
      clear: () => backing.clear(),
    };
    const settings = createSettingsService(store);
    await expect(settings.getAutofillPolicySettings()).resolves.toEqual(oldPolicy);

    const newPolicy = combined({
      defaultUriMatchStrategy: UriMatchStrategy.Exact,
      inlineSuggestions: false,
      pageLoadFill: true,
      blockedDomains: ['new.example'],
    });
    const pendingSave = settings.saveAutofillPolicySettings(newPolicy);
    await writeStarted;
    let readSettled = false;
    const pendingRead = settings.getAutofillPolicySettings().then((value) => {
      readSettled = true;
      return value;
    });
    await Promise.resolve();
    expect(readSettled).toBe(false);

    releaseWrite();
    await pendingSave;
    await expect(pendingRead).resolves.toEqual(newPolicy);
  });

  it('rolls back a guarded autofill policy write before releasing the settings queue', async () => {
    const backing = createMemoryStore();
    const oldPolicy = combined({
      pageLoadFill: false,
      pageLoadFillDefault: true,
      blockedDomains: ['old.example'],
    });
    await backing.set('autofillPolicySettings', oldPolicy);
    const settings = createSettingsService(backing);
    const nextPolicy = combined({
      pageLoadFill: true,
      pageLoadFillDefault: false,
      blockedDomains: ['new.example'],
    });
    let checks = 0;

    await expect(settings.saveAutofillPolicySettings(nextPolicy, () => {
      checks += 1;
      if (checks === 2) throw new Error('enterprise policy changed');
    })).rejects.toThrow('enterprise policy changed');

    expect(checks).toBe(2);
    await expect(settings.getAutofillPolicySettings()).resolves.toEqual(oldPolicy);
  });
});

describe('website passkey settings', () => {
  const record = (overrides: Partial<WebsitePasskeySettings> = {}): WebsitePasskeySettings => ({
    schemaVersion: WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION,
    enabled: true,
    excludedDomains: [],
    ...overrides,
  });

  it('uses a frozen, disabled-by-default record when the dedicated key is absent', async () => {
    const settings = createSettingsService(createMemoryStore());

    const loaded = await settings.getWebsitePasskeySettings();
    expect(loaded).toEqual({ schemaVersion: 1, enabled: false, excludedDomains: [] });
    expect(loaded).toBe(DEFAULT_WEBSITE_PASSKEY_SETTINGS);
    expect(Object.isFrozen(loaded)).toBe(true);
    expect(Object.isFrozen(loaded.excludedDomains)).toBe(true);
  });

  it('canonicalizes exact hostnames with URL host parsing and deterministic ordering', async () => {
    const settings = createSettingsService(createMemoryStore());
    await settings.saveWebsitePasskeySettings(record({
      excludedDomains: ['BÜCHER.Example', 'accounts.EXAMPLE.com.', 'bücher.example', '127.1', '::1'],
    }));

    await expect(settings.getWebsitePasskeySettings()).resolves.toEqual(record({
      excludedDomains: ['[::1]', '127.0.0.1', 'accounts.example.com', 'xn--bcher-kva.example'],
    }));
    expect(canonicalizeWebsitePasskeyHostname('BÜCHER.Example')).toBe('xn--bcher-kva.example');
  });

  it.each([
    ['HTTP URL', 'https://example.com'],
    ['non-HTTP URL', 'ftp://example.com'],
    ['userinfo', 'user@example.com'],
    ['port', 'example.com:8443'],
    ['path', 'example.com/login'],
    ['query', 'example.com?tenant=one'],
    ['fragment', 'example.com#login'],
    ['control character', 'example.com\n'],
    ['whitespace', ' example.com'],
    ['invalid DNS label', 'bad_label.example'],
    ['oversized hostname', 'a'.repeat(MAX_WEBSITE_PASSKEY_EXCLUDED_DOMAIN_LENGTH + 1)],
  ])('rejects %s exclusion input', (_label, input) => {
    expect(() => canonicalizeWebsitePasskeyHostname(input)).toThrow(
      INVALID_WEBSITE_PASSKEY_SETTINGS_MESSAGE,
    );
  });

  it.each([
    ['null', null],
    ['array', []],
    ['missing schema', { enabled: true, excludedDomains: [] }],
    ['future schema', { schemaVersion: 2, enabled: true, excludedDomains: [] }],
    ['missing enabled', { schemaVersion: 1, excludedDomains: [] }],
    ['invalid enabled', { schemaVersion: 1, enabled: 'yes', excludedDomains: [] }],
    ['missing exclusions', { schemaVersion: 1, enabled: true }],
    ['non-array exclusions', { schemaVersion: 1, enabled: true, excludedDomains: 'example.com' }],
    ['non-string exclusion', { schemaVersion: 1, enabled: true, excludedDomains: [42] }],
    ['URL exclusion', { schemaVersion: 1, enabled: true, excludedDomains: ['https://example.com'] }],
    ['extra property', { schemaVersion: 1, enabled: true, excludedDomains: [], futureFlag: true }],
    ['too many exclusions', {
      schemaVersion: 1,
      enabled: true,
      excludedDomains: Array.from(
        { length: MAX_WEBSITE_PASSKEY_EXCLUDED_DOMAINS + 1 },
        (_, index) => `host-${index}.example`,
      ),
    }],
  ])('rejects a non-exact or corrupt whole record: %s', (_label, value) => {
    expect(() => sanitizeWebsitePasskeySettings(value)).toThrow(
      INVALID_WEBSITE_PASSKEY_SETTINGS_MESSAGE,
    );
  });

  it('rejects sparse exclusion arrays', () => {
    const excludedDomains = Array<string>(1);
    expect(() => sanitizeWebsitePasskeySettings(record({ excludedDomains }))).toThrow(
      INVALID_WEBSITE_PASSKEY_SETTINGS_MESSAGE,
    );
  });

  it('fails closed on a corrupt persisted record instead of falling back to enabled defaults', async () => {
    const store = createMemoryStore();
    await store.set('websitePasskeySettings', { schemaVersion: 1, enabled: true });

    await expect(createSettingsService(store).getWebsitePasskeySettings()).rejects.toThrow(
      INVALID_WEBSITE_PASSKEY_SETTINGS_MESSAGE,
    );
  });

  it('adds and removes canonical hosts idempotently without touching autofill policy storage', async () => {
    const store = createMemoryStore();
    const set = vi.spyOn(store, 'set');
    const settings = createSettingsService(store);
    await settings.saveWebsitePasskeySettings(record());
    set.mockClear();

    await settings.addWebsitePasskeyExcludedDomain('BÜCHER.Example');
    await settings.addWebsitePasskeyExcludedDomain('xn--bcher-kva.example');
    await settings.removeWebsitePasskeyExcludedDomain('missing.example');
    await settings.removeWebsitePasskeyExcludedDomain('BÜCHER.Example');
    await settings.removeWebsitePasskeyExcludedDomain('xn--bcher-kva.example');

    expect(set).toHaveBeenCalledTimes(2);
    expect(set.mock.calls.every(([key]) => key === 'websitePasskeySettings')).toBe(true);
    await expect(settings.getWebsitePasskeySettings()).resolves.toEqual(record());
  });

  it('serializes concurrent exclusion updates independently from autofill policy writes', async () => {
    const store = createMemoryStore();
    const settings = createSettingsService(store);
    await settings.saveWebsitePasskeySettings(record());

    await Promise.all([
      settings.addWebsitePasskeyExcludedDomain('one.example'),
      settings.addWebsitePasskeyExcludedDomain('two.example'),
      settings.saveAutofillSettings({
        ...DEFAULT_AUTOFILL_SETTINGS,
        inlineSuggestions: false,
        pageLoadFill: false,
        blockedDomains: ['autofill.example'],
      }),
    ]);

    await expect(settings.getWebsitePasskeySettings()).resolves.toEqual(record({
      excludedDomains: ['one.example', 'two.example'],
    }));
    await expect(settings.getAutofillSettings()).resolves.toMatchObject({
      blockedDomains: ['autofill.example'],
    });
  });

  it('accepts the bounded maximum exclusion count and preserves the old record on invalid save', async () => {
    const store = createMemoryStore();
    const settings = createSettingsService(store);
    const excludedDomains = Array.from(
      { length: MAX_WEBSITE_PASSKEY_EXCLUDED_DOMAINS },
      (_, index) => `host-${index}.example`,
    );
    await settings.saveWebsitePasskeySettings(record({ excludedDomains }));
    await expect(settings.getWebsitePasskeySettings()).resolves.toMatchObject({
      enabled: true,
      excludedDomains: [...excludedDomains].sort((left, right) => left.localeCompare(right)),
    });

    await expect(settings.saveWebsitePasskeySettings({
      ...record(),
      excludedDomains: ['https://not-a-host.example'],
    })).rejects.toThrow(INVALID_WEBSITE_PASSKEY_SETTINGS_MESSAGE);
    await expect(settings.getWebsitePasskeySettings()).resolves.toMatchObject({
      excludedDomains: [...excludedDomains].sort((left, right) => left.localeCompare(right)),
    });
  });
});

describe('onIdleAction setting', () => {
  it('defaults to lock and round-trips lock/logout', async () => {
    const s = createSettingsService(createMemoryStore());
    expect(await s.getOnIdleAction()).toBe(DEFAULT_ON_IDLE_ACTION);
    expect(DEFAULT_ON_IDLE_ACTION).toBe('lock');
    await s.saveOnIdleAction('logout');
    expect(await s.getOnIdleAction()).toBe('logout');
  });
  it('rejects an unknown action and falls back on a corrupt stored value', async () => {
    const s = createSettingsService(createMemoryStore());
    await expect(s.saveOnIdleAction('sleep' as never)).rejects.toThrow();
    expect(isOnIdleAction('lock')).toBe(true);
    expect(isOnIdleAction('nope')).toBe(false);
  });
});

describe('clipboardClearSeconds setting', () => {
  it('defaults to 60 and round-trips values', async () => {
    const s = createSettingsService(createMemoryStore());
    expect(await s.getClipboardClearSetting()).toBe(DEFAULT_CLIPBOARD_CLEAR);
    expect(DEFAULT_CLIPBOARD_CLEAR).toBe('60');
    await s.saveClipboardClearSetting('never');
    expect(await s.getClipboardClearSetting()).toBe('never');
    expect(await s.getClipboardClearSeconds()).toBeNull();
    await s.saveClipboardClearSetting('120');
    expect(await s.getClipboardClearSeconds()).toBe(120);
  });
  it('validates values and maps never to null', () => {
    expect(isClipboardClearSetting('30')).toBe(true);
    expect(isClipboardClearSetting('15')).toBe(false);
    expect(clipboardClearToSeconds('never')).toBeNull();
    expect(clipboardClearToSeconds('300')).toBe(300);
  });
});
