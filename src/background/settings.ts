import type { KeyValueStore } from '../platform/store.js';
import { isUriMatchStrategySetting, UriMatchStrategy, type UriMatchStrategySetting } from '../core/vault/uri-match.js';

const SERVER_URL_KEY = 'serverUrl';
const DEFAULT_URI_MATCH_STRATEGY_KEY = 'defaultUriMatchStrategy';
const LOCK_TIMEOUT_KEY = 'lockTimeout';

/** Idle auto-lock options. Minute values plus two sentinels that disable idle-locking. */
export const LOCK_TIMEOUT_VALUES = ['1', '5', '15', '30', 'onClose', 'never'] as const;
export type LockTimeoutSetting = (typeof LOCK_TIMEOUT_VALUES)[number];
export const DEFAULT_LOCK_TIMEOUT: LockTimeoutSetting = '15';

export function isLockTimeoutSetting(value: unknown): value is LockTimeoutSetting {
  return typeof value === 'string' && (LOCK_TIMEOUT_VALUES as readonly string[]).includes(value);
}

/** Idle window in ms, or null when locking is disabled ('onClose'/'never' rely on session clearing). */
export function lockTimeoutToIdleMs(value: LockTimeoutSetting): number | null {
  if (value === 'never' || value === 'onClose') return null;
  return Number(value) * 60 * 1000;
}

export function createSettingsService(store: KeyValueStore) {
  const service = {
    async getServerUrl(): Promise<string | undefined> {
      return store.get<string>(SERVER_URL_KEY);
    },

    async saveServerUrl(serverUrl: string): Promise<void> {
      const url = new URL(serverUrl);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') {
        throw new Error('serverUrl must start with http:// or https://');
      }
      await store.set(SERVER_URL_KEY, url.toString());
    },

    async getDefaultUriMatchStrategy(): Promise<UriMatchStrategySetting> {
      const value = await store.get<unknown>(DEFAULT_URI_MATCH_STRATEGY_KEY);
      return isUriMatchStrategySetting(value) ? value : UriMatchStrategy.Domain;
    },

    async saveDefaultUriMatchStrategy(strategy: UriMatchStrategySetting): Promise<void> {
      if (!isUriMatchStrategySetting(strategy)) {
        throw new Error('unsupported URI match strategy');
      }
      await store.set(DEFAULT_URI_MATCH_STRATEGY_KEY, strategy);
    },

    async getLockTimeout(): Promise<LockTimeoutSetting> {
      const value = await store.get<unknown>(LOCK_TIMEOUT_KEY);
      return isLockTimeoutSetting(value) ? value : DEFAULT_LOCK_TIMEOUT;
    },

    async saveLockTimeout(value: LockTimeoutSetting): Promise<void> {
      if (!isLockTimeoutSetting(value)) {
        throw new Error('unsupported lock timeout');
      }
      await store.set(LOCK_TIMEOUT_KEY, value);
    },

    async getIdleMs(): Promise<number | null> {
      return lockTimeoutToIdleMs(await service.getLockTimeout());
    },
  };
  return service;
}
