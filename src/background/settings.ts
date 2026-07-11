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

export function normalizeServerUrl(serverUrl: string): string {
  const url = new URL(serverUrl);
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('serverUrl must start with http:// or https://');
  }
  return url.toString();
}

export function createSettingsService(store: KeyValueStore) {
  const service = {
    async getServerUrl(): Promise<string | undefined> {
      return store.get<string>(SERVER_URL_KEY);
    },

    async saveServerUrl(serverUrl: string): Promise<void> {
      await store.set(SERVER_URL_KEY, normalizeServerUrl(serverUrl));
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
