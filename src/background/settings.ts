import type { KeyValueStore } from '../platform/store.js';
import { isUriMatchStrategySetting, UriMatchStrategy, type UriMatchStrategySetting } from '../core/vault/uri-match.js';

const SERVER_URL_KEY = 'serverUrl';
const DEFAULT_URI_MATCH_STRATEGY_KEY = 'defaultUriMatchStrategy';

export function createSettingsService(store: KeyValueStore) {
  return {
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
  };
}
