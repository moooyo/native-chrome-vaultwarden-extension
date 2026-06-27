import type { KeyValueStore } from '../platform/store.js';

const SERVER_URL_KEY = 'serverUrl';

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
  };
}
