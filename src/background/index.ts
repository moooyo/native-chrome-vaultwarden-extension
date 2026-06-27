import browser from 'webextension-polyfill';
import { ApiClient } from '../core/api/client.js';
import { AuthService } from '../core/session/auth-service.js';
import { SessionManager } from '../core/session/session-manager.js';
import { VaultService } from '../core/vault/vault-service.js';
import { createBrowserStore } from '../platform/store.js';
import { createRouter } from './router.js';
import { createSettingsService } from './settings.js';
import { createAlarmHandlers, IDLE_LOCK_ALARM } from './alarms.js';
import type { RequestMessage } from '../messaging/protocol.js';

const localStore = createBrowserStore('local');
const sessionStore = createBrowserStore('session');
const settings = createSettingsService(localStore);
const session = new SessionManager({ localStore, sessionStore });
const api = new ApiClient({
  serverUrlProvider: async () => {
    const serverUrl = await settings.getServerUrl();
    if (!serverUrl) throw new Error('serverUrl is not configured');
    return serverUrl;
  },
  localStore,
});
const auth = new AuthService({ api, session });
const vault = new VaultService({ api, auth, session, localStore });
const router = createRouter({ auth, vault, settings });
const alarms = createAlarmHandlers({
  auth,
  idleMs: 15 * 60 * 1000,
  now: () => Date.now(),
  getLastActivity: () => sessionStore.get<number>('lastActivity'),
  setLastActivity: (n) => sessionStore.set('lastActivity', n),
});

browser.runtime.onInstalled.addListener(() => {
  browser.alarms.create(IDLE_LOCK_ALARM, { periodInMinutes: 1 });
});

browser.runtime.onMessage.addListener(async (message: unknown) => {
  await alarms.touch();
  return router.handle(message as RequestMessage);
});

browser.alarms.onAlarm.addListener((alarm) => {
  void alarms.handleAlarm(alarm.name);
});
