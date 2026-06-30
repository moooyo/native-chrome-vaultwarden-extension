import browser from 'webextension-polyfill';
import { ApiClient } from '../core/api/client.js';
import { AuthService } from '../core/session/auth-service.js';
import { SessionManager } from '../core/session/session-manager.js';
import { VaultService } from '../core/vault/vault-service.js';
import { createBrowserStore, hardenSessionAccessLevel } from '../platform/store.js';
import { createRouter } from './router.js';
import { createSettingsService } from './settings.js';
import { createAlarmHandlers, IDLE_LOCK_ALARM } from './alarms.js';
import { createContextMenu, shouldRefreshMenu } from './context-menu.js';
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
const contextMenu = createContextMenu({
  getState: () => auth.getState(),
  findFillItems: (kind) => vault.findFillItems(kind),
  getFillData: (cipherId, kind) => vault.getFillData(cipherId, kind),
  menus: {
    removeAll: () => browser.contextMenus.removeAll(),
    create: (props) => { browser.contextMenus.create(props as Parameters<typeof browser.contextMenus.create>[0]); },
  },
  tabs: {
    sendMessage: (tabId, message, options) => browser.tabs.sendMessage(tabId, message, options),
  },
});
const alarms = createAlarmHandlers({
  auth,
  getIdleMs: () => settings.getIdleMs(),
  now: () => Date.now(),
  getLastActivity: () => sessionStore.get<number>('lastActivity'),
  setLastActivity: (n) => sessionStore.set('lastActivity', n),
});

// Pin storage.session to trusted contexts on every SW start (MV3 workers re-evaluate this file
// on each wake) and again on install. Default is already TRUSTED_CONTEXTS; this is defense-in-depth.
void hardenSessionAccessLevel().catch(() => {
  /* default is already TRUSTED_CONTEXTS; ignore if the API is unsupported */
});

void contextMenu.refresh().catch(() => {});

browser.contextMenus.onClicked.addListener((info, tab) => {
  void contextMenu.handleClick(String(info.menuItemId), tab, info.frameId);
});

browser.runtime.onInstalled.addListener(() => {
  browser.alarms.create(IDLE_LOCK_ALARM, { periodInMinutes: 1 });
  void hardenSessionAccessLevel().catch(() => {});
  void contextMenu.refresh().catch(() => {});
});

browser.runtime.onMessage.addListener(async (message: unknown) => {
  await alarms.touch();
  const response = await router.handle(message as RequestMessage);
  if (typeof message === 'object' && message !== null && typeof (message as { type?: unknown }).type === 'string'
      && shouldRefreshMenu((message as { type: string }).type)) {
    void contextMenu.refresh().catch(() => {});
  }
  return response;
});

browser.alarms.onAlarm.addListener((alarm) => {
  void (async () => {
    const locked = await alarms.handleAlarm(alarm.name);
    if (locked) void contextMenu.refresh().catch(() => {});
  })();
});
