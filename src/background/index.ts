import browser from 'webextension-polyfill';
import { ApiClient } from '../core/api/client.js';
import { AuthService } from '../core/session/auth-service.js';
import { SessionManager } from '../core/session/session-manager.js';
import { VaultService } from '../core/vault/vault-service.js';
import { createBrowserStore, hardenSessionAccessLevel } from '../platform/store.js';
import { createRouter } from './router.js';
import { createSettingsService } from './settings.js';
import { createIdleLock, IDLE_LOCK_ALARM } from './idle-lock.js';
import { createClipboard, CLIPBOARD_CLEAR_ALARM } from './clipboard.js';
import { createContextMenu, shouldRefreshMenu } from './context-menu.js';
import { handleFocusedFillCommand } from './commands.js';
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
const auth = new AuthService({ api, session, serverUrlProvider: () => settings.getServerUrl() });
const vault = new VaultService({ api, auth, session, localStore });
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
const idleLock = createIdleLock({
  getConfig: async () => {
    const ms = await settings.getIdleMs();
    return { idleSeconds: ms === null ? null : ms / 1000, action: await settings.getOnIdleAction() };
  },
  isUnlocked: async () => (await auth.getState()) === 'unlocked',
  lock: () => auth.lock(),
  logout: () => auth.logout(),
  queryState: (seconds) => browser.idle.queryState(seconds) as Promise<'active' | 'idle' | 'locked'>,
  setDetectionInterval: (seconds) => browser.idle.setDetectionInterval(seconds),
});

const offscreenApi = (globalThis as unknown as { chrome?: {
  offscreen?: { createDocument(o: { url: string; reasons: string[]; justification: string }): Promise<void>; closeDocument(): Promise<void> };
  runtime?: { getContexts?(o: { contextTypes: string[] }): Promise<unknown[]> };
} }).chrome;

const clipboard = createClipboard({
  getClearSeconds: () => settings.getClipboardClearSeconds(),
  createAlarm: (name, delayInMinutes) => browser.alarms.create(name, { delayInMinutes }),
  clearAlarm: (name) => { void browser.alarms.clear(name); },
  ensureOffscreen: async () => {
    const ctx = (await offscreenApi?.runtime?.getContexts?.({ contextTypes: ['OFFSCREEN_DOCUMENT'] })) ?? [];
    if (ctx.length === 0) {
      try { await offscreenApi?.offscreen?.createDocument({ url: 'offscreen.html', reasons: ['CLIPBOARD'], justification: 'Clear the clipboard after the copy auto-clear delay' }); }
      catch { /* already exists */ }
    }
  },
  sendOffscreen: (msg) => browser.runtime.sendMessage(msg),
  closeOffscreen: async () => { try { await offscreenApi?.offscreen?.closeDocument(); } catch { /* none open */ } },
});

const router = createRouter({ auth, vault, settings, clipboard: { scheduleClear: () => clipboard.scheduleClear() } });

// Pin storage.session to trusted contexts on every SW start (MV3 workers re-evaluate this file
// on each wake) and again on install. Default is already TRUSTED_CONTEXTS; this is defense-in-depth.
void hardenSessionAccessLevel().catch(() => {
  /* default is already TRUSTED_CONTEXTS; ignore if the API is unsupported */
});

void contextMenu.refresh().catch(() => {});

browser.idle.onStateChanged.addListener((state) => { void idleLock.onStateChanged(state as 'active' | 'idle' | 'locked'); });
void idleLock.applyDetection();

browser.contextMenus.onClicked.addListener((info, tab) => {
  void contextMenu.handleClick(String(info.menuItemId), tab, info.frameId);
});

browser.commands.onCommand.addListener((command, tab) => {
  void handleFocusedFillCommand(command, tab, {
    tabs: { sendMessage: (tabId, message) => browser.tabs.sendMessage(tabId, message) },
  });
});

browser.runtime.onInstalled.addListener(() => {
  browser.alarms.create(IDLE_LOCK_ALARM, { periodInMinutes: 1 });
  void hardenSessionAccessLevel().catch(() => {});
  void contextMenu.refresh().catch(() => {});
  void idleLock.applyDetection();
});

browser.runtime.onMessage.addListener((message: unknown) => {
  // Do not hijack the offscreen document's own responses.
  if (typeof message === 'object' && message !== null && typeof (message as { type?: unknown }).type === 'string'
      && (message as { type: string }).type.startsWith('offscreen.')) {
    return; // synchronous return, no Promise
  }
  return (async () => {
    const response = await router.handle(message as RequestMessage);
    const type = (message as { type?: unknown }).type;
    if (typeof type === 'string') {
      if (shouldRefreshMenu(type)) void contextMenu.refresh().catch(() => {});
      if (type === 'settings.save' || type === 'settings.saveSecurity') void idleLock.applyDetection();
    }
    return response;
  })();
});

browser.alarms.onAlarm.addListener((alarm) => {
  void (async () => {
    if (alarm.name === IDLE_LOCK_ALARM) await idleLock.onBackstopAlarm();
    else if (alarm.name === CLIPBOARD_CLEAR_ALARM) await clipboard.handleClipboardAlarm();
  })();
});
