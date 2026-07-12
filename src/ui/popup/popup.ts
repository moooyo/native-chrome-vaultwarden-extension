// Popup entry: a thin dependency adapter that mounts the Lit popup root and injects the real
// worker-request channel and the browser seam. All UI, state, and routing live in `VwPopupApp`.
import browser from 'webextension-polyfill';
import { sendRequest } from '../../messaging/protocol.js';
import { VwPopupApp } from './app.js';

const app = document.createElement('vw-popup-app') as VwPopupApp;
app.request = sendRequest;
app.browser = {
  getActiveTabId: async () => (await browser.tabs.query({ active: true, currentWindow: true }))[0]?.id,
  openOptions: () => browser.runtime.openOptionsPage(),
  openReceive: async () => {
    await browser.tabs.create({ url: browser.runtime.getURL('ui/receive/receive.html') });
  },
  openUrl: async (url: string) => {
    await browser.tabs.create({ url: url.includes('://') ? url : `https://${url}` });
  },
};
document.getElementById('app')?.append(app);
