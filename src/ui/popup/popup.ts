// Popup entry: a thin dependency adapter that mounts the Lit popup root and injects the real
// worker-request channel and the browser seam. All UI, state, and routing live in `VwPopupApp`.
import browser from 'webextension-polyfill';
import { sendRequest } from '../../messaging/protocol.js';
import { VwPopupApp } from './app.js';
import { safeWebUrl } from './utils.js';

const app = document.createElement('vw-popup-app') as VwPopupApp;
const workspace = new URLSearchParams(window.location.search).get('workspace') === '1';
app.workspace = workspace;
document.documentElement.classList.toggle('workspace', workspace);
document.body.classList.toggle('workspace', workspace);
app.request = sendRequest;
app.browser = {
  getActiveTabId: async () => (await browser.tabs.query({ active: true, currentWindow: true }))[0]?.id,
  getActiveTabUrl: async () => (await browser.tabs.query({ active: true, currentWindow: true }))[0]?.url,
  captureVisibleTab: () => browser.tabs.captureVisibleTab(undefined, { format: 'png' }),
  openOptions: () => browser.runtime.openOptionsPage(),
  openWorkspace: async () => {
    await browser.tabs.create({ url: browser.runtime.getURL('ui/popup/popup.html?workspace=1') });
  },
  openReceive: async () => {
    await browser.tabs.create({ url: browser.runtime.getURL('ui/receive/receive.html') });
  },
  openUrl: async (url: string) => {
    const normalized = url.includes('://') ? url : `https://${url}`;
    // Gate the stored URI down to http/https before navigating — never open a non-web scheme.
    const safe = safeWebUrl(normalized);
    if (safe !== undefined) await browser.tabs.create({ url: safe });
  },
};
document.getElementById('app')?.append(app);

// The action popup needs a definite height during Chrome's initial autosizing. Only shrink it for
// a genuinely constrained window; the explicit full-tab workspace follows the available viewport.
function fitPopupHeight(): void {
  const ih = window.innerHeight;
  const px = `${workspace ? ih : ih >= 120 && ih < 600 ? ih : 600}px`;
  if (document.body.style.height === px) return;
  document.documentElement.style.height = px;
  document.body.style.height = px;
}
fitPopupHeight();
window.addEventListener('resize', fitPopupHeight);
requestAnimationFrame(fitPopupHeight);
