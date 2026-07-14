// Popup entry: a thin dependency adapter that mounts the Lit popup root and injects the real
// worker-request channel and the browser seam. All UI, state, and routing live in `VwPopupApp`.
import browser from 'webextension-polyfill';
import { sendRequest } from '../../messaging/protocol.js';
import { VwPopupApp } from './app.js';
import { safeWebUrl } from './utils.js';

const app = document.createElement('vw-popup-app') as VwPopupApp;
app.request = sendRequest;
app.browser = {
  getActiveTabId: async () => (await browser.tabs.query({ active: true, currentWindow: true }))[0]?.id,
  openOptions: () => browser.runtime.openOptionsPage(),
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

// Fit the popup to the ACTUAL popup-window height. The frame is a fixed 560px (popup.css); on a short
// screen Chrome caps the popup window below 560 and shows its own window scrollbar to reach the clipped
// bottom (the scrollbar is on the popup window, not the DOM, so CSS overflow:hidden can't suppress it).
// Match the document height to window.innerHeight so the document never exceeds the window — the inner
// list/editor scrollers then own all scrolling. Guarded so a transient tiny innerHeight during initial
// sizing can never collapse the popup (that was the v0.0.15 `100vh` failure): only shrink when the
// window is genuinely 120–559px, otherwise keep the 560px design height.
function fitPopupHeight(): void {
  const ih = window.innerHeight;
  const px = `${ih >= 120 && ih < 560 ? ih : 560}px`;
  if (document.body.style.height === px) return;
  document.documentElement.style.height = px;
  document.body.style.height = px;
}
fitPopupHeight();
window.addEventListener('resize', fitPopupHeight);
requestAnimationFrame(fitPopupHeight);
