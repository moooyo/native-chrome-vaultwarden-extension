import browser from 'webextension-polyfill';

browser.runtime.onInstalled.addListener(() => {
  console.log('[vaultwarden] service worker installed');
});

browser.runtime.onMessage.addListener(async () => {
  return { ok: false, error: { code: 'not_ready', message: 'router not wired yet' } };
});
