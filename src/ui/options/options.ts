import browser from 'webextension-polyfill';
import { sendRequest } from '../../messaging/protocol.js';

const form = document.getElementById('settingsForm') as HTMLFormElement;
const input = document.getElementById('serverUrl') as HTMLInputElement;
const status = document.getElementById('status')!;

void init();

async function init() {
  const response = await sendRequest({ type: 'settings.get' });
  if (response.ok) {
    const { serverUrl } = response.data as { serverUrl?: string };
    if (serverUrl) input.value = serverUrl;
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const normalized = new URL(input.value).toString();
    const originPattern = new URL(normalized).origin + '/*';
    const granted = await browser.permissions.request({ origins: [originPattern] });
    if (!granted) {
      setStatus('Host permission was not granted.', true);
      return;
    }
    const response = await sendRequest({ type: 'settings.save', serverUrl: normalized });
    if (!response.ok) {
      setStatus(response.error.message, true);
      return;
    }
    setStatus('Saved.', false);
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), true);
  }
});

function setStatus(message: string, isError: boolean) {
  status.innerHTML = `<p class="${isError ? 'error' : 'success'}">${escapeHtml(message)}</p>`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}
