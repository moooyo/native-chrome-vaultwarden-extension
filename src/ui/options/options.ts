import browser from 'webextension-polyfill';
import { sendRequest } from '../../messaging/protocol.js';
import { isUriMatchStrategySetting } from '../../core/vault/uri-match.js';
import { isLockTimeoutSetting, isOnIdleAction, isClipboardClearSetting } from '../../background/settings.js';
import { icon } from '../icons.js';

const form = document.getElementById('settingsForm') as HTMLFormElement;
const input = document.getElementById('serverUrl') as HTMLInputElement;
const defaultUriMatchStrategyInput = document.getElementById('defaultUriMatchStrategy') as HTMLSelectElement;
const lockTimeoutInput = document.getElementById('lockTimeout') as HTMLSelectElement;
const status = document.getElementById('status')!;
const strategyHelp = document.getElementById('strategyHelp')!;
const saveButton = document.getElementById('saveButton') as HTMLButtonElement;
const onIdleActionInput = document.getElementById('onIdleAction') as HTMLSelectElement;
const clipboardClearInput = document.getElementById('clipboardClear') as HTMLSelectElement;
const idleActionWarning = document.getElementById('idleActionWarning')!;
document.getElementById('brandMark')!.innerHTML = icon('shield');

/** Plain-language description of each match strategy, shown beneath the select. */
const STRATEGY_HELP: Record<string, string> = {
  '0': 'Fills when the registrable domain matches — example.com matches app.example.com. The safe default for most sites.',
  '1': 'Fills only when the host and port match exactly, so app.example.com and example.com are treated separately.',
  '2': 'Fills when the page address starts with the saved URI. Useful for path-scoped logins.',
  '3': 'Fills only when the full address matches the saved URI character for character.',
  '4': 'Fills when the page address matches the saved URI as a regular expression. For advanced setups.',
  '5': 'Never offers to fill automatically for these items.',
};

function updateStrategyHelp() {
  strategyHelp.textContent = STRATEGY_HELP[defaultUriMatchStrategyInput.value] ?? '';
}

function updateIdleWarning() {
  idleActionWarning.textContent = onIdleActionInput.value === 'logout'
    ? 'Log out will end your session (and disable PIN unlock) on every idle timeout and system lock.'
    : '';
}

async function saveSecurity() {
  const el = document.getElementById('securityStatus')!;
  const action = onIdleActionInput.value;
  const clip = clipboardClearInput.value;
  if (!isOnIdleAction(action) || !isClipboardClearSetting(clip)) {
    el.innerHTML = `<div class="toast error">${escapeHtml('Unsupported security setting.')}</div>`;
    return;
  }
  const response = await sendRequest({ type: 'settings.saveSecurity', onIdleAction: action, clipboardClearSeconds: clip });
  el.innerHTML = response.ok ? '' : `<div class="toast error">${escapeHtml(response.error.message)}</div>`;
}

void init();

async function init() {
  const response = await sendRequest({ type: 'settings.get' });
  if (response.ok) {
    const { serverUrl, defaultUriMatchStrategy, lockTimeout, onIdleAction, clipboardClearSeconds } = response.data as {
      serverUrl?: string;
      defaultUriMatchStrategy: number;
      lockTimeout: string;
      onIdleAction: string;
      clipboardClearSeconds: string;
    };
    if (serverUrl) input.value = serverUrl;
    defaultUriMatchStrategyInput.value = String(defaultUriMatchStrategy);
    lockTimeoutInput.value = lockTimeout;
    onIdleActionInput.value = onIdleAction;
    clipboardClearInput.value = clipboardClearSeconds;
  }
  updateStrategyHelp();
  updateIdleWarning();
}

defaultUriMatchStrategyInput.addEventListener('change', updateStrategyHelp);
onIdleActionInput.addEventListener('change', () => { updateIdleWarning(); void saveSecurity(); });
clipboardClearInput.addEventListener('change', () => void saveSecurity());

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  saveButton.disabled = true;
  try {
    const normalized = new URL(input.value).toString();
    const originPattern = new URL(normalized).origin + '/*';
    const granted = await browser.permissions.request({ origins: [originPattern] });
    if (!granted) {
      setStatus('Host permission was not granted.', true);
      return;
    }
    const parsedStrategy = Number(defaultUriMatchStrategyInput.value);
    if (!isUriMatchStrategySetting(parsedStrategy)) {
      setStatus('Unsupported URI match strategy.', true);
      return;
    }
    if (!isLockTimeoutSetting(lockTimeoutInput.value)) {
      setStatus('Unsupported lock timeout.', true);
      return;
    }
    const response = await sendRequest({ type: 'settings.save', serverUrl: normalized, defaultUriMatchStrategy: parsedStrategy, lockTimeout: lockTimeoutInput.value });
    if (!response.ok) {
      setStatus(response.error.message, true);
      return;
    }
    setStatus('Settings saved.', false);
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), true);
  } finally {
    saveButton.disabled = false;
  }
});

function setStatus(message: string, isError: boolean) {
  status.innerHTML = `<div class="toast ${isError ? 'error' : 'success'}">${icon(isError ? 'alert' : 'checkCircle')}<span>${escapeHtml(message)}</span></div>`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}
