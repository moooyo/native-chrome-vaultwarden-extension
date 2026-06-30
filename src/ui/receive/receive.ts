import browser from 'webextension-polyfill';
import { icon } from '../icons.js';
import {
  parseSendUrl, accessSend, decryptAccessedSend, requestFileDownloadUrl,
  downloadAndDecryptFile, sendPasswordHash, type ParsedSendUrl, type AccessedSend, type SendAccessError,
} from '../../core/vault/send-access.js';

const linkInput = document.getElementById('link') as HTMLInputElement;
const passwordField = document.getElementById('passwordField') as HTMLElement;
const passwordInput = document.getElementById('password') as HTMLInputElement;
const accessButton = document.getElementById('accessButton') as HTMLButtonElement;
const result = document.getElementById('result')!;
const status = document.getElementById('status')!;
document.getElementById('brandMark')!.innerHTML = icon('shield');

let busy = false;
accessButton.addEventListener('click', () => void onAccess());

const MESSAGES: Record<SendAccessError, string> = {
  invalid_link: 'Invalid Send link.',
  password_required: 'This Send needs a password.',
  unavailable: 'This Send is no longer available.',
  decrypt_failed: 'Could not decrypt — the link or file may be corrupted.',
};

async function onAccess(): Promise<void> {
  if (busy) return;
  result.innerHTML = '';
  let parsed: ParsedSendUrl;
  try { parsed = parseSendUrl(linkInput.value); } catch { return setStatus(MESSAGES.invalid_link, true); }

  busy = true; accessButton.disabled = true;
  try {
    if (!(await ensureHostPermission(parsed.serverUrl))) return setStatus(`Grant access to ${hostOf(parsed.serverUrl)} to receive this Send.`, true);
    const pwd = passwordInput.value;
    const passwordHash = pwd ? await sendPasswordHash(pwd, parsed.sendKey) : undefined;
    const raw = await accessSend(fetch, parsed.serverUrl, parsed.accessId, passwordHash);
    const send = await decryptAccessedSend(raw, parsed.sendKey);
    setStatus('', false);
    renderSend(parsed, send, passwordHash);
  } catch (err) {
    const code = (err as { code?: SendAccessError }).code;
    if (code === 'password_required') { passwordField.hidden = false; passwordInput.focus(); }
    setStatus(code ? MESSAGES[code] : 'Something went wrong.', true);
  } finally {
    busy = false; accessButton.disabled = false;
  }
}

function renderSend(parsed: ParsedSendUrl, send: AccessedSend, passwordHash?: string): void {
  if (send.type === 1) {
    result.innerHTML = `<div class="send-name">${escapeHtml(send.name)}</div>
      <div class="send-file">📎 ${escapeHtml(send.fileName ?? 'file')}${send.sizeName ? ` · ${escapeHtml(send.sizeName)}` : ''}
      <button type="button" class="btn" id="downloadButton"><span>Download</span></button></div>`;
    document.getElementById('downloadButton')!.addEventListener('click', () => void downloadFile(parsed, send, passwordHash));
  } else {
    result.innerHTML = `<div class="send-name">${escapeHtml(send.name)}</div><div class="send-text">${escapeHtml(send.text ?? '')}</div>`;
  }
}

async function downloadFile(parsed: ParsedSendUrl, send: AccessedSend, passwordHash?: string): Promise<void> {
  if (busy) return;
  if (!send.fileId || !send.id) { setStatus(MESSAGES.unavailable, true); return; }
  busy = true;
  const button = document.getElementById('downloadButton') as HTMLButtonElement | null;
  if (button) button.disabled = true;
  try {
    const url = await requestFileDownloadUrl(fetch, parsed.serverUrl, send.id, send.fileId, passwordHash);
    const bytes = await downloadAndDecryptFile(fetch, url, parsed.serverUrl, parsed.sendKey);
    triggerDownload(bytes, send.fileName ?? 'download');
    setStatus('', false);
  } catch (err) {
    const code = (err as { code?: SendAccessError }).code;
    setStatus(code ? MESSAGES[code] : 'Download failed.', true);
  } finally {
    busy = false;
    if (button) button.disabled = false;
  }
}

function triggerDownload(bytes: Uint8Array, fileName: string): void {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart]));
  const a = document.createElement('a');
  a.href = url; a.download = fileName; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** Request host permission for the Send's origin (must run in a user gesture). `permissions.request`
 *  is idempotent — it returns true without a prompt when the origin is already granted, so calling it
 *  directly (no prior async `contains`) keeps the call inside the click's user-gesture window. */
async function ensureHostPermission(serverUrl: string): Promise<boolean> {
  const origin = `${new URL(serverUrl).origin}/*`;
  return browser.permissions.request({ origins: [origin] });
}

function hostOf(serverUrl: string): string { try { return new URL(serverUrl).host; } catch { return serverUrl; } }
function setStatus(message: string, isError: boolean): void { status.textContent = message; status.classList.toggle('error', isError); }
function escapeHtml(v: string): string { return v.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!)); }
