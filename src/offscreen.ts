import browser from 'webextension-polyfill';
import type { Runtime } from 'webextension-polyfill';
import { isBoundedClipboardSecret } from './background/clipboard.js';
import { constantTimeEqual, utf8ToBytes } from './core/crypto/encoding.js';
import { isContentTotpClipboardCode } from './messaging/totp-clipboard-code.js';

export type ClipboardClearResult =
  | { ok: true; cleared: boolean }
  | { ok: false; error: string };

export type ClipboardWriteResult =
  | { ok: true; written: true }
  | { ok: false; error: string };

/** Write a bounded TOTP value inside the offscreen document. */
export async function writeClipboard(value: string): Promise<ClipboardWriteResult> {
  if (!isContentTotpClipboardCode(value)) {
    return { ok: false, error: 'Invalid clipboard value' };
  }
  return writeValidatedClipboard(value);
}

/** Write a bounded arbitrary secret accepted only from the extension service worker. */
export async function writeSecretClipboard(value: string): Promise<ClipboardWriteResult> {
  if (!isBoundedClipboardSecret(value)) {
    return { ok: false, error: 'Invalid clipboard value' };
  }
  return writeValidatedClipboard(value);
}

async function writeValidatedClipboard(value: string): Promise<ClipboardWriteResult> {
  try {
    await navigator.clipboard.writeText(value);
    return { ok: true, written: true };
  } catch {
    const textarea = document.createElement('textarea');
    try {
      textarea.value = value;
      document.body.append(textarea);
      textarea.select();
      return document.execCommand('copy')
        ? { ok: true, written: true }
        : { ok: false, error: 'Clipboard write was rejected' };
    } catch {
      return { ok: false, error: 'Clipboard write was rejected' };
    } finally {
      textarea.value = '';
      textarea.remove();
    }
  }
}

/** Clear only when the clipboard still contains the value copied by this extension. Reading must
 *  succeed before any write is attempted; otherwise the operation fails closed. */
export async function clearClipboardIfOwned(expectedDigest: Uint8Array): Promise<ClipboardClearResult> {
  let currentDigest: Uint8Array | undefined;
  try {
    if (expectedDigest.length !== 32) return { ok: false, error: 'Invalid clipboard digest' };
    try {
      currentDigest = await readClipboardDigest();
    } catch {
      return { ok: false, error: 'Clipboard read was rejected' };
    }
    if (!currentDigest || !constantTimeEqual(currentDigest, expectedDigest)) {
      return { ok: true, cleared: false };
    }

    try {
      await navigator.clipboard.writeText('');
      return { ok: true, cleared: true };
    } catch {
      // Fallback: overwrite with a single space via execCommand. Copying an empty selection is a no-op.
      const ta = document.createElement('textarea');
      try {
        ta.value = ' ';
        document.body.append(ta);
        ta.select();
        const copied = document.execCommand('copy');
        if (!copied) return { ok: false, error: 'Clipboard overwrite was rejected' };
        return { ok: true, cleared: true };
      } catch {
        return { ok: false, error: 'Clipboard overwrite was rejected' };
      } finally {
        ta.remove();
      }
    }
  } finally {
    currentDigest?.fill(0);
    expectedDigest.fill(0);
  }
}

async function readClipboardDigest(): Promise<Uint8Array> {
  return digestClipboardValue(await navigator.clipboard.readText());
}

async function digestClipboardValue(value: string): Promise<Uint8Array> {
  const bytes = utf8ToBytes(value);
  try {
    return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes as BufferSource));
  } finally {
    bytes.fill(0);
  }
}

/** Return a Promise (response) only for our own message; otherwise undefined so we don't answer others'. */
export function handleOffscreenMessage(
  message: unknown,
  sender?: Runtime.MessageSender,
): Promise<ClipboardClearResult | ClipboardWriteResult> | undefined {
  if (typeof message !== 'object' || message === null
      || Array.isArray(message)) return undefined;
  if (!isExtensionWorkerSender(sender)) return undefined;
  if ((message as { type?: unknown }).type === 'offscreen.writeClipboard') {
    const keys = Reflect.ownKeys(message);
    const value = Object.getOwnPropertyDescriptor(message, 'value');
    if (keys.length !== 2 || !keys.includes('type') || !keys.includes('value')
        || !value?.enumerable || !('value' in value)) return undefined;
    return writeClipboard(value.value as string);
  }
  if ((message as { type?: unknown }).type === 'offscreen.writeSecretClipboard') {
    const keys = Reflect.ownKeys(message);
    const value = Object.getOwnPropertyDescriptor(message, 'value');
    if (keys.length !== 2 || !keys.includes('type') || !keys.includes('value')
        || !value?.enumerable || !('value' in value)) return undefined;
    return writeSecretClipboard(value.value as string);
  }
  if ((message as { type?: unknown }).type !== 'offscreen.clearClipboardIfOwned') return undefined;
  const wireDigest = (message as { expectedDigest?: unknown }).expectedDigest;
  if (!Array.isArray(wireDigest)
      || wireDigest.length !== 32
      || !wireDigest.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)) return undefined;
  const expectedDigest = Uint8Array.from(wireDigest as number[]);
  wireDigest.fill(0);
  return clearClipboardIfOwned(expectedDigest);
}

browser.runtime.onMessage.addListener(handleOffscreenMessage);

function isExtensionWorkerSender(sender: Runtime.MessageSender | undefined): boolean {
  if (!sender || sender.id !== browser.runtime.id || sender.tab !== undefined) return false;
  return sender.url === browser.runtime.getURL('background.js');
}
