import browser from 'webextension-polyfill';

/** Clear the system clipboard. Primary: writeText(''). Fallback: overwrite with a single space via
 *  execCommand (a non-empty selection — execCommand('copy') on an EMPTY selection is a no-op). */
export async function clearClipboard(): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await navigator.clipboard.writeText('');
    return { ok: true };
  } catch {
    try {
      const ta = document.createElement('textarea');
      ta.value = ' ';
      document.body.append(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  }
}

/** Return a Promise (response) only for our own message; otherwise undefined so we don't answer others'. */
export function handleOffscreenMessage(message: unknown): Promise<{ ok: true } | { ok: false; error: string }> | undefined {
  if (typeof message === 'object' && message !== null && (message as { type?: unknown }).type === 'offscreen.clearClipboard') {
    return clearClipboard();
  }
  return undefined;
}

browser.runtime.onMessage.addListener(handleOffscreenMessage);
