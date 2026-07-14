/**
 * Focused, side-effect-light helpers for the dormant Lit item-detail views. These live outside the
 * components so they can be unit-tested directly and reused by the root orchestration:
 *  - `safeWebUrl` gates a stored URI down to http/https before it is ever used as an `href`.
 *  - `formatTotp` groups a six-digit code for readability.
 *  - `fileToBase64` / `base64ToBytes` bridge chosen files and decrypted attachment bytes
 *    (thin wrappers over the shared core codec in `core/crypto/encoding`).
 *  - `triggerDownload` saves decrypted bytes with strict object-URL cleanup.
 */

import { base64ToBytes, bytesToBase64 } from '../../core/crypto/encoding.js';

// Re-export the shared decoder so existing callers keep importing it from here.
export { base64ToBytes };

/** Return a normalized http(s) URL, or `undefined` for anything else (other schemes, non-URLs).
 *  Callers render a link only when this is defined — never a `javascript:`/`data:`/`file:` href. */
export function safeWebUrl(value: string): string | undefined {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.toString() : undefined;
  } catch {
    return undefined;
  }
}

/** Group a six-digit verification code into two halves (e.g. "081804" -> "081 804"); other lengths
 *  pass through unchanged. */
export function formatTotp(code: string): string {
  return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
}

/** Read a chosen file into base64 (the worker re-encrypts it under a fresh attachment key). */
export async function fileToBase64(file: Blob): Promise<string> {
  return bytesToBase64(new Uint8Array(await file.arrayBuffer()));
}

/** Save decrypted attachment bytes as a file, revoking the object URL once the click is dispatched. */
export function triggerDownload(dataB64: string, fileName: string): void {
  const url = URL.createObjectURL(new Blob([base64ToBytes(dataB64) as BlobPart]));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
