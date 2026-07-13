// HIBP Pwned Passwords (k-anonymity). The password is SHA-1'd IN THE WORKER; only the first 5 hex
// characters of the hash are sent to the API. The full password / full hash / suffix never leave the
// device — the suffix is matched locally against the returned range. `Add-Padding` hides the hit count.

import { utf8ToBytes } from '../crypto/encoding.js';

const HIBP_RANGE = 'https://api.pwnedpasswords.com/range/';

/** Uppercase hex of SHA-1(text). HIBP's range endpoint returns uppercase suffixes. */
export async function sha1Hex(text: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-1', utf8ToBytes(text) as BufferSource);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/**
 * Look up a password in HIBP Pwned Passwords via k-anonymity. Returns the breach count (0 if not found).
 * Throws on a network / non-2xx error. `fetchFn`/`sha1` are injectable for tests.
 */
export async function pwnedCount(
  password: string,
  fetchFn: typeof fetch = fetch,
  sha1: (text: string) => Promise<string> = sha1Hex,
): Promise<number> {
  const hash = await sha1(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5).toUpperCase();
  const res = await fetchFn(`${HIBP_RANGE}${prefix}`, { headers: { 'Add-Padding': 'true' } });
  if (!res.ok) throw new Error(`HIBP request failed: ${res.status}`);
  const body = await res.text();
  for (const line of body.split('\n')) {
    const sep = line.indexOf(':');
    if (sep < 0) continue;
    if (line.slice(0, sep).trim().toUpperCase() === suffix) {
      return Number.parseInt(line.slice(sep + 1).trim(), 10) || 0;
    }
  }
  return 0;
}
