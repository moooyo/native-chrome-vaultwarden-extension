import { decryptToBytes, encryptToBytes } from '../crypto/encstring.js';
import type { SymmetricKey } from '../crypto/keys.js';

/** A Bitwarden EncString: "<encType digit>.<base64>[|<base64>|<base64>]". Rejects UUIDs, numbers, dates. */
export function isEncString(v: unknown): v is string {
  return typeof v === 'string' && /^\d+\.[A-Za-z0-9+/=]+(\|[A-Za-z0-9+/=]+)*$/.test(v);
}

/** Re-encrypt an EncString from oldKey to newKey (decrypt bytes then re-encrypt). Throws (MAC) if the
 *  ciphertext cannot be decrypted with oldKey — callers MUST treat that as fail-close. */
export async function rewrapEncString(enc: string, oldKey: SymmetricKey, newKey: SymmetricKey): Promise<string> {
  return encryptToBytes(await decryptToBytes(enc, oldKey), newKey);
}

/** Deep-clone a JSON-ish value, re-wrapping every EncString leaf from oldKey to newKey. Non-EncString
 *  values (ids, numbers, dates, plain strings) pass through unchanged. Used for KEYLESS ciphers/folders
 *  whose every EncString is under the UserKey. */
export async function rewrapDeep(value: unknown, oldKey: SymmetricKey, newKey: SymmetricKey): Promise<unknown> {
  if (isEncString(value)) return rewrapEncString(value, oldKey, newKey);
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (const item of value) out.push(await rewrapDeep(item, oldKey, newKey));
    return out;
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = await rewrapDeep(v, oldKey, newKey);
    return out;
  }
  return value;
}
