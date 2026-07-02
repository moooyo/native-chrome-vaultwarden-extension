import { decryptToBytes, encryptToBytes } from '../crypto/encstring.js';
import { rewrapDeep } from './rotate-crypto.js';
import type { SymmetricKey } from '../crypto/keys.js';
import type { CipherResponse } from '../api/types.js';

export type RotatedCipher = Record<string, unknown> & { id: string };

/**
 * Re-encrypt a PERSONAL cipher under a new UserKey. Keyed ciphers (cipher.key set) re-wrap only the item
 * key — every field/attachment/passkey/history stays under the unchanged item key. Keyless ciphers re-wrap
 * every UserKey EncString field, and lift attachment keys into `attachments2` for the rotation endpoint.
 * Throws on any undecryptable field (caller fails closed).
 */
export async function rotateCipher(raw: CipherResponse, oldKey: SymmetricKey, newKey: SymmetricKey): Promise<RotatedCipher> {
  if (raw.key) {
    // Keyed: unwrap the raw item-key bytes with the old UserKey, re-wrap under the new UserKey. Fields untouched.
    const itemKeyBytes = await decryptToBytes(raw.key, oldKey);
    return { ...(raw as unknown as Record<string, unknown>), key: await encryptToBytes(itemKeyBytes, newKey) } as unknown as RotatedCipher;
  }
  // Keyless: deep re-wrap all EncString fields under the new UserKey (excluding attachments, handled below).
  const { attachments, ...rest } = raw as unknown as Record<string, unknown> & { attachments?: unknown[] };
  const rotated = await rewrapDeep(rest, oldKey, newKey) as RotatedCipher;
  if (Array.isArray(attachments) && attachments.length > 0) {
    // Re-wrap the attachments array ONCE (rewrapEncString uses a fresh random IV per call, so re-wrapping
    // key/fileName a second time would produce non-identical-but-equally-valid ciphertext). attachments2
    // is built by lifting key/fileName from this same rewrapped array so both stay byte-identical.
    const rotatedAttachments = await rewrapDeep(attachments, oldKey, newKey) as Array<{ id: string; key: string; fileName: string }>;
    const attachments2: Record<string, { key: string; fileName: string }> = {};
    for (const a of rotatedAttachments) {
      attachments2[a.id] = { key: a.key, fileName: a.fileName };
    }
    (rotated as Record<string, unknown>).attachments2 = attachments2;
    (rotated as Record<string, unknown>).attachments = rotatedAttachments;
  }
  return rotated;
}
