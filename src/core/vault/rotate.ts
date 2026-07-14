import { decryptToBytes, encryptToBytes } from '../crypto/encstring.js';
import { isEncString, rewrapDeep, rewrapEncString } from './rotate-crypto.js';
import { symmetricKeyFromBytes, type SymmetricKey } from '../crypto/keys.js';
import type { CipherResponse, FolderResponse, SendResponse } from '../api/types.js';

export type RotatedCipher = Record<string, unknown> & { id: string };

/**
 * Re-encrypt a PERSONAL cipher under a new UserKey. Keyed ciphers (cipher.key set) re-wrap only the item
 * key — every field/attachment/passkey/history stays under the unchanged item key. Keyless ciphers re-wrap
 * every UserKey EncString field, and lift attachment keys into `attachments2` for the rotation endpoint.
 * Throws on any undecryptable field (caller fails closed).
 */
export async function rotateCipher(raw: CipherResponse, oldKey: SymmetricKey, newKey: SymmetricKey): Promise<RotatedCipher> {
  // Fail-close on legacy attachments with no per-attachment key: their blob is encrypted directly under
  // the account UserKey, which this rotation replaces. Neither branch re-wraps the server blob, so
  // rotating would leave it permanently undecryptable once the old UserKey is gone. Refuse instead
  // (upstream Bitwarden hard-blocks the same case) — the user must re-upload the attachment first.
  const rawAttachments = (raw as unknown as { attachments?: Array<{ id?: string; key?: string | null }> }).attachments;
  if (Array.isArray(rawAttachments)) {
    for (const a of rawAttachments) {
      if (!a || typeof a.key !== 'string' || !a.key) {
        throw new Error('cannot rotate account key: a legacy attachment has no per-attachment key (its blob is encrypted under the account key). Re-upload the attachment, then rotate.');
      }
    }
  }
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

/**
 * Strict pre-POST self-verify for a single rotated personal cipher. Stronger than a plain
 * `decryptCipher` check:
 *  - KEYED (`rotated.key` set): rotateCipher leaves every field/attachment under the unchanged item
 *    key, so this recovers the item key from the re-wrapped `rotated.key` and — for each
 *    attachment — verifies its `key` unwraps under THAT item key. This catches a legacy
 *    cross-client attachment whose key is actually wrapped under the (rotated-away) UserKey:
 *    `decryptCipher` never attempts to decrypt attachment keys at all, so that corruption would
 *    otherwise sail through self-verify and get POSTed (Finding 1).
 *  - KEYLESS: deep-walks every EncString leaf in the rotated cipher (name/login/card/identity/
 *    fields/fido2/notes, and — unlike `decryptCipher` — passwordHistory, attachment keys/fileNames,
 *    and any unmodeled fields such as sshKey) and confirms each decrypts under the new UserKey
 *    (Finding 2). `attachments2` is skipped: it is a key/fileName lift from the SAME rewrapped
 *    `attachments` array (byte-identical), so verifying `attachments` already covers it.
 * Throws (fail-close) on the first undecryptable leaf/key.
 */
export async function verifyRotatedCipher(rotated: RotatedCipher, newUserKey: SymmetricKey): Promise<void> {
  const wrappedItemKey = rotated.key;
  if (typeof wrappedItemKey === 'string' && wrappedItemKey) {
    const itemKey = symmetricKeyFromBytes(await decryptToBytes(wrappedItemKey, newUserKey));
    const attachments = rotated.attachments;
    if (Array.isArray(attachments) && attachments.length > 0) {
      for (const att of attachments) {
        const attKey = (att as { key?: string | null } | null | undefined)?.key;
        if (attKey) await decryptToBytes(attKey, itemKey);
      }
    }
    return;
  }
  const rest: Record<string, unknown> = { ...(rotated as Record<string, unknown>) };
  delete rest.attachments2;
  await verifyEncStringsDeep(rest, newUserKey);
}

async function verifyEncStringsDeep(value: unknown, key: SymmetricKey): Promise<void> {
  if (isEncString(value)) {
    await decryptToBytes(value, key);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) await verifyEncStringsDeep(item, key);
    return;
  }
  if (value && typeof value === 'object') {
    for (const v of Object.values(value as Record<string, unknown>)) await verifyEncStringsDeep(v, key);
  }
}

export async function rotateFolder(raw: FolderResponse, oldKey: SymmetricKey, newKey: SymmetricKey): Promise<{ id: string; name: string }> {
  if (!raw.name) throw new Error('folder has no name to rotate');
  return { id: raw.id, name: await rewrapEncString(raw.name, oldKey, newKey) };
}

export type RotatedSend = Record<string, unknown> & { id: string };

/** Re-wrap ONLY the send key EncString; the name/text/file ciphertext is under the HKDF-derived send key,
 *  which does not change, so it is left byte-identical. */
export async function rotateSend(raw: SendResponse, oldKey: SymmetricKey, newKey: SymmetricKey): Promise<RotatedSend> {
  const r = raw as unknown as Record<string, unknown> & { id: string; key?: string };
  if (!r.key || typeof r.key !== 'string') throw new Error('send has no key to rotate');
  return { ...r, key: await rewrapEncString(r.key, oldKey, newKey) } as RotatedSend;
}
