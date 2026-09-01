import { decryptToBytes, decryptToText, encryptToBytes } from '../crypto/encstring.js';
import { isEncString, rewrapDeep, rewrapEncString } from './rotate-crypto.js';
import { symmetricKeyFromBytes, type SymmetricKey } from '../crypto/keys.js';
import type { CipherResponse, FolderResponse, SendResponse, SshKeyCipherData } from '../api/types.js';
import { isKnownCipherType } from './models.js';
import {
  assertSshCipherPayloadExclusivity,
  assertValidatedRawSshCipherPayloadExclusivity,
  parseDecryptedSshKey,
  parseSshKeyCipherData,
} from './ssh-key.js';
import {
  validateRawSyncCipherCompatibility,
  type RawSyncCipherCompatibilityResult,
} from './vault-sync-cipher-compat.js';

type ValidatedRawCipherCompatibility = Extract<
  RawSyncCipherCompatibilityResult,
  { readonly ok: true }
>;

export type RotatedCipher = Record<string, unknown> & { id: string };

/**
 * Re-encrypt a PERSONAL cipher under a new UserKey. Keyed ciphers (cipher.key set) re-wrap only the item
 * key — every field/attachment/passkey/history stays under the unchanged item key. Keyless ciphers re-wrap
 * every UserKey EncString field, and lift attachment keys into `attachments2` for the rotation endpoint.
 * Throws on any undecryptable field (caller fails closed).
 */
export async function rotateCipher(raw: CipherResponse, oldKey: SymmetricKey, newKey: SymmetricKey): Promise<RotatedCipher> {
  const compatibility = validateRawSyncCipherCompatibility(raw);
  if (!compatibility.ok) {
    if (compatibility.code === 'unsupported_cipher_type') {
      throw new TypeError('Cannot rotate an unsupported cipher type');
    }
    throw new TypeError(`Cannot rotate an incompatible cipher representation (${compatibility.code})`);
  }
  if (!isKnownCipherType(raw.type)) throw new TypeError('Cannot rotate an unsupported cipher type');
  if (raw.key !== undefined && raw.key !== null && (typeof raw.key !== 'string' || raw.key.length === 0)) {
    throw new TypeError('Cipher key must be a non-empty EncString when present');
  }
  const sshKey = raw.type === 5 ? validatedRawSshKeyPayload(raw, compatibility) : undefined;
  const requestProjection = rotationRequestProjection(raw);
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
    try {
      return { ...requestProjection, key: await encryptToBytes(itemKeyBytes, newKey) } as unknown as RotatedCipher;
    } finally {
      itemKeyBytes.fill(0);
    }
  }
  // Keyless: deep re-wrap all EncString fields under the new UserKey (excluding attachments, handled below).
  const rest = requestProjection as Record<string, unknown> & { attachments?: unknown[] };
  const attachments = rest.attachments;
  delete rest.attachments;
  if (sshKey) delete rest.sshKey;
  const rotated = await rewrapDeep(rest, oldKey, newKey) as RotatedCipher;
  if (sshKey) rotated.sshKey = await rewrapSshKey(sshKey, oldKey, newKey);
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
 *    key, so this recovers that key and verifies every EncString leaf under it. This includes
 *    attachment keys/file names and catches cross-key legacy data before the old UserKey is removed.
 *  - KEYLESS: deep-walks every EncString leaf in the rotated cipher (name/login/card/identity/
 *    fields/fido2/notes, and — unlike `decryptCipher` — passwordHistory, attachment keys/fileNames,
 *    and any unmodeled fields) and confirms each decrypts under the new UserKey. SSH fields are
 *    verified explicitly so their strict structure and plaintext bounds cannot be bypassed
 *    (Finding 2). `attachments2` is skipped: it is a key/fileName lift from the SAME rewrapped
 *    `attachments` array (byte-identical), so verifying `attachments` already covers it.
 * Throws (fail-close) on the first undecryptable leaf/key.
 */
export async function verifyRotatedCipher(rotated: RotatedCipher, newUserKey: SymmetricKey): Promise<void> {
  if (typeof rotated.type !== 'number' || !isKnownCipherType(rotated.type)) {
    throw new TypeError('Cannot verify an unsupported cipher type');
  }
  assertCanonicalRotationRequest(rotated);
  const sshKey = rotated.type === 5 ? validatedCanonicalSshKeyPayload(rotated) : undefined;
  const wrappedItemKey = rotated.key;
  if (wrappedItemKey !== undefined && wrappedItemKey !== null && (
    typeof wrappedItemKey !== 'string' || wrappedItemKey.length === 0
  )) throw new TypeError('Cipher key must be a non-empty EncString when present');
  if (typeof wrappedItemKey === 'string' && wrappedItemKey) {
    const itemKeyBytes = await decryptToBytes(wrappedItemKey, newUserKey);
    let itemKey: SymmetricKey;
    try {
      itemKey = symmetricKeyFromBytes(itemKeyBytes);
    } finally {
      itemKeyBytes.fill(0);
    }
    const rest: Record<string, unknown> = { ...(rotated as Record<string, unknown>) };
    delete rest.key;
    delete rest.attachments2;
    if (sshKey) delete rest.sshKey;
    try {
      await verifyEncStringsDeep(rest, itemKey);
      if (sshKey) await verifySshKey(sshKey, itemKey);
    } finally {
      itemKey.encKey.fill(0);
      itemKey.macKey.fill(0);
    }
    return;
  }
  const rest: Record<string, unknown> = { ...(rotated as Record<string, unknown>) };
  delete rest.attachments2;
  if (sshKey) delete rest.sshKey;
  await verifyEncStringsDeep(rest, newUserKey);
  if (sshKey) await verifySshKey(sshKey, newUserKey);
}

/**
 * The 2026.8 server gives `Data` precedence over all structured cipher fields. Rotation therefore
 * sends only the already-audited structured projection and lets CipherRequestModel rebuild its
 * canonical CipherData JSON. Keeping either redundant response field would create two authorities.
 */
function rotationRequestProjection(raw: CipherResponse): Record<string, unknown> {
  const projection = { ...(raw as unknown as Record<string, unknown>) };
  delete projection.data;
  if (raw.type === 1 && raw.login && typeof raw.login === 'object') {
    const login = { ...(raw.login as unknown as Record<string, unknown>) };
    delete login.uri;
    projection.login = login;
  }
  return projection;
}

function assertCanonicalRotationRequest(rotated: RotatedCipher): void {
  if (Object.prototype.hasOwnProperty.call(rotated, 'data')) {
    throw new TypeError('Rotated cipher must omit the redundant data field');
  }
  if (rotated.type !== 1) return;
  const login = rotated.login;
  if (login && typeof login === 'object' && Object.prototype.hasOwnProperty.call(login, 'uri')) {
    throw new TypeError('Rotated login cipher must omit the obsolete URI alias');
  }
}

function validatedRawSshKeyPayload(
  value: CipherResponse,
  compatibility: ValidatedRawCipherCompatibility,
): SshKeyCipherData {
  assertValidatedRawSshCipherPayloadExclusivity(value, compatibility);
  return parseSshKeyCipherData(value.sshKey);
}

function validatedCanonicalSshKeyPayload(value: RotatedCipher): SshKeyCipherData {
  assertSshCipherPayloadExclusivity(value);
  return parseSshKeyCipherData(value.sshKey);
}

async function rewrapSshKey(
  value: SshKeyCipherData,
  oldKey: SymmetricKey,
  newKey: SymmetricKey,
): Promise<SshKeyCipherData> {
  const rotated: SshKeyCipherData = {
    privateKey: await rewrapEncString(value.privateKey, oldKey, newKey),
  };
  if (value.publicKey) rotated.publicKey = await rewrapEncString(value.publicKey, oldKey, newKey);
  if (value.keyFingerprint) {
    rotated.keyFingerprint = await rewrapEncString(value.keyFingerprint, oldKey, newKey);
  }
  return parseSshKeyCipherData(rotated);
}

async function verifySshKey(
  value: SshKeyCipherData,
  key: SymmetricKey,
): Promise<void> {
  const decrypted = {
    privateKey: await decryptToText(value.privateKey, key),
    ...(value.publicKey ? { publicKey: await decryptToText(value.publicKey, key) } : {}),
    ...(value.keyFingerprint
      ? { keyFingerprint: await decryptToText(value.keyFingerprint, key) }
      : {}),
  };
  parseDecryptedSshKey(decrypted);
}

async function verifyEncStringsDeep(value: unknown, key: SymmetricKey): Promise<void> {
  if (isEncString(value)) {
    const plaintext = await decryptToBytes(value, key);
    plaintext.fill(0);
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
