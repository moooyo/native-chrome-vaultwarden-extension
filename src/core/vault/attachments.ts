// Attachment cryptography. A cipher attachment is a file encrypted with its own random 64-byte key
// (32 enc ‖ 32 mac); that key is stored as an encType=2 EncString wrapped under the cipher's key.
// The file blob itself is an "EncArrayBuffer": [encType=2 (1 byte)] ‖ iv(16) ‖ mac(32) ‖ ciphertext,
// authenticated with Encrypt-then-MAC just like an EncString.

import { aesCbc256Decrypt, aesCbc256Encrypt, hmacSha256 } from '../crypto/primitives.js';
import { constantTimeEqual } from '../crypto/encoding.js';
import { unwrapSymmetricKey, symmetricKeyFromBytes, serializeSymmetricKey, type SymmetricKey } from '../crypto/keys.js';
import { encryptToBytes } from '../crypto/encstring.js';

const ENC_TYPE_AESCBC_HMAC = 2;

/** Decrypt the per-attachment key (an encType=2 EncString wrapped by the cipher key). */
export async function decryptAttachmentKey(keyEncString: string, cipherKey: SymmetricKey): Promise<SymmetricKey> {
  return unwrapSymmetricKey(keyEncString, cipherKey);
}

/** Generate a fresh random 64-byte attachment key (32 enc ‖ 32 mac). */
export function generateAttachmentKey(randomBytes: (n: number) => Uint8Array = defaultRandomBytes): SymmetricKey {
  return symmetricKeyFromBytes(randomBytes(64));
}

/** Wrap an attachment key under the cipher key as an encType=2 EncString (stored as attachment.key). */
export async function wrapAttachmentKey(attachmentKey: SymmetricKey, cipherKey: SymmetricKey): Promise<string> {
  return encryptToBytes(serializeSymmetricKey(attachmentKey), cipherKey);
}

/** Encrypt file bytes into an EncArrayBuffer: [2] ‖ iv ‖ mac ‖ ct (Encrypt-then-MAC). */
export async function encryptAttachmentFile(
  data: Uint8Array,
  key: SymmetricKey,
  iv: Uint8Array = defaultRandomBytes(16),
): Promise<Uint8Array> {
  const ct = await aesCbc256Encrypt(key.encKey, iv, data);
  const macData = new Uint8Array(iv.length + ct.length);
  macData.set(iv, 0);
  macData.set(ct, iv.length);
  const mac = await hmacSha256(key.macKey, macData);
  const out = new Uint8Array(1 + iv.length + mac.length + ct.length);
  out[0] = ENC_TYPE_AESCBC_HMAC;
  out.set(iv, 1);
  out.set(mac, 1 + iv.length);
  out.set(ct, 1 + iv.length + mac.length);
  return out;
}

/** Decrypt an EncArrayBuffer ([2] ‖ iv ‖ mac ‖ ct) back to the original file bytes; throws on a bad MAC. */
export async function decryptAttachmentFile(buffer: Uint8Array, key: SymmetricKey): Promise<Uint8Array> {
  if (buffer.length < 1 + 16 + 32) throw new Error('attachment blob too short');
  if (buffer[0] !== ENC_TYPE_AESCBC_HMAC) throw new Error(`unsupported attachment encType ${buffer[0]}`);
  // subarray returns views that share the blob's backing buffer (no copy). macData is then the only
  // copy we build, dropping the full-ciphertext duplication a `buffer.slice(49)` would have made.
  const iv = buffer.subarray(1, 17);
  const mac = buffer.subarray(17, 49);
  const ct = buffer.subarray(49);
  const macData = new Uint8Array(iv.length + ct.length);
  macData.set(iv, 0);
  macData.set(ct, iv.length);
  const expected = await hmacSha256(key.macKey, macData);
  if (!constantTimeEqual(expected, mac)) throw new Error('attachment MAC verification failed');
  return aesCbc256Decrypt(key.encKey, iv, ct);
}

function defaultRandomBytes(n: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}
