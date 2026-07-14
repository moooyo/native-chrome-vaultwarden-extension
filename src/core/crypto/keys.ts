import { decryptToBytes, parseRsaEncString } from './encstring.js';
import { rsaOaepDecrypt } from './primitives.js';

export type SymmetricKey = { encKey: Uint8Array; macKey: Uint8Array };

export function symmetricKeyFromBytes(bytes: Uint8Array): SymmetricKey {
  if (bytes.length !== 64) {
    throw new Error(`symmetric key must be 64 bytes, got ${bytes.length}`);
  }
  return { encKey: bytes.slice(0, 32), macKey: bytes.slice(32, 64) };
}

/**
 * Serialize a SymmetricKey to its 64-byte wire layout: enc(32) ‖ mac(32). The exact inverse of
 * symmetricKeyFromBytes. This byte order is a security-sensitive invariant shared by every place that
 * wraps a symmetric key (UserKey / PIN / attachment / emergency-access), so it lives here once.
 */
export function serializeSymmetricKey(key: SymmetricKey): Uint8Array {
  const raw = new Uint8Array(64);
  raw.set(key.encKey, 0);
  raw.set(key.macKey, 32);
  return raw;
}

export async function unwrapSymmetricKey(
  protectedKey: string,
  wrappingKey: SymmetricKey,
): Promise<SymmetricKey> {
  return symmetricKeyFromBytes(await decryptToBytes(protectedKey, wrappingKey));
}

/**
 * Decrypt the account RSA PrivateKey into raw PKCS8 DER bytes. The PrivateKey field is an
 * encType=2 EncString wrapped by the UserKey (symmetric), NOT an RSA blob.
 */
export async function decryptPrivateKey(
  encPrivateKey: string,
  userKey: SymmetricKey,
): Promise<Uint8Array> {
  return decryptToBytes(encPrivateKey, userKey);
}

/**
 * Unwrap an RSA-OAEP wrapped symmetric key (e.g. an organization key from
 * `Profile.organizations[].key`) into a 64-byte SymmetricKey using the account RSA PrivateKey
 * (PKCS8 DER, decrypted via decryptPrivateKey). The OAEP hash follows the encType: SHA-256 for
 * encType 3/5 (Rsa2048_OaepSha256*), SHA-1 for encType 4/6 (Rsa2048_OaepSha1*).
 */
export async function unwrapRsaWrappedKey(
  protectedKey: string,
  privateKeyPkcs8: Uint8Array,
): Promise<SymmetricKey> {
  const { encType, data } = parseRsaEncString(protectedKey);
  const hash = RSA_SHA256_ENC_TYPES.has(encType) ? 'SHA-256' : 'SHA-1';
  return symmetricKeyFromBytes(await rsaOaepDecrypt(privateKeyPkcs8, data, hash));
}

const RSA_SHA256_ENC_TYPES = new Set([3, 5]);
