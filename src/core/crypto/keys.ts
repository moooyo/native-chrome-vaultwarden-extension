import { decryptToBytes, parseRsaEncString } from './encstring.js';
import { rsaOaepDecrypt } from './primitives.js';

export type SymmetricKey = { encKey: Uint8Array; macKey: Uint8Array };

export function symmetricKeyFromBytes(bytes: Uint8Array): SymmetricKey {
  if (bytes.length !== 64) {
    throw new Error(`symmetric key must be 64 bytes, got ${bytes.length}`);
  }
  return { encKey: bytes.slice(0, 32), macKey: bytes.slice(32, 64) };
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
 * `Profile.organizations[].key`, an encType=4 EncString) into a 64-byte SymmetricKey using the
 * account RSA PrivateKey (PKCS8 DER, decrypted via decryptPrivateKey).
 */
export async function unwrapRsaWrappedKey(
  protectedKey: string,
  privateKeyPkcs8: Uint8Array,
): Promise<SymmetricKey> {
  const { data } = parseRsaEncString(protectedKey);
  return symmetricKeyFromBytes(await rsaOaepDecrypt(privateKeyPkcs8, data));
}
