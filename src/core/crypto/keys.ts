import { decryptToBytes } from './encstring.js';

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
