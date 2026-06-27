import { pbkdf2Sha256, hkdfExpandSha256 } from './primitives.js';
import { utf8ToBytes, bytesToBase64 } from './encoding.js';
import type { SymmetricKey } from './keys.js';

export async function deriveMasterKey(
  password: string,
  email: string,
  iterations: number,
): Promise<Uint8Array> {
  const salt = utf8ToBytes(email.trim().toLowerCase());
  return pbkdf2Sha256(utf8ToBytes(password), salt, iterations, 32);
}

export async function deriveMasterPasswordHash(
  masterKey: Uint8Array,
  password: string,
): Promise<string> {
  const hash = await pbkdf2Sha256(masterKey, utf8ToBytes(password), 1, 32);
  return bytesToBase64(hash);
}

export async function stretchMasterKey(masterKey: Uint8Array): Promise<SymmetricKey> {
  const encKey = await hkdfExpandSha256(masterKey, 'enc', 32);
  const macKey = await hkdfExpandSha256(masterKey, 'mac', 32);
  return { encKey, macKey };
}
