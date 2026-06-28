import { pbkdf2Sha256, hkdfExpandSha256 } from './primitives.js';
import { utf8ToBytes, bytesToBase64 } from './encoding.js';
import type { SymmetricKey } from './keys.js';

/**
 * Absolute lower bound on PBKDF2 iterations we will accept from a server.
 * 5000 was Bitwarden's pre-2023 default and remains its client-enforced floor; the current
 * default is 600000 (OWASP PBKDF2-SHA256 guidance). The floor stays below any legitimate
 * self-hosted account so none are locked out, while refusing an implausibly weak downgrade.
 */
export const MIN_PBKDF2_ITERATIONS = 5000;

/** Throw (fail closed, derive nothing) if a server reports an unsafe KDF iteration count. */
export function assertKdfIterationsFloor(iterations: number): void {
  if (!Number.isInteger(iterations) || iterations < MIN_PBKDF2_ITERATIONS) {
    throw new Error(
      'Server reported an unsafe KDF iteration count; refusing to derive keys. Please contact your server administrator.',
    );
  }
}

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
