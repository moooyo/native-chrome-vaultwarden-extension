import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey } from './kdf.js';
import { encryptToBytes } from './encstring.js';
import { symmetricKeyFromBytes } from './keys.js';
import { bytesToBase64 } from './encoding.js';

const subtle = globalThis.crypto.subtle;

/** Account registration material: everything the register endpoint needs, derived client-side. */
export interface RegistrationKeys {
  masterPasswordHash: string;
  /** UserKey wrapped under the stretched master key (encType=2). Sent as `key`. */
  key: string;
  keys: { publicKey: string; encryptedPrivateKey: string };
  kdf: 0;
  kdfIterations: number;
}

/**
 * Build the client-side registration material for a new PBKDF2 account: a freshly generated 64-byte
 * UserKey wrapped under the stretched master key, plus a new RSA-2048 keypair whose private key is
 * wrapped under the UserKey. Mirrors the Bitwarden account-creation key hierarchy.
 */
export async function buildRegistration(
  email: string,
  password: string,
  kdfIterations = 600000,
): Promise<RegistrationKeys> {
  const normalizedEmail = email.trim().toLowerCase();
  const masterKey = await deriveMasterKey(password, normalizedEmail, kdfIterations);
  const masterPasswordHash = await deriveMasterPasswordHash(masterKey, password);
  const stretched = await stretchMasterKey(masterKey);

  // Fresh random UserKey (32B enc + 32B mac), wrapped under the stretched master key.
  const userKeyBytes = new Uint8Array(64);
  globalThis.crypto.getRandomValues(userKeyBytes);
  const userKey = symmetricKeyFromBytes(userKeyBytes);
  const key = await encryptToBytes(userKeyBytes, stretched);

  // Account RSA keypair; private key (PKCS8) wrapped under the UserKey, public key as SPKI base64.
  const pair = await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
    true,
    ['encrypt', 'decrypt'],
  );
  const spki = new Uint8Array(await subtle.exportKey('spki', pair.publicKey));
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
  const encryptedPrivateKey = await encryptToBytes(pkcs8, userKey);

  return {
    masterPasswordHash,
    key,
    keys: { publicKey: bytesToBase64(spki), encryptedPrivateKey },
    kdf: 0,
    kdfIterations,
  };
}
