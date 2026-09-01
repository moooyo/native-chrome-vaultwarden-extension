import type { AccountPasskeyWebAuthnPrfOption } from '../api/account-passkey.js';
import {
  decryptPrivateKey,
  unwrapRsaWrappedKey,
  type SymmetricKey,
} from '../crypto/keys.js';
import { hkdfExpandSha256, validateRsa2048OaepPrivateKey } from '../crypto/primitives.js';

export interface AccountPasskeyPrfUnlockMaterial {
  /** Ownership transfers to the caller, which must zero both key halves. */
  readonly userKey: SymmetricKey;
  /** Ownership transfers to the caller, which must zero these PKCS8 bytes. */
  readonly privateKey: Uint8Array;
}

/** Derive the official 64-byte PrfKey layout: HKDF-Expand(raw, "enc") || HKDF-Expand(raw, "mac"). */
export async function deriveAccountPasskeyPrfKey(prfOutput: Uint8Array): Promise<SymmetricKey> {
  assertAccountPasskeyPrfOutput(prfOutput);
  let encKey: Uint8Array | undefined;
  let macKey: Uint8Array | undefined;
  let ownershipTransferred = false;
  try {
    encKey = await hkdfExpandSha256(prfOutput, 'enc', 32);
    macKey = await hkdfExpandSha256(prfOutput, 'mac', 32);
    ownershipTransferred = true;
    return { encKey, macKey };
  } finally {
    if (!ownershipTransferred) {
      encKey?.fill(0);
      macKey?.fill(0);
    }
  }
}

/** Recover and validate the UserKey and account RSA key for one authoritative matching PRF option. */
export async function recoverAccountPasskeyPrfUnlockMaterial(input: {
  readonly prfOutput: Uint8Array;
  readonly option: AccountPasskeyWebAuthnPrfOption;
  readonly encPrivateKey: string;
}): Promise<AccountPasskeyPrfUnlockMaterial> {
  let prfKey: SymmetricKey | undefined;
  let credentialPrivateKey: Uint8Array | undefined;
  let userKey: SymmetricKey | undefined;
  let privateKey: Uint8Array | undefined;
  let ownershipTransferred = false;
  try {
    prfKey = await deriveAccountPasskeyPrfKey(input.prfOutput);
    credentialPrivateKey = await decryptPrivateKey(input.option.encryptedPrivateKey, prfKey);
    userKey = await unwrapRsaWrappedKey(input.option.encryptedUserKey, credentialPrivateKey);
    privateKey = await decryptPrivateKey(input.encPrivateKey, userKey);
    await validateRsa2048OaepPrivateKey(privateKey, 'SHA-1');
    ownershipTransferred = true;
    return { userKey, privateKey };
  } finally {
    clearSymmetricKey(prfKey);
    credentialPrivateKey?.fill(0);
    if (!ownershipTransferred) {
      clearSymmetricKey(userKey);
      privateKey?.fill(0);
    }
  }
}

/** Copy a borrowed PRF result so AuthService can own and clear its lifetime independently. */
export function copyAccountPasskeyPrfOutput(input: unknown): Uint8Array | undefined {
  if (input === undefined) return undefined;
  if (!(input instanceof Uint8Array)) {
    throw new Error('Account passkey PRF output must be a byte array');
  }
  assertAccountPasskeyPrfOutput(input);
  return input.slice();
}

function assertAccountPasskeyPrfOutput(input: Uint8Array): void {
  if (input.byteLength !== 32 || input.every((value) => value === 0)) {
    throw new Error('Account passkey PRF output must contain 32 bytes and must not be all zero');
  }
}

function clearSymmetricKey(key: SymmetricKey | undefined): void {
  key?.encKey.fill(0);
  key?.macKey.fill(0);
}
