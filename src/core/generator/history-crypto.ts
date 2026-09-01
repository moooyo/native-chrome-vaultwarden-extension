import { decryptToBytes, encryptToBytes } from '../crypto/encstring.js';
import { symmetricKeyFromBytes, serializeSymmetricKey, type SymmetricKey } from '../crypto/keys.js';
import { hkdfExpandSha256 } from '../crypto/primitives.js';

const GENERATOR_HISTORY_KEY_DOMAIN = 'miyu.generator-history.encryption.v1:';
const SCOPE_DIGEST_PATTERN = /^[A-Za-z0-9_-]{43}$/u;

/**
 * Account-key encryption boundary used by the worker-owned generator history repository.
 * Implementations transfer ownership of decrypted byte arrays to the caller. The caller retains
 * ownership of plaintext byte arrays supplied to `encrypt` and clears them after the call settles.
 */
export interface GeneratorHistoryCrypto {
  encrypt(scopeDigest: string, plaintext: Uint8Array): Promise<string>;
  decrypt(scopeDigest: string, ciphertext: string): Promise<Uint8Array>;
}

/**
 * Derive an account-and-purpose-separated EncString key from the current UserKey. The returned
 * adapter deliberately retains only the caller-owned UserKey reference, so clearing that key on
 * lock also prevents this adapter from retaining a private copy.
 */
export function createUserKeyGeneratorHistoryCrypto(userKey: SymmetricKey): GeneratorHistoryCrypto {
  assertUserKey(userKey);
  return Object.freeze({
    encrypt: (scopeDigest: string, plaintext: Uint8Array) => withDerivedKey(scopeDigest, userKey, async (key) => {
      if (!(plaintext instanceof Uint8Array)) throw new TypeError('Generator history plaintext must be bytes');
      return encryptToBytes(plaintext, key);
    }),
    decrypt: (scopeDigest: string, ciphertext: string) => withDerivedKey(scopeDigest, userKey, (key) => {
      if (typeof ciphertext !== 'string' || ciphertext.length === 0) {
        throw new TypeError('Generator history ciphertext must be a non-empty string');
      }
      return decryptToBytes(ciphertext, key);
    }),
  });
}

async function withDerivedKey<Result>(
  scopeDigest: string,
  userKey: SymmetricKey,
  operation: (key: SymmetricKey) => Promise<Result>,
): Promise<Result> {
  assertScopeDigest(scopeDigest);
  assertUserKey(userKey);
  const rawUserKey = serializeSymmetricKey(userKey);
  let expanded: Uint8Array | undefined;
  let derived: SymmetricKey | undefined;
  try {
    expanded = await hkdfExpandSha256(
      rawUserKey,
      `${GENERATOR_HISTORY_KEY_DOMAIN}${scopeDigest}`,
      64,
    );
    derived = symmetricKeyFromBytes(expanded);
    return await operation(derived);
  } finally {
    rawUserKey.fill(0);
    expanded?.fill(0);
    if (derived) {
      derived.encKey.fill(0);
      derived.macKey.fill(0);
    }
  }
}

function assertScopeDigest(value: string): void {
  if (typeof value !== 'string' || !SCOPE_DIGEST_PATTERN.test(value)) {
    throw new TypeError('Generator history scope digest is invalid');
  }
}

function assertUserKey(value: SymmetricKey): void {
  if (!(value?.encKey instanceof Uint8Array)
    || !(value.macKey instanceof Uint8Array)
    || value.encKey.byteLength !== 32
    || value.macKey.byteLength !== 32) {
    throw new TypeError('Generator history requires a 64-byte UserKey');
  }
}
