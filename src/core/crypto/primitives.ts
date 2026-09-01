import { constantTimeEqual, utf8ToBytes } from './encoding.js';

const subtle = globalThis.crypto.subtle;

/**
 * Cache the imported (non-extractable) CryptoKey per raw-key Uint8Array. Bulk decryption fans a
 * MAC-verify + AES-CBC-decrypt over every field of every cipher, all under the same UserKey, so
 * without a cache each field re-imports the same two raw keys. Keyed by the key-bytes array identity:
 * SymmetricKey.encKey/macKey are stable, immutable slices, so identity implies identical bytes.
 * A Promise is stored to dedupe concurrent imports; entries are GC'd once the key array is dropped
 * (e.g. on lock/logout). Separate maps per algorithm/usage keep an AES key from colliding with an
 * HMAC key. The cached CryptoKey is byte-for-byte equivalent to a fresh import, so output is identical.
 */
const hmacKeyCache = new WeakMap<Uint8Array, Promise<CryptoKey>>();
const aesDecryptKeyCache = new WeakMap<Uint8Array, Promise<CryptoKey>>();

function importHmacKey(key: Uint8Array): Promise<CryptoKey> {
  let imported = hmacKeyCache.get(key);
  if (!imported) {
    imported = subtle.importKey('raw', key as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    hmacKeyCache.set(key, imported);
  }
  return imported;
}

function importAesDecryptKey(key: Uint8Array): Promise<CryptoKey> {
  let imported = aesDecryptKeyCache.get(key);
  if (!imported) {
    imported = subtle.importKey('raw', key as BufferSource, { name: 'AES-CBC' }, false, ['decrypt']);
    aesDecryptKeyCache.set(key, imported);
  }
  return imported;
}

export async function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  lengthBytes: number,
): Promise<Uint8Array> {
  const baseKey = await subtle.importKey('raw', password as BufferSource, 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' },
    baseKey,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await importHmacKey(key);
  return new Uint8Array(await subtle.sign('HMAC', k, data as BufferSource));
}

/**
 * HKDF-Expand (RFC 5869 §2.3) over SHA-256. Multi-block: T(n) = HMAC(PRK, T(n-1) ‖ info ‖ n), with
 * the output the first `lengthBytes` of T(1) ‖ T(2) ‖ … Single-block (≤32B) matches the prior
 * behavior; 64B output is used for Bitwarden Send keys (derive_shareable_key).
 */
export async function hkdfExpandSha256(
  prk: Uint8Array,
  info: string,
  lengthBytes: number,
): Promise<Uint8Array> {
  if (lengthBytes <= 0 || lengthBytes > 255 * 32) throw new Error('hkdfExpand: invalid length');
  const infoBytes = utf8ToBytes(info);
  const out = new Uint8Array(lengthBytes);
  let previous: Uint8Array = new Uint8Array(0);
  let pos = 0;
  let succeeded = false;
  try {
    for (let counter = 1; pos < lengthBytes; counter++) {
      const input = new Uint8Array(previous.length + infoBytes.length + 1);
      input.set(previous, 0);
      input.set(infoBytes, previous.length);
      input[input.length - 1] = counter & 0xff;
      let next: Uint8Array | undefined;
      try {
        next = await hmacSha256(prk, input);
      } finally {
        input.fill(0);
      }
      if (!next) throw new Error('HKDF expansion did not produce a block');
      previous.fill(0);
      previous = next;
      const take = Math.min(previous.length, lengthBytes - pos);
      out.set(previous.subarray(0, take), pos);
      pos += take;
    }
    succeeded = true;
    return out;
  } finally {
    previous.fill(0);
    infoBytes.fill(0);
    if (!succeeded) out.fill(0);
  }
}

export async function aesCbc256Decrypt(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const k = await importAesDecryptKey(key);
  return new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv: iv as BufferSource }, k, data as BufferSource));
}

export async function aesCbc256Encrypt(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const k = await subtle.importKey('raw', key as BufferSource, { name: 'AES-CBC' }, false, ['encrypt']);
  return new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: iv as BufferSource }, k, data as BufferSource));
}

/**
 * RSA-OAEP decrypt. `hash` selects the OAEP hash: SHA-1 for Bitwarden encType 4/6
 * (Rsa2048_OaepSha1*) and SHA-256 for encType 3/5 (Rsa2048_OaepSha256*). privateKey is PKCS8 DER.
 */
export async function rsaOaepDecrypt(
  privateKeyPkcs8: Uint8Array,
  data: Uint8Array,
  hash: 'SHA-1' | 'SHA-256' = 'SHA-1',
): Promise<Uint8Array> {
  if (!(data instanceof Uint8Array) || data.byteLength !== 256) {
    throw new Error('RSA-OAEP ciphertext must contain exactly 256 bytes');
  }
  const key = await importRsa2048OaepPrivateKey(privateKeyPkcs8, hash);
  return new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, key, data as BufferSource));
}

/** Validate a Bitwarden account private key without retaining an extractable CryptoKey. */
export async function validateRsa2048OaepPrivateKey(
  privateKeyPkcs8: Uint8Array,
  hash: 'SHA-1' | 'SHA-256' = 'SHA-1',
): Promise<void> {
  await importRsa2048OaepPrivateKey(privateKeyPkcs8, hash);
}

/** RSA-OAEP encrypt to a public key (SPKI DER). Used to wrap a symmetric key to another party's
 *  public key — e.g. emergency-access grants or organization key sharing. */
export async function rsaOaepEncrypt(
  spkiPublicKey: Uint8Array,
  data: Uint8Array,
  hash: 'SHA-1' | 'SHA-256' = 'SHA-1',
): Promise<Uint8Array> {
  const key = await subtle.importKey('spki', spkiPublicKey as BufferSource, { name: 'RSA-OAEP', hash }, false, ['encrypt']);
  return new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, key, data as BufferSource));
}

async function importRsa2048OaepPrivateKey(
  privateKeyPkcs8: Uint8Array,
  hash: 'SHA-1' | 'SHA-256',
): Promise<CryptoKey> {
  if (
    !(privateKeyPkcs8 instanceof Uint8Array)
    || privateKeyPkcs8.byteLength < 512
    || privateKeyPkcs8.byteLength > 4_096
  ) {
    throw new Error('RSA-OAEP private key PKCS8 length is invalid');
  }
  const key = await subtle.importKey(
    'pkcs8',
    privateKeyPkcs8 as BufferSource,
    { name: 'RSA-OAEP', hash },
    false,
    ['decrypt'],
  );
  const algorithm = key.algorithm as Partial<RsaHashedKeyAlgorithm>;
  if (
    algorithm.name !== 'RSA-OAEP'
    || algorithm.modulusLength !== 2_048
    || algorithm.hash?.name !== hash
    || !(algorithm.publicExponent instanceof Uint8Array)
    || !constantTimeEqual(algorithm.publicExponent, Uint8Array.from([1, 0, 1]))
  ) {
    throw new Error('RSA-OAEP private key must be RSA-2048 with exponent 65537');
  }
  return key;
}
