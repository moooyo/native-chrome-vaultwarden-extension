import { utf8ToBytes } from './encoding.js';

const subtle = globalThis.crypto.subtle;

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
  const k = await subtle.importKey('raw', key as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
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
  for (let counter = 1; pos < lengthBytes; counter++) {
    const input = new Uint8Array(previous.length + infoBytes.length + 1);
    input.set(previous, 0);
    input.set(infoBytes, previous.length);
    input[input.length - 1] = counter & 0xff;
    previous = await hmacSha256(prk, input);
    const take = Math.min(previous.length, lengthBytes - pos);
    out.set(previous.subarray(0, take), pos);
    pos += take;
  }
  return out;
}

export async function aesCbc256Decrypt(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const k = await subtle.importKey('raw', key as BufferSource, { name: 'AES-CBC' }, false, ['decrypt']);
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
  const key = await subtle.importKey(
    'pkcs8',
    privateKeyPkcs8 as BufferSource,
    { name: 'RSA-OAEP', hash },
    false,
    ['decrypt'],
  );
  return new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, key, data as BufferSource));
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
