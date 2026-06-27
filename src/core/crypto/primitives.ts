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

export async function hkdfExpandSha256(
  prk: Uint8Array,
  info: string,
  lengthBytes: number,
): Promise<Uint8Array> {
  if (lengthBytes > 32) throw new Error('hkdfExpand: only single-block (<=32B) supported');
  const infoBytes = utf8ToBytes(info);
  const input = new Uint8Array(infoBytes.length + 1);
  input.set(infoBytes, 0);
  input[infoBytes.length] = 0x01;
  return (await hmacSha256(prk, input)).slice(0, lengthBytes);
}

export async function aesCbc256Decrypt(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const k = await subtle.importKey('raw', key as BufferSource, { name: 'AES-CBC' }, false, ['decrypt']);
  return new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv: iv as BufferSource }, k, data as BufferSource));
}
