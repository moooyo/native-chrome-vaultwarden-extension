import { hmacSha256, aesCbc256Decrypt, aesCbc256Encrypt } from './primitives.js';
import { base64ToBytes, bytesToBase64, bytesToUtf8, utf8ToBytes, constantTimeEqual } from './encoding.js';
import type { SymmetricKey } from './keys.js';

export interface ParsedEncString {
  encType: number;
  iv: Uint8Array;
  ct: Uint8Array;
  mac: Uint8Array;
}

/** RSA EncStrings are single-segment `encType.data` (encType 3/4), optionally with a trailing
 *  `|mac` outer HMAC for the HMAC variants (encType 5/6). */
export interface ParsedRsaEncString {
  encType: number;
  data: Uint8Array;
  /** Outer HMAC-SHA256 segment present on encType 5/6. Parsed but not verified — see parseRsaEncString. */
  mac?: Uint8Array;
}

// Rsa2048_OaepSha256_B64=3, Rsa2048_OaepSha1_B64=4, Rsa2048_OaepSha256_HmacSha256_B64=5,
// Rsa2048_OaepSha1_HmacSha256_B64=6.
const RSA_ENC_TYPES = new Set([3, 4, 5, 6]);
const RSA_HMAC_ENC_TYPES = new Set([5, 6]);

export class UnsupportedEncTypeError extends Error {}
export class EncStringMacError extends Error {}

export function parseEncString(value: string): ParsedEncString {
  const dot = value.indexOf('.');
  if (dot < 0) throw new UnsupportedEncTypeError('missing encType prefix');
  const encType = Number(value.slice(0, dot));
  const body = value.slice(dot + 1);
  if (encType !== 2) throw new UnsupportedEncTypeError(`unsupported encType ${encType}`);
  const parts = body.split('|');
  if (parts.length !== 3) throw new UnsupportedEncTypeError('encType=2 requires iv|ct|mac');
  return {
    encType,
    iv: base64ToBytes(parts[0]!),
    ct: base64ToBytes(parts[1]!),
    mac: base64ToBytes(parts[2]!),
  };
}

/**
 * Parse an RSA EncString (encType 3/4/5/6). The first segment is the RSA blob; encType 5/6 add a
 * trailing `|`-separated outer HMAC-SHA256 segment, which is parsed into `mac`.
 *
 * The RSA MAC is intentionally NOT verified: asymmetric (public-key) encryption has no shared MAC
 * key between sender and recipient, so the HMAC cannot be checked the way symmetric Encrypt-then-MAC
 * is — integrity for RSA EncStrings comes from RSA-OAEP padding. This matches upstream Bitwarden,
 * which also does not validate the MAC for RSA encryption types. (Vaultwarden wraps the organization
 * key as encType=4, so the HMAC variants are rare in practice.)
 */
export function parseRsaEncString(value: string): ParsedRsaEncString {
  const dot = value.indexOf('.');
  if (dot < 0) throw new UnsupportedEncTypeError('missing encType prefix');
  const encType = Number(value.slice(0, dot));
  if (Number.isNaN(encType) || !RSA_ENC_TYPES.has(encType)) {
    throw new UnsupportedEncTypeError(`unsupported RSA encType ${value.slice(0, dot)}`);
  }
  const segments = value.slice(dot + 1).split('|');
  const out: ParsedRsaEncString = { encType, data: base64ToBytes(segments[0]!) };
  if (RSA_HMAC_ENC_TYPES.has(encType) && segments.length > 1) {
    out.mac = base64ToBytes(segments[1]!);
  }
  return out;
}

export async function decryptToBytes(value: string, key: SymmetricKey): Promise<Uint8Array> {
  const { iv, ct, mac } = parseEncString(value);
  const macData = new Uint8Array(iv.length + ct.length);
  macData.set(iv, 0);
  macData.set(ct, iv.length);
  const expected = await hmacSha256(key.macKey, macData);
  if (!constantTimeEqual(expected, mac)) throw new EncStringMacError('MAC verification failed');
  return aesCbc256Decrypt(key.encKey, iv, ct);
}

export async function decryptToText(value: string, key: SymmetricKey): Promise<string> {
  return bytesToUtf8(await decryptToBytes(value, key));
}

/**
 * Build an encType=2 (AesCbc256_HmacSha256_B64) EncString: AES-256-CBC encrypt with a fresh random
 * IV, then HMAC-SHA256 over `iv ‖ ct` (Encrypt-then-MAC). The IV is injectable for deterministic
 * tests; production always uses a fresh `crypto.getRandomValues` IV.
 */
export async function encryptToBytes(
  plaintext: Uint8Array,
  key: SymmetricKey,
  iv: Uint8Array = randomIv(),
): Promise<string> {
  const ct = await aesCbc256Encrypt(key.encKey, iv, plaintext);
  const macData = new Uint8Array(iv.length + ct.length);
  macData.set(iv, 0);
  macData.set(ct, iv.length);
  const mac = await hmacSha256(key.macKey, macData);
  return `2.${bytesToBase64(iv)}|${bytesToBase64(ct)}|${bytesToBase64(mac)}`;
}

export async function encryptToText(plaintext: string, key: SymmetricKey, iv?: Uint8Array): Promise<string> {
  return iv ? encryptToBytes(utf8ToBytes(plaintext), key, iv) : encryptToBytes(utf8ToBytes(plaintext), key);
}

function randomIv(): Uint8Array {
  const iv = new Uint8Array(16);
  globalThis.crypto.getRandomValues(iv);
  return iv;
}
