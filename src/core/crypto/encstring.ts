import { hmacSha256, aesCbc256Decrypt } from './primitives.js';
import { base64ToBytes, bytesToUtf8, constantTimeEqual } from './encoding.js';
import type { SymmetricKey } from './keys.js';

export interface ParsedEncString {
  encType: number;
  iv: Uint8Array;
  ct: Uint8Array;
  mac: Uint8Array;
}

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
