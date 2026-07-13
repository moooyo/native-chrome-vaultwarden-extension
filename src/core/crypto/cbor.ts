// Minimal CBOR (RFC 8949) encoder — only the shapes WebAuthn attestation needs: unsigned ints,
// negative ints, byte strings, text strings, and definite-length maps. Plus a small decoder used
// by tests/self-verification. NOT a general-purpose CBOR library.
import { utf8ToBytes } from './encoding.js';

function head(major: number, value: number): number[] {
  const mt = major << 5;
  if (value < 24) return [mt | value];
  if (value < 0x100) return [mt | 24, value];
  if (value < 0x10000) return [mt | 25, (value >> 8) & 0xff, value & 0xff];
  return [mt | 26, (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
}

export function cborUint(n: number): number[] { return head(0, n); }
/** CBOR negative integer. `n` is the negative value itself (e.g. -7); encoded arg is (-1 - n). */
export function cborNegInt(n: number): number[] { return head(1, -1 - n); }
export function cborBytes(b: Uint8Array): number[] { return [...head(2, b.length), ...b]; }
export function cborText(s: string): number[] { const b = utf8ToBytes(s); return [...head(3, b.length), ...b]; }
/** Definite-length map. `pairs` are already-encoded [..key, ..value] byte arrays; caller supplies
 *  keys in canonical order. */
export function cborMap(pairs: number[][]): number[] {
  const out = head(5, pairs.length);
  for (const p of pairs) out.push(...p);
  return out;
}

/** Minimal decoder for the subset we encode. Byte strings → Uint8Array; maps → Map. Test/verify only. */
export function cborDecode(bytes: Uint8Array): unknown {
  let i = 0;
  function readArg(ai: number): number {
    if (ai < 24) return ai;
    if (ai === 24) return bytes[i++]!;
    if (ai === 25) { const v = (bytes[i]! << 8) | bytes[i + 1]!; i += 2; return v; }
    if (ai === 26) { const v = ((bytes[i]! << 24) | (bytes[i + 1]! << 16) | (bytes[i + 2]! << 8) | bytes[i + 3]!) >>> 0; i += 4; return v; }
    throw new Error('unsupported cbor arg');
  }
  function read(): unknown {
    const b = bytes[i++]!;
    const major = b >> 5;
    const ai = b & 0x1f;
    if (major === 0) return readArg(ai);
    if (major === 1) return -1 - readArg(ai);
    if (major === 2) { const len = readArg(ai); const v = bytes.slice(i, i + len); i += len; return v; }
    if (major === 3) { const len = readArg(ai); const v = new TextDecoder().decode(bytes.slice(i, i + len)); i += len; return v; }
    if (major === 5) { const n = readArg(ai); const m = new Map<unknown, unknown>(); for (let k = 0; k < n; k++) { const key = read(); m.set(key, read()); } return m; }
    throw new Error('unsupported cbor major type ' + major);
  }
  return read();
}
