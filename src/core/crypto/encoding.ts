const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8ToBytes(s: string): Uint8Array {
  return encoder.encode(s);
}

export function bytesToUtf8(b: Uint8Array): string {
  return decoder.decode(b);
}

export function bytesToBase64(b: Uint8Array): string {
  // Fast path: native, C++-backed base64 (Uint8Array#toBase64). Byte-identical
  // standard base64 to the btoa fallback below, but without the O(n) JS string churn.
  const nativeToBase64 = (b as { toBase64?: () => string }).toBase64;
  if (typeof nativeToBase64 === 'function') return nativeToBase64.call(b);
  // Fallback: build the Latin1 string in 32 KiB chunks (fromCharCode.apply caps out
  // on the argument count), then btoa. Avoids per-byte string concatenation.
  let binary = '';
  for (let i = 0; i < b.length; i += 0x8000) {
    binary += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000) as unknown as number[]);
  }
  return btoa(binary);
}

export function base64ToBytes(s: string): Uint8Array {
  let binary: string;
  try {
    binary = atob(s);
  } catch {
    throw new Error('invalid base64');
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Encode bytes as unpadded base64url (RFC 4648 §5), as used by WebAuthn/FIDO2. */
export function bytesToBase64Url(b: Uint8Array): string {
  return bytesToBase64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decode unpadded or padded base64url into bytes. */
export function base64UrlToBytes(s: string): Uint8Array {
  const base = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base.length % 4;
  return base64ToBytes(pad ? base + '='.repeat(4 - pad) : base);
}

export function bytesToHex(b: Uint8Array): string {
  let out = '';
  for (let i = 0; i < b.length; i++) out += b[i]!.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(h: string): Uint8Array {
  if (h.length % 2 !== 0) throw new Error('invalid hex length');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const pair = h.slice(i * 2, i * 2 + 2);
    // Validate that both characters are hex digits (0-9, a-f, A-F)
    if (!/^[0-9a-fA-F]{2}$/.test(pair)) throw new Error('invalid hex byte');
    out[i] = Number.parseInt(pair, 16);
  }
  return out;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
