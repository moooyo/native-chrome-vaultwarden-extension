const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8ToBytes(s: string): Uint8Array {
  return encoder.encode(s);
}

export function bytesToUtf8(b: Uint8Array): string {
  return decoder.decode(b);
}

export function bytesToBase64(b: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < b.length; i++) binary += String.fromCharCode(b[i]!);
  return btoa(binary);
}

export function base64ToBytes(s: string): Uint8Array {
  const binary = atob(s);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
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
    const byte = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error('invalid hex byte');
    out[i] = byte;
  }
  return out;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
