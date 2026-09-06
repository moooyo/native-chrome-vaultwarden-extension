// A deterministic, position-sensitive payload detects missing, reordered, or altered chunks.
export function fillPayload(bytes, offset = 0) {
  for (let index = 0; index < bytes.length; index += 1) {
    const position = offset + index;
    const markerByte = position & 0xffff;
    // Prefix every 64 KiB region with its absolute region index. Full transport chunks therefore
    // differ even when their remaining byte pattern repeats, so chunk reuse changes the digest.
    bytes[index] = markerByte < 4
      ? ((position >>> 16) >>> (markerByte * 8)) & 255
      : ((position * 31) ^ (position >>> 8) ^ 0xa5) & 255;
  }
  return bytes;
}

export async function digestBytes(bytes) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, '0')).join('');
}
