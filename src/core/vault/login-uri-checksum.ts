import {
  bytesToBase64,
  constantTimeEqual,
  utf8ToBytes,
} from '../crypto/encoding.js';

/** Standard padded Base64 of SHA-256(UTF-8(uri)), matching Bitwarden LoginUri checksum semantics. */
export async function computeLoginUriChecksum(uri: string): Promise<string> {
  const uriBytes = utf8ToBytes(uri);
  let digest: Uint8Array | undefined;
  try {
    digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', uriBytes as BufferSource));
    return bytesToBase64(digest);
  } finally {
    uriBytes.fill(0);
    digest?.fill(0);
  }
}

/** Compare a decrypted checksum without accepting non-canonical Base64 spellings. */
export async function validateLoginUriChecksum(uri: string, checksum: string): Promise<boolean> {
  const expected = await computeLoginUriChecksum(uri);
  const expectedBytes = utf8ToBytes(expected);
  const actualBytes = utf8ToBytes(checksum);
  try {
    return constantTimeEqual(expectedBytes, actualBytes);
  } finally {
    expectedBytes.fill(0);
    actualBytes.fill(0);
  }
}
