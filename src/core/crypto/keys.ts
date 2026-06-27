export type SymmetricKey = { encKey: Uint8Array; macKey: Uint8Array };

export function symmetricKeyFromBytes(bytes: Uint8Array): SymmetricKey {
  if (bytes.length !== 64) {
    throw new Error(`symmetric key must be 64 bytes, got ${bytes.length}`);
  }
  return { encKey: bytes.slice(0, 32), macKey: bytes.slice(32, 64) };
}
