// Shared FIDO2 / WebAuthn primitives used by both the assertion (get) and registration (create) paths:
// the authenticator-data flag bits, SHA-256, and the clientDataJSON builder. Each path composes its own
// flags at the call site (get() omits AT; create() sets it) and passes its ceremony `type` here.

const subtle = globalThis.crypto.subtle;

// Authenticator data flags (WebAuthn §6.1): UP=user present, UV=user verified, BE=backup eligible,
// BS=backup state, AT=attested credential data included (registration only). Vault passkeys are synced
// (cloud-backed) → BE and BS are set on every ceremony.
export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;
export const FLAG_BS = 0x10;
export const FLAG_AT = 0x40;

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', data as BufferSource));
}

/** Build a WebAuthn clientDataJSON. Property order matches what browsers emit; challenge stays base64url. */
export function buildClientDataJSON(type: 'webauthn.get' | 'webauthn.create', challenge: string, origin: string): string {
  return JSON.stringify({ type, challenge, origin, crossOrigin: false });
}
