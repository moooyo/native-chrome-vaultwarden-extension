// FIDO2 / WebAuthn assertion signing for stored passkeys. Given a credential's PKCS#8 private key
// (ECDSA P-256, alg -7) the worker produces a WebAuthn `navigator.credentials.get()` assertion:
// authenticatorData ‖ SHA-256(clientDataJSON) signed with ES256, DER-encoded as WebAuthn requires.

import { bytesToBase64Url, utf8ToBytes } from '../crypto/encoding.js';
import { FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS, sha256, buildClientDataJSON } from './fido2-common.js';

const subtle = globalThis.crypto.subtle;

export interface AssertionParams {
  rpId: string;
  origin: string;
  /** Challenge as base64url (passed through verbatim into clientDataJSON). */
  challenge: string;
  counter?: number;
  userVerified?: boolean;
}

export interface AssertionResult {
  authenticatorData: string; // base64url
  clientDataJSON: string;    // base64url
  signature: string;         // base64url, DER-encoded ECDSA signature
}

/** An assertion plus the credential identifiers the page needs to build a PublicKeyCredential. */
export interface PasskeyAssertion extends AssertionResult {
  credentialId: string; // base64url
  userHandle?: string;  // base64url
}

// Authenticator data flags live in fido2-common (FLAG_*); each path composes its own flag set. Vault
// passkeys are synced (cloud-backed) → BE and BS are set on every ceremony.

/** authenticatorData = SHA-256(rpId) ‖ flags ‖ signCount(uint32 big-endian). No attested cred data for get(). */
export async function buildAuthenticatorData(rpId: string, flags: number, signCount: number): Promise<Uint8Array> {
  const rpIdHash = await sha256(utf8ToBytes(rpId));
  const out = new Uint8Array(37);
  out.set(rpIdHash, 0);
  out[32] = flags & 0xff;
  out[33] = (signCount >>> 24) & 0xff;
  out[34] = (signCount >>> 16) & 0xff;
  out[35] = (signCount >>> 8) & 0xff;
  out[36] = signCount & 0xff;
  return out;
}

/** Sign a WebAuthn assertion with a stored passkey private key (PKCS#8, ECDSA P-256). */
export async function signFido2Assertion(pkcs8: Uint8Array, params: AssertionParams): Promise<AssertionResult> {
  const key = await subtle.importKey('pkcs8', pkcs8 as BufferSource, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const flags = FLAG_UP | FLAG_BE | FLAG_BS | (params.userVerified ? FLAG_UV : 0);
  const authData = await buildAuthenticatorData(params.rpId, flags, params.counter ?? 0);
  const clientDataJSON = buildClientDataJSON('webauthn.get', params.challenge, params.origin);
  const clientDataBytes = utf8ToBytes(clientDataJSON);
  const signedData = new Uint8Array([...authData, ...(await sha256(clientDataBytes))]);
  const rawSig = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, signedData as BufferSource));
  return {
    authenticatorData: bytesToBase64Url(authData),
    clientDataJSON: bytesToBase64Url(clientDataBytes),
    signature: bytesToBase64Url(rawToDerSignature(rawSig)),
  };
}

/** Convert a raw ECDSA signature (r‖s, 64 bytes) to the DER SEQUENCE WebAuthn expects. */
export function rawToDerSignature(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const r = derInteger(raw.slice(0, half));
  const s = derInteger(raw.slice(half));
  const body = new Uint8Array([0x02, r.length, ...r, 0x02, s.length, ...s]);
  return new Uint8Array([0x30, body.length, ...body]);
}

/** Convert a DER ECDSA signature back to raw r‖s (32+32). Useful for verification/tests. Validates the
 *  minimal DER shape a P-256 signature must have — SEQUENCE of two INTEGERs, all definite single-byte
 *  lengths (r/s are ≤ 33 bytes, well under the 0x80 multi-byte threshold) — so a malformed blob throws
 *  instead of silently producing garbage from a clamped slice. */
export function derToRawSignature(der: Uint8Array): Uint8Array {
  if (der[0] !== 0x30) throw new Error('invalid DER signature'); // SEQUENCE tag
  const seqLen = der[1]!;
  if (seqLen & 0x80) throw new Error('invalid DER signature'); // multi-byte/indefinite length
  let i = 2;
  if (der[i] !== 0x02) throw new Error('invalid DER signature'); // INTEGER (r)
  const rLen = der[i + 1]!;
  if (rLen & 0x80 || i + 2 + rLen > der.length) throw new Error('invalid DER signature');
  const r = der.slice(i + 2, i + 2 + rLen);
  i = i + 2 + rLen;
  if (der[i] !== 0x02) throw new Error('invalid DER signature'); // INTEGER (s)
  const sLen = der[i + 1]!;
  if (sLen & 0x80 || i + 2 + sLen > der.length) throw new Error('invalid DER signature');
  const s = der.slice(i + 2, i + 2 + sLen);
  const out = new Uint8Array(64);
  out.set(leftPadOrTrim(r, 32), 0);
  out.set(leftPadOrTrim(s, 32), 32);
  return out;
}

/** DER integer encoding: strip leading zeros, then prepend 0x00 if the high bit is set (keep positive). */
function derInteger(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0x00) start++;
  const trimmed = bytes.slice(start);
  return (trimmed[0]! & 0x80) ? new Uint8Array([0x00, ...trimmed]) : trimmed;
}

function leftPadOrTrim(bytes: Uint8Array, size: number): Uint8Array {
  if (bytes.length === size) return bytes;
  if (bytes.length > size) return bytes.slice(bytes.length - size); // drop a leading 0x00
  const out = new Uint8Array(size);
  out.set(bytes, size - bytes.length);
  return out;
}
