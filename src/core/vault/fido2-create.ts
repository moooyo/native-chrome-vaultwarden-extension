// FIDO2 / WebAuthn REGISTRATION (navigator.credentials.create) for vault-stored passkeys. Generates an
// ES256 (P-256) keypair in the worker, builds the attestationObject (COSE public key + attested
// authenticator data, fmt="none"), and encrypts the credential for storage. The private key never
// leaves the worker; only the public attestation is returned to the page.
import { base64UrlToBytes, bytesToBase64Url, utf8ToBytes } from '../crypto/encoding.js';
import { cborBytes, cborMap, cborNegInt, cborText, cborUint } from '../crypto/cbor.js';
import { encryptToText } from '../crypto/encstring.js';
import { FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS, FLAG_AT, sha256, buildClientDataJSON } from './fido2-common.js';
import type { SymmetricKey } from '../crypto/keys.js';
import type { Fido2CredentialData } from '../api/types.js';
import { isIsoTimestamp } from './iso-date.js';
import {
  MAX_PASSKEY_CHALLENGE_BYTES,
  MAX_PASSKEY_CREDENTIAL_DESCRIPTORS,
  MAX_PASSKEY_CREDENTIAL_ID_BYTES,
  MAX_PASSKEY_USER_HANDLE_BYTES,
} from './fido2-limits.js';

export {
  MAX_PASSKEY_CHALLENGE_BYTES,
  MAX_PASSKEY_CREDENTIAL_DESCRIPTORS,
  MAX_PASSKEY_CREDENTIAL_ID_BYTES,
  MAX_PASSKEY_USER_HANDLE_BYTES,
} from './fido2-limits.js';

const subtle = globalThis.crypto.subtle;

export type PasskeyResidentKeyRequirement = 'discouraged' | 'preferred' | 'required';
export type PasskeyAuthenticatorAttachment = 'platform' | 'cross-platform';

export interface PasskeyCreateRequest {
  readonly rpId: string;
  readonly rpName?: string;
  readonly userHandle?: string;
  readonly userName?: string;
  readonly userDisplayName?: string;
  readonly challenge: string;
  readonly origin: string;
  readonly targetCipherId?: string;
  readonly residentKey?: PasskeyResidentKeyRequirement;
  readonly requireResidentKey?: boolean;
  readonly excludeCredentialIds?: readonly string[];
  readonly authenticatorAttachment?: PasskeyAuthenticatorAttachment;
  /** Legacy, untrusted transport input. Vault-backed ceremonies intentionally ignore it. */
  readonly userVerified?: unknown;
  /** Browser-owned ancestor-lineage result. Never derive this from page options. */
  readonly crossOrigin?: boolean;
}

export type PasskeyCredentialSelection =
  | { readonly mode: 'resident'; readonly credentialIds: readonly string[] }
  | { readonly mode: 'allow-list'; readonly credentialIds: readonly string[] };

export interface PasskeyResidentSelection {
  readonly residentKey: PasskeyResidentKeyRequirement;
  readonly requireResidentKey: boolean;
  readonly discoverable: boolean;
}

export type PasskeyCreationRoute =
  | { readonly kind: 'vault' }
  | { readonly kind: 'native-fallback'; readonly reason: 'cross-platform-authenticator' };

/** Hardware-only requests stay with the browser/native authenticator. */
export function decidePasskeyCreationRoute(
  attachment: PasskeyAuthenticatorAttachment | undefined,
): PasskeyCreationRoute {
  if (attachment === undefined || attachment === 'platform') {
    return Object.freeze({ kind: 'vault' });
  }
  if (attachment === 'cross-platform') {
    return Object.freeze({ kind: 'native-fallback', reason: 'cross-platform-authenticator' });
  }
  throw new TypeError('Unsupported authenticator attachment');
}

export function normalizePasskeyResidentSelection(
  residentKey: PasskeyResidentKeyRequirement | undefined,
  requireResidentKey: boolean | undefined,
): PasskeyResidentSelection {
  if (residentKey !== undefined
    && residentKey !== 'discouraged'
    && residentKey !== 'preferred'
    && residentKey !== 'required') {
    throw new TypeError('Invalid residentKey requirement');
  }
  if (requireResidentKey !== undefined && typeof requireResidentKey !== 'boolean') {
    throw new TypeError('Invalid requireResidentKey value');
  }
  const normalizedResidentKey = requireResidentKey === true
    ? 'required'
    : residentKey ?? 'discouraged';
  const normalizedRequireResidentKey = normalizedResidentKey === 'required';
  return Object.freeze({
    residentKey: normalizedResidentKey,
    requireResidentKey: normalizedRequireResidentKey,
    discoverable: normalizedResidentKey !== 'discouraged',
  });
}

/** Undefined and empty allow lists are resident lookups; non-empty lists are exact-ID lookups. */
export function normalizePasskeyCredentialSelection(
  credentialIds: readonly string[] | undefined,
): PasskeyCredentialSelection {
  const normalized = normalizeCredentialIds(credentialIds, false);
  return normalized.length === 0
    ? Object.freeze({ mode: 'resident', credentialIds: Object.freeze([]) })
    : Object.freeze({ mode: 'allow-list', credentialIds: normalized });
}

/** excludeCredentials originates as binary WebAuthn IDs and therefore must be canonical base64url. */
export function normalizePasskeyExcludeCredentialIds(
  credentialIds: readonly string[] | undefined,
): readonly string[] {
  return normalizeCredentialIds(credentialIds, true);
}

export function normalizePasskeyUserHandle(userHandle: string | undefined): string | undefined {
  if (userHandle === undefined) return undefined;
  validateCanonicalBase64Url(userHandle, 1, MAX_PASSKEY_USER_HANDLE_BYTES, 'userHandle');
  return userHandle;
}

export function normalizePasskeyChallenge(challenge: string): string {
  validateCanonicalBase64Url(challenge, 1, MAX_PASSKEY_CHALLENGE_BYTES, 'challenge');
  return challenge;
}

export interface GeneratedFido2Keypair {
  pkcs8: Uint8Array;        // private key (PKCS#8) — stays in the worker
  coseKey: Uint8Array;      // public key as a COSE_Key (CBOR)
  credentialId: Uint8Array; // 16 random bytes
  publicKeySpki: Uint8Array; // public key as SPKI DER (for the page's getPublicKey())
}

export async function generateFido2Keypair(): Promise<GeneratedFido2Keypair> {
  let pkcs8: Uint8Array | undefined;
  let raw: Uint8Array | undefined;
  let ownershipTransferred = false;
  try {
    const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey));
    raw = new Uint8Array(await subtle.exportKey('raw', kp.publicKey)); // 0x04 || x(32) || y(32)
    const x = raw.subarray(1, 33), y = raw.subarray(33, 65);
    const coseKey = new Uint8Array(cborMap([
      [...cborUint(1), ...cborUint(2)],     // kty: EC2
      [...cborUint(3), ...cborNegInt(-7)],  // alg: ES256
      [...cborNegInt(-1), ...cborUint(1)],  // crv: P-256
      [...cborNegInt(-2), ...cborBytes(x)], // x
      [...cborNegInt(-3), ...cborBytes(y)], // y
    ]));
    const publicKeySpki = new Uint8Array(await subtle.exportKey('spki', kp.publicKey));
    const credentialId = crypto.getRandomValues(new Uint8Array(16));
    ownershipTransferred = true;
    return { pkcs8, coseKey, credentialId, publicKeySpki };
  } finally {
    raw?.fill(0);
    if (!ownershipTransferred) pkcs8?.fill(0);
  }
}

export async function buildAttestationObject(params: {
  rpId: string; coseKey: Uint8Array; credentialId: Uint8Array; userVerified: boolean;
}): Promise<{ attestationObject: Uint8Array; authData: Uint8Array }> {
  const rpIdHash = await sha256(utf8ToBytes(params.rpId));
  const flags = FLAG_UP | FLAG_AT | FLAG_BE | FLAG_BS | (params.userVerified ? FLAG_UV : 0);
  const credLen = params.credentialId.length;
  const attestedCredData = new Uint8Array([
    ...new Uint8Array(16),                 // AAGUID (all zero)
    (credLen >> 8) & 0xff, credLen & 0xff, // credentialIdLength, uint16 big-endian
    ...params.credentialId,
    ...params.coseKey,
  ]);
  const authData = new Uint8Array([...rpIdHash, flags, 0, 0, 0, 0, ...attestedCredData]);
  const attestationObject = new Uint8Array(cborMap([
    [...cborText('fmt'), ...cborText('none')],
    [...cborText('attStmt'), ...cborMap([])],
    [...cborText('authData'), ...cborBytes(authData)],
  ]));
  return { attestationObject, authData };
}

export function buildCreateClientDataJSON(
  challenge: string,
  origin: string,
  crossOrigin = false,
): string {
  return buildClientDataJSON('webauthn.create', challenge, origin, crossOrigin);
}

export interface NewFido2Credential {
  credentialId: string; keyValue: string; rpId: string; counter: number;
  discoverable: boolean; creationDate: string;
  userHandle?: string; userName?: string; rpName?: string; userDisplayName?: string;
}

/** Encrypt a freshly generated credential into the server's Fido2CredentialData shape (all EncStrings)
 *  under the given key (account UserKey for a new personal cipher, or the target cipher's field key). */
export async function encryptFido2Credential(cred: NewFido2Credential, key: SymmetricKey): Promise<Fido2CredentialData> {
  if (!isIsoTimestamp(cred.creationDate)
    || new Date(cred.creationDate).toISOString() !== cred.creationDate) {
    throw new TypeError('Passkey creationDate must be a canonical UTC ISO timestamp');
  }
  const enc = (v: string) => encryptToText(v, key);
  const opt = async (v: string | undefined) => (v ? await enc(v) : null);
  return {
    credentialId: await enc(cred.credentialId),
    keyType: await enc('public-key'),
    keyAlgorithm: await enc('ECDSA'),
    keyCurve: await enc('P-256'),
    keyValue: await enc(cred.keyValue),
    rpId: await enc(cred.rpId),
    userHandle: await opt(cred.userHandle),
    userName: await opt(cred.userName),
    counter: await enc(String(cred.counter)),
    rpName: await opt(cred.rpName),
    userDisplayName: await opt(cred.userDisplayName),
    discoverable: await enc(cred.discoverable ? 'true' : 'false'),
    creationDate: cred.creationDate,
  };
}

function normalizeCredentialIds(
  value: readonly string[] | undefined,
  requireCanonical: boolean,
): readonly string[] {
  if (value === undefined) return Object.freeze([]);
  if (!Array.isArray(value) || value.length > MAX_PASSKEY_CREDENTIAL_DESCRIPTORS) {
    throw new TypeError('Invalid passkey credential descriptor list');
  }
  const unique = new Set<string>();
  for (const credentialId of value) {
    if (
      typeof credentialId !== 'string'
      || credentialId.length === 0
      || credentialId.length > 1_364
      || !/^[A-Za-z0-9_-]+$/.test(credentialId)
    ) {
      throw new TypeError('Invalid passkey credential ID');
    }
    if (requireCanonical) {
      validateCanonicalBase64Url(
        credentialId,
        1,
        MAX_PASSKEY_CREDENTIAL_ID_BYTES,
        'credential ID',
      );
    }
    unique.add(credentialId);
  }
  return Object.freeze([...unique]);
}

function validateCanonicalBase64Url(
  value: string,
  minimumBytes: number,
  maximumBytes: number,
  label: string,
): void {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TypeError(`Invalid ${label}`);
  }
  let bytes: Uint8Array | undefined;
  try {
    bytes = base64UrlToBytes(value);
    if (
      bytes.byteLength < minimumBytes
      || bytes.byteLength > maximumBytes
      || bytesToBase64Url(bytes) !== value
    ) {
      throw new TypeError(`Invalid ${label}`);
    }
  } catch (error) {
    if (error instanceof TypeError) throw error;
    throw new TypeError(`Invalid ${label}`, { cause: error });
  } finally {
    bytes?.fill(0);
  }
}

export { bytesToBase64Url };
