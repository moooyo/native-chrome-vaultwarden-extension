// FIDO2 / WebAuthn REGISTRATION (navigator.credentials.create) for vault-stored passkeys. Generates an
// ES256 (P-256) keypair in the worker, builds the attestationObject (COSE public key + attested
// authenticator data, fmt="none"), and encrypts the credential for storage. The private key never
// leaves the worker; only the public attestation is returned to the page.
import { bytesToBase64Url, utf8ToBytes } from '../crypto/encoding.js';
import { cborBytes, cborMap, cborNegInt, cborText, cborUint } from '../crypto/cbor.js';
import { encryptToText } from '../crypto/encstring.js';
import { FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS, FLAG_AT, sha256, buildClientDataJSON } from './fido2-common.js';
import type { SymmetricKey } from '../crypto/keys.js';
import type { Fido2CredentialData } from '../api/types.js';

const subtle = globalThis.crypto.subtle;

export interface GeneratedFido2Keypair {
  pkcs8: Uint8Array;        // private key (PKCS#8) — stays in the worker
  coseKey: Uint8Array;      // public key as a COSE_Key (CBOR)
  credentialId: Uint8Array; // 16 random bytes
  publicKeySpki: Uint8Array; // public key as SPKI DER (for the page's getPublicKey())
}

export async function generateFido2Keypair(): Promise<GeneratedFido2Keypair> {
  const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey));
  const raw = new Uint8Array(await subtle.exportKey('raw', kp.publicKey)); // 0x04 || x(32) || y(32)
  const x = raw.slice(1, 33), y = raw.slice(33, 65);
  const coseKey = new Uint8Array(cborMap([
    [...cborUint(1), ...cborUint(2)],     // kty: EC2
    [...cborUint(3), ...cborNegInt(-7)],  // alg: ES256
    [...cborNegInt(-1), ...cborUint(1)],  // crv: P-256
    [...cborNegInt(-2), ...cborBytes(x)], // x
    [...cborNegInt(-3), ...cborBytes(y)], // y
  ]));
  const publicKeySpki = new Uint8Array(await subtle.exportKey('spki', kp.publicKey));
  const credentialId = crypto.getRandomValues(new Uint8Array(16));
  return { pkcs8, coseKey, credentialId, publicKeySpki };
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

export function buildCreateClientDataJSON(challenge: string, origin: string): string {
  return buildClientDataJSON('webauthn.create', challenge, origin);
}

export interface NewFido2Credential {
  credentialId: string; keyValue: string; rpId: string; counter: number;
  userHandle?: string; userName?: string; rpName?: string; userDisplayName?: string;
}

/** Encrypt a freshly generated credential into the server's Fido2CredentialData shape (all EncStrings)
 *  under the given key (account UserKey for a new personal cipher, or the target cipher's field key). */
export async function encryptFido2Credential(cred: NewFido2Credential, key: SymmetricKey): Promise<Fido2CredentialData> {
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
    discoverable: await enc('true'),
  };
}

export { bytesToBase64Url };
