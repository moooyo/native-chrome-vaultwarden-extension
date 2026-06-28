// Emergency access — cryptographic core. A grantor shares their account UserKey with a trusted
// grantee by wrapping it to the grantee's RSA public key (encType=4, like organization key sharing).
// After the server's grant/accept/confirm/request/approve flow, the grantee recovers the UserKey
// with their private key and can read (or take over) the grantor's vault.
//
// The full multi-party server protocol (/emergency-access endpoints) and UI are NOT implemented here;
// this module is the reusable key-grant primitive that the flow is built on. See docs/tech-debt.md.

import { rsaOaepEncrypt } from '../crypto/primitives.js';
import { unwrapRsaWrappedKey, type SymmetricKey } from '../crypto/keys.js';
import { bytesToBase64 } from '../crypto/encoding.js';

/** Wrap a 64-byte UserKey to the grantee's RSA public key (SPKI DER) as an encType=4 EncString. */
export async function grantEmergencyKey(userKey: SymmetricKey, granteePublicKeySpki: Uint8Array): Promise<string> {
  const raw = new Uint8Array(64);
  raw.set(userKey.encKey, 0);
  raw.set(userKey.macKey, 32);
  const ciphertext = await rsaOaepEncrypt(granteePublicKeySpki, raw);
  return `4.${bytesToBase64(ciphertext)}`;
}

/** Recover a granted UserKey using the grantee's RSA private key (PKCS#8 DER). */
export async function recoverEmergencyKey(wrapped: string, granteePrivateKeyPkcs8: Uint8Array): Promise<SymmetricKey> {
  return unwrapRsaWrappedKey(wrapped, granteePrivateKeyPkcs8);
}
