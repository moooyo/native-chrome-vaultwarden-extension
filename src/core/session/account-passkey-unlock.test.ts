import { describe, expect, it } from 'vitest';
import {
  bytesToBase64,
  bytesToHex,
  hexToBytes,
} from '../crypto/encoding.js';
import { encryptToBytes } from '../crypto/encstring.js';
import { serializeSymmetricKey } from '../crypto/keys.js';
import { rsaOaepEncrypt } from '../crypto/primitives.js';
import {
  deriveAccountPasskeyPrfKey,
  recoverAccountPasskeyPrfUnlockMaterial,
} from './account-passkey-unlock.js';
import {
  RSA_PRIVATE_KEY_VECTOR,
  USER_KEY_VECTOR,
} from '../../../test/vectors.js';

const CREDENTIAL_ID = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc';

describe('account passkey PRF unlock', () => {
  it('derives the official enc and mac HKDF labels without mutating the PRF result', async () => {
    const prfOutput = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const before = bytesToHex(prfOutput);
    const prfKey = await deriveAccountPasskeyPrfKey(prfOutput);
    try {
      expect(bytesToHex(prfKey.encKey))
        .toBe('9c5639fac602366b486253191cb7900d7d8e3a1514676b118d5803a11dd97213');
      expect(bytesToHex(prfKey.macKey))
        .toBe('cce388b4ac0f05edee78d40dcbe78a7715640de75ed9ba06942fb42398d6b1f1');
      expect(bytesToHex(prfOutput)).toBe(before);
    } finally {
      prfKey.encKey.fill(0);
      prfKey.macKey.fill(0);
      prfOutput.fill(0);
    }
  });

  it('rejects the authenticator all-zero sentinel', async () => {
    await expect(deriveAccountPasskeyPrfKey(new Uint8Array(32))).rejects.toThrow(/all zero|non-zero/u);
  });

  it.each([3, 4] as const)(
    'recovers a validated UserKey and account private key through encType=%s RSA-OAEP',
    async (encType) => {
      const fixture = await prfUnlockFixture(encType);
      const material = await recoverAccountPasskeyPrfUnlockMaterial({
        prfOutput: fixture.prfOutput,
        option: fixture.option,
        encPrivateKey: RSA_PRIVATE_KEY_VECTOR.encPrivateKey,
      });
      let rawUserKey: Uint8Array | undefined;
      try {
        rawUserKey = serializeSymmetricKey(material.userKey);
        expect(bytesToHex(rawUserKey))
          .toBe(USER_KEY_VECTOR.userKeyHex);
        expect(bytesToBase64(material.privateKey)).toBe(RSA_PRIVATE_KEY_VECTOR.pkcs8B64);
      } finally {
        rawUserKey?.fill(0);
        fixture.prfOutput.fill(0);
        material.userKey.encKey.fill(0);
        material.userKey.macKey.fill(0);
        material.privateKey.fill(0);
      }
    },
  );

  it('fails closed when the authoritative credential key cannot unwrap the UserKey', async () => {
    const fixture = await prfUnlockFixture(4);
    const other = await prfUnlockFixture(4);
    try {
      await expect(recoverAccountPasskeyPrfUnlockMaterial({
        prfOutput: fixture.prfOutput,
        option: { ...fixture.option, encryptedUserKey: other.option.encryptedUserKey },
        encPrivateKey: RSA_PRIVATE_KEY_VECTOR.encPrivateKey,
      })).rejects.toThrow();
    } finally {
      fixture.prfOutput.fill(0);
      other.prfOutput.fill(0);
    }
  });
});

async function prfUnlockFixture(encType: 3 | 4) {
  const hash: 'SHA-1' | 'SHA-256' = encType === 3 ? 'SHA-256' : 'SHA-1';
  const prfOutput = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const prfKey = await deriveAccountPasskeyPrfKey(prfOutput);
  const rawUserKey = hexToBytes(USER_KEY_VECTOR.userKeyHex);
  let credentialPrivateKey: Uint8Array | undefined;
  let wrappedUserKey: Uint8Array | undefined;
  try {
    const pair = await crypto.subtle.generateKey({
      name: 'RSA-OAEP',
      modulusLength: 2_048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash,
    }, true, ['encrypt', 'decrypt']);
    credentialPrivateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    try {
      wrappedUserKey = await rsaOaepEncrypt(publicKey, rawUserKey, hash);
    } finally {
      publicKey.fill(0);
    }
    if (!credentialPrivateKey || !wrappedUserKey) throw new Error('RSA fixture generation failed');
    const encryptedPrivateKey = await encryptToBytes(
      credentialPrivateKey,
      prfKey,
      new Uint8Array(16).fill(3),
    );
    return {
      prfOutput,
      option: {
        encryptedPrivateKey,
        encryptedUserKey: `${encType}.${bytesToBase64(wrappedUserKey)}`,
        credentialId: CREDENTIAL_ID,
        transports: ['internal' as const],
      },
    };
  } catch (error) {
    prfOutput.fill(0);
    throw error;
  } finally {
    prfKey.encKey.fill(0);
    prfKey.macKey.fill(0);
    rawUserKey.fill(0);
    credentialPrivateKey?.fill(0);
    wrappedUserKey?.fill(0);
  }
}
