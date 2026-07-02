import { describe, it, expect, vi } from 'vitest';

// Partially mock the rotate primitives: rotateFolder/rotateSend stay real, but rotateCipher is
// wrapped in a vi.fn so a single test (self-verify abort) can force a corrupt-but-non-throwing
// result — something the real rotateCipher cannot produce, since if it succeeds the output is by
// construction re-decryptable. This isolates the orchestrator's OWN defense-in-depth check.
vi.mock('../vault/rotate.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../vault/rotate.js')>();
  return { ...actual, rotateCipher: vi.fn(actual.rotateCipher) };
});

import { rotateAccountKey } from './key-rotation.js';
import { rotateCipher } from '../vault/rotate.js';
import { symmetricKeyFromBytes, unwrapSymmetricKey } from '../crypto/keys.js';
import { deriveMasterKey, stretchMasterKey } from '../crypto/kdf.js';
import { encryptToText, decryptToBytes, decryptToText } from '../crypto/encstring.js';
import { rsaOaepDecrypt } from '../crypto/primitives.js';
import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes } from '../crypto/encoding.js';
import { KDF_VECTOR_600K, USER_KEY_VECTOR, RSA_PRIVATE_KEY_VECTOR } from '../../../test/vectors.js';
import type { CipherResponse } from '../api/types.js';
import type { RotateKeyData } from '../api/types.js';

const subtle = globalThis.crypto.subtle;

const EMAIL = KDF_VECTOR_600K.email;
const PASSWORD = KDF_VECTOR_600K.password;
const ITERATIONS = KDF_VECTOR_600K.iterations;
const oldUserKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
const pkcs8 = base64ToBytes(RSA_PRIVATE_KEY_VECTOR.pkcs8B64);

function makeSession(overrides: Partial<{
  getPersistedAuth: () => Promise<{ email: string; accessToken: string; kdfIterations: number; encPrivateKey?: string } | undefined>;
  loadUserKey: () => Promise<ReturnType<typeof symmetricKeyFromBytes> | undefined>;
  loadPrivateKey: () => Promise<Uint8Array | undefined>;
  logout: () => Promise<void>;
}> = {}) {
  return {
    getPersistedAuth: vi.fn(overrides.getPersistedAuth ?? (async () => ({
      email: EMAIL,
      accessToken: 'access-token',
      kdfIterations: ITERATIONS,
      encPrivateKey: RSA_PRIVATE_KEY_VECTOR.encPrivateKey,
    }))),
    loadUserKey: vi.fn(overrides.loadUserKey ?? (async () => oldUserKey)),
    loadPrivateKey: vi.fn(overrides.loadPrivateKey ?? (async () => pkcs8)),
    logout: vi.fn(overrides.logout ?? (async () => {})),
  };
}

function makeApi(overrides: Partial<{
  sync: (token: string) => Promise<unknown>;
  getTrustedEmergencyAccess: (token: string) => Promise<Array<{ id: string }>>;
  getOrganizationPublicKey: (token: string, orgId: string) => Promise<{ publicKey: string }>;
  getAccountPublicKey: (token: string) => Promise<{ publicKey: string }>;
  rotateAccountKey: (token: string, body: RotateKeyData) => Promise<void>;
}> = {}) {
  return {
    sync: vi.fn(overrides.sync ?? (async () => ({
      profile: { id: 'u1', email: EMAIL, organizations: [] },
      ciphers: [],
      folders: [],
      sends: [],
    }))),
    getTrustedEmergencyAccess: vi.fn(overrides.getTrustedEmergencyAccess ?? (async () => [])),
    getOrganizationPublicKey: vi.fn(overrides.getOrganizationPublicKey ?? (async () => {
      throw new Error('unexpected: no org should need a public key in this fixture');
    })),
    getAccountPublicKey: vi.fn(overrides.getAccountPublicKey ?? (async () => ({ publicKey: 'account-pub-key-b64' }))),
    rotateAccountKey: vi.fn(overrides.rotateAccountKey ?? (async () => {})),
  };
}

const verifyMasterPassword = vi.fn(async (pw: string) => pw === PASSWORD);

async function currentUserKeyFrom(body: RotateKeyData) {
  const stretched = await stretchMasterKey(await deriveMasterKey(PASSWORD, EMAIL, ITERATIONS));
  return unwrapSymmetricKey(body.accountUnlockData.masterPasswordUnlockData.masterKeyEncryptedUserKey, stretched);
}

describe('rotateAccountKey — guards (fail closed, no downstream calls)', () => {
  it('throws when there is no persisted auth (not logged in)', async () => {
    const session = makeSession({ getPersistedAuth: async () => undefined });
    const api = makeApi();
    await expect(rotateAccountKey(PASSWORD, { api, session, verifyMasterPassword: vi.fn() }))
      .rejects.toThrow(/not logged in/i);
    expect(api.sync).not.toHaveBeenCalled();
    expect(api.rotateAccountKey).not.toHaveBeenCalled();
  });

  it('throws when the vault is locked (no UserKey loaded)', async () => {
    const session = makeSession({ loadUserKey: async () => undefined });
    const api = makeApi();
    await expect(rotateAccountKey(PASSWORD, { api, session, verifyMasterPassword: vi.fn() }))
      .rejects.toThrow(/locked/i);
    expect(api.sync).not.toHaveBeenCalled();
    expect(api.rotateAccountKey).not.toHaveBeenCalled();
  });

  it('throws when the master password fails verification, before any API call', async () => {
    const session = makeSession();
    const api = makeApi();
    const verify = vi.fn(async () => false);
    await expect(rotateAccountKey('wrong-password', { api, session, verifyMasterPassword: verify }))
      .rejects.toThrow(/incorrect/i);
    expect(verify).toHaveBeenCalledWith('wrong-password');
    expect(api.getTrustedEmergencyAccess).not.toHaveBeenCalled();
    expect(api.sync).not.toHaveBeenCalled();
    expect(api.rotateAccountKey).not.toHaveBeenCalled();
  });

  it('throws before any re-encryption when the account has trusted emergency-access grants', async () => {
    const session = makeSession();
    const api = makeApi({ getTrustedEmergencyAccess: async () => [{ id: 'grant-1' }] });
    await expect(rotateAccountKey(PASSWORD, { api, session, verifyMasterPassword }))
      .rejects.toThrow(/emergency/i);
    expect(api.sync).not.toHaveBeenCalled();
    expect(api.rotateAccountKey).not.toHaveBeenCalled();
  });
});

describe('rotateAccountKey — empty vault happy path', () => {
  it('rotates an empty vault: builds an internally-consistent payload and logs out', async () => {
    const session = makeSession();
    const api = makeApi();

    await rotateAccountKey(PASSWORD, { api, session, verifyMasterPassword });

    expect(api.rotateAccountKey).toHaveBeenCalledTimes(1);
    const [token, body] = api.rotateAccountKey.mock.calls[0]! as [string, RotateKeyData];
    expect(token).toBe('access-token');
    expect(body.accountData).toEqual({ ciphers: [], folders: [], sends: [] });
    expect(body.accountUnlockData.emergencyAccessUnlockData).toEqual([]);
    expect(body.accountUnlockData.organizationAccountRecoveryUnlockData).toEqual([]);
    expect(body.oldMasterKeyAuthenticationHash).toBe(KDF_VECTOR_600K.masterPasswordHashB64);

    const u = body.accountUnlockData.masterPasswordUnlockData;
    expect(u.kdfType).toBe(0);
    expect(u.kdfIterations).toBe(ITERATIONS);
    expect(u.kdfParallelism).toBeNull();
    expect(u.kdfMemory).toBeNull();
    expect(u.email).toBe(EMAIL);
    expect(u.masterKeyAuthenticationHash).toBe(KDF_VECTOR_600K.masterPasswordHashB64);

    // The new UserKey unwraps under the CURRENT (unchanged) master key — the password itself does
    // not change during a key rotation.
    const newUserKey = await currentUserKeyFrom(body);

    // The account private key is re-wrapped under that SAME new UserKey.
    const recoveredPkcs8 = await decryptToBytes(body.accountKeys.userKeyEncryptedAccountPrivateKey, newUserKey);
    expect(bytesToHex(recoveredPkcs8)).toBe(bytesToHex(pkcs8));
    expect(body.accountKeys.accountPublicKey).toBe('account-pub-key-b64');

    expect(session.logout).toHaveBeenCalledTimes(1);
  });
});

describe('rotateAccountKey — cipher/folder/send re-encryption', () => {
  it('throws before any POST when a personal cipher cannot be decrypted with the old UserKey', async () => {
    const wrongKey = symmetricKeyFromBytes(new Uint8Array(64).fill(9));
    const badCipher = { id: 'c1', type: 1, name: await encryptToText('x', wrongKey) } as unknown as CipherResponse;
    const session = makeSession();
    const api = makeApi({
      sync: async () => ({ profile: { id: 'u1', email: EMAIL, organizations: [] }, ciphers: [badCipher], folders: [], sends: [] }),
    });
    await expect(rotateAccountKey(PASSWORD, { api, session, verifyMasterPassword })).rejects.toBeTruthy();
    expect(api.rotateAccountKey).not.toHaveBeenCalled();
  });

  it('rotates personal ciphers including trashed ones, and excludes organization ciphers', async () => {
    const personalActive = { id: 'p1', type: 1, name: await encryptToText('Active', oldUserKey) } as unknown as CipherResponse;
    const personalTrashed = {
      id: 'p2', type: 1, name: await encryptToText('Trashed', oldUserKey), deletedDate: '2026-01-01T00:00:00Z',
    } as unknown as CipherResponse;
    const orgCipher = { id: 'o1', type: 1, organizationId: 'org-1', name: '2.some-org-ciphertext==' } as unknown as CipherResponse;
    const session = makeSession();
    const api = makeApi({
      sync: async () => ({
        profile: { id: 'u1', email: EMAIL, organizations: [] },
        ciphers: [personalActive, personalTrashed, orgCipher],
        folders: [],
        sends: [],
      }),
    });

    await rotateAccountKey(PASSWORD, { api, session, verifyMasterPassword });

    const [, body] = api.rotateAccountKey.mock.calls[0]! as [string, RotateKeyData];
    const rotated = body.accountData.ciphers as Array<{ id: string; name: string }>;
    expect(rotated.map((c) => c.id).sort()).toEqual(['p1', 'p2']); // org cipher excluded, trashed included

    const newUserKey = await currentUserKeyFrom(body);
    const active = rotated.find((c) => c.id === 'p1')!;
    const trashed = rotated.find((c) => c.id === 'p2')!;
    expect(await decryptToText(active.name, newUserKey)).toBe('Active');
    expect(await decryptToText(trashed.name, newUserKey)).toBe('Trashed');
  });

  it('re-encrypts folders and sends under the new UserKey (round-trip decrypt matches)', async () => {
    const folder = { id: 'f1', name: await encryptToText('Work', oldUserKey) };
    const send = {
      id: 's1', accessId: 'a1', type: 0, deletionDate: '2026-01-01T00:00:00Z',
      key: await encryptToText('sendkeybytes', oldUserKey),
    };
    const session = makeSession();
    const api = makeApi({
      sync: async () => ({ profile: { id: 'u1', email: EMAIL, organizations: [] }, ciphers: [], folders: [folder], sends: [send] }),
    });

    await rotateAccountKey(PASSWORD, { api, session, verifyMasterPassword });

    const [, body] = api.rotateAccountKey.mock.calls[0]! as [string, RotateKeyData];
    const newUserKey = await currentUserKeyFrom(body);
    const rotatedFolder = (body.accountData.folders as Array<{ id: string; name: string }>)[0]!;
    expect(rotatedFolder.id).toBe('f1');
    expect(await decryptToText(rotatedFolder.name, newUserKey)).toBe('Work');
    const rotatedSend = (body.accountData.sends as Array<{ id: string; key: string }>)[0]!;
    expect(rotatedSend.id).toBe('s1');
    expect(await decryptToText(rotatedSend.key, newUserKey)).toBe('sendkeybytes');
  });
});

describe('rotateAccountKey — organization account-recovery re-enrollment', () => {
  it('includes recovery data for resetPasswordEnrolled orgs only, wrapping the SAME new UserKey', async () => {
    const orgPair = await subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
      true,
      ['encrypt', 'decrypt'],
    );
    const orgPublicKeySpki = new Uint8Array(await subtle.exportKey('spki', orgPair.publicKey));
    const orgPrivateKeyPkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', orgPair.privateKey));

    const session = makeSession();
    const getOrganizationPublicKey = vi.fn(async (token: string, orgId: string) => {
      expect(token).toBe('access-token');
      expect(orgId).toBe('org-enrolled');
      return { publicKey: bytesToBase64(orgPublicKeySpki) };
    });
    const api = makeApi({
      sync: async () => ({
        profile: {
          id: 'u1',
          email: EMAIL,
          organizations: [
            { id: 'org-enrolled', key: 'irrelevant', resetPasswordEnrolled: true },
            { id: 'org-not-enrolled', key: 'irrelevant', resetPasswordEnrolled: false },
          ],
        },
        ciphers: [],
        folders: [],
        sends: [],
      }),
      getOrganizationPublicKey,
    });

    await rotateAccountKey(PASSWORD, { api, session, verifyMasterPassword });

    expect(getOrganizationPublicKey).toHaveBeenCalledTimes(1); // only the enrolled org

    const [, body] = api.rotateAccountKey.mock.calls[0]! as [string, RotateKeyData];
    const recovery = body.accountUnlockData.organizationAccountRecoveryUnlockData;
    expect(recovery).toHaveLength(1);
    expect(recovery[0]!.organizationId).toBe('org-enrolled');
    expect(recovery[0]!.resetPasswordKey.startsWith('4.')).toBe(true);

    // Decrypting the org-wrapped key with the org's RSA private key must yield the SAME new
    // UserKey bytes that wrap the account private key — proving org-recovery targets the actual
    // rotated key, not some other value.
    const wrappedBytes = base64ToBytes(recovery[0]!.resetPasswordKey.slice(2));
    const newUserKeyBytesViaOrg = await rsaOaepDecrypt(orgPrivateKeyPkcs8, wrappedBytes, 'SHA-1');
    const newUserKeyViaMaster = await currentUserKeyFrom(body);
    const newUserKeyBytesViaMaster = new Uint8Array([...newUserKeyViaMaster.encKey, ...newUserKeyViaMaster.macKey]);
    expect(bytesToHex(newUserKeyBytesViaOrg)).toBe(bytesToHex(newUserKeyBytesViaMaster));
  });
});

describe('rotateAccountKey — strict pre-POST self-verify', () => {
  it('aborts (no POST) when the self-verify detects an undecryptable rotated cipher', async () => {
    const goodCipher = { id: 'c1', type: 1, name: await encryptToText('ok', oldUserKey) } as unknown as CipherResponse;
    const otherKey = symmetricKeyFromBytes(new Uint8Array(64).fill(5));
    // Force rotateCipher (normally fail-closed and self-consistent) to instead return a cipher
    // whose name is encrypted under a key that is NEITHER old nor new — something the real
    // implementation cannot produce, but which the orchestrator's OWN self-verify must still catch.
    vi.mocked(rotateCipher).mockResolvedValueOnce({ id: 'c1', type: 1, name: await encryptToText('corrupt', otherKey) });

    const session = makeSession();
    const api = makeApi({
      sync: async () => ({ profile: { id: 'u1', email: EMAIL, organizations: [] }, ciphers: [goodCipher], folders: [], sends: [] }),
    });

    await expect(rotateAccountKey(PASSWORD, { api, session, verifyMasterPassword }))
      .rejects.toThrow(/self-check|self-verify/i);
    expect(api.rotateAccountKey).not.toHaveBeenCalled();
  });
});
