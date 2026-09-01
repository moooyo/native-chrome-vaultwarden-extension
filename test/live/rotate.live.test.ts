// Live end-to-end test for account key rotation, against a disposable test Vaultwarden (MIYU_SERVER / MIYU_EMAIL / MIYU_PASSWORD)
// this environment). Excluded by default; run with:
//   $env:LIVE = '1'; npm run test:live -- test/live/rotate.live.test.ts
//
// Registers a throwaway account, seeds a keyless login cipher + a folder, builds a REAL rotation
// payload using the production `rotateCipher`/`rotateFolder` (not re-encryptCipher), POSTs the
// rotation endpoint, re-logs in, and verifies the vault decrypts under the NEW UserKey while the
// OLD UserKey no longer works. A second case proves a soft-deleted (trashed) cipher survives
// rotation with its deletedDate intact. The throwaway account is deleted in a `finally`.
import { describe, it, expect, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({ default: { storage: { local: {}, session: {} } } }));

import { ApiClient, BITWARDEN_CLIENT_VERSION } from '../../src/core/api/client.js';
import { deriveMasterKey, deriveMasterPasswordHash, parseKdfConfig, stretchMasterKey, type KdfConfig } from '../../src/core/crypto/kdf.js';
import { symmetricKeyFromBytes, unwrapSymmetricKey, decryptPrivateKey, type SymmetricKey } from '../../src/core/crypto/keys.js';
import { buildRegistration } from '../../src/core/crypto/registration.js';
import { encryptToBytes, encryptToText, decryptToText } from '../../src/core/crypto/encstring.js';
import { encryptCipher } from '../../src/core/vault/encrypt.js';
import { decryptCipher } from '../../src/core/vault/decrypt.js';
import { rotateCipher, rotateFolder } from '../../src/core/vault/rotate.js';
import { validateRawSyncCipherCompatibility } from '../../src/core/vault/vault-sync-cipher-compat.js';
import type { RotateKeyData } from '../../src/core/api/types.js';
import type { KeyValueStore } from '../../src/platform/store.js';

const SERVER = process.env.ROTATE_SERVER ?? '';

const LIVE = process.env.LIVE === '1';
const AUTHORIZED_TEST_ENV_TUNNELS = new Set([
  'http://127.0.0.1:18082',
  'http://127.0.0.1:18083',
]);
if (LIVE && !AUTHORIZED_TEST_ENV_TUNNELS.has(SERVER)) {
  throw new Error('Live rotation tests require an authorized test-env SSH tunnel');
}

function memStore(): KeyValueStore {
  const m = new Map<string, unknown>();
  return {
    get: async <T>(k: string) => m.get(k) as T | undefined,
    set: async (k: string, v: unknown) => { m.set(k, v); },
    remove: async (k: string) => { m.delete(k); },
  } as KeyValueStore;
}

async function requestRegistrationToken(email: string): Promise<string | undefined> {
  const response = await fetch(`${SERVER}/identity/accounts/register/send-verification-email`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'Bitwarden-Client-Version': BITWARDEN_CLIENT_VERSION,
    },
    body: JSON.stringify({ email, name: 'Rotate Test' }),
  });
  if (response.status === 404) return undefined;
  if (!response.ok) throw new Error(`registration start failed with status ${response.status}`);
  const text = await response.text();
  if (!text.trim()) return undefined;
  let token: unknown;
  try {
    token = JSON.parse(text) as unknown;
  } catch {
    token = text.trim();
  }
  if (typeof token !== 'string' || token.length === 0 || token.length > 16_384) {
    throw new Error('registration start returned an invalid token');
  }
  return token;
}

/** Register a throwaway account and log straight in, returning everything the rotation flow needs. */
async function registerAndLogin(api: ApiClient, email: string, password: string) {
  const reg = await buildRegistration(email, password);
  const emailVerificationToken = await requestRegistrationToken(email);
  let registered = false;
  try {
    await api.register({
      ...reg,
      masterPasswordHint: '',
      email,
      name: 'Rotate Test',
      ...(emailVerificationToken ? { emailVerificationToken } : {}),
    });
    registered = true;

    const kdf = parseKdfConfig(await api.prelogin(email));
    const masterKey = await deriveMasterKey(password, email, kdf);
    const hash = await deriveMasterPasswordHash(masterKey, password);
    const login = await api.passwordLogin({ email, masterPasswordHash: hash });
    expect(login.kind, 'login after register').toBe('success');
    if (login.kind !== 'success') throw new Error('unreachable: asserted above');
    if (!login.data.PrivateKey) throw new Error('login response missing PrivateKey');

    const token = login.data.access_token;
    const stretched = await stretchMasterKey(masterKey);
    const userKey = await unwrapSymmetricKey(login.data.Key, stretched);
    const pkcs8 = await decryptPrivateKey(login.data.PrivateKey, userKey);

    return { reg, kdf, hash, token, stretched, userKey, pkcs8 };
  } catch (error) {
    if (registered) {
      try {
        const cleanupLogin = await api.passwordLogin({
          email,
          masterPasswordHash: reg.masterPasswordHash,
        });
        if (cleanupLogin.kind === 'success') {
          await deleteAccount(cleanupLogin.data.access_token, reg.masterPasswordHash);
        }
      } catch {
        // Best-effort cleanup must not hide the setup failure.
      }
    }
    throw error;
  }
}

/**
 * Build a RotateKeyData payload wrapping a freshly generated new UserKey, mirroring the production
 * orchestrator's assembly (src/core/session/key-rotation.ts). `ciphers`/`folders` must already be
 * the OUTPUT of rotateCipher/rotateFolder against the SAME newUserKey this function generates, so
 * the caller passes a factory that receives newUserKey and returns the rotated arrays.
 */
async function buildRotateBody(params: {
  hash: string;
  kdf: KdfConfig;
  email: string;
  stretched: SymmetricKey;
  pkcs8: Uint8Array;
  publicKey: string;
  rotate: (newUserKey: SymmetricKey) => Promise<{ ciphers: unknown[]; folders: unknown[] }>;
}): Promise<RotateKeyData> {
  const newUserKeyBytes = globalThis.crypto.getRandomValues(new Uint8Array(64));
  const newUserKey = symmetricKeyFromBytes(newUserKeyBytes);
  const { ciphers, folders } = await params.rotate(newUserKey);

  const masterKeyEncryptedUserKey = await encryptToBytes(newUserKeyBytes, params.stretched);
  const userKeyEncryptedAccountPrivateKey = await encryptToBytes(params.pkcs8, newUserKey);

  return {
    oldMasterKeyAuthenticationHash: params.hash,
    accountUnlockData: {
      masterPasswordUnlockData: {
        kdfType: params.kdf.kdf,
        kdfIterations: params.kdf.kdfIterations,
        kdfParallelism: params.kdf.kdf === 1 ? params.kdf.kdfParallelism : null,
        kdfMemory: params.kdf.kdf === 1 ? params.kdf.kdfMemory : null,
        email: params.email,
        masterKeyAuthenticationHash: params.hash,
        masterKeyEncryptedUserKey,
      },
      emergencyAccessUnlockData: [],
      organizationAccountRecoveryUnlockData: [],
      passkeyUnlockData: [],
      deviceKeyUnlockData: [],
    },
    accountKeys: { userKeyEncryptedAccountPrivateKey, accountPublicKey: params.publicKey },
    accountData: { ciphers, folders, sends: [] },
  };
}

/** POST the rotation endpoint via raw fetch (per the task's exact-flow spec) and assert 2xx. */
async function postRotate(token: string, body: RotateKeyData): Promise<void> {
  const res = await fetch(`${SERVER}/api/accounts/key-management/rotate-user-account-keys`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  expect(res.ok, `rotate-user-account-keys failed: ${res.status} ${text}`).toBe(true);
}

/** Best-effort account cleanup; swallowed so a cleanup failure never masks the real test failure. */
async function deleteAccount(token: string, masterPasswordHash: string): Promise<boolean> {
  try {
    const response = await fetch(`${SERVER}/api/accounts`, {
      method: 'DELETE',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ masterPasswordHash }),
    });
    return response.ok;
  } catch {
    return false;
  }
}

/** Re-login after a successful rotation if the original token was invalidated before cleanup. */
async function cleanupAccount(api: ApiClient, email: string, token: string, masterPasswordHash: string): Promise<void> {
  if (await deleteAccount(token, masterPasswordHash)) return;
  try {
    const login = await api.passwordLogin({ email, masterPasswordHash });
    if (login.kind === 'success') await deleteAccount(login.data.access_token, masterPasswordHash);
  } catch {
    // Best-effort cleanup must not hide the test's primary assertion failure.
  }
}

(LIVE ? describe : describe.skip)('live account key rotation against the test server', () => {
  it('authoritatively proves a new account has no passkey or trusted-device unlock records', async () => {
    const api = new ApiClient({
      serverUrlProvider: async () => SERVER,
      fetchFn: fetch,
      localStore: memStore(),
    });
    const email = `rotate-inventory-${Date.now()}@example.com`;
    const password = 'Rotate-Inventory-Pass-1!';
    const { hash, token } = await registerAndLogin(api, email, password);

    try {
      await expect(api.getKeyRotationUnlockRecordsStatus(token)).resolves.toEqual({
        passkeyUnlockData: 'empty',
        deviceKeyUnlockData: 'empty',
      });
    } finally {
      await cleanupAccount(api, email, token, hash);
    }
  }, 60_000);

  it('rotates a keyless cipher + folder to a new UserKey; old UserKey stops working', async () => {
    const api = new ApiClient({ serverUrlProvider: async () => SERVER, fetchFn: fetch, localStore: memStore() });
    const email = `rotate-${Date.now()}@example.com`;
    const password = 'Rotate-Test-Pass-1!';

    const { reg, kdf, hash, token, stretched, userKey: oldUserKey, pkcs8 } =
      await registerAndLogin(api, email, password);
    let cleanupToken = token;

    try {
      // Seed a KEYLESS login cipher (custom field included) + a folder, then fetch their RAW
      // (still-encrypted) server representations via sync — these are what rotateCipher/rotateFolder
      // consume in production.
      const createdCipher = await api.createCipher(token, await encryptCipher({
        type: 1,
        name: 'RotateMe',
        notes: 'n',
        login: { username: 'u', password: 'p', uris: [{ uri: 'https://x' }] },
        fields: [{ type: 1, name: 'cf', value: 'cv' }],
      }, oldUserKey));
      const createdFolder = await api.createFolder(token, await encryptToText('F', oldUserKey));

      const sync = await api.sync(token);
      const rawCipher = sync.ciphers.find((c) => c.id === createdCipher.id);
      const rawFolder = sync.folders?.find((f) => f.id === createdFolder.id);
      expect(rawCipher, 'seeded cipher present in sync').toBeTruthy();
      expect(rawFolder, 'seeded folder present in sync').toBeTruthy();
      expect(typeof rawCipher?.data, '2026.8 sync returns canonical CipherResponse.data').toBe('string');
      expect(validateRawSyncCipherCompatibility(rawCipher)).toEqual({
        ok: true,
        dataMode: 'redundant-plain-data',
      });
      const oldCiphertexts = [
        rawCipher!.name,
        rawCipher!.login?.username,
        rawCipher!.login?.password,
        rawCipher!.login?.uris?.[0]?.uri,
      ].filter((value): value is string => typeof value === 'string');

      // Build the REAL rotation payload using the production re-encryption functions, both against
      // the SAME freshly generated new UserKey.
      const body = await buildRotateBody({
        hash, kdf, email, stretched, pkcs8, publicKey: reg.keys.publicKey,
        rotate: async (newUserKey) => ({
          ciphers: [await rotateCipher(rawCipher!, oldUserKey, newUserKey)],
          folders: [await rotateFolder(rawFolder!, oldUserKey, newUserKey)],
        }),
      });
      const rotatedCipher = body.accountData.ciphers[0] as Record<string, unknown> & {
        login?: Record<string, unknown>;
      };
      expect(rotatedCipher).not.toHaveProperty('data');
      expect(rotatedCipher.login).not.toHaveProperty('uri');
      const serializedBody = JSON.stringify(body);
      for (const oldCiphertext of oldCiphertexts) expect(serializedBody).not.toContain(oldCiphertext);

      await postRotate(token, body);

      // Re-login: the security stamp rotated, so the OLD token is dead; the master password itself
      // did not change, so the same hash logs in again and returns the NEW wrapped UserKey.
      const newLogin = await api.passwordLogin({ email, masterPasswordHash: hash });
      expect(newLogin.kind, 'login after rotation').toBe('success');
      if (newLogin.kind !== 'success') return;
      const newToken = newLogin.data.access_token;
      cleanupToken = newToken;
      const reUserKey = await unwrapSymmetricKey(newLogin.data.Key, stretched);

      const sync2 = await api.sync(newToken);
      const rawCipher2 = sync2.ciphers.find((c) => c.id === createdCipher.id);
      const rawFolder2 = sync2.folders?.find((f) => f.id === createdFolder.id);
      expect(rawCipher2, 'rotated cipher present after re-login').toBeTruthy();
      expect(rawFolder2, 'rotated folder present after re-login').toBeTruthy();
      expect(typeof rawCipher2?.data, 'server rebuilt canonical CipherResponse.data').toBe('string');
      expect(validateRawSyncCipherCompatibility(rawCipher2)).toEqual({
        ok: true,
        dataMode: 'redundant-plain-data',
      });
      expect(rawCipher2!.data).not.toBe(rawCipher!.data);
      for (const oldCiphertext of oldCiphertexts) expect(rawCipher2!.data).not.toContain(oldCiphertext);

      // NEW UserKey decrypts everything correctly.
      const decrypted = await decryptCipher(rawCipher2!, reUserKey);
      expect(decrypted).toMatchObject({
        name: 'RotateMe',
        notes: 'n',
        username: 'u',
        password: 'p',
        uris: ['https://x'],
      });
      expect(decrypted?.fields?.[0]).toMatchObject({ name: 'cf', value: 'cv' });

      const folderNamePlain = await decryptToText(rawFolder2!.name!, reUserKey);
      expect(folderNamePlain).toBe('F');

      // OLD UserKey no longer decrypts the rotated cipher: either it throws, or decryptCipher's own
      // fail-close path degrades it to the undecryptable '(error)' summary.
      let oldKeyResult: unknown;
      try {
        oldKeyResult = await decryptCipher(rawCipher2!, oldUserKey);
      } catch (err) {
        oldKeyResult = err;
      }
      if (oldKeyResult instanceof Error) {
        expect(oldKeyResult).toBeInstanceOf(Error);
      } else {
        expect((oldKeyResult as { name?: string } | undefined)?.name).toBe('(error)');
      }
    } finally {
      await cleanupAccount(api, email, cleanupToken, hash);
    }
  }, 60_000);

  it('preserves a soft-deleted (trashed) cipher through rotation', async () => {
    const api = new ApiClient({ serverUrlProvider: async () => SERVER, fetchFn: fetch, localStore: memStore() });
    const email = `rotate-trash-${Date.now()}@example.com`;
    const password = 'Rotate-Trash-Pass-1!';

    const { reg, kdf, hash, token, stretched, userKey: oldUserKey, pkcs8 } =
      await registerAndLogin(api, email, password);
    let cleanupToken = token;

    try {
      const createdCipher = await api.createCipher(token, await encryptCipher({
        type: 1,
        name: 'ToTrash',
        login: { username: 'u2', password: 'p2' },
      }, oldUserKey));

      // Soft-delete BEFORE rotating: the raw synced cipher now carries a deletedDate, which
      // rotateCipher/rewrapDeep must pass through unchanged (it is not an EncString).
      await api.softDeleteCipher(token, createdCipher.id);
      const sync = await api.sync(token);
      const rawTrashed = sync.ciphers.find((c) => c.id === createdCipher.id);
      expect(rawTrashed, 'trashed cipher present in sync').toBeTruthy();
      expect(rawTrashed?.deletedDate, 'cipher is soft-deleted before rotation').toBeTruthy();

      const body = await buildRotateBody({
        hash, kdf, email, stretched, pkcs8, publicKey: reg.keys.publicKey,
        rotate: async (newUserKey) => ({
          ciphers: [await rotateCipher(rawTrashed!, oldUserKey, newUserKey)],
          folders: [],
        }),
      });

      await postRotate(token, body);

      const newLogin = await api.passwordLogin({ email, masterPasswordHash: hash });
      expect(newLogin.kind, 'login after rotation').toBe('success');
      if (newLogin.kind !== 'success') return;
      const newToken = newLogin.data.access_token;
      cleanupToken = newToken;
      const reUserKey = await unwrapSymmetricKey(newLogin.data.Key, stretched);

      const sync2 = await api.sync(newToken);
      const rawTrashed2 = sync2.ciphers.find((c) => c.id === createdCipher.id);
      expect(rawTrashed2, 'trashed cipher still present after rotation').toBeTruthy();
      expect(rawTrashed2?.deletedDate, 'still trashed after rotation').toBeTruthy();
      const decrypted = await decryptCipher(rawTrashed2!, reUserKey);
      expect(decrypted).toMatchObject({ name: 'ToTrash', username: 'u2', password: 'p2' });
    } finally {
      await cleanupAccount(api, email, cleanupToken, hash);
    }
  }, 60_000);
});
