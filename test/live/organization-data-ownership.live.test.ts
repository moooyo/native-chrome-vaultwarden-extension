// Live organization data-ownership transport contract against an authorized test-env backend.
import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({ default: { storage: { local: {}, session: {} } } }));

import { ApiClient, ApiHttpError } from '../../src/core/api/client.js';
import type { CipherBulkShareRequest } from '../../src/core/api/types.js';
import { bytesToBase64 } from '../../src/core/crypto/encoding.js';
import { decryptToText, encryptToBytes, encryptToText } from '../../src/core/crypto/encstring.js';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey } from '../../src/core/crypto/kdf.js';
import {
  decryptPrivateKey,
  symmetricKeyFromBytes,
  unwrapSymmetricKey,
  type SymmetricKey,
} from '../../src/core/crypto/keys.js';
import { rsaOaepEncrypt } from '../../src/core/crypto/primitives.js';
import { buildRegistration } from '../../src/core/crypto/registration.js';
import { encryptCipher } from '../../src/core/vault/encrypt.js';
import type { CipherInput } from '../../src/core/vault/models.js';
import type { KeyValueStore } from '../../src/platform/store.js';

const SERVER = (process.env.MIYU_SERVER ?? 'http://localhost:8080').replace(/\/+$/u, '');
const LIVE = process.env.LIVE === '1';

function memoryStore(): KeyValueStore {
  const values = new Map<string, unknown>();
  return {
    get: async <T>(key: string) => values.get(key) as T | undefined,
    set: async (key: string, value: unknown) => { values.set(key, value); },
    remove: async (key: string) => { values.delete(key); },
    clear: async () => { values.clear(); },
  };
}

async function derivePublicSpki(pkcs8: Uint8Array): Promise<Uint8Array> {
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8 as BufferSource,
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    true,
    ['decrypt'],
  );
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    { kty: 'RSA', n: jwk.n, e: jwk.e, ext: true, key_ops: ['encrypt'] } as JsonWebKey,
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    true,
    ['encrypt'],
  );
  return new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
}

async function rawJson(
  method: string,
  path: string,
  token: string,
  body: unknown,
): Promise<unknown> {
  const response = await fetch(`${SERVER}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  const parsed = text ? JSON.parse(text) as unknown : undefined;
  if (!response.ok) throw new ApiHttpError(response.status, parsed ?? text);
  return parsed;
}

async function deleteAccount(token: string, masterPasswordHash: string): Promise<void> {
  try {
    await rawJson('DELETE', '/api/accounts', token, { masterPasswordHash });
  } catch {
    // Cleanup must not replace the protocol assertion that failed.
  }
}

function sameDate(actual: string | null | undefined, expected: string | null | undefined): boolean {
  return typeof expected === 'string'
    ? typeof actual === 'string' && Date.parse(actual) === Date.parse(expected)
    : actual == null;
}

(LIVE ? describe : describe.skip)('live organization data ownership transport against test-env', () => {
  it('bulk-shares every lifecycle state and exercises current-member revoke routing', async () => {
    const accountSuffix = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
    const email = `odo-${accountSuffix}@example.com`;
    const password = 'Organization-Ownership-Live-1!';
    const revokeRequests: Array<{ readonly url: string; readonly method: string }> = [];
    const api = new ApiClient({
      serverUrlProvider: async () => SERVER,
      fetchFn: async (input, init) => {
        const url = typeof input === 'string' ? input : input.toString();
        if (url.includes('/users/revoke-self') || url.endsWith('/leave')) {
          revokeRequests.push({ url, method: init?.method ?? 'GET' });
        }
        return fetch(input, init);
      },
      localStore: memoryStore(),
    });

    let token: string | undefined;
    let masterPasswordHash: string | undefined;
    let organizationId: string | undefined;
    let userKey: SymmetricKey | undefined;
    let organizationKey: SymmetricKey | undefined;
    let organizationKeyBytes: Uint8Array | undefined;
    let organizationPrivateKey: Uint8Array | undefined;
    let organizationPublicKey: Uint8Array | undefined;
    try {
      const registration = await buildRegistration(email, password);
      const started = await api.startRegistration({ email, name: 'ODO Live Test' });
      if (started.kind === 'email_required') {
        throw new Error('test-env unexpectedly requires email verification');
      }
      await api.register({
        ...registration,
        masterPasswordHint: '',
        email,
        name: 'ODO Live Test',
        ...(started.kind === 'inline'
          ? { emailVerificationToken: started.emailVerificationToken }
          : {}),
      });

      const prelogin = await api.prelogin(email);
      const masterKey = await deriveMasterKey(password, email, prelogin);
      masterPasswordHash = await deriveMasterPasswordHash(masterKey, password);
      const login = await api.passwordLogin({ email, masterPasswordHash });
      if (login.kind !== 'success') throw new Error('test-env login did not complete');
      token = login.data.access_token;
      userKey = await unwrapSymmetricKey(login.data.Key, await stretchMasterKey(masterKey));
      const accountPrivateKey = await decryptPrivateKey(login.data.PrivateKey!, userKey);
      let accountPublicKey: Uint8Array;
      try {
        accountPublicKey = await derivePublicSpki(accountPrivateKey);
      } finally {
        accountPrivateKey.fill(0);
      }

      organizationKeyBytes = crypto.getRandomValues(new Uint8Array(64));
      organizationKey = symmetricKeyFromBytes(organizationKeyBytes);
      const organizationKeyPair = await crypto.subtle.generateKey({
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-1',
      }, true, ['encrypt', 'decrypt']);
      organizationPublicKey = new Uint8Array(
        await crypto.subtle.exportKey('spki', organizationKeyPair.publicKey),
      );
      organizationPrivateKey = new Uint8Array(
        await crypto.subtle.exportKey('pkcs8', organizationKeyPair.privateKey),
      );
      const organization = await rawJson('POST', '/api/organizations', token, {
        name: `ODO Live ${accountSuffix}`,
        billingEmail: email,
        collectionName: await encryptToText('Ownership target', organizationKey),
        key: `4.${bytesToBase64(await rsaOaepEncrypt(accountPublicKey, organizationKeyBytes))}`,
        keys: {
          publicKey: bytesToBase64(organizationPublicKey),
          encryptedPrivateKey: await encryptToBytes(organizationPrivateKey, organizationKey),
        },
        planType: 0,
      }) as { id?: unknown };
      accountPublicKey.fill(0);
      if (typeof organization.id !== 'string' || organization.id.length === 0) {
        throw new Error('test-env did not return an organization id');
      }
      organizationId = organization.id;
      const refreshed = await api.refresh(login.data.refresh_token);
      token = refreshed.access_token;

      const activeInput: CipherInput = {
        type: 1,
        name: 'ODO active login',
        login: { username: 'active@example.com', password: 'active-secret' },
      };
      const archivedInput: CipherInput = { type: 2, name: 'ODO archived note' };
      const trashedInput: CipherInput = { type: 2, name: 'ODO trashed note' };
      const active = await api.createCipher(token, await encryptCipher(activeInput, userKey));
      const archivedRequest = await encryptCipher(archivedInput, userKey);
      archivedRequest.archivedDate = '2026-08-30T00:00:00.000Z';
      const archived = await api.createCipher(token, archivedRequest);
      const trashed = await api.createCipher(token, await encryptCipher(trashedInput, userKey));
      await api.softDeleteCipher(token, trashed.id);

      const before = await api.sync(token);
      const collection = (before.collections ?? []).find((entry) => (
        entry.organizationId === organizationId
      ));
      if (!collection) throw new Error('test-env organization has no writable collection');
      const inputs = new Map<string, CipherInput>([
        [active.id, activeInput],
        [archived.id, archivedInput],
        [trashed.id, trashedInput],
      ]);
      const originals = before.ciphers.filter((cipher) => inputs.has(cipher.id));
      expect(originals).toHaveLength(3);
      const ciphers = await Promise.all(originals.map(async (original) => {
        const encrypted = await encryptCipher(inputs.get(original.id)!, organizationKey!);
        encrypted.organizationId = organizationId!;
        encrypted.lastKnownRevisionDate = original.revisionDate ?? null;
        encrypted.archivedDate = original.archivedDate ?? null;
        return {
          ...encrypted,
          id: original.id,
          organizationId: organizationId!,
          encryptedFor: before.profile.id,
        };
      }));
      const request: CipherBulkShareRequest = {
        ciphers,
        collectionIds: [collection.id],
        encryptedFor: before.profile.id,
      };
      const receipt = await api.shareCiphers(token, request);
      expect(receipt === undefined || receipt.length === 3).toBe(true);

      const after = await api.sync(token);
      for (const original of originals) {
        const migrated = after.ciphers.find((cipher) => cipher.id === original.id);
        expect(migrated).toBeDefined();
        expect(migrated?.organizationId).toBe(organizationId);
        expect(migrated?.collectionIds).toContain(collection.id);
        expect(sameDate(migrated?.deletedDate, original.deletedDate)).toBe(true);
        expect(sameDate(migrated?.archivedDate, original.archivedDate)).toBe(true);
        await expect(decryptToText(migrated!.name!, organizationKey))
          .resolves.toBe(inputs.get(original.id)!.name);
      }

      await expect(api.revokeCurrentOrganizationMembership(token, organizationId))
        .rejects.toBeInstanceOf(ApiHttpError);
      const routedRequests = revokeRequests.map((entry) => ({
        path: new URL(entry.url).pathname,
        method: entry.method,
      }));
      expect(routedRequests[0]).toEqual({
        path: `/api/organizations/${organizationId}/users/revoke-self`,
        method: 'PUT',
      });
      if (routedRequests.length === 2) {
        expect(routedRequests[1]).toEqual({
          path: `/api/organizations/${organizationId}/leave`,
          method: 'POST',
        });
      } else {
        expect(routedRequests).toHaveLength(1);
      }
    } finally {
      if (token && organizationId && masterPasswordHash) {
        try {
          await rawJson('DELETE', `/api/organizations/${organizationId}`, token, {
            masterPasswordHash,
          });
        } catch {
          // Best effort; the account deletion below is the final cleanup boundary.
        }
      }
      if (token && masterPasswordHash) await deleteAccount(token, masterPasswordHash);
      userKey?.encKey.fill(0);
      userKey?.macKey.fill(0);
      organizationKey?.encKey.fill(0);
      organizationKey?.macKey.fill(0);
      organizationKeyBytes?.fill(0);
      organizationPrivateKey?.fill(0);
      organizationPublicKey?.fill(0);
    }
  }, 120_000);
});
