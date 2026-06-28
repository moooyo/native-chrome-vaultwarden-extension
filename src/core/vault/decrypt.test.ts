import { describe, it, expect } from 'vitest';
import { decryptCipher, decryptFolders } from './decrypt.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { hexToBytes, bytesToBase64 } from '../crypto/encoding.js';
import { hmacSha256 } from '../crypto/primitives.js';
import { FIELD_VECTOR, USER_KEY_VECTOR, TAMPERED_FIELD_ENCSTRING } from '../../../test/vectors.js';
import type { CipherResponse, FolderResponse } from '../api/types.js';

const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));

// Test-only AES-CBC encrypt helper that builds a Bitwarden EncString type 2.
async function encryptBytes(plainBytes: Uint8Array, key: SymmetricKey, iv: Uint8Array): Promise<string> {
  const subtle = globalThis.crypto.subtle;
  const cryptoKey = await subtle.importKey('raw', key.encKey as BufferSource, { name: 'AES-CBC' }, false, ['encrypt']);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: iv as BufferSource }, cryptoKey, plainBytes as BufferSource));
  const macData = new Uint8Array(iv.length + ct.length);
  macData.set(iv, 0);
  macData.set(ct, iv.length);
  const mac = await hmacSha256(key.macKey, macData);
  return `2.${bytesToBase64(iv)}|${bytesToBase64(ct)}|${bytesToBase64(mac)}`;
}

async function encryptString(plaintext: string, key: SymmetricKey): Promise<string> {
  return encryptBytes(new TextEncoder().encode(plaintext), key, new Uint8Array(16).fill(0x03));
}

async function wrapKey(itemKey: SymmetricKey, wrappingKey: SymmetricKey): Promise<string> {
  const raw = new Uint8Array(64);
  raw.set(itemKey.encKey, 0);
  raw.set(itemKey.macKey, 32);
  return encryptBytes(raw, wrappingKey, new Uint8Array(16).fill(0x04));
}

describe('decryptCipher', () => {
  it('decrypts a personal login cipher', async () => {
    const cipher: CipherResponse = {
      id: 'cipher-1',
      type: 1,
      name: FIELD_VECTOR.encString,
      favorite: true,
      organizationId: null,
      notes: FIELD_VECTOR.encString,
      login: {
        username: FIELD_VECTOR.encString,
        password: FIELD_VECTOR.encString,
        totp: FIELD_VECTOR.encString,
        uris: [{ uri: FIELD_VECTOR.encString, match: 1 }],
      },
    };
    const out = await decryptCipher(cipher, userKey);
    expect(out).toEqual({
      id: 'cipher-1',
      type: 1,
      favorite: true,
      name: FIELD_VECTOR.plaintext,
      notes: FIELD_VECTOR.plaintext,
      username: FIELD_VECTOR.plaintext,
      password: FIELD_VECTOR.plaintext,
      totp: FIELD_VECTOR.plaintext,
      uris: [FIELD_VECTOR.plaintext],
      loginUris: [{ uri: FIELD_VECTOR.plaintext, match: 1 }],
    });
  });

  it('skips organization ciphers in M3', async () => {
    const cipher: CipherResponse = {
      id: 'org-1',
      type: 1,
      name: FIELD_VECTOR.encString,
      favorite: false,
      organizationId: 'org',
      login: { username: FIELD_VECTOR.encString },
    };
    await expect(decryptCipher(cipher, userKey)).resolves.toBeUndefined();
  });

  it('resolves to undecryptable for a corrupted personal cipher', async () => {
    const cipher: CipherResponse = {
      id: 'bad-cipher',
      type: 1,
      name: TAMPERED_FIELD_ENCSTRING,
      favorite: true,
      organizationId: null,
      login: null,
    };
    const out = await decryptCipher(cipher, userKey);
    expect(out).toEqual({
      id: 'bad-cipher',
      type: 1,
      favorite: true,
      name: '(error)',
      uris: [],
      loginUris: [],
      undecryptable: true,
    });
  });

  it('decrypts a personal cipher using a per-cipher item key', async () => {
    const itemEncKey = new Uint8Array(32).fill(0x01);
    const itemMacKey = new Uint8Array(32).fill(0x02);
    const itemKeyBytes = new Uint8Array(64);
    itemKeyBytes.set(itemEncKey, 0);
    itemKeyBytes.set(itemMacKey, 32);
    const itemKey = symmetricKeyFromBytes(itemKeyBytes);
    const wrappedKey = await wrapKey(itemKey, userKey);

    const cipher: CipherResponse = {
      id: 'cipher-item-key',
      type: 1,
      name: await encryptString('Secure Login', itemKey),
      favorite: false,
      organizationId: null,
      notes: await encryptString('my secret notes', itemKey),
      key: wrappedKey,
      login: {
        username: await encryptString('user@example.com', itemKey),
        password: await encryptString('s3cr3t', itemKey),
        uris: [{ uri: await encryptString('https://example.com', itemKey), match: 0 }],
      },
    };
    const out = await decryptCipher(cipher, userKey);
    expect(out).toEqual({
      id: 'cipher-item-key',
      type: 1,
      favorite: false,
      name: 'Secure Login',
      notes: 'my secret notes',
      username: 'user@example.com',
      password: 's3cr3t',
      uris: ['https://example.com'],
      loginUris: [{ uri: 'https://example.com', match: 0 }],
    });
  });

  it('decrypts a personal card cipher (all fields are EncStrings)', async () => {
    const cipher: CipherResponse = {
      id: 'card-1',
      type: 3,
      name: FIELD_VECTOR.encString,
      favorite: false,
      organizationId: null,
      card: {
        cardholderName: FIELD_VECTOR.encString,
        brand: FIELD_VECTOR.encString,
        number: FIELD_VECTOR.encString,
        expMonth: FIELD_VECTOR.encString,
        expYear: FIELD_VECTOR.encString,
        code: FIELD_VECTOR.encString,
      },
    };
    const out = await decryptCipher(cipher, userKey);
    expect(out?.card).toEqual({
      cardholderName: FIELD_VECTOR.plaintext,
      brand: FIELD_VECTOR.plaintext,
      number: FIELD_VECTOR.plaintext,
      expMonth: FIELD_VECTOR.plaintext,
      expYear: FIELD_VECTOR.plaintext,
      code: FIELD_VECTOR.plaintext,
    });
    expect(out?.name).toBe(FIELD_VECTOR.plaintext);
  });

  it('decrypts a personal identity cipher (all 18 fields are EncStrings)', async () => {
    const all = FIELD_VECTOR.encString;
    const cipher: CipherResponse = {
      id: 'id-1',
      type: 4,
      name: all,
      favorite: false,
      organizationId: null,
      identity: {
        title: all, firstName: all, middleName: all, lastName: all,
        address1: all, address2: all, address3: all, city: all, state: all,
        postalCode: all, country: all, company: all, email: all, phone: all,
        ssn: all, username: all, passportNumber: all, licenseNumber: all,
      },
    };
    const out = await decryptCipher(cipher, userKey);
    const p = FIELD_VECTOR.plaintext;
    expect(out?.identity).toEqual({
      title: p, firstName: p, middleName: p, lastName: p,
      address1: p, address2: p, address3: p, city: p, state: p,
      postalCode: p, country: p, company: p, email: p, phone: p,
      ssn: p, username: p, passportNumber: p, licenseNumber: p,
    });
    // identity.username must not leak into the login-only top-level username field
    expect(out?.username).toBeUndefined();
  });

  it('omits empty card fields', async () => {
    const cipher: CipherResponse = {
      id: 'card-2',
      type: 3,
      name: FIELD_VECTOR.encString,
      favorite: false,
      organizationId: null,
      card: { brand: FIELD_VECTOR.encString, number: FIELD_VECTOR.encString },
    };
    const out = await decryptCipher(cipher, userKey);
    expect(out?.card).toEqual({ brand: FIELD_VECTOR.plaintext, number: FIELD_VECTOR.plaintext });
  });

  it('marks a card cipher undecryptable when a field MAC fails', async () => {
    const cipher: CipherResponse = {
      id: 'card-bad',
      type: 3,
      name: FIELD_VECTOR.encString,
      favorite: false,
      organizationId: null,
      card: { number: TAMPERED_FIELD_ENCSTRING },
    };
    const out = await decryptCipher(cipher, userKey);
    expect(out).toMatchObject({ id: 'card-bad', type: 3, name: '(error)', undecryptable: true });
  });

  it('surfaces folderId when present and omits it when absent', async () => {
    const withFolder = await decryptCipher({
      id: 'c-folder', type: 1, name: FIELD_VECTOR.encString, favorite: false, organizationId: null, folderId: 'folder-1', login: null,
    }, userKey);
    expect(withFolder).toMatchObject({ id: 'c-folder', folderId: 'folder-1' });

    const noFolder = await decryptCipher({
      id: 'c-nofolder', type: 1, name: FIELD_VECTOR.encString, favorite: false, organizationId: null, login: null,
    }, userKey);
    expect(noFolder && 'folderId' in noFolder).toBe(false);
  });
});

describe('decryptFolders', () => {
  it('decrypts folder names into FolderSummary[]', async () => {
    const folders: FolderResponse[] = [{ id: 'f1', name: FIELD_VECTOR.encString }];
    await expect(decryptFolders(folders, userKey)).resolves.toEqual([{ id: 'f1', name: FIELD_VECTOR.plaintext }]);
  });

  it('falls back to (no name) when a folder has no name', async () => {
    await expect(decryptFolders([{ id: 'f2', name: null }], userKey)).resolves.toEqual([{ id: 'f2', name: '(no name)' }]);
  });

  it('falls back to (undecryptable) on a tampered folder name without aborting', async () => {
    const folders: FolderResponse[] = [
      { id: 'f3', name: TAMPERED_FIELD_ENCSTRING },
      { id: 'f4', name: FIELD_VECTOR.encString },
    ];
    await expect(decryptFolders(folders, userKey)).resolves.toEqual([
      { id: 'f3', name: '(undecryptable)' },
      { id: 'f4', name: FIELD_VECTOR.plaintext },
    ]);
  });

  it('returns [] for empty or undefined input', async () => {
    await expect(decryptFolders(undefined, userKey)).resolves.toEqual([]);
    await expect(decryptFolders([], userKey)).resolves.toEqual([]);
  });
});
