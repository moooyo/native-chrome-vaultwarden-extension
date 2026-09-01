import { describe, it, expect, vi } from 'vitest';
import { decryptCipher, decryptCipherSummary, decryptFolders, decryptCollections, buildOrgKeyMap, buildSyncProfileOrgKeyMap, undecryptableSummary } from './decrypt.js';
import * as encstring from '../crypto/encstring.js';
import { serializeSymmetricKey, symmetricKeyFromBytes } from '../crypto/keys.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { hexToBytes, bytesToBase64, base64ToBytes } from '../crypto/encoding.js';
import { hmacSha256 } from '../crypto/primitives.js';
import { FIELD_VECTOR, USER_KEY_VECTOR, TAMPERED_FIELD_ENCSTRING, RSA_VECTOR, ORG_KEY_VECTOR } from '../../../test/vectors.js';
import type { CipherResponse, CollectionResponse, Fido2CredentialData, FolderResponse, OrganizationResponse } from '../api/types.js';
import type { CipherSummary } from './models.js';

const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
const orgKey = symmetricKeyFromBytes(hexToBytes(ORG_KEY_VECTOR.orgKeyHex));

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
  it('decrypts exact Bitwarden 2026.8 Data projections for every known cipher type', async () => {
    const loginName = await encryptString('Login', userKey);
    const username = await encryptString('alice', userKey);
    const noteName = await encryptString('Note', userKey);
    const cardName = await encryptString('Card', userKey);
    const brand = await encryptString('Visa', userKey);
    const identityName = await encryptString('Identity', userKey);
    const firstName = await encryptString('Ada', userKey);
    const lastName = await encryptString('Lovelace', userKey);
    const sshName = await encryptString('Deploy key', userKey);
    const privateKey = await encryptString('PRIVATE', userKey);
    const publicKey = await encryptString('PUBLIC', userKey);
    const fingerprint = await encryptString('SHA256:fingerprint', userKey);
    const ciphers: CipherResponse[] = [
      {
        id: 'data-login', type: 1, name: loginName, login: { username },
        data: JSON.stringify({ Name: loginName, Username: username }),
      },
      {
        id: 'data-note', type: 2, name: noteName, secureNote: { type: 0 },
        data: JSON.stringify({ Name: noteName, Type: 0 }),
      },
      {
        id: 'data-card', type: 3, name: cardName, card: { brand },
        data: JSON.stringify({ Name: cardName, Brand: brand }),
      },
      {
        id: 'data-identity', type: 4, name: identityName, identity: { firstName, lastName },
        data: JSON.stringify({ Name: identityName, FirstName: firstName, LastName: lastName }),
      },
      {
        id: 'data-ssh', type: 5, name: sshName,
        sshKey: { privateKey, publicKey, keyFingerprint: fingerprint },
        data: JSON.stringify({
          Name: sshName,
          PrivateKey: privateKey,
          PublicKey: publicKey,
          KeyFingerprint: fingerprint,
        }),
      },
    ];

    for (const cipher of ciphers) {
      const detail = await decryptCipher(cipher, userKey);
      const summary = await decryptCipherSummary(cipher, userKey);
      expect(detail).toMatchObject({ id: cipher.id, type: cipher.type });
      expect(summary).toMatchObject({ id: cipher.id, type: cipher.type });
    }
    await expect(decryptCipher(ciphers[4]!, userKey)).resolves.toMatchObject({
      sshKey: { privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:fingerprint' },
    });
    await expect(decryptCipherSummary(ciphers[4]!, userKey)).resolves.toMatchObject({
      subtitle: 'SHA256:fingerprint',
    });
  });

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

  it('decrypts custom fields (Text/Hidden/Boolean) and preserves Linked metadata', async () => {
    const cipher: CipherResponse = {
      id: 'c', type: 1, favorite: false, organizationId: null,
      name: FIELD_VECTOR.encString,
      login: { username: FIELD_VECTOR.encString },
      fields: [
        { type: 0, name: await encryptString('Note', userKey), value: await encryptString('plain text', userKey) },
        { type: 1, name: await encryptString('PIN', userKey), value: await encryptString('1234', userKey) },
        { type: 2, name: await encryptString('Subscribed', userKey), value: await encryptString('true', userKey) },
        { type: 3, name: await encryptString('User', userKey), value: null, linkedId: 100 },
      ],
    };
    const out = await decryptCipher(cipher, userKey);
    expect(out?.fields).toEqual([
      { type: 0, name: 'Note', value: 'plain text' },
      { type: 1, name: 'PIN', value: '1234' },
      { type: 2, name: 'Subscribed', value: 'true' },
      { type: 3, name: 'User', linkedId: 100 },
    ]);
  });

  it('skips organization ciphers when no organization key is available', async () => {
    const cipher: CipherResponse = {
      id: 'org-1',
      type: 1,
      name: FIELD_VECTOR.encString,
      favorite: false,
      organizationId: 'org',
      login: { username: FIELD_VECTOR.encString },
    };
    await expect(decryptCipher(cipher, userKey)).resolves.toBeUndefined();
    await expect(decryptCipher(cipher, userKey, new Map())).resolves.toBeUndefined();
  });

  it('decrypts an organization cipher with the matching organization key', async () => {
    const cipher: CipherResponse = {
      id: 'org-login',
      type: 1,
      name: await encryptString('Org Login', orgKey),
      favorite: true,
      organizationId: 'org-1',
      login: {
        username: await encryptString('alice@org.example', orgKey),
        password: await encryptString('org-s3cret', orgKey),
        uris: [{ uri: await encryptString('https://org.example', orgKey), match: 0 }],
      },
    };
    const out = await decryptCipher(cipher, userKey, new Map([['org-1', orgKey]]));
    expect(out).toEqual({
      id: 'org-login',
      type: 1,
      favorite: true,
      organizationId: 'org-1',
      access: {
        edit: false,
        clone: false,
        viewPassword: false,
        delete: false,
        restore: false,
        autofillTotp: false,
        viewTotp: false,
      },
      name: 'Org Login',
      username: 'alice@org.example',
      password: 'org-s3cret',
      uris: ['https://org.example'],
      loginUris: [{ uri: 'https://org.example', match: 0 }],
    });
  });

  it('decrypts an organization cipher that carries its own per-item key wrapped by the org key', async () => {
    const itemKeyBytes = new Uint8Array(64);
    itemKeyBytes.set(new Uint8Array(32).fill(0x05), 0);
    itemKeyBytes.set(new Uint8Array(32).fill(0x06), 32);
    const itemKey = symmetricKeyFromBytes(itemKeyBytes);
    const cipher: CipherResponse = {
      id: 'org-item-key',
      type: 1,
      name: await encryptString('Org Secure', itemKey),
      favorite: false,
      organizationId: 'org-1',
      key: await wrapKey(itemKey, orgKey),
      login: { username: await encryptString('bob@org.example', itemKey) },
    };
    const out = await decryptCipher(cipher, userKey, new Map([['org-1', orgKey]]));
    expect(out).toMatchObject({ id: 'org-item-key', name: 'Org Secure', username: 'bob@org.example' });
  });

  it('resolves to undecryptable for a corrupted personal cipher', async () => {
    const cipher: CipherResponse = {
      id: 'bad-cipher',
      type: 1,
      name: TAMPERED_FIELD_ENCSTRING,
      favorite: true,
      organizationId: null,
      login: {},
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

  it('resolves to undecryptable when a field throws a non-MAC error (bad wrapped-key length)', async () => {
    // A per-cipher key that unwraps to 32 bytes (not 64) makes symmetricKeyFromBytes throw a plain
    // Error — not EncStringMacError/UnsupportedEncTypeError. It must still degrade to undecryptable
    // rather than reject (targeted reveal/download must never throw on one malformed cipher).
    const badKey = await encryptBytes(new Uint8Array(32), userKey, new Uint8Array(16).fill(0x07));
    const cipher: CipherResponse = {
      id: 'bad-key', type: 1, favorite: true, organizationId: null,
      name: FIELD_VECTOR.encString, key: badKey, login: {},
    };
    const out = await decryptCipher(cipher, userKey);
    expect(out).toMatchObject({ id: 'bad-key', type: 1, favorite: true, name: '(error)', undecryptable: true });
  });

  it('resolves to undecryptable when a field EncString has invalid base64 (not a MAC error)', async () => {
    const cipher: CipherResponse = {
      id: 'bad-b64', type: 1, favorite: false, organizationId: null,
      name: '2.@@@invalid@@@|@@@|@@@', login: {},
    };
    const out = await decryptCipher(cipher, userKey);
    expect(out).toMatchObject({ id: 'bad-b64', type: 1, name: '(error)', undecryptable: true });
  });

  it('degrades a single custom field whose name or value fails to decrypt instead of nuking the item', async () => {
    const cipher: CipherResponse = {
      id: 'field-bad', type: 1, favorite: false, organizationId: null,
      name: await encryptString('Good Name', userKey),
      login: { username: await encryptString('alice', userKey) },
      fields: [
        { type: 0, name: TAMPERED_FIELD_ENCSTRING, value: await encryptString('v', userKey) },
        { type: 1, name: await encryptString('PIN', userKey), value: TAMPERED_FIELD_ENCSTRING },
        { type: 2, name: await encryptString('Flag', userKey), value: await encryptString('true', userKey) },
      ],
    };
    const out = await decryptCipher(cipher, userKey);
    expect(out?.undecryptable).toBeUndefined();
    expect(out?.name).toBe('Good Name');
    expect(out?.username).toBe('alice');
    // Bad name → empty name (kept); bad value → dropped; the healthy field is intact.
    expect(out?.fields).toEqual([
      { type: 0, name: '', value: 'v' },
      { type: 1, name: 'PIN' },
      { type: 2, name: 'Flag', value: 'true' },
    ]);
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

  it('decrypts a login cipher with a stored passkey (fido2Credentials)', async () => {
    const cipher: CipherResponse = {
      id: 'pk', type: 1, name: await encryptString('Acme', userKey), favorite: false, organizationId: null,
      login: {
        username: await encryptString('alice', userKey),
        fido2Credentials: [{
          credentialId: await encryptString('cred-1', userKey),
          keyType: await encryptString('public-key', userKey),
          keyAlgorithm: await encryptString('ECDSA', userKey),
          keyCurve: await encryptString('P-256', userKey),
          keyValue: await encryptString('PKCS8B64URL', userKey),
          rpId: await encryptString('acme.com', userKey),
          userName: await encryptString('alice@acme.com', userKey),
          userHandle: await encryptString('handle-1', userKey),
          counter: await encryptString('0', userKey),
          discoverable: await encryptString('true', userKey),
          creationDate: '2026-08-30T00:00:00Z',
        }],
      },
    };
    const out = await decryptCipher(cipher, userKey);
    expect(out?.fido2Credentials).toEqual([{
      credentialId: 'cred-1', keyValue: 'PKCS8B64URL', rpId: 'acme.com',
      counter: 0, discoverable: true, userName: 'alice@acme.com', userHandle: 'handle-1',
    }]);
  });

  it('validates discoverable strictly and fails missing or malformed values closed to false', async () => {
    const credential = async (
      id: string,
      discoverable: string | null | undefined,
    ): Promise<Fido2CredentialData> => ({
      credentialId: await encryptString(id, userKey),
      keyType: await encryptString('public-key', userKey),
      keyAlgorithm: await encryptString('ECDSA', userKey),
      keyCurve: await encryptString('P-256', userKey),
      keyValue: await encryptString(`key-${id}`, userKey),
      rpId: await encryptString('acme.com', userKey),
      counter: await encryptString('0', userKey),
      creationDate: '2026-08-30T00:00:00Z',
      ...(discoverable === undefined ? {} : { discoverable }),
    });
    const cipher: CipherResponse = {
      id: 'discoverable-matrix',
      type: 1,
      name: await encryptString('Acme', userKey),
      login: {
        fido2Credentials: [
          await credential('true', await encryptString('true', userKey)),
          await credential('false', await encryptString('false', userKey)),
          await credential('missing', undefined),
          await credential('invalid-text', await encryptString('TRUE', userKey)),
          await credential('invalid-ciphertext', '2.bad|bad|bad'),
        ],
      },
    };

    const out = await decryptCipher(cipher, userKey);

    expect(out?.fido2Credentials?.map(({ credentialId, discoverable }) => ({
      credentialId,
      discoverable,
    }))).toEqual([
      { credentialId: 'true', discoverable: true },
      { credentialId: 'false', discoverable: false },
      { credentialId: 'missing', discoverable: false },
      { credentialId: 'invalid-text', discoverable: false },
      { credentialId: 'invalid-ciphertext', discoverable: false },
    ]);
  });

  it('surfaces folderId when present and omits it when absent', async () => {
    const withFolder = await decryptCipher({
      id: 'c-folder', type: 1, name: FIELD_VECTOR.encString, favorite: false, organizationId: null, folderId: 'folder-1', login: {},
    }, userKey);
    expect(withFolder).toMatchObject({ id: 'c-folder', folderId: 'folder-1' });

    const noFolder = await decryptCipher({
      id: 'c-nofolder', type: 1, name: FIELD_VECTOR.encString, favorite: false, organizationId: null, login: {},
    }, userKey);
    expect(noFolder && 'folderId' in noFolder).toBe(false);
  });

  it('surfaces collectionIds on an organization cipher and omits them when absent', async () => {
    const withCollections = await decryptCipher({
      id: 'org-coll', type: 1, name: await encryptString('Org', orgKey), favorite: false,
      organizationId: 'org-1', collectionIds: ['col-1', 'col-2'], login: {},
    }, userKey, new Map([['org-1', orgKey]]));
    expect(withCollections).toMatchObject({ id: 'org-coll', collectionIds: ['col-1', 'col-2'] });

    const withoutCollections = await decryptCipher({
      id: 'org-nocoll', type: 1, name: await encryptString('Org', orgKey), favorite: false,
      organizationId: 'org-1', login: {},
    }, userKey, new Map([['org-1', orgKey]]));
    expect(withoutCollections && 'collectionIds' in withoutCollections).toBe(false);
  });

  it('decrypts an SSH key with common notes, custom fields, and reprompt metadata', async () => {
    const cipher: CipherResponse = {
      id: 'ssh-1',
      type: 5,
      name: await encryptString('Deploy key', userKey),
      notes: await encryptString('Production only', userKey),
      favorite: true,
      reprompt: 1,
      sshKey: {
        privateKey: await encryptString('PRIVATE', userKey),
        publicKey: await encryptString('ssh-ed25519 PUBLIC', userKey),
        keyFingerprint: await encryptString('SHA256:fingerprint', userKey),
      },
      fields: [{
        type: 0,
        name: await encryptString('Environment', userKey),
        value: await encryptString('production', userKey),
      }],
    };

    await expect(decryptCipher(cipher, userKey)).resolves.toMatchObject({
      id: 'ssh-1',
      type: 5,
      name: 'Deploy key',
      notes: 'Production only',
      favorite: true,
      reprompt: true,
      uris: [],
      loginUris: [],
      sshKey: {
        privateKey: 'PRIVATE',
        publicKey: 'ssh-ed25519 PUBLIC',
        keyFingerprint: 'SHA256:fingerprint',
      },
      fields: [{ type: 0, name: 'Environment', value: 'production' }],
    });
  });

  it('accepts a read-side SSH key whose derivable public fields are absent', async () => {
    const cipher: CipherResponse = {
      id: 'ssh-sparse',
      type: 5,
      name: await encryptString('Imported key', userKey),
      sshKey: { privateKey: await encryptString('PRIVATE', userKey) },
    };

    await expect(decryptCipher(cipher, userKey)).resolves.toMatchObject({
      type: 5,
      sshKey: { privateKey: 'PRIVATE' },
    });
  });

  it.each(['privateKey', 'publicKey', 'keyFingerprint'] as const)(
    'fails closed when SSH %s authentication fails',
    async (field) => {
      const sshKey = {
        privateKey: await encryptString('PRIVATE', userKey),
        publicKey: await encryptString('PUBLIC', userKey),
        keyFingerprint: await encryptString('SHA256:fingerprint', userKey),
      };
      sshKey[field] = TAMPERED_FIELD_ENCSTRING;
      const cipher: CipherResponse = {
        id: `ssh-bad-${field}`,
        type: 5,
        name: await encryptString('Broken key', userKey),
        sshKey,
      };

      await expect(decryptCipher(cipher, userKey)).resolves.toMatchObject({
        id: `ssh-bad-${field}`,
        type: 5,
        name: '(error)',
        undecryptable: true,
      });
    },
  );

  it('fails closed for missing, extra, or conflicting SSH payload fields', async () => {
    const base = { id: 'ssh-invalid', type: 5, name: await encryptString('Broken', userKey) };
    const invalidPayloads = [
      {},
      { privateKey: await encryptString('PRIVATE', userKey), futureField: await encryptString('x', userKey) },
    ];
    for (const sshKey of invalidPayloads) {
      await expect(decryptCipher({ ...base, sshKey } as CipherResponse, userKey))
        .rejects.toThrow(/incompatible cipher representation/i);
    }
    await expect(decryptCipher({
      ...base,
      sshKey: { privateKey: await encryptString('PRIVATE', userKey) },
      login: { password: await encryptString('must-not-interpret', userKey) },
    }, userKey)).rejects.toThrow(/incompatible cipher representation/i);
  });

  it.each([
    ['mismatched Data', (name: string) => ({
      id: 'mismatch', type: 1, name, login: {}, data: JSON.stringify({ Name: '2.different==' }),
    })],
    ['unknown Data field', (name: string) => ({
      id: 'unknown-data', type: 1, name, login: {},
      data: JSON.stringify({ Name: name, FutureSecret: name }),
    })],
    ['sealed Data blob', (name: string) => ({
      id: 'blob', type: 1, name, login: {},
      data: JSON.stringify({ format_version: 1, wrapped_cek: name }),
    })],
  ] as const)('rejects %s before detail or summary decryption', async (_label, build) => {
    const cipher = build(await encryptString('Blocked', userKey)) as CipherResponse;
    const spy = vi.spyOn(encstring, 'decryptToText');
    try {
      await expect(decryptCipher(cipher, userKey)).rejects.toThrow(/incompatible cipher representation/i);
      await expect(decryptCipherSummary(cipher, userKey)).rejects.toThrow(/incompatible cipher representation/i);
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  it('rejects accessor-backed and proxy-backed raw ciphers without reading their properties', async () => {
    const typeGetter = vi.fn(() => 1);
    const accessor = Object.defineProperty({ id: 'accessor' }, 'type', {
      enumerable: true,
      get: typeGetter,
    }) as CipherResponse;
    const proxyGet = vi.fn(Reflect.get);
    const proxy = new Proxy({ id: 'proxy', type: 1 }, {
      getPrototypeOf: () => Array.prototype,
      get: proxyGet,
    }) as CipherResponse;

    for (const cipher of [accessor, proxy]) {
      await expect(decryptCipher(cipher, userKey)).rejects.toThrow(/incompatible cipher representation/i);
      await expect(decryptCipherSummary(cipher, userKey)).rejects.toThrow(/incompatible cipher representation/i);
      expect(() => undecryptableSummary(cipher)).toThrow(/incompatible cipher representation/i);
    }
    expect(typeGetter).not.toHaveBeenCalled();
    expect(proxyGet).not.toHaveBeenCalled();
  });

  it('rejects an accessor-backed SSH payload before parsing or decrypting it', async () => {
    const privateKeyGetter = vi.fn(() => '2.must-not-be-read');
    const sshKey = Object.defineProperty({}, 'privateKey', {
      enumerable: true,
      get: privateKeyGetter,
    });
    const cipher = {
      id: 'ssh-accessor', type: 5, name: await encryptString('SSH', userKey), sshKey,
    } as CipherResponse;
    const decryptSpy = vi.spyOn(encstring, 'decryptToText');
    try {
      await expect(decryptCipher(cipher, userKey)).rejects.toThrow(/incompatible cipher representation/i);
      await expect(decryptCipherSummary(cipher, userKey)).rejects.toThrow(/incompatible cipher representation/i);
      expect(privateKeyGetter).not.toHaveBeenCalled();
      expect(decryptSpy).not.toHaveBeenCalled();
    } finally {
      decryptSpy.mockRestore();
    }
  });
});

describe('decryptCipherSummary', () => {
  const orgKeys = new Map([['org-1', orgKey]]);
  const enc = (s: string) => encryptString(s, userKey);
  const encOrg = (s: string) => encryptString(s, orgKey);

  // Rebuild the summary exactly as the pre-optimization path did (full decryptCipher + the old
  // decryptSummaries projection), so we can prove the lightweight path is byte-identical.
  async function referenceSummary(cipher: CipherResponse): Promise<CipherSummary | undefined> {
    const decrypted = await decryptCipher(cipher, userKey, orgKeys);
    if (!decrypted) return undefined;
    if (decrypted.undecryptable) {
      const s: CipherSummary = {
        id: decrypted.id, type: decrypted.type, favorite: decrypted.favorite,
        name: '(undecryptable)', uris: [], loginUris: [], undecryptable: true,
      };
      if (decrypted.organizationId) {
        s.organizationId = decrypted.organizationId;
        if (decrypted.access) s.access = decrypted.access;
      }
      if (decrypted.folderId) s.folderId = decrypted.folderId;
      if (decrypted.collectionIds) s.collectionIds = decrypted.collectionIds;
      if (cipher.deletedDate) s.deletedDate = cipher.deletedDate;
      if (cipher.archivedDate) s.archivedDate = cipher.archivedDate;
      return s;
    }
    const s: CipherSummary = {
      id: decrypted.id, type: decrypted.type, favorite: decrypted.favorite,
      name: decrypted.name, uris: decrypted.uris, loginUris: decrypted.loginUris,
    };
    if (decrypted.username) s.username = decrypted.username;
    if (decrypted.totp) s.hasTotp = true;
    if (decrypted.fido2Credentials?.length) s.hasPasskey = true;
    if (decrypted.reprompt) s.reprompt = true;
    if (decrypted.passwordHistoryCount) s.passwordHistoryCount = decrypted.passwordHistoryCount;
    if (decrypted.organizationId) {
      s.organizationId = decrypted.organizationId;
      if (decrypted.access) s.access = decrypted.access;
    }
    if (decrypted.folderId) s.folderId = decrypted.folderId;
    if (decrypted.collectionIds) s.collectionIds = decrypted.collectionIds;
    if (cipher.deletedDate) s.deletedDate = cipher.deletedDate;
    if (cipher.archivedDate) s.archivedDate = cipher.archivedDate;
    let subtitle: string | undefined;
    if (decrypted.type === 3) subtitle = decrypted.card?.brand;
    else if (decrypted.type === 4) {
      const name = [decrypted.identity?.firstName, decrypted.identity?.lastName].filter(Boolean).join(' ');
      subtitle = name || undefined;
    }
    if (subtitle) s.subtitle = subtitle;
    return s;
  }

  it('produces summaries identical to the old full-decrypt path across representative ciphers', async () => {
    const cred = async () => ({
      credentialId: await enc('cred-1'), keyType: await enc('public-key'),
      keyAlgorithm: await enc('ECDSA'), keyCurve: await enc('P-256'),
      keyValue: await enc('PKCS8B64URL'), rpId: await enc('acme.com'),
      counter: await enc('0'), discoverable: await enc('true'),
      creationDate: '2026-08-30T00:00:00Z',
    });
    const ciphers: CipherResponse[] = [
      // login: username + password + uris, no totp/passkey/history
      { id: 'login-plain', type: 1, favorite: false, organizationId: null, name: await enc('Plain'),
        login: { username: await enc('alice'), password: await enc('pw'), uris: [{ uri: await enc('https://a.example'), match: 0 }] } },
      // login with a TOTP secret
      { id: 'login-totp', type: 1, favorite: true, organizationId: null, name: await enc('Totp'),
        login: { username: await enc('bob'), totp: await enc('SEED') } },
      // login with a stored passkey (no username)
      { id: 'login-pk', type: 1, favorite: false, organizationId: null, name: await enc('Passkey'),
        login: { fido2Credentials: [await cred()] } },
      // login with password history + reprompt
      { id: 'login-hist', type: 1, favorite: false, organizationId: null, name: await enc('Hist'), reprompt: 1,
        login: { password: await enc('pw') }, passwordHistory: [
          { password: await enc('old1'), lastUsedDate: '2026-08-29T00:00:00Z' },
          { password: await enc('old2'), lastUsedDate: '2026-08-30T00:00:00Z' },
        ] },
      // card with brand → subtitle
      { id: 'card-brand', type: 3, favorite: false, organizationId: null, name: await enc('Card'),
        card: { brand: await enc('Visa'), number: await enc('4111'), code: await enc('123') } },
      // card without a brand → no subtitle
      { id: 'card-nobrand', type: 3, favorite: false, organizationId: null, name: await enc('Card2'),
        card: { number: await enc('4111') } },
      // identity → subtitle from first + last name
      { id: 'id-1', type: 4, favorite: false, organizationId: null, name: await enc('Id'),
        identity: { firstName: await enc('Ada'), lastName: await enc('Lovelace'), ssn: await enc('999') } },
      // secure note
      { id: 'note-1', type: 2, favorite: false, organizationId: null, name: await enc('Note'), notes: await enc('secret notes'), secureNote: { type: 0 } },
      // soft-deleted login (folderId + deletedDate)
      { id: 'login-del', type: 1, favorite: false, organizationId: null, folderId: 'f1', name: await enc('Del'),
        login: { username: await enc('carol') }, deletedDate: '2026-01-01T00:00:00.000Z' },
      // archived login remains decryptable but is projected as inactive for callers
      { id: 'login-archived', type: 1, favorite: false, organizationId: null, name: await enc('Archived'),
        login: { username: await enc('erin') }, archivedDate: '2026-08-30T00:00:00.000Z' },
      // org cipher with collectionIds
      { id: 'org-login', type: 1, favorite: false, organizationId: 'org-1', collectionIds: ['col-1'], name: await encOrg('Org'),
        login: { username: await encOrg('dave'), password: await encOrg('pw') } },
      // undecryptable (corrupt name) — favorite/collectionIds carried through
      { id: 'bad', type: 1, favorite: true, organizationId: null, name: TAMPERED_FIELD_ENCSTRING, login: {} },
    ];
    for (const cipher of ciphers) {
      const [reference, actual] = await Promise.all([referenceSummary(cipher), decryptCipherSummary(cipher, userKey, orgKeys)]);
      expect(actual).toEqual(reference);
    }
  });

  it('sets hasTotp / hasPasskey from the encrypted shape without decrypting the secrets (deterministic)', async () => {
    // Secrets encrypted under a DIFFERENT key (orgKey): decrypting them with userKey would MAC-fail.
    // The full path marks the cipher undecryptable; the lightweight path ignores them and stays usable.
    const cipher: CipherResponse = {
      id: 'mix', type: 1, favorite: false, organizationId: null,
      name: await encryptString('Visible', userKey),
      login: {
        username: await encryptString('alice', userKey),
        password: await encryptString('s3cret', orgKey),
        totp: await encryptString('SEED', orgKey),
        fido2Credentials: [{
          credentialId: await encryptString('cred', orgKey),
          keyType: await encryptString('public-key', orgKey),
          keyAlgorithm: await encryptString('ECDSA', orgKey),
          keyCurve: await encryptString('P-256', orgKey),
          keyValue: await encryptString('PRIVATE', orgKey),
          rpId: await encryptString('acme.com', orgKey),
          counter: await encryptString('0', orgKey),
          discoverable: await encryptString('true', orgKey),
          creationDate: '2026-08-30T00:00:00Z',
        }],
      },
    };
    await expect(decryptCipher(cipher, userKey)).resolves.toMatchObject({ undecryptable: true });
    const summary = await decryptCipherSummary(cipher, userKey);
    expect(summary).toMatchObject({ id: 'mix', name: 'Visible', username: 'alice', hasTotp: true, hasPasskey: true });
    expect(summary?.undecryptable).toBeUndefined();
  });

  it('never passes secret ciphertexts to decryptToText for the list path (spy)', async () => {
    const nameEnc = await encryptString('Acme', userKey);
    const usernameEnc = await encryptString('alice', userKey);
    const passwordEnc = await encryptString('s3cret', userKey);
    const totpEnc = await encryptString('SEED', userKey);
    const keyValueEnc = await encryptString('PRIVATE', userKey);
    const notesEnc = await encryptString('notes', userKey);
    const fieldNameEnc = await encryptString('PIN', userKey);
    const fieldValueEnc = await encryptString('1234', userKey);
    const cipher: CipherResponse = {
      id: 'spy', type: 1, favorite: false, organizationId: null, name: nameEnc, notes: notesEnc,
      login: {
        username: usernameEnc, password: passwordEnc, totp: totpEnc,
        fido2Credentials: [{
          credentialId: await encryptString('cred', userKey),
          keyType: await encryptString('public-key', userKey),
          keyAlgorithm: await encryptString('ECDSA', userKey),
          keyCurve: await encryptString('P-256', userKey),
          keyValue: keyValueEnc,
          rpId: await encryptString('acme.com', userKey),
          counter: await encryptString('0', userKey),
          discoverable: await encryptString('true', userKey),
          creationDate: '2026-08-30T00:00:00Z',
        }],
      },
      fields: [{ type: 1, name: fieldNameEnc, value: fieldValueEnc }],
    };
    const spy = vi.spyOn(encstring, 'decryptToText');
    try {
      const summary = await decryptCipherSummary(cipher, userKey);
      const seen = spy.mock.calls.map((c) => c[0]);
      // Display fields ARE decrypted…
      expect(seen).toContain(nameEnc);
      expect(seen).toContain(usernameEnc);
      // …secrets and non-summary fields are NOT.
      expect(seen).not.toContain(passwordEnc);
      expect(seen).not.toContain(totpEnc);
      expect(seen).not.toContain(keyValueEnc);
      expect(seen).not.toContain(notesEnc);
      expect(seen).not.toContain(fieldNameEnc);
      expect(seen).not.toContain(fieldValueEnc);
      expect(summary).toMatchObject({ hasTotp: true, hasPasskey: true });
    } finally {
      spy.mockRestore();
    }
  });

  it('uses only an SSH fingerprint as the safe subtitle without decrypting key material', async () => {
    const privateKey = await encryptString('PRIVATE', orgKey);
    const publicKey = await encryptString('PUBLIC', orgKey);
    const keyFingerprint = await encryptString('SHA256:fingerprint', userKey);
    const cipher: CipherResponse = {
      id: 'ssh-summary',
      type: 5,
      name: await encryptString('Deploy key', userKey),
      sshKey: { privateKey, publicKey, keyFingerprint },
    };
    const spy = vi.spyOn(encstring, 'decryptToText');
    try {
      await expect(decryptCipherSummary(cipher, userKey)).resolves.toMatchObject({
        id: 'ssh-summary',
        type: 5,
        name: 'Deploy key',
        subtitle: 'SHA256:fingerprint',
      });
      const seen = spy.mock.calls.map((call) => call[0]);
      expect(seen).toContain(keyFingerprint);
      expect(seen).not.toContain(privateKey);
      expect(seen).not.toContain(publicKey);
    } finally {
      spy.mockRestore();
    }
  });

  it('preserves an unknown positive type as an unsupported summary without touching encrypted fields', async () => {
    const cipher: CipherResponse = {
      id: 'future-6',
      type: 6,
      favorite: true,
      organizationId: 'org-without-a-key',
      folderId: 'folder-1',
      collectionIds: ['collection-1'],
      deletedDate: '2026-08-30T00:00:00Z',
      key: 'malformed-key-that-must-not-be-read',
      name: 'encrypted-name-that-must-not-be-read',
      notes: 'encrypted-notes-that-must-not-be-read',
      bankAccount: { accountNumber: 'encrypted-account-number' },
    };
    const spy = vi.spyOn(encstring, 'decryptToText');
    try {
      await expect(decryptCipher(cipher, userKey)).resolves.toBeUndefined();
      await expect(decryptCipherSummary(cipher, userKey)).resolves.toEqual({
        id: 'future-6',
        type: 6,
        favorite: true,
        name: '(unsupported item)',
        uris: [],
        loginUris: [],
        organizationId: 'org-without-a-key',
        folderId: 'folder-1',
        collectionIds: ['collection-1'],
        deletedDate: '2026-08-30T00:00:00Z',
        unsupported: true,
        undecryptable: true,
      });
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  it('preserves archivedDate on an unsupported summary without reading its future payload', async () => {
    const futurePayloadGetter = vi.fn(() => ({ secret: 'must-not-materialize' }));
    const cipher = Object.defineProperty({
      id: 'future-archived',
      type: 99,
      favorite: false,
      archivedDate: '2026-08-30T00:00:00Z',
      name: '2.opaque-name',
    }, 'passport', {
      enumerable: true,
      get: futurePayloadGetter,
    }) as CipherResponse;

    await expect(decryptCipherSummary(cipher, userKey)).resolves.toEqual({
      id: 'future-archived',
      type: 99,
      favorite: false,
      name: '(unsupported item)',
      uris: [],
      loginUris: [],
      archivedDate: '2026-08-30T00:00:00Z',
      unsupported: true,
      undecryptable: true,
    });
    expect(futurePayloadGetter).not.toHaveBeenCalled();
  });

  it('ignores an unknown type payload accessor while projecting only safe metadata', async () => {
    const futurePayloadGetter = vi.fn(() => ({ secret: 'must-not-materialize' }));
    const cipher = Object.defineProperty({
      id: 'future-accessor',
      type: 99,
      favorite: false,
      organizationId: null,
      name: '2.opaque-name',
    }, 'bankAccount', {
      enumerable: true,
      get: futurePayloadGetter,
    }) as CipherResponse;

    await expect(decryptCipher(cipher, userKey)).resolves.toBeUndefined();
    await expect(decryptCipherSummary(cipher, userKey)).resolves.toEqual({
      id: 'future-accessor',
      type: 99,
      favorite: false,
      name: '(unsupported item)',
      uris: [],
      loginUris: [],
      unsupported: true,
      undecryptable: true,
    });
    expect(futurePayloadGetter).not.toHaveBeenCalled();
  });

  it.each([-1, 0, 1.5, Number.MAX_SAFE_INTEGER + 1])(
    'rejects an invalid raw cipher type %s',
    async (type) => {
      const cipher = { id: 'invalid', type, name: 'opaque' } as CipherResponse;
      await expect(decryptCipher(cipher, userKey)).rejects.toThrow(/positive safe integer/i);
      await expect(decryptCipherSummary(cipher, userKey)).rejects.toThrow(/positive safe integer/i);
    },
  );
});

describe('decryptCollections', () => {
  it('decrypts collection names using the org key into CollectionSummary[]', async () => {
    const collections: CollectionResponse[] = [
      { id: 'c1', organizationId: 'org-1', name: await encryptString('Engineering', orgKey) },
    ];
    await expect(decryptCollections(collections, new Map([['org-1', orgKey]])))
      .resolves.toEqual([{ id: 'c1', organizationId: 'org-1', name: 'Engineering' }]);
  });

  it('preserves collection authorization metadata without inventing absent grants', async () => {
    const collections: CollectionResponse[] = [{
      id: 'c-access',
      organizationId: 'org-1',
      name: await encryptString('Engineering', orgKey),
      readOnly: false,
      manage: true,
      hidePasswords: false,
      assigned: true,
      type: 0,
      defaultUserCollectionEmail: 'offboarded@example.com',
    }, {
      id: 'c-sparse',
      organizationId: 'org-1',
      name: await encryptString('Sparse', orgKey),
    }];

    const result = await decryptCollections(collections, new Map([['org-1', orgKey]]));

    expect(result[0]).toMatchObject({
      name: 'offboarded@example.com',
      readOnly: false,
      manage: true,
      hidePasswords: false,
      assigned: true,
      type: 0,
      defaultUserCollectionEmail: 'offboarded@example.com',
    });
    expect(result[1]).toEqual({ id: 'c-sparse', organizationId: 'org-1', name: 'Sparse' });
  });

  it('skips collections whose organization key is unavailable', async () => {
    const collections: CollectionResponse[] = [
      { id: 'c1', organizationId: 'missing', name: await encryptString('X', orgKey) },
    ];
    await expect(decryptCollections(collections, new Map())).resolves.toEqual([]);
  });

  it('degrades to (undecryptable) when the name cannot be decrypted but the org key exists', async () => {
    const collections: CollectionResponse[] = [
      { id: 'c1', organizationId: 'org-1', name: TAMPERED_FIELD_ENCSTRING },
    ];
    await expect(decryptCollections(collections, new Map([['org-1', orgKey]])))
      .resolves.toEqual([{ id: 'c1', organizationId: 'org-1', name: '(undecryptable)' }]);
  });

  it('returns [] for empty or undefined input', async () => {
    await expect(decryptCollections(undefined, new Map())).resolves.toEqual([]);
    await expect(decryptCollections([], new Map())).resolves.toEqual([]);
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

describe('buildOrgKeyMap', () => {
  const privateKey = base64ToBytes(RSA_VECTOR.privateKeyPkcs8B64);

  it('unwraps each organization key into a map keyed by organization id', async () => {
    const orgs: OrganizationResponse[] = [{ id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey }];
    const map = await buildOrgKeyMap(orgs, privateKey);
    expect(map.has('org-1')).toBe(true);
    const expected = symmetricKeyFromBytes(hexToBytes(ORG_KEY_VECTOR.orgKeyHex));
    expect(bytesToBase64(map.get('org-1')!.encKey)).toBe(bytesToBase64(expected.encKey));
    expect(bytesToBase64(map.get('org-1')!.macKey)).toBe(bytesToBase64(expected.macKey));
  });

  it('returns an empty map when the private key is unavailable', async () => {
    const orgs: OrganizationResponse[] = [{ id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey }];
    await expect(buildOrgKeyMap(orgs, undefined)).resolves.toEqual(new Map());
    await expect(buildOrgKeyMap(undefined, privateKey)).resolves.toEqual(new Map());
  });

  it('skips organizations whose key cannot be unwrapped without aborting the rest', async () => {
    const orgs: OrganizationResponse[] = [
      { id: 'bad', key: '4.not-valid-base64-or-rsa' },
      { id: 'org-1', key: ORG_KEY_VECTOR.encOrgKey },
    ];
    const map = await buildOrgKeyMap(orgs, privateKey);
    expect(map.has('bad')).toBe(false);
    expect(map.has('org-1')).toBe(true);
  });
});

describe('buildSyncProfileOrgKeyMap', () => {
  const privateKey = base64ToBytes(RSA_VECTOR.privateKeyPkcs8B64);

  it('unwraps provider organizations through the provider key and ignores organizationsNew keys', async () => {
    const wrappedProviderOrgKey = await encryptBytes(
      serializeSymmetricKey(userKey),
      orgKey,
      new Uint8Array(16).fill(31),
    );
    const map = await buildSyncProfileOrgKeyMap({
      id: 'user-1',
      email: 'user@example.com',
      organizations: [{ id: 'direct', key: ORG_KEY_VECTOR.encOrgKey }],
      organizationsNew: [{ id: 'accepted-only', key: ORG_KEY_VECTOR.encOrgKey, status: 1 }],
      providers: [{ id: 'provider-1', key: ORG_KEY_VECTOR.encOrgKey }],
      providerOrganizations: [{
        id: 'provider-org',
        providerId: 'provider-1',
        key: wrappedProviderOrgKey,
      }],
    }, privateKey);

    expect(map.has('direct')).toBe(true);
    expect(map.has('accepted-only')).toBe(false);
    expect(map.get('provider-org')).toEqual(userKey);
  });

  it('uses the provider projection for a duplicate organization id', async () => {
    const wrappedProviderOrgKey = await encryptBytes(
      serializeSymmetricKey(userKey),
      orgKey,
      new Uint8Array(16).fill(32),
    );
    const map = await buildSyncProfileOrgKeyMap({
      id: 'user-1',
      email: 'user@example.com',
      organizations: [{ id: 'shared', key: ORG_KEY_VECTOR.encOrgKey }],
      providers: [{ id: 'provider-1', key: ORG_KEY_VECTOR.encOrgKey }],
      providerOrganizations: [{ id: 'shared', providerId: 'provider-1', key: wrappedProviderOrgKey }],
    }, privateKey);

    expect(map.get('shared')).toEqual(userKey);
  });

  it('isolates malformed direct, provider, and provider-organization records', async () => {
    const validWrappedKey = await encryptBytes(
      serializeSymmetricKey(userKey),
      orgKey,
      new Uint8Array(16).fill(33),
    );
    const badWrappedKey = `${validWrappedKey.slice(0, -1)}${validWrappedKey.endsWith('A') ? 'B' : 'A'}`;
    const map = await buildSyncProfileOrgKeyMap({
      id: 'user-1',
      email: 'user@example.com',
      organizations: [
        { id: 'bad-direct', key: '4.invalid' },
        { id: 'good-direct', key: ORG_KEY_VECTOR.encOrgKey },
      ],
      providers: [
        { id: 'bad-provider', key: '4.invalid' },
        { id: 'good-provider', key: ORG_KEY_VECTOR.encOrgKey },
      ],
      providerOrganizations: [
        { id: 'missing-provider', providerId: 'bad-provider', key: validWrappedKey },
        { id: 'bad-provider-org', providerId: 'good-provider', key: badWrappedKey },
        { id: 'good-provider-org', providerId: 'good-provider', key: validWrappedKey },
      ],
    }, privateKey);

    expect([...map.keys()]).toEqual(['good-direct', 'good-provider-org']);
    expect(map.get('good-provider-org')).toEqual(userKey);
  });

  it('fails closed for a malformed provider override of a valid direct key', async () => {
    const map = await buildSyncProfileOrgKeyMap({
      id: 'user-1',
      email: 'user@example.com',
      organizations: [{ id: 'shared', key: ORG_KEY_VECTOR.encOrgKey }],
      providerOrganizations: [{ id: 'shared', providerId: 'missing', key: '2.invalid' }],
    }, privateKey);

    expect(map.has('shared')).toBe(false);
  });
});
