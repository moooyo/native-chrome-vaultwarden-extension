import { describe, expect, it, vi } from 'vitest';
import type { CipherResponse, SyncResponse } from '../api/types.js';
import { encryptToBytes, encryptToText } from '../crypto/encstring.js';
import { bytesToUtf8 } from '../crypto/encoding.js';
import {
  serializeSymmetricKey,
  symmetricKeyFromBytes,
  type SymmetricKey,
} from '../crypto/keys.js';
import {
  createStrictVaultTransferExportDecryptors,
  encodeVaultTransferJsonBytes,
} from './vault-transfer-export-crypto.js';
import { buildVaultTransferExport } from './vault-transfer-export.js';
import { computeLoginUriChecksum } from './login-uri-checksum.js';

const userKey = keyFilled(0x11, 0x22);
const itemKey = keyFilled(0x33, 0x44);
const organizationKey = keyFilled(0x55, 0x66);
const attachmentKey = keyFilled(0x77, 0x88);

function keyFilled(enc: number, mac: number): SymmetricKey {
  const bytes = new Uint8Array(64);
  bytes.fill(enc, 0, 32);
  bytes.fill(mac, 32);
  return symmetricKeyFromBytes(bytes);
}

async function wrapKey(key: SymmetricKey, wrappingKey: SymmetricKey): Promise<string> {
  return encryptToBytes(serializeSymmetricKey(key), wrappingKey);
}

async function fullLoginCipher(): Promise<CipherResponse> {
  const enc = (value: string) => encryptToText(value, itemKey);
  const firstUri = 'https://example.com';
  const firstUriCiphertext = await enc(firstUri);
  return {
    id: 'login-1',
    type: 1,
    organizationId: null,
    folderId: 'folder-1',
    collectionIds: null,
    key: await wrapKey(itemKey, userKey),
    name: await enc('Complete login'),
    notes: await enc('Preserved notes'),
    favorite: true,
    reprompt: 1,
    fields: [
      { type: 0, name: await enc('Environment'), value: await enc('production') },
      { type: 1, name: null, value: await enc('hidden') },
      { type: 2, name: await enc('Enabled'), value: await enc('true'), linkedId: null },
      { type: 3, name: await enc('Login username'), value: null, linkedId: 100 },
    ],
    passwordHistory: [{ password: await enc('old-password'), lastUsedDate: '2025-01-01T00:00:00.000Z' }],
    login: {
      uri: firstUriCiphertext,
      username: await enc('alice'),
      password: await enc('current-password'),
      totp: null,
      autofillOnPageLoad: false,
      passwordRevisionDate: '2026-01-01T02:03:04.1234567Z',
      uris: [
        {
          uri: firstUriCiphertext,
          uriChecksum: await enc(await computeLoginUriChecksum(firstUri)),
          match: 0,
        },
        { uri: await enc('example.org'), match: null },
      ],
      fido2Credentials: [{
        credentialId: await enc('credential-id'),
        keyType: await enc('public-key'),
        keyAlgorithm: await enc('ECDSA'),
        keyCurve: await enc('P-256'),
        keyValue: await enc('private-key'),
        rpId: await enc('example.com'),
        userHandle: null,
        userName: await enc('alice@example.com'),
        counter: await enc('4'),
        rpName: await enc('Example'),
        userDisplayName: null,
        discoverable: await enc('true'),
        creationDate: '2026-01-02T03:04:05.000Z',
      }],
    },
    attachments: [{
      id: 'attachment-1',
      url: 'https://files.example/attachment-1',
      key: await wrapKey(attachmentKey, itemKey),
      fileName: await enc('report.txt'),
      size: '12',
      sizeName: null,
    }],
    creationDate: '2025-01-01T00:00:00.000Z',
    revisionDate: '2025-02-01T00:00:00.000Z',
  };
}

function personalDecryptors() {
  return createStrictVaultTransferExportDecryptors({ scope: { kind: 'personal' }, userKey });
}

describe('createStrictVaultTransferExportDecryptors', () => {
  it('runs the accessor-safe compatibility gate before reading cipher fields', async () => {
    const typeGetter = vi.fn(() => 1);
    const cipher = Object.defineProperty({
      id: 'hostile',
      name: '2.name',
      login: {},
    }, 'type', { enumerable: true, get: typeGetter });

    await expect(personalDecryptors().decryptCipher(cipher as CipherResponse, 0)).resolves.toEqual({
      status: 'failed', code: 'undecryptable',
    });
    expect(typeGetter).not.toHaveBeenCalled();
  });

  it('decrypts every supported login field with the per-cipher key and preserves nullable shape', async () => {
    const result = await personalDecryptors().decryptCipher(await fullLoginCipher(), 0);

    expect(result.status).toBe('decrypted');
    if (result.status !== 'decrypted') return;
    expect(result.value).toEqual({
      type: 1,
      name: 'Complete login',
      notes: 'Preserved notes',
      fields: [
        { type: 0, name: 'Environment', value: 'production' },
        { type: 1, name: null, value: 'hidden' },
        { type: 2, name: 'Enabled', value: 'true', linkedId: null },
        { type: 3, name: 'Login username', value: null, linkedId: 100 },
      ],
      passwordHistory: [{ password: 'old-password', lastUsedDate: '2025-01-01T00:00:00.000Z' }],
      login: {
        username: 'alice',
        password: 'current-password',
        totp: null,
        autofillOnPageLoad: false,
        passwordRevisionDate: '2026-01-01T02:03:04.1234567Z',
        uris: [
          { uri: 'https://example.com', match: 0 },
          { uri: 'example.org', match: null },
        ],
        fido2Credentials: [{
          credentialId: 'credential-id',
          keyType: 'public-key',
          keyAlgorithm: 'ECDSA',
          keyCurve: 'P-256',
          keyValue: 'private-key',
          rpId: 'example.com',
          userHandle: null,
          userName: 'alice@example.com',
          counter: '4',
          rpName: 'Example',
          userDisplayName: null,
          discoverable: 'true',
          creationDate: '2026-01-02T03:04:05.000Z',
        }],
      },
      attachments: [{
        id: 'attachment-1', fileName: 'report.txt', size: '12', sizeName: null,
      }],
    });
  });

  it('decrypts secure note, card, identity, and complete SSH payloads', async () => {
    const enc = (value: string) => encryptToText(value, userKey);
    const card = {
      id: 'card', type: 3, name: await enc('Card'), card: {
        cardholderName: await enc('Alice'), brand: null, number: await enc('4111111111111111'),
        expMonth: await enc('01'), expYear: await enc('2030'), code: await enc('123'),
      },
    } satisfies CipherResponse;
    const identityValues = [
      'title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3', 'city',
      'state', 'postalCode', 'country', 'company', 'email', 'phone', 'ssn', 'username',
      'passportNumber', 'licenseNumber',
    ] as const;
    const identity: Record<string, string> = {};
    for (const field of identityValues) identity[field] = await enc(field);
    const ciphers: CipherResponse[] = [
      { id: 'note', type: 2, name: await enc('Note'), notes: null, secureNote: { type: 0 } },
      card,
      { id: 'identity', type: 4, name: await enc('Identity'), identity },
      {
        id: 'ssh', type: 5, name: await enc('SSH'), sshKey: {
          privateKey: await enc('PRIVATE'),
          publicKey: await enc('PUBLIC'),
          keyFingerprint: await enc('SHA256:fingerprint'),
        },
      },
    ];

    const results = await Promise.all(ciphers.map((cipher, index) =>
      personalDecryptors().decryptCipher(cipher, index)));
    expect(results).toEqual([
      { status: 'decrypted', value: { type: 2, name: 'Note', notes: null, secureNote: { type: 0 } } },
      { status: 'decrypted', value: {
        type: 3, name: 'Card', card: {
          cardholderName: 'Alice', brand: null, number: '4111111111111111',
          expMonth: '01', expYear: '2030', code: '123',
        },
      } },
      { status: 'decrypted', value: {
        type: 4, name: 'Identity', identity: Object.fromEntries(identityValues.map((field) => [field, field])),
      } },
      { status: 'decrypted', value: {
        type: 5, name: 'SSH', sshKey: {
          privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:fingerprint',
        },
      } },
    ]);
  });

  it('uses the selected organization key before unwrapping an organization item key', async () => {
    const organizationItemKey = keyFilled(0x91, 0x92);
    const decryptors = createStrictVaultTransferExportDecryptors({
      scope: { kind: 'organization', organizationId: 'org-1' },
      userKey,
      organizationKeys: new Map([['org-1', organizationKey]]),
    });
    const cipher: CipherResponse = {
      id: 'org-note', type: 2, organizationId: 'org-1', collectionIds: ['collection-1'],
      key: await wrapKey(organizationItemKey, organizationKey),
      name: await encryptToText('Organization note', organizationItemKey),
      secureNote: { type: 0 },
    };

    await expect(decryptors.decryptCollection({
      id: 'collection-1', organizationId: 'org-1', name: await encryptToText('Engineering', organizationKey),
    }, 0)).resolves.toEqual({ status: 'decrypted', value: { name: 'Engineering' } });
    await expect(decryptors.decryptCipher(cipher, 0)).resolves.toEqual({
      status: 'decrypted',
      value: { type: 2, name: 'Organization note', secureNote: { type: 0 } },
    });
  });

  it('refuses organization data in personal scope and reports a missing selected organization key', async () => {
    const orgCipher: CipherResponse = {
      id: 'org-note', type: 2, organizationId: 'org-1',
      name: await encryptToText('Organization note', organizationKey), secureNote: { type: 0 },
    };
    await expect(personalDecryptors().decryptCipher(orgCipher, 0)).resolves.toEqual({
      status: 'failed', code: 'undecryptable',
    });
    await expect(createStrictVaultTransferExportDecryptors({
      scope: { kind: 'organization', organizationId: 'org-1' }, userKey,
    }).decryptCipher(orgCipher, 0)).resolves.toEqual({
      status: 'failed', code: 'missing_organization_key',
    });
  });

  it('fails the whole object on a bad MAC, unsupported EncString, or invalid UTF-8', async () => {
    const base = await fullLoginCipher();
    const tampered = { ...base, name: tamperMac(base.name!) };
    const unsupported = { ...base, name: '1.unsupported' };
    const invalidUtf8 = { ...base, name: await encryptToBytes(new Uint8Array([0xff]), itemKey) };

    await expect(personalDecryptors().decryptCipher(tampered, 0)).resolves.toEqual({
      status: 'failed', code: 'undecryptable',
    });
    await expect(personalDecryptors().decryptCipher(unsupported, 0)).resolves.toEqual({
      status: 'failed', code: 'unsupported_encryption',
    });
    await expect(personalDecryptors().decryptCipher(invalidUtf8, 0)).resolves.toEqual({
      status: 'failed', code: 'undecryptable',
    });
  });

  it('fails on missing required fields, unknown payload data, and invalid attachment keys', async () => {
    const complete = await fullLoginCipher();
    const missingPasskey = structuredClone(complete);
    delete missingPasskey.login!.fido2Credentials![0]!.keyAlgorithm;
    const unknownNested = structuredClone(complete);
    (unknownNested.login as Record<string, unknown>).futureSecret = complete.login!.password;
    const unknownRoot = structuredClone(complete);
    (unknownRoot as unknown as Record<string, unknown>).futureSecret = complete.login!.password;
    const conflictingPayload = structuredClone(complete);
    conflictingPayload.card = {};
    const missingName = structuredClone(complete);
    delete missingName.name;
    const badCustomField = structuredClone(complete);
    badCustomField.fields![0]!.value = tamperMac(badCustomField.fields![0]!.value!);
    const missingSshField: CipherResponse = {
      id: 'ssh', type: 5, name: await encryptToText('SSH', userKey),
      sshKey: { privateKey: await encryptToText('PRIVATE', userKey) },
    };
    const badAttachment = structuredClone(complete);
    badAttachment.attachments![0]!.key = tamperMac(badAttachment.attachments![0]!.key!);
    const badAutofill = structuredClone(complete);
    (badAutofill.login as Record<string, unknown>).autofillOnPageLoad = 0;
    const badPasswordRevision = structuredClone(complete);
    badPasswordRevision.login!.passwordRevisionDate = '2026-02-30T03:04:05Z';

    for (const cipher of [
      missingPasskey,
      unknownNested,
      unknownRoot,
      conflictingPayload,
      missingName,
      badCustomField,
      missingSshField,
      badAttachment,
      badAutofill,
      badPasswordRevision,
    ]) {
      await expect(personalDecryptors().decryptCipher(cipher, 0)).resolves.toEqual({
        status: 'failed', code: 'undecryptable',
      });
    }
  });

  it('blocks a mismatched legacy URI alias before accepting the structured login', async () => {
    const cipher = await fullLoginCipher();
    cipher.login!.uri = await encryptToText('https://different.example', itemKey);
    await expect(personalDecryptors().decryptCipher(cipher, 0)).resolves.toEqual({
      status: 'failed', code: 'undecryptable',
    });
  });

  it('decrypts and validates URI checksums but never exports the derived checksum', async () => {
    const valid = await fullLoginCipher();
    const result = await personalDecryptors().decryptCipher(valid, 0);
    expect(result).toMatchObject({ status: 'decrypted' });
    expect(JSON.stringify(result)).not.toContain('EAaArVRs5qV39C9S3zO0z9ynVoWeZkuNfeMpsVDQnOk=');

    const mismatch = await fullLoginCipher();
    mismatch.login!.uris![0]!.uriChecksum = await encryptToText(
      await computeLoginUriChecksum('https://different.example'),
      itemKey,
    );
    await expect(personalDecryptors().decryptCipher(mismatch, 0)).resolves.toEqual({
      status: 'failed', code: 'undecryptable',
    });

    const malformed = await fullLoginCipher();
    malformed.login!.uris![0]!.uriChecksum = tamperMac(malformed.login!.uris![0]!.uriChecksum!);
    await expect(personalDecryptors().decryptCipher(malformed, 0)).resolves.toEqual({
      status: 'failed', code: 'undecryptable',
    });
  });

  it.each([6, 7, 8])('does not claim support for cipher type %i', async (type) => {
    const cipher: CipherResponse = {
      id: `future-${type}`, type, name: await encryptToText('Future', userKey),
      [type === 6 ? 'bankAccount' : type === 7 ? 'driversLicense' : 'passport']: {},
    };
    await expect(personalDecryptors().decryptCipher(cipher, 0)).resolves.toEqual({
      status: 'failed', code: 'unsupported_encryption',
    });
  });
});

describe('encodeVaultTransferJsonBytes', () => {
  it('runs strict crypto through the export builder and returns canonical UTF-8 bytes', async () => {
    const cipher = await fullLoginCipher();
    const sync: SyncResponse = {
      profile: { id: 'user-1', email: 'alice@example.com' },
      folders: [{ id: 'folder-1', name: await encryptToText('Personal', userKey) }],
      ciphers: [cipher],
    };
    const built = await buildVaultTransferExport(
      sync,
      { scope: { kind: 'personal' } },
      personalDecryptors(),
    );
    expect(built.ok).toBe(true);
    expect(built.attachments).toEqual([expect.objectContaining({
      attachmentId: 'attachment-1', fileName: 'report.txt', itemSourceIndex: 0,
    })]);

    const encoded = encodeVaultTransferJsonBytes(built.ir!);
    expect(encoded.ok).toBe(true);
    if (!encoded.ok) return;
    const document = JSON.parse(bytesToUtf8(encoded.bytes)) as {
      encrypted: boolean;
      items: Array<{
        name: string;
        login: {
          autofillOnPageLoad: boolean | null;
          passwordRevisionDate: string | null;
          fido2Credentials: Array<{ keyValue: string }>;
        };
      }>;
    };
    expect(document.encrypted).toBe(false);
    expect(document.items[0]).toMatchObject({
      name: 'Complete login',
      login: {
        autofillOnPageLoad: false,
        passwordRevisionDate: '2026-01-01T02:03:04.1234567Z',
        fido2Credentials: [{ keyValue: 'private-key' }],
      },
    });
    expect(bytesToUtf8(encoded.bytes)).not.toContain(cipher.key!);
  });

  it('returns structured diagnostics and no bytes when the IR cannot be encoded', async () => {
    const sync: SyncResponse = {
      profile: { id: 'user-1', email: 'alice@example.com' },
      ciphers: [{
        id: 'note', type: 2, name: await encryptToText('Note', userKey), secureNote: { type: 0 },
      }],
    };
    const built = await buildVaultTransferExport(
      sync,
      { scope: { kind: 'personal' } },
      personalDecryptors(),
    );
    expect(built.ok).toBe(true);
    const invalidIr = { ...built.ir!, version: 2 } as unknown as NonNullable<typeof built.ir>;
    const encoded = encodeVaultTransferJsonBytes(invalidIr);
    expect(encoded).toEqual(expect.objectContaining({ ok: false, bytes: null }));
    expect(encoded.diagnostics).toContainEqual(expect.objectContaining({
      severity: 'error', code: 'unsupported_ir_version', path: '$.version',
    }));
  });
});

function tamperMac(value: string): string {
  const parts = value.split('|');
  const mac = parts[2];
  if (parts.length !== 3 || !mac) throw new Error('Expected an authenticated EncString');
  parts[2] = `${mac[0] === 'A' ? 'B' : 'A'}${mac.slice(1)}`;
  return parts.join('|');
}
