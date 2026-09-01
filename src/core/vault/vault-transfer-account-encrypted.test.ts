import { describe, expect, it, vi } from 'vitest';
import type { CipherResponse, SyncResponse } from '../api/types.js';
import { decryptToBytes, encryptToBytes, encryptToText } from '../crypto/encstring.js';
import { bytesToUtf8 } from '../crypto/encoding.js';
import {
  serializeSymmetricKey,
  symmetricKeyFromBytes,
  type SymmetricKey,
} from '../crypto/keys.js';
import { buildVaultTransferExport } from './vault-transfer-export.js';
import { createStrictVaultTransferExportDecryptors } from './vault-transfer-export-crypto.js';
import { computeLoginUriChecksum } from './login-uri-checksum.js';
import {
  AccountEncryptedVaultTransferError,
  encodeAccountEncryptedVaultExport,
  inspectAccountEncryptedVaultExport,
} from './vault-transfer-account-encrypted.js';

const DATE = '2026-08-01T12:00:00.000Z';

interface TestLoginDocument extends Record<string, unknown> {
  uris: Array<Record<string, unknown>>;
}

interface TestItemDocument extends Record<string, unknown> {
  name: string;
  login: TestLoginDocument;
}

interface TestPersonalDocument extends Record<string, unknown> {
  encKeyValidation_DO_NOT_EDIT: string;
  folders: Array<Record<string, unknown>>;
  items: TestItemDocument[];
}

interface TestOrganizationDocument extends Record<string, unknown> {
  encKeyValidation_DO_NOT_EDIT: string;
  collections: Array<Record<string, unknown>>;
  items: Array<Record<string, unknown> & { collectionIds: string[] }>;
}

function parsePersonalDocument(value: string): TestPersonalDocument {
  return JSON.parse(value) as TestPersonalDocument;
}

function parseOrganizationDocument(value: string): TestOrganizationDocument {
  return JSON.parse(value) as TestOrganizationDocument;
}

function key(seed: number): SymmetricKey {
  return symmetricKeyFromBytes(Uint8Array.from({ length: 64 }, (_, index) => (seed + index) & 0xff));
}

async function personalFixture() {
  const userKey = key(1);
  const itemKey = key(91);
  const wrappedItemKey = await encryptToBytes(serializeSymmetricKey(itemKey), userKey);
  const folderId = 'folder-1';
  const cipher: CipherResponse = {
    id: 'cipher-1',
    organizationId: null,
    folderId,
    collectionIds: null,
    type: 1,
    reprompt: 0,
    name: await encryptToText('Official account export', itemKey),
    notes: await encryptToText('Encrypted notes', itemKey),
    key: wrappedItemKey,
    favorite: true,
    fields: [{
      type: 1,
      name: await encryptToText('Hidden', itemKey),
      value: await encryptToText('secret', itemKey),
    }],
    login: {
      uris: [{
        uri: await encryptToText('https://example.com', itemKey),
        uriChecksum: await encryptToText(await computeLoginUriChecksum('https://example.com'), itemKey),
        match: 0,
      }],
      username: await encryptToText('alice', itemKey),
      password: await encryptToText('password', itemKey),
      totp: null,
      autofillOnPageLoad: true,
      passwordRevisionDate: DATE,
      fido2Credentials: [],
    },
    passwordHistory: [{ password: await encryptToText('old-password', itemKey), lastUsedDate: DATE }],
    creationDate: DATE,
    revisionDate: DATE,
    deletedDate: null,
    archivedDate: null,
  };
  const sync: SyncResponse = {
    profile: { id: 'user-1', email: 'alice@example.com' },
    folders: [{ id: folderId, name: await encryptToText('Folder', userKey) }],
    ciphers: [cipher],
  };
  const built = await buildVaultTransferExport(sync, { scope: { kind: 'personal' } },
    createStrictVaultTransferExportDecryptors({ scope: { kind: 'personal' }, userKey }));
  expect(built.ok).toBe(true);
  expect(built.ir).not.toBeNull();
  return { userKey, itemKey, sync, ir: built.ir! };
}

async function encodedPersonal() {
  const fixture = await personalFixture();
  const bytes = await encodeAccountEncryptedVaultExport(
    fixture.sync,
    fixture.ir,
    fixture.userKey,
    { maxOutputBytes: 1024 * 1024, validationText: () => 'fixed-validation' },
  );
  return { ...fixture, bytes, json: bytesToUtf8(bytes) };
}

async function organizationFixture() {
  const userKey = key(1);
  const orgKey = key(70);
  const itemKey = key(140);
  const organizationId = 'org-1';
  const collectionIds = ['collection-b', 'collection-a'];
  const sync: SyncResponse = {
    profile: {
      id: 'user-1',
      email: 'alice@example.com',
      organizations: [{ id: organizationId }],
    },
    collections: [
      {
        id: 'collection-a',
        organizationId,
        name: await encryptToText('Engineering', orgKey),
        externalId: null,
        readOnly: false,
        manage: true,
        hidePasswords: false,
      },
      {
        id: 'collection-b',
        organizationId,
        name: await encryptToText('Operations', orgKey),
        externalId: 'external-operations',
        readOnly: false,
        manage: true,
        hidePasswords: false,
      },
    ],
    ciphers: [{
      id: 'cipher-org',
      organizationId,
      folderId: null,
      collectionIds,
      type: 2,
      reprompt: 0,
      name: await encryptToText('Runbook', itemKey),
      notes: await encryptToText('Encrypted organization notes', itemKey),
      key: await encryptToBytes(serializeSymmetricKey(itemKey), orgKey),
      favorite: false,
      secureNote: { type: 0 },
      creationDate: DATE,
      revisionDate: DATE,
      deletedDate: null,
      archivedDate: null,
    }],
  };
  const scope = { kind: 'organization', organizationId } as const;
  const built = await buildVaultTransferExport(
    sync,
    { scope },
    createStrictVaultTransferExportDecryptors({
      scope,
      userKey,
      organizationKeys: new Map([[organizationId, orgKey]]),
    }),
  );
  expect(built.ok).toBe(true);
  expect(built.ir).not.toBeNull();
  return { userKey, orgKey, organizationId, collectionIds, sync, ir: built.ir! };
}

function expectAuthenticationFailure(error: unknown): void {
  expect(error).toBeInstanceOf(AccountEncryptedVaultTransferError);
  expect(error).toMatchObject({
    code: 'authentication_failed',
    message: 'The account-encrypted vault transfer could not be authenticated.',
  });
}

describe('Bitwarden account-encrypted export encoding', () => {
  it('emits the v2026.8 personal shape without a password envelope or sync-only fields', async () => {
    const { json, userKey } = await encodedPersonal();
    const document = parsePersonalDocument(json);

    expect(Object.keys(document)).toEqual([
      'encrypted', 'encKeyValidation_DO_NOT_EDIT', 'folders', 'items',
    ]);
    expect(document).not.toHaveProperty('passwordProtected');
    expect(document).not.toHaveProperty('data');
    expect(Object.keys(document.folders[0]!)).toEqual(['id', 'name']);
    expect(document.items[0]!).toMatchObject({
      id: 'cipher-1',
      organizationId: null,
      folderId: 'folder-1',
      type: 1,
      reprompt: 0,
      favorite: true,
      collectionIds: null,
    });
    expect(document.items[0]!).not.toHaveProperty('attachments');
    expect(Object.keys(document.items[0]!.login).sort()).toEqual([
      'fido2Credentials', 'password', 'uris', 'username',
    ]);
    expect(document.items[0]!.login).not.toHaveProperty('autofillOnPageLoad');
    expect(document.items[0]!.login).not.toHaveProperty('passwordRevisionDate');
    expect(document.items[0]!.login.uris[0]).toHaveProperty('uriChecksum');

    const validation = await decryptToBytes(document.encKeyValidation_DO_NOT_EDIT, userKey);
    try {
      expect(bytesToUtf8(validation)).toBe('fixed-validation');
    } finally {
      validation.fill(0);
    }
  });

  it('emits the exact organization shape and authenticates it with the specified OrgKey', async () => {
    const fixture = await organizationFixture();
    const bytes = await encodeAccountEncryptedVaultExport(
      fixture.sync,
      fixture.ir,
      fixture.userKey,
      {
        maxOutputBytes: 1024 * 1024,
        validationText: () => 'fixed-org-validation',
        organization: { organizationId: fixture.organizationId, key: fixture.orgKey },
      },
    );
    const json = bytesToUtf8(bytes);
    const document = parseOrganizationDocument(json);

    expect(Object.keys(document)).toEqual([
      'encrypted', 'encKeyValidation_DO_NOT_EDIT', 'collections', 'items',
    ]);
    expect(document).not.toHaveProperty('folders');
    expect(document).not.toHaveProperty('passwordProtected');
    expect(document).not.toHaveProperty('data');
    expect(document.collections).toHaveLength(2);
    expect(Object.keys(document.collections[0]!)).toEqual([
      'id', 'organizationId', 'name', 'externalId',
    ]);
    expect(document.collections[0]).not.toHaveProperty('manage');
    expect(document.collections[0]).not.toHaveProperty('readOnly');
    expect(document.items[0]).toMatchObject({
      id: 'cipher-org',
      organizationId: fixture.organizationId,
      folderId: null,
      type: 2,
      collectionIds: fixture.collectionIds,
    });
    expect(document.items[0]!.collectionIds).toEqual(['collection-b', 'collection-a']);

    const validation = await decryptToBytes(document.encKeyValidation_DO_NOT_EDIT, fixture.orgKey);
    try {
      expect(bytesToUtf8(validation)).toBe('fixed-org-validation');
    } finally {
      validation.fill(0);
    }
    await expect(decryptToBytes(
      document.encKeyValidation_DO_NOT_EDIT,
      fixture.userKey,
    )).rejects.toBeDefined();

    const inspection = await inspectAccountEncryptedVaultExport(json, {
      userKey: fixture.userKey,
      organizationKeys: new Map([[fixture.organizationId, fixture.orgKey]]),
    });
    expect(inspection.ir).toMatchObject({
      scope: 'organization',
      collections: [
        { id: 'collection-a', organizationId: fixture.organizationId },
        { id: 'collection-b', organizationId: fixture.organizationId },
      ],
      items: [{
        id: 'cipher-org',
        organizationId: fixture.organizationId,
        collectionIds: fixture.collectionIds,
      }],
    });
  });

  it('rejects absent authority, mixed organizations, and collection references outside the selection', async () => {
    const fixture = await organizationFixture();
    const mixedCollection = structuredClone(fixture.sync);
    mixedCollection.collections![0]!.organizationId = 'other-org';
    const mixedItem = structuredClone(fixture.sync);
    mixedItem.ciphers[0]!.organizationId = 'other-org';
    const danglingIr = structuredClone(fixture.ir);
    danglingIr.collections = danglingIr.collections.filter((collection) => collection.id !== 'collection-b');
    const personal = await personalFixture();
    const organization = { organizationId: fixture.organizationId, key: fixture.orgKey };

    const attempts = [
      () => encodeAccountEncryptedVaultExport(fixture.sync, fixture.ir, fixture.userKey, {
        maxOutputBytes: 1024 * 1024,
      }),
      () => encodeAccountEncryptedVaultExport(fixture.sync, fixture.ir, fixture.userKey, {
        maxOutputBytes: 1024 * 1024,
        organization: { organizationId: 'other-org', key: fixture.orgKey },
      }),
      () => encodeAccountEncryptedVaultExport(mixedCollection, fixture.ir, fixture.userKey, {
        maxOutputBytes: 1024 * 1024,
        organization,
      }),
      () => encodeAccountEncryptedVaultExport(mixedItem, fixture.ir, fixture.userKey, {
        maxOutputBytes: 1024 * 1024,
        organization,
      }),
      () => encodeAccountEncryptedVaultExport(fixture.sync, danglingIr, fixture.userKey, {
        maxOutputBytes: 1024 * 1024,
        organization,
      }),
      () => encodeAccountEncryptedVaultExport(personal.sync, personal.ir, personal.userKey, {
        maxOutputBytes: 1024 * 1024,
        organization,
      }),
    ];
    for (const attempt of attempts) {
      await expect(attempt()).rejects.toSatisfy((error: unknown) => {
        expectAuthenticationFailure(error);
        return true;
      });
    }
  });

  it('zeroes validation plaintext and rejects oversized output without returning bytes', async () => {
    const fixture = await personalFixture();
    let observed: Uint8Array | undefined;
    await encodeAccountEncryptedVaultExport(fixture.sync, fixture.ir, fixture.userKey, {
      maxOutputBytes: 1024 * 1024,
      validationText: () => 'ephemeral-validation',
      crypto: {
        encryptBytes: async (plaintext, encryptionKey) => {
          observed = plaintext;
          return encryptToBytes(plaintext, encryptionKey);
        },
      },
    });
    expect(observed).toBeDefined();
    expect(observed?.every((byte) => byte === 0)).toBe(true);

    await expect(encodeAccountEncryptedVaultExport(fixture.sync, fixture.ir, fixture.userKey, {
      maxOutputBytes: 1,
      validationText: () => 'validation',
    })).rejects.toSatisfy((error: unknown) => {
      expectAuthenticationFailure(error);
      return true;
    });
  });
});

describe('Bitwarden account-encrypted import inspection', () => {
  it('authenticates the UserKey, unwraps per-item keys, and returns plaintext IR', async () => {
    const { json, userKey } = await encodedPersonal();
    const loadOrganizationKeys = vi.fn(async () => new Map<string, SymmetricKey>());
    const inspection = await inspectAccountEncryptedVaultExport(json, { userKey, loadOrganizationKeys });
    expect(inspection.canCommit).toBe(true);
    expect(inspection.ir).toMatchObject({ scope: 'personal', format: 'bitwarden-json' });
    expect(inspection.ir?.folders[0]).toMatchObject({ id: 'folder-1', name: 'Folder' });
    expect(inspection.ir?.items[0]).toMatchObject({
      kind: 'login',
      name: 'Official account export',
      notes: 'Encrypted notes',
    });
    expect(inspection.ir?.items[0]?.fields[0]).toMatchObject({ name: 'Hidden', value: 'secret' });
    expect(loadOrganizationKeys).not.toHaveBeenCalled();
  });

  it('uses one indistinguishable failure for a wrong account, marker tamper, and item tamper', async () => {
    const { json, userKey } = await encodedPersonal();
    const wrongAccount = key(200);
    const markerTamper = parsePersonalDocument(json);
    markerTamper.encKeyValidation_DO_NOT_EDIT += 'A';
    const itemTamper = parsePersonalDocument(json);
    itemTamper.items[0]!.name += 'A';

    const attempts = [
      inspectAccountEncryptedVaultExport(json, { userKey: wrongAccount }),
      inspectAccountEncryptedVaultExport(JSON.stringify(markerTamper), { userKey }),
      inspectAccountEncryptedVaultExport(JSON.stringify(itemTamper), { userKey }),
    ];
    const errors = await Promise.all(attempts.map((attempt) => attempt.then(
      () => undefined,
      (error: unknown) => error,
    )));
    for (const error of errors) expectAuthenticationFailure(error);
    expect(new Set(errors.map((error) => (error as Error).message)).size).toBe(1);
  });

  it('selects the unique OrgKey without enabling organization commit', async () => {
    const userKey = key(1);
    const orgKey = key(70);
    const otherOrgKey = key(120);
    const organizationId = 'org-1';
    const collectionId = 'collection-1';
    const validation = await encryptToText('org-validation', orgKey);
    const json = JSON.stringify({
      encrypted: true,
      encKeyValidation_DO_NOT_EDIT: validation,
      collections: [{
        id: collectionId,
        organizationId,
        name: await encryptToText('Operations', orgKey),
        externalId: null,
      }],
      items: [{
        id: 'cipher-org',
        organizationId,
        folderId: null,
        type: 2,
        reprompt: 0,
        name: await encryptToText('Runbook', orgKey),
        favorite: false,
        secureNote: { type: 0 },
        collectionIds: [collectionId],
      }],
    });

    const loadOrganizationKeys = vi.fn(async () => (
      new Map([['other-org', otherOrgKey], [organizationId, orgKey]])
    ));
    const inspection = await inspectAccountEncryptedVaultExport(json, {
      userKey,
      loadOrganizationKeys,
    });
    expect(inspection.canCommit).toBe(true);
    expect(inspection.ir).toMatchObject({ scope: 'organization' });
    expect(inspection.ir?.collections[0]).toMatchObject({ id: collectionId, name: 'Operations' });
    expect(inspection.ir?.items[0]).toMatchObject({ name: 'Runbook', organizationId });
    expect(loadOrganizationKeys).toHaveBeenCalledOnce();

    await expect(inspectAccountEncryptedVaultExport(json, {
      userKey,
      organizationKeys: new Map([['other-org', otherOrgKey]]),
    })).rejects.toSatisfy((error: unknown) => {
      expectAuthenticationFailure(error);
      return true;
    });
  });

  it('enforces exact root/nested shapes and resource limits before returning inspection data', async () => {
    const { json, userKey } = await encodedPersonal();
    const rootExtra = parsePersonalDocument(json);
    rootExtra.accountHint = 'do-not-accept';
    const nestedExtra = parsePersonalDocument(json);
    nestedExtra.items[0]!.login.passwordRevisionDate = DATE;
    const tooManyItems = parsePersonalDocument(json);
    tooManyItems.items.push(structuredClone(tooManyItems.items[0]!));

    for (const [content, limits] of [
      [JSON.stringify(rootExtra), undefined],
      [JSON.stringify(nestedExtra), undefined],
      [JSON.stringify(tooManyItems), { maxItems: 1 }],
      [json, { maxInputBytes: 1 }],
    ] as const) {
      await expect(inspectAccountEncryptedVaultExport(content, {
        userKey,
        ...(limits === undefined ? {} : { limits }),
      }))
        .rejects.toSatisfy((error: unknown) => {
          expectAuthenticationFailure(error);
          return true;
        });
    }
  });

  it('zeroes validation bytes and propagates final-authority revocation separately from auth failure', async () => {
    const { json, userKey } = await encodedPersonal();
    let validationBytes: Uint8Array | undefined;
    let checkpoints = 0;
    const revoked = new Error('authority revoked');
    const decryptBytes = vi.fn(async (ciphertext: string, encryptionKey: SymmetricKey) => {
      validationBytes = await decryptToBytes(ciphertext, encryptionKey);
      return validationBytes;
    });

    await expect(inspectAccountEncryptedVaultExport(json, {
      userKey,
      crypto: { decryptBytes },
      assertCurrent: () => {
        checkpoints++;
        if (checkpoints === 2) throw revoked;
      },
    })).rejects.toBe(revoked);
    expect(decryptBytes).toHaveBeenCalledOnce();
    expect(validationBytes?.every((byte) => byte === 0)).toBe(true);
  });
});
