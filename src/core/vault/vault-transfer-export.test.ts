import { describe, expect, it, vi } from 'vitest';
import type { SyncResponse } from '../api/types.js';
import { inspectVaultTransferJson } from './vault-transfer.js';
import { encodeVaultTransferJson } from './vault-transfer-json.js';
import {
  buildVaultTransferExport,
  type VaultTransferExportCipher,
  type VaultTransferExportDecryptors,
} from './vault-transfer-export.js';

function syncFixture(): SyncResponse {
  return {
    profile: {
      id: 'user-1',
      email: 'user@example.com',
      organizations: [
        { id: 'org-other', key: '4.other', name: 'Other', status: 2 },
        { id: 'org-target', key: '4.target', name: 'Target', status: 2 },
      ],
    },
    folders: [
      { id: 'folder-a', name: '2.folder-a' },
      { id: 'folder-b', name: '2.folder-b' },
    ],
    collections: [
      { id: 'collection-other', organizationId: 'org-other', name: '2.other' },
      { id: 'collection-target', organizationId: 'org-target', name: '2.target', externalId: null },
    ],
    ciphers: [
      {
        id: 'org-other-item', type: 2, organizationId: 'org-other', collectionIds: ['collection-other'],
        name: '2.name', favorite: false, secureNote: { type: 0 },
      },
      {
        id: 'personal-login', type: 1, organizationId: null, folderId: 'folder-b', collectionIds: null,
        name: '2.name', notes: '2.notes', favorite: true, reprompt: 1, key: '2.cipher-key',
        creationDate: '2025-01-01T00:00:00.000Z', revisionDate: '2025-02-01T00:00:00.000Z',
        archivedDate: null,
        fields: [{ type: 0, name: '2.field-name', value: '2.field-value' }, { type: 3, name: null, value: null, linkedId: 100 }],
        passwordHistory: [{ password: '2.old', lastUsedDate: '2024-12-01T00:00:00.000Z' }],
        login: {
          username: '2.username', password: '2.password', totp: '2.totp',
          autofillOnPageLoad: false,
          passwordRevisionDate: '2025-01-15T00:00:00.000Z',
          uris: [{ uri: '2.uri', match: 0 }],
          fido2Credentials: [{
            credentialId: '2.credential', keyType: '2.type', keyAlgorithm: '2.algorithm',
            keyCurve: '2.curve', keyValue: '2.key', rpId: '2.rp', counter: '2.counter',
            discoverable: '2.discoverable', creationDate: '2026-01-02T03:04:05.000Z',
          }],
        },
        attachments: [{
          id: 'attachment-1', url: 'https://files.example/a1', key: '2.attachment-key',
          fileName: '2.file-name', size: '12', sizeName: '12 B',
        }],
      },
      {
        id: 'personal-ssh', type: 5, organizationId: null, folderId: null,
        name: '2.name', favorite: false,
        sshKey: { privateKey: '2.private', publicKey: '2.public', keyFingerprint: '2.fingerprint' },
      },
      {
        id: 'org-target-item', type: 2, organizationId: 'org-target', collectionIds: ['collection-target'],
        name: '2.name', notes: null, favorite: false, reprompt: 0, secureNote: { type: 0 },
      },
    ],
  };
}

function loginPlaintext(): VaultTransferExportCipher {
  return {
    type: 1,
    name: 'Login "special" 雪',
    notes: '',
    fields: [
      { type: 0, name: 'environment', value: 'production' },
      { type: 3, name: null, value: null, linkedId: 100 },
    ],
    passwordHistory: [{ password: 'old-password', lastUsedDate: '2024-12-01T00:00:00.000Z' }],
    login: {
      username: 'alice',
      password: 'secret',
      totp: 'TOTP',
      autofillOnPageLoad: false,
      passwordRevisionDate: '2025-01-15T00:00:00.000Z',
      uris: [{ uri: 'https://example.com/a,b', match: 0 }],
      fido2Credentials: [{
        credentialId: 'credential-id', keyType: 'public-key', keyAlgorithm: 'ECDSA', keyCurve: 'P-256',
        keyValue: 'private-key', rpId: 'example.com', counter: '4', discoverable: 'true',
        creationDate: null,
      }],
    },
    attachments: [{ id: 'attachment-1', fileName: 'report 雪.txt', size: '12', sizeName: '12 B' }],
  };
}

function decryptors(overrides: Partial<VaultTransferExportDecryptors> = {}): VaultTransferExportDecryptors {
  const decryptCipher: VaultTransferExportDecryptors['decryptCipher'] = async (cipher) => {
    const values: Record<string, VaultTransferExportCipher> = {
      'personal-login': loginPlaintext(),
      'personal-ssh': {
        type: 5,
        name: 'Deploy key',
        sshKey: { privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:abc' },
      },
      'org-target-item': { type: 2, name: 'Runbook', notes: null, secureNote: { type: 0 } },
      'org-other-item': { type: 2, name: 'Other note', secureNote: { type: 0 } },
    };
    const value = values[cipher.id];
    return value ? { status: 'decrypted', value } : { status: 'failed', code: 'undecryptable' };
  };
  return {
    decryptFolder: vi.fn(async (folder) => ({ status: 'decrypted', value: { name: folder.id === 'folder-a' ? 'A' : 'B' } } as const)),
    decryptCollection: vi.fn(async (collection) => ({ status: 'decrypted', value: { name: collection.id === 'collection-target' ? 'Engineering' : 'Other' } } as const)),
    decryptCipher: vi.fn(decryptCipher),
    ...overrides,
  };
}

describe('buildVaultTransferExport personal scope', () => {
  it('builds complete source-indexed IR plus attachment metadata and round-trips through the encoder', async () => {
    const sync = syncFixture();
    const deps = decryptors();
    const built = await buildVaultTransferExport(sync, { scope: { kind: 'personal' } }, deps);

    expect(built.ok).toBe(true);
    expect(built.ir).not.toBeNull();
    expect(built.ir).toMatchObject({
      scope: 'personal',
      folders: [{ sourceIndex: 0, id: 'folder-a' }, { sourceIndex: 1, id: 'folder-b' }],
      folderRelationships: [{ itemSourceIndex: 1, sourceFolderId: 'folder-b', folderSourceIndex: 1 }],
    });
    expect(built.ir!.items.map((item) => [item.sourceIndex, item.kind])).toEqual([
      [1, 'login'],
      [2, 'sshKey'],
    ]);
    expect(built.ir!.items[0]).toMatchObject({
      reprompt: 1,
      creationDate: '2025-01-01T00:00:00.000Z',
      archivedDate: null,
      fields: [{ type: 0, name: 'environment', value: 'production' }, { type: 3, linkedId: 100 }],
      passwordHistory: [{ password: 'old-password' }],
      payload: {
        username: 'alice',
        autofillOnPageLoad: false,
        passwordRevisionDate: '2025-01-15T00:00:00.000Z',
        uris: [{ uri: 'https://example.com/a,b', match: 0 }],
        fido2Credentials: [{ credentialId: 'credential-id', keyValue: 'private-key' }],
      },
    });
    expect(built.attachments).toEqual([{
      itemSourceIndex: 1,
      sourceIndex: 0,
      itemToken: 'personal-login',
      attachmentId: 'attachment-1',
      fileName: 'report 雪.txt',
      size: '12',
      sizeName: '12 B',
    }]);
    expect(deps.decryptCipher).toHaveBeenCalledTimes(2);
    expect(deps.decryptCipher).not.toHaveBeenCalledWith(expect.objectContaining({ id: 'org-target-item' }), expect.anything());

    const encoded = encodeVaultTransferJson(built.ir!);
    expect(encoded.ok).toBe(true);
    expect(encoded.json).not.toContain('attachment-1');
    expect(encoded.json).not.toContain('2.cipher-key');
    const reinspected = inspectVaultTransferJson(encoded.json!);
    expect(reinspected.canCommit).toBe(true);
    expect(reinspected.ir!.items.map((item) => item.kind)).toEqual(['login', 'sshKey']);
  });

  it('never decrypts or includes organization items in a personal export', async () => {
    const deps = decryptors({
      decryptCipher: vi.fn(async (cipher) => {
        if (cipher.organizationId) throw new Error('organization item must never be touched');
        return cipher.type === 1
          ? { status: 'decrypted', value: loginPlaintext() } as const
          : { status: 'decrypted', value: { type: 5, name: 'SSH', sshKey: { privateKey: 'P', publicKey: 'U', keyFingerprint: 'F' } } } as const;
      }),
    });
    const built = await buildVaultTransferExport(syncFixture(), { scope: { kind: 'personal' } }, deps);
    expect(built.ok).toBe(true);
    expect(built.ir!.items.every((item) => item.organizationId == null)).toBe(true);
    expect(deps.decryptCipher).toHaveBeenCalledTimes(2);
  });

  it('excludes trashed items before decrypting, matching the official portable export scope', async () => {
    const sync = syncFixture();
    sync.ciphers.push({
      id: 'trashed-personal',
      type: 2,
      name: '2.trashed-name',
      secureNote: { type: 0 },
      deletedDate: '2026-08-30T00:00:00.000Z',
    });
    const deps = decryptors({
      decryptCipher: vi.fn(async (cipher) => {
        if (cipher.id === 'trashed-personal') throw new Error('trashed item must not be decrypted');
        const value = cipher.type === 1
          ? loginPlaintext()
          : { type: 5 as const, name: 'SSH', sshKey: { privateKey: 'P', publicKey: 'U', keyFingerprint: 'F' } };
        return { status: 'decrypted' as const, value };
      }),
    });

    const built = await buildVaultTransferExport(sync, { scope: { kind: 'personal' } }, deps);

    expect(built.ok).toBe(true);
    expect(built.ir?.items.some((item) => item.id === 'trashed-personal')).toBe(false);
    expect(built.diagnostics).toContainEqual(expect.objectContaining({
      severity: 'info',
      code: 'trashed_items_excluded',
    }));
    expect(deps.decryptCipher).not.toHaveBeenCalledWith(
      expect.objectContaining({ id: 'trashed-personal' }),
      expect.anything(),
    );
  });

  it('blocks types 6-8 until the strict crypto and Data schemas support them', async () => {
    const sync = syncFixture();
    sync.ciphers = [
      { id: 'bank', type: 6, name: '2.name', favorite: false, bankAccount: { bankName: '2.bank' } },
      { id: 'license', type: 7, name: '2.name', favorite: false, driversLicense: { licenseNumber: '2.number' } },
      { id: 'passport', type: 8, name: '2.name', favorite: false, passport: { passportNumber: '2.number' } },
    ];
    const data: Record<string, VaultTransferExportCipher> = {
      bank: { type: 6, name: 'Bank', bankAccount: { bankName: 'Acme', iban: null } },
      license: { type: 7, name: 'License', driversLicense: { licenseNumber: 'D123', issuingCountry: 'US' } },
      passport: { type: 8, name: 'Passport', passport: { passportNumber: 'P123', nationality: 'US' } },
    };
    const built = await buildVaultTransferExport(sync, { scope: { kind: 'personal' } }, decryptors({
      decryptCipher: vi.fn(async (cipher) => ({ status: 'decrypted', value: data[cipher.id]! } as const)),
    }));
    expect(built.ok).toBe(false);
    expect(built.ir).toBeNull();
    expect(built.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'unknown_item_type', sourceIndex: 0 }),
      expect.objectContaining({ code: 'unsupported_cipher_type', sourceIndex: 1 }),
      expect.objectContaining({ code: 'unsupported_cipher_type', sourceIndex: 2 }),
    ]));
  });
});

describe('buildVaultTransferExport organization scope', () => {
  it('requires and exports exactly one explicit organization with collection relationships', async () => {
    const deps = decryptors();
    const built = await buildVaultTransferExport(
      syncFixture(),
      { scope: { kind: 'organization', organizationId: 'org-target' } },
      deps,
    );

    expect(built.ok).toBe(true);
    expect(built.ir).toMatchObject({
      scope: 'organization',
      folders: [],
      collections: [{ sourceIndex: 1, id: 'collection-target', organizationId: 'org-target', name: 'Engineering' }],
      items: [{ sourceIndex: 3, organizationId: 'org-target', kind: 'secureNote' }],
      collectionRelationships: [{
        itemSourceIndex: 3,
        sourceCollectionId: 'collection-target',
        collectionSourceIndex: 1,
      }],
    });
    expect(deps.decryptCollection).toHaveBeenCalledTimes(1);
    expect(deps.decryptCipher).toHaveBeenCalledTimes(1);

    const encoded = encodeVaultTransferJson(built.ir!, { organization: { mode: 'export' } });
    expect(encoded.ok).toBe(true);
    const reinspected = inspectVaultTransferJson(encoded.json!);
    expect(reinspected.ir?.scope).toBe('organization');
    expect(reinspected.ir?.items).toHaveLength(1);
  });

  it('fails when the organization is absent or its key cannot decrypt a selected object', async () => {
    const absentDeps = decryptors();
    const absent = await buildVaultTransferExport(
      syncFixture(),
      { scope: { kind: 'organization', organizationId: 'missing-org' } },
      absentDeps,
    );
    expect(absent.ok).toBe(false);
    expect(absent.ir).toBeNull();
    expect(absent.diagnostics).toContainEqual(expect.objectContaining({ code: 'organization_unavailable' }));
    expect(absentDeps.decryptCipher).not.toHaveBeenCalled();

    const missingKey = await buildVaultTransferExport(
      syncFixture(),
      { scope: { kind: 'organization', organizationId: 'org-target' } },
      decryptors({
        decryptCipher: vi.fn(async () => ({ status: 'failed', code: 'missing_organization_key' } as const)),
      }),
    );
    expect(missingKey.ok).toBe(false);
    expect(missingKey.ir).toBeNull();
    expect(missingKey.diagnostics).toContainEqual(expect.objectContaining({
      code: 'missing_organization_key', sourceIndex: 3,
    }));
  });
});

describe('buildVaultTransferExport blocking integrity checks', () => {
  it('accepts an exact 2026.8 Data projection and excludes Data and permissions from export', async () => {
    const sync = syncFixture();
    sync.ciphers = [{
      id: 'note',
      type: 2,
      name: '2.name',
      notes: null,
      secureNote: { type: 0 },
      data: JSON.stringify({ Name: '2.name', Notes: null, Type: 0 }),
      permissions: { delete: true, restore: false },
    }];
    const deps = decryptors({
      decryptCipher: vi.fn(async () => ({
        status: 'decrypted', value: { type: 2, name: 'Note', notes: null, secureNote: { type: 0 } },
      } as const)),
    });

    const built = await buildVaultTransferExport(sync, { scope: { kind: 'personal' } }, deps);
    expect(built.ok).toBe(true);
    expect(JSON.stringify(built.ir)).not.toContain('2.name');
    expect(JSON.stringify(built.ir)).not.toContain('permissions');
  });

  it('blocks Data disagreement, blobs, and malformed permissions before decryption', async () => {
    const cases: Array<{ cipher: SyncResponse['ciphers'][number]; code: string }> = [
      {
        cipher: {
          id: 'mismatch', type: 2, name: '2.name', secureNote: { type: 0 },
          data: JSON.stringify({ Name: '2.other', Type: 0 }),
        },
        code: 'data_projection_mismatch',
      },
      {
        cipher: {
          id: 'blob', type: 2, name: '2.name', secureNote: { type: 0 },
          data: JSON.stringify({ format_version: 1, ciphertext: 'secret' }),
        },
        code: 'encrypted_data_blob',
      },
      {
        cipher: {
          id: 'permissions', type: 2, name: '2.name', secureNote: { type: 0 },
          permissions: { delete: true, restore: false, share: true } as never,
        },
        code: 'invalid_permissions',
      },
    ];
    for (const entry of cases) {
      const sync = syncFixture();
      sync.ciphers = [entry.cipher];
      const deps = decryptors();
      const built = await buildVaultTransferExport(sync, { scope: { kind: 'personal' } }, deps);
      expect(built.ok).toBe(false);
      expect(built.diagnostics).toContainEqual(expect.objectContaining({ code: entry.code }));
      expect(deps.decryptCipher).not.toHaveBeenCalled();
    }
  });

  it('validates and excludes bounded user-decryption control-plane metadata', async () => {
    const sync = syncFixture();
    sync.userDecryption = {
      masterPasswordUnlock: {
        kdf: { kdfType: 1, iterations: 3, memory: 64, parallelism: 4 },
        masterKeyEncryptedUserKey: '2.control-plane-key',
        salt: 'user@example.com',
      },
    };
    const built = await buildVaultTransferExport(sync, { scope: { kind: 'personal' } }, decryptors());
    expect(built.ok).toBe(true);
    expect(JSON.stringify(built.ir)).not.toContain('control-plane-key');

    sync.userDecryption = { value: 'x'.repeat(128 * 1024 + 1) };
    const blocked = await buildVaultTransferExport(sync, { scope: { kind: 'personal' } }, decryptors());
    expect(blocked.ok).toBe(false);
    expect(blocked.diagnostics).toContainEqual(expect.objectContaining({
      code: 'control_plane_metadata_too_large',
      path: '$.userDecryption',
    }));
  });

  it('blocks unknown selected cipher types and raw fields before decryption', async () => {
    const sync = syncFixture();
    sync.ciphers = [{ id: 'future', type: 99, name: '2.name', favorite: false, futureSecret: '2.value' }];
    const deps = decryptors();
    const built = await buildVaultTransferExport(sync, { scope: { kind: 'personal' } }, deps);
    expect(built.ok).toBe(false);
    expect(built.ir).toBeNull();
    expect(built.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'unknown_item_type', sourceIndex: 0 }),
      expect.objectContaining({ code: 'unknown_raw_field', path: '$.ciphers[0].futureSecret' }),
    ]));
    expect(deps.decryptCipher).not.toHaveBeenCalled();
  });

  it('blocks an undecryptable selected cipher instead of omitting it', async () => {
    const sync = syncFixture();
    sync.ciphers = [sync.ciphers[1]!];
    const built = await buildVaultTransferExport(sync, { scope: { kind: 'personal' } }, decryptors({
      decryptCipher: vi.fn(async () => ({ status: 'failed', code: 'undecryptable' } as const)),
    }));
    expect(built.ok).toBe(false);
    expect(built.ir).toBeNull();
    expect(built.attachments).toEqual([]);
    expect(built.diagnostics).toContainEqual(expect.objectContaining({ code: 'undecryptable', sourceIndex: 0 }));
  });

  it('blocks broken folder and collection relationships', async () => {
    const personalSync = syncFixture();
    personalSync.ciphers[1]!.folderId = 'missing-folder';
    const personal = await buildVaultTransferExport(personalSync, { scope: { kind: 'personal' } }, decryptors());
    expect(personal.ok).toBe(false);
    expect(personal.diagnostics).toContainEqual(expect.objectContaining({
      code: 'missing_folder_reference', sourceIndex: 1, path: '$.items[1].folderId',
    }));

    const orgSync = syncFixture();
    orgSync.ciphers[3]!.collectionIds = ['missing-collection'];
    const organization = await buildVaultTransferExport(
      orgSync,
      { scope: { kind: 'organization', organizationId: 'org-target' } },
      decryptors(),
    );
    expect(organization.ok).toBe(false);
    expect(organization.diagnostics).toContainEqual(expect.objectContaining({ code: 'missing_collection_reference' }));
  });

  it('blocks incomplete attachment metadata and never returns a partial attachment plan', async () => {
    const sync = syncFixture();
    const personal = sync.ciphers[1]!;
    personal.attachments = [{ id: 'attachment-1', fileName: '2.file', size: '12' }];
    const built = await buildVaultTransferExport(sync, { scope: { kind: 'personal' } }, decryptors());
    expect(built.ok).toBe(false);
    expect(built.ir).toBeNull();
    expect(built.attachments).toEqual([]);
    expect(built.diagnostics).toContainEqual(expect.objectContaining({ code: 'attachment_unavailable' }));
  });

  it('blocks unknown nested raw fields before decrypting secrets', async () => {
    const sync = syncFixture();
    const login = sync.ciphers[1]!.login as Record<string, unknown>;
    login.futureEncryptedSecret = '2.future';
    const deps = decryptors();
    const built = await buildVaultTransferExport(sync, { scope: { kind: 'personal' } }, deps);
    expect(built.ok).toBe(false);
    expect(built.ir).toBeNull();
    expect(built.diagnostics).toContainEqual(expect.objectContaining({
      code: 'invalid_structured_projection', sourceIndex: 1,
    }));
    expect(deps.decryptCipher).not.toHaveBeenCalled();
  });

  it('blocks a mismatched or alias-only legacy login URI before decryption', async () => {
    for (const login of [
      { uri: '2.one', uris: [{ uri: '2.two', match: null }] },
      { uri: '2.legacy' },
      { uri: null, uris: [{ uri: '2.first', match: null }] },
    ]) {
      const sync = syncFixture();
      sync.ciphers = [{ id: 'login', type: 1, name: '2.name', login }];
      const deps = decryptors();
      const built = await buildVaultTransferExport(sync, { scope: { kind: 'personal' } }, deps);
      expect(built.ok).toBe(false);
      expect(built.diagnostics).toContainEqual(expect.objectContaining({
        code: 'login_uri_alias_mismatch',
        path: '$.ciphers[0].login.uri',
      }));
      expect(deps.decryptCipher).not.toHaveBeenCalled();
    }
  });
});

describe('buildVaultTransferExport resource limits', () => {
  it('blocks selected item counts before invoking decryptors', async () => {
    const sync = syncFixture();
    sync.ciphers = [sync.ciphers[1]!, sync.ciphers[2]!];
    const deps = decryptors();
    const built = await buildVaultTransferExport(sync, {
      scope: { kind: 'personal' },
      limits: { maxItems: 1 },
    }, deps);
    expect(built.ok).toBe(false);
    expect(built.diagnostics).toContainEqual(expect.objectContaining({ code: 'items_limit_exceeded' }));
    expect(deps.decryptCipher).not.toHaveBeenCalled();
  });

  it('blocks field and declared attachment-byte limits at their earliest safe phase', async () => {
    const sync = syncFixture();
    sync.ciphers = [sync.ciphers[1]!];
    const rich = loginPlaintext();
    rich.fields = [
      { type: 0, name: 'a', value: '1' },
      { type: 0, name: 'b', value: '2' },
    ];
    const fieldsBlocked = await buildVaultTransferExport(sync, {
      scope: { kind: 'personal' },
      limits: { maxFieldsPerItem: 1 },
    }, decryptors({
      decryptCipher: vi.fn(async () => ({ status: 'decrypted', value: rich } as const)),
    }));
    expect(fieldsBlocked.ok).toBe(false);
    expect(fieldsBlocked.ir).toBeNull();
    expect(fieldsBlocked.diagnostics).toContainEqual(expect.objectContaining({ code: 'fields_limit_exceeded' }));

    const bytesBlocked = await buildVaultTransferExport(sync, {
      scope: { kind: 'personal' },
      limits: { maxTotalDeclaredAttachmentBytes: 10 },
    }, decryptors());
    expect(bytesBlocked.ok).toBe(false);
    expect(bytesBlocked.ir).toBeNull();
    expect(bytesBlocked.diagnostics).toContainEqual(expect.objectContaining({ code: 'declared_attachment_bytes_limit_exceeded' }));
  });

  it('blocks normalized plaintext that exceeds the configured byte limit', async () => {
    const sync = syncFixture();
    sync.ciphers = [sync.ciphers[2]!];
    const built = await buildVaultTransferExport(sync, {
      scope: { kind: 'personal' },
      limits: { maxInputBytes: 16 },
    }, decryptors());
    expect(built.ok).toBe(false);
    expect(built.ir).toBeNull();
    expect(built.diagnostics).toContainEqual(expect.objectContaining({ code: 'input_too_large' }));
  });

  it('rejects invalid limit overrides as programmer errors', async () => {
    await expect(buildVaultTransferExport(syncFixture(), {
      scope: { kind: 'personal' },
      limits: { maxItems: 0 },
    }, decryptors())).rejects.toThrow(RangeError);
  });
});
