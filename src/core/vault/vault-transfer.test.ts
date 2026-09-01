import { describe, expect, it } from 'vitest';
import {
  VAULT_TRANSFER_IR_VERSION,
  inspectVaultTransfer,
  inspectVaultTransferCsv,
  inspectVaultTransferJson,
} from './vault-transfer.js';

function personalJson(items: unknown[], folders: unknown[] = []): string {
  return JSON.stringify({ encrypted: false, folders, items });
}

describe('vault transfer JSON inspection', () => {
  it('rejects calendar-invalid item provenance dates instead of normalizing them', () => {
    const inspected = inspectVaultTransferJson(personalJson([{
      type: 2,
      name: 'Invalid date',
      creationDate: '2026-02-30T00:00:00Z',
      secureNote: { type: 0 },
    }]));
    expect(inspected.canCommit).toBe(false);
    expect(inspected.diagnostics).toContainEqual(expect.objectContaining({
      code: 'invalid_shape',
      path: '$.items[0].creationDate',
    }));
  });

  it('builds a versioned, source-indexed IR with known lossless fields and relationships', () => {
    const inspected = inspectVaultTransferJson(personalJson([
      {
        id: 'login-1',
        type: 1,
        name: 'GitHub',
        notes: 'work account',
        favorite: true,
        reprompt: 1,
        folderId: 'folder-1',
        fields: [
          { type: 0, name: 'environment', value: 'production' },
          { type: 3, name: 'linked username', value: null, linkedId: 100 },
        ],
        passwordHistory: [{ password: 'old-secret', lastUsedDate: '2025-01-02T03:04:05.000Z' }],
        creationDate: '2025-01-01T00:00:00.000Z',
        revisionDate: '2025-02-01T00:00:00.000Z',
        archivedDate: '2025-03-01T00:00:00.000Z',
        login: {
          username: 'octocat',
          password: 'secret',
          totp: 'JBSWY3DPEHPK3PXP',
          autofillOnPageLoad: false,
          passwordRevisionDate: '2025-01-02T03:04:05.1234567Z',
          uris: [{ uri: 'https://github.com', match: 0 }],
          fido2Credentials: [{
            credentialId: 'credential',
            keyType: 'public-key',
            keyAlgorithm: 'ECDSA',
            keyCurve: 'P-256',
            keyValue: 'private-key',
            rpId: 'github.com',
            counter: '4',
            discoverable: 'true',
            userHandle: 'user-handle',
            creationDate: '2025-01-01T00:00:00.000Z',
          }],
        },
      },
      {
        id: 'ssh-1',
        type: 5,
        name: 'Deploy key',
        favorite: false,
        sshKey: { privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:abc' },
      },
    ], [{ id: 'folder-1', name: 'Work' }]));

    expect(inspected.canCommit).toBe(true);
    expect(inspected.diagnostics).toEqual([{
      severity: 'warning',
      code: 'server_managed_dates_dropped',
      message: 'Creation and revision dates are server-managed and will not be preserved during import.',
      path: '$.items[0]',
      sourceKind: 'item',
      sourceIndex: 0,
    }]);
    expect(inspected.ir).toMatchObject({
      version: VAULT_TRANSFER_IR_VERSION,
      format: 'bitwarden-json',
      scope: 'personal',
      folders: [{ sourceIndex: 0, id: 'folder-1', name: 'Work' }],
      folderRelationships: [{ itemSourceIndex: 0, sourceFolderId: 'folder-1', folderSourceIndex: 0 }],
    });
    const login = inspected.ir!.items[0]!;
    expect(login).toMatchObject({
      sourceIndex: 0,
      rawType: 1,
      kind: 'login',
      reprompt: 1,
      creationDate: '2025-01-01T00:00:00.000Z',
      archivedDate: '2025-03-01T00:00:00.000Z',
      fields: [
        { sourceIndex: 0, type: 0, name: 'environment', value: 'production' },
        { sourceIndex: 1, type: 3, linkedId: 100 },
      ],
      passwordHistory: [{ sourceIndex: 0, password: 'old-secret' }],
      payload: {
        username: 'octocat',
        autofillOnPageLoad: false,
        passwordRevisionDate: '2025-01-02T03:04:05.1234567Z',
        uris: [{ sourceIndex: 0, uri: 'https://github.com', match: 0 }],
        fido2Credentials: [{ sourceIndex: 0, credentialId: 'credential', keyValue: 'private-key' }],
      },
    });
    expect(inspected.ir!.items[1]).toMatchObject({
      sourceIndex: 1,
      rawType: 5,
      kind: 'sshKey',
      payload: { values: { privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:abc' } },
    });
  });

  it.each([false, true, null] as const)(
    'preserves the page-load autofill tri-state without coercion: %s',
    (autofillOnPageLoad) => {
      const inspected = inspectVaultTransferJson(personalJson([{
        type: 1,
        name: 'Login',
        login: { autofillOnPageLoad, uris: [] },
      }]));
      expect(inspected.canCommit).toBe(true);
      expect(inspected.ir!.items[0]!.payload).toHaveProperty(
        'autofillOnPageLoad',
        autofillOnPageLoad,
      );
    },
  );

  it('rejects non-boolean autofill overrides and invalid password revision timestamps', () => {
    const inspected = inspectVaultTransferJson(personalJson([{
      type: 1,
      name: 'Login',
      login: {
        autofillOnPageLoad: 0,
        passwordRevisionDate: '2026-02-30T03:04:05Z',
        uris: [],
      },
    }]));

    expect(inspected.canCommit).toBe(false);
    expect(inspected.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'invalid_shape', path: '$.items[0].login.autofillOnPageLoad' }),
      expect.objectContaining({ code: 'invalid_shape', path: '$.items[0].login.passwordRevisionDate' }),
    ]));
  });

  it('represents current structured item types without narrowing their raw type', () => {
    const inspected = inspectVaultTransferJson(personalJson([
      { type: 6, name: 'Checking', bankAccount: { bankName: 'Acme', iban: 'GB00' } },
      { type: 7, name: 'License', driversLicense: { licenseNumber: 'D123', issuingCountry: 'US' } },
      { type: 8, name: 'Passport', passport: { passportNumber: 'P123', nationality: 'US' } },
    ]));

    expect(inspected.canCommit).toBe(true);
    expect(inspected.ir!.items.map((item) => [item.rawType, item.kind])).toEqual([
      [6, 'bankAccount'],
      [7, 'driversLicense'],
      [8, 'passport'],
    ]);
  });

  it.each([
    ['malformed JSON', '{ nope', 'malformed_json'],
    ['non-object JSON', '[]', 'invalid_json_root'],
    ['missing items', JSON.stringify({ encrypted: false, folders: [] }), 'missing_items'],
    ['encrypted JSON', JSON.stringify({ encrypted: true, passwordProtected: true, data: '2.x' }), 'encrypted_input_requires_decryption'],
  ])('fails closed for %s', (_label, input, code) => {
    const inspected = inspectVaultTransferJson(input);
    expect(inspected.canCommit).toBe(false);
    expect(inspected.diagnostics).toContainEqual(expect.objectContaining({ severity: 'error', code }));
  });

  it('retains unknown item data and reports its exact path instead of silently dropping it', () => {
    const inspected = inspectVaultTransferJson(personalJson([
      { type: 1, name: 'Login', futureFlag: { enabled: true }, login: { username: 'u', futureLoginField: 'x', uris: [] } },
    ]));

    expect(inspected.canCommit).toBe(false);
    expect(inspected.ir!.unknownFieldPaths).toEqual([
      '$.items[0].futureFlag',
      '$.items[0].login.futureLoginField',
    ]);
    expect(inspected.ir!.items[0]!.raw).toMatchObject({ futureFlag: { enabled: true } });
    expect(inspected.diagnostics.filter((diagnostic) => diagnostic.code === 'unknown_field')).toHaveLength(2);
  });

  it('retains an unknown raw type as unsupported and blocks commit', () => {
    const inspected = inspectVaultTransferJson(personalJson([
      { type: 99, name: 'Future item', futurePayload: { secret: 'x' } },
    ]));

    expect(inspected.canCommit).toBe(false);
    expect(inspected.ir!.items[0]).toMatchObject({ rawType: 99, kind: 'unsupported' });
    expect(inspected.diagnostics).toContainEqual(expect.objectContaining({ code: 'unknown_item_type', sourceIndex: 0 }));
  });

  it('fails closed for known data that requires another transfer mechanism', () => {
    const inspected = inspectVaultTransferJson(personalJson([
      {
        type: 1,
        name: 'Login',
        key: '2.encrypted-key',
        attachments: [{ id: 'a1', fileName: 'file.txt' }],
        login: { uris: [] },
      },
    ]));

    expect(inspected.canCommit).toBe(false);
    expect(inspected.diagnostics.filter((diagnostic) => diagnostic.code === 'unsupported_known_data')).toHaveLength(2);
  });

  it('captures organization collections and relationships but requires an explicit target', () => {
    const inspected = inspectVaultTransferJson(JSON.stringify({
      encrypted: false,
      collections: [{ id: 'collection-1', name: 'Engineering', organizationId: 'old-org' }],
      items: [{
        type: 2,
        name: 'Runbook',
        organizationId: 'old-org',
        collectionIds: ['collection-1'],
        secureNote: { type: 0 },
      }],
    }));

    expect(inspected.canCommit).toBe(false);
    expect(inspected.ir).toMatchObject({
      scope: 'organization',
      collections: [{ sourceIndex: 0, id: 'collection-1', name: 'Engineering' }],
      collectionRelationships: [{
        itemSourceIndex: 0,
        sourceCollectionId: 'collection-1',
        collectionSourceIndex: 0,
      }],
    });
    expect(inspected.diagnostics).toContainEqual(expect.objectContaining({ code: 'organization_target_required' }));
  });

  it('blocks unresolved folder references', () => {
    const inspected = inspectVaultTransferJson(personalJson([
      { type: 2, name: 'Note', folderId: 'missing', secureNote: { type: 0 } },
    ]));
    expect(inspected.canCommit).toBe(false);
    expect(inspected.diagnostics).toContainEqual(expect.objectContaining({ code: 'missing_folder_reference' }));
  });
});

describe('vault transfer CSV inspection', () => {
  it('preserves source indexes, folders, custom fields, multiple URIs, and archive metadata', () => {
    const csv = [
      'folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp',
      'Work,1,login,GitHub,note,"environment: production',
      'pin: 1234",1,2025-03-01T00:00:00.000Z,"https://github.com,https://gist.github.com",octocat,secret,TOTP',
      ',0,note,Runbook,body,,0,,,,,',
    ].join('\n');

    const inspected = inspectVaultTransferCsv(csv);
    expect(inspected.canCommit).toBe(true);
    expect(inspected.ir).toMatchObject({
      format: 'bitwarden-csv',
      scope: 'personal',
      folders: [{ sourceIndex: 0, id: 'csv-folder-0', name: 'Work' }],
      folderRelationships: [{ itemSourceIndex: 0, sourceFolderId: 'csv-folder-0', folderSourceIndex: 0 }],
    });
    expect(inspected.ir!.items[0]).toMatchObject({
      sourceIndex: 0,
      kind: 'login',
      archivedDate: '2025-03-01T00:00:00.000Z',
      fields: [
        { sourceIndex: 0, name: 'environment', value: 'production', type: 0 },
        { sourceIndex: 1, name: 'pin', value: '1234', type: 0 },
      ],
      payload: {
        username: 'octocat',
        uris: [{ uri: 'https://github.com' }, { uri: 'https://gist.github.com' }],
      },
    });
    expect(inspected.ir!.items[1]).toMatchObject({ sourceIndex: 1, kind: 'secureNote', name: 'Runbook' });
  });

  it('captures CSV collections but blocks organization semantics', () => {
    const inspected = inspectVaultTransferCsv([
      'collections,type,name,notes',
      'Engineering,note,Runbook,body',
    ].join('\n'));

    expect(inspected.canCommit).toBe(false);
    expect(inspected.ir).toMatchObject({
      scope: 'organization',
      collections: [{ name: 'Engineering' }],
      collectionRelationships: [{ itemSourceIndex: 0, collectionSourceIndex: 0 }],
    });
    expect(inspected.diagnostics).toContainEqual(expect.objectContaining({ code: 'organization_target_required' }));
  });

  it('blocks unknown headers and malformed quoted cells', () => {
    const unknown = inspectVaultTransferCsv('name,type,future\nLogin,login,x\n');
    expect(unknown.canCommit).toBe(false);
    expect(unknown.ir!.unknownFieldPaths).toEqual(['$.headers[2]']);

    const malformed = inspectVaultTransferCsv('name,type\n"Login,login\n');
    expect(malformed.canCommit).toBe(false);
    expect(malformed.diagnostics).toContainEqual(expect.objectContaining({ code: 'malformed_csv' }));
  });

  it('auto-detects JSON and CSV without changing either specialized API', () => {
    expect(inspectVaultTransfer(personalJson([])).ir?.format).toBe('bitwarden-json');
    expect(inspectVaultTransfer('name,type\nLogin,login\n').ir?.format).toBe('bitwarden-csv');
  });
});

describe('vault transfer resource limits', () => {
  it('rejects input by UTF-8 byte length before parsing', () => {
    const inspected = inspectVaultTransfer('密码', { limits: { maxInputBytes: 5 } });
    expect(inspected.ir).toBeNull();
    expect(inspected.diagnostics).toContainEqual(expect.objectContaining({ code: 'input_too_large' }));
  });

  it('rejects JSON item counts above the configured limit', () => {
    const inspected = inspectVaultTransferJson(personalJson([
      { type: 2, name: 'A', secureNote: { type: 0 } },
      { type: 2, name: 'B', secureNote: { type: 0 } },
    ]), { limits: { maxItems: 1 } });
    expect(inspected.canCommit).toBe(false);
    expect(inspected.ir!.items).toEqual([]);
    expect(inspected.diagnostics).toContainEqual(expect.objectContaining({ code: 'items_limit_exceeded' }));
  });

  it('rejects custom field counts above the configured per-item limit', () => {
    const inspected = inspectVaultTransferJson(personalJson([
      {
        type: 2,
        name: 'Note',
        secureNote: { type: 0 },
        fields: [{ type: 0, name: 'a', value: '1' }, { type: 0, name: 'b', value: '2' }],
      },
    ]), { limits: { maxFieldsPerItem: 1 } });
    expect(inspected.canCommit).toBe(false);
    expect(inspected.ir!.items[0]!.fields).toEqual([]);
    expect(inspected.diagnostics).toContainEqual(expect.objectContaining({ code: 'fields_limit_exceeded' }));
  });

  it('stops CSV parsing when a cell exceeds its configured length', () => {
    const inspected = inspectVaultTransferCsv('name,type\nabcdefghijk,login\n', {
      limits: { maxCellChars: 10 },
    });
    expect(inspected.ir).toBeNull();
    expect(inspected.diagnostics).toContainEqual(expect.objectContaining({ code: 'csv_cell_limit_exceeded' }));
  });

  it('rejects invalid custom limits as programmer errors', () => {
    expect(() => inspectVaultTransferJson(personalJson([]), { limits: { maxItems: 0 } })).toThrow(RangeError);
  });
});
