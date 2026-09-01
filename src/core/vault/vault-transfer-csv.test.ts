import { describe, expect, it } from 'vitest';
import { inspectVaultTransferCsv, inspectVaultTransferJson, type VaultTransferIR } from './vault-transfer.js';
import {
  BITWARDEN_ORGANIZATION_CSV_COLUMNS,
  BITWARDEN_PERSONAL_CSV_COLUMNS,
  encodeVaultTransferCsv,
} from './vault-transfer-csv.js';

function inspectPersonal(
  items: readonly Record<string, unknown>[],
  folders: readonly Record<string, unknown>[] = [],
): VaultTransferIR {
  const inspected = inspectVaultTransferJson(JSON.stringify({ encrypted: false, folders, items }));
  expect(inspected.ir).not.toBeNull();
  return inspected.ir!;
}

function inspectOrganization(
  items: readonly Record<string, unknown>[],
  collections: readonly Record<string, unknown>[],
): VaultTransferIR {
  const inspected = inspectVaultTransferJson(JSON.stringify({
    encrypted: false,
    collections,
    items,
  }));
  expect(inspected.ir).not.toBeNull();
  expect(inspected.ir?.scope).toBe('organization');
  return inspected.ir!;
}

function login(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'login-1', type: 1, name: 'Example', notes: 'Login notes', favorite: true, reprompt: 1,
    fields: [{ type: 0, name: 'environment', value: 'production' }],
    login: {
      uris: [{ uri: 'https://example.com' }], username: 'alice', password: 'secret',
      totp: 'otpauth://totp/example',
    },
    ...overrides,
  };
}

function note(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'note-1', type: 2, name: 'Runbook', notes: 'Recovery steps', favorite: false,
    reprompt: 0, secureNote: { type: 0 }, ...overrides,
  };
}

describe('encodeVaultTransferCsv official schema', () => {
  it('matches the Bitwarden v2026.8 column order and PapaParse defaults', () => {
    const ir = inspectPersonal([
      login({ folderId: 'folder-1', archivedDate: '2026-08-01T02:03:04.000Z' }),
      note(),
    ], [{ id: 'folder-1', name: 'Work' }]);
    const result = encodeVaultTransferCsv(ir);

    expect(result).toMatchObject({ ok: true, exportedItemCount: 2, omittedItemCount: 0 });
    expect(result.diagnostics).toEqual([]);
    expect(result.csv).toBe([
      'folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp',
      'Work,1,login,Example,Login notes,environment: production,1,2026-08-01T02:03:04.000Z,https://example.com,alice,secret,otpauth://totp/example',
      ',,note,Runbook,Recovery steps,,0,,,,,',
    ].join('\r\n'));
    expect(result.csv?.startsWith('\uFEFF')).toBe(false);
    expect(result.csv?.endsWith('\r\n')).toBe(false);
    expect(BITWARDEN_PERSONAL_CSV_COLUMNS).toHaveLength(12);
  });

  it('round-trips commas, quotes, newlines, and Unicode through the current importer', () => {
    const source = inspectPersonal([
      login({
        folderId: 'folder-1',
        name: 'Portal, "雪"',
        notes: 'Line one\nLine two, quoted "value"',
        fields: [
          { type: 0, name: 'region', value: 'north,west' },
          { type: 0, name: 'quote', value: 'say "hello"' },
        ],
        login: {
          uris: [{ uri: 'https://example.com' }, { uri: 'https://login.example.com' }],
          username: '用户@example.com', password: 'päss,"word"\n第二行', totp: '密钥',
        },
      }),
      note({ name: '日本語メモ', notes: null, fields: null }),
    ], [{ id: 'folder-1', name: 'R&D, "国际"' }]);

    const encoded = encodeVaultTransferCsv(source);
    expect(encoded.ok).toBe(true);
    expect(encoded.csv).toContain('"R&D, ""国际"""');
    expect(encoded.csv).toContain('"Line one\nLine two, quoted ""value"""');

    const imported = inspectVaultTransferCsv(encoded.csv!);
    expect(imported.canCommit).toBe(true);
    expect(imported.ir?.folders).toEqual([expect.objectContaining({ name: 'R&D, "国际"' })]);
    expect(imported.ir?.items[0]).toMatchObject({
      kind: 'login', name: 'Portal, "雪"', notes: 'Line one\nLine two, quoted "value"',
      favorite: true, reprompt: 1,
      fields: [
        expect.objectContaining({ name: 'region', value: 'north,west' }),
        expect.objectContaining({ name: 'quote', value: 'say "hello"' }),
      ],
      payload: {
        username: '用户@example.com', password: 'päss,"word"\n第二行', totp: '密钥',
        uris: [
          expect.objectContaining({ uri: 'https://example.com' }),
          expect.objectContaining({ uri: 'https://login.example.com' }),
        ],
      },
    });
    expect(imported.ir?.items[1]).toMatchObject({ kind: 'secureNote', name: '日本語メモ' });
  });

  it('uses official empty-cell and custom-field coercion for null values', () => {
    const ir = inspectPersonal([login({
      notes: null, favorite: false, archivedDate: null,
      fields: [{ type: 0, name: null, value: null }],
      login: { uris: null, username: null, password: null, totp: null },
    })]);
    const result = encodeVaultTransferCsv(ir);

    expect(result.ok).toBe(true);
    expect(result.csv?.split('\r\n')[1]).toBe(',,login,Example,,: null,1,,,,,');
    const imported = inspectVaultTransferCsv(result.csv!);
    expect(imported.canCommit).toBe(true);
    expect(imported.ir?.items[0]).toMatchObject({
      favorite: false,
      fields: [expect.objectContaining({ name: '', value: 'null' })],
      payload: { uris: [] },
    });
  });

  it('canonicalizes source-indexed folders, rows, fields, and URIs', () => {
    const canonical = inspectPersonal([
      login({
        folderId: 'folder-2',
        fields: [{ type: 0, name: 'a', value: '1' }, { type: 0, name: 'b', value: '2' }],
        login: { uris: [{ uri: 'https://a.example' }, { uri: 'https://b.example' }] },
      }),
      note(),
    ], [{ id: 'folder-1', name: 'A' }, { id: 'folder-2', name: 'B' }]);
    const reordered = structuredClone(canonical);
    reordered.items.reverse();
    reordered.folders.reverse();
    const item = reordered.items.find((candidate) => candidate.kind === 'login');
    if (item?.kind === 'login') {
      item.fields.reverse();
      item.payload.uris.reverse();
    }
    expect(encodeVaultTransferCsv(reordered).csv).toBe(encodeVaultTransferCsv(canonical).csv);
  });
});

describe('encodeVaultTransferCsv organization schema', () => {
  it('matches the Bitwarden v2026.8 organization column order and collection list encoding', () => {
    const ir = inspectOrganization([
      login({
        organizationId: 'org-1',
        collectionIds: ['collection-2', 'collection-1'],
        favorite: false,
        archivedDate: '2026-08-01T02:03:04.000Z',
      }),
      note({ organizationId: 'org-1', collectionIds: ['collection-1'] }),
    ], [
      { id: 'collection-1', organizationId: 'org-1', name: 'Engineering' },
      { id: 'collection-2', organizationId: 'org-1', name: 'Operations' },
    ]);
    const result = encodeVaultTransferCsv(ir);

    expect(result).toMatchObject({ ok: true, exportedItemCount: 2, omittedItemCount: 0 });
    expect(result.diagnostics).toEqual([]);
    expect(result.csv).toBe([
      'collections,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp',
      '"Operations,Engineering",login,Example,Login notes,environment: production,1,2026-08-01T02:03:04.000Z,https://example.com,alice,secret,otpauth://totp/example',
      'Engineering,note,Runbook,Recovery steps,,0,,,,,',
    ].join('\r\n'));
    expect(BITWARDEN_ORGANIZATION_CSV_COLUMNS).toHaveLength(11);

    const imported = inspectVaultTransferCsv(result.csv!);
    expect(imported.ir).toMatchObject({
      scope: 'organization',
      collections: [{ name: 'Operations' }, { name: 'Engineering' }],
      items: [
        { kind: 'login', collectionIds: ['csv-collection-0', 'csv-collection-1'] },
        { kind: 'secureNote', collectionIds: ['csv-collection-1'] },
      ],
    });
    expect(imported.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'organization_target_required' }),
    );
  });

  it('applies reversible spreadsheet formula protection to organization collections', () => {
    const result = encodeVaultTransferCsv(inspectOrganization([
      note({ organizationId: 'org-1', collectionIds: ['collection-1'] }),
    ], [
      { id: 'collection-1', organizationId: 'org-1', name: '=Finance' },
    ]));

    expect(result.ok).toBe(true);
    expect(result.csv).toContain('"\t=Finance",note,Runbook');
    expect(result.diagnostics).toContainEqual(expect.objectContaining({
      code: 'formula_prefix_escaped',
      sourceIndex: 0,
    }));
    const imported = inspectVaultTransferCsv(result.csv!);
    expect(imported.ir?.collections[0]?.name).toBe('=Finance');
  });

  it('fails closed when any item collection id is absent from the IR', () => {
    const ir = inspectOrganization([
      note({
        organizationId: 'org-1',
        collectionIds: ['collection-1', 'missing-collection'],
      }),
    ], [
      { id: 'collection-1', organizationId: 'org-1', name: 'Engineering' },
    ]);
    const result = encodeVaultTransferCsv(ir);

    expect(result).toMatchObject({ ok: false, csv: null, exportedItemCount: 0 });
    expect(result.diagnostics).toContainEqual(expect.objectContaining({
      severity: 'error',
      code: 'missing_collection_reference',
      path: '$.items[0].collectionIds',
      sourceIndex: 0,
    }));

    const omittedType = encodeVaultTransferCsv(inspectOrganization([
      {
        type: 3, name: 'Card', organizationId: 'org-1',
        collectionIds: ['missing-collection'], card: {},
      },
    ], [
      { id: 'collection-1', organizationId: 'org-1', name: 'Engineering' },
    ]));
    expect(omittedType).toMatchObject({ ok: false, csv: null, omittedItemCount: 0 });
    expect(omittedType.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'missing_collection_reference', sourceIndex: 0 }),
    );
  });

  it('fails closed for ambiguous collection identities and bounded collection cells', () => {
    const duplicate = inspectOrganization([
      note({ organizationId: 'org-1', collectionIds: ['collection-1'] }),
    ], [
      { id: 'collection-1', organizationId: 'org-1', name: 'Engineering' },
      { id: 'collection-1', organizationId: 'org-1', name: 'Operations' },
    ]);
    expect(encodeVaultTransferCsv(duplicate)).toMatchObject({ ok: false, csv: null });

    const oversized = encodeVaultTransferCsv(inspectOrganization([
      note({
        organizationId: 'org-1',
        collectionIds: ['collection-1', 'collection-2'],
        name: 'N',
      }),
    ], [
      { id: 'collection-1', organizationId: 'org-1', name: '123456' },
      { id: 'collection-2', organizationId: 'org-1', name: 'abcdef' },
    ]), { limits: { maxCellChars: 10 } });
    expect(oversized).toMatchObject({ ok: false, csv: null });
    expect(oversized.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'csv_cell_limit_exceeded' }),
    );
  });

  it('diagnoses organization-only CSV losses while omitting unsupported item types', () => {
    const result = encodeVaultTransferCsv(inspectOrganization([
      login({
        organizationId: 'org-1', collectionIds: ['collection-1'], favorite: true,
      }),
      { type: 3, name: 'Card', organizationId: 'org-1', collectionIds: ['collection-1'], card: {} },
    ], [
      { id: 'collection-1', organizationId: 'org-1', name: 'Engineering', externalId: 'ext-1' },
      { id: 'collection-2', organizationId: 'org-1', name: 'Empty collection' },
    ]));

    expect(result).toMatchObject({ ok: true, exportedItemCount: 1, omittedItemCount: 1 });
    expect(result.diagnostics.map((diagnostic) => diagnostic.code)).toEqual(expect.arrayContaining([
      'organization_favorite_omitted',
      'collection_external_id_omitted',
      'unrepresented_collection_omitted',
      'card_item_omitted',
    ]));
    expect(result.csv?.split('\r\n')[0]).not.toContain('favorite');
  });
});

describe('encodeVaultTransferCsv loss diagnostics', () => {
  it('omits unsupported official item types with source-indexed diagnostics', () => {
    const ir = inspectPersonal([
      login(),
      note(),
      { type: 3, name: 'Card', card: { brand: 'Visa' } },
      { type: 4, name: 'Identity', identity: { firstName: 'Ada' } },
      { type: 5, name: 'SSH', sshKey: {
        privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:x',
      } },
      { type: 6, name: 'Bank', bankAccount: { accountNumber: '123' } },
      { type: 7, name: 'License', driversLicense: { licenseNumber: 'D1' } },
      { type: 8, name: 'Passport', passport: { passportNumber: 'P1' } },
    ]);
    const result = encodeVaultTransferCsv(ir);

    expect(result).toMatchObject({ ok: true, exportedItemCount: 2, omittedItemCount: 6 });
    expect(result.csv?.split('\r\n')).toHaveLength(3);
    expect(result.diagnostics).toHaveLength(6);
    expect(result.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'card_item_omitted', sourceIndex: 2 }),
      expect.objectContaining({ code: 'identity_item_omitted', sourceIndex: 3 }),
      expect.objectContaining({ code: 'ssh_key_item_omitted', sourceIndex: 4 }),
      expect.objectContaining({ code: 'new_item_type_omitted', sourceIndex: 7 }),
    ]));
    expect(result.csv).not.toContain('PRIVATE');
    expect(result.csv).not.toContain('123');
  });

  it('diagnoses passkeys, attachments, history, and flattened custom fields', () => {
    const ir = inspectPersonal([login({
      fields: [
        { type: 1, name: 'hidden', value: 'secret' },
        { type: 3, name: 'linked', linkedId: 100 },
      ],
      attachments: [{ id: 'attachment-1', fileName: 'report.pdf' }],
      passwordHistory: [{ password: 'old-password' }],
      login: {
        autofillOnPageLoad: true,
        passwordRevisionDate: '2026-08-01T00:00:00.000Z',
        uris: [{ uri: 'https://example.com', match: 5 }],
        fido2Credentials: [{
          credentialId: 'credential', keyType: 'public-key', keyAlgorithm: 'ECDSA',
          keyCurve: 'P-256', keyValue: 'private-key', rpId: 'example.com', counter: '0',
          discoverable: 'true', creationDate: '2026-08-01T00:00:00.000Z',
        }],
      },
    })]);
    const result = encodeVaultTransferCsv(ir);

    expect(result.ok).toBe(true);
    expect(result.exportedItemCount).toBe(1);
    expect(result.diagnostics.map((diagnostic) => diagnostic.code)).toEqual(expect.arrayContaining([
      'custom_field_type_flattened',
      'attachments_omitted',
      'password_history_omitted',
      'passkeys_omitted',
      'autofill_override_omitted',
      'password_revision_date_omitted',
      'uri_match_rules_omitted',
    ]));
    expect(result.csv).not.toContain('private-key');
    expect(result.csv).not.toContain('old-password');
    expect(result.csv).not.toContain('report.pdf');
  });

  it('diagnoses non-generic secure-note subtype loss while retaining the note row', () => {
    const result = encodeVaultTransferCsv(inspectPersonal([
      note({ secureNote: { type: 1 } }),
    ]));
    expect(result).toMatchObject({ ok: true, exportedItemCount: 1, omittedItemCount: 0 });
    expect(result.diagnostics).toContainEqual(expect.objectContaining({
      code: 'secure_note_subtype_omitted',
      sourceIndex: 0,
    }));
  });

  it('neutralizes formula prefixes reversibly for the current importer', () => {
    const ir = inspectPersonal([login({
      name: '=HYPERLINK("https://evil.example")',
      notes: '+cmd|calc',
      login: { uris: [], username: '@SUM(A1)', password: '-2+3', totp: '=1+1' },
      folderId: 'folder-1',
    })], [{ id: 'folder-1', name: '=folder' }]);
    const result = encodeVaultTransferCsv(ir);

    expect(result.ok).toBe(true);
    expect(result.diagnostics.filter((diagnostic) => diagnostic.code === 'formula_prefix_escaped'))
      .toHaveLength(6);
    expect(result.csv).toContain('"\t=folder"');
    expect(result.csv).toContain('"\t=HYPERLINK(""https://evil.example"")"');
    expect(result.csv).not.toMatch(/(?:^|,)[=+\-@]/mu);

    const imported = inspectVaultTransferCsv(result.csv!);
    expect(imported.canCommit).toBe(true);
    expect(imported.ir?.folders[0]?.name).toBe('=folder');
    expect(imported.ir?.items[0]).toMatchObject({
      name: '=HYPERLINK("https://evil.example")',
      notes: '+cmd|calc',
      payload: { username: '@SUM(A1)', password: '-2+3', totp: '=1+1' },
    });
  });

  it('summarizes diagnostics beyond the retention limit', () => {
    const ir = inspectPersonal([
      { type: 3, name: 'Card', card: {} },
      { type: 4, name: 'Identity', identity: {} },
      { type: 5, name: 'SSH', sshKey: {
        privateKey: 'a', publicKey: 'b', keyFingerprint: 'c',
      } },
    ]);
    const result = encodeVaultTransferCsv(ir, { limits: { maxDiagnostics: 2 } });
    expect(result.ok).toBe(true);
    expect(result.omittedItemCount).toBe(3);
    expect(result.diagnostics).toHaveLength(2);
    expect(result.diagnostics.at(-1)).toMatchObject({ code: 'diagnostics_truncated' });
  });
});

describe('encodeVaultTransferCsv bounds', () => {
  it('fails closed instead of returning a partial file when row capacity is exceeded', () => {
    const result = encodeVaultTransferCsv(inspectPersonal([login(), note()]), {
      limits: { maxRows: 1 },
    });
    expect(result).toMatchObject({ ok: false, csv: null });
    expect(result.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'csv_rows_limit_exceeded' }),
    );
  });

  it('accepts 10,000 default rows and rejects the next row', () => {
    const ir = inspectPersonal([note()]);
    const template = ir.items[0]!;
    ir.items = Array.from({ length: 10_000 }, (_, sourceIndex) => ({
      ...template,
      sourceIndex,
      id: `note-${sourceIndex}`,
      raw: { ...template.raw, id: `note-${sourceIndex}` },
    }));
    const atLimit = encodeVaultTransferCsv(ir);
    expect(atLimit).toMatchObject({ ok: true, exportedItemCount: 10_000 });

    ir.items.push({
      ...template,
      sourceIndex: 10_000,
      id: 'note-10000',
      raw: { ...template.raw, id: 'note-10000' },
    });
    const overLimit = encodeVaultTransferCsv(ir);
    expect(overLimit).toMatchObject({ ok: false, csv: null });
    expect(overLimit.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'csv_rows_limit_exceeded' }),
    );
  });

  it('bounds cells before quote expansion and handles a default-limit huge string', () => {
    const small = encodeVaultTransferCsv(inspectPersonal([login({ name: 'abcdefghijk' })]), {
      limits: { maxCellChars: 10 },
    });
    expect(small).toMatchObject({ ok: false, csv: null });
    expect(small.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'csv_cell_limit_exceeded' }),
    );

    const huge = encodeVaultTransferCsv(inspectPersonal([
      login({ name: 'x'.repeat(256 * 1024 + 1) }),
    ]));
    expect(huge).toMatchObject({ ok: false, csv: null });
    expect(huge.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'csv_cell_limit_exceeded' }),
    );
  });

  it('bounds complete UTF-8 output rather than UTF-16 character count', () => {
    const baseline = encodeVaultTransferCsv(inspectPersonal([note({ name: 'a' })]));
    expect(baseline.ok).toBe(true);
    const asciiBytes = new TextEncoder().encode(baseline.csv!).byteLength;
    const unicode = encodeVaultTransferCsv(inspectPersonal([note({ name: '雪' })]), {
      limits: { maxOutputBytes: asciiBytes },
    });
    expect(unicode).toMatchObject({ ok: false, csv: null });
    expect(unicode.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'csv_output_limit_exceeded' }),
    );
  });

  it('rejects invalid or excessive limit overrides as programmer errors', () => {
    const ir = inspectPersonal([login()]);
    expect(() => encodeVaultTransferCsv(ir, { limits: { maxRows: 0 } })).toThrow(RangeError);
    expect(() => encodeVaultTransferCsv(ir, {
      limits: { maxOutputBytes: 64 * 1024 * 1024 + 1 },
    })).toThrow(RangeError);
  });

  it('rejects duplicate source identities', () => {
    const duplicate = structuredClone(inspectPersonal([login(), note()]));
    duplicate.items[1]!.sourceIndex = duplicate.items[0]!.sourceIndex;
    const result = encodeVaultTransferCsv(duplicate);
    expect(result).toMatchObject({ ok: false, csv: null });
    expect(result.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'invalid_source_index' }),
    );
  });
});
