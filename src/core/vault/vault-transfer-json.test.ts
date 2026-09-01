import { describe, expect, it } from 'vitest';
import { inspectVaultTransferJson, type VaultTransferIR } from './vault-transfer.js';
import { encodeVaultTransferJson } from './vault-transfer-json.js';

function richPersonalDocument(): Record<string, unknown> {
  return {
    encrypted: false,
    folders: [{ id: 'folder-1', name: 'Work / 特殊 "folder"' }],
    items: [
      {
        id: 'login-1',
        organizationId: null,
        folderId: 'folder-1',
        collectionIds: null,
        type: 1,
        reprompt: 1,
        name: 'Login "quoted"\n雪',
        notes: '',
        favorite: true,
        fields: [
          { type: 0, name: '', value: '' },
          { type: 3, name: null, value: null, linkedId: 100 },
        ],
        login: {
          username: null,
          password: '',
          totp: 'TOTP-雪',
          autofillOnPageLoad: false,
          passwordRevisionDate: '2025-01-02T03:04:05.1234567Z',
          uris: [
            { match: null, uri: 'https://example.com/a,b?x="quoted"' },
            { match: 5, uri: 'https://never.example.com' },
          ],
          fido2Credentials: [{
            credentialId: 'credential-id',
            keyType: 'public-key',
            keyAlgorithm: 'ECDSA',
            keyCurve: 'P-256',
            keyValue: 'private-key-value',
            rpId: 'example.com',
            counter: '7',
            discoverable: 'true',
            userHandle: null,
            userName: 'alice',
            rpName: 'Example',
            userDisplayName: '',
            creationDate: null,
          }],
        },
        passwordHistory: [{ password: 'old\npassword', lastUsedDate: null }],
        creationDate: '2025-01-01T00:00:00.000Z',
        revisionDate: null,
        deletedDate: null,
        archivedDate: null,
      },
      {
        id: 'note-1', type: 2, reprompt: 0, name: 'Note', notes: null, favorite: false,
        secureNote: { type: 0 }, fields: null, passwordHistory: null,
      },
      {
        id: 'card-1', type: 3, reprompt: 0, name: 'Card', favorite: false,
        card: { cardholderName: 'A & B', brand: 'Visa', number: null, expMonth: '01', expYear: '2030', code: '' },
      },
      {
        id: 'identity-1', type: 4, reprompt: 0, name: 'Identity', favorite: false,
        identity: { firstName: 'Ada', middleName: null, lastName: 'Lovelace', address1: '', email: 'ada@example.com' },
      },
      {
        id: 'ssh-1', type: 5, reprompt: 0, name: 'SSH', favorite: false,
        sshKey: { privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:abc' },
      },
      {
        id: 'bank-1', type: 6, reprompt: 0, name: 'Bank', favorite: false,
        bankAccount: { bankName: 'Acme', nameOnAccount: null, accountNumber: '0001', iban: '' },
      },
      {
        id: 'license-1', type: 7, reprompt: 0, name: 'License', favorite: false,
        driversLicense: { firstName: 'Ada', middleName: null, licenseNumber: 'D123', issuingCountry: 'GB' },
      },
      {
        id: 'passport-1', type: 8, reprompt: 0, name: 'Passport', favorite: false,
        passport: { surname: 'Lovelace', givenName: 'Ada', passportNumber: null, nationality: 'GB' },
      },
    ],
  };
}

function inspectRich(): VaultTransferIR {
  const inspected = inspectVaultTransferJson(JSON.stringify(richPersonalDocument()));
  expect(inspected.canCommit).toBe(true);
  return inspected.ir!;
}

describe('encodeVaultTransferJson personal round trip', () => {
  it('round-trips complete types 1-8 with stable null and special-character semantics', () => {
    const firstIr = inspectRich();
    const first = encodeVaultTransferJson(firstIr);
    expect(first.ok).toBe(true);
    expect(first.diagnostics).toEqual([]);
    expect(first.json).not.toBeNull();

    const document = JSON.parse(first.json!) as { encrypted: boolean; folders: unknown[]; items: Array<Record<string, unknown>> };
    expect(document.encrypted).toBe(false);
    expect(document.folders).toEqual([{ id: 'folder-1', name: 'Work / 特殊 "folder"' }]);
    const login = document.items[0]!;
    expect(login).toMatchObject({
      organizationId: null,
      folderId: 'folder-1',
      collectionIds: null,
      reprompt: 1,
      name: 'Login "quoted"\n雪',
      notes: '',
      fields: [
        { type: 0, name: '', value: '' },
        { type: 3, name: null, value: null, linkedId: 100 },
      ],
      passwordHistory: [{ password: 'old\npassword', lastUsedDate: null }],
      revisionDate: null,
      archivedDate: null,
    });
    expect(login.login).toMatchObject({
      username: null,
      password: '',
      autofillOnPageLoad: false,
      passwordRevisionDate: '2025-01-02T03:04:05.1234567Z',
      uris: [
        { match: null, uri: 'https://example.com/a,b?x="quoted"' },
        { match: 5, uri: 'https://never.example.com' },
      ],
      fido2Credentials: [{
        credentialId: 'credential-id', userHandle: null, userDisplayName: '', creationDate: null,
      }],
    });
    expect(document.items.map((item) => item.type)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);

    const secondInspection = inspectVaultTransferJson(first.json!);
    expect(secondInspection.canCommit).toBe(true);
    const second = encodeVaultTransferJson(secondInspection.ir!);
    expect(second).toMatchObject({ ok: true, json: first.json });
  });

  it('canonicalizes every source-indexed collection with deterministic ordering', () => {
    const ir = structuredClone(inspectRich());
    ir.folders.reverse();
    ir.items.reverse();
    const login = ir.items.find((item) => item.kind === 'login');
    if (login?.kind === 'login') {
      login.fields.reverse();
      login.passwordHistory.reverse();
      login.payload.uris.reverse();
      login.payload.fido2Credentials.reverse();
    }
    const reordered = encodeVaultTransferJson(ir);
    const canonical = encodeVaultTransferJson(inspectRich());
    expect(reordered.ok).toBe(true);
    expect(reordered.json).toBe(canonical.json);
  });

  it('supports compact output without changing the encoded document', () => {
    const ir = inspectRich();
    const pretty = encodeVaultTransferJson(ir);
    const compact = encodeVaultTransferJson(ir, { pretty: false });
    expect(compact.ok).toBe(true);
    expect(compact.json).not.toContain('\n');
    expect(JSON.parse(compact.json!)).toEqual(JSON.parse(pretty.json!));
  });
});

describe('encodeVaultTransferJson organization modes', () => {
  function organizationIr(): VaultTransferIR {
    const inspected = inspectVaultTransferJson(JSON.stringify({
      encrypted: false,
      collections: [{ id: 'collection-1', name: 'Engineering', organizationId: 'old-org', externalId: null }],
      items: [{
        id: 'item-1',
        organizationId: 'old-org',
        folderId: null,
        collectionIds: ['collection-1'],
        type: 2,
        reprompt: 0,
        name: 'Runbook',
        notes: null,
        favorite: false,
        secureNote: { type: 0 },
      }],
    }));
    expect(inspected.ir?.scope).toBe('organization');
    return inspected.ir!;
  }

  it('rejects organization IR by default and permits explicit export mode', () => {
    const ir = organizationIr();
    const blocked = encodeVaultTransferJson(ir);
    expect(blocked.ok).toBe(false);
    expect(blocked.json).toBeNull();
    expect(blocked.diagnostics).toContainEqual(expect.objectContaining({ code: 'organization_mode_required' }));

    const exported = encodeVaultTransferJson(ir, { organization: { mode: 'export' } });
    expect(exported.ok).toBe(true);
    const document = JSON.parse(exported.json!) as { collections: Array<Record<string, unknown>>; items: Array<Record<string, unknown>> };
    expect(document.collections[0]).toMatchObject({ organizationId: 'old-org', externalId: null });
    expect(document.items[0]).toMatchObject({ organizationId: 'old-org', collectionIds: ['collection-1'] });
    expect(document).not.toHaveProperty('folders');
  });

  it('rewrites organization ownership only in explicit target mode', () => {
    const targeted = encodeVaultTransferJson(organizationIr(), {
      organization: { mode: 'target', organizationId: 'new-org' },
    });
    expect(targeted.ok).toBe(true);
    const document = JSON.parse(targeted.json!) as { collections: Array<Record<string, unknown>>; items: Array<Record<string, unknown>> };
    expect(document.collections[0]!.organizationId).toBe('new-org');
    expect(document.items[0]!.organizationId).toBe('new-org');

    const reinspected = inspectVaultTransferJson(targeted.json!);
    expect(reinspected.ir?.scope).toBe('organization');
    expect(reinspected.ir?.collectionRelationships).toEqual([
      { itemSourceIndex: 0, sourceCollectionId: 'collection-1', collectionSourceIndex: 0 },
    ]);
  });

  it('rejects organization mode on personal IR and invalid target ids', () => {
    const personal = encodeVaultTransferJson(inspectRich(), { organization: { mode: 'export' } });
    expect(personal.ok).toBe(false);
    expect(personal.diagnostics).toContainEqual(expect.objectContaining({ code: 'organization_mode_on_personal' }));

    const invalidTarget = encodeVaultTransferJson(organizationIr(), {
      organization: { mode: 'target', organizationId: '' },
    });
    expect(invalidTarget.ok).toBe(false);
    expect(invalidTarget.diagnostics).toContainEqual(expect.objectContaining({ code: 'invalid_organization_target' }));
  });
});

describe('encodeVaultTransferJson refusal paths', () => {
  it('revalidates strict login metadata retained by a blocked inspection', () => {
    const inspected = inspectVaultTransferJson(JSON.stringify({
      encrypted: false,
      folders: [],
      items: [{
        type: 1,
        name: 'Login',
        login: {
          autofillOnPageLoad: 'false',
          passwordRevisionDate: '2026-01-01T00:00:00+14:01',
          uris: [],
        },
      }],
    }));
    expect(inspected.canCommit).toBe(false);

    const encoded = encodeVaultTransferJson(inspected.ir!);

    expect(encoded.ok).toBe(false);
    expect(encoded.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: '$.items[0].login.autofillOnPageLoad' }),
      expect.objectContaining({ path: '$.items[0].login.passwordRevisionDate' }),
    ]));
  });

  it('revalidates malformed known JSON fields retained by a blocked inspection', () => {
    const inspected = inspectVaultTransferJson(JSON.stringify({
      encrypted: false,
      folders: [],
      items: [{
        type: 3,
        name: 'Card',
        favorite: false,
        creationDate: 'not-a-date',
        card: { brand: 'Visa', number: 4111 },
      }],
    }));
    expect(inspected.canCommit).toBe(false);
    const encoded = encodeVaultTransferJson(inspected.ir!);
    expect(encoded.ok).toBe(false);
    expect(encoded.json).toBeNull();
    expect(encoded.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'unrepresentable_known_data', path: '$.items[0].creationDate' }),
      expect.objectContaining({ code: 'unrepresentable_known_data', path: '$.items[0].card.number' }),
    ]));
  });

  it('refuses unsupported items and unknown paths instead of generating partial JSON', () => {
    const unsupportedInspection = inspectVaultTransferJson(JSON.stringify({
      encrypted: false,
      folders: [],
      items: [{ type: 99, name: 'Future', futurePayload: { secret: 'do not drop' } }],
    }));
    const unsupported = encodeVaultTransferJson(unsupportedInspection.ir!);
    expect(unsupported.ok).toBe(false);
    expect(unsupported.json).toBeNull();
    expect(unsupported.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'unsupported_item' }),
      expect.objectContaining({ code: 'unknown_field' }),
    ]));

    const unknownInspection = inspectVaultTransferJson(JSON.stringify({
      encrypted: false,
      folders: [],
      items: [{ type: 2, name: 'Note', futureFlag: true, secureNote: { type: 0 } }],
    }));
    const unknown = encodeVaultTransferJson(unknownInspection.ir!);
    expect(unknown.ok).toBe(false);
    expect(unknown.json).toBeNull();
    expect(unknown.diagnostics).toContainEqual(expect.objectContaining({
      code: 'unknown_field', path: '$.items[0].futureFlag',
    }));
  });

  it.each([
    ['attachments', { attachments: [{ id: 'attachment-1', fileName: 'file.txt' }] }, 'attachments_require_archive'],
    ['encrypted item key', { key: '2.encrypted-key' }, 'encrypted_item_key_unsupported'],
  ])('refuses %s that plaintext JSON cannot represent safely', (_label, extra, code) => {
    const inspected = inspectVaultTransferJson(JSON.stringify({
      encrypted: false,
      folders: [],
      items: [{ type: 2, name: 'Note', secureNote: { type: 0 }, ...extra }],
    }));
    const result = encodeVaultTransferJson(inspected.ir!);
    expect(result.ok).toBe(false);
    expect(result.json).toBeNull();
    expect(result.diagnostics).toContainEqual(expect.objectContaining({ code }));
  });

  it('refuses missing or mismatched folder relationships', () => {
    const missing = structuredClone(inspectVaultTransferJson(JSON.stringify({
      encrypted: false,
      folders: [{ id: 'folder-1', name: 'Work' }],
      items: [{ type: 2, name: 'Note', folderId: 'folder-1', secureNote: { type: 0 } }],
    })).ir!);
    missing.folderRelationships = [];
    const missingResult = encodeVaultTransferJson(missing);
    expect(missingResult.ok).toBe(false);
    expect(missingResult.json).toBeNull();
    expect(missingResult.diagnostics).toContainEqual(expect.objectContaining({ code: 'unresolved_folder_relationship' }));

    const mismatched = structuredClone(inspectRich());
    mismatched.folderRelationships[0]!.folderSourceIndex = 99;
    const mismatchResult = encodeVaultTransferJson(mismatched);
    expect(mismatchResult.ok).toBe(false);
    expect(mismatchResult.diagnostics).toContainEqual(expect.objectContaining({ code: 'unresolved_folder_relationship' }));
  });

  it('refuses unresolved organization collection relationships', () => {
    const inspected = inspectVaultTransferJson(JSON.stringify({
      encrypted: false,
      collections: [{ id: 'collection-1', name: 'Team' }],
      items: [{ type: 2, name: 'Note', collectionIds: ['collection-1'], secureNote: { type: 0 } }],
    }));
    const ir = structuredClone(inspected.ir!);
    ir.collectionRelationships[0]!.collectionSourceIndex = 4;
    const result = encodeVaultTransferJson(ir, { organization: { mode: 'export' } });
    expect(result.ok).toBe(false);
    expect(result.json).toBeNull();
    expect(result.diagnostics).toContainEqual(expect.objectContaining({ code: 'unresolved_collection_relationship' }));
  });
});
