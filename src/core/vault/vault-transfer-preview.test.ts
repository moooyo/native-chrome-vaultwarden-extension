import { describe, expect, it } from 'vitest';
import {
  CIPHER_INPUT_IMPORT_CAPABILITIES,
  type PersonalImportCapabilityPolicy,
} from './vault-transfer-commit.js';
import {
  VAULTWARDEN_ORGANIZATION_IMPORT_BLOCKER,
  buildVaultTransferPreview,
} from './vault-transfer-preview.js';
import { inspectVaultTransferCsv, inspectVaultTransferJson, type VaultTransferInspection } from './vault-transfer.js';

function personal(items: unknown[] = [], folders: unknown[] = []): VaultTransferInspection {
  return inspectVaultTransferJson(JSON.stringify({ encrypted: false, folders, items }));
}

function policy(overrides: Partial<PersonalImportCapabilityPolicy> = {}): PersonalImportCapabilityPolicy {
  return { ...CIPHER_INPUT_IMPORT_CAPABILITIES, ...overrides };
}

describe('vault transfer preview', () => {
  it('builds a deeply frozen, bounded, value-free preview for a personal transfer', () => {
    const preview = buildVaultTransferPreview(personal([
      { type: 1, name: 'Private login', login: { username: 'alice', password: 'SECRET', uris: [] } },
    ], [{ id: 'f1', name: 'Private folder' }]), policy());

    expect(preview).toMatchObject({
      format: 'bitwarden-json',
      scope: 'personal',
      counts: { folders: 1, collections: 0, items: 1, attachments: 0 },
      canCommit: true,
    });
    expect(Object.isFrozen(preview)).toBe(true);
    expect(Object.isFrozen(preview.counts)).toBe(true);
    expect(Object.isFrozen(preview.diagnostics)).toBe(true);
    expect(Object.isFrozen(preview.diagnostics.errors)).toBe(true);
    expect(JSON.stringify(preview)).not.toMatch(/Private login|Private folder|alice|SECRET/);
  });

  it('preserves only the stable CSV warning and format', () => {
    const inspection = inspectVaultTransferCsv('name,login_username,login_password\nSite,user,pass');
    const preview = buildVaultTransferPreview(inspection, policy());

    expect(preview.format).toBe('bitwarden-csv');
    expect(preview.diagnostics.warnings).toContainEqual({
      category: 'warning',
      code: 'csv_format_is_lossy',
    });
    expect(preview.canCommit).toBe(true);
  });

  it('never serializes hostile messages, paths, codes, names, values, or passwords', () => {
    const base = personal([{ type: 1, name: 'ITEM-NAME-SECRET', login: { password: 'PASSWORD-SECRET', uris: [] } }]);
    const poisoned: VaultTransferInspection = {
      ...base,
      canCommit: false,
      diagnostics: [{
        severity: 'error',
        code: 'CODE-SECRET',
        message: 'MESSAGE-SECRET',
        path: '$.items[0].PATH-SECRET',
        sourceKind: 'item',
        sourceIndex: 0,
      }],
    };
    const preview = buildVaultTransferPreview(poisoned, policy());
    const serialized = JSON.stringify(preview);

    expect(preview.diagnostics.errors).toContainEqual({
      category: 'error',
      code: 'transfer_diagnostic',
      sourceIndex: 0,
    });
    for (const secret of [
      'CODE-SECRET', 'MESSAGE-SECRET', 'PATH-SECRET', 'ITEM-NAME-SECRET', 'PASSWORD-SECRET',
    ]) expect(serialized).not.toContain(secret);
  });

  it('blocks capabilities that the active personal writer cannot preserve', () => {
    const inspection = personal([{
      type: 1,
      name: 'Login',
      passwordHistory: [{ password: 'OLD-SECRET' }],
      login: { uris: [] },
    }]);
    const preview = buildVaultTransferPreview(inspection, policy({ passwordHistory: false }));

    expect(preview.canCommit).toBe(false);
    expect(preview.diagnostics.unsupported).toContainEqual({
      category: 'unsupported',
      code: 'password_history_unsupported',
      sourceIndex: 0,
    });
    expect(JSON.stringify(preview)).not.toContain('OLD-SECRET');
  });

  it('keeps SSH keys disabled by default and previews them when type 5 is dynamically enabled', () => {
    const inspection = personal([{
      type: 5,
      name: 'Deploy key',
      notes: 'PRIVATE-NOTE',
      reprompt: 1,
      fields: [{ type: 0, name: 'environment', value: 'PRIVATE-FIELD' }],
      sshKey: {
        privateKey: 'PRIVATE-KEY-SECRET',
        publicKey: 'ssh-ed25519 PUBLIC-KEY-SECRET',
        keyFingerprint: 'SHA256:FINGERPRINT-SECRET',
      },
    }]);
    const disabled = buildVaultTransferPreview(inspection, policy());
    const enabled = buildVaultTransferPreview(
      inspection,
      policy({ supportedItemTypes: [1, 2, 3, 4, 5] }),
    );

    expect(disabled.canCommit).toBe(false);
    expect(disabled.diagnostics.unsupported).toContainEqual({
      category: 'unsupported',
      code: 'item_type_unsupported',
      sourceIndex: 0,
    });
    expect(enabled.canCommit).toBe(true);
    expect(enabled.diagnostics.unsupported).not.toContainEqual(expect.objectContaining({
      code: 'item_type_unsupported',
    }));
    expect(JSON.stringify(enabled)).not.toMatch(/PRIVATE-NOTE|PRIVATE-FIELD|PRIVATE-KEY-SECRET|PUBLIC-KEY-SECRET|FINGERPRINT-SECRET/);
  });

  it('blocks linked custom fields on SSH key previews without exposing field data', () => {
    const inspection = personal([{
      type: 5,
      name: 'Deploy key',
      fields: [{ type: 3, name: 'PRIVATE-FIELD-NAME', value: 'PRIVATE-FIELD-VALUE', linkedId: 100 }],
      sshKey: {
        privateKey: 'PRIVATE-KEY-SECRET',
        publicKey: 'PUBLIC-KEY-SECRET',
        keyFingerprint: 'FINGERPRINT-SECRET',
      },
    }]);
    const preview = buildVaultTransferPreview(
      inspection,
      policy({ supportedItemTypes: [1, 2, 3, 4, 5] }),
    );

    expect(preview.canCommit).toBe(false);
    expect(preview.diagnostics.unsupported).toContainEqual({
      category: 'unsupported',
      code: 'ssh_linked_fields_unsupported',
      sourceIndex: 0,
    });
    expect(JSON.stringify(preview)).not.toMatch(/PRIVATE-FIELD-NAME|PRIVATE-FIELD-VALUE|PRIVATE-KEY-SECRET|PUBLIC-KEY-SECRET|FINGERPRINT-SECRET/);
  });

  it('rejects forged type 5 kind mappings and incomplete SSH payloads', () => {
    const source = personal([{
      type: 5,
      name: 'Deploy key',
      sshKey: {
        privateKey: 'PRIVATE',
        publicKey: 'PUBLIC',
        keyFingerprint: 'SHA256:key',
      },
    }]);
    const mismatched = structuredClone(source);
    const mismatchedItem = mismatched.ir!.items[0]! as unknown as Record<string, unknown>;
    mismatchedItem.kind = 'login';
    const incomplete = structuredClone(source);
    const incompleteItem = incomplete.ir!.items[0]!;
    if (incompleteItem.kind !== 'sshKey') throw new Error('Expected an SSH transfer item');
    delete (incompleteItem.payload.values as Record<string, string | null>).publicKey;

    for (const forged of [mismatched, incomplete]) {
      const preview = buildVaultTransferPreview(
        forged,
        policy({ supportedItemTypes: [1, 2, 3, 4, 5] }),
      );
      expect(preview.canCommit).toBe(false);
      expect(preview.diagnostics.errors).toContainEqual({
        category: 'error',
        code: 'inspection_invalid',
      });
    }
  });

  it('rejects item types above 5 and refuses policies that claim them', () => {
    const inspection = personal([{
      type: 6,
      name: 'Bank account',
      bankAccount: { bankName: 'Example' },
    }]);
    const preview = buildVaultTransferPreview(
      inspection,
      policy({ supportedItemTypes: [1, 2, 3, 4, 5] }),
    );
    const forgedPolicy = policy({
      supportedItemTypes: [1, 2, 3, 4, 6],
    } as unknown as Partial<PersonalImportCapabilityPolicy>);
    const forgedPolicyPreview = buildVaultTransferPreview(inspection, forgedPolicy);

    expect(preview.canCommit).toBe(false);
    expect(preview.diagnostics.unsupported).toContainEqual({
      category: 'unsupported',
      code: 'item_type_unsupported',
      sourceIndex: 0,
    });
    expect(forgedPolicyPreview.canCommit).toBe(false);
    expect(forgedPolicyPreview.diagnostics.errors).toContainEqual({
      category: 'error',
      code: 'capability_policy_invalid',
    });
  });

  it('keeps server-managed item dates advisory while enforcing the autofill writer capability', () => {
    const inspection = personal([{
      type: 1,
      name: 'Login',
      creationDate: '2025-01-01T00:00:00.000Z',
      revisionDate: '2025-02-01T00:00:00.000Z',
      deletedDate: null,
      archivedDate: null,
      login: { autofillOnPageLoad: false, uris: [] },
    }]);
    const allowed = buildVaultTransferPreview(inspection, policy());
    const denied = buildVaultTransferPreview(inspection, policy({ autofillOnPageLoad: false }));

    expect(allowed.canCommit).toBe(true);
    expect(allowed.diagnostics.warnings).toContainEqual({
      category: 'warning',
      code: 'server_managed_dates_dropped',
      sourceIndex: 0,
    });
    expect(allowed.diagnostics.unsupported).not.toContainEqual(expect.objectContaining({
      code: 'item_dates_unsupported',
    }));
    expect(denied.canCommit).toBe(false);
    expect(denied.diagnostics.unsupported).toContainEqual({
      category: 'unsupported',
      code: 'autofill_on_page_load_unsupported',
      sourceIndex: 0,
    });
  });

  it('allows archived state only when advertised and always blocks deleted state', () => {
    const archivedInspection = personal([{
      type: 2,
      name: 'Archived note',
      archivedDate: '2025-01-01T00:00:00.000Z',
      secureNote: { type: 0 },
    }]);
    expect(buildVaultTransferPreview(archivedInspection, policy()).canCommit).toBe(false);
    expect(buildVaultTransferPreview(
      archivedInspection,
      policy({ itemDates: true }),
    ).canCommit).toBe(true);

    const deleted = buildVaultTransferPreview(personal([{
      type: 2,
      name: 'Deleted note',
      deletedDate: '2025-01-01T00:00:00.000Z',
      secureNote: { type: 0 },
    }]), policy({ itemDates: true }));
    expect(deleted.canCommit).toBe(false);
    expect(deleted.diagnostics.unsupported).toContainEqual({
      category: 'unsupported',
      code: 'item_dates_unsupported',
      sourceIndex: 0,
    });
  });

  it('blocks password history beyond the lossless writer limit', () => {
    const preview = buildVaultTransferPreview(personal([{
      type: 1,
      name: 'Login',
      passwordHistory: Array.from({ length: 6 }, (_, index) => ({ password: `old-${index}` })),
      login: { uris: [] },
    }]), policy({ passwordHistory: true }));

    expect(preview.canCommit).toBe(false);
    expect(preview.diagnostics.unsupported).toContainEqual({
      category: 'unsupported',
      code: 'password_history_limit_exceeded',
      sourceIndex: 0,
    });
  });

  it('blocks passkeys missing the required creation timestamp even when supported', () => {
    const preview = buildVaultTransferPreview(personal([{
      type: 1,
      name: 'Login',
      login: {
        uris: [],
        fido2Credentials: [{
          credentialId: 'AQ',
          keyType: 'public-key',
          keyAlgorithm: 'ECDSA',
          keyCurve: 'P-256',
          keyValue: 'AQ',
          rpId: 'example.com',
          counter: '0',
          discoverable: 'false',
        }],
      },
    }]), policy({ passkeys: true }));

    expect(preview.canCommit).toBe(false);
    expect(preview.diagnostics.unsupported).toContainEqual({
      category: 'unsupported',
      code: 'passkeys_unsupported',
      sourceIndex: 0,
    });
  });

  it('strictly rejects forged login metadata before deriving capabilities', () => {
    const forged = structuredClone(personal([{
      type: 1,
      name: 'Login',
      login: { autofillOnPageLoad: null, passwordRevisionDate: null, uris: [] },
    }]));
    const item = forged.ir!.items[0];
    if (item?.kind === 'login') item.payload.passwordRevisionDate = '2026-02-30T03:04:05Z';

    const preview = buildVaultTransferPreview(forged, policy());

    expect(preview.canCommit).toBe(false);
    expect(preview.diagnostics.errors).toContainEqual({
      category: 'error',
      code: 'inspection_invalid',
    });
  });

  it('strictly rejects forged calendar-invalid provenance metadata', () => {
    const forged = structuredClone(personal([{
      type: 2,
      name: 'Note',
      creationDate: '2026-01-01T00:00:00Z',
      secureNote: { type: 0 },
    }]));
    forged.ir!.items[0]!.creationDate = '2026-02-30T00:00:00Z';

    const preview = buildVaultTransferPreview(forged, policy());
    expect(preview.canCommit).toBe(false);
    expect(preview.diagnostics.errors).toContainEqual({
      category: 'error',
      code: 'inspection_invalid',
    });
  });

  it('blocks organization transfers until an atomic server transport is negotiated', () => {
    const inspection = inspectVaultTransferJson(JSON.stringify({
      encrypted: false,
      collections: [],
      items: [],
    }));
    const preview = buildVaultTransferPreview(inspection, policy());

    expect(preview.scope).toBe('organization');
    expect(preview.organizationTargetRequired).toBe(true);
    expect(preview.canCommit).toBe(false);
    expect(preview.diagnostics.errors).toContainEqual({
      category: 'error',
      code: 'organization_target_required',
    });
    expect(preview.diagnostics.unsupported).toContainEqual({
      category: 'unsupported',
      code: 'organization_import_atomicity_unavailable',
    });
    expect(VAULTWARDEN_ORGANIZATION_IMPORT_BLOCKER).toEqual({
      endpoint: '/api/ciphers/import-organization',
      code: 'non_atomic_partial_commit',
      atomic: false,
    });
  });

  it('reports ZIP metadata but blocks attachments unsupported by the current writer', () => {
    const preview = buildVaultTransferPreview(personal(), policy(), {
      format: 'bitwarden-zip',
      attachmentCount: 3,
    });

    expect(preview.format).toBe('bitwarden-zip');
    expect(preview.counts.attachments).toBe(3);
    expect(preview.canCommit).toBe(false);
    expect(preview.diagnostics.unsupported).toContainEqual({
      category: 'unsupported',
      code: 'attachments_unsupported',
    });
  });

  it('blocks a prior unknown outcome until reconciliation', () => {
    const preview = buildVaultTransferPreview(personal(), policy(), { unknownOutcome: true });

    expect(preview.hasUnknownOutcome).toBe(true);
    expect(preview.canCommit).toBe(false);
    expect(preview.diagnostics.errors).toContainEqual({
      category: 'error',
      code: 'outcome_unknown',
    });
  });

  it('limits each diagnostic group to 32 and reports one total omitted count', () => {
    const base = personal();
    const diagnostics = [
      ...Array.from({ length: 40 }, (_, sourceIndex) => ({
        severity: 'warning' as const,
        code: 'csv_format_is_lossy',
        message: `WARNING-SECRET-${sourceIndex}`,
        sourceKind: 'row' as const,
        sourceIndex,
      })),
      ...Array.from({ length: 35 }, (_, sourceIndex) => ({
        severity: 'error' as const,
        code: 'invalid_shape',
        message: `ERROR-SECRET-${sourceIndex}`,
        sourceKind: 'item' as const,
        sourceIndex,
      })),
    ];
    const preview = buildVaultTransferPreview({ ...base, canCommit: false, diagnostics }, policy());

    expect(preview.diagnostics.warnings).toHaveLength(32);
    expect(preview.diagnostics.errors).toHaveLength(32);
    expect(preview.diagnostics.omittedCount).toBe(11);
    expect(preview.canCommit).toBe(false);
    expect(JSON.stringify(preview)).not.toContain('SECRET');
  });

  it('does not make omitted warnings blocking', () => {
    const base = personal();
    const diagnostics = Array.from({ length: 40 }, (_, sourceIndex) => ({
      severity: 'warning' as const,
      code: 'csv_format_is_lossy',
      message: 'not exported',
      sourceKind: 'row' as const,
      sourceIndex,
    }));
    const preview = buildVaultTransferPreview({ ...base, diagnostics }, policy());

    expect(preview.diagnostics.warnings).toHaveLength(32);
    expect(preview.diagnostics.omittedCount).toBe(8);
    expect(preview.canCommit).toBe(true);
  });

  it('rejects accessors without invoking them', () => {
    let reads = 0;
    const diagnostic = {
      severity: 'error',
      code: 'invalid_shape',
      get message() {
        reads++;
        return 'ACCESSOR-SECRET';
      },
      sourceKind: 'root',
    };
    const inspection = { ...personal(), canCommit: false, diagnostics: [diagnostic] } as VaultTransferInspection;
    const preview = buildVaultTransferPreview(inspection, policy());

    expect(reads).toBe(0);
    expect(preview.canCommit).toBe(false);
    expect(preview.diagnostics.errors).toContainEqual({
      category: 'error',
      code: 'inspection_invalid',
    });
    expect(JSON.stringify(preview)).not.toContain('ACCESSOR-SECRET');
  });

  it('fails closed before traversing oversized or sparse forged arrays', () => {
    const forged = structuredClone(personal());
    forged.ir!.items = new Array(10_001);
    const preview = buildVaultTransferPreview(forged, policy());

    expect(preview.canCommit).toBe(false);
    expect(preview.counts.items).toBe(0);
    expect(preview.diagnostics.errors).toContainEqual({
      category: 'error',
      code: 'inspection_resource_limit',
    });
    expect(preview.diagnostics.omittedCount).toBe(0);
  });

  it('bounds the source diagnostic array before cloning it', () => {
    const forged = {
      ...personal(),
      diagnostics: new Array(1_001).fill({
        severity: 'warning',
        code: 'csv_format_is_lossy',
        message: 'not exported',
      }),
    } as VaultTransferInspection;
    const preview = buildVaultTransferPreview(forged, policy());

    expect(preview.canCommit).toBe(false);
    expect(preview.diagnostics.errors).toContainEqual({
      category: 'error',
      code: 'inspection_resource_limit',
    });
    expect(preview.diagnostics.omittedCount).toBe(1_001);
  });

  it('rejects malformed policies and mismatched format metadata', () => {
    const invalidPolicy = { ...policy(), folders: 'yes' } as unknown as PersonalImportCapabilityPolicy;
    const policyPreview = buildVaultTransferPreview(personal(), invalidPolicy);
    expect(policyPreview.canCommit).toBe(false);
    expect(policyPreview.diagnostics.errors).toContainEqual({
      category: 'error',
      code: 'capability_policy_invalid',
    });

    const formatPreview = buildVaultTransferPreview(personal(), policy(), { format: 'bitwarden-csv' });
    expect(formatPreview.canCommit).toBe(false);
    expect(formatPreview.diagnostics.errors).toContainEqual({
      category: 'error',
      code: 'format_mismatch',
    });
  });
});
