import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) },
      onChanged: { addListener: vi.fn() },
    },
  },
}));

import { setLocale } from '../../ui/i18n/index.js';
import { toSanitizedImportPreview } from '../../ui/options/sections/import-preview-adapter.js';
import {
  inspectVaultTransferJson,
  type VaultTransferInspection,
  type VaultTransferItem,
} from './vault-transfer.js';
import {
  CIPHER_INPUT_IMPORT_CAPABILITIES,
  commitPersonalVaultTransfer,
  inspectPersonalImportCapabilities,
  toPersonalImportItemWrite,
  type PersonalImportCapabilityPolicy,
  type PersonalImportCommitDeps,
  type PersonalImportItemWrite,
} from './vault-transfer-commit.js';

function json(items: unknown[], folders: unknown[] = []): string {
  return JSON.stringify({ encrypted: false, folders, items });
}

function inspect(items: unknown[], folders: unknown[] = []): VaultTransferInspection {
  const inspection = inspectVaultTransferJson(json(items, folders));
  expect(inspection.canCommit).toBe(true);
  return inspection;
}

function policy(overrides: Partial<PersonalImportCapabilityPolicy> = {}): PersonalImportCapabilityPolicy {
  return {
    ...CIPHER_INPUT_IMPORT_CAPABILITIES,
    supportedItemTypes: [...CIPHER_INPUT_IMPORT_CAPABILITIES.supportedItemTypes],
    ...overrides,
  };
}

function makeDeps(overrides: Partial<PersonalImportCommitDeps> = {}): PersonalImportCommitDeps {
  return {
    createFolder: vi.fn(async (folder) => ({ status: 'committed', value: { id: `new-${folder.sourceId}` } } as const)),
    createItem: vi.fn(async (item) => ({ status: 'committed', value: { id: `new-item-${item.sourceIndex}` } } as const)),
    markDirty: vi.fn(async () => {}),
    forceReconcile: vi.fn(async () => {}),
    ...overrides,
  };
}

const note = (name: string, folderId?: string) => ({
  type: 2,
  name,
  ...(folderId ? { folderId } : {}),
  secureNote: { type: 0 },
});

describe('personal import capability preflight', () => {
  it('blocks a non-committable inspection before any remote create', async () => {
    const inspection = inspectVaultTransferJson('{ invalid');
    const deps = makeDeps();
    const result = await commitPersonalVaultTransfer({ inspection, capabilities: policy(), deps });

    expect(result.status).toBe('blocked');
    expect(result.capabilityErrors).toContainEqual(expect.objectContaining({ code: 'inspection_not_committable' }));
    expect(deps.createFolder).not.toHaveBeenCalled();
    expect(deps.createItem).not.toHaveBeenCalled();
  });

  it('blocks organization scope without an explicit target', async () => {
    const inspection = inspectVaultTransferJson(JSON.stringify({
      encrypted: false,
      collections: [{ id: 'collection-1', name: 'Team' }],
      items: [{ type: 2, name: 'Runbook', collectionIds: ['collection-1'], secureNote: { type: 0 } }],
    }));
    const deps = makeDeps();
    const result = await commitPersonalVaultTransfer({ inspection, capabilities: policy(), deps });

    expect(result.status).toBe('blocked');
    expect(result.capabilityErrors).toContainEqual(expect.objectContaining({ code: 'organization_target_required' }));
    expect(deps.createFolder).not.toHaveBeenCalled();
    expect(deps.createItem).not.toHaveBeenCalled();
  });

  it('reports every advanced field that the current CipherInput writer cannot preserve', async () => {
    const inspection = inspect([{
      type: 1,
      name: 'Passkey login',
      creationDate: '2025-01-01T00:00:00.000Z',
      passwordHistory: [{ password: 'old-password', lastUsedDate: '2025-01-02T00:00:00.000Z' }],
      login: {
        uris: [],
        fido2Credentials: [{
          credentialId: 'credential', keyType: 'public-key', keyAlgorithm: 'ECDSA', keyCurve: 'P-256',
          keyValue: 'private-key', rpId: 'example.com', counter: '0', discoverable: 'true',
          creationDate: '2025-01-01T00:00:00.000Z',
        }],
      },
    }]);
    const errors = inspectPersonalImportCapabilities(inspection, policy());
    expect(errors.map((error) => error.code)).toEqual(expect.arrayContaining([
      'password_history_unsupported',
      'passkeys_unsupported',
    ]));
    expect(errors.map((error) => error.code)).not.toContain('item_dates_unsupported');
    expect(inspection.diagnostics).toContainEqual(expect.objectContaining({
      severity: 'warning', code: 'server_managed_dates_dropped', sourceIndex: 0,
    }));

    const deps = makeDeps();
    const result = await commitPersonalVaultTransfer({ inspection, capabilities: policy(), deps });
    expect(result.status).toBe('blocked');
    expect(deps.createItem).not.toHaveBeenCalled();
  });

  it('keeps type 5 disabled by default and permits a caller to enable it dynamically', () => {
    const inspection = inspect([{
      type: 5,
      name: 'Deploy key',
      sshKey: { privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:key' },
    }]);
    expect(CIPHER_INPUT_IMPORT_CAPABILITIES.supportedItemTypes).toEqual([1, 2, 3, 4]);
    expect(inspectPersonalImportCapabilities(inspection, policy())).toContainEqual(expect.objectContaining({
      code: 'item_type_unsupported', sourceIndex: 0,
    }));
    expect(inspectPersonalImportCapabilities(
      inspection,
      policy({ supportedItemTypes: [1, 2, 3, 4, 5] }),
    )).toEqual([]);
  });

  it('rejects a forged item whose kind and raw type disagree', async () => {
    const valid = inspect([{
      type: 5,
      name: 'Deploy key',
      sshKey: { privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:key' },
    }]);
    const mismatched = {
      ...valid.ir!.items[0]!,
      rawType: 1,
    } as unknown as VaultTransferItem;
    const inspection: VaultTransferInspection = {
      ...valid,
      ir: { ...valid.ir!, items: [mismatched] },
    };
    const deps = makeDeps();

    expect(inspectPersonalImportCapabilities(
      inspection,
      policy({ supportedItemTypes: [1, 2, 3, 4, 5] }),
    )).toContainEqual(expect.objectContaining({ code: 'item_type_unsupported', sourceIndex: 0 }));
    expect(toPersonalImportItemWrite(mismatched, undefined)).toBeUndefined();
    const result = await commitPersonalVaultTransfer({
      inspection,
      capabilities: policy({ supportedItemTypes: [1, 2, 3, 4, 5] }),
      deps,
    });
    expect(result.status).toBe('blocked');
    expect(deps.createItem).not.toHaveBeenCalled();
  });

  it('blocks linked custom fields on dynamically enabled SSH key items', async () => {
    const inspection = inspect([{
      type: 5,
      name: 'Deploy key',
      fields: [{ type: 3, name: 'linked username', linkedId: 100 }],
      sshKey: { privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:key' },
    }]);
    const capabilities = policy({ supportedItemTypes: [1, 2, 3, 4, 5] });
    const deps = makeDeps();

    expect(inspectPersonalImportCapabilities(inspection, capabilities)).toContainEqual({
      code: 'ssh_linked_fields_unsupported',
      message: 'SSH key items cannot preserve linked custom fields.',
      path: '$.items[0].fields',
      sourceIndex: 0,
    });
    expect(toPersonalImportItemWrite(inspection.ir!.items[0]!, undefined)).toBeUndefined();
    const result = await commitPersonalVaultTransfer({ inspection, capabilities, deps });
    expect(result.status).toBe('blocked');
    expect(deps.createFolder).not.toHaveBeenCalled();
    expect(deps.createItem).not.toHaveBeenCalled();
  });

  it('always blocks deleted timestamps because create APIs cannot preserve them', () => {
    const inspection = inspect([{
      type: 2,
      name: 'Deleted note',
      deletedDate: '2025-01-01T00:00:00.000Z',
      secureNote: { type: 0 },
    }]);
    expect(inspectPersonalImportCapabilities(inspection, policy({ itemDates: true })))
      .toContainEqual(expect.objectContaining({
        code: 'item_dates_unsupported',
        path: '$.items[0].deletedDate',
        sourceIndex: 0,
      }));
  });

  it('allows archivedDate only when the active writer advertises portable date support', () => {
    const inspection = inspect([{
      type: 2,
      name: 'Archived note',
      archivedDate: '2025-01-01T00:00:00.000Z',
      secureNote: { type: 0 },
    }]);
    expect(inspectPersonalImportCapabilities(inspection, policy()))
      .toContainEqual(expect.objectContaining({
        code: 'item_dates_unsupported',
        path: '$.items[0].archivedDate',
        sourceIndex: 0,
      }));
    expect(inspectPersonalImportCapabilities(inspection, policy({ itemDates: true }))).toEqual([]);
  });

  it('blocks password histories above the lossless five-entry limit even when enabled', () => {
    const inspection = inspect([{
      type: 1,
      name: 'Login',
      passwordHistory: Array.from({ length: 6 }, (_, index) => ({ password: `old-${index}` })),
      login: { uris: [] },
    }]);
    expect(inspectPersonalImportCapabilities(inspection, policy({ passwordHistory: true })))
      .toContainEqual(expect.objectContaining({
        code: 'password_history_limit_exceeded',
        path: '$.items[0].passwordHistory',
        sourceIndex: 0,
      }));
  });

  it('accepts exactly five password-history entries without changing their order', () => {
    const entries = Array.from({ length: 5 }, (_, index) => ({
      password: `old-${index}`,
      lastUsedDate: `2025-01-0${index + 1}T00:00:00Z`,
    }));
    const inspection = inspect([{
      type: 1,
      name: 'Login',
      passwordHistory: entries,
      login: { uris: [] },
    }]);
    expect(inspectPersonalImportCapabilities(inspection, policy({ passwordHistory: true }))).toEqual([]);
    expect(toPersonalImportItemWrite(inspection.ir!.items[0]!, undefined)?.passwordHistory)
      .toEqual(entries);
  });

  it('blocks a passkey without a creation timestamp before any create dependency can run', async () => {
    const inspection = inspect([{
      type: 1,
      name: 'Login',
      login: {
        uris: [],
        fido2Credentials: [{
          credentialId: 'credential', keyType: 'public-key', keyAlgorithm: 'ECDSA', keyCurve: 'P-256',
          keyValue: 'private-key', rpId: 'example.com', counter: '0', discoverable: 'true',
        }],
      },
    }]);
    const capabilities = policy({ passkeys: true });
    const deps = makeDeps();

    expect(inspectPersonalImportCapabilities(inspection, capabilities)).toContainEqual(expect.objectContaining({
      code: 'passkeys_unsupported',
      path: '$.items[0].login.fido2Credentials',
      sourceIndex: 0,
    }));
    const result = await commitPersonalVaultTransfer({ inspection, capabilities, deps });
    expect(result.status).toBe('blocked');
    expect(deps.createFolder).not.toHaveBeenCalled();
    expect(deps.createItem).not.toHaveBeenCalled();
  });

  it.each([
    ['archivedDate', { archivedDate: '2025-01-01T01:00:00+01:00' }],
    ['passwordHistory.lastUsedDate', { passwordHistory: [{ password: 'old', lastUsedDate: '2025-01-01T01:00:00+01:00' }] }],
    ['login.passwordRevisionDate', { login: { uris: [], passwordRevisionDate: '2025-01-01T01:00:00+01:00' } }],
    ['login.fido2Credentials.creationDate', { login: { uris: [], fido2Credentials: [{
      credentialId: 'credential', keyType: 'public-key', keyAlgorithm: 'ECDSA', keyCurve: 'P-256',
      keyValue: 'private-key', rpId: 'example.com', counter: '0', discoverable: 'true',
      creationDate: '2025-01-01T01:00:00+01:00',
    }] } }],
  ])('rejects non-UTC portable timestamp %s during inspection', (_label, advanced) => {
    const inspection = inspectVaultTransferJson(json([{
      type: 1,
      name: 'Login',
      login: { uris: [] },
      ...advanced,
    }]));
    expect(inspection.canCommit).toBe(false);
    expect(inspection.diagnostics).toContainEqual(expect.objectContaining({
      severity: 'error',
      code: 'invalid_shape',
      sourceIndex: 0,
    }));
  });

  it('blocks an autofill override only when the active writer denies that capability', () => {
    const inspection = inspect([{
      type: 1,
      name: 'Login',
      login: { autofillOnPageLoad: false, uris: [] },
    }]);
    expect(inspectPersonalImportCapabilities(inspection, policy())).toEqual([]);
    expect(inspectPersonalImportCapabilities(
      inspection,
      policy({ autofillOnPageLoad: false }),
    )).toContainEqual(expect.objectContaining({
      code: 'autofill_on_page_load_unsupported',
      path: '$.items[0].login.autofillOnPageLoad',
    }));
  });
});

describe('personal import commit ordering and conversion', () => {
  it('creates folders serially before items and maps complete type 1-4 write models', async () => {
    const inspection = inspect([
      {
        type: 1,
        name: 'GitHub',
        folderId: 'folder-a',
        favorite: true,
        reprompt: 1,
        notes: 'work login',
        fields: [
          { type: 0, name: 'environment', value: 'production' },
          { type: 3, name: 'linked user', value: null, linkedId: 100 },
        ],
        login: {
          username: 'octocat', password: 'secret', totp: 'TOTP',
          autofillOnPageLoad: false,
          passwordRevisionDate: '2025-01-02T03:04:05.1234567Z',
          uris: [{ uri: 'https://github.com', match: 0 }],
        },
      },
      note('Runbook'),
      { type: 3, name: 'Visa', folderId: 'folder-b', card: { brand: 'Visa', number: '4111', code: '123' } },
      { type: 4, name: 'Me', identity: { firstName: 'Ada', lastName: 'Lovelace', email: 'ada@example.com' } },
    ], [
      { id: 'folder-a', name: 'Work' },
      { id: 'folder-b', name: 'Finance' },
    ]);
    const order: string[] = [];
    const writes: PersonalImportItemWrite[] = [];
    const deps = makeDeps({
      createFolder: vi.fn(async (folder) => {
        order.push(`folder:${folder.sourceId}`);
        return { status: 'committed', value: { id: `mapped-${folder.sourceId}` } } as const;
      }),
      createItem: vi.fn(async (item) => {
        order.push(`item:${item.sourceIndex}`);
        writes.push(item);
        return { status: 'committed', value: { id: `item-${item.sourceIndex}` } } as const;
      }),
    });

    const result = await commitPersonalVaultTransfer({ inspection, capabilities: policy(), deps });
    expect(result.status).toBe('completed');
    expect(result.mustSyncBeforeRetry).toBe(false);
    expect(order).toEqual(['folder:folder-a', 'folder:folder-b', 'item:0', 'item:1', 'item:2', 'item:3']);
    expect(writes[0]).toMatchObject({
      sourceIndex: 0,
      cipher: {
        type: 1,
        name: 'GitHub',
        folderId: 'mapped-folder-a',
        favorite: true,
        reprompt: true,
        notes: 'work login',
        fields: [
          { type: 0, name: 'environment', value: 'production' },
          { type: 3, name: 'linked user', linkedId: 100 },
        ],
        login: {
          username: 'octocat', password: 'secret', totp: 'TOTP',
          autofillOnPageLoad: false,
          passwordRevisionDate: '2025-01-02T03:04:05.1234567Z',
          uris: [{ uri: 'https://github.com', match: 0 }],
        },
      },
    });
    expect(writes[1]).toMatchObject({ cipher: { type: 2 }, secureNoteType: 0 });
    expect(writes[2]).toMatchObject({ cipher: { type: 3, folderId: 'mapped-folder-b', card: { brand: 'Visa', number: '4111', code: '123' } } });
    expect(writes[3]).toMatchObject({ cipher: { type: 4, identity: { firstName: 'Ada', lastName: 'Lovelace' } } });
    expect(result.folderOutcomes.map((outcome) => outcome.sourceIndex)).toEqual([0, 1]);
    expect(result.itemOutcomes.map((outcome) => outcome.sourceIndex)).toEqual([0, 1, 2, 3]);
  });

  it('passes supported advanced metadata while dropping server-managed item dates', async () => {
    const inspection = inspect([{
      type: 1,
      name: 'Passkey login',
      creationDate: '2025-01-01T00:00:00.000Z',
      revisionDate: '2025-02-01T00:00:00.000Z',
      deletedDate: null,
      archivedDate: '2025-03-01T00:00:00.000Z',
      passwordHistory: [{ password: 'old-password', lastUsedDate: null }],
      login: {
        autofillOnPageLoad: null,
        passwordRevisionDate: '2025-01-15T00:00:00.000Z',
        uris: [],
        fido2Credentials: [{
          credentialId: 'credential', keyType: 'public-key', keyAlgorithm: 'ECDSA', keyCurve: 'P-256',
          keyValue: 'private-key', rpId: 'example.com', counter: '0', discoverable: 'true',
          creationDate: '2025-01-01T00:00:00.000Z',
        }],
      },
    }]);
    const writes: PersonalImportItemWrite[] = [];
    const deps = makeDeps({
      createItem: vi.fn(async (item) => {
        writes.push(item);
        return { status: 'committed', value: { id: 'created' } } as const;
      }),
    });
    const capabilities = policy({ passwordHistory: true, passkeys: true, itemDates: true });
    const result = await commitPersonalVaultTransfer({ inspection, capabilities, deps });

    expect(result.status).toBe('completed');
    expect(writes[0]).toMatchObject({
      passwordHistory: [{ password: 'old-password', lastUsedDate: null }],
      fido2Credentials: [{ credentialId: 'credential', keyValue: 'private-key', rpId: 'example.com' }],
      dates: { archivedDate: '2025-03-01T00:00:00.000Z' },
      cipher: { login: { autofillOnPageLoad: null, passwordRevisionDate: '2025-01-15T00:00:00.000Z' } },
    });
    expect(capabilities.itemDates).toBe(true);
    expect(JSON.stringify(writes[0])).not.toContain('unknownFieldPaths');
    expect(JSON.stringify(writes[0])).not.toContain('"raw"');
  });

  it('maps a dynamically enabled type 5 item to a complete SSH writer payload', async () => {
    const inspection = inspect([{
      type: 5,
      name: 'Production deploy key',
      folderId: 'folder-a',
      favorite: true,
      reprompt: 1,
      notes: 'Rotate quarterly',
      fields: [{ type: 0, name: 'environment', value: 'production' }],
      sshKey: {
        privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE\n-----END OPENSSH PRIVATE KEY-----',
        publicKey: 'ssh-ed25519 AAAATEST deploy@example.com',
        keyFingerprint: 'SHA256:deploy-key',
      },
    }], [{ id: 'folder-a', name: 'Infrastructure' }]);
    const writes: PersonalImportItemWrite[] = [];
    const deps = makeDeps({
      createItem: vi.fn(async (write) => {
        writes.push(write);
        return { status: 'committed', value: { id: 'ssh-created' } } as const;
      }),
    });

    const result = await commitPersonalVaultTransfer({
      inspection,
      capabilities: policy({ supportedItemTypes: [1, 2, 3, 4, 5] }),
      deps,
    });

    expect(result.status).toBe('completed');
    expect(writes).toEqual([{
      sourceIndex: 0,
      cipher: {
        type: 5,
        name: 'Production deploy key',
        favorite: true,
        reprompt: true,
        notes: 'Rotate quarterly',
        folderId: 'new-folder-a',
        fields: [{ type: 0, name: 'environment', value: 'production' }],
        sshKey: {
          privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE\n-----END OPENSSH PRIVATE KEY-----',
          publicKey: 'ssh-ed25519 AAAATEST deploy@example.com',
          keyFingerprint: 'SHA256:deploy-key',
        },
      },
    }]);
    expect(result.itemOutcomes).toEqual([
      expect.objectContaining({ rawType: 5, status: 'committed', createdId: 'ssh-created' }),
    ]);
  });

  it('rejects an incomplete type 5 payload at the pure conversion boundary', () => {
    const inspection = inspect([{
      type: 5,
      name: 'Deploy key',
      sshKey: { privateKey: 'PRIVATE', publicKey: 'PUBLIC', keyFingerprint: 'SHA256:key' },
    }]);
    const item = inspection.ir!.items[0]!;
    expect(item.kind).toBe('sshKey');
    if (item.kind !== 'sshKey') throw new Error('Expected an SSH transfer item');
    const incomplete = {
      ...item,
      payload: {
        ...item.payload,
        values: { ...item.payload.values, publicKey: null },
      },
    } as VaultTransferItem;

    expect(toPersonalImportItemWrite(incomplete, undefined)).toBeUndefined();
  });
});

describe('personal import classified outcomes', () => {
  it('continues after rejected folders and explicitly skips only their dependent items', async () => {
    const inspection = inspect([
      note('Blocked child', 'folder-a'),
      note('Mapped child', 'folder-b'),
      note('Root item'),
    ], [
      { id: 'folder-a', name: 'Rejected' },
      { id: 'folder-b', name: 'Accepted' },
    ]);
    const writes: PersonalImportItemWrite[] = [];
    const deps = makeDeps({
      createFolder: vi.fn(async (folder) => folder.sourceId === 'folder-a'
        ? { status: 'rejected', failure: { code: 'forbidden', message: 'Folder rejected.' } } as const
        : { status: 'committed', value: { id: 'new-folder-b' } } as const),
      createItem: vi.fn(async (item) => {
        writes.push(item);
        return { status: 'committed', value: { id: `item-${item.sourceIndex}` } } as const;
      }),
    });

    const result = await commitPersonalVaultTransfer({ inspection, capabilities: policy(), deps });
    expect(result.status).toBe('partial');
    expect(result.mustSyncBeforeRetry).toBe(true);
    expect(result.itemOutcomes).toEqual([
      expect.objectContaining({ sourceIndex: 0, status: 'skipped', reason: 'folder_rejected', folderSourceId: 'folder-a' }),
      expect.objectContaining({ sourceIndex: 1, status: 'committed' }),
      expect.objectContaining({ sourceIndex: 2, status: 'committed' }),
    ]);
    expect(writes).toHaveLength(2);
    expect(writes[0]!.cipher.folderId).toBe('new-folder-b');
    expect(writes[1]!.cipher.folderId).toBeUndefined();
  });

  it('records an item rejection and continues without retrying it', async () => {
    const inspection = inspect([note('A'), note('B'), note('C')]);
    const attempts: number[] = [];
    const deps = makeDeps({
      createItem: vi.fn(async (item) => {
        attempts.push(item.sourceIndex);
        return item.sourceIndex === 1
          ? { status: 'rejected', failure: { code: 'invalid', message: 'Item rejected.' } } as const
          : { status: 'committed', value: { id: `item-${item.sourceIndex}` } } as const;
      }),
    });

    const result = await commitPersonalVaultTransfer({ inspection, capabilities: policy(), deps });
    expect(attempts).toEqual([0, 1, 2]);
    expect(result.itemOutcomes.map((outcome) => outcome.status)).toEqual(['committed', 'rejected', 'committed']);
    expect(result.status).toBe('partial');
    expect(result.mustSyncBeforeRetry).toBe(true);
    expect(deps.markDirty).not.toHaveBeenCalled();
    expect(deps.forceReconcile).not.toHaveBeenCalled();
  });

  it('stops immediately after an unknown item outcome, marks dirty, and forces reconciliation', async () => {
    const inspection = inspect([note('A'), note('B'), note('C')]);
    const order: string[] = [];
    const deps = makeDeps({
      createItem: vi.fn(async (item) => {
        order.push(`item:${item.sourceIndex}`);
        return item.sourceIndex === 1
          ? { status: 'outcome_unknown', failure: { code: 'timeout', message: 'Remote result is unknown.' } } as const
          : { status: 'committed', value: { id: `item-${item.sourceIndex}` } } as const;
      }),
      markDirty: vi.fn(async () => { order.push('dirty'); }),
      forceReconcile: vi.fn(async () => { order.push('reconcile'); }),
    });

    const result = await commitPersonalVaultTransfer({ inspection, capabilities: policy(), deps });
    expect(order).toEqual(['item:0', 'item:1', 'dirty', 'reconcile']);
    expect(result.status).toBe('outcome_unknown');
    expect(result.mustSyncBeforeRetry).toBe(true);
    expect(result.dirtyMarked).toBe(true);
    expect(result.forceReconcileAttempted).toBe(true);
    expect(result.forceReconcileSucceeded).toBe(true);
    expect(result.itemOutcomes).toEqual([
      expect.objectContaining({ sourceIndex: 0, status: 'committed' }),
      expect.objectContaining({ sourceIndex: 1, status: 'outcome_unknown' }),
      expect.objectContaining({ sourceIndex: 2, status: 'skipped', reason: 'stopped_after_unknown_outcome' }),
    ]);
    expect(deps.createItem).toHaveBeenCalledTimes(2);
  });

  it('treats an unclassified thrown create as outcome_unknown and never attempts later folders or items', async () => {
    const inspection = inspect([note('Child', 'folder-a')], [
      { id: 'folder-a', name: 'A' },
      { id: 'folder-b', name: 'B' },
    ]);
    const deps = makeDeps({
      createFolder: vi.fn(async () => { throw new Error('transport failed'); }),
    });

    const result = await commitPersonalVaultTransfer({ inspection, capabilities: policy(), deps });
    expect(result.status).toBe('outcome_unknown');
    expect(result.folderOutcomes).toEqual([
      expect.objectContaining({ sourceIndex: 0, status: 'outcome_unknown', failure: { code: 'unclassified_remote_exception', message: expect.any(String) } }),
      expect.objectContaining({ sourceIndex: 1, status: 'skipped' }),
    ]);
    expect(result.itemOutcomes).toEqual([
      expect.objectContaining({ sourceIndex: 0, status: 'skipped', reason: 'stopped_after_unknown_outcome' }),
    ]);
    expect(deps.createFolder).toHaveBeenCalledTimes(1);
    expect(deps.createItem).not.toHaveBeenCalled();
    expect(deps.markDirty).toHaveBeenCalledWith('import_outcome_unknown');
    expect(deps.forceReconcile).toHaveBeenCalledTimes(1);
  });

  it('still attempts reconciliation when marking dirty fails and reports reconciliation failure', async () => {
    const inspection = inspect([note('A')]);
    const deps = makeDeps({
      createItem: vi.fn(async () => ({
        status: 'outcome_unknown', failure: { code: 'timeout', message: 'Unknown.' },
      } as const)),
      markDirty: vi.fn(async () => { throw new Error('storage unavailable'); }),
      forceReconcile: vi.fn(async () => { throw new Error('sync unavailable'); }),
    });
    const result = await commitPersonalVaultTransfer({ inspection, capabilities: policy(), deps });
    expect(result.status).toBe('outcome_unknown');
    expect(result.dirtyMarked).toBe(false);
    expect(result.forceReconcileAttempted).toBe(true);
    expect(result.forceReconcileSucceeded).toBe(false);
    expect(deps.forceReconcile).toHaveBeenCalledTimes(1);
  });
});

describe('sanitized personal import preview adapter', () => {
  beforeEach(() => setLocale('en', false));

  it('maps safe counts and capability readiness without carrying IR payloads', () => {
    const inspection = inspect([note('A')], [{ id: 'folder-a', name: 'Folder' }]);
    const preview = toSanitizedImportPreview(inspection, policy(), {
      format: 'bitwarden-zip',
      attachmentCount: 3,
    });
    expect(preview).toMatchObject({
      format: 'bitwarden-zip',
      scope: 'personal',
      counts: { folders: 1, items: 1, attachments: 3 },
      canCommit: true,
    });
    expect(JSON.stringify(preview)).not.toContain('secureNote');
    expect(JSON.stringify(preview)).not.toContain('Folder');
  });

  it('turns unsupported advanced data into a blocking, secret-free preview diagnostic', () => {
    const secret = 'SUPER-SECRET-HISTORY';
    const inspection = inspect([{
      type: 1,
      name: 'Login',
      passwordHistory: [{ password: secret }],
      login: { uris: [] },
    }]);
    const preview = toSanitizedImportPreview(inspection, policy());
    expect(preview.canCommit).toBe(false);
    expect(preview.diagnostics.unsupported).toContainEqual(expect.objectContaining({
      code: 'password_history_unsupported',
      sourceIndex: 0,
      path: '$.items[0].passwordHistory',
    }));
    expect(JSON.stringify(preview)).not.toContain(secret);
    expect(JSON.stringify(preview)).not.toContain('Login');
  });

  it('does not trust diagnostic messages, codes, or unknown path segments from the input object', () => {
    const inspection = inspect([note('A')]);
    const poisoned: VaultTransferInspection = {
      ...inspection,
      canCommit: false,
      diagnostics: [{
        severity: 'error',
        code: 'BAD CODE SECRET',
        message: 'MASTER-PASSWORD-SECRET',
        path: '$.items[0].passwordNamedAfterSecret',
        sourceKind: 'item',
        sourceIndex: 0,
      }],
    };
    const preview = toSanitizedImportPreview(poisoned, policy());
    const serialized = JSON.stringify(preview);
    expect(serialized).not.toContain('MASTER-PASSWORD-SECRET');
    expect(serialized).not.toContain('passwordNamedAfterSecret');
    expect(preview.diagnostics.errors[0]).toMatchObject({
      code: 'transfer_diagnostic',
      path: '$.items[0].[unknown]',
      sourceIndex: 0,
    });
  });

  it('marks organization and previous unknown outcomes as non-committable', () => {
    const organization = inspectVaultTransferJson(JSON.stringify({
      encrypted: false,
      collections: [],
      items: [],
    }));
    const orgPreview = toSanitizedImportPreview(organization, policy());
    expect(orgPreview.scope).toBe('organization');
    expect(orgPreview.organizationTargetRequired).toBe(true);
    expect(orgPreview.canCommit).toBe(false);

    const personal = toSanitizedImportPreview(inspect([], []), policy(), { hasUnknownOutcome: true });
    expect(personal.hasUnknownOutcome).toBe(true);
    expect(personal.canCommit).toBe(false);
  });

  it('bounds diagnostic arrays before handing them to the component', () => {
    const inspection = inspect([]);
    const noisy: VaultTransferInspection = {
      ...inspection,
      diagnostics: Array.from({ length: 40 }, (_, sourceIndex) => ({
        severity: 'warning' as const,
        code: 'csv_format_is_lossy',
        message: `untrusted ${sourceIndex}`,
        sourceKind: 'row' as const,
        sourceIndex,
      })),
    };
    const preview = toSanitizedImportPreview(noisy, policy());
    expect(preview.diagnostics.warnings).toHaveLength(32);
    expect(preview.diagnostics.warnings.at(-1)).toMatchObject({ code: 'diagnostics_omitted' });
    expect(JSON.stringify(preview)).not.toContain('untrusted');
  });
});
