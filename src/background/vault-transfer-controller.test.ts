import { describe, expect, it, vi } from 'vitest';
import type { KeyValueStore } from '../platform/store.js';
import {
  CIPHER_INPUT_IMPORT_CAPABILITIES,
  type PersonalImportCapabilityPolicy,
} from '../core/vault/vault-transfer-commit.js';
import {
  VAULT_TRANSFER_JOURNAL_STORE_KEY,
  VaultTransferJournalStore,
  digestVaultTransferAccountIdentity,
  type VaultTransferJournalStoreOptions,
} from '../core/vault/vault-transfer-journal.js';
import { VaultTransferSessionManager } from '../core/vault/vault-transfer-session.js';
import {
  inspectVaultTransferSource,
  type InspectVaultTransferSourceOptions,
  type VaultTransferSourceOk,
  type VaultTransferSourceResult,
} from '../core/vault/vault-transfer-source.js';
import { inspectVaultTransferJson } from '../core/vault/vault-transfer.js';
import type { VaultTransferExportTarget } from '../core/vault/vault-transfer-target.js';
import {
  VaultTransferController,
  type BeginVaultTransferImportInput,
  type BuiltVaultTransferExport,
  type VaultTransferImportCommitInput,
  type VaultTransferReconcileInput,
} from './vault-transfer-controller.js';

const encoder = new TextEncoder();
const CANONICAL_ACCOUNT = 'https://vault.example/\0user@example.com';
const EXPORT_AUTHORIZATION_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ORGANIZATION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const OTHER_ORGANIZATION_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

interface LeaseState {
  account: number;
  session: number;
  policy: number;
  identity: number;
  transfer: number;
  reconcile: number;
  canonicalIdentity: string;
}

type ExportAuthorization = true | {
  readonly account: number;
  readonly session: number;
  readonly target?: VaultTransferExportTarget;
};
type Controller = VaultTransferController<number, number, number, number, number, number, ExportAuthorization>;
const startupPromises = new WeakMap<Controller, Promise<void>>();

interface FixtureOptions {
  readonly inspectSource?: (
    source: Uint8Array,
    options?: InspectVaultTransferSourceOptions,
    authority?: import('./vault-transfer-controller.js').VaultTransferInspectAuthority<number, number>,
  ) => Promise<VaultTransferSourceResult>;
  readonly getCapabilities?: () => PersonalImportCapabilityPolicy | Promise<PersonalImportCapabilityPolicy>;
  readonly validateImportSource?: (
    source: VaultTransferSourceOk,
    capabilities: PersonalImportCapabilityPolicy,
  ) => boolean | Promise<boolean>;
  readonly commitImport?: (input: VaultTransferImportCommitInput) => void | Promise<void>;
  readonly buildExport?: (
    format: 'json' | 'encrypted-json' | 'csv' | 'zip',
    filePassword: string | undefined,
    authorization: ExportAuthorization,
    target: VaultTransferExportTarget,
  ) => BuiltVaultTransferExport | Promise<BuiltVaultTransferExport>;
  readonly redeemExportAuthorization?: (input: {
    readonly authorizationId: string;
    readonly format: 'json' | 'encrypted-json' | 'csv' | 'zip';
    readonly encryptionType?: 'account' | 'file';
    readonly target: VaultTransferExportTarget;
  }) => ExportAuthorization | undefined;
  readonly reconcile?: (input: VaultTransferReconcileInput) => void | Promise<void>;
  readonly exportChunkBytes?: number;
  readonly ttlMs?: number;
  readonly confirmedAccessDeadlineMs?: number;
  readonly journalOptions?: VaultTransferJournalStoreOptions;
}

interface Fixture {
  readonly controller: Controller;
  readonly sessions: VaultTransferSessionManager<number, number, number>;
  readonly journal: VaultTransferJournalStore;
  readonly leases: LeaseState;
  readonly values: Map<string, unknown>;
  readonly setNow: (value: number) => void;
}

function createFixture(options: FixtureOptions = {}): Fixture {
  let now = 1_000;
  const leases: LeaseState = {
    account: 1,
    session: 1,
    policy: 1,
    identity: 1,
    transfer: 1,
    reconcile: 1,
    canonicalIdentity: CANONICAL_ACCOUNT,
  };
  const values = new Map<string, unknown>();
  const store: KeyValueStore = {
    async get<T>(key: string): Promise<T | undefined> {
      const value = values.get(key);
      return value === undefined ? undefined : structuredClone(value) as T;
    },
    async set(key: string, value: unknown): Promise<void> {
      values.set(key, structuredClone(value));
    },
    async remove(key: string): Promise<void> {
      values.delete(key);
    },
    async clear(): Promise<void> {
      values.clear();
    },
  };
  const sessions = new VaultTransferSessionManager<number, number, number>({
    captureLeases: () => ({
      account: leases.account,
      session: leases.session,
      enterprisePolicy: leases.policy,
    }),
    assertLeasesCurrent: (captured) => captured.account === leases.account
      && captured.session === leases.session
      && captured.enterprisePolicy === leases.policy,
    now: () => now,
    ttlMs: options.ttlMs ?? 10_000,
    confirmedAccessDeadlineMs: options.confirmedAccessDeadlineMs ?? 30_000,
    maxTotalBytes: 1024 * 1024,
    maxChunkBytes: 64 * 1024,
    maxResidentBytes: 2 * 1024 * 1024,
  });
  const journal = new VaultTransferJournalStore(store, {
    now: () => now,
    ...options.journalOptions,
  });
  const controller = new VaultTransferController({
    sessions,
    journal,
    getImportCapabilities: options.getCapabilities ?? (() => CIPHER_INPUT_IMPORT_CAPABILITIES),
    ...(options.validateImportSource === undefined
      ? {}
      : { validateImportSource: options.validateImportSource }),
    captureAccountIdentity: () => ({
      canonicalIdentity: leases.canonicalIdentity,
      lease: leases.identity,
    }),
    assertAccountIdentityCurrent: (snapshot) => snapshot.lease === leases.identity
      && snapshot.canonicalIdentity === leases.canonicalIdentity,
    captureTransferLeases: () => leases.transfer,
    assertTransferLeasesCurrent: (captured) => captured === leases.transfer,
    captureReconcileLeases: () => leases.reconcile,
    assertReconcileLeasesCurrent: (captured) => captured === leases.reconcile,
    ...(options.inspectSource === undefined ? {} : { inspectSource: options.inspectSource }),
    ...(options.commitImport === undefined ? {} : { commitImport: options.commitImport }),
    ...(options.buildExport === undefined ? {} : { buildExport: options.buildExport }),
    redeemExportAuthorization: options.redeemExportAuthorization ?? (() => true as const),
    ...(options.reconcile === undefined ? {} : { reconcileCurrentAccount: options.reconcile }),
    ...(options.exportChunkBytes === undefined ? {} : { exportChunkBytes: options.exportChunkBytes }),
    now: () => now,
  });
  return {
    controller,
    sessions,
    journal,
    leases,
    values,
    setNow(value: number) {
      now = value;
    },
  };
}

function personalJson(items: unknown[] = [{
  type: 2,
  name: 'PRIVATE ITEM NAME',
  notes: 'PRIVATE ITEM VALUE',
  secureNote: { type: 0 },
}]): Uint8Array {
  return encoder.encode(JSON.stringify({ encrypted: false, folders: [], items }));
}

async function upload(
  controller: Controller,
  bytes = personalJson(),
  input: BeginVaultTransferImportInput = {},
  password?: string,
) {
  await ensureStartup(controller);
  const begun = controller.beginImport({ expectedTotalBytes: bytes.byteLength, ...input });
  const ack = controller.appendImportChunk(begun.transferId, 0, bytes);
  controller.acknowledgeImportChunk(begun.transferId, ack.sequence);
  const inspected = await controller.sealAndInspectImport(begun.transferId, password);
  return { begun, inspected };
}

function ensureStartup(controller: Controller): Promise<void> {
  const existing = startupPromises.get(controller);
  if (existing) return existing;
  const started = controller.inspectJournalForStartup().then(() => undefined);
  startupPromises.set(controller, started);
  return started;
}

function protectedSourceResult(password: string): (
  source: Uint8Array,
  options?: InspectVaultTransferSourceOptions,
) => Promise<VaultTransferSourceResult> {
  const inspection = inspectVaultTransferJson(JSON.stringify({
    encrypted: false,
    folders: [],
    items: [{ type: 2, name: 'Decrypted', secureNote: { type: 0 } }],
  }));
  return async (_source, options) => {
    if (options?.password === undefined) {
      return { status: 'password_required', format: 'encrypted-json' };
    }
    if (options.password !== password) return { status: 'failed', code: 'decryption_failed' };
    return {
      status: 'ok',
      format: 'encrypted-json',
      inspection,
      attachmentCount: 0,
      attachments: [],
      skippedAttachmentCount: 0,
    };
  };
}

async function confirmUploaded(controller: Controller, input: BeginVaultTransferImportInput = {}) {
  const uploaded = await upload(controller, personalJson(), input);
  const confirmation = controller.confirmImport(
    uploaded.begun.transferId,
    uploaded.inspected.previewCapability,
  );
  return { ...uploaded, confirmation };
}

async function commitEverySource({ source, journal }: VaultTransferImportCommitInput): Promise<void> {
  const ir = source.inspection.ir;
  if (!ir) throw new Error('expected import IR');
  for (const folder of ir.folders) {
    const marked = await journal.markInFlight('folder', folder.sourceIndex);
    await journal.settleInFlight({ operationId: marked.operationId, status: 'committed' });
  }
  for (const item of ir.items) {
    const marked = await journal.markInFlight('item', item.sourceIndex);
    await journal.settleInFlight({ operationId: marked.operationId, status: 'committed' });
  }
}

describe('VaultTransferController import lifecycle', () => {
  it('fails closed until startup journal inspection has completed', async () => {
    const fixture = createFixture({ commitImport: commitEverySource });
    expect(() => fixture.controller.beginImport()).toThrowError(expect.objectContaining({
      code: 'invalid_state',
    }));

    await ensureStartup(fixture.controller);
    expect(() => fixture.controller.beginImport()).not.toThrow();
  });

  it('captures account and transfer authority before invoking a key-aware inspector', async () => {
    const authorities: Array<import('./vault-transfer-controller.js').VaultTransferInspectAuthority<number, number>> = [];
    const fixture = createFixture({
      inspectSource: async (source, options, authority) => {
        expect(authority).toBeDefined();
        await authority!.assertCurrent();
        authorities.push(authority!);
        return inspectVaultTransferSource(source, options);
      },
    });

    const { begun } = await upload(fixture.controller);
    expect(authorities).toHaveLength(1);
    expect(authorities[0]).toMatchObject({
      account: { canonicalIdentity: CANONICAL_ACCOUNT, lease: fixture.leases.identity },
      transferLeases: fixture.leases.transfer,
    });
    await fixture.controller.cancel(begun.transferId);
  });

  it('replays account-encrypted inspection under the same authority before any commit', async () => {
    const authorities: Array<import('./vault-transfer-controller.js').VaultTransferInspectAuthority<number, number>> = [];
    const fixture = createFixture({
      inspectSource: async (source, _options, authority) => {
        await authority!.assertCurrent();
        authorities.push(authority!);
        return {
          status: 'ok',
          format: 'encrypted-json',
          inspection: inspectVaultTransferJson(new TextDecoder().decode(source)),
          attachmentCount: 0,
          attachments: [],
          skippedAttachmentCount: 0,
        };
      },
      commitImport: commitEverySource,
    });

    const { begun, inspected } = await confirmUploaded(fixture.controller);
    expect(inspected.sourceFormat).toBe('encrypted-json');
    await expect(fixture.controller.commitConfirmedImport(begun.transferId)).resolves.toMatchObject({
      status: 'completed',
    });
    expect(authorities).toHaveLength(2);
    expect(authorities.map((authority) => ({
      account: authority.account,
      transferLeases: authority.transferLeases,
    }))).toEqual([
      { account: authorities[0]!.account, transferLeases: fixture.leases.transfer },
      { account: authorities[0]!.account, transferLeases: fixture.leases.transfer },
    ]);
  });

  it('returns only a value-free preview, hides confirmation ids, and journals before remote writes', async () => {
    const commitImport = vi.fn(async ({ source, journal }: VaultTransferImportCommitInput) => {
      const item = source.inspection.ir?.items[0];
      expect(item?.name).toBe('PRIVATE ITEM NAME');
      const marked = await journal.markInFlight('item', item?.sourceIndex ?? 0);
      await journal.settleInFlight({ operationId: marked.operationId, status: 'committed' });
    });
    const fixture = createFixture({ commitImport });
    const beginSpy = vi.spyOn(fixture.journal, 'begin');

    const { begun, inspected, confirmation } = await confirmUploaded(fixture.controller);
    expect(inspected.preview).toMatchObject({
      format: 'bitwarden-json',
      scope: 'personal',
      counts: { folders: 0, collections: 0, items: 1, attachments: 0 },
      canCommit: true,
    });
    expect(inspected.sourceFormat).toBe('json');
    expect(JSON.stringify(inspected.preview)).not.toMatch(/PRIVATE ITEM/);
    expect(confirmation).toEqual({ transferId: begun.transferId, status: 'confirmed' });
    expect(confirmation).not.toHaveProperty('confirmationId');

    await expect(fixture.controller.commitConfirmedImport(begun.transferId)).resolves.toEqual({
      transferId: begun.transferId,
      status: 'completed',
      counts: { committed: 1, rejected: 0, skipped: 0, outcomeUnknown: 0 },
      requiresReconcile: false,
    });
    expect(commitImport).toHaveBeenCalledOnce();
    expect(beginSpy.mock.invocationCallOrder[0]).toBeLessThan(commitImport.mock.invocationCallOrder[0]!);
    expect(beginSpy.mock.calls[0]?.[1]).toEqual([{ kind: 'item', sourceIndex: 0 }]);
    const accountDigest = await digestVaultTransferAccountIdentity(CANONICAL_ACCOUNT);
    await expect(fixture.journal.getSummary(begun.transferId, accountDigest)).resolves.toMatchObject({
      phase: 'completed',
      replayBarrier: true,
      outcomeCount: 1,
      itemMappingCount: 1,
    });
    await expect(fixture.controller.acknowledgeImportResult(begun.transferId)).resolves.toBeUndefined();
    await expect(fixture.journal.getSummary(begun.transferId, accountDigest)).resolves.toMatchObject({
      resultDeliveredAt: expect.any(Number),
      replayBarrier: false,
    });
    expect(fixture.sessions.residentBytes).toBe(0);
  });

  it('blocks confirmation when worker-only advanced data validation fails', async () => {
    const validateImportSource = vi.fn(async () => false);
    const fixture = createFixture({ validateImportSource });
    const { begun, inspected } = await upload(fixture.controller);

    expect(validateImportSource).toHaveBeenCalledOnce();
    expect(inspected.preview.canCommit).toBe(false);
    expect(inspected.preview.diagnostics.unsupported).toContainEqual({
      category: 'unsupported',
      code: 'unsupported_known_data',
    });
    expect(() => fixture.controller.confirmImport(
      begun.transferId,
      inspected.previewCapability,
    )).toThrowError(expect.objectContaining({ code: 'preview_blocked' }));
  });

  it('consumes a bad preview capability and cannot be repaired by replaying the real one', async () => {
    const fixture = createFixture({ commitImport: () => undefined });
    const { begun, inspected } = await upload(fixture.controller);

    expect(() => fixture.controller.confirmImport(
      begun.transferId,
      'ffffffff-ffff-4fff-8fff-ffffffffffff',
    )).toThrowError(expect.objectContaining({ code: 'preview_mismatch' }));
    expect(() => fixture.controller.confirmImport(
      begun.transferId,
      inspected.previewCapability,
    )).toThrowError(expect.objectContaining({ code: 'not_found' }));
    expect(fixture.sessions.residentBytes).toBe(0);
  });

  it('reparses after confirmation and rejects a changed preview fingerprint before journaling', async () => {
    let capabilityRead = 0;
    const commitImport = vi.fn();
    const fixture = createFixture({
      commitImport,
      getCapabilities: () => {
        capabilityRead += 1;
        return capabilityRead === 1
          ? CIPHER_INPUT_IMPORT_CAPABILITIES
          : { ...CIPHER_INPUT_IMPORT_CAPABILITIES, supportedItemTypes: [] };
      },
    });
    const { begun } = await confirmUploaded(fixture.controller);

    await expect(fixture.controller.commitConfirmedImport(begun.transferId)).rejects.toMatchObject({
      code: 'preview_mismatch',
      message: 'preview_mismatch',
    });
    expect(commitImport).not.toHaveBeenCalled();
    expect(fixture.values.has(VAULT_TRANSFER_JOURNAL_STORE_KEY)).toBe(false);
    expect(fixture.sessions.residentBytes).toBe(0);
  });

  it('rechecks explicit preview-bound transfer leases after confirmed parsing and before WAL', async () => {
    let inspectionCount = 0;
    let release!: () => void;
    let entered!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const inspectSource = async (
      source: Uint8Array,
      options?: InspectVaultTransferSourceOptions,
    ): Promise<VaultTransferSourceResult> => {
      inspectionCount += 1;
      if (inspectionCount === 2) {
        entered();
        await gate;
      }
      return inspectVaultTransferSource(source, options);
    };
    const commitImport = vi.fn();
    const fixture = createFixture({ inspectSource, commitImport });
    const { begun } = await confirmUploaded(fixture.controller);
    const committing = fixture.controller.commitConfirmedImport(begun.transferId);
    await started;

    fixture.leases.transfer += 1;
    release();

    await expect(committing).rejects.toMatchObject({ code: 'lease_changed' });
    expect(commitImport).not.toHaveBeenCalled();
    expect(fixture.values.has(VAULT_TRANSFER_JOURNAL_STORE_KEY)).toBe(false);
  });

  it('rejects A-to-B-to-A lease ABA while an authoritative preview is pending', async () => {
    let release!: () => void;
    let entered!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const inspectSource = vi.fn(async (
      source: Uint8Array,
      options?: InspectVaultTransferSourceOptions,
    ): Promise<VaultTransferSourceResult> => {
      entered();
      await gate;
      return inspectVaultTransferSource(source, options);
    });
    const fixture = createFixture({ inspectSource, commitImport: () => undefined });
    await ensureStartup(fixture.controller);
    const bytes = personalJson();
    const begun = fixture.controller.beginImport({ expectedTotalBytes: bytes.byteLength });
    const ack = fixture.controller.appendImportChunk(begun.transferId, 0, bytes);
    fixture.controller.acknowledgeImportChunk(begun.transferId, ack.sequence);
    const inspecting = fixture.controller.sealAndInspectImport(begun.transferId);
    await started;

    fixture.leases.canonicalIdentity = 'https://vault.example/\0other@example.com';
    fixture.leases.session += 1;
    fixture.leases.canonicalIdentity = CANONICAL_ACCOUNT;
    fixture.leases.session += 1;
    release();

    await expect(inspecting).rejects.toMatchObject({ code: 'lease_changed' });
    expect(fixture.sessions.residentBytes).toBe(0);
    expect(fixture.controller.retainedPasswordBytes).toBe(0);
  });

  it('performs a same-buffer password challenge and exposes only a stable wrong-password code', async () => {
    const seenSources: Uint8Array[] = [];
    const inspectSource = vi.fn(async (
      source: Uint8Array,
      options?: InspectVaultTransferSourceOptions,
    ): Promise<VaultTransferSourceResult> => {
      seenSources.push(source);
      if (options?.password === undefined) {
        return { status: 'password_required', format: 'encrypted-json' };
      }
      return { status: 'failed', code: 'decryption_failed' };
    });
    const fixture = createFixture({ inspectSource, commitImport: () => undefined });
    await ensureStartup(fixture.controller);
    const bytes = encoder.encode('opaque encrypted source');
    const begun = fixture.controller.beginImport({
      expectedTotalBytes: bytes.byteLength,
    });
    const ack = fixture.controller.appendImportChunk(begun.transferId, 0, bytes);
    fixture.controller.acknowledgeImportChunk(begun.transferId, ack.sequence);

    let failure: unknown;
    try {
      await fixture.controller.sealAndInspectImport(begun.transferId, 'WRONG PRIVATE PASSWORD');
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({ code: 'decryption_failed', message: 'decryption_failed' });
    expect(JSON.stringify(failure)).not.toContain('WRONG PRIVATE PASSWORD');
    expect(seenSources).toHaveLength(2);
    expect(seenSources[0]).toBe(seenSources[1]);
    expect(fixture.controller.retainedPasswordBytes).toBe(0);
    expect(fixture.sessions.residentBytes).toBe(0);
  });

  it('accepts the password only at seal and rejects an empty password before inspection', async () => {
    const inspectSource = vi.fn(protectedSourceResult('pw'));
    const fixture = createFixture({ inspectSource, commitImport: commitEverySource });
    await ensureStartup(fixture.controller);
    const bytes = encoder.encode('opaque encrypted source');
    const begun = fixture.controller.beginImport({ expectedTotalBytes: bytes.byteLength });
    expect(fixture.controller.retainedPasswordBytes).toBe(0);
    const ack = fixture.controller.appendImportChunk(begun.transferId, 0, bytes);
    fixture.controller.acknowledgeImportChunk(begun.transferId, ack.sequence);

    await expect(fixture.controller.sealAndInspectImport(begun.transferId, ''))
      .rejects.toMatchObject({ code: 'invalid_request' });
    expect(inspectSource).not.toHaveBeenCalled();
    expect(fixture.controller.retainedPasswordBytes).toBe(0);
    expect(fixture.sessions.residentBytes).toBe(0);
  });

  it('requires re-upload when an encrypted source is sealed without its password', async () => {
    const fixture = createFixture({
      inspectSource: protectedSourceResult('pw'),
      commitImport: commitEverySource,
    });
    await ensureStartup(fixture.controller);
    const bytes = encoder.encode('opaque encrypted source');
    const begun = fixture.controller.beginImport({ expectedTotalBytes: bytes.byteLength });
    const ack = fixture.controller.appendImportChunk(begun.transferId, 0, bytes);
    fixture.controller.acknowledgeImportChunk(begun.transferId, ack.sequence);

    await expect(fixture.controller.sealAndInspectImport(begun.transferId))
      .rejects.toMatchObject({ code: 'password_required' });
    await expect(fixture.controller.sealAndInspectImport(begun.transferId, 'pw'))
      .rejects.toMatchObject({ code: 'not_found' });
    expect(fixture.sessions.residentBytes).toBe(0);
  });

  it('does not materialize password bytes after cancellation during initial source detection', async () => {
    let release!: () => void;
    let entered!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const inspectSource = vi.fn(async (): Promise<VaultTransferSourceResult> => {
      entered();
      await gate;
      return { status: 'password_required', format: 'encrypted-json' };
    });
    const fixture = createFixture({ inspectSource, commitImport: commitEverySource });
    await ensureStartup(fixture.controller);
    const bytes = encoder.encode('opaque encrypted source');
    const begun = fixture.controller.beginImport({ expectedTotalBytes: bytes.byteLength });
    const ack = fixture.controller.appendImportChunk(begun.transferId, 0, bytes);
    fixture.controller.acknowledgeImportChunk(begun.transferId, ack.sequence);
    const inspecting = fixture.controller.sealAndInspectImport(begun.transferId, 'private password');
    await started;

    await fixture.controller.cancel(begun.transferId);
    release();
    await expect(inspecting).rejects.toMatchObject({ code: 'cancelled' });
    expect(inspectSource).toHaveBeenCalledOnce();
    expect(fixture.controller.retainedPasswordBytes).toBe(0);
    expect(fixture.sessions.residentBytes).toBe(0);
  });

  it('rejects passwords on ordinary formats without passing them to the source inspector', async () => {
    const passwords: Array<string | undefined> = [];
    const inspectSource = async (
      source: Uint8Array,
      options?: InspectVaultTransferSourceOptions,
    ): Promise<VaultTransferSourceResult> => {
      passwords.push(options?.password);
      return inspectVaultTransferSource(source, options);
    };
    const fixture = createFixture({ inspectSource, commitImport: () => undefined });

    await expect(upload(fixture.controller, personalJson(), {}, 'not for plaintext'))
      .rejects.toMatchObject({ code: 'unexpected_password' });
    expect(passwords).toEqual([undefined]);
    expect(fixture.controller.retainedPasswordBytes).toBe(0);
  });

  it('prunes an expired inactive import before enforcing the single-import gate', async () => {
    const fixture = createFixture({ ttlMs: 10 });
    await ensureStartup(fixture.controller);
    const expired = fixture.controller.beginImport();
    fixture.setNow(1_010);

    const replacement = fixture.controller.beginImport();
    expect(replacement.transferId).not.toBe(expired.transferId);
    expect(fixture.sessions.status(expired.transferId)).toBeUndefined();
  });
});

describe('VaultTransferController commit safety', () => {
  it('drops the retained password before confirmed parsing starts', async () => {
    let passwordRetries = 0;
    let release!: () => void;
    let entered!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const baseInspector = protectedSourceResult('correct password');
    const inspectSource = async (
      source: Uint8Array,
      options?: InspectVaultTransferSourceOptions,
    ): Promise<VaultTransferSourceResult> => {
      if (options?.password !== undefined) {
        passwordRetries += 1;
        if (passwordRetries === 2) {
          entered();
          await gate;
        }
      }
      return baseInspector(source, options);
    };
    const fixture = createFixture({ inspectSource, commitImport: commitEverySource });
    const encrypted = encoder.encode('opaque encrypted source');
    const { begun, inspected } = await upload(
      fixture.controller,
      encrypted,
      {},
      'correct password',
    );
    expect(inspected.sourceFormat).toBe('encrypted-json');
    expect(fixture.controller.retainedPasswordBytes).toBeGreaterThan(0);
    fixture.controller.confirmImport(begun.transferId, inspected.previewCapability);

    const committing = fixture.controller.commitConfirmedImport(begun.transferId);
    await started;
    expect(fixture.controller.retainedPasswordBytes).toBe(0);
    release();
    await expect(committing).resolves.toMatchObject({ status: 'completed' });
    expect(fixture.controller.retainedPasswordBytes).toBe(0);
  });

  it('halts immediately on an unknown remote outcome and leaves a reconcile-required journal', async () => {
    let attemptedAfterUnknown = false;
    const fixture = createFixture({
      commitImport: async ({ journal }) => {
        const marked = await journal.markInFlight('item', 0);
        await journal.settleInFlight({
          operationId: marked.operationId,
          status: 'outcome_unknown',
          code: 'network_result_unknown',
        });
        attemptedAfterUnknown = true;
        await journal.markInFlight('item', 1);
      },
    });
    const { begun } = await confirmUploaded(fixture.controller);

    await expect(fixture.controller.commitConfirmedImport(begun.transferId)).resolves.toMatchObject({
      status: 'outcome_unknown',
      counts: { committed: 0, rejected: 0, skipped: 0, outcomeUnknown: 1 },
      requiresReconcile: true,
    });
    expect(attemptedAfterUnknown).toBe(false);
    await expect(fixture.controller.acknowledgeImportResult(begun.transferId)).rejects.toMatchObject({
      code: 'not_found',
    });
    const accountDigest = await digestVaultTransferAccountIdentity(CANONICAL_ACCOUNT);
    await expect(fixture.journal.getSummary(begun.transferId, accountDigest)).resolves.toMatchObject({
      phase: 'reconcile_required',
      requiresReconcile: true,
      outcomeCount: 1,
    });
    expect(fixture.sessions.residentBytes).toBe(0);
  });

  it('does not report success when a commit adapter omits source outcomes', async () => {
    const fixture = createFixture({ commitImport: () => undefined });
    const { begun } = await confirmUploaded(fixture.controller);

    await expect(fixture.controller.commitConfirmedImport(begun.transferId)).rejects.toMatchObject({
      code: 'commit_incomplete',
      message: 'commit_incomplete',
    });
    const accountDigest = await digestVaultTransferAccountIdentity(CANONICAL_ACCOUNT);
    await expect(fixture.journal.getSummary(begun.transferId, accountDigest)).resolves.toMatchObject({
      phase: 'cancelled',
      requiresReconcile: false,
      outcomeCount: 0,
    });
    expect(fixture.sessions.residentBytes).toBe(0);
  });

  it('passes the full plan to atomic journal preflight and performs zero writes when it does not fit', async () => {
    const commitImport = vi.fn(commitEverySource);
    const fixture = createFixture({
      commitImport,
      journalOptions: { maxOutcomes: 1, maxMappings: 1 },
    });
    const bytes = personalJson([
      { type: 2, name: 'A', secureNote: { type: 0 } },
      { type: 2, name: 'B', secureNote: { type: 0 } },
    ]);
    const uploaded = await upload(fixture.controller, bytes);
    fixture.controller.confirmImport(uploaded.begun.transferId, uploaded.inspected.previewCapability);

    await expect(fixture.controller.commitConfirmedImport(uploaded.begun.transferId)).rejects.toMatchObject({
      code: 'journal_failed',
    });
    expect(commitImport).not.toHaveBeenCalled();
    expect(fixture.values.has(VAULT_TRANSFER_JOURNAL_STORE_KEY)).toBe(false);
  });

  it('returns partial with reconciliation when an adapter fails after a known commit', async () => {
    const fixture = createFixture({
      commitImport: async ({ journal }) => {
        const marked = await journal.markInFlight('item', 0);
        await journal.settleInFlight({ operationId: marked.operationId, status: 'committed' });
        throw new Error('PRIVATE REMOTE ERROR');
      },
    });
    const { begun } = await confirmUploaded(fixture.controller);

    await expect(fixture.controller.commitConfirmedImport(begun.transferId)).resolves.toEqual({
      transferId: begun.transferId,
      status: 'partial',
      counts: { committed: 1, rejected: 0, skipped: 0, outcomeUnknown: 0 },
      requiresReconcile: true,
    });
    expect(() => fixture.controller.beginImport()).toThrowError(expect.objectContaining({
      code: 'outcome_unknown',
    }));
  });

  it('audits against a pre-adapter source snapshot when an adapter mutates the IR', async () => {
    const fixture = createFixture({
      commitImport: async ({ source, journal }) => {
        const items = source.inspection.ir?.items as unknown as unknown[];
        items.pop();
        const marked = await journal.markInFlight('item', 0);
        await journal.settleInFlight({ operationId: marked.operationId, status: 'committed' });
      },
    });
    const bytes = personalJson([
      { type: 2, name: 'A', secureNote: { type: 0 } },
      { type: 2, name: 'B', secureNote: { type: 0 } },
    ]);
    const uploaded = await upload(fixture.controller, bytes);
    fixture.controller.confirmImport(uploaded.begun.transferId, uploaded.inspected.previewCapability);

    await expect(fixture.controller.commitConfirmedImport(uploaded.begun.transferId)).resolves.toMatchObject({
      status: 'partial',
      counts: { committed: 1 },
      requiresReconcile: true,
    });
  });

  it('returns exact committed, rejected, and skipped counts for a complete partial import', async () => {
    const fixture = createFixture({
      reconcile: () => undefined,
      commitImport: async ({ source, journal }) => {
        const items = source.inspection.ir?.items ?? [];
        const committed = await journal.markInFlight('item', items[0]?.sourceIndex ?? 0);
        await journal.settleInFlight({ operationId: committed.operationId, status: 'committed' });
        const rejected = await journal.markInFlight('item', items[1]?.sourceIndex ?? 1);
        await journal.settleInFlight({
          operationId: rejected.operationId,
          status: 'rejected',
          code: 'server_rejected',
        });
        await journal.recordSkipped('item', items[2]?.sourceIndex ?? 2, 'dependency_rejected');
      },
    });
    const bytes = personalJson([
      { type: 2, name: 'A', secureNote: { type: 0 } },
      { type: 2, name: 'B', secureNote: { type: 0 } },
      { type: 2, name: 'C', secureNote: { type: 0 } },
    ]);
    const uploaded = await upload(fixture.controller, bytes);
    fixture.controller.confirmImport(uploaded.begun.transferId, uploaded.inspected.previewCapability);

    await expect(fixture.controller.commitConfirmedImport(uploaded.begun.transferId)).resolves.toEqual({
      transferId: uploaded.begun.transferId,
      status: 'partial',
      counts: { committed: 1, rejected: 1, skipped: 1, outcomeUnknown: 0 },
      requiresReconcile: true,
    });
    const accountDigest = await digestVaultTransferAccountIdentity(CANONICAL_ACCOUNT);
    await fixture.controller.acknowledgeImportResult(uploaded.begun.transferId);
    await expect(fixture.journal.getSummary(uploaded.begun.transferId, accountDigest)).resolves.toMatchObject({
      phase: 'reconcile_required',
      resultDeliveredAt: expect.any(Number),
      replayBarrier: true,
    });
    await expect(fixture.controller.reconcileCurrentAccount()).resolves.toEqual({ reconciled: 1 });
    await expect(fixture.journal.getSummary(uploaded.begun.transferId, accountDigest)).resolves.toMatchObject({
      phase: 'completed',
      reconciledAt: expect.any(Number),
      replayBarrier: true,
    });
    await expect(fixture.controller.clearReplayBarrier(uploaded.begun.transferId)).resolves.toBeUndefined();
    await expect(fixture.journal.getSummary(uploaded.begun.transferId, accountDigest)).resolves.toMatchObject({
      replayBarrier: false,
      unresolvedOutcomeUnknown: false,
    });
  });

  it('finishes remote commit after the raw-byte callback deadline because raw bytes are already zeroed', async () => {
    let release!: () => void;
    let entered!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const sessionRef: { current?: VaultTransferSessionManager<number, number, number> } = {};
    const fixture = createFixture({
      confirmedAccessDeadlineMs: 5,
      commitImport: async (input) => {
        expect(sessionRef.current?.residentBytes).toBe(0);
        entered();
        await gate;
        await commitEverySource(input);
      },
    });
    sessionRef.current = fixture.sessions;
    const { begun } = await confirmUploaded(fixture.controller);
    let settled = false;
    const committing = fixture.controller.commitConfirmedImport(begun.transferId);
    void committing.then(
      () => { settled = true; },
      () => { settled = true; },
    );
    await started;
    await new Promise((resolve) => setTimeout(resolve, 15));
    expect(settled).toBe(false);
    expect(fixture.sessions.residentBytes).toBe(0);
    release();
    await expect(committing).resolves.toMatchObject({ status: 'completed' });
  });

  it('turns cancellation with an in-flight remote operation into mandatory reconciliation', async () => {
    let release!: () => void;
    let marked!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const markedReady = new Promise<void>((resolve) => {
      marked = resolve;
    });
    let observedSignal: AbortSignal | undefined;
    const fixture = createFixture({
      commitImport: async ({ journal }) => {
        observedSignal = journal.signal;
        await journal.markInFlight('item', 0);
        marked();
        await gate;
        await journal.assertCurrent();
      },
    });
    const { begun } = await confirmUploaded(fixture.controller);
    const committing = fixture.controller.commitConfirmedImport(begun.transferId);
    await markedReady;

    await expect(fixture.controller.cancel(begun.transferId)).resolves.toEqual({
      cancelled: true,
      requiresReconcile: true,
    });
    expect(observedSignal?.aborted).toBe(true);
    release();
    await expect(committing).rejects.toMatchObject({ code: 'cancelled' });
    const accountDigest = await digestVaultTransferAccountIdentity(CANONICAL_ACCOUNT);
    await expect(fixture.journal.getSummary(begun.transferId, accountDigest)).resolves.toMatchObject({
      phase: 'reconcile_required',
      requiresReconcile: true,
    });
  });

  it('also requires reconciliation when cancellation follows a known committed outcome', async () => {
    let release!: () => void;
    let committed!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const committedReady = new Promise<void>((resolve) => {
      committed = resolve;
    });
    const fixture = createFixture({
      commitImport: async ({ journal }) => {
        const marked = await journal.markInFlight('item', 0);
        await journal.settleInFlight({ operationId: marked.operationId, status: 'committed' });
        committed();
        await gate;
        await journal.assertCurrent();
      },
    });
    const { begun } = await confirmUploaded(fixture.controller);
    const committing = fixture.controller.commitConfirmedImport(begun.transferId);
    await committedReady;

    await expect(fixture.controller.cancel(begun.transferId)).resolves.toEqual({
      cancelled: true,
      requiresReconcile: true,
    });
    release();
    await expect(committing).rejects.toMatchObject({ code: 'cancelled' });
    const accountDigest = await digestVaultTransferAccountIdentity(CANONICAL_ACCOUNT);
    await expect(fixture.journal.getSummary(begun.transferId, accountDigest)).resolves.toMatchObject({
      phase: 'reconcile_required',
      requiresReconcile: true,
      outcomeCount: 1,
    });
  });

  it('does not run startup or reconciliation while a cancelled remote commit is still settling', async () => {
    let release!: () => void;
    let marked!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const markedReady = new Promise<void>((resolve) => {
      marked = resolve;
    });
    const reconcile = vi.fn(async () => undefined);
    const fixture = createFixture({
      reconcile,
      commitImport: async ({ journal }) => {
        await journal.markInFlight('item', 0);
        marked();
        await gate;
        await journal.assertCurrent();
      },
    });
    const { begun } = await confirmUploaded(fixture.controller);
    const committing = fixture.controller.commitConfirmedImport(begun.transferId);
    await markedReady;

    await expect(fixture.controller.inspectJournalForStartup()).rejects.toMatchObject({
      code: 'invalid_state',
    });
    await fixture.controller.cancel(begun.transferId);
    await expect(fixture.controller.reconcileCurrentAccount()).rejects.toMatchObject({
      code: 'invalid_state',
    });
    release();
    await expect(committing).rejects.toMatchObject({ code: 'cancelled' });
    await expect(fixture.controller.reconcileCurrentAccount()).resolves.toEqual({ reconciled: 1 });
    expect(reconcile).toHaveBeenCalledOnce();
  });

  it('linearizes a too-late cancel behind journal finalization and requires a sync before retry', async () => {
    const reconcile = vi.fn(async () => undefined);
    const fixture = createFixture({ commitImport: commitEverySource, reconcile });
    const originalComplete = fixture.journal.complete.bind(fixture.journal);
    let release!: () => void;
    let entered!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const finalizing = new Promise<void>((resolve) => {
      entered = resolve;
    });
    vi.spyOn(fixture.journal, 'complete').mockImplementation(async (...args) => {
      entered();
      await gate;
      return originalComplete(...args);
    });
    const { begun } = await confirmUploaded(fixture.controller);
    const committing = fixture.controller.commitConfirmedImport(begun.transferId);
    await finalizing;

    expect(() => fixture.controller.beginImport()).toThrowError(expect.objectContaining({
      code: 'capacity',
    }));
    await expect(fixture.controller.cancel(begun.transferId)).resolves.toEqual({
      cancelled: false,
      requiresReconcile: false,
    });
    release();
    await expect(committing).resolves.toMatchObject({ status: 'completed' });
    await expect(upload(fixture.controller)).rejects.toMatchObject({ code: 'outcome_unknown' });
    await expect(fixture.controller.inspectReplayBarriers()).resolves.toMatchObject({
      count: 1,
      barriers: [{ transferId: begun.transferId, reason: 'pending_result_delivery', clearable: false }],
    });
    await expect(fixture.controller.reconcileCurrentAccount()).resolves.toEqual({ reconciled: 1 });
    expect(reconcile).toHaveBeenCalledOnce();
    await expect(fixture.controller.inspectReplayBarriers()).resolves.toMatchObject({
      barriers: [{ transferId: begun.transferId, clearable: true }],
    });
    await expect(fixture.controller.clearCurrentAccountReplayBarriers()).resolves.toEqual({ cleared: 1 });
    await expect(upload(fixture.controller)).resolves.toMatchObject({
      inspected: { preview: { canCommit: true } },
    });
  });

  it('does not batch-clear a live full-result delivery barrier before its ACK', async () => {
    const fixture = createFixture({ commitImport: commitEverySource, reconcile: () => undefined });
    const { begun } = await confirmUploaded(fixture.controller);
    await fixture.controller.commitConfirmedImport(begun.transferId);
    await fixture.controller.reconcileCurrentAccount();

    await expect(fixture.controller.inspectReplayBarriers()).resolves.toMatchObject({
      barriers: [{ transferId: begun.transferId, reason: 'pending_result_delivery', clearable: false }],
    });
    await expect(fixture.controller.clearCurrentAccountReplayBarriers()).resolves.toEqual({ cleared: 0 });
    await fixture.controller.acknowledgeImportResult(begun.transferId);
    await expect(fixture.controller.inspectReplayBarriers()).resolves.toMatchObject({ count: 0 });
  });

  it('clears retained passwords on cancel, disconnect, clear, and expiry', async () => {
    const fixture = createFixture({
      inspectSource: protectedSourceResult('pw'),
      commitImport: () => undefined,
      ttlMs: 10,
    });
    const source = encoder.encode('opaque encrypted source');
    const first = await upload(fixture.controller, source, {}, 'pw');
    expect(fixture.controller.retainedPasswordBytes).toBe(2);
    await fixture.controller.cancel(first.begun.transferId);
    expect(fixture.controller.retainedPasswordBytes).toBe(0);

    const second = await upload(fixture.controller, source, {}, 'pw');
    await fixture.controller.disconnect(second.begun.transferId);
    expect(fixture.controller.retainedPasswordBytes).toBe(0);

    await upload(fixture.controller, source, {}, 'pw');
    await fixture.controller.clearAll();
    expect(fixture.controller.retainedPasswordBytes).toBe(0);

    startupPromises.delete(fixture.controller);
    await upload(fixture.controller, source, {}, 'pw');
    fixture.setNow(1_010);
    await expect(fixture.controller.sweepExpired()).resolves.toBe(1);
    expect(fixture.controller.retainedPasswordBytes).toBe(0);
    expect(fixture.sessions.residentBytes).toBe(0);
  });
});

describe('VaultTransferController export lifecycle', () => {
  it('binds CSV to a passwordless export and returns only canonical loss-review metadata', async () => {
    const buildExport = vi.fn(() => ({
      bytes: new Uint8Array([1, 2, 3]),
      filename: 'vault.csv',
      review: {
        exportedItemCount: 1,
        omittedItemCount: 1,
        warnings: [
          { code: 'ssh_key_items_omitted' as const, count: 1 },
          { code: 'passkeys_omitted' as const, count: 2 },
        ],
      },
    }));
    const fixture = createFixture({ buildExport });

    await expect(fixture.controller.beginExport({
      format: 'csv', authorizationId: EXPORT_AUTHORIZATION_ID, filePassword: 'not-allowed',
    })).rejects.toMatchObject({ code: 'unexpected_password' });
    const begun = await fixture.controller.beginExport({
      format: 'csv', authorizationId: EXPORT_AUTHORIZATION_ID,
    });

    expect(buildExport).toHaveBeenCalledOnce();
    expect(buildExport).toHaveBeenCalledWith(
      'csv', undefined, true, { kind: 'personal' },
    );
    expect(begun).toMatchObject({
      format: 'csv', filename: 'vault.csv',
      review: {
        exportedItemCount: 1,
        omittedItemCount: 1,
        warnings: [
          { code: 'ssh_key_items_omitted', count: 1 },
          { code: 'passkeys_omitted', count: 2 },
        ],
      },
    });
    expect(Object.isFrozen(begun.review)).toBe(true);
    expect(Object.isFrozen(begun.review?.warnings)).toBe(true);
    await fixture.controller.cancel(begun.transferId);
  });

  it('rejects malformed or misplaced CSV review metadata before streaming', async () => {
    const missing = createFixture({
      buildExport: () => ({ bytes: new Uint8Array([1]), filename: 'vault.csv' }),
    });
    await expect(missing.controller.beginExport({
      format: 'csv', authorizationId: EXPORT_AUTHORIZATION_ID,
    })).rejects.toMatchObject({ code: 'export_failed' });

    const malformed = createFixture({
      buildExport: () => ({
        bytes: new Uint8Array([1]),
        filename: 'vault.csv',
        review: {
          exportedItemCount: 1,
          omittedItemCount: 0,
          warnings: [{ code: 'passkeys_omitted', count: 0 }],
        },
      }) as BuiltVaultTransferExport,
    });
    await expect(malformed.controller.beginExport({
      format: 'csv', authorizationId: EXPORT_AUTHORIZATION_ID,
    })).rejects.toMatchObject({ code: 'export_failed' });

    const misplaced = createFixture({
      buildExport: () => ({
        bytes: new Uint8Array([1]), filename: 'vault.json',
        review: { exportedItemCount: 0, omittedItemCount: 0, warnings: [] },
      }),
    });
    await expect(misplaced.controller.beginExport({
      format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    })).rejects.toMatchObject({ code: 'export_failed' });
  });

  it('stages owned bytes, streams bounded borrowed chunks, and zeroes each chunk on ACK', async () => {
    const owned = new Uint8Array([1, 2, 3, 4, 5]);
    const fixture = createFixture({
      buildExport: () => ({ bytes: owned, filename: 'vault.json' }),
      exportChunkBytes: 2,
    });
    const begun = await fixture.controller.beginExport({
      format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    expect(begun).toMatchObject({ filename: 'vault.json', totalBytes: 5, chunkBytes: 2 });
    expect(begun).not.toHaveProperty('confirmationId');
    expect(Array.from(owned)).toEqual([0, 0, 0, 0, 0]);

    const transferred: number[] = [];
    const borrowed: Uint8Array[] = [];
    await expect(fixture.controller.streamExport(begun.transferId, async ({ producer }) => {
      for (;;) {
        const chunk = await producer.next();
        if (chunk.done) {
          expect(chunk.totalBytes).toBe(5);
          break;
        }
        borrowed.push(chunk.bytes);
        transferred.push(...chunk.bytes);
        await expect(producer.next()).rejects.toMatchObject({ code: 'ack_required' });
        producer.acknowledge(chunk.sequence);
        expect(Array.from(chunk.bytes)).toEqual(new Array(chunk.bytes.length).fill(0));
      }
    })).resolves.toEqual({
      transferId: begun.transferId,
      format: 'json',
      status: 'completed',
      totalBytes: 5,
    });

    expect(transferred).toEqual([1, 2, 3, 4, 5]);
    expect(borrowed.every((chunk) => chunk.every((byte) => byte === 0))).toBe(true);
    expect(fixture.sessions.residentBytes).toBe(0);
  });

  it('fails closed and zeroes an outstanding chunk when the consumer does not finish', async () => {
    const fixture = createFixture({
      buildExport: () => ({ bytes: new Uint8Array([9, 8, 7]), filename: 'vault.json' }),
      exportChunkBytes: 2,
    });
    const begun = await fixture.controller.beginExport({
      format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    let borrowed: Uint8Array | undefined;

    await expect(fixture.controller.streamExport(begun.transferId, async ({ producer }) => {
      const chunk = await producer.next();
      if (!chunk.done) borrowed = chunk.bytes;
    })).rejects.toMatchObject({ code: 'export_incomplete' });
    expect(Array.from(borrowed ?? [])).toEqual([0, 0]);
    expect(fixture.sessions.residentBytes).toBe(0);
  });

  it('reaches teardown when the upper adapter detaches a borrowed export chunk', async () => {
    const fixture = createFixture({
      buildExport: () => ({ bytes: new Uint8Array([4, 5]), filename: 'vault.json' }),
      exportChunkBytes: 2,
    });
    const begun = await fixture.controller.beginExport({
      format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });

    await expect(fixture.controller.streamExport(begun.transferId, async ({ producer }) => {
      const chunk = await producer.next();
      if (chunk.done) throw new Error('expected data');
      structuredClone(chunk.bytes, { transfer: [chunk.bytes.buffer as ArrayBuffer] });
      expect(chunk.bytes.byteLength).toBe(0);
      producer.acknowledge(chunk.sequence);
      await producer.next();
    })).resolves.toMatchObject({ status: 'completed' });
    expect(fixture.sessions.residentBytes).toBe(0);
  });

  it('rechecks the original session lease before each export chunk', async () => {
    const fixture = createFixture({
      buildExport: () => ({ bytes: new Uint8Array([1, 2, 3]), filename: 'vault.json' }),
      exportChunkBytes: 1,
    });
    const begun = await fixture.controller.beginExport({
      format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    let first: Uint8Array | undefined;

    await expect(fixture.controller.streamExport(begun.transferId, async ({ producer }) => {
      const chunk = await producer.next();
      if (chunk.done) throw new Error('expected a data chunk');
      first = chunk.bytes;
      producer.acknowledge(chunk.sequence);
      fixture.leases.session += 1;
      await producer.next();
    })).rejects.toMatchObject({ code: 'lease_changed' });
    expect(Array.from(first ?? [])).toEqual([0]);
    expect(fixture.sessions.residentBytes).toBe(0);
  });

  it('uses missing versus present filePassword to select account or file encrypted JSON', async () => {
    const buildExport = vi.fn(() => ({ bytes: new Uint8Array([1]), filename: 'vault.json' }));
    const redeemExportAuthorization = vi.fn(() => true as const);
    const fixture = createFixture({ buildExport, redeemExportAuthorization });

    await expect(fixture.controller.beginExport({
      format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID, filePassword: 'secret',
    }))
      .rejects.toMatchObject({ code: 'unexpected_password' });
    const accountEncrypted = await fixture.controller.beginExport({
      format: 'encrypted-json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    expect(buildExport).toHaveBeenNthCalledWith(
      1, 'encrypted-json', undefined, true, { kind: 'personal' },
    );
    expect(redeemExportAuthorization).toHaveBeenNthCalledWith(1, {
      format: 'encrypted-json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      encryptionType: 'account',
      target: { kind: 'personal' },
    });
    await fixture.controller.cancel(accountEncrypted.transferId);

    const fileEncrypted = await fixture.controller.beginExport({
      format: 'encrypted-json', authorizationId: EXPORT_AUTHORIZATION_ID, filePassword: 'secret',
    });
    expect(buildExport).toHaveBeenNthCalledWith(
      2, 'encrypted-json', 'secret', true, { kind: 'personal' },
    );
    expect(redeemExportAuthorization).toHaveBeenNthCalledWith(2, {
      format: 'encrypted-json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      encryptionType: 'file',
      target: { kind: 'personal' },
    });
    await fixture.controller.cancel(fileEncrypted.transferId);
  });

  it('rejects Windows-unsafe trailing dots or spaces in export filenames', async () => {
    const trailingDot = createFixture({
      buildExport: () => ({ bytes: new Uint8Array([1]), filename: 'vault.json.' }),
    });
    await expect(trailingDot.controller.beginExport({
      format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    }))
      .rejects.toMatchObject({ code: 'export_failed' });

    const trailingSpace = createFixture({
      buildExport: () => ({ bytes: new Uint8Array([1]), filename: 'vault.json ' }),
    });
    await expect(trailingSpace.controller.beginExport({
      format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    }))
      .rejects.toMatchObject({ code: 'export_failed' });
  });

  it('tears down the hidden session when the export builder returns a malformed container', async () => {
    const fixture = createFixture({
      buildExport: () => ({}) as BuiltVaultTransferExport,
    });

    await expect(fixture.controller.beginExport({
      format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    })).rejects.toMatchObject({
      code: 'export_failed',
      message: 'export_failed',
    });
    expect(fixture.sessions.residentBytes).toBe(0);
    await expect(fixture.controller.clearAll()).resolves.toBe(0);
  });

  it('fails before staging or decrypting when the export authorization is invalid', async () => {
    const buildExport = vi.fn(() => ({ bytes: new Uint8Array([1]), filename: 'vault.json' }));
    const redeemExportAuthorization = vi.fn(() => undefined);
    const fixture = createFixture({ buildExport, redeemExportAuthorization });

    await expect(fixture.controller.beginExport({
      format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    })).rejects.toMatchObject({ code: 'export_authorization_invalid' });
    expect(redeemExportAuthorization).toHaveBeenCalledWith({
      format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'personal' },
    });
    expect(buildExport).not.toHaveBeenCalled();
    expect(fixture.sessions.residentBytes).toBe(0);
  });

  it('passes the exact redeemed authorization object to the exporter', async () => {
    const authorization = {
      account: 7,
      session: 9,
      target: { kind: 'personal' as const },
    } as const;
    const buildExport = vi.fn(() => ({ bytes: new Uint8Array([1]), filename: 'vault.json' }));
    const fixture = createFixture({
      buildExport,
      redeemExportAuthorization: () => authorization,
    });

    const begun = await fixture.controller.beginExport({
      format: 'encrypted-json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    expect(buildExport).toHaveBeenCalledWith(
      'encrypted-json', undefined, authorization, { kind: 'personal' },
    );
    await fixture.controller.cancel(begun.transferId);
  });

  it('passes one canonical organization target through redemption and export building', async () => {
    const buildExport = vi.fn((
      _format: 'json' | 'encrypted-json' | 'csv' | 'zip',
      _filePassword: string | undefined,
      _authorization: ExportAuthorization,
      _target: VaultTransferExportTarget,
    ) => ({ bytes: new Uint8Array([1]), filename: 'organization.json' }));
    const redeemExportAuthorization = vi.fn((input: {
      readonly target: VaultTransferExportTarget;
    }) => ({ account: 7, session: 9, target: input.target }));
    const fixture = createFixture({ buildExport, redeemExportAuthorization });

    const begun = await fixture.controller.beginExport({
      format: 'json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'organization', organizationId: ORGANIZATION_ID.toUpperCase() },
    });

    expect(redeemExportAuthorization).toHaveBeenCalledWith({
      format: 'json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'organization', organizationId: ORGANIZATION_ID },
    });
    const authorization = redeemExportAuthorization.mock.results[0]?.value;
    const redeemedTarget = redeemExportAuthorization.mock.calls[0]?.[0].target;
    expect(buildExport).toHaveBeenCalledWith(
      'json',
      undefined,
      authorization,
      { kind: 'organization', organizationId: ORGANIZATION_ID },
    );
    expect(buildExport.mock.calls[0]?.[3]).toBe(redeemedTarget);
    expect(Object.isFrozen(redeemedTarget)).toBe(true);
    await fixture.controller.cancel(begun.transferId);
  });

  it('fails a mismatched redeemed target before export building', async () => {
    const buildExport = vi.fn(() => ({ bytes: new Uint8Array([1]), filename: 'organization.json' }));
    const redeemExportAuthorization = vi.fn(() => ({
      account: 7,
      session: 9,
      target: { kind: 'organization' as const, organizationId: OTHER_ORGANIZATION_ID },
    }));
    const fixture = createFixture({ buildExport, redeemExportAuthorization });

    await expect(fixture.controller.beginExport({
      format: 'json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'organization', organizationId: ORGANIZATION_ID },
    })).rejects.toMatchObject({ code: 'export_authorization_invalid' });

    expect(redeemExportAuthorization).toHaveBeenCalledOnce();
    expect(buildExport).not.toHaveBeenCalled();
  });

  it('rejects malformed targets and organization ZIP before consuming a grant', async () => {
    const buildExport = vi.fn(() => ({ bytes: new Uint8Array([1]), filename: 'vault.zip' }));
    const redeemExportAuthorization = vi.fn(() => true as const);
    const fixture = createFixture({ buildExport, redeemExportAuthorization });

    await expect(fixture.controller.beginExport({
      format: 'json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'organization', organizationId: 'not-an-id' } as never,
    })).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(fixture.controller.beginExport({
      format: 'zip',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'organization', organizationId: ORGANIZATION_ID },
    })).rejects.toMatchObject({ code: 'invalid_request' });

    expect(redeemExportAuthorization).not.toHaveBeenCalled();
    expect(buildExport).not.toHaveBeenCalled();
  });
});

describe('VaultTransferController journal recovery', () => {
  it('partitions unresolved barriers by account across an A-to-B-to-A transition', async () => {
    const fixture = createFixture({
      commitImport: async ({ journal }) => {
        const marked = await journal.markInFlight('item', 0);
        await journal.settleInFlight({
          operationId: marked.operationId,
          status: 'outcome_unknown',
          code: 'network_result_unknown',
        });
      },
    });
    const first = await confirmUploaded(fixture.controller);
    await expect(fixture.controller.commitConfirmedImport(first.begun.transferId)).resolves.toMatchObject({
      status: 'outcome_unknown',
    });

    await fixture.controller.revokeAll();
    fixture.leases.canonicalIdentity = 'https://vault.example/\0other@example.com';
    fixture.leases.account += 1;
    fixture.leases.session += 1;
    fixture.leases.identity += 1;
    fixture.leases.transfer += 1;
    fixture.leases.reconcile += 1;
    startupPromises.delete(fixture.controller);
    await ensureStartup(fixture.controller);
    const accountB = await upload(fixture.controller);
    expect(accountB.inspected.preview.canCommit).toBe(true);
    await fixture.controller.cancel(accountB.begun.transferId);

    await fixture.controller.revokeAll();
    fixture.leases.canonicalIdentity = CANONICAL_ACCOUNT;
    fixture.leases.account += 1;
    fixture.leases.session += 1;
    fixture.leases.identity += 1;
    fixture.leases.transfer += 1;
    fixture.leases.reconcile += 1;
    startupPromises.delete(fixture.controller);
    await ensureStartup(fixture.controller);
    await expect(upload(fixture.controller, encoder.encode(JSON.stringify({
      encrypted: false,
      folders: [],
      items: [{ type: 2, name: 'Different source', secureNote: { type: 0 } }],
    })))).rejects.toMatchObject({ code: 'outcome_unknown' });
  });

  it('keeps imports closed when startup journal inspection fails', async () => {
    const fixture = createFixture({ reconcile: () => undefined });
    vi.spyOn(fixture.journal, 'inspectForStartup').mockRejectedValueOnce(new Error('PRIVATE'));

    await expect(fixture.controller.inspectJournalForStartup()).rejects.toMatchObject({
      code: 'journal_failed',
    });
    expect(() => fixture.controller.beginImport()).toThrowError(expect.objectContaining({
      code: 'invalid_state',
    }));
  });

  it('inspects startup state without resuming plaintext and reconciles only the current account', async () => {
    const reconcile = vi.fn(async (_input: VaultTransferReconcileInput) => undefined);
    const fixture = createFixture({ reconcile });
    const accountDigest = await digestVaultTransferAccountIdentity(CANONICAL_ACCOUNT);
    const transferId = '00000000-0000-4000-8000-000000000099';
    await fixture.journal.begin({
      transferId,
      direction: 'import',
      accountIdentityDigest: accountDigest,
      sourceDigest: 'a'.repeat(64),
    });
    await fixture.journal.markInFlight({
      transferId,
      accountIdentityDigest: accountDigest,
      kind: 'item',
      sourceIndex: 0,
    });

    await expect(fixture.controller.inspectJournalForStartup()).resolves.toMatchObject({
      kind: 'valid',
      requiresReconcile: true,
      autoResume: false,
      journals: [{ transferId, phase: 'reconcile_required' }],
    });
    await expect(fixture.controller.reconcileCurrentAccount()).resolves.toEqual({ reconciled: 1 });
    expect(reconcile).toHaveBeenCalledOnce();
    expect(reconcile.mock.calls[0]?.[0]).toMatchObject({
      accountIdentityDigest: accountDigest,
      journals: [{ transferId, requiresReconcile: true }],
    });
    await expect(fixture.journal.getSummary(transferId, accountDigest)).resolves.toMatchObject({
      phase: 'completed',
      requiresReconcile: false,
      replayBarrier: true,
      unresolvedOutcomeUnknown: true,
    });
    expect(() => fixture.controller.beginImport()).toThrowError(expect.objectContaining({
      code: 'outcome_unknown',
    }));
    await expect(fixture.controller.inspectReplayBarriers()).resolves.toMatchObject({
      count: 1,
      unresolvedUnknownCount: 1,
      barriers: [{ transferId, reason: 'outcome_unknown', clearable: true }],
    });
    await expect(fixture.controller.clearCurrentAccountReplayBarriers()).resolves.toEqual({ cleared: 1 });
    await expect(fixture.journal.getSummary(transferId, accountDigest)).resolves.toMatchObject({
      replayBarrier: false,
      unresolvedOutcomeUnknown: false,
    });
    expect(() => fixture.controller.beginImport()).not.toThrow();
  });

  it('lets revocation preempt a pending reconcile without acknowledging stale recovery', async () => {
    let release!: () => void;
    let entered!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const fixture = createFixture({
      reconcile: async () => {
        entered();
        await gate;
      },
    });
    const accountDigest = await digestVaultTransferAccountIdentity(CANONICAL_ACCOUNT);
    const transferId = '00000000-0000-4000-8000-000000000097';
    await fixture.journal.begin({
      transferId,
      direction: 'import',
      accountIdentityDigest: accountDigest,
      sourceDigest: 'c'.repeat(64),
    });
    const marked = await fixture.journal.markInFlight({
      transferId,
      accountIdentityDigest: accountDigest,
      kind: 'item',
      sourceIndex: 0,
    });
    await fixture.journal.settleInFlight({
      transferId,
      accountIdentityDigest: accountDigest,
      operationId: marked.operationId,
      status: 'outcome_unknown',
      code: 'network_result_unknown',
    });
    await ensureStartup(fixture.controller);
    const reconciling = fixture.controller.reconcileCurrentAccount();
    await started;

    await expect(fixture.controller.revokeAll()).resolves.toBe(0);
    release();
    await expect(reconciling).rejects.toMatchObject({ code: 'cancelled' });
    await expect(fixture.journal.getSummary(transferId, accountDigest)).resolves.toMatchObject({
      phase: 'reconcile_required',
      requiresReconcile: true,
      reconciledAt: null,
    });
  });

  it('does not acknowledge reconciliation after an account lease ABA', async () => {
    const leaseRef: { current?: LeaseState } = {};
    const reconcile = vi.fn(async () => {
      const leases = leaseRef.current!;
      leases.canonicalIdentity = 'https://vault.example/\0other@example.com';
      leases.identity += 1;
      leases.canonicalIdentity = CANONICAL_ACCOUNT;
      leases.identity += 1;
    });
    const fixture = createFixture({ reconcile });
    leaseRef.current = fixture.leases;
    const accountDigest = await digestVaultTransferAccountIdentity(CANONICAL_ACCOUNT);
    const transferId = '00000000-0000-4000-8000-000000000098';
    await fixture.journal.begin({
      transferId,
      direction: 'import',
      accountIdentityDigest: accountDigest,
      sourceDigest: 'b'.repeat(64),
    });
    const marked = await fixture.journal.markInFlight({
      transferId,
      accountIdentityDigest: accountDigest,
      kind: 'item',
      sourceIndex: 0,
    });
    await fixture.journal.settleInFlight({
      transferId,
      accountIdentityDigest: accountDigest,
      operationId: marked.operationId,
      status: 'outcome_unknown',
      code: 'network_result_unknown',
    });

    await expect(fixture.controller.reconcileCurrentAccount()).rejects.toMatchObject({
      code: 'lease_changed',
    });
    expect(() => fixture.controller.beginImport()).toThrowError(expect.objectContaining({
      code: 'outcome_unknown',
    }));
    await expect(fixture.journal.getSummary(transferId, accountDigest)).resolves.toMatchObject({
      phase: 'reconcile_required',
      requiresReconcile: true,
    });
  });
});
