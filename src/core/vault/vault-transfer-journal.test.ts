import { describe, expect, it, vi } from 'vitest';
import type { KeyValueStore } from '../../platform/store.js';
import {
  MAX_VAULT_TRANSFER_JOURNAL_BYTES,
  MAX_VAULT_TRANSFER_JOURNALS,
  MAX_VAULT_TRANSFER_MAPPINGS,
  MAX_VAULT_TRANSFER_OUTCOMES,
  MAX_VAULT_TRANSFER_OUTCOME_PAGE_SIZE,
  VAULT_TRANSFER_JOURNAL_STORE_KEY,
  VaultTransferJournalStore,
  digestVaultTransferAccountIdentity,
  type VaultTransferJournalStoreOptions,
} from './vault-transfer-journal.js';

const TRANSFER_A = '00000000-0000-4000-8000-000000000001';
const TRANSFER_B = '00000000-0000-4000-8000-000000000002';
const ACCOUNT_A = 'a'.repeat(64);
const ACCOUNT_B = 'b'.repeat(64);
const SOURCE_A = 'c'.repeat(64);
const SOURCE_B = 'd'.repeat(64);

interface MemoryStoreFixture {
  readonly store: KeyValueStore;
  readonly values: Map<string, unknown>;
  readonly set: ReturnType<typeof vi.fn>;
}

interface JournalFixture extends MemoryStoreFixture {
  readonly journal: VaultTransferJournalStore;
  readonly setNow: (value: number) => void;
}

function memoryStore(initial?: unknown): MemoryStoreFixture {
  const values = new Map<string, unknown>();
  if (initial !== undefined) values.set(VAULT_TRANSFER_JOURNAL_STORE_KEY, structuredClone(initial));
  const set = vi.fn(async (key: string, value: unknown): Promise<void> => {
    await Promise.resolve();
    values.set(key, structuredClone(value));
  });
  return {
    values,
    set,
    store: {
      async get<T>(key: string): Promise<T | undefined> {
        await Promise.resolve();
        const value = values.get(key);
        return value === undefined ? undefined : structuredClone(value) as T;
      },
      set,
      async remove(key: string): Promise<void> {
        values.delete(key);
      },
      async clear(): Promise<void> {
        values.clear();
      },
    },
  };
}

function createFixture(
  options: VaultTransferJournalStoreOptions = {},
  memory = memoryStore(),
): JournalFixture {
  let now = 100;
  let nextId = 100;
  const journal = new VaultTransferJournalStore(memory.store, {
    now: () => now,
    createId: () => `00000000-0000-4000-8000-${String(nextId++).padStart(12, '0')}`,
    ...options,
  });
  return {
    ...memory,
    journal,
    setNow(value: number) {
      now = value;
    },
  };
}

function beginInput(transferId = TRANSFER_A, accountIdentityDigest = ACCOUNT_A) {
  return {
    transferId,
    direction: 'import' as const,
    accountIdentityDigest,
    sourceDigest: SOURCE_A,
  };
}

function operationInput(
  transferId = TRANSFER_A,
  accountIdentityDigest = ACCOUNT_A,
  kind: 'folder' | 'collection' | 'item' | 'attachment' = 'item',
  sourceIndex = 0,
) {
  return { transferId, accountIdentityDigest, kind, sourceIndex };
}

function storedBytes(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

describe('VaultTransferJournalStore', () => {
  it('persists write-ahead markers, bounded result pages, and opaque aliases', async () => {
    const fixture = createFixture({ outcomePageSize: 2 });
    const begun = await fixture.journal.begin(beginInput());
    expect(begun).toMatchObject({
      transferId: TRANSFER_A,
      phase: 'prepared',
      replayBarrier: false,
      resultDeliveredAt: null,
      autoResume: false,
      outcomeCount: 0,
    });

    fixture.setNow(101);
    const folderPost = await fixture.journal.markInFlight(operationInput(
      TRANSFER_A,
      ACCOUNT_A,
      'folder',
      4,
    ));
    const marked = fixture.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY) as {
      journals: Array<{ inFlight: unknown }>;
    };
    expect(marked.journals[0]?.inFlight).toMatchObject(folderPost);
    expect(marked.journals[0]?.inFlight).toHaveProperty('settlementReserve');

    fixture.setNow(102);
    const folderOutcome = await fixture.journal.settleInFlight({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      operationId: folderPost.operationId,
      status: 'committed',
    });
    expect(folderOutcome).toMatchObject({
      sequence: 0,
      kind: 'folder',
      sourceIndex: 4,
      status: 'committed',
      code: null,
    });
    expect(folderOutcome.alias).toMatch(/^[0-9a-f-]{36}$/);
    expect(folderOutcome.alias).not.toBe(folderPost.operationId);
    await expect(fixture.journal.getAlias(TRANSFER_A, ACCOUNT_A, 'folder', 4))
      .resolves.toBe(folderOutcome.alias);

    await fixture.journal.recordSkipped({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      kind: 'item',
      sourceIndex: 5,
      code: 'folder_rejected',
    });
    const itemPost = await fixture.journal.markInFlight(operationInput(
      TRANSFER_A,
      ACCOUNT_A,
      'item',
      6,
    ));
    await fixture.journal.settleInFlight({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      operationId: itemPost.operationId,
      status: 'rejected',
      code: 'server_rejected',
    });

    const firstPage = await fixture.journal.getOutcomePage(TRANSFER_A, ACCOUNT_A, 0);
    const secondPage = await fixture.journal.getOutcomePage(TRANSFER_A, ACCOUNT_A, 1);
    expect(firstPage).toMatchObject({ pageCount: 2, outcomeCount: 3 });
    expect(firstPage.outcomes.map((outcome) => outcome.sequence)).toEqual([0, 1]);
    expect(secondPage.outcomes.map((outcome) => outcome.sequence)).toEqual([2]);

    const completed = await fixture.journal.complete(TRANSFER_A, ACCOUNT_A);
    expect(completed).toMatchObject({
      phase: 'completed',
      replayBarrier: true,
      unresolvedOutcomeUnknown: false,
      resultDeliveredAt: null,
      outcomeCount: 3,
      outcomePageCount: 2,
      folderMappingCount: 1,
      itemMappingCount: 0,
    });

    const serialized = JSON.stringify(fixture.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY));
    expect(serialized).not.toContain('remoteId');
    expect(serialized).not.toContain('password');
    expect(serialized).not.toContain('folder name');
  });

  it('preflights a complete plan without persisting simulated outcomes or aliases', async () => {
    const fixture = createFixture({ maxOutcomes: 3, maxMappings: 2, outcomePageSize: 2 });
    const begun = await fixture.journal.begin(beginInput(), [
      { kind: 'folder', sourceIndex: 4 },
      { kind: 'item', sourceIndex: 4 },
      { kind: 'attachment', sourceIndex: 4 },
    ]);

    expect(begun).toMatchObject({
      phase: 'prepared',
      replayBarrier: false,
      resultDeliveredAt: null,
      outcomeCount: 0,
      outcomePageCount: 0,
      folderMappingCount: 0,
      itemMappingCount: 0,
    });
    const stored = fixture.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY) as {
      journals: Array<{
        outcomePages: unknown[];
        folderAliases: unknown[];
        itemAliases: unknown[];
      }>;
    };
    expect(stored.journals[0]).toMatchObject({
      outcomePages: [],
      folderAliases: [],
      itemAliases: [],
    });
    expect(fixture.set).toHaveBeenCalledTimes(1);
  });

  it('rejects duplicate and over-limit plans before writing a journal', async () => {
    const duplicate = createFixture();
    await expect(duplicate.journal.begin(beginInput(), [
      { kind: 'item', sourceIndex: 1 },
      { kind: 'item', sourceIndex: 1 },
    ])).rejects.toMatchObject({ code: 'duplicate_source' });
    expect(duplicate.values.has(VAULT_TRANSFER_JOURNAL_STORE_KEY)).toBe(false);
    expect(duplicate.set).not.toHaveBeenCalled();

    const outcomes = createFixture({ maxOutcomes: 1 });
    await expect(outcomes.journal.begin(beginInput(), [
      { kind: 'attachment', sourceIndex: 1 },
      { kind: 'collection', sourceIndex: 1 },
    ])).rejects.toMatchObject({ code: 'resource_limit' });
    expect(outcomes.values.has(VAULT_TRANSFER_JOURNAL_STORE_KEY)).toBe(false);
    expect(outcomes.set).not.toHaveBeenCalled();

    const mappings = createFixture({ maxOutcomes: 2, maxMappings: 1 });
    await expect(mappings.journal.begin(beginInput(), [
      { kind: 'folder', sourceIndex: 1 },
      { kind: 'item', sourceIndex: 1 },
    ])).rejects.toMatchObject({ code: 'resource_limit' });
    expect(mappings.values.has(VAULT_TRANSFER_JOURNAL_STORE_KEY)).toBe(false);
    expect(mappings.set).not.toHaveBeenCalled();

    const invalid = createFixture();
    await expect(invalid.journal.begin(beginInput(), [{
      kind: 'item',
      sourceIndex: 1,
      password: 'must-not-persist',
    }] as never)).rejects.toThrow(TypeError);
    expect(invalid.values.has(VAULT_TRANSFER_JOURNAL_STORE_KEY)).toBe(false);
    expect(invalid.set).not.toHaveBeenCalled();
  });

  it('atomically rejects a complete plan that exceeds bytes left by completed journals', async () => {
    const seedMemory = memoryStore();
    const seed = createFixture({ maxJournals: 2 }, seedMemory).journal;
    await seed.begin(beginInput());
    await seed.complete(TRANSFER_A, ACCOUNT_A);
    const completedState = structuredClone(
      seedMemory.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY),
    );

    const probeMemory = memoryStore(completedState);
    const probe = createFixture({
      maxJournals: 2,
      maxOutcomes: 2,
      maxMappings: 2,
    }, probeMemory).journal;
    await probe.begin({ ...beginInput(TRANSFER_B), sourceDigest: SOURCE_B });
    const preparedBytes = storedBytes(probeMemory.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY));

    const constrainedMemory = memoryStore(completedState);
    const constrained = createFixture({
      maxJournals: 2,
      maxOutcomes: 2,
      maxMappings: 2,
      maxStoredBytes: preparedBytes,
    }, constrainedMemory).journal;
    await expect(constrained.begin(
      { ...beginInput(TRANSFER_B), sourceDigest: SOURCE_B },
      [
        { kind: 'folder', sourceIndex: 0 },
        { kind: 'item', sourceIndex: 1 },
      ],
    )).rejects.toMatchObject({ code: 'resource_limit' });
    expect(constrainedMemory.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY))
      .toEqual(completedState);
    expect(constrainedMemory.set).not.toHaveBeenCalled();
    await expect(constrained.getSummary(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      phase: 'completed',
    });
    await expect(constrained.getSummary(TRANSFER_B, ACCOUNT_A)).rejects.toMatchObject({
      code: 'not_found',
    });
  });

  it('preflights completion and result delivery bytes for an empty plan', async () => {
    const probeMemory = memoryStore();
    await createFixture({}, probeMemory).journal.begin(beginInput(), []);
    const preparedBytes = storedBytes(probeMemory.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY));

    const constrained = createFixture({ maxStoredBytes: preparedBytes });
    await expect(constrained.journal.begin(beginInput(), []))
      .rejects.toMatchObject({ code: 'resource_limit' });
    expect(constrained.values.has(VAULT_TRANSFER_JOURNAL_STORE_KEY)).toBe(false);
    expect(constrained.set).not.toHaveBeenCalled();
  });

  it('turns an MV3-interrupted POST into outcome_unknown and never auto-resumes', async () => {
    const memory = memoryStore();
    const first = createFixture({}, memory);
    await first.journal.begin(beginInput());
    const inFlight = await first.journal.markInFlight(operationInput(
      TRANSFER_A,
      ACCOUNT_A,
      'attachment',
      7,
    ));

    const restarted = createFixture({ now: () => 500 }, memory).journal;
    const startup = await restarted.inspectForStartup();
    expect(startup).toMatchObject({
      kind: 'valid',
      requiresReconcile: true,
      autoResume: false,
      journals: [{
        transferId: TRANSFER_A,
        phase: 'reconcile_required',
        requiresReconcile: true,
        autoResume: false,
        inFlight: null,
        outcomeCount: 1,
      }],
    });
    const page = await restarted.getOutcomePage(TRANSFER_A, ACCOUNT_A, 0);
    expect(page.outcomes).toEqual([expect.objectContaining({
      operationId: inFlight.operationId,
      kind: 'attachment',
      sourceIndex: 7,
      status: 'outcome_unknown',
      code: 'service_worker_restarted',
    })]);
    await expect(restarted.markInFlight(operationInput())).rejects.toMatchObject({
      code: 'reconcile_required',
    });

    const secondRestart = createFixture({ now: () => 600 }, memory).journal;
    const repeatedStartup = await secondRestart.inspectForStartup();
    expect(repeatedStartup.kind).toBe('valid');
    await expect(secondRestart.getOutcomePage(TRANSFER_A, ACCOUNT_A, 0)).resolves.toMatchObject({
      outcomeCount: 1,
    });

    await expect(secondRestart.acknowledgeReconciled(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      phase: 'completed',
      requiresReconcile: false,
    });
  });

  it('also requires reconciliation after restart when known writes were only partially completed', async () => {
    const memory = memoryStore();
    const first = createFixture({}, memory).journal;
    await first.begin(beginInput());
    const post = await first.markInFlight(operationInput());
    await first.settleInFlight({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      operationId: post.operationId,
      status: 'committed',
    });

    const startup = await createFixture({}, memory).journal.inspectForStartup();
    expect(startup).toMatchObject({
      kind: 'valid',
      requiresReconcile: true,
      journals: [{ phase: 'reconcile_required', outcomeCount: 1 }],
    });
  });

  it('removes unrecoverable prepared journals on startup even at the stored-byte boundary', async () => {
    const memory = memoryStore();
    await createFixture({ maxJournals: 1 }, memory).journal.begin(beginInput());
    const preparedBytes = storedBytes(memory.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY));

    const restarted = createFixture({
      maxJournals: 1,
      maxStoredBytes: preparedBytes,
    }, memory).journal;
    await expect(restarted.inspectForStartup()).resolves.toEqual({
      kind: 'none',
      requiresReconcile: false,
      autoResume: false,
      journals: [],
    });
    await expect(restarted.getSummary(TRANSFER_A, ACCOUNT_A)).rejects.toMatchObject({
      code: 'not_found',
    });
  });

  it('rejects cross-account reads and mutations without changing durable state', async () => {
    const fixture = createFixture();
    await fixture.journal.begin(beginInput());
    const before = structuredClone(fixture.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY));

    await expect(fixture.journal.getSummary(TRANSFER_A, ACCOUNT_B)).rejects.toMatchObject({
      code: 'cross_account',
    });
    await expect(fixture.journal.markInFlight(operationInput(
      TRANSFER_A,
      ACCOUNT_B,
    ))).rejects.toMatchObject({ code: 'cross_account' });
    await expect(fixture.journal.cancel(TRANSFER_A, ACCOUNT_B)).rejects.toMatchObject({
      code: 'cross_account',
    });
    expect(fixture.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY)).toEqual(before);
  });

  it('binds settlement to operationId so a stale response cannot settle a newer POST', async () => {
    const fixture = createFixture();
    await fixture.journal.begin(beginInput());
    const oldOperation = await fixture.journal.markInFlight(operationInput(
      TRANSFER_A,
      ACCOUNT_A,
      'item',
      0,
    ));
    await fixture.journal.settleInFlight({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      operationId: oldOperation.operationId,
      status: 'rejected',
      code: 'validation_failed',
    });
    const currentOperation = await fixture.journal.markInFlight(operationInput(
      TRANSFER_A,
      ACCOUNT_A,
      'item',
      1,
    ));

    await expect(fixture.journal.settleInFlight({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      operationId: oldOperation.operationId,
      status: 'committed',
    })).rejects.toMatchObject({ code: 'in_flight_mismatch' });
    await expect(fixture.journal.getSummary(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      inFlight: currentOperation,
    });
    await expect(fixture.journal.settleInFlight({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      operationId: currentOperation.operationId,
      status: 'committed',
    })).resolves.toMatchObject({ sourceIndex: 1, status: 'committed' });
  });

  it('keeps a durable in-flight marker when result persistence is ambiguous', async () => {
    const memory = memoryStore();
    const fixture = createFixture({}, memory);
    await fixture.journal.begin(beginInput());
    const operation = await fixture.journal.markInFlight(operationInput());
    const storageError = new Error('storage write was interrupted');
    fixture.set.mockRejectedValueOnce(storageError);

    await expect(fixture.journal.settleInFlight({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      operationId: operation.operationId,
      status: 'committed',
    })).rejects.toBe(storageError);

    const restarted = createFixture({}, memory).journal;
    await expect(restarted.getSummary(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      inFlight: operation,
      phase: 'committing',
    });
    await expect(restarted.inspectForStartup()).resolves.toMatchObject({
      kind: 'valid',
      requiresReconcile: true,
      journals: [{ phase: 'reconcile_required', outcomeCount: 1 }],
    });
  });

  it('does not authorize a POST when persisting its write-ahead marker fails', async () => {
    const memory = memoryStore();
    const fixture = createFixture({}, memory);
    await fixture.journal.begin(beginInput());
    const storageError = new Error('storage unavailable');
    fixture.set.mockRejectedValueOnce(storageError);

    await expect(fixture.journal.markInFlight(operationInput())).rejects.toBe(storageError);
    const restarted = createFixture({}, memory).journal;
    await expect(restarted.getSummary(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      phase: 'prepared',
      inFlight: null,
      outcomeCount: 0,
    });
  });

  it('fails closed for corrupt and future state without replacing it', async () => {
    const candidates = [
      { stored: { schemaVersion: 1, journals: 'invalid' }, reason: 'corrupt_state', code: 'corrupt_state' },
      { stored: { schemaVersion: 2, journals: [], future: true }, reason: 'unsupported_schema', code: 'unsupported_schema' },
      { stored: null, reason: 'corrupt_state', code: 'corrupt_state' },
    ] as const;

    for (const candidate of candidates) {
      const memory = memoryStore(candidate.stored);
      const journal = createFixture({}, memory).journal;
      await expect(journal.inspectForStartup()).resolves.toEqual({
        kind: 'invalid',
        reason: candidate.reason,
        requiresReconcile: true,
        autoResume: false,
        journals: [],
      });
      await expect(journal.begin(beginInput())).rejects.toMatchObject({ code: candidate.code });
      expect(memory.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY)).toEqual(candidate.stored);
      expect(memory.set).not.toHaveBeenCalled();
    }
  });

  it('rejects tampered phase, unknown fields, alias relationships, and outcome sequences', async () => {
    const base = createFixture({ outcomePageSize: 1 });
    await base.journal.begin(beginInput());
    const operation = await base.journal.markInFlight(operationInput(
      TRANSFER_A,
      ACCOUNT_A,
      'folder',
      3,
    ));
    await base.journal.settleInFlight({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      operationId: operation.operationId,
      status: 'committed',
    });
    const valid = base.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY) as {
      journals: Array<Record<string, unknown>>;
    };

    const mutations: Array<(state: typeof valid) => void> = [
      (state) => { state.journals[0]!.futureSecret = 'must reject'; },
      (state) => { state.journals[0]!.autoResume = true; },
      (state) => { state.journals[0]!.replayBarrier = false; },
      (state) => { state.journals[0]!.unresolvedOutcomeUnknown = true; },
      (state) => { state.journals[0]!.phase = 'prepared'; },
      (state) => {
        const pages = state.journals[0]!.outcomePages as Array<Array<Record<string, unknown>>>;
        pages[0]![0]!.sequence = 4;
      },
      (state) => {
        const aliases = state.journals[0]!.folderAliases as Array<Record<string, unknown>>;
        aliases[0]!.alias = '00000000-0000-4000-8000-999999999999';
      },
    ];

    for (const mutate of mutations) {
      const tampered = structuredClone(valid);
      mutate(tampered);
      const memory = memoryStore(tampered);
      const journal = createFixture({ outcomePageSize: 1 }, memory).journal;
      await expect(journal.inspectForStartup()).resolves.toMatchObject({
        kind: 'invalid',
        requiresReconcile: true,
      });
      expect(memory.set).not.toHaveBeenCalled();
    }
  });

  it('enforces journal, outcome, mapping, and stored-byte resource limits', async () => {
    const capacity = createFixture({ maxJournals: 1 });
    await capacity.journal.begin(beginInput());
    await expect(capacity.journal.begin({
      ...beginInput(TRANSFER_B),
      sourceDigest: SOURCE_B,
    })).rejects.toMatchObject({ code: 'capacity' });

    const outcomes = createFixture({ maxOutcomes: 2, outcomePageSize: 1 });
    await outcomes.journal.begin(beginInput());
    await outcomes.journal.recordSkipped({
      ...operationInput(TRANSFER_A, ACCOUNT_A, 'item', 0),
      code: 'dependency_failed',
    });
    await outcomes.journal.recordSkipped({
      ...operationInput(TRANSFER_A, ACCOUNT_A, 'item', 1),
      code: 'dependency_failed',
    });
    await expect(outcomes.journal.recordSkipped({
      ...operationInput(TRANSFER_A, ACCOUNT_A, 'item', 2),
      code: 'dependency_failed',
    })).rejects.toMatchObject({ code: 'resource_limit' });
    await expect(outcomes.journal.markInFlight(operationInput(
      TRANSFER_A,
      ACCOUNT_A,
      'item',
      2,
    ))).rejects.toMatchObject({ code: 'resource_limit' });

    const mappings = createFixture({ maxMappings: 1 });
    await mappings.journal.begin(beginInput());
    const folder = await mappings.journal.markInFlight(operationInput(
      TRANSFER_A,
      ACCOUNT_A,
      'folder',
      0,
    ));
    await mappings.journal.settleInFlight({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      operationId: folder.operationId,
      status: 'committed',
    });
    await expect(mappings.journal.markInFlight(operationInput(
      TRANSFER_A,
      ACCOUNT_A,
      'item',
      1,
    ))).rejects.toMatchObject({ code: 'resource_limit' });
    await expect(mappings.journal.getSummary(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      inFlight: null,
      folderMappingCount: 1,
      itemMappingCount: 0,
    });

    const oversized = {
      schemaVersion: 1,
      journals: [],
      padding: 'x'.repeat(1_000),
    };
    const oversizedMemory = memoryStore(oversized);
    const byteLimited = createFixture({ maxStoredBytes: 128 }, oversizedMemory).journal;
    await expect(byteLimited.inspectForStartup()).resolves.toMatchObject({
      kind: 'invalid',
      reason: 'resource_limit',
    });
    expect(oversizedMemory.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY)).toEqual(oversized);
  });

  it('preserves write evidence on cancellation and removes only terminal journals', async () => {
    const untouched = createFixture();
    await untouched.journal.begin(beginInput());
    await expect(untouched.journal.cancel(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      phase: 'cancelled',
      requiresReconcile: false,
    });
    await expect(untouched.journal.remove(TRANSFER_A, ACCOUNT_A)).resolves.toBeUndefined();
    await expect(untouched.journal.inspectForStartup()).resolves.toMatchObject({ kind: 'none' });

    const interrupted = createFixture();
    await interrupted.journal.begin(beginInput());
    const operation = await interrupted.journal.markInFlight(operationInput());
    await expect(interrupted.journal.cancel(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      phase: 'reconcile_required',
      requiresReconcile: true,
      inFlight: null,
      outcomeCount: 1,
    });
    const page = await interrupted.journal.getOutcomePage(TRANSFER_A, ACCOUNT_A, 0);
    expect(page.outcomes[0]).toMatchObject({
      operationId: operation.operationId,
      status: 'outcome_unknown',
      code: 'cancelled_during_request',
    });
    await expect(interrupted.journal.remove(TRANSFER_A, ACCOUNT_A)).rejects.toMatchObject({
      code: 'reconcile_required',
    });
  });

  it('never evicts a reconciled outcome-unknown tombstone to begin another journal', async () => {
    const fixture = createFixture({ maxJournals: 1 });
    await fixture.journal.begin(beginInput());
    const operation = await fixture.journal.markInFlight(operationInput(
      TRANSFER_A,
      ACCOUNT_A,
      'attachment',
      3,
    ));
    await fixture.journal.settleInFlight({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      operationId: operation.operationId,
      status: 'outcome_unknown',
      code: 'response_lost',
    });
    await expect(fixture.journal.acknowledgeReconciled(
      TRANSFER_A,
      ACCOUNT_A,
    )).resolves.toMatchObject({
      phase: 'completed',
      replayBarrier: true,
      unresolvedOutcomeUnknown: true,
      resultDeliveredAt: null,
    });
    await expect(fixture.journal.acknowledgeResultDelivered(
      TRANSFER_A,
      ACCOUNT_A,
    )).resolves.toMatchObject({
      phase: 'completed',
      replayBarrier: true,
      unresolvedOutcomeUnknown: true,
      resultDeliveredAt: 100,
    });
    const tombstone = structuredClone(
      fixture.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY),
    );
    fixture.set.mockClear();

    await expect(fixture.journal.remove(TRANSFER_A, ACCOUNT_A)).rejects.toMatchObject({
      code: 'invalid_phase',
    });

    await expect(fixture.journal.begin({
      ...beginInput(TRANSFER_B),
      sourceDigest: SOURCE_B,
    })).rejects.toMatchObject({ code: 'capacity' });
    expect(fixture.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY)).toEqual(tombstone);
    expect(fixture.set).not.toHaveBeenCalled();
    await expect(fixture.journal.getSummary(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      phase: 'completed',
      requiresReconcile: false,
      replayBarrier: true,
      unresolvedOutcomeUnknown: true,
      resultDeliveredAt: 100,
      outcomeCount: 1,
    });

    await expect(fixture.journal.clearReplayBarrier(
      TRANSFER_A,
      ACCOUNT_A,
    )).resolves.toMatchObject({
      replayBarrier: false,
      unresolvedOutcomeUnknown: false,
      resultDeliveredAt: 100,
    });
    await expect(fixture.journal.begin({
      ...beginInput(TRANSFER_B),
      sourceDigest: SOURCE_B,
    })).resolves.toMatchObject({ transferId: TRANSFER_B, phase: 'prepared' });
  });

  it('retains known completed results until delivery is durably acknowledged', async () => {
    const fixture = createFixture({ maxJournals: 1 });
    await fixture.journal.begin(beginInput(), [{ kind: 'item', sourceIndex: 2 }]);
    const operation = await fixture.journal.markInFlight(operationInput(
      TRANSFER_A,
      ACCOUNT_A,
      'item',
      2,
    ));
    await fixture.journal.settleInFlight({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      operationId: operation.operationId,
      status: 'committed',
    });
    await expect(fixture.journal.complete(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      phase: 'completed',
      replayBarrier: true,
      unresolvedOutcomeUnknown: false,
      resultDeliveredAt: null,
    });

    await expect(fixture.journal.inspectForStartup()).resolves.toMatchObject({
      kind: 'valid',
      requiresReconcile: false,
      journals: [{
        transferId: TRANSFER_A,
        replayBarrier: true,
        unresolvedOutcomeUnknown: false,
        resultDeliveredAt: null,
      }],
    });
    await expect(fixture.journal.begin({
      ...beginInput(TRANSFER_B),
      sourceDigest: SOURCE_B,
    })).rejects.toMatchObject({ code: 'capacity' });
    await expect(fixture.journal.remove(TRANSFER_A, ACCOUNT_A)).rejects.toMatchObject({
      code: 'invalid_phase',
    });

    fixture.setNow(200);
    await expect(fixture.journal.acknowledgeResultDelivered(
      TRANSFER_A,
      ACCOUNT_A,
    )).resolves.toMatchObject({
      phase: 'completed',
      replayBarrier: false,
      unresolvedOutcomeUnknown: false,
      resultDeliveredAt: 200,
    });
    await expect(fixture.journal.remove(TRANSFER_A, ACCOUNT_A)).resolves.toBeUndefined();
  });

  it('drops the temporary in-flight barrier when every POST is rejected', async () => {
    const fixture = createFixture();
    await fixture.journal.begin(beginInput(), [{ kind: 'item', sourceIndex: 0 }]);
    const operation = await fixture.journal.markInFlight(operationInput());
    await expect(fixture.journal.getSummary(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      replayBarrier: true,
      unresolvedOutcomeUnknown: false,
    });
    await fixture.journal.settleInFlight({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      operationId: operation.operationId,
      status: 'rejected',
      code: 'rejected',
    });
    await expect(fixture.journal.complete(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      phase: 'completed',
      replayBarrier: false,
      unresolvedOutcomeUnknown: false,
      resultDeliveredAt: null,
    });
  });

  it('lets a full successful result acknowledgement clear a previously reviewed barrier', async () => {
    const fixture = createFixture();
    await fixture.journal.begin(beginInput());
    const operation = await fixture.journal.markInFlight(operationInput());
    await fixture.journal.settleInFlight({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      operationId: operation.operationId,
      status: 'committed',
    });
    await fixture.journal.complete(TRANSFER_A, ACCOUNT_A);
    fixture.setNow(250);
    await expect(fixture.journal.acknowledgeReplayBarrierReconciled(
      TRANSFER_A,
      ACCOUNT_A,
    )).resolves.toMatchObject({
      replayBarrier: true,
      reconciledAt: 250,
      resultDeliveredAt: null,
    });
    fixture.setNow(251);
    await expect(fixture.journal.acknowledgeResultDelivered(
      TRANSFER_A,
      ACCOUNT_A,
    )).resolves.toMatchObject({
      replayBarrier: false,
      unresolvedOutcomeUnknown: false,
      reconciledAt: 250,
      resultDeliveredAt: 251,
    });
  });

  it('retains a known partial-result barrier after delivery and reconciliation in either order', async () => {
    const createPartial = async (transferId: string): Promise<JournalFixture> => {
      const fixture = createFixture();
      await fixture.journal.begin(beginInput(transferId), [{ kind: 'item', sourceIndex: 0 }]);
      const operation = await fixture.journal.markInFlight(operationInput(
        transferId,
        ACCOUNT_A,
        'item',
        0,
      ));
      await fixture.journal.settleInFlight({
        transferId,
        accountIdentityDigest: ACCOUNT_A,
        operationId: operation.operationId,
        status: 'committed',
      });
      await expect(fixture.journal.complete(transferId, ACCOUNT_A, {
        requiresReconcile: true,
      })).resolves.toMatchObject({
        phase: 'reconcile_required',
        requiresReconcile: true,
        replayBarrier: true,
      });
      return fixture;
    };

    const deliveredFirst = await createPartial(TRANSFER_A);
    deliveredFirst.setNow(200);
    await expect(deliveredFirst.journal.acknowledgeResultDelivered(
      TRANSFER_A,
      ACCOUNT_A,
    )).resolves.toMatchObject({
      phase: 'reconcile_required',
      replayBarrier: true,
      resultDeliveredAt: 200,
    });
    deliveredFirst.setNow(201);
    await expect(deliveredFirst.journal.acknowledgeReconciled(
      TRANSFER_A,
      ACCOUNT_A,
    )).resolves.toMatchObject({
      phase: 'completed',
      requiresReconcile: false,
      replayBarrier: true,
      resultDeliveredAt: 200,
      reconciledAt: 201,
    });
    await expect(deliveredFirst.journal.clearReplayBarrier(
      TRANSFER_A,
      ACCOUNT_A,
    )).resolves.toMatchObject({ replayBarrier: false });

    const reconciledFirst = await createPartial(TRANSFER_B);
    reconciledFirst.setNow(300);
    await expect(reconciledFirst.journal.acknowledgeReconciled(
      TRANSFER_B,
      ACCOUNT_A,
    )).resolves.toMatchObject({
      phase: 'completed',
      replayBarrier: true,
      resultDeliveredAt: null,
      reconciledAt: 300,
    });
    reconciledFirst.setNow(301);
    await expect(reconciledFirst.journal.acknowledgeResultDelivered(
      TRANSFER_B,
      ACCOUNT_A,
    )).resolves.toMatchObject({
      phase: 'completed',
      replayBarrier: true,
      resultDeliveredAt: 301,
      reconciledAt: 300,
    });
    await expect(reconciledFirst.journal.clearReplayBarrier(
      TRANSFER_B,
      ACCOUNT_A,
    )).resolves.toMatchObject({ replayBarrier: false });
  });

  it('requires a reconciliation review before manually clearing a completed barrier', async () => {
    const fixture = createFixture();
    await fixture.journal.begin(beginInput());
    const operation = await fixture.journal.markInFlight(operationInput());
    await fixture.journal.settleInFlight({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      operationId: operation.operationId,
      status: 'committed',
    });
    await fixture.journal.complete(TRANSFER_A, ACCOUNT_A);

    await expect(fixture.journal.clearReplayBarrier(
      TRANSFER_A,
      ACCOUNT_A,
    )).rejects.toMatchObject({ code: 'invalid_phase' });
    fixture.setNow(400);
    await expect(fixture.journal.acknowledgeReplayBarrierReconciled(
      TRANSFER_A,
      ACCOUNT_A,
    )).resolves.toMatchObject({
      replayBarrier: true,
      resultDeliveredAt: null,
      reconciledAt: 400,
    });
    await expect(fixture.journal.clearReplayBarrier(
      TRANSFER_A,
      ACCOUNT_A,
    )).resolves.toMatchObject({
      replayBarrier: false,
      resultDeliveredAt: null,
      reconciledAt: 400,
    });
  });

  it('still evicts terminal journals that never formed a replay barrier', async () => {
    const fixture = createFixture({ maxJournals: 1 });
    await fixture.journal.begin(beginInput());
    await expect(fixture.journal.complete(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      phase: 'completed',
      replayBarrier: false,
      unresolvedOutcomeUnknown: false,
      resultDeliveredAt: null,
    });
    await expect(fixture.journal.begin({
      ...beginInput(TRANSFER_B),
      sourceDigest: SOURCE_B,
    })).resolves.toMatchObject({ transferId: TRANSFER_B, phase: 'prepared' });
    await expect(fixture.journal.getSummary(TRANSFER_A, ACCOUNT_A)).rejects.toMatchObject({
      code: 'not_found',
    });
  });

  it('never reopens a completed journal as reconcile-required', async () => {
    const fixture = createFixture();
    await fixture.journal.begin(beginInput());
    await fixture.journal.complete(TRANSFER_A, ACCOUNT_A);
    const completed = structuredClone(fixture.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY));
    fixture.set.mockClear();

    await expect(fixture.journal.complete(TRANSFER_A, ACCOUNT_A, {
      requiresReconcile: true,
    })).rejects.toMatchObject({ code: 'invalid_phase' });
    expect(fixture.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY)).toEqual(completed);
    expect(fixture.set).not.toHaveBeenCalled();
    await expect(fixture.journal.inspectForStartup()).resolves.toMatchObject({
      kind: 'valid',
      journals: [{ transferId: TRANSFER_A, phase: 'completed' }],
    });
  });

  it('allows export journaling to complete but never accepts import POST markers', async () => {
    const fixture = createFixture();
    await fixture.journal.begin({
      ...beginInput(),
      direction: 'export',
    });
    await expect(fixture.journal.markInFlight(operationInput())).rejects.toMatchObject({
      code: 'invalid_phase',
    });
    await expect(fixture.journal.complete(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      phase: 'completed',
    });
  });

  it('serializes concurrent result writes into stable pages', async () => {
    const fixture = createFixture({ outcomePageSize: 2 });
    await fixture.journal.begin(beginInput());
    await Promise.all([0, 1, 2, 3, 4].map((sourceIndex) => fixture.journal.recordSkipped({
      ...operationInput(TRANSFER_A, ACCOUNT_A, 'item', sourceIndex),
      code: 'dependency_failed',
    })));

    await expect(fixture.journal.getSummary(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      outcomeCount: 5,
      outcomePageCount: 3,
    });
    const pages = await Promise.all([0, 1, 2].map((page) => (
      fixture.journal.getOutcomePage(TRANSFER_A, ACCOUNT_A, page)
    )));
    expect(pages.flatMap((page) => page.outcomes.map((outcome) => outcome.sequence)))
      .toEqual([0, 1, 2, 3, 4]);
  });

  it('shares one read-modify-write queue across journal instances using the same store and key', async () => {
    const memory = memoryStore();
    const first = createFixture({ outcomePageSize: 2 }, memory).journal;
    const second = createFixture({ outcomePageSize: 2 }, memory).journal;
    await first.begin(beginInput());

    await Promise.all([
      first.recordSkipped({
        ...operationInput(TRANSFER_A, ACCOUNT_A, 'item', 0),
        code: 'dependency_failed',
      }),
      second.recordSkipped({
        ...operationInput(TRANSFER_A, ACCOUNT_A, 'item', 1),
        code: 'dependency_failed',
      }),
    ]);

    await expect(first.getSummary(TRANSFER_A, ACCOUNT_A)).resolves.toMatchObject({
      outcomeCount: 2,
    });
    const page = await second.getOutcomePage(TRANSFER_A, ACCOUNT_A, 0);
    expect(page.outcomes.map((outcome) => outcome.sourceIndex)).toEqual([0, 1]);
  });

  it('reserves committed, outcome_unknown, and maximum rejected WAL shapes before a POST', async () => {
    const maximumTimestamp = Number.MAX_SAFE_INTEGER;
    const seedMemory = memoryStore();
    const seed = createFixture({ now: () => maximumTimestamp }, seedMemory).journal;
    await seed.begin(beginInput());
    const begunState = structuredClone(seedMemory.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY));
    const operation = await seed.markInFlight(operationInput(
      TRANSFER_A,
      ACCOUNT_A,
      'attachment',
      0,
    ));
    const markerState = structuredClone(seedMemory.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY));
    const reservedMarkerBytes = storedBytes(markerState);
    const unreservedMarkerState = structuredClone(markerState) as {
      journals: Array<{ inFlight: { settlementReserve: string } | null }>;
    };
    const unreservedInFlight = unreservedMarkerState.journals[0]?.inFlight;
    expect(unreservedInFlight).not.toBeNull();
    if (unreservedInFlight) unreservedInFlight.settlementReserve = '';
    const markerBytes = storedBytes(unreservedMarkerState);

    const settledBytes = async (
      status: 'committed' | 'rejected' | 'outcome_unknown',
      code?: string,
    ): Promise<number> => {
      const memory = memoryStore(markerState);
      const journal = createFixture({ now: () => maximumTimestamp }, memory).journal;
      await journal.settleInFlight({
        transferId: TRANSFER_A,
        accountIdentityDigest: ACCOUNT_A,
        operationId: operation.operationId,
        status,
        ...(code === undefined ? {} : { code }),
      });
      return storedBytes(memory.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY));
    };
    const committedBytes = await settledBytes('committed');
    const unknownBytes = await settledBytes('outcome_unknown', 'u'.repeat(128));
    const rejectedBytes = await settledBytes('rejected', 'r'.repeat(128));
    expect(reservedMarkerBytes).toBeGreaterThanOrEqual(committedBytes);
    expect(reservedMarkerBytes).toBeGreaterThanOrEqual(unknownBytes);
    expect(reservedMarkerBytes).toBeGreaterThanOrEqual(rejectedBytes);

    const constrainedMemory = memoryStore(begunState);
    const constrained = createFixture({
      now: () => maximumTimestamp,
      maxStoredBytes: markerBytes,
    }, constrainedMemory).journal;
    await expect(constrained.markInFlight(operationInput(
      TRANSFER_A,
      ACCOUNT_A,
      'attachment',
      0,
    ))).rejects.toMatchObject({ code: 'resource_limit' });
    expect(constrainedMemory.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY)).toEqual(begunState);

    const interruptedMemory = memoryStore(unreservedMarkerState);
    const interrupted = createFixture({
      now: () => maximumTimestamp,
      maxStoredBytes: markerBytes,
    }, interruptedMemory).journal;
    await expect(interrupted.inspectForStartup()).resolves.toEqual({
      kind: 'invalid',
      reason: 'resource_limit',
      requiresReconcile: true,
      autoResume: false,
      journals: [],
    });
    expect(interruptedMemory.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY))
      .toEqual(unreservedMarkerState);
  });

  it('rejects duplicate sources, concurrent in-flight operations, and secret-shaped extra fields', async () => {
    const fixture = createFixture();
    await fixture.journal.begin(beginInput());
    const operation = await fixture.journal.markInFlight(operationInput());
    await expect(fixture.journal.markInFlight(operationInput(
      TRANSFER_A,
      ACCOUNT_A,
      'item',
      1,
    ))).rejects.toMatchObject({ code: 'in_flight_exists' });
    await fixture.journal.settleInFlight({
      transferId: TRANSFER_A,
      accountIdentityDigest: ACCOUNT_A,
      operationId: operation.operationId,
      status: 'rejected',
      code: 'rejected',
    });
    await expect(fixture.journal.markInFlight(operationInput())).rejects.toMatchObject({
      code: 'duplicate_source',
    });

    await expect(fixture.journal.recordSkipped({
      ...operationInput(TRANSFER_A, ACCOUNT_A, 'item', 2),
      code: 'skipped',
      password: 'must-not-persist',
    } as never)).rejects.toThrow(TypeError);
    expect(JSON.stringify(fixture.values.get(VAULT_TRANSFER_JOURNAL_STORE_KEY)))
      .not.toContain('must-not-persist');
  });

  it('creates stable domain-separated account digests and validates canonical input', async () => {
    const first = await digestVaultTransferAccountIdentity('https://vault.example/\0user@example.com');
    const repeated = await digestVaultTransferAccountIdentity('https://vault.example/\0user@example.com');
    const other = await digestVaultTransferAccountIdentity('https://vault.example/\0other@example.com');
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(repeated).toBe(first);
    expect(other).not.toBe(first);
    await expect(digestVaultTransferAccountIdentity(' user@example.com')).rejects.toThrow(TypeError);
    await expect(digestVaultTransferAccountIdentity('x'.repeat(4_097))).rejects.toThrow(TypeError);
  });

  it('validates inputs and all configured bounds before mutating storage', async () => {
    const fixture = createFixture();
    await expect(fixture.journal.begin({
      ...beginInput(),
      transferId: 'not-a-uuid',
    })).rejects.toThrow(TypeError);
    await expect(fixture.journal.begin({
      ...beginInput(),
      accountIdentityDigest: ACCOUNT_A.toUpperCase(),
    })).rejects.toThrow(TypeError);
    expect(fixture.set).not.toHaveBeenCalled();

    const base = memoryStore().store;
    expect(() => new VaultTransferJournalStore(base, { maxJournals: 0 })).toThrow(RangeError);
    expect(() => new VaultTransferJournalStore(base, { maxJournals: MAX_VAULT_TRANSFER_JOURNALS + 1 })).toThrow(RangeError);
    expect(() => new VaultTransferJournalStore(base, { outcomePageSize: MAX_VAULT_TRANSFER_OUTCOME_PAGE_SIZE + 1 })).toThrow(RangeError);
    expect(() => new VaultTransferJournalStore(base, { maxOutcomes: MAX_VAULT_TRANSFER_OUTCOMES + 1 })).toThrow(RangeError);
    expect(() => new VaultTransferJournalStore(base, { maxMappings: MAX_VAULT_TRANSFER_MAPPINGS + 1 })).toThrow(RangeError);
    expect(() => new VaultTransferJournalStore(base, { maxStoredBytes: MAX_VAULT_TRANSFER_JOURNAL_BYTES + 1 })).toThrow(RangeError);
  });
});
