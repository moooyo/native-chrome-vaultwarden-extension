import type { KeyValueStore } from '../../platform/store.js';

export const VAULT_TRANSFER_JOURNAL_STORE_KEY = 'vaultTransferJournal';
export const VAULT_TRANSFER_JOURNAL_SCHEMA_VERSION = 1 as const;
export const DEFAULT_MAX_VAULT_TRANSFER_JOURNALS = 8;
export const MAX_VAULT_TRANSFER_JOURNALS = 32;
export const DEFAULT_VAULT_TRANSFER_OUTCOME_PAGE_SIZE = 64;
export const MAX_VAULT_TRANSFER_OUTCOME_PAGE_SIZE = 256;
// The journal is one atomic storage value, so bounds stay deliberately below bulk-database scale.
export const DEFAULT_MAX_VAULT_TRANSFER_OUTCOMES = 2_048;
export const MAX_VAULT_TRANSFER_OUTCOMES = 8_192;
export const DEFAULT_MAX_VAULT_TRANSFER_MAPPINGS = 2_048;
export const MAX_VAULT_TRANSFER_MAPPINGS = 8_192;
export const DEFAULT_MAX_VAULT_TRANSFER_JOURNAL_BYTES = 4 * 1024 * 1024;
export const MAX_VAULT_TRANSFER_JOURNAL_BYTES = 16 * 1024 * 1024;
export const MAX_VAULT_TRANSFER_OUTCOME_CODE_LENGTH = 128;

const MAX_SOURCE_INDEX = 10_000_000;
const MAX_IDENTITY_INPUT_LENGTH = 4_096;
const MAX_ID_GENERATION_ATTEMPTS = 32;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA_256_PATTERN = /^[0-9a-f]{64}$/;
const OUTCOME_CODE_PATTERN = /^[a-z0-9][a-z0-9._:-]*$/i;
const MAX_REJECTED_RESERVE_CODE = 'r'.repeat(MAX_VAULT_TRANSFER_OUTCOME_CODE_LENGTH);
const RESERVE_ALIAS = 'ffffffff-ffff-4fff-8fff-ffffffffffff';

interface SharedJournalQueue {
  tail: Promise<void>;
}

const SHARED_JOURNAL_QUEUES = new WeakMap<KeyValueStore, Map<string, SharedJournalQueue>>();

export type VaultTransferJournalDirection = 'import' | 'export';
export type VaultTransferJournalOperationKind = 'folder' | 'collection' | 'item' | 'attachment';
export type VaultTransferJournalOutcomeStatus =
  | 'committed'
  | 'rejected'
  | 'skipped'
  | 'outcome_unknown';
export type VaultTransferJournalPhase =
  | 'prepared'
  | 'committing'
  | 'reconcile_required'
  | 'completed'
  | 'cancelled';
export type VaultTransferJournalAliasKind = 'folder' | 'item';

export interface VaultTransferJournalInFlight {
  readonly operationId: string;
  readonly kind: VaultTransferJournalOperationKind;
  readonly sourceIndex: number;
  readonly startedAt: number;
}

export interface VaultTransferJournalOutcome {
  readonly sequence: number;
  readonly operationId: string | null;
  readonly kind: VaultTransferJournalOperationKind;
  readonly sourceIndex: number;
  readonly status: VaultTransferJournalOutcomeStatus;
  /** Stable machine code only. Imported values and server messages are never accepted. */
  readonly code: string | null;
  /** Locally generated correlation alias. This is never a remote object identifier. */
  readonly alias: string | null;
  readonly recordedAt: number;
}

export interface VaultTransferJournalSummary {
  readonly transferId: string;
  readonly direction: VaultTransferJournalDirection;
  readonly accountIdentityDigest: string;
  readonly sourceDigest: string;
  readonly phase: VaultTransferJournalPhase;
  readonly requiresReconcile: boolean;
  readonly replayBarrier: boolean;
  readonly unresolvedOutcomeUnknown: boolean;
  readonly autoResume: false;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly reconciledAt: number | null;
  readonly resultDeliveredAt: number | null;
  readonly inFlight: VaultTransferJournalInFlight | null;
  readonly outcomeCount: number;
  readonly outcomePageCount: number;
  readonly folderMappingCount: number;
  readonly itemMappingCount: number;
}

export interface VaultTransferJournalOutcomePage {
  readonly transferId: string;
  readonly pageIndex: number;
  readonly pageCount: number;
  readonly outcomeCount: number;
  readonly outcomes: readonly VaultTransferJournalOutcome[];
}

export interface BeginVaultTransferJournalInput {
  readonly transferId: string;
  readonly direction: VaultTransferJournalDirection;
  readonly accountIdentityDigest: string;
  readonly sourceDigest: string;
}

export interface VaultTransferJournalPlanEntry {
  readonly kind: VaultTransferJournalOperationKind;
  readonly sourceIndex: number;
}

export interface CompleteVaultTransferJournalOptions {
  readonly requiresReconcile?: boolean;
}

export interface MarkVaultTransferInFlightInput {
  readonly transferId: string;
  readonly accountIdentityDigest: string;
  readonly kind: VaultTransferJournalOperationKind;
  readonly sourceIndex: number;
}

export interface SettleVaultTransferInFlightInput {
  readonly transferId: string;
  readonly accountIdentityDigest: string;
  readonly operationId: string;
  readonly status: Exclude<VaultTransferJournalOutcomeStatus, 'skipped'>;
  readonly code?: string;
}

export interface RecordVaultTransferSkippedInput {
  readonly transferId: string;
  readonly accountIdentityDigest: string;
  readonly kind: VaultTransferJournalOperationKind;
  readonly sourceIndex: number;
  readonly code: string;
}

export interface VaultTransferJournalStoreOptions {
  readonly storageKey?: string;
  readonly now?: () => number;
  readonly createId?: () => string;
  readonly maxJournals?: number;
  readonly outcomePageSize?: number;
  readonly maxOutcomes?: number;
  readonly maxMappings?: number;
  readonly maxStoredBytes?: number;
}

export type VaultTransferJournalStartupInspection =
  | { readonly kind: 'none'; readonly requiresReconcile: false; readonly autoResume: false; readonly journals: readonly [] }
  | {
      readonly kind: 'valid';
      readonly requiresReconcile: boolean;
      readonly autoResume: false;
      readonly journals: readonly VaultTransferJournalSummary[];
    }
  | {
      readonly kind: 'invalid';
      readonly reason: 'corrupt_state' | 'unsupported_schema' | 'resource_limit';
      readonly requiresReconcile: true;
      readonly autoResume: false;
      readonly journals: readonly [];
    };

export type VaultTransferJournalErrorCode =
  | 'capacity'
  | 'journal_exists'
  | 'not_found'
  | 'cross_account'
  | 'invalid_phase'
  | 'in_flight_exists'
  | 'in_flight_mismatch'
  | 'duplicate_source'
  | 'resource_limit'
  | 'reconcile_required'
  | 'corrupt_state'
  | 'unsupported_schema';

export class VaultTransferJournalError extends Error {
  constructor(readonly code: VaultTransferJournalErrorCode, message: string) {
    super(message);
    this.name = 'VaultTransferJournalError';
  }
}

interface StoredAlias {
  sourceIndex: number;
  alias: string;
}

interface StoredInFlight extends VaultTransferJournalInFlight {
  settlementReserve: string;
}

interface StoredJournal {
  transferId: string;
  direction: VaultTransferJournalDirection;
  accountIdentityDigest: string;
  sourceDigest: string;
  phase: VaultTransferJournalPhase;
  requiresReconcile: boolean;
  replayBarrier: boolean;
  unresolvedOutcomeUnknown: boolean;
  requiresExplicitReplayBarrierClear: boolean;
  autoResume: false;
  createdAt: number;
  updatedAt: number;
  reconciledAt: number | null;
  resultDeliveredAt: number | null;
  inFlight: StoredInFlight | null;
  outcomePageSize: number;
  nextOutcomeSequence: number;
  outcomePages: VaultTransferJournalOutcome[][];
  folderAliases: StoredAlias[];
  itemAliases: StoredAlias[];
}

interface StoredState {
  schemaVersion: typeof VAULT_TRANSFER_JOURNAL_SCHEMA_VERSION;
  journals: StoredJournal[];
}

type ParsedState =
  | { readonly kind: 'empty'; readonly state: StoredState }
  | { readonly kind: 'valid'; readonly state: StoredState }
  | { readonly kind: 'corrupt' }
  | { readonly kind: 'unsupported' }
  | { readonly kind: 'resource_limit' };

/**
 * Secret-free write-ahead journal. Await markInFlight before each non-idempotent POST.
 *
 * Instances sharing the same KeyValueStore object and storage key also share an in-realm queue.
 * Production must still own one background singleton because separate store wrappers, realms, or
 * service-worker generations cannot provide cross-instance compare-and-swap through KeyValueStore.
 */
export class VaultTransferJournalStore {
  private readonly storageKey: string;
  private readonly now: () => number;
  private readonly createId: () => string;
  private readonly maxJournals: number;
  private readonly outcomePageSize: number;
  private readonly maxOutcomes: number;
  private readonly maxMappings: number;
  private readonly maxStoredBytes: number;
  private readonly sharedQueue: SharedJournalQueue;

  constructor(private readonly store: KeyValueStore, options: VaultTransferJournalStoreOptions = {}) {
    this.storageKey = options.storageKey ?? VAULT_TRANSFER_JOURNAL_STORE_KEY;
    this.now = options.now ?? (() => Date.now());
    this.createId = options.createId ?? (() => crypto.randomUUID());
    this.maxJournals = boundedPositiveInteger(options.maxJournals ?? DEFAULT_MAX_VAULT_TRANSFER_JOURNALS, 'maxJournals', MAX_VAULT_TRANSFER_JOURNALS);
    this.outcomePageSize = boundedPositiveInteger(options.outcomePageSize ?? DEFAULT_VAULT_TRANSFER_OUTCOME_PAGE_SIZE, 'outcomePageSize', MAX_VAULT_TRANSFER_OUTCOME_PAGE_SIZE);
    this.maxOutcomes = boundedPositiveInteger(options.maxOutcomes ?? DEFAULT_MAX_VAULT_TRANSFER_OUTCOMES, 'maxOutcomes', MAX_VAULT_TRANSFER_OUTCOMES);
    this.maxMappings = boundedPositiveInteger(options.maxMappings ?? DEFAULT_MAX_VAULT_TRANSFER_MAPPINGS, 'maxMappings', MAX_VAULT_TRANSFER_MAPPINGS);
    this.maxStoredBytes = boundedPositiveInteger(options.maxStoredBytes ?? DEFAULT_MAX_VAULT_TRANSFER_JOURNAL_BYTES, 'maxStoredBytes', MAX_VAULT_TRANSFER_JOURNAL_BYTES);
    if (!this.storageKey.trim()) throw new TypeError('storageKey must not be empty');
    this.sharedQueue = sharedJournalQueue(this.store, this.storageKey);
  }

  async begin(
    input: BeginVaultTransferJournalInput,
    plan: readonly VaultTransferJournalPlanEntry[] = [],
  ): Promise<VaultTransferJournalSummary> {
    const canonical = validateBeginInput(input);
    const planSnapshot = validateJournalPlan(plan);
    return this.serialize(async () => {
      const canonicalPlan = validateJournalPlan(planSnapshot);
      this.assertPlanWithinLimits(canonicalPlan);
      const state = await this.readWritableState();
      if (state.journals.some((journal) => journal.transferId === canonical.transferId)) {
        throw new VaultTransferJournalError('journal_exists', 'Transfer journal already exists');
      }
      while (state.journals.length >= this.maxJournals) {
        const terminalIndex = oldestEvictableTerminalJournalIndex(state.journals);
        if (terminalIndex < 0) break;
        state.journals.splice(terminalIndex, 1);
      }
      if (state.journals.length >= this.maxJournals) {
        throw new VaultTransferJournalError('capacity', `Transfer journal capacity (${this.maxJournals}) was reached`);
      }
      const timestamp = this.currentTimestamp();
      const journal: StoredJournal = {
        ...canonical,
        phase: 'prepared',
        requiresReconcile: false,
        replayBarrier: false,
        unresolvedOutcomeUnknown: false,
        requiresExplicitReplayBarrierClear: false,
        autoResume: false,
        createdAt: timestamp,
        updatedAt: timestamp,
        reconciledAt: null,
        resultDeliveredAt: null,
        inFlight: null,
        outcomePageSize: this.outcomePageSize,
        nextOutcomeSequence: 0,
        outcomePages: [],
        folderAliases: [],
        itemAliases: [],
      };
      state.journals.push(journal);
      this.assertPlanFitsStoredState(state, journal, canonicalPlan);
      await this.persist(state);
      return summarize(journal);
    });
  }

  /** Persist and await this marker before sending the corresponding POST. */
  async markInFlight(input: MarkVaultTransferInFlightInput): Promise<VaultTransferJournalInFlight> {
    const canonical = validateOperationInput(input);
    return this.serialize(async () => {
      const state = await this.readWritableState();
      const journal = requireJournal(state, canonical.transferId, canonical.accountIdentityDigest);
      if (journal.direction !== 'import' || !isWritablePhase(journal.phase)) {
        throw new VaultTransferJournalError(journal.requiresReconcile ? 'reconcile_required' : 'invalid_phase', 'Transfer journal is not accepting import writes');
      }
      if (journal.inFlight) throw new VaultTransferJournalError('in_flight_exists', 'A transfer POST is already awaiting a result');
      if (hasSourceOutcome(journal, canonical.kind, canonical.sourceIndex)) {
        throw new VaultTransferJournalError('duplicate_source', 'This transfer source was already resolved and cannot be retried');
      }
      if (journal.nextOutcomeSequence >= this.maxOutcomes) {
        throw new VaultTransferJournalError('resource_limit', 'Transfer outcome capacity was reached before a POST could be marked');
      }
      if ((canonical.kind === 'folder' || canonical.kind === 'item')
        && mappingCount(journal) >= this.maxMappings) {
        throw new VaultTransferJournalError('resource_limit', 'Transfer mapping capacity was reached before a POST could be marked');
      }
      const inFlight: StoredInFlight = {
        operationId: this.uniqueOpaqueId(state),
        kind: canonical.kind,
        sourceIndex: canonical.sourceIndex,
        startedAt: this.timestampFor(journal),
        settlementReserve: '',
      };
      journal.inFlight = inFlight;
      journal.phase = 'committing';
      journal.replayBarrier = true;
      journal.updatedAt = inFlight.startedAt;
      this.installWorstCaseSettlementReserve(state, journal);
      await this.persist(state);
      return exposeInFlight(inFlight);
    });
  }

  /** Atomically replace the exact in-flight marker with its source-indexed result. */
  async settleInFlight(input: SettleVaultTransferInFlightInput): Promise<VaultTransferJournalOutcome> {
    const canonical = validateSettlementInput(input);
    return this.serialize(async () => {
      const state = await this.readWritableState();
      const journal = requireJournal(state, canonical.transferId, canonical.accountIdentityDigest);
      const inFlight = journal.inFlight;
      if (!inFlight || inFlight.operationId !== canonical.operationId) {
        throw new VaultTransferJournalError('in_flight_mismatch', 'Operation identifier did not match the current in-flight POST');
      }
      if (!isWritablePhase(journal.phase)) {
        throw new VaultTransferJournalError('invalid_phase', 'Transfer journal cannot settle writes');
      }
      if (canonical.status === 'committed' && canonical.code !== null) {
        throw new TypeError('Committed outcomes must not include a code');
      }
      if (canonical.status !== 'committed' && canonical.code === null) {
        throw new TypeError('Non-committed outcomes require a stable code');
      }

      let alias: string | null = null;
      if (canonical.status === 'committed' && (inFlight.kind === 'folder' || inFlight.kind === 'item')) {
        if (mappingCount(journal) >= this.maxMappings) {
          throw new VaultTransferJournalError('resource_limit', 'Transfer mapping capacity was reached');
        }
        const target = inFlight.kind === 'folder' ? journal.folderAliases : journal.itemAliases;
        if (target.some((entry) => entry.sourceIndex === inFlight.sourceIndex)) {
          throw new VaultTransferJournalError('duplicate_source', 'This source already has a local mapping alias');
        }
        alias = this.uniqueOpaqueId(state);
        target.push({ sourceIndex: inFlight.sourceIndex, alias });
      }

      const outcome = createOutcome(
        journal,
        inFlight.operationId,
        inFlight.kind,
        inFlight.sourceIndex,
        canonical.status,
        canonical.code,
        alias,
        this.timestampFor(journal),
      );
      appendOutcome(journal, outcome, this.maxOutcomes);
      journal.inFlight = null;
      journal.replayBarrier = hasRemoteWriteEvidence(journal);
      journal.updatedAt = outcome.recordedAt;
      if (canonical.status === 'outcome_unknown') {
        journal.phase = 'reconcile_required';
        journal.requiresReconcile = true;
        journal.unresolvedOutcomeUnknown = true;
      } else {
        journal.phase = 'committing';
      }
      await this.persist(state);
      return { ...outcome };
    });
  }

  async recordSkipped(input: RecordVaultTransferSkippedInput): Promise<VaultTransferJournalOutcome> {
    const canonical = validateSkippedInput(input);
    return this.serialize(async () => {
      const state = await this.readWritableState();
      const journal = requireJournal(state, canonical.transferId, canonical.accountIdentityDigest);
      if (journal.direction !== 'import' || !isWritablePhase(journal.phase)) {
        throw new VaultTransferJournalError(journal.requiresReconcile ? 'reconcile_required' : 'invalid_phase', 'Transfer journal is not accepting import results');
      }
      if (journal.inFlight) throw new VaultTransferJournalError('in_flight_exists', 'A skipped result cannot pass an in-flight POST');
      if (hasSourceOutcome(journal, canonical.kind, canonical.sourceIndex)) {
        throw new VaultTransferJournalError('duplicate_source', 'This transfer source was already resolved');
      }
      const outcome = createOutcome(
        journal,
        null,
        canonical.kind,
        canonical.sourceIndex,
        'skipped',
        canonical.code,
        null,
        this.timestampFor(journal),
      );
      appendOutcome(journal, outcome, this.maxOutcomes);
      journal.phase = 'committing';
      journal.updatedAt = outcome.recordedAt;
      await this.persist(state);
      return { ...outcome };
    });
  }

  async complete(
    transferId: string,
    accountIdentityDigest: string,
    options: CompleteVaultTransferJournalOptions = {},
  ): Promise<VaultTransferJournalSummary> {
    const canonical = validateIdentityPair(transferId, accountIdentityDigest);
    const completion = validateCompleteOptions(options);
    return this.serialize(async () => {
      const state = await this.readWritableState();
      const journal = requireJournal(state, canonical.transferId, canonical.accountIdentityDigest);
      if (journal.inFlight) throw new VaultTransferJournalError('in_flight_exists', 'An in-flight POST must be settled before completion');
      if (journal.phase === 'cancelled') throw new VaultTransferJournalError('invalid_phase', 'Cancelled transfer cannot complete');
      if (journal.phase === 'completed') {
        if (completion.requiresReconcile) {
          throw new VaultTransferJournalError('invalid_phase', 'Completed transfer cannot re-enter reconciliation');
        }
        return summarize(journal);
      }
      if (journal.phase === 'reconcile_required' && completion.requiresReconcile) {
        return summarize(journal);
      }
      if (!completion.requiresReconcile && journal.requiresReconcile) {
        throw new VaultTransferJournalError('reconcile_required', 'Transfer must be reconciled before completion');
      }
      journal.phase = completion.requiresReconcile ? 'reconcile_required' : 'completed';
      journal.requiresReconcile = completion.requiresReconcile;
      journal.requiresExplicitReplayBarrierClear ||= completion.requiresReconcile
        && journal.replayBarrier;
      journal.updatedAt = this.timestampFor(journal);
      await this.persist(state);
      return summarize(journal);
    });
  }

  /** Cancel without discarding evidence of writes that may have reached the server. */
  async cancel(transferId: string, accountIdentityDigest: string): Promise<VaultTransferJournalSummary> {
    const canonical = validateIdentityPair(transferId, accountIdentityDigest);
    return this.serialize(async () => {
      const state = await this.readWritableState();
      const journal = requireJournal(state, canonical.transferId, canonical.accountIdentityDigest);
      if (journal.phase === 'completed' || journal.phase === 'cancelled') return summarize(journal);
      const timestamp = this.timestampFor(journal);
      if (journal.inFlight) {
        const inFlight = journal.inFlight;
        appendOutcome(journal, createOutcome(
          journal,
          inFlight.operationId,
          inFlight.kind,
          inFlight.sourceIndex,
          'outcome_unknown',
          'cancelled_during_request',
          null,
          timestamp,
        ), this.maxOutcomes);
        journal.inFlight = null;
        journal.unresolvedOutcomeUnknown = true;
      }
      if (hasRemoteWriteEvidence(journal) || journal.replayBarrier) {
        journal.phase = 'reconcile_required';
        journal.requiresReconcile = true;
        journal.requiresExplicitReplayBarrierClear ||= hasRemoteWriteEvidence(journal)
          && !journal.unresolvedOutcomeUnknown;
      } else {
        journal.phase = 'cancelled';
        journal.requiresReconcile = false;
      }
      journal.updatedAt = timestamp;
      await this.persist(state);
      return summarize(journal);
    });
  }

  async acknowledgeResultDelivered(
    transferId: string,
    accountIdentityDigest: string,
  ): Promise<VaultTransferJournalSummary> {
    const canonical = validateIdentityPair(transferId, accountIdentityDigest);
    return this.serialize(async () => {
      const state = await this.readWritableState();
      const journal = requireJournal(state, canonical.transferId, canonical.accountIdentityDigest);
      if ((journal.phase !== 'completed' && journal.phase !== 'reconcile_required')
        || journal.inFlight) {
        throw new VaultTransferJournalError(
          'invalid_phase',
          'Only finalized transfers can acknowledge result delivery',
        );
      }
      if (journal.resultDeliveredAt !== null) return summarize(journal);
      const timestamp = this.timestampFor(journal);
      journal.resultDeliveredAt = timestamp;
      if (journal.phase === 'completed'
        && !journal.unresolvedOutcomeUnknown
        && !journal.requiresExplicitReplayBarrierClear) {
        journal.replayBarrier = false;
      }
      journal.updatedAt = timestamp;
      await this.persist(state);
      return summarize(journal);
    });
  }

  async clearReplayBarrier(
    transferId: string,
    accountIdentityDigest: string,
  ): Promise<VaultTransferJournalSummary> {
    const canonical = validateIdentityPair(transferId, accountIdentityDigest);
    return this.serialize(async () => {
      const state = await this.readWritableState();
      const journal = requireJournal(state, canonical.transferId, canonical.accountIdentityDigest);
      if (journal.phase !== 'completed' || journal.inFlight || journal.reconciledAt === null) {
        throw new VaultTransferJournalError(
          'invalid_phase',
          'Replay barrier can be cleared only after a completed reconciliation review',
        );
      }
      if (!journal.replayBarrier) return summarize(journal);
      journal.replayBarrier = false;
      journal.unresolvedOutcomeUnknown = false;
      journal.requiresExplicitReplayBarrierClear = false;
      journal.updatedAt = this.timestampFor(journal);
      await this.persist(state);
      return summarize(journal);
    });
  }

  async acknowledgeReplayBarrierReconciled(
    transferId: string,
    accountIdentityDigest: string,
  ): Promise<VaultTransferJournalSummary> {
    const canonical = validateIdentityPair(transferId, accountIdentityDigest);
    return this.serialize(async () => {
      const state = await this.readWritableState();
      const journal = requireJournal(state, canonical.transferId, canonical.accountIdentityDigest);
      if (journal.phase !== 'completed' || journal.inFlight || !journal.replayBarrier) {
        throw new VaultTransferJournalError(
          'invalid_phase',
          'Transfer journal is not a completed replay barrier',
        );
      }
      if (journal.reconciledAt !== null) return summarize(journal);
      const timestamp = this.timestampFor(journal);
      journal.reconciledAt = timestamp;
      journal.updatedAt = timestamp;
      await this.persist(state);
      return summarize(journal);
    });
  }

  /** Mark a reconcile-required transfer terminal after an authoritative sync completes. */
  async acknowledgeReconciled(transferId: string, accountIdentityDigest: string): Promise<VaultTransferJournalSummary> {
    const canonical = validateIdentityPair(transferId, accountIdentityDigest);
    return this.serialize(async () => {
      const state = await this.readWritableState();
      const journal = requireJournal(state, canonical.transferId, canonical.accountIdentityDigest);
      if (journal.phase !== 'reconcile_required' || !journal.requiresReconcile || journal.inFlight) {
        throw new VaultTransferJournalError('invalid_phase', 'Transfer journal is not awaiting reconciliation');
      }
      journal.phase = 'completed';
      journal.requiresReconcile = false;
      const timestamp = this.timestampFor(journal);
      journal.reconciledAt = timestamp;
      journal.updatedAt = timestamp;
      await this.persist(state);
      return summarize(journal);
    });
  }

  async getSummary(transferId: string, accountIdentityDigest: string): Promise<VaultTransferJournalSummary> {
    const canonical = validateIdentityPair(transferId, accountIdentityDigest);
    return this.serialize(async () => {
      const state = await this.readReadableState();
      return summarize(requireJournal(state, canonical.transferId, canonical.accountIdentityDigest));
    });
  }

  async getOutcomePage(transferId: string, accountIdentityDigest: string, pageIndex: number): Promise<VaultTransferJournalOutcomePage> {
    const canonical = validateIdentityPair(transferId, accountIdentityDigest);
    if (!Number.isSafeInteger(pageIndex) || pageIndex < 0) throw new RangeError('pageIndex must be a non-negative safe integer');
    return this.serialize(async () => {
      const state = await this.readReadableState();
      const journal = requireJournal(state, canonical.transferId, canonical.accountIdentityDigest);
      const pageCount = journal.outcomePages.length;
      if ((pageCount === 0 && pageIndex !== 0) || (pageCount > 0 && pageIndex >= pageCount)) {
        throw new RangeError('pageIndex is outside the journal outcome pages');
      }
      return {
        transferId,
        pageIndex,
        pageCount,
        outcomeCount: journal.nextOutcomeSequence,
        outcomes: (journal.outcomePages[pageIndex] ?? []).map((outcome) => ({ ...outcome })),
      };
    });
  }

  async getAlias(transferId: string, accountIdentityDigest: string, kind: VaultTransferJournalAliasKind, sourceIndex: number): Promise<string | undefined> {
    const canonical = validateIdentityPair(transferId, accountIdentityDigest);
    assertAliasKind(kind);
    assertSourceIndex(sourceIndex);
    return this.serialize(async () => {
      const state = await this.readReadableState();
      const journal = requireJournal(state, canonical.transferId, canonical.accountIdentityDigest);
      const aliases = kind === 'folder' ? journal.folderAliases : journal.itemAliases;
      return aliases.find((entry) => entry.sourceIndex === sourceIndex)?.alias;
    });
  }

  async remove(transferId: string, accountIdentityDigest: string): Promise<void> {
    const canonical = validateIdentityPair(transferId, accountIdentityDigest);
    return this.serialize(async () => {
      const state = await this.readWritableState();
      const index = state.journals.findIndex((journal) => journal.transferId === transferId);
      const journal = state.journals[index];
      if (!journal) throw new VaultTransferJournalError('not_found', 'Transfer journal was not found');
      assertAccount(journal, canonical.accountIdentityDigest);
      if (journal.phase !== 'completed' && journal.phase !== 'cancelled') {
        throw new VaultTransferJournalError(journal.requiresReconcile ? 'reconcile_required' : 'invalid_phase', 'Only terminal transfer journals may be removed');
      }
      if (journal.replayBarrier) {
        throw new VaultTransferJournalError('invalid_phase', 'Replay barrier must be cleared before removal');
      }
      state.journals.splice(index, 1);
      await this.persist(state);
    });
  }

  /** Convert interrupted POSTs to outcome_unknown without reconstructing or resuming plaintext. */
  async inspectForStartup(): Promise<VaultTransferJournalStartupInspection> {
    return this.serialize(async () => {
      const parsed = this.parse(await this.store.get<unknown>(this.storageKey));
      if (parsed.kind === 'empty') {
        return { kind: 'none', requiresReconcile: false, autoResume: false, journals: [] };
      }
      if (parsed.kind !== 'valid') {
        return {
          kind: 'invalid',
          reason: parsed.kind === 'unsupported'
            ? 'unsupported_schema'
            : parsed.kind === 'resource_limit' ? 'resource_limit' : 'corrupt_state',
          requiresReconcile: true,
          autoResume: false,
          journals: [],
        };
      }

      const state = parsed.state;
      if (state.journals.length === 0) {
        return { kind: 'none', requiresReconcile: false, autoResume: false, journals: [] };
      }
      const retained = state.journals.filter((journal) => journal.phase !== 'prepared');
      let changed = retained.length !== state.journals.length;
      state.journals = retained;
      for (const journal of state.journals) {
        if (journal.phase !== 'committing') continue;
        const timestamp = Math.max(this.currentTimestamp(), journal.updatedAt);
        if (journal.inFlight) {
          const inFlight = journal.inFlight;
          appendOutcome(journal, createOutcome(
            journal,
            inFlight.operationId,
            inFlight.kind,
            inFlight.sourceIndex,
            'outcome_unknown',
            'service_worker_restarted',
            null,
            timestamp,
          ), this.maxOutcomes);
          journal.inFlight = null;
          journal.replayBarrier = true;
          journal.unresolvedOutcomeUnknown = true;
        }
        journal.phase = 'reconcile_required';
        journal.requiresReconcile = true;
        journal.requiresExplicitReplayBarrierClear ||= hasRemoteWriteEvidence(journal)
          && !journal.unresolvedOutcomeUnknown;
        journal.updatedAt = timestamp;
        changed = true;
      }
      if (changed) {
        if (serializedByteLength(state) > this.maxStoredBytes) {
          return {
            kind: 'invalid',
            reason: 'resource_limit',
            requiresReconcile: true,
            autoResume: false,
            journals: [],
          };
        }
        await this.persist(state);
      }
      if (state.journals.length === 0) {
        return { kind: 'none', requiresReconcile: false, autoResume: false, journals: [] };
      }
      const journals = state.journals.map(summarize);
      return {
        kind: 'valid',
        requiresReconcile: journals.some((journal) => journal.requiresReconcile),
        autoResume: false,
        journals,
      };
    });
  }

  private async readReadableState(): Promise<StoredState> {
    const parsed = this.parse(await this.store.get<unknown>(this.storageKey));
    if (parsed.kind === 'empty' || parsed.kind === 'valid') return parsed.state;
    if (parsed.kind === 'unsupported') {
      throw new VaultTransferJournalError('unsupported_schema', 'Transfer journal uses an unsupported schema version');
    }
    if (parsed.kind === 'resource_limit') {
      throw new VaultTransferJournalError('resource_limit', 'Transfer journal exceeds configured resource limits');
    }
    throw new VaultTransferJournalError('corrupt_state', 'Transfer journal storage is corrupt');
  }

  private readWritableState(): Promise<StoredState> {
    return this.readReadableState();
  }

  private parse(value: unknown): ParsedState {
    if (value === undefined) return { kind: 'empty', state: emptyState() };
    if (!isRecord(value)) return { kind: 'corrupt' };
    if (isFutureSchemaVersion(value.schemaVersion)) return { kind: 'unsupported' };
    if (serializedByteLength(value) > this.maxStoredBytes) return { kind: 'resource_limit' };
    if (value.schemaVersion !== VAULT_TRANSFER_JOURNAL_SCHEMA_VERSION
      || !hasExactFields(value, ['schemaVersion', 'journals'])
      || !Array.isArray(value.journals)) return { kind: 'corrupt' };
    if (value.journals.length > this.maxJournals) return { kind: 'resource_limit' };

    const journals: StoredJournal[] = [];
    const transferIds = new Set<string>();
    for (const candidate of value.journals) {
      const journal = this.parseJournal(candidate);
      if (!journal || transferIds.has(journal.transferId)) return { kind: 'corrupt' };
      transferIds.add(journal.transferId);
      journals.push(journal);
    }
    return { kind: 'valid', state: { schemaVersion: VAULT_TRANSFER_JOURNAL_SCHEMA_VERSION, journals } };
  }

  private parseJournal(value: unknown): StoredJournal | undefined {
    if (!isRecord(value) || !hasExactFields(value, [
      'transferId',
      'direction',
      'accountIdentityDigest',
      'sourceDigest',
      'phase',
      'requiresReconcile',
      'replayBarrier',
      'unresolvedOutcomeUnknown',
      'requiresExplicitReplayBarrierClear',
      'autoResume',
      'createdAt',
      'updatedAt',
      'reconciledAt',
      'resultDeliveredAt',
      'inFlight',
      'outcomePageSize',
      'nextOutcomeSequence',
      'outcomePages',
      'folderAliases',
      'itemAliases',
    ])) return undefined;
    if (!isUuidV4(value.transferId)
      || !isDirection(value.direction)
      || !isSha256(value.accountIdentityDigest)
      || !isSha256(value.sourceDigest)
      || !isPhase(value.phase)
      || typeof value.requiresReconcile !== 'boolean'
      || typeof value.replayBarrier !== 'boolean'
      || typeof value.unresolvedOutcomeUnknown !== 'boolean'
      || typeof value.requiresExplicitReplayBarrierClear !== 'boolean'
      || value.autoResume !== false
      || !isTimestamp(value.createdAt)
      || !isTimestamp(value.updatedAt)
      || value.updatedAt < value.createdAt
      || (value.reconciledAt !== null && !isTimestamp(value.reconciledAt))
      || (typeof value.reconciledAt === 'number'
        && (value.reconciledAt < value.createdAt || value.reconciledAt > value.updatedAt))
      || (value.resultDeliveredAt !== null && !isTimestamp(value.resultDeliveredAt))
      || (typeof value.resultDeliveredAt === 'number'
        && (value.resultDeliveredAt < value.createdAt || value.resultDeliveredAt > value.updatedAt))
      || !Number.isSafeInteger(value.outcomePageSize)
      || (value.outcomePageSize as number) < 1
      || (value.outcomePageSize as number) > MAX_VAULT_TRANSFER_OUTCOME_PAGE_SIZE
      || !Number.isSafeInteger(value.nextOutcomeSequence)
      || (value.nextOutcomeSequence as number) < 0
      || (value.nextOutcomeSequence as number) > this.maxOutcomes
      || !Array.isArray(value.outcomePages)
      || !Array.isArray(value.folderAliases)
      || !Array.isArray(value.itemAliases)) return undefined;

    const inFlight = parseInFlight(value.inFlight);
    if (inFlight === undefined) return undefined;
    const pageSize = value.outcomePageSize as number;
    if (value.outcomePages.length > Math.ceil(this.maxOutcomes / pageSize)) return undefined;
    const outcomePages: VaultTransferJournalOutcome[][] = [];
    const sourceKeys = new Set<string>();
    const opaqueIds = new Set<string>([value.transferId]);
    const outcomeAliases = new Set<string>();
    const outcomeAliasesByKey = new Map<string, string>();
    let nextSequence = 0;
    for (let pageIndex = 0; pageIndex < value.outcomePages.length; pageIndex += 1) {
      const page = value.outcomePages[pageIndex];
      if (!Array.isArray(page) || page.length < 1 || page.length > pageSize) return undefined;
      if (pageIndex < value.outcomePages.length - 1 && page.length !== pageSize) return undefined;
      const parsedPage: VaultTransferJournalOutcome[] = [];
      for (const candidate of page) {
        const outcome = parseOutcome(candidate, nextSequence);
        if (!outcome) return undefined;
        const sourceKey = `${outcome.kind}:${outcome.sourceIndex}`;
        if (sourceKeys.has(sourceKey)) return undefined;
        sourceKeys.add(sourceKey);
        if (outcome.operationId) {
          if (opaqueIds.has(outcome.operationId) || outcomeAliases.has(outcome.operationId)) return undefined;
          opaqueIds.add(outcome.operationId);
        }
        if (outcome.alias) {
          if (opaqueIds.has(outcome.alias) || outcomeAliases.has(outcome.alias)) return undefined;
          outcomeAliases.add(outcome.alias);
          outcomeAliasesByKey.set(sourceKey, outcome.alias);
        }
        parsedPage.push(outcome);
        nextSequence += 1;
      }
      outcomePages.push(parsedPage);
    }
    if (nextSequence !== value.nextOutcomeSequence) return undefined;
    if (inFlight) {
      if (sourceKeys.has(`${inFlight.kind}:${inFlight.sourceIndex}`)
        || opaqueIds.has(inFlight.operationId)
        || outcomeAliases.has(inFlight.operationId)
        || nextSequence >= this.maxOutcomes) return undefined;
      opaqueIds.add(inFlight.operationId);
    }

    const folderAliases = parseAliases(value.folderAliases, this.maxMappings, opaqueIds);
    if (!folderAliases) return undefined;
    const itemAliases = parseAliases(value.itemAliases, this.maxMappings - folderAliases.length, opaqueIds);
    if (!itemAliases) return undefined;
    const aliasesByKey = new Map<string, string>();
    for (const entry of folderAliases) aliasesByKey.set(`folder:${entry.sourceIndex}`, entry.alias);
    for (const entry of itemAliases) aliasesByKey.set(`item:${entry.sourceIndex}`, entry.alias);
    for (const page of outcomePages) {
      for (const outcome of page) {
        if (outcome.alias !== null
          && aliasesByKey.get(`${outcome.kind}:${outcome.sourceIndex}`) !== outcome.alias) return undefined;
      }
    }
    for (const [key, alias] of aliasesByKey) {
      if (outcomeAliasesByKey.get(key) !== alias) return undefined;
    }

    const journal: StoredJournal = {
      transferId: value.transferId,
      direction: value.direction,
      accountIdentityDigest: value.accountIdentityDigest,
      sourceDigest: value.sourceDigest,
      phase: value.phase,
      requiresReconcile: value.requiresReconcile,
      replayBarrier: value.replayBarrier,
      unresolvedOutcomeUnknown: value.unresolvedOutcomeUnknown,
      requiresExplicitReplayBarrierClear: value.requiresExplicitReplayBarrierClear,
      autoResume: false,
      createdAt: value.createdAt,
      updatedAt: value.updatedAt,
      reconciledAt: value.reconciledAt,
      resultDeliveredAt: value.resultDeliveredAt,
      inFlight,
      outcomePageSize: pageSize,
      nextOutcomeSequence: nextSequence,
      outcomePages,
      folderAliases,
      itemAliases,
    };
    if (journal.inFlight
      && (journal.inFlight.startedAt < journal.createdAt
        || journal.inFlight.startedAt > journal.updatedAt)) return undefined;
    let previousOutcomeAt = journal.createdAt;
    for (const page of journal.outcomePages) {
      for (const outcome of page) {
        if (outcome.recordedAt < previousOutcomeAt || outcome.recordedAt > journal.updatedAt) {
          return undefined;
        }
        previousOutcomeAt = outcome.recordedAt;
      }
    }
    return hasValidPhaseInvariants(journal) ? journal : undefined;
  }

  private async persist(state: StoredState): Promise<void> {
    if (serializedByteLength(state) > this.maxStoredBytes) {
      throw new VaultTransferJournalError('resource_limit', 'Transfer journal exceeds the configured byte limit');
    }
    await this.store.set(this.storageKey, state);
  }

  private assertPlanWithinLimits(plan: readonly VaultTransferJournalPlanEntry[]): void {
    if (plan.length > this.maxOutcomes) {
      throw new VaultTransferJournalError(
        'resource_limit',
        'Transfer plan exceeds the outcome capacity',
      );
    }
    const plannedMappings = plan.reduce((count, entry) => (
      entry.kind === 'folder' || entry.kind === 'item' ? count + 1 : count
    ), 0);
    if (plannedMappings > this.maxMappings) {
      throw new VaultTransferJournalError(
        'resource_limit',
        'Transfer plan exceeds the mapping capacity',
      );
    }
  }

  private assertPlanFitsStoredState(
    state: StoredState,
    journal: StoredJournal,
    plan: readonly VaultTransferJournalPlanEntry[],
  ): void {
    const candidate = cloneStoredState(state);
    const candidateJournal = requireSimulatedJournal(candidate, journal.transferId);
    const statuses: Array<'committed' | 'rejected'> = [];
    for (const entry of plan) {
      const status = worstStoredPlanStatus(candidateJournal, entry);
      statuses.push(status);
      appendSimulatedPlanOutcome(candidateJournal, entry, status, this.maxOutcomes);
    }
    this.assertPlanCandidateFits(candidate);

    const delivered = cloneStoredState(candidate);
    const deliveredJournal = requireSimulatedJournal(delivered, journal.transferId);
    deliveredJournal.phase = 'completed';
    deliveredJournal.replayBarrier = false;
    deliveredJournal.resultDeliveredAt = Number.MAX_SAFE_INTEGER;
    deliveredJournal.updatedAt = Number.MAX_SAFE_INTEGER;
    this.assertPlanCandidateFits(delivered);

    const partial = cloneStoredState(candidate);
    const partialJournal = requireSimulatedJournal(partial, journal.transferId);
    partialJournal.phase = 'reconcile_required';
    partialJournal.requiresReconcile = true;
    partialJournal.requiresExplicitReplayBarrierClear = partialJournal.replayBarrier;
    partialJournal.updatedAt = Number.MAX_SAFE_INTEGER;
    this.assertPlanCandidateFits(partial);

    const partialDelivered = cloneStoredState(partial);
    requireSimulatedJournal(partialDelivered, journal.transferId).resultDeliveredAt = Number.MAX_SAFE_INTEGER;
    this.assertPlanCandidateFits(partialDelivered);

    const partialReconciled = cloneStoredState(partial);
    const partialReconciledJournal = requireSimulatedJournal(partialReconciled, journal.transferId);
    partialReconciledJournal.phase = 'completed';
    partialReconciledJournal.requiresReconcile = false;
    partialReconciledJournal.reconciledAt = Number.MAX_SAFE_INTEGER;
    this.assertPlanCandidateFits(partialReconciled);

    const partialDeliveredAndReconciled = cloneStoredState(partialDelivered);
    const partialDeliveredAndReconciledJournal = requireSimulatedJournal(
      partialDeliveredAndReconciled,
      journal.transferId,
    );
    partialDeliveredAndReconciledJournal.phase = 'completed';
    partialDeliveredAndReconciledJournal.requiresReconcile = false;
    partialDeliveredAndReconciledJournal.reconciledAt = Number.MAX_SAFE_INTEGER;
    this.assertPlanCandidateFits(partialDeliveredAndReconciled);

    if (plan.length === 0) return;

    // A later interrupted prefix dominates earlier ones because every settled prefix adds an
    // outcome and never removes a mapping. Replay the largest reachable prefix with a lost result.
    const interrupted = cloneStoredState(state);
    const interruptedJournal = requireSimulatedJournal(interrupted, journal.transferId);
    for (let index = 0; index < plan.length; index += 1) {
      const entry = plan[index];
      if (!entry) throw new Error('Transfer journal plan reservation invariant failed');
      appendSimulatedPlanOutcome(
        interruptedJournal,
        entry,
        index === plan.length - 1 ? 'outcome_unknown' : statuses[index]!,
        this.maxOutcomes,
      );
    }
    this.assertPlanCandidateFits(interrupted);

    const interruptedDelivered = cloneStoredState(interrupted);
    requireSimulatedJournal(
      interruptedDelivered,
      journal.transferId,
    ).resultDeliveredAt = Number.MAX_SAFE_INTEGER;
    this.assertPlanCandidateFits(interruptedDelivered);

    const reconciled = cloneStoredState(interruptedDelivered);
    const reconciledJournal = requireSimulatedJournal(reconciled, journal.transferId);
    reconciledJournal.phase = 'completed';
    reconciledJournal.requiresReconcile = false;
    reconciledJournal.reconciledAt = Number.MAX_SAFE_INTEGER;
    this.assertPlanCandidateFits(reconciled);

    const cleared = cloneStoredState(reconciled);
    const clearedJournal = requireSimulatedJournal(cleared, journal.transferId);
    clearedJournal.replayBarrier = false;
    clearedJournal.unresolvedOutcomeUnknown = false;
    clearedJournal.requiresExplicitReplayBarrierClear = false;
    this.assertPlanCandidateFits(cleared);
  }

  private assertPlanCandidateFits(candidate: StoredState): void {
    if (serializedByteLength(candidate) > this.maxStoredBytes) {
      throw new VaultTransferJournalError(
        'resource_limit',
        'Transfer journal cannot reserve every planned outcome',
      );
    }
  }

  private installWorstCaseSettlementReserve(state: StoredState, journal: StoredJournal): void {
    const shapes: ReadonlyArray<{
      readonly status: Exclude<VaultTransferJournalOutcomeStatus, 'skipped'>;
      readonly code: string | null;
    }> = [
      { status: 'committed', code: null },
      { status: 'rejected', code: MAX_REJECTED_RESERVE_CODE },
      { status: 'outcome_unknown', code: MAX_REJECTED_RESERVE_CODE },
    ];
    let maximumSettlementBytes = 0;
    for (const shape of shapes) {
      const candidate = cloneStoredState(state);
      const candidateJournal = candidate.journals.find(
        (entry) => entry.transferId === journal.transferId,
      );
      const inFlight = candidateJournal?.inFlight;
      if (!candidateJournal || !inFlight) {
        throw new Error('Transfer journal settlement reservation invariant failed');
      }
      let alias: string | null = null;
      if (shape.status === 'committed' && (inFlight.kind === 'folder' || inFlight.kind === 'item')) {
        alias = RESERVE_ALIAS;
        const mappings = inFlight.kind === 'folder'
          ? candidateJournal.folderAliases
          : candidateJournal.itemAliases;
        mappings.push({ sourceIndex: inFlight.sourceIndex, alias });
      }
      const timestamp = Number.MAX_SAFE_INTEGER;
      appendOutcome(candidateJournal, createOutcome(
        candidateJournal,
        inFlight.operationId,
        inFlight.kind,
        inFlight.sourceIndex,
        shape.status,
        shape.code,
        alias,
        timestamp,
      ), this.maxOutcomes);
      candidateJournal.inFlight = null;
      candidateJournal.replayBarrier = hasRemoteWriteEvidence(candidateJournal);
      if (shape.status === 'outcome_unknown') {
        candidateJournal.unresolvedOutcomeUnknown = true;
      }
      candidateJournal.updatedAt = timestamp;
      candidateJournal.phase = shape.status === 'outcome_unknown'
        ? 'reconcile_required'
        : 'committing';
      candidateJournal.requiresReconcile = shape.status === 'outcome_unknown';
      maximumSettlementBytes = Math.max(maximumSettlementBytes, serializedByteLength(candidate));
    }
    const markerBytes = serializedByteLength(state);
    const inFlight = journal.inFlight;
    if (!inFlight) throw new Error('Transfer journal settlement reservation invariant failed');
    const reserveBytes = Math.max(0, maximumSettlementBytes - markerBytes);
    inFlight.settlementReserve = '0'.repeat(reserveBytes);
    if (serializedByteLength(state) > this.maxStoredBytes) {
      throw new VaultTransferJournalError(
        'resource_limit',
        'Transfer journal cannot reserve every possible POST outcome',
      );
    }
  }

  private uniqueOpaqueId(state: StoredState): string {
    const used = collectOpaqueIds(state);
    for (let attempt = 0; attempt < MAX_ID_GENERATION_ATTEMPTS; attempt += 1) {
      const candidate = this.createId();
      assertUuidV4(candidate, 'createId result');
      if (!used.has(candidate)) return candidate;
    }
    throw new VaultTransferJournalError('capacity', 'Could not allocate a unique journal identifier');
  }

  private currentTimestamp(): number {
    const timestamp = this.now();
    if (!isTimestamp(timestamp)) throw new RangeError('now must return a non-negative safe integer');
    return timestamp;
  }

  private timestampFor(journal: StoredJournal): number {
    return Math.max(this.currentTimestamp(), journal.updatedAt);
  }

  private serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.sharedQueue.tail.then(operation, operation);
    this.sharedQueue.tail = result.then(() => undefined, () => undefined);
    return result;
  }
}

export function createVaultTransferJournalStore(store: KeyValueStore, options?: VaultTransferJournalStoreOptions): VaultTransferJournalStore {
  return new VaultTransferJournalStore(store, options);
}

/** Produce a domain-separated account digest without persisting the identity itself. */
export async function digestVaultTransferAccountIdentity(canonicalIdentity: string): Promise<string> {
  if (typeof canonicalIdentity !== 'string'
    || canonicalIdentity.length < 1
    || canonicalIdentity.length > MAX_IDENTITY_INPUT_LENGTH
    || canonicalIdentity.trim() !== canonicalIdentity) {
    throw new TypeError('canonicalIdentity must be a non-empty bounded canonical string');
  }
  const bytes = new TextEncoder().encode(`miyu-vault-transfer-account-v1\0${canonicalIdentity}`);
  try {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
    return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
  } finally {
    bytes.fill(0);
  }
}

function emptyState(): StoredState {
  return { schemaVersion: VAULT_TRANSFER_JOURNAL_SCHEMA_VERSION, journals: [] };
}

function sharedJournalQueue(store: KeyValueStore, storageKey: string): SharedJournalQueue {
  let queues = SHARED_JOURNAL_QUEUES.get(store);
  if (!queues) {
    queues = new Map();
    SHARED_JOURNAL_QUEUES.set(store, queues);
  }
  let queue = queues.get(storageKey);
  if (!queue) {
    queue = { tail: Promise.resolve() };
    queues.set(storageKey, queue);
  }
  return queue;
}

function oldestEvictableTerminalJournalIndex(journals: readonly StoredJournal[]): number {
  let oldestIndex = -1;
  for (let index = 0; index < journals.length; index += 1) {
    const journal = journals[index];
    if (!journal
      || (journal.phase !== 'completed' && journal.phase !== 'cancelled')
      || journal.replayBarrier) continue;
    const oldest = oldestIndex < 0 ? undefined : journals[oldestIndex];
    if (!oldest
      || journal.updatedAt < oldest.updatedAt
      || (journal.updatedAt === oldest.updatedAt && journal.transferId < oldest.transferId)) {
      oldestIndex = index;
    }
  }
  return oldestIndex;
}

function cloneStoredState(state: StoredState): StoredState {
  return {
    schemaVersion: VAULT_TRANSFER_JOURNAL_SCHEMA_VERSION,
    journals: state.journals.map((journal) => ({
      ...journal,
      inFlight: journal.inFlight ? { ...journal.inFlight } : null,
      outcomePages: journal.outcomePages.map((page) => page.map((outcome) => ({ ...outcome }))),
      folderAliases: journal.folderAliases.map((alias) => ({ ...alias })),
      itemAliases: journal.itemAliases.map((alias) => ({ ...alias })),
    })),
  };
}

function requireSimulatedJournal(state: StoredState, transferId: string): StoredJournal {
  const journal = state.journals.find((entry) => entry.transferId === transferId);
  if (!journal) throw new Error('Transfer journal plan reservation invariant failed');
  return journal;
}

function worstStoredPlanStatus(
  journal: StoredJournal,
  entry: VaultTransferJournalPlanEntry,
): 'committed' | 'rejected' {
  const timestamp = Number.MAX_SAFE_INTEGER;
  const committedAlias = entry.kind === 'folder' || entry.kind === 'item'
    ? RESERVE_ALIAS
    : null;
  const committedOutcome = createOutcome(
    journal,
    RESERVE_ALIAS,
    entry.kind,
    entry.sourceIndex,
    'committed',
    null,
    committedAlias,
    timestamp,
  );
  let committedBytes = serializedByteLength(committedOutcome);
  if (!journal.replayBarrier) committedBytes -= 1;
  if (committedAlias) {
    const mappings = entry.kind === 'folder' ? journal.folderAliases : journal.itemAliases;
    committedBytes += serializedByteLength({
      sourceIndex: entry.sourceIndex,
      alias: committedAlias,
    }) + (mappings.length === 0 ? 0 : 1);
  }
  const rejectedBytes = serializedByteLength(createOutcome(
    journal,
    RESERVE_ALIAS,
    entry.kind,
    entry.sourceIndex,
    'rejected',
    MAX_REJECTED_RESERVE_CODE,
    null,
    timestamp,
  ));
  return committedBytes >= rejectedBytes ? 'committed' : 'rejected';
}

function appendSimulatedPlanOutcome(
  journal: StoredJournal,
  entry: VaultTransferJournalPlanEntry,
  status: 'committed' | 'rejected' | 'outcome_unknown',
  maxOutcomes: number,
): void {
  let alias: string | null = null;
  if (status === 'committed' && (entry.kind === 'folder' || entry.kind === 'item')) {
    alias = RESERVE_ALIAS;
    const mappings = entry.kind === 'folder' ? journal.folderAliases : journal.itemAliases;
    mappings.push({ sourceIndex: entry.sourceIndex, alias });
  }
  appendOutcome(journal, createOutcome(
    journal,
    RESERVE_ALIAS,
    entry.kind,
    entry.sourceIndex,
    status,
    status === 'committed' ? null : MAX_REJECTED_RESERVE_CODE,
    alias,
    Number.MAX_SAFE_INTEGER,
  ), maxOutcomes);
  journal.updatedAt = Number.MAX_SAFE_INTEGER;
  journal.phase = status === 'outcome_unknown' ? 'reconcile_required' : 'committing';
  journal.requiresReconcile = status === 'outcome_unknown';
  journal.replayBarrier = journal.replayBarrier
    || status === 'committed'
    || status === 'outcome_unknown';
  if (status === 'outcome_unknown') journal.unresolvedOutcomeUnknown = true;
}

function validateBeginInput(input: BeginVaultTransferJournalInput): BeginVaultTransferJournalInput {
  if (!isRecord(input) || !hasExactFields(input, [
    'transferId', 'direction', 'accountIdentityDigest', 'sourceDigest',
  ])) throw new TypeError('Journal input must contain only supported fields');
  assertUuidV4(input.transferId, 'transferId');
  if (!isDirection(input.direction)) throw new TypeError('direction must be import or export');
  assertSha256(input.accountIdentityDigest, 'accountIdentityDigest');
  assertSha256(input.sourceDigest, 'sourceDigest');
  return {
    transferId: input.transferId,
    direction: input.direction,
    accountIdentityDigest: input.accountIdentityDigest,
    sourceDigest: input.sourceDigest,
  };
}

function validateCompleteOptions(
  value: CompleteVaultTransferJournalOptions,
): { readonly requiresReconcile: boolean } {
  if (!isRecord(value)
    || !hasOnlyFields(value, ['requiresReconcile'], [])
    || (value.requiresReconcile !== undefined && typeof value.requiresReconcile !== 'boolean')) {
    throw new TypeError('Completion options may contain only requiresReconcile');
  }
  return { requiresReconcile: value.requiresReconcile ?? false };
}

function validateJournalPlan(value: readonly VaultTransferJournalPlanEntry[]): VaultTransferJournalPlanEntry[] {
  if (!Array.isArray(value)) throw new TypeError('Transfer journal plan must be an array');
  const plan: VaultTransferJournalPlanEntry[] = [];
  const sourceKeys = new Set<string>();
  for (const candidate of value) {
    if (!isRecord(candidate) || !hasExactFields(candidate, ['kind', 'sourceIndex'])) {
      throw new TypeError('Transfer journal plan entries must contain only kind and sourceIndex');
    }
    assertOperationKind(candidate.kind);
    assertSourceIndex(candidate.sourceIndex);
    const sourceKey = `${candidate.kind}:${candidate.sourceIndex}`;
    if (sourceKeys.has(sourceKey)) {
      throw new VaultTransferJournalError(
        'duplicate_source',
        'Transfer journal plan contains a duplicate source',
      );
    }
    sourceKeys.add(sourceKey);
    plan.push({ kind: candidate.kind, sourceIndex: candidate.sourceIndex });
  }
  return plan;
}

function validateIdentityPair(transferId: string, accountIdentityDigest: string): {
  readonly transferId: string;
  readonly accountIdentityDigest: string;
} {
  assertUuidV4(transferId, 'transferId');
  assertSha256(accountIdentityDigest, 'accountIdentityDigest');
  return { transferId, accountIdentityDigest };
}

function validateOperationInput(input: MarkVaultTransferInFlightInput): MarkVaultTransferInFlightInput {
  if (!isRecord(input) || !hasExactFields(input, [
    'transferId', 'accountIdentityDigest', 'kind', 'sourceIndex',
  ])) throw new TypeError('Operation input must contain only supported fields');
  const identity = validateIdentityPair(input.transferId, input.accountIdentityDigest);
  assertOperationKind(input.kind);
  assertSourceIndex(input.sourceIndex);
  return { ...identity, kind: input.kind, sourceIndex: input.sourceIndex };
}

function validateSettlementInput(input: SettleVaultTransferInFlightInput): {
  readonly transferId: string;
  readonly accountIdentityDigest: string;
  readonly operationId: string;
  readonly status: Exclude<VaultTransferJournalOutcomeStatus, 'skipped'>;
  readonly code: string | null;
} {
  if (!isRecord(input) || !hasOnlyFields(input, [
    'transferId', 'accountIdentityDigest', 'operationId', 'status', 'code',
  ], ['transferId', 'accountIdentityDigest', 'operationId', 'status'])) {
    throw new TypeError('Settlement input contains unsupported or missing fields');
  }
  const identity = validateIdentityPair(input.transferId, input.accountIdentityDigest);
  assertUuidV4(input.operationId, 'operationId');
  if (input.status !== 'committed' && input.status !== 'rejected' && input.status !== 'outcome_unknown') {
    throw new TypeError('status must be committed, rejected, or outcome_unknown');
  }
  return {
    ...identity,
    operationId: input.operationId,
    status: input.status,
    code: input.code === undefined ? null : canonicalOutcomeCode(input.code),
  };
}

function validateSkippedInput(input: RecordVaultTransferSkippedInput): RecordVaultTransferSkippedInput {
  if (!isRecord(input) || !hasExactFields(input, [
    'transferId', 'accountIdentityDigest', 'kind', 'sourceIndex', 'code',
  ])) throw new TypeError('Skipped outcome input must contain only supported fields');
  const operation = validateOperationInput({
    transferId: input.transferId,
    accountIdentityDigest: input.accountIdentityDigest,
    kind: input.kind,
    sourceIndex: input.sourceIndex,
  });
  return { ...operation, code: canonicalOutcomeCode(input.code) };
}

function createOutcome(
  journal: StoredJournal,
  operationId: string | null,
  kind: VaultTransferJournalOperationKind,
  sourceIndex: number,
  status: VaultTransferJournalOutcomeStatus,
  code: string | null,
  alias: string | null,
  recordedAt: number,
): VaultTransferJournalOutcome {
  return {
    sequence: journal.nextOutcomeSequence,
    operationId,
    kind,
    sourceIndex,
    status,
    code,
    alias,
    recordedAt,
  };
}

function appendOutcome(journal: StoredJournal, outcome: VaultTransferJournalOutcome, maxOutcomes: number): void {
  if (journal.nextOutcomeSequence >= maxOutcomes) {
    throw new VaultTransferJournalError('resource_limit', 'Transfer outcome capacity was reached');
  }
  let page = journal.outcomePages[journal.outcomePages.length - 1];
  if (!page || page.length >= journal.outcomePageSize) {
    page = [];
    journal.outcomePages.push(page);
  }
  page.push(outcome);
  journal.nextOutcomeSequence += 1;
}

function requireJournal(state: StoredState, transferId: string, accountIdentityDigest: string): StoredJournal {
  const journal = state.journals.find((candidate) => candidate.transferId === transferId);
  if (!journal) throw new VaultTransferJournalError('not_found', 'Transfer journal was not found');
  assertAccount(journal, accountIdentityDigest);
  return journal;
}

function assertAccount(journal: StoredJournal, accountIdentityDigest: string): void {
  if (journal.accountIdentityDigest !== accountIdentityDigest) {
    throw new VaultTransferJournalError('cross_account', 'Transfer journal does not belong to the active account identity');
  }
}

function summarize(journal: StoredJournal): VaultTransferJournalSummary {
  return {
    transferId: journal.transferId,
    direction: journal.direction,
    accountIdentityDigest: journal.accountIdentityDigest,
    sourceDigest: journal.sourceDigest,
    phase: journal.phase,
    requiresReconcile: journal.requiresReconcile,
    replayBarrier: journal.replayBarrier,
    unresolvedOutcomeUnknown: journal.unresolvedOutcomeUnknown,
    autoResume: false,
    createdAt: journal.createdAt,
    updatedAt: journal.updatedAt,
    reconciledAt: journal.reconciledAt,
    resultDeliveredAt: journal.resultDeliveredAt,
    inFlight: journal.inFlight ? exposeInFlight(journal.inFlight) : null,
    outcomeCount: journal.nextOutcomeSequence,
    outcomePageCount: journal.outcomePages.length,
    folderMappingCount: journal.folderAliases.length,
    itemMappingCount: journal.itemAliases.length,
  };
}

function exposeInFlight(inFlight: StoredInFlight): VaultTransferJournalInFlight {
  return {
    operationId: inFlight.operationId,
    kind: inFlight.kind,
    sourceIndex: inFlight.sourceIndex,
    startedAt: inFlight.startedAt,
  };
}

function hasSourceOutcome(journal: StoredJournal, kind: VaultTransferJournalOperationKind, sourceIndex: number): boolean {
  return journal.outcomePages.some((page) => page.some(
    (outcome) => outcome.kind === kind && outcome.sourceIndex === sourceIndex,
  ));
}

function hasRemoteWriteEvidence(journal: StoredJournal): boolean {
  return journal.outcomePages.some((page) => page.some(
    (outcome) => outcome.status === 'committed' || outcome.status === 'outcome_unknown',
  ));
}

function mappingCount(journal: StoredJournal): number {
  return journal.folderAliases.length + journal.itemAliases.length;
}

function collectOpaqueIds(state: StoredState): Set<string> {
  const ids = new Set<string>();
  for (const journal of state.journals) {
    ids.add(journal.transferId);
    if (journal.inFlight) ids.add(journal.inFlight.operationId);
    for (const page of journal.outcomePages) {
      for (const outcome of page) {
        if (outcome.operationId) ids.add(outcome.operationId);
        if (outcome.alias) ids.add(outcome.alias);
      }
    }
    for (const mapping of journal.folderAliases) ids.add(mapping.alias);
    for (const mapping of journal.itemAliases) ids.add(mapping.alias);
  }
  return ids;
}

function parseInFlight(value: unknown): StoredInFlight | null | undefined {
  if (value === null) return null;
  if (!isRecord(value) || !hasExactFields(value, [
    'operationId', 'kind', 'sourceIndex', 'startedAt', 'settlementReserve',
  ])) {
    return undefined;
  }
  if (!isUuidV4(value.operationId)
    || !isOperationKind(value.kind)
    || !isSourceIndex(value.sourceIndex)
    || !isTimestamp(value.startedAt)
    || typeof value.settlementReserve !== 'string'
    || value.settlementReserve.length > MAX_VAULT_TRANSFER_JOURNAL_BYTES
    || !/^0*$/.test(value.settlementReserve)) return undefined;
  return {
    operationId: value.operationId,
    kind: value.kind,
    sourceIndex: value.sourceIndex,
    startedAt: value.startedAt,
    settlementReserve: value.settlementReserve,
  };
}

function parseOutcome(value: unknown, expectedSequence: number): VaultTransferJournalOutcome | undefined {
  if (!isRecord(value) || !hasExactFields(value, [
    'sequence', 'operationId', 'kind', 'sourceIndex', 'status', 'code', 'alias', 'recordedAt',
  ])) return undefined;
  if (value.sequence !== expectedSequence
    || (value.operationId !== null && !isUuidV4(value.operationId))
    || !isOperationKind(value.kind)
    || !isSourceIndex(value.sourceIndex)
    || !isOutcomeStatus(value.status)
    || (value.code !== null && !isOutcomeCode(value.code))
    || (value.alias !== null && !isUuidV4(value.alias))
    || !isTimestamp(value.recordedAt)) return undefined;
  if (value.status === 'skipped' && value.operationId !== null) return undefined;
  if (value.status !== 'skipped' && value.operationId === null) return undefined;
  if (value.status === 'committed' && value.code !== null) return undefined;
  if (value.status !== 'committed' && value.code === null) return undefined;
  if (value.alias !== null
    && (value.status !== 'committed' || (value.kind !== 'folder' && value.kind !== 'item'))) {
    return undefined;
  }
  return {
    sequence: value.sequence,
    operationId: value.operationId,
    kind: value.kind,
    sourceIndex: value.sourceIndex,
    status: value.status,
    code: value.code,
    alias: value.alias,
    recordedAt: value.recordedAt,
  };
}

function parseAliases(value: unknown[], maximum: number, opaqueIds: Set<string>): StoredAlias[] | undefined {
  if (value.length > maximum) return undefined;
  const aliases: StoredAlias[] = [];
  const sourceIndices = new Set<number>();
  for (const candidate of value) {
    if (!isRecord(candidate)
      || !hasExactFields(candidate, ['sourceIndex', 'alias'])
      || !isSourceIndex(candidate.sourceIndex)
      || !isUuidV4(candidate.alias)
      || sourceIndices.has(candidate.sourceIndex)
      || opaqueIds.has(candidate.alias)) return undefined;
    sourceIndices.add(candidate.sourceIndex);
    opaqueIds.add(candidate.alias);
    aliases.push({ sourceIndex: candidate.sourceIndex, alias: candidate.alias });
  }
  return aliases;
}

function hasValidPhaseInvariants(journal: StoredJournal): boolean {
  const outcomes = journal.outcomePages.flat();
  const hasUnknown = outcomes.some((outcome) => outcome.status === 'outcome_unknown');
  const hasBarrierEvidence = journal.inFlight !== null
    || outcomes.some((outcome) => (
      outcome.status === 'committed' || outcome.status === 'outcome_unknown'
    ));
  if ((journal.replayBarrier && !hasBarrierEvidence)
    || (journal.phase !== 'completed' && hasBarrierEvidence && !journal.replayBarrier)
    || (journal.phase === 'completed'
      && hasBarrierEvidence
      && !journal.replayBarrier
      && journal.resultDeliveredAt === null
      && journal.reconciledAt === null)
    || (journal.unresolvedOutcomeUnknown && (!hasUnknown || !journal.replayBarrier))
    || (journal.requiresExplicitReplayBarrierClear
      && (!journal.replayBarrier
        || (journal.phase !== 'reconcile_required' && journal.phase !== 'completed')))
    || (hasUnknown
      && !journal.unresolvedOutcomeUnknown
      && (journal.phase !== 'completed'
        || journal.replayBarrier
        || journal.reconciledAt === null))
    || (journal.resultDeliveredAt !== null
      && journal.phase !== 'completed'
      && journal.phase !== 'reconcile_required')
    || (journal.resultDeliveredAt !== null
      && journal.phase === 'completed'
      && journal.replayBarrier
      && !journal.unresolvedOutcomeUnknown
      && !journal.requiresExplicitReplayBarrierClear)) return false;
  if (journal.phase === 'prepared') {
    return !journal.requiresReconcile
      && !journal.replayBarrier
      && journal.reconciledAt === null
      && journal.resultDeliveredAt === null
      && journal.inFlight === null
      && journal.nextOutcomeSequence === 0;
  }
  if (journal.phase === 'committing') {
    return !journal.requiresReconcile
      && journal.reconciledAt === null
      && !hasUnknown
      && journal.direction === 'import';
  }
  if (journal.phase === 'reconcile_required') {
    return journal.requiresReconcile
      && journal.reconciledAt === null
      && journal.inFlight === null;
  }
  if (journal.phase === 'cancelled') {
    return !journal.requiresReconcile
      && !journal.replayBarrier
      && journal.reconciledAt === null
      && journal.resultDeliveredAt === null
      && journal.inFlight === null
      && !hasBarrierEvidence;
  }
  return !journal.requiresReconcile
    && journal.inFlight === null
    && (journal.reconciledAt !== null || !hasUnknown);
}

function isWritablePhase(phase: VaultTransferJournalPhase): boolean {
  return phase === 'prepared' || phase === 'committing';
}

function serializedByteLength(value: unknown): number {
  try {
    const serialized = JSON.stringify(value);
    return serialized === undefined
      ? Number.POSITIVE_INFINITY
      : new TextEncoder().encode(serialized).byteLength;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

function canonicalOutcomeCode(value: string): string {
  if (!isOutcomeCode(value)) {
    throw new TypeError(`Outcome code must be 1-${MAX_VAULT_TRANSFER_OUTCOME_CODE_LENGTH} ASCII identifier characters`);
  }
  return value;
}

function assertUuidV4(value: unknown, name: string): asserts value is string {
  if (!isUuidV4(value)) throw new TypeError(`${name} must be a lowercase UUIDv4 string`);
}

function assertSha256(value: unknown, name: string): asserts value is string {
  if (!isSha256(value)) throw new TypeError(`${name} must be a lowercase SHA-256 hex digest`);
}

function assertSourceIndex(value: unknown): asserts value is number {
  if (!isSourceIndex(value)) {
    throw new RangeError(`sourceIndex must be an integer between 0 and ${MAX_SOURCE_INDEX}`);
  }
}

function assertOperationKind(value: unknown): asserts value is VaultTransferJournalOperationKind {
  if (!isOperationKind(value)) throw new TypeError('Unsupported transfer operation kind');
}

function assertAliasKind(value: unknown): asserts value is VaultTransferJournalAliasKind {
  if (value !== 'folder' && value !== 'item') throw new TypeError('Alias kind must be folder or item');
}

function isUuidV4(value: unknown): value is string {
  return typeof value === 'string' && UUID_V4_PATTERN.test(value);
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && SHA_256_PATTERN.test(value);
}

function isDirection(value: unknown): value is VaultTransferJournalDirection {
  return value === 'import' || value === 'export';
}

function isOperationKind(value: unknown): value is VaultTransferJournalOperationKind {
  return value === 'folder' || value === 'collection' || value === 'item' || value === 'attachment';
}

function isOutcomeStatus(value: unknown): value is VaultTransferJournalOutcomeStatus {
  return value === 'committed' || value === 'rejected' || value === 'skipped' || value === 'outcome_unknown';
}

function isPhase(value: unknown): value is VaultTransferJournalPhase {
  return value === 'prepared'
    || value === 'committing'
    || value === 'reconcile_required'
    || value === 'completed'
    || value === 'cancelled';
}

function isOutcomeCode(value: unknown): value is string {
  return typeof value === 'string'
    && value.length >= 1
    && value.length <= MAX_VAULT_TRANSFER_OUTCOME_CODE_LENGTH
    && OUTCOME_CODE_PATTERN.test(value);
}

function isSourceIndex(value: unknown): value is number {
  return typeof value === 'number'
    && Number.isSafeInteger(value)
    && value >= 0
    && value <= MAX_SOURCE_INDEX;
}

function isTimestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isFutureSchemaVersion(value: unknown): boolean {
  return Number.isSafeInteger(value) && (value as number) > VAULT_TRANSFER_JOURNAL_SCHEMA_VERSION;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function hasExactFields(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((field) => actual.includes(field));
}

function hasOnlyFields(
  value: Record<string, unknown>,
  allowed: readonly string[],
  required: readonly string[],
): boolean {
  const actual = Object.keys(value);
  return actual.every((field) => allowed.includes(field))
    && required.every((field) => actual.includes(field));
}

function boundedPositiveInteger(value: number, name: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new RangeError(`${name} must be an integer between 1 and ${maximum}`);
  }
  return value;
}
