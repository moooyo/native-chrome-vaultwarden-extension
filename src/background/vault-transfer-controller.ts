import type { PersonalImportCapabilityPolicy } from '../core/vault/vault-transfer-commit.js';
import {
  digestVaultTransferAccountIdentity,
  VaultTransferJournalError,
  type VaultTransferJournalAliasKind,
  type VaultTransferJournalInFlight,
  type VaultTransferJournalOperationKind,
  type VaultTransferJournalOutcome,
  type VaultTransferJournalPlanEntry,
  type VaultTransferJournalStartupInspection,
  type VaultTransferJournalStore,
  type VaultTransferJournalSummary,
} from '../core/vault/vault-transfer-journal.js';
import {
  buildVaultTransferPreview,
  type VaultTransferPreview,
  type VaultTransferPreviewFormat,
} from '../core/vault/vault-transfer-preview.js';
import {
  VaultTransferSessionError,
  type BegunVaultTransfer,
  type VaultTransferChunkAck,
  type VaultTransferSessionErrorCode,
  type VaultTransferSessionManager,
} from '../core/vault/vault-transfer-session.js';
import {
  inspectVaultTransferSource,
  type InspectVaultTransferSourceOptions,
  type VaultTransferSourceFailureCode,
  type VaultTransferSourceFormat,
  type VaultTransferSourceLimits,
  type VaultTransferSourceOk,
  type VaultTransferSourceResult,
} from '../core/vault/vault-transfer-source.js';
import {
  VAULT_TRANSFER_EXPORT_WARNING_CODES,
  type VaultTransferExportReview,
  type VaultTransferExportWarning,
  type VaultTransferExportWarningCode,
} from '../core/vault/vault-transfer-export-review.js';
import {
  PERSONAL_VAULT_TRANSFER_EXPORT_TARGET,
  canonicalizeVaultTransferExportTarget,
  sameVaultTransferExportTarget,
  type VaultTransferExportTarget,
} from '../core/vault/vault-transfer-target.js';

export const MAX_VAULT_TRANSFER_PASSWORD_BYTES = 4_096;
export const DEFAULT_VAULT_TRANSFER_EXPORT_CHUNK_BYTES = 256 * 1_024;

const MAX_EXPORT_FILENAME_CHARS = 255;
const INVALID_EXPORT_FILENAME_CHARS = new Set(['\\', '/', ':', '*', '?', '"', '<', '>', '|']);

export type VaultTransferControllerErrorCode =
  | VaultTransferSessionErrorCode
  | VaultTransferSourceFailureCode
  | 'invalid_request'
  | 'password_required'
  | 'preview_blocked'
  | 'account_unavailable'
  | 'journal_failed'
  | 'commit_unavailable'
  | 'commit_failed'
  | 'commit_incomplete'
  | 'outcome_unknown'
  | 'cancelled'
  | 'export_unavailable'
  | 'export_authorization_invalid'
  | 'export_failed'
  | 'export_incomplete'
  | 'reconcile_unavailable'
  | 'reconcile_failed';

export class VaultTransferControllerError extends Error {
  constructor(readonly code: VaultTransferControllerErrorCode) {
    super(code);
    this.name = 'VaultTransferControllerError';
  }
}

export interface VaultTransferAccountIdentitySnapshot<Lease> {
  /** Canonical server-and-account identity. It is hashed before journal persistence. */
  readonly canonicalIdentity: string;
  readonly lease: Lease;
}

export interface VaultTransferInspectAuthority<AccountIdentityLease, TransferLease> {
  readonly account: VaultTransferAccountIdentitySnapshot<AccountIdentityLease>;
  readonly transferLeases: TransferLease;
  assertCurrent(): Promise<void>;
}

export type VaultTransferJournalDependency = Pick<
  VaultTransferJournalStore,
  | 'begin'
  | 'markInFlight'
  | 'settleInFlight'
  | 'recordSkipped'
  | 'complete'
  | 'cancel'
  | 'getSummary'
  | 'getOutcomePage'
  | 'getAlias'
  | 'inspectForStartup'
  | 'acknowledgeReconciled'
  | 'acknowledgeResultDelivered'
  | 'acknowledgeReplayBarrierReconciled'
  | 'clearReplayBarrier'
>;

export type VaultTransferJournalSettlement =
  | { readonly operationId: string; readonly status: 'committed' }
  | {
      readonly operationId: string;
      readonly status: 'rejected' | 'outcome_unknown';
      readonly code: string;
    };

/** The commit adapter receives no account identity, source digest, or persistent journal key. */
export interface VaultTransferCommitJournal {
  readonly signal: AbortSignal;
  assertCurrent(): Promise<void>;
  markInFlight(
    kind: VaultTransferJournalOperationKind,
    sourceIndex: number,
  ): Promise<VaultTransferJournalInFlight>;
  settleInFlight(settlement: VaultTransferJournalSettlement): Promise<VaultTransferJournalOutcome>;
  recordSkipped(
    kind: VaultTransferJournalOperationKind,
    sourceIndex: number,
    code: string,
  ): Promise<VaultTransferJournalOutcome>;
  getAlias(
    kind: VaultTransferJournalAliasKind,
    sourceIndex: number,
  ): Promise<string | undefined>;
}

export interface VaultTransferImportCommitInput {
  /** Authoritative second parse. It is valid only for the lifetime of this callback. */
  readonly source: VaultTransferSourceOk;
  readonly capabilities: PersonalImportCapabilityPolicy;
  readonly journal: VaultTransferCommitJournal;
}

export type VaultTransferExportFormat = 'json' | 'encrypted-json' | 'csv' | 'zip';

export interface BuiltVaultTransferExport {
  /** Ownership transfers to the controller, which zeroes this exact view after staging. */
  readonly bytes: Uint8Array;
  readonly filename: string;
  readonly review?: VaultTransferExportReview;
}

export interface VaultTransferExportAuthorizationInput {
  readonly authorizationId: string;
  readonly format: VaultTransferExportFormat;
  readonly encryptionType?: 'account' | 'file';
  readonly target: VaultTransferExportTarget;
}

export type VaultTransferExportChunk =
  | {
      readonly done: false;
      readonly sequence: number;
      /** Borrowed until acknowledge(). The producer zeroes it on ACK or teardown. */
      readonly bytes: Uint8Array;
      readonly requiresAcknowledgement: true;
    }
  | { readonly done: true; readonly totalBytes: number };

export interface VaultTransferExportChunkProducer {
  next(): Promise<VaultTransferExportChunk>;
  acknowledge(sequence: number): void;
  assertCurrent(): void;
}

export interface VaultTransferExportStreamInput {
  readonly transferId: string;
  readonly format: VaultTransferExportFormat;
  readonly filename: string;
  readonly totalBytes: number;
  readonly signal: AbortSignal;
  readonly producer: VaultTransferExportChunkProducer;
}

export interface VaultTransferReconcileInput {
  readonly accountIdentityDigest: string;
  readonly journals: readonly VaultTransferJournalSummary[];
}

export interface VaultTransferControllerDeps<
  AccountLease,
  SessionLease,
  EnterprisePolicyLease,
  AccountIdentityLease,
  TransferLease,
  ReconcileLease = TransferLease,
  ExportAuthorization = boolean,
> {
  readonly sessions: VaultTransferSessionManager<AccountLease, SessionLease, EnterprisePolicyLease>;
  readonly journal: VaultTransferJournalDependency;
  readonly getImportCapabilities: () => PersonalImportCapabilityPolicy | Promise<PersonalImportCapabilityPolicy>;
  readonly validateImportSource?: (
    source: VaultTransferSourceOk,
    capabilities: PersonalImportCapabilityPolicy,
  ) => boolean | Promise<boolean>;
  readonly captureAccountIdentity: () =>
    | VaultTransferAccountIdentitySnapshot<AccountIdentityLease>
    | Promise<VaultTransferAccountIdentitySnapshot<AccountIdentityLease>>;
  readonly assertAccountIdentityCurrent: (
    snapshot: VaultTransferAccountIdentitySnapshot<AccountIdentityLease>,
  ) => boolean | void | Promise<boolean | void>;
  readonly captureTransferLeases: () => TransferLease | Promise<TransferLease>;
  readonly assertTransferLeasesCurrent: (
    leases: TransferLease,
  ) => boolean | void | Promise<boolean | void>;
  readonly captureReconcileLeases: () => ReconcileLease | Promise<ReconcileLease>;
  readonly assertReconcileLeasesCurrent: (
    leases: ReconcileLease,
  ) => boolean | void | Promise<boolean | void>;
  readonly commitImport?: (input: VaultTransferImportCommitInput) => void | Promise<void>;
  readonly buildExport?: (
    format: VaultTransferExportFormat,
    filePassword: string | undefined,
    authorization: ExportAuthorization,
    target: VaultTransferExportTarget,
  ) => BuiltVaultTransferExport | Promise<BuiltVaultTransferExport>;
  /** Synchronously consume one worker-issued, format-bound user-verification grant. */
  readonly redeemExportAuthorization?: (
    input: VaultTransferExportAuthorizationInput,
  ) => ExportAuthorization | undefined;
  readonly reconcileCurrentAccount?: (input: VaultTransferReconcileInput) => void | Promise<void>;
  readonly inspectSource?: (
    source: Uint8Array,
    options: InspectVaultTransferSourceOptions | undefined,
    authority: VaultTransferInspectAuthority<AccountIdentityLease, TransferLease>,
  ) => Promise<VaultTransferSourceResult>;
  readonly sourceLimits?: VaultTransferSourceLimits;
  readonly exportChunkBytes?: number;
  readonly now?: () => number;
}

export interface BeginVaultTransferImportInput {
  readonly expectedTotalBytes?: number;
}

export interface VaultTransferImportPreviewResult {
  readonly transferId: string;
  readonly sourceFormat: VaultTransferSourceFormat;
  readonly previewCapability: string;
  readonly preview: VaultTransferPreview;
}

export interface VaultTransferImportConfirmation {
  readonly transferId: string;
  readonly status: 'confirmed';
}

export interface VaultTransferImportCommitResult {
  readonly transferId: string;
  readonly status: 'completed' | 'partial' | 'outcome_unknown';
  readonly counts: VaultTransferImportOutcomeCounts;
  readonly requiresReconcile: boolean;
}

export interface VaultTransferImportOutcomeCounts {
  readonly committed: number;
  readonly rejected: number;
  readonly skipped: number;
  readonly outcomeUnknown: number;
}

export interface BeginVaultTransferExportInput {
  readonly format: VaultTransferExportFormat;
  readonly authorizationId: string;
  readonly filePassword?: string;
  readonly target?: VaultTransferExportTarget;
}

export interface BegunVaultTransferExport {
  readonly transferId: string;
  readonly format: VaultTransferExportFormat;
  readonly filename: string;
  readonly totalBytes: number;
  readonly chunkBytes: number;
  readonly expiresAt: number;
  readonly review?: VaultTransferExportReview;
}

export interface VaultTransferExportResult {
  readonly transferId: string;
  readonly format: VaultTransferExportFormat;
  readonly status: 'completed';
  readonly totalBytes: number;
}

export interface VaultTransferCancelResult {
  readonly cancelled: boolean;
  readonly requiresReconcile: boolean;
}

export interface VaultTransferReconcileResult {
  readonly reconciled: number;
}

export type VaultTransferReplayBarrierReason =
  | 'outcome_unknown'
  | 'partial_result'
  | 'pending_result_delivery';

export interface VaultTransferReplayBarrierEntry {
  readonly transferId: string;
  readonly reason: VaultTransferReplayBarrierReason;
  readonly reconciled: boolean;
  readonly clearable: boolean;
}

export interface VaultTransferReplayBarrierInspection {
  readonly count: number;
  readonly unresolvedUnknownCount: number;
  readonly reconcileRequiredCount: number;
  readonly omittedCount: number;
  readonly barriers: readonly VaultTransferReplayBarrierEntry[];
}

export interface VaultTransferReplayBarrierClearResult {
  readonly cleared: number;
}

type ImportPhase =
  | 'uploading'
  | 'inspecting'
  | 'previewed'
  | 'confirming'
  | 'confirmed'
  | 'committing'
  | 'finalizing';
type ExportPhase = 'building' | 'ready' | 'streaming';
type MaintenancePhase = 'none' | 'startup' | 'reconcile' | 'clearing' | 'barrier';

interface TransferStateBase {
  readonly transferId: string;
  readonly expiresAt: number;
  readonly abort: AbortController;
  cancelled: boolean;
}

interface ImportState extends TransferStateBase {
  readonly direction: 'import';
  phase: ImportPhase;
  passwordBytes?: Uint8Array;
  previewRevision?: string;
  previewFingerprint?: string;
  previewCanCommit?: boolean;
  confirmationId?: string;
  journalAccountIdentityDigest?: string;
  journalBegun: boolean;
  resultDeliveryAbandoned?: boolean;
}

interface ExportState extends TransferStateBase {
  readonly direction: 'export';
  phase: ExportPhase;
  readonly format: VaultTransferExportFormat;
  readonly target: VaultTransferExportTarget;
  filename?: string;
  totalBytes?: number;
  chunkBytes?: number;
  confirmationId?: string;
  activeProducer?: ExportChunkProducer;
}

type TransferState = ImportState | ExportState;

interface ImportInspectionSnapshot {
  readonly source: VaultTransferSourceOk;
  readonly capabilities: PersonalImportCapabilityPolicy;
  readonly preview: VaultTransferPreview;
  readonly fingerprint: string;
}

interface ImportPrivateContext<AccountIdentityLease, TransferLease> {
  readonly account: VaultTransferAccountIdentitySnapshot<AccountIdentityLease>;
  readonly accountIdentityDigest: string;
  readonly transferLeases: TransferLease;
}

type ImportAuthorityContext<AccountIdentityLease, TransferLease> = Pick<
  ImportPrivateContext<AccountIdentityLease, TransferLease>,
  'account' | 'transferLeases'
>;

interface PendingImportResultAck<AccountIdentityLease, TransferLease> {
  readonly accountIdentityDigest: string;
  readonly context: ImportPrivateContext<AccountIdentityLease, TransferLease>;
}

/**
 * Coordinates plaintext transfer sessions without knowing about runtime messaging or browser APIs.
 * Protocol adapters are responsible only for moving chunks and invoking these narrow operations.
 */
export class VaultTransferController<
  AccountLease,
  SessionLease,
  EnterprisePolicyLease,
  AccountIdentityLease,
  TransferLease,
  ReconcileLease = TransferLease,
  ExportAuthorization = boolean,
> {
  private readonly sessions: VaultTransferControllerDeps<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease,
    AccountIdentityLease,
    TransferLease
  >['sessions'];
  private readonly journal: VaultTransferJournalDependency;
  private readonly getImportCapabilities: VaultTransferControllerDeps<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease,
    AccountIdentityLease,
    TransferLease
  >['getImportCapabilities'];
  private readonly validateImportSource: VaultTransferControllerDeps<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease,
    AccountIdentityLease,
    TransferLease
  >['validateImportSource'];
  private readonly captureAccountIdentity: VaultTransferControllerDeps<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease,
    AccountIdentityLease,
    TransferLease
  >['captureAccountIdentity'];
  private readonly assertAccountIdentityCurrent: VaultTransferControllerDeps<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease,
    AccountIdentityLease,
    TransferLease
  >['assertAccountIdentityCurrent'];
  private readonly captureTransferLeases: VaultTransferControllerDeps<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease,
    AccountIdentityLease,
    TransferLease
  >['captureTransferLeases'];
  private readonly assertTransferLeasesCurrent: VaultTransferControllerDeps<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease,
    AccountIdentityLease,
    TransferLease
  >['assertTransferLeasesCurrent'];
  private readonly captureReconcileLeases: () => ReconcileLease | Promise<ReconcileLease>;
  private readonly assertReconcileLeasesCurrent: (
    leases: ReconcileLease,
  ) => boolean | void | Promise<boolean | void>;
  private readonly commitImport: VaultTransferControllerDeps<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease,
    AccountIdentityLease,
    TransferLease
  >['commitImport'];
  private readonly buildExport: VaultTransferControllerDeps<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease,
    AccountIdentityLease,
    TransferLease,
    ReconcileLease,
    ExportAuthorization
  >['buildExport'];
  private readonly redeemExportAuthorization: VaultTransferControllerDeps<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease,
    AccountIdentityLease,
    TransferLease,
    ReconcileLease,
    ExportAuthorization
  >['redeemExportAuthorization'];
  private readonly reconcileCurrentAccountHook: VaultTransferControllerDeps<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease,
    AccountIdentityLease,
    TransferLease
  >['reconcileCurrentAccount'];
  private readonly inspectSource: NonNullable<VaultTransferControllerDeps<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease,
    AccountIdentityLease,
    TransferLease
  >['inspectSource']>;
  private readonly sourceLimits: VaultTransferSourceLimits | undefined;
  private readonly configuredExportChunkBytes: number;
  private readonly now: () => number;
  private readonly states = new Map<string, TransferState>();
  private readonly importPrivateContexts = new WeakMap<
    ImportState,
    ImportPrivateContext<AccountIdentityLease, TransferLease>
  >();
  private readonly pendingImportResultAcks = new Map<
    string,
    PendingImportResultAck<AccountIdentityLease, TransferLease>
  >();
  private maintenance: MaintenancePhase = 'none';
  private startupReady = false;
  private globalImportBlocked = false;
  private activeAccountIdentityDigest: string | undefined;
  private readonly blockedAccountIdentityDigests = new Set<string>();
  private activeImportCommits = 0;
  private revocationGeneration = 0;

  constructor(deps: VaultTransferControllerDeps<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease,
    AccountIdentityLease,
    TransferLease,
    ReconcileLease,
    ExportAuthorization
  >) {
    this.sessions = deps.sessions;
    this.journal = deps.journal;
    this.getImportCapabilities = deps.getImportCapabilities;
    this.validateImportSource = deps.validateImportSource;
    this.captureAccountIdentity = deps.captureAccountIdentity;
    this.assertAccountIdentityCurrent = deps.assertAccountIdentityCurrent;
    this.captureTransferLeases = deps.captureTransferLeases;
    this.assertTransferLeasesCurrent = deps.assertTransferLeasesCurrent;
    this.captureReconcileLeases = deps.captureReconcileLeases;
    this.assertReconcileLeasesCurrent = deps.assertReconcileLeasesCurrent;
    this.commitImport = deps.commitImport;
    this.buildExport = deps.buildExport;
    this.redeemExportAuthorization = deps.redeemExportAuthorization;
    this.reconcileCurrentAccountHook = deps.reconcileCurrentAccount;
    this.inspectSource = deps.inspectSource ?? inspectVaultTransferSource;
    this.sourceLimits = deps.sourceLimits;
    this.configuredExportChunkBytes = boundedPositiveInteger(
      deps.exportChunkBytes ?? DEFAULT_VAULT_TRANSFER_EXPORT_CHUNK_BYTES,
      'exportChunkBytes',
    );
    this.now = deps.now ?? (() => Date.now());
  }

  get retainedPasswordBytes(): number {
    let total = 0;
    for (const state of this.states.values()) {
      if (state.direction === 'import') total += state.passwordBytes?.byteLength ?? 0;
    }
    return total;
  }

  beginImport(input: BeginVaultTransferImportInput = {}): BegunVaultTransfer {
    if (this.maintenance !== 'none') throw new VaultTransferControllerError('invalid_state');
    if (!this.startupReady) throw new VaultTransferControllerError('invalid_state');
    if (this.globalImportBlocked
      || (this.activeAccountIdentityDigest !== undefined
        && this.blockedAccountIdentityDigests.has(this.activeAccountIdentityDigest))) {
      throw new VaultTransferControllerError('outcome_unknown');
    }
    if (this.activeImportCommits > 0) throw new VaultTransferControllerError('capacity');
    this.pruneInactiveImportStates();
    if ([...this.states.values()].some((state) => state.direction === 'import')) {
      throw new VaultTransferControllerError('capacity');
    }
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
      throw new VaultTransferControllerError('invalid_request');
    }
    let begun: BegunVaultTransfer;
    try {
      begun = this.sessions.begin({
        direction: 'import',
        ...(input.expectedTotalBytes === undefined ? {} : { expectedTotalBytes: input.expectedTotalBytes }),
      });
    } catch (error) {
      throw normalizeControllerError(error, 'invalid_request');
    }
    const state: ImportState = {
      transferId: begun.transferId,
      direction: 'import',
      phase: 'uploading',
      expiresAt: begun.expiresAt,
      abort: new AbortController(),
      cancelled: false,
      journalBegun: false,
    };
    if (this.states.has(state.transferId)) {
      this.sessions.cancel(state.transferId);
      throw new VaultTransferControllerError('capacity');
    }
    this.states.set(state.transferId, state);
    return begun;
  }

  appendImportChunk(transferId: string, sequence: number, chunk: Uint8Array): VaultTransferChunkAck {
    const state = this.requireImport(transferId, 'uploading');
    try {
      return this.sessions.append(transferId, sequence, chunk);
    } catch (error) {
      this.destroyState(state, true);
      throw normalizeControllerError(error, 'invalid_request');
    }
  }

  acknowledgeImportChunk(transferId: string, sequence: number): void {
    const state = this.requireImport(transferId, 'uploading');
    try {
      this.sessions.acknowledge(transferId, sequence);
    } catch (error) {
      this.destroyState(state, true);
      throw normalizeControllerError(error, 'invalid_request');
    }
  }

  async sealAndInspectImport(
    transferId: string,
    password?: string,
  ): Promise<VaultTransferImportPreviewResult> {
    const state = this.requireImport(transferId, 'uploading');
    if (this.globalImportBlocked) {
      this.destroyState(state, true);
      throw new VaultTransferControllerError('outcome_unknown');
    }
    state.phase = 'inspecting';
    try {
      if (password !== undefined) validatePasswordShape(password);
      await this.sessions.seal(transferId);
      const inspected = await this.sessions.inspect(transferId, async ({
        bytes,
        direction,
        sourceDigest,
      }) => {
        this.assertActive(state, 'inspecting');
        if (direction !== 'import') throw new VaultTransferControllerError('invalid_state');
        const account = await this.captureCurrentAccount();
        const transferLeases = await this.captureCurrentTransferLeases();
        const context: ImportAuthorityContext<AccountIdentityLease, TransferLease> = {
          account,
          transferLeases,
        };
        await this.assertImportContextCurrent(context);
        const inspection = await this.inspectImport(state, bytes, password, context);
        await this.assertImportContextCurrent(context);
        const accountIdentityDigest = await this.assertSourceReplaySafe(account, sourceDigest);
        return { inspection, account, accountIdentityDigest, transferLeases };
      });
      this.assertActive(state, 'inspecting');
      state.phase = 'previewed';
      state.previewRevision = inspected.previewRevision;
      state.previewFingerprint = inspected.preview.inspection.fingerprint;
      state.previewCanCommit = inspected.preview.inspection.preview.canCommit;
      this.importPrivateContexts.set(state, {
        account: inspected.preview.account,
        accountIdentityDigest: inspected.preview.accountIdentityDigest,
        transferLeases: inspected.preview.transferLeases,
      });
      this.activeAccountIdentityDigest = inspected.preview.accountIdentityDigest;
      return Object.freeze({
        transferId,
        sourceFormat: inspected.preview.inspection.source.format,
        previewCapability: inspected.previewRevision,
        preview: inspected.preview.inspection.preview,
      });
    } catch (error) {
      this.destroyState(state, true);
      throw normalizeControllerError(error, 'invalid_input');
    }
  }

  confirmImport(transferId: string, previewCapability: string): VaultTransferImportConfirmation {
    const state = this.requireImport(transferId, 'previewed');
    const context = this.importPrivateContexts.get(state);
    if (this.globalImportBlocked
      || (context !== undefined
        && this.blockedAccountIdentityDigests.has(context.accountIdentityDigest))) {
      this.destroyState(state, true);
      throw new VaultTransferControllerError('outcome_unknown');
    }
    const previewRevision = state.previewRevision;
    const previewFingerprint = state.previewFingerprint;
    const canCommit = state.previewCanCommit === true;

    // Consume every preview capability before validating it or invoking the session manager.
    delete state.previewRevision;
    delete state.previewCanCommit;
    state.phase = 'confirming';
    if (previewRevision === undefined
      || previewFingerprint === undefined
      || previewCapability !== previewRevision
      || !canCommit) {
      this.destroyState(state, true);
      throw new VaultTransferControllerError(canCommit ? 'preview_mismatch' : 'preview_blocked');
    }

    try {
      const confirmed = this.sessions.confirm(transferId, previewRevision);
      this.assertActive(state, 'confirming');
      state.confirmationId = confirmed.confirmationId;
      state.previewFingerprint = previewFingerprint;
      state.phase = 'confirmed';
      return Object.freeze({ transferId, status: 'confirmed' });
    } catch (error) {
      this.destroyState(state, true);
      throw normalizeControllerError(error, 'preview_mismatch');
    }
  }

  async commitConfirmedImport(transferId: string): Promise<VaultTransferImportCommitResult> {
    const state = this.requireImport(transferId, 'confirmed');
    if (!this.commitImport) {
      this.destroyState(state, true);
      throw new VaultTransferControllerError('commit_unavailable');
    }
    const confirmationId = state.confirmationId;
    const expectedFingerprint = state.previewFingerprint;
    const context = this.importPrivateContexts.get(state);
    if (confirmationId === undefined || expectedFingerprint === undefined || context === undefined) {
      this.destroyState(state, true);
      throw new VaultTransferControllerError('invalid_state');
    }
    if (this.globalImportBlocked
      || this.blockedAccountIdentityDigests.has(context.accountIdentityDigest)) {
      this.destroyState(state, true);
      throw new VaultTransferControllerError('outcome_unknown');
    }

    state.phase = 'committing';
    this.activeImportCommits += 1;
    let journalIdentityDigest: string | undefined;
    let journalBegun = false;
    let authoritative: ImportInspectionSnapshot | undefined;
    try {
      await this.assertImportContextCurrent(context);
      const reparsed = await this.sessions.withConfirmedBytes(transferId, confirmationId, async ({
        bytes,
        direction,
        sourceDigest,
      }) => {
        this.assertActive(state, 'committing');
        if (direction !== 'import') throw new VaultTransferControllerError('invalid_state');

        // Remove and zero the only retained password representation before authoritative parsing.
        const current = await this.inspectConfirmedImport(state, bytes, context);
        await this.assertImportContextCurrent(context);
        if (current.fingerprint !== expectedFingerprint || !current.preview.canCommit) {
          throw new VaultTransferControllerError('preview_mismatch');
        }
        return { current, sourceDigest };
      });

      // Raw uploaded bytes and their scratch copy are gone before any remote operation begins.
      this.sessions.complete(transferId, confirmationId);
      authoritative = reparsed.current;
      this.assertActive(state, 'committing');
      await this.assertImportContextCurrent(context);
      await this.assertSourceReplaySafe(context.account, reparsed.sourceDigest);
      if (this.globalImportBlocked
        || this.blockedAccountIdentityDigests.has(context.accountIdentityDigest)) {
        throw new VaultTransferControllerError('outcome_unknown');
      }
      const journalPlan = journalPlanFromSource(authoritative.source);
      const expectedSourceKeys = new Set(
        journalPlan.map((entry) => `${entry.kind}:${entry.sourceIndex}`),
      );

      journalIdentityDigest = await digestVaultTransferAccountIdentity(context.account.canonicalIdentity);
      await this.assertImportContextCurrent(context);
      await this.journal.begin({
        transferId,
        direction: 'import',
        accountIdentityDigest: journalIdentityDigest,
        sourceDigest: reparsed.sourceDigest,
      }, journalPlan);
      journalBegun = true;
      state.journalBegun = true;
      state.journalAccountIdentityDigest = journalIdentityDigest;
      this.assertActive(state, 'committing');
      await this.assertImportContextCurrent(context);

      const facade = new ScopedCommitJournal(
        this.journal,
        transferId,
        journalIdentityDigest,
        state.abort.signal,
        () => this.assertActive(state, 'committing'),
        () => this.assertImportContextCurrent(context),
      );
      await this.commitImport({
        source: authoritative.source,
        capabilities: authoritative.capabilities,
        journal: facade,
      });
      await facade.assertCurrent();
      const audit = await auditJournalOutcomes(
        this.journal,
        transferId,
        journalIdentityDigest,
        expectedSourceKeys,
      );
      if (audit.counts.outcomeUnknown > 0 || audit.summary.requiresReconcile) {
        throw new VaultTransferControllerError('outcome_unknown');
      }
      if (!audit.complete) throw new VaultTransferControllerError('commit_incomplete');

      this.assertActive(state, 'committing');
      await this.assertImportContextCurrent(context);
      const partial = audit.counts.rejected > 0 || audit.counts.skipped > 0;
      const requiresReconcile = partial && audit.counts.committed > 0;
      state.phase = 'finalizing';
      await this.journal.complete(
        transferId,
        journalIdentityDigest,
        requiresReconcile ? { requiresReconcile: true } : {},
      );
      if (state.resultDeliveryAbandoned !== true) {
        this.pendingImportResultAcks.set(transferId, {
          accountIdentityDigest: journalIdentityDigest,
          context,
        });
      }
      this.destroyState(state, false);
      if (requiresReconcile) this.blockedAccountIdentityDigests.add(journalIdentityDigest);
      return importCommitResult(
        transferId,
        partial ? 'partial' : 'completed',
        audit.counts,
        requiresReconcile,
      );
    } catch (error) {
      let cancelledSummary: VaultTransferJournalSummary | undefined;
      if (journalBegun && journalIdentityDigest !== undefined) {
        this.blockedAccountIdentityDigests.add(journalIdentityDigest);
        try {
          cancelledSummary = await this.journal.cancel(transferId, journalIdentityDigest);
          if (!cancelledSummary.requiresReconcile && !cancelledSummary.unresolvedOutcomeUnknown) {
            this.blockedAccountIdentityDigests.delete(journalIdentityDigest);
          }
        } catch {
          // Preserve the original stable failure. Startup inspection remains the recovery boundary.
        }
      }
      const cancelled = state.cancelled;
      this.destroyState(state, true);
      if (cancelled) throw new VaultTransferControllerError('cancelled');
      const normalized = normalizeControllerError(error, 'commit_failed');
      if (journalIdentityDigest !== undefined
        && cancelledSummary?.requiresReconcile === true) {
        this.blockedAccountIdentityDigests.add(journalIdentityDigest);
        try {
          const counts = await readJournalOutcomeCounts(
            this.journal,
            transferId,
            journalIdentityDigest,
            cancelledSummary,
          );
          const status = counts.outcomeUnknown > 0 ? 'outcome_unknown' : 'partial';
          if (status === 'partial') {
            this.pendingImportResultAcks.set(transferId, {
              accountIdentityDigest: journalIdentityDigest,
              context,
            });
          }
          return importCommitResult(
            transferId,
            status,
            counts,
            true,
          );
        } catch {
          // The original stable failure remains authoritative when journal inspection also fails.
        }
      }
      throw normalized;
    } finally {
      this.activeImportCommits -= 1;
    }
  }

  async beginExport(input: BeginVaultTransferExportInput): Promise<BegunVaultTransferExport> {
    if (this.maintenance !== 'none') throw new VaultTransferControllerError('invalid_state');
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
      throw new VaultTransferControllerError('invalid_request');
    }
    validateExportPassword(input.format, input.filePassword);
    const target = canonicalControllerExportTarget(input.target);
    if (input.format === 'zip' && target.kind === 'organization') {
      throw new VaultTransferControllerError('invalid_request');
    }
    if (!this.buildExport) throw new VaultTransferControllerError('export_unavailable');
    let authorization: ExportAuthorization | undefined;
    try {
      authorization = typeof input.authorizationId === 'string'
        ? this.redeemExportAuthorization?.({
          authorizationId: input.authorizationId,
          format: input.format,
          ...(input.format === 'encrypted-json'
            ? { encryptionType: input.filePassword === undefined ? 'account' : 'file' }
            : {}),
          target,
        })
        : undefined;
    } catch {
      authorization = undefined;
    }
    if (!authorization || !authorizationTargetMatches(authorization, target)) {
      throw new VaultTransferControllerError('export_authorization_invalid');
    }

    let begun: BegunVaultTransfer;
    try {
      begun = this.sessions.begin({ direction: 'export' });
    } catch (error) {
      throw normalizeControllerError(error, 'export_failed');
    }
    const state: ExportState = {
      transferId: begun.transferId,
      direction: 'export',
      phase: 'building',
      format: input.format,
      target,
      expiresAt: begun.expiresAt,
      abort: new AbortController(),
      cancelled: false,
    };
    if (this.states.has(state.transferId)) {
      this.sessions.cancel(state.transferId);
      throw new VaultTransferControllerError('capacity');
    }
    this.states.set(state.transferId, state);

    let built: BuiltVaultTransferExport | undefined;
    try {
      built = await this.buildExport(input.format, input.filePassword, authorization, target);
      this.assertActive(state, 'building');
      const review = validateBuiltExport(built, input.format);
      state.filename = built.filename;
      state.totalBytes = built.bytes.byteLength;
      state.chunkBytes = Math.min(this.configuredExportChunkBytes, begun.maxChunkBytes);

      try {
        for (let offset = 0, sequence = 0; offset < built.bytes.byteLength; sequence += 1) {
          const end = Math.min(offset + begun.maxChunkBytes, built.bytes.byteLength);
          const ack = this.sessions.append(state.transferId, sequence, built.bytes.subarray(offset, end));
          this.sessions.acknowledge(state.transferId, ack.sequence);
          offset = end;
        }
      } finally {
        clearBuiltExport(built);
      }

      await this.sessions.seal(state.transferId);
      const inspected = await this.sessions.inspect(state.transferId, ({ bytes, direction }) => {
        this.assertActive(state, 'building');
        if (direction !== 'export' || bytes.byteLength !== state.totalBytes) {
          throw new VaultTransferControllerError('invalid_state');
        }
        return Object.freeze({ ready: true });
      });
      const confirmed = this.sessions.confirm(state.transferId, inspected.previewRevision);
      this.assertActive(state, 'building');
      state.confirmationId = confirmed.confirmationId;
      state.phase = 'ready';
      return Object.freeze({
        transferId: state.transferId,
        format: state.format,
        filename: built.filename,
        totalBytes: built.bytes.byteLength,
        chunkBytes: Math.min(this.configuredExportChunkBytes, begun.maxChunkBytes),
        expiresAt: state.expiresAt,
        ...(review ? { review } : {}),
      });
    } catch (error) {
      clearBuiltExport(built);
      const cancelled = state.cancelled;
      this.destroyState(state, true);
      if (cancelled) throw new VaultTransferControllerError('cancelled');
      throw normalizeControllerError(error, 'export_failed');
    }
  }

  async acknowledgeImportResult(transferId: string): Promise<void> {
    if (this.maintenance !== 'none') throw new VaultTransferControllerError('invalid_state');
    const revocation = this.revocationGeneration;
    const pending = this.pendingImportResultAcks.get(transferId);
    if (!pending) throw new VaultTransferControllerError('not_found');
    try {
      await this.assertImportContextCurrent(pending.context);
      this.assertRevocationCurrent(revocation);
      const summary = await this.journal.acknowledgeResultDelivered(
        transferId,
        pending.accountIdentityDigest,
      );
      this.assertRevocationCurrent(revocation);
      await this.assertImportContextCurrent(pending.context);
      if (summary.resultDeliveredAt === null || summary.unresolvedOutcomeUnknown) {
        throw new VaultTransferControllerError('invalid_state');
      }
      this.pendingImportResultAcks.delete(transferId);
    } catch (error) {
      throw normalizeControllerError(error, 'journal_failed');
    }
  }

  async streamExport(
    transferId: string,
    consume: (input: VaultTransferExportStreamInput) => void | Promise<void>,
  ): Promise<VaultTransferExportResult> {
    if (typeof consume !== 'function') throw new VaultTransferControllerError('invalid_request');
    const state = this.requireExport(transferId, 'ready');
    const confirmationId = state.confirmationId;
    const filename = state.filename;
    const totalBytes = state.totalBytes;
    const chunkBytes = state.chunkBytes;
    if (confirmationId === undefined || filename === undefined
      || totalBytes === undefined || chunkBytes === undefined) {
      this.destroyState(state, true);
      throw new VaultTransferControllerError('invalid_state');
    }
    state.phase = 'streaming';

    try {
      await this.sessions.withConfirmedBytes(transferId, confirmationId, async ({ bytes, direction }) => {
        this.assertActive(state, 'streaming');
        if (direction !== 'export' || bytes.byteLength !== totalBytes) {
          throw new VaultTransferControllerError('invalid_state');
        }
        const producer = new ExportChunkProducer(
          bytes,
          chunkBytes,
          state.abort.signal,
          () => this.assertSessionActive(state, 'streaming'),
        );
        state.activeProducer = producer;
        try {
          await consume(Object.freeze({
            transferId,
            format: state.format,
            filename,
            totalBytes,
            signal: state.abort.signal,
            producer,
          }));
          this.assertActive(state, 'streaming');
          if (!producer.completed) throw new VaultTransferControllerError('export_incomplete');
        } finally {
          producer.destroy();
          if (state.activeProducer === producer) delete state.activeProducer;
        }
      });
      this.assertActive(state, 'streaming');
      this.sessions.complete(transferId, confirmationId);
      this.destroyState(state, false);
      return Object.freeze({
        transferId,
        format: state.format,
        status: 'completed',
        totalBytes,
      });
    } catch (error) {
      const cancelled = state.cancelled;
      this.destroyState(state, true);
      if (cancelled) throw new VaultTransferControllerError('cancelled');
      throw normalizeControllerError(error, 'export_failed');
    }
  }

  async cancel(transferId: string): Promise<VaultTransferCancelResult> {
    if (typeof transferId !== 'string') throw new VaultTransferControllerError('invalid_request');
    const state = this.states.get(transferId);
    if (!state) return Object.freeze({ cancelled: false, requiresReconcile: false });
    if (state.direction === 'import' && state.phase === 'finalizing') {
      state.resultDeliveryAbandoned = true;
      return Object.freeze({ cancelled: false, requiresReconcile: false });
    }
    state.cancelled = true;
    state.abort.abort();
    if (state.direction === 'export') state.activeProducer?.destroy();
    clearPassword(state);
    this.sessions.cancel(transferId);

    let requiresReconcile = false;
    if (state.direction === 'import'
      && state.journalBegun
      && state.journalAccountIdentityDigest !== undefined) {
      try {
        const summary = await this.journal.cancel(transferId, state.journalAccountIdentityDigest);
        requiresReconcile = summary.requiresReconcile;
      } catch {
        requiresReconcile = true;
      }
    }
    if (requiresReconcile && state.direction === 'import'
      && state.journalAccountIdentityDigest !== undefined) {
      this.blockedAccountIdentityDigests.add(state.journalAccountIdentityDigest);
    }
    this.destroyState(state, false);
    return Object.freeze({ cancelled: true, requiresReconcile });
  }

  disconnect(transferId: string): Promise<VaultTransferCancelResult> {
    return this.cancel(transferId);
  }

  async sweepExpired(): Promise<number> {
    const timestamp = currentTimestamp(this.now);
    const expired = [...this.states.values()].filter((state) => state.expiresAt <= timestamp);
    for (const state of expired) await this.cancel(state.transferId);
    this.sessions.sweepExpired();
    return expired.length;
  }

  async clearAll(): Promise<number> {
    return this.revokeAll();
  }

  /** Synchronously revoke every plaintext owner, then persist journal cancellation asynchronously. */
  async revokeAll(): Promise<number> {
    const revocation = this.revocationGeneration + 1;
    this.revocationGeneration = revocation;
    this.maintenance = 'clearing';
    const states = [...this.states.values()];
    this.startupReady = false;
    this.activeAccountIdentityDigest = undefined;
    this.pendingImportResultAcks.clear();
    const journals: Array<{ readonly transferId: string; readonly accountIdentityDigest: string }> = [];
    for (const state of states) {
      state.cancelled = true;
      if (state.direction === 'import' && state.phase === 'finalizing') {
        state.resultDeliveryAbandoned = true;
      }
      state.abort.abort();
      if (state.direction === 'export') state.activeProducer?.destroy();
      clearPassword(state);
      if (state.direction === 'import'
        && state.journalBegun
        && state.journalAccountIdentityDigest !== undefined) {
        journals.push({
          transferId: state.transferId,
          accountIdentityDigest: state.journalAccountIdentityDigest,
        });
      }
      this.destroyState(state, false);
    }
    this.sessions.clearAll();
    try {
      for (const journal of journals) {
        try {
          const summary = await this.journal.cancel(
            journal.transferId,
            journal.accountIdentityDigest,
          );
          if (summary.requiresReconcile || summary.unresolvedOutcomeUnknown) {
            this.blockedAccountIdentityDigests.add(journal.accountIdentityDigest);
          }
        } catch {
          this.blockedAccountIdentityDigests.add(journal.accountIdentityDigest);
        }
      }
      return states.length;
    } finally {
      if (this.revocationGeneration === revocation) this.leaveMaintenance('clearing');
    }
  }

  async inspectJournalForStartup(): Promise<VaultTransferJournalStartupInspection> {
    this.enterMaintenance('startup', false);
    const revocation = this.revocationGeneration;
    this.globalImportBlocked = true;
    try {
      const inspection = await this.journal.inspectForStartup();
      this.assertRevocationCurrent(revocation);
      this.startupReady = true;
      this.refreshBarrierState(inspection);
      return inspection;
    } catch (error) {
      throw normalizeControllerError(error, 'journal_failed');
    } finally {
      this.leaveMaintenance('startup');
    }
  }

  async clearReplayBarrier(transferId: string): Promise<void> {
    this.enterMaintenance('barrier', false);
    const revocation = this.revocationGeneration;
    let accountIdentityDigest: string | undefined;
    try {
      const account = await this.captureCurrentAccount();
      const reconcileLeases = await this.captureCurrentReconcileLeases();
      accountIdentityDigest = await digestVaultTransferAccountIdentity(account.canonicalIdentity);
      this.activeAccountIdentityDigest = accountIdentityDigest;
      await this.assertReconcileContextCurrent(account, reconcileLeases);
      this.assertRevocationCurrent(revocation);
      const summary = await this.journal.clearReplayBarrier(transferId, accountIdentityDigest);
      this.assertRevocationCurrent(revocation);
      await this.assertReconcileContextCurrent(account, reconcileLeases);
      if (summary.replayBarrier || summary.unresolvedOutcomeUnknown) {
        throw new VaultTransferControllerError('journal_failed');
      }
      this.pendingImportResultAcks.delete(transferId);
      const inspection = await this.journal.inspectForStartup();
      this.startupReady = true;
      this.refreshBarrierState(inspection);
    } catch (error) {
      if (accountIdentityDigest !== undefined) {
        this.blockedAccountIdentityDigests.add(accountIdentityDigest);
      }
      throw normalizeControllerError(error, 'journal_failed');
    } finally {
      this.leaveMaintenance('barrier');
    }
  }

  async inspectReplayBarriers(): Promise<VaultTransferReplayBarrierInspection> {
    this.enterMaintenance('barrier', false);
    const revocation = this.revocationGeneration;
    try {
      const account = await this.captureCurrentAccount();
      const reconcileLeases = await this.captureCurrentReconcileLeases();
      const accountIdentityDigest = await digestVaultTransferAccountIdentity(account.canonicalIdentity);
      this.activeAccountIdentityDigest = accountIdentityDigest;
      await this.assertReconcileContextCurrent(account, reconcileLeases);
      this.assertRevocationCurrent(revocation);
      const inspection = await this.journal.inspectForStartup();
      this.assertRevocationCurrent(revocation);
      this.startupReady = true;
      this.refreshBarrierState(inspection);
      const matching = inspection.kind === 'valid'
        ? inspection.journals.filter((journal) => (
            journal.accountIdentityDigest === accountIdentityDigest && journal.replayBarrier
          ))
        : [];
      const barriers = matching.slice(0, 32).map((journal) => Object.freeze({
        transferId: journal.transferId,
        reason: replayBarrierReason(journal),
        reconciled: journal.reconciledAt !== null,
        clearable: journal.phase === 'completed'
          && journal.reconciledAt !== null
          && !this.pendingImportResultAcks.has(journal.transferId),
      }));
      await this.assertReconcileContextCurrent(account, reconcileLeases);
      return Object.freeze({
        count: matching.length,
        unresolvedUnknownCount: matching.filter((journal) => journal.unresolvedOutcomeUnknown).length,
        reconcileRequiredCount: matching.filter((journal) => journal.requiresReconcile).length,
        omittedCount: Math.max(0, matching.length - barriers.length),
        barriers: Object.freeze(barriers),
      });
    } catch (error) {
      throw normalizeControllerError(error, 'journal_failed');
    } finally {
      this.leaveMaintenance('barrier');
    }
  }

  async clearCurrentAccountReplayBarriers(): Promise<VaultTransferReplayBarrierClearResult> {
    this.enterMaintenance('barrier', false);
    const revocation = this.revocationGeneration;
    let accountIdentityDigest: string | undefined;
    try {
      const account = await this.captureCurrentAccount();
      const reconcileLeases = await this.captureCurrentReconcileLeases();
      accountIdentityDigest = await digestVaultTransferAccountIdentity(account.canonicalIdentity);
      this.activeAccountIdentityDigest = accountIdentityDigest;
      this.assertRevocationCurrent(revocation);
      const inspection = await this.journal.inspectForStartup();
      this.assertRevocationCurrent(revocation);
      if (inspection.kind === 'invalid') throw new VaultTransferControllerError('journal_failed');
      const journals = inspection.kind === 'valid' ? inspection.journals.filter((journal) => (
        journal.accountIdentityDigest === accountIdentityDigest
          && journal.replayBarrier
          && journal.phase === 'completed'
          && journal.reconciledAt !== null
          && !this.pendingImportResultAcks.has(journal.transferId)
      )) : [];
      await this.assertReconcileContextCurrent(account, reconcileLeases);
      for (const journal of journals) {
        this.assertRevocationCurrent(revocation);
        await this.journal.clearReplayBarrier(journal.transferId, accountIdentityDigest);
        this.pendingImportResultAcks.delete(journal.transferId);
        await this.assertReconcileContextCurrent(account, reconcileLeases);
      }
      const after = await this.journal.inspectForStartup();
      this.startupReady = true;
      this.refreshBarrierState(after);
      return Object.freeze({ cleared: journals.length });
    } catch (error) {
      if (accountIdentityDigest !== undefined) {
        this.blockedAccountIdentityDigests.add(accountIdentityDigest);
      }
      throw normalizeControllerError(error, 'journal_failed');
    } finally {
      this.leaveMaintenance('barrier');
    }
  }

  async reconcileCurrentAccount(): Promise<VaultTransferReconcileResult> {
    if (!this.reconcileCurrentAccountHook) {
      throw new VaultTransferControllerError('reconcile_unavailable');
    }
    this.enterMaintenance('reconcile', false);
    const revocation = this.revocationGeneration;
    let accountIdentityDigest: string | undefined;
    try {
      const account = await this.captureCurrentAccount();
      const reconcileLeases = await this.captureCurrentReconcileLeases();
      accountIdentityDigest = await digestVaultTransferAccountIdentity(account.canonicalIdentity);
      this.activeAccountIdentityDigest = accountIdentityDigest;
      const forcedSync = this.blockedAccountIdentityDigests.has(accountIdentityDigest);
      this.blockedAccountIdentityDigests.add(accountIdentityDigest);
      const startup = await this.journal.inspectForStartup();
      this.assertRevocationCurrent(revocation);
      this.startupReady = true;
      if (startup.kind === 'invalid') throw new VaultTransferControllerError('reconcile_failed');
      this.refreshBarrierState(startup);
      this.blockedAccountIdentityDigests.add(accountIdentityDigest);
      if (startup.kind === 'none' && !forcedSync) {
        this.blockedAccountIdentityDigests.delete(accountIdentityDigest);
        return Object.freeze({ reconciled: 0 });
      }
      const startupJournals = startup.kind === 'valid' ? startup.journals : [];
      const journals = startupJournals.filter(
        (journal) => journal.accountIdentityDigest === accountIdentityDigest
          && (journal.requiresReconcile || journal.replayBarrier),
      );
      if (journals.length === 0 && !forcedSync) {
        this.refreshBarrierState(startup);
        return Object.freeze({ reconciled: 0 });
      }

      await this.assertReconcileContextCurrent(account, reconcileLeases);
      this.assertRevocationCurrent(revocation);
      await this.reconcileCurrentAccountHook(Object.freeze({
        accountIdentityDigest,
        journals: Object.freeze(journals),
      }));
      this.assertRevocationCurrent(revocation);
      await this.assertReconcileContextCurrent(account, reconcileLeases);
      for (const journal of journals) {
        this.assertRevocationCurrent(revocation);
        if (journal.requiresReconcile) {
          await this.journal.acknowledgeReconciled(journal.transferId, accountIdentityDigest);
        } else if (journal.replayBarrier && journal.reconciledAt === null) {
          await this.journal.acknowledgeReplayBarrierReconciled(
            journal.transferId,
            accountIdentityDigest,
          );
        }
        await this.assertReconcileContextCurrent(account, reconcileLeases);
      }
      const after = await this.journal.inspectForStartup();
      this.assertRevocationCurrent(revocation);
      this.refreshBarrierState(after);
      return Object.freeze({ reconciled: journals.length });
    } catch (error) {
      if (accountIdentityDigest !== undefined) {
        this.blockedAccountIdentityDigests.add(accountIdentityDigest);
      }
      throw normalizeControllerError(error, 'reconcile_failed');
    } finally {
      this.leaveMaintenance('reconcile');
    }
  }

  private async inspectImport(
    state: ImportState,
    bytes: Readonly<Uint8Array>,
    password: string | undefined,
    context: ImportAuthorityContext<AccountIdentityLease, TransferLease>,
  ): Promise<ImportInspectionSnapshot> {
    const source = await this.inspectWithPasswordHandshake(
      bytes,
      password !== undefined,
      () => {
        this.assertActive(state, 'inspecting');
        if (password === undefined) return undefined;
        state.passwordBytes = encodePassword(password);
        return readPassword(state);
      },
      context,
    );
    return this.finishImportInspection(source);
  }

  private async finishImportInspection(source: VaultTransferSourceOk): Promise<ImportInspectionSnapshot> {
    const capabilities = await this.getImportCapabilities();
    const advancedDataSupported = this.validateImportSource
      ? await this.validateImportSource(source, capabilities)
      : true;
    const preview = buildVaultTransferPreview(source.inspection, capabilities, {
      format: previewFormat(source.format),
      attachmentCount: source.attachmentCount + source.skippedAttachmentCount,
      advancedDataUnsupported: !advancedDataSupported,
    });
    const fingerprint = await fingerprintPreview(source.format, preview);
    return { source, capabilities, preview, fingerprint };
  }

  private inspectConfirmedImport(
    state: ImportState,
    bytes: Readonly<Uint8Array>,
    context: ImportAuthorityContext<AccountIdentityLease, TransferLease>,
  ): Promise<ImportInspectionSnapshot> {
    const passwordSupplied = state.passwordBytes !== undefined;
    return this.inspectWithPasswordHandshake(bytes, passwordSupplied, () => {
      this.assertActive(state, 'committing');
      return takePassword(state);
    }, context)
      .then((source) => this.finishImportInspection(source));
  }

  private async inspectWithPasswordHandshake(
    bytes: Readonly<Uint8Array>,
    passwordSupplied: boolean,
    getPassword: () => string | undefined,
    context: ImportAuthorityContext<AccountIdentityLease, TransferLease>,
  ): Promise<VaultTransferSourceOk> {
    const source = bytes as Uint8Array;
    const authority = this.inspectAuthority(context);
    const initial = await this.inspectSource(source, this.sourceOptions(), authority);
    if (initial.status === 'failed') throw new VaultTransferControllerError(initial.code);
    if (initial.status === 'ok') {
      if (passwordSupplied) throw new VaultTransferControllerError('unexpected_password');
      return initial;
    }
    const password = getPassword();
    if (password === undefined) throw new VaultTransferControllerError('password_required');

    const retry = await this.inspectSource(source, this.sourceOptions(password), authority);
    if (retry.status === 'failed') throw new VaultTransferControllerError(retry.code);
    if (retry.status !== 'ok') throw new VaultTransferControllerError('decryption_failed');
    if (retry.format !== initial.format) throw new VaultTransferControllerError('invalid_input');
    return retry;
  }

  private sourceOptions(password?: string): InspectVaultTransferSourceOptions {
    return {
      ...(password === undefined ? {} : { password }),
      ...(this.sourceLimits === undefined ? {} : { limits: this.sourceLimits }),
    };
  }

  private inspectAuthority(
    context: ImportAuthorityContext<AccountIdentityLease, TransferLease>,
  ): VaultTransferInspectAuthority<AccountIdentityLease, TransferLease> {
    return Object.freeze({
      account: context.account,
      transferLeases: context.transferLeases,
      assertCurrent: () => this.assertImportContextCurrent(context),
    });
  }

  private async captureCurrentAccount(): Promise<VaultTransferAccountIdentitySnapshot<AccountIdentityLease>> {
    let snapshot: VaultTransferAccountIdentitySnapshot<AccountIdentityLease>;
    try {
      snapshot = await this.captureAccountIdentity();
      if (!snapshot || typeof snapshot.canonicalIdentity !== 'string') {
        throw new Error('invalid account snapshot');
      }
    } catch {
      throw new VaultTransferControllerError('account_unavailable');
    }
    await this.assertCurrentAccount(snapshot);
    return snapshot;
  }

  private async captureCurrentTransferLeases(): Promise<TransferLease> {
    let leases: TransferLease;
    try {
      leases = await this.captureTransferLeases();
    } catch {
      throw new VaultTransferControllerError('lease_changed');
    }
    await this.assertCurrentTransferLeases(leases);
    return leases;
  }

  private async assertCurrentAccount(
    snapshot: VaultTransferAccountIdentitySnapshot<AccountIdentityLease>,
  ): Promise<void> {
    try {
      if (await this.assertAccountIdentityCurrent(snapshot) === false) {
        throw new Error('stale account');
      }
    } catch {
      throw new VaultTransferControllerError('lease_changed');
    }
  }

  private async assertCurrentTransferLeases(leases: TransferLease): Promise<void> {
    try {
      if (await this.assertTransferLeasesCurrent(leases) === false) {
        throw new Error('stale transfer leases');
      }
    } catch {
      throw new VaultTransferControllerError('lease_changed');
    }
  }

  private async captureCurrentReconcileLeases(): Promise<ReconcileLease> {
    let leases: ReconcileLease;
    try {
      leases = await this.captureReconcileLeases();
    } catch {
      throw new VaultTransferControllerError('lease_changed');
    }
    await this.assertCurrentReconcileLeases(leases);
    return leases;
  }

  private async assertCurrentReconcileLeases(leases: ReconcileLease): Promise<void> {
    try {
      if (await this.assertReconcileLeasesCurrent(leases) === false) {
        throw new Error('stale reconcile leases');
      }
    } catch {
      throw new VaultTransferControllerError('lease_changed');
    }
  }

  private async assertReconcileContextCurrent(
    account: VaultTransferAccountIdentitySnapshot<AccountIdentityLease>,
    reconcileLeases: ReconcileLease,
  ): Promise<void> {
    await this.assertCurrentReconcileLeases(reconcileLeases);
    await this.assertCurrentAccount(account);
  }

  private async assertImportContextCurrent(
    context: ImportAuthorityContext<AccountIdentityLease, TransferLease>,
  ): Promise<void> {
    await this.assertCurrentTransferLeases(context.transferLeases);
    await this.assertCurrentAccount(context.account);
  }

  private async assertSourceReplaySafe(
    account: VaultTransferAccountIdentitySnapshot<AccountIdentityLease>,
    sourceDigest: string,
  ): Promise<string> {
    const accountIdentityDigest = await digestVaultTransferAccountIdentity(account.canonicalIdentity);
    let startup: VaultTransferJournalStartupInspection;
    try {
      startup = await this.journal.inspectForStartup();
    } catch {
      this.globalImportBlocked = true;
      throw new VaultTransferControllerError('journal_failed');
    }
    this.refreshBarrierState(startup);
    this.activeAccountIdentityDigest = accountIdentityDigest;
    if (startup.kind === 'invalid') {
      throw new VaultTransferControllerError('outcome_unknown');
    }
    if (this.blockedAccountIdentityDigests.has(accountIdentityDigest)) {
      throw new VaultTransferControllerError('outcome_unknown');
    }
    if (startup.kind === 'none') return accountIdentityDigest;
    for (const summary of startup.journals) {
      if (summary.accountIdentityDigest !== accountIdentityDigest
        || summary.sourceDigest !== sourceDigest) continue;
      if (summary.requiresReconcile || summary.replayBarrier) {
        throw new VaultTransferControllerError('outcome_unknown');
      }
    }
    await this.assertCurrentAccount(account);
    return accountIdentityDigest;
  }

  private requireImport(transferId: string, phase: ImportPhase): ImportState {
    const state = this.requireState(transferId);
    if (state.direction !== 'import' || state.phase !== phase) {
      this.destroyState(state, true);
      throw new VaultTransferControllerError('invalid_state');
    }
    return state;
  }

  private requireExport(transferId: string, phase: ExportPhase): ExportState {
    const state = this.requireState(transferId);
    if (state.direction !== 'export' || state.phase !== phase) {
      this.destroyState(state, true);
      throw new VaultTransferControllerError('invalid_state');
    }
    return state;
  }

  private requireState(transferId: string): TransferState {
    if (typeof transferId !== 'string') throw new VaultTransferControllerError('invalid_request');
    if (this.maintenance === 'clearing') throw new VaultTransferControllerError('cancelled');
    const state = this.states.get(transferId);
    if (!state) throw new VaultTransferControllerError('not_found');
    if (state.expiresAt <= currentTimestamp(this.now)) {
      this.destroyState(state, true);
      throw new VaultTransferControllerError('expired');
    }
    try {
      if (!this.sessions.status(transferId)) {
        this.destroyState(state, false);
        throw new VaultTransferControllerError('not_found');
      }
    } catch (error) {
      this.destroyState(state, false);
      throw normalizeControllerError(error, 'lease_changed');
    }
    return state;
  }

  private assertActive(state: TransferState, phase: ImportPhase | ExportPhase): void {
    if (this.maintenance === 'clearing') throw new VaultTransferControllerError('cancelled');
    if (state.expiresAt <= currentTimestamp(this.now)) {
      throw new VaultTransferControllerError('expired');
    }
    if (this.states.get(state.transferId) !== state
      || state.cancelled
      || state.abort.signal.aborted
      || state.phase !== phase) {
      throw new VaultTransferControllerError(state.cancelled ? 'cancelled' : 'invalid_state');
    }
  }

  private assertSessionActive(state: TransferState, phase: ImportPhase | ExportPhase): void {
    this.assertActive(state, phase);
    try {
      if (!this.sessions.status(state.transferId)) {
        this.destroyState(state, false);
        throw new VaultTransferControllerError('not_found');
      }
    } catch (error) {
      this.destroyState(state, false);
      throw normalizeControllerError(error, 'lease_changed');
    }
  }

  private destroyState(state: TransferState, cancelSession: boolean): void {
    clearPassword(state);
    if (state.direction === 'import') this.importPrivateContexts.delete(state);
    if (state.direction === 'export') state.activeProducer?.destroy();
    if (!state.abort.signal.aborted) state.abort.abort();
    if (cancelSession) {
      try {
        this.sessions.cancel(state.transferId);
      } catch {
        // Teardown remains best effort after a stable outer failure was selected.
      }
    }
    if (this.states.get(state.transferId) === state) this.states.delete(state.transferId);
  }

  private pruneInactiveImportStates(): void {
    const now = currentTimestamp(this.now);
    for (const state of [...this.states.values()]) {
      if (state.direction !== 'import'
        || state.phase === 'committing'
        || state.phase === 'finalizing') continue;
      try {
        if (state.expiresAt <= now || !this.sessions.status(state.transferId)) {
          this.destroyState(state, false);
        }
      } catch {
        this.destroyState(state, false);
      }
    }
  }

  private enterMaintenance(phase: Exclude<MaintenancePhase, 'none'>, allowActive: boolean): void {
    if (this.maintenance !== 'none'
      || (!allowActive && (this.states.size > 0 || this.activeImportCommits > 0))) {
      throw new VaultTransferControllerError('invalid_state');
    }
    this.maintenance = phase;
  }

  private leaveMaintenance(phase: Exclude<MaintenancePhase, 'none'>): void {
    if (this.maintenance === phase) this.maintenance = 'none';
  }

  private assertRevocationCurrent(expected: number): void {
    if (this.revocationGeneration !== expected || this.maintenance === 'clearing') {
      throw new VaultTransferControllerError('cancelled');
    }
  }

  private refreshBarrierState(inspection: VaultTransferJournalStartupInspection): void {
    if (inspection.kind === 'invalid') {
      this.globalImportBlocked = true;
      return;
    }
    this.globalImportBlocked = false;
    this.blockedAccountIdentityDigests.clear();
    if (inspection.kind === 'none') return;
    for (const journal of inspection.journals) {
      if (journal.requiresReconcile || journal.unresolvedOutcomeUnknown) {
        this.blockedAccountIdentityDigests.add(journal.accountIdentityDigest);
      }
    }
  }
}

class ScopedCommitJournal implements VaultTransferCommitJournal {
  private halted = false;

  constructor(
    private readonly journal: VaultTransferJournalDependency,
    private readonly transferId: string,
    private readonly accountIdentityDigest: string,
    readonly signal: AbortSignal,
    private readonly assertTransferActive: () => void,
    private readonly assertAccountCurrent: () => Promise<void>,
  ) {}

  async assertCurrent(): Promise<void> {
    if (this.halted) throw new VaultTransferControllerError('outcome_unknown');
    if (this.signal.aborted) throw new VaultTransferControllerError('cancelled');
    this.assertTransferActive();
    await this.assertAccountCurrent();
    if (this.signal.aborted) throw new VaultTransferControllerError('cancelled');
    this.assertTransferActive();
  }

  async markInFlight(
    kind: VaultTransferJournalOperationKind,
    sourceIndex: number,
  ): Promise<VaultTransferJournalInFlight> {
    await this.assertCurrent();
    const marked = await this.journal.markInFlight({
      transferId: this.transferId,
      accountIdentityDigest: this.accountIdentityDigest,
      kind,
      sourceIndex,
    });
    await this.assertCurrent();
    return marked;
  }

  async settleInFlight(settlement: VaultTransferJournalSettlement): Promise<VaultTransferJournalOutcome> {
    await this.assertCurrent();
    const outcome = await this.journal.settleInFlight({
      transferId: this.transferId,
      accountIdentityDigest: this.accountIdentityDigest,
      operationId: settlement.operationId,
      status: settlement.status,
      ...(settlement.status === 'committed' ? {} : { code: settlement.code }),
    });
    if (settlement.status === 'outcome_unknown') {
      this.halted = true;
      throw new VaultTransferControllerError('outcome_unknown');
    }
    await this.assertCurrent();
    return outcome;
  }

  async recordSkipped(
    kind: VaultTransferJournalOperationKind,
    sourceIndex: number,
    code: string,
  ): Promise<VaultTransferJournalOutcome> {
    await this.assertCurrent();
    const outcome = await this.journal.recordSkipped({
      transferId: this.transferId,
      accountIdentityDigest: this.accountIdentityDigest,
      kind,
      sourceIndex,
      code,
    });
    await this.assertCurrent();
    return outcome;
  }

  async getAlias(
    kind: VaultTransferJournalAliasKind,
    sourceIndex: number,
  ): Promise<string | undefined> {
    await this.assertCurrent();
    const alias = await this.journal.getAlias(
      this.transferId,
      this.accountIdentityDigest,
      kind,
      sourceIndex,
    );
    await this.assertCurrent();
    return alias;
  }
}

class ExportChunkProducer implements VaultTransferExportChunkProducer {
  private cursor = 0;
  private sequence = 0;
  private outstanding: { readonly sequence: number; readonly end: number; readonly bytes: Uint8Array } | undefined;
  private reachedEnd = false;
  private destroyed = false;

  constructor(
    private readonly source: Readonly<Uint8Array>,
    private readonly chunkBytes: number,
    private readonly signal: AbortSignal,
    private readonly assertTransferCurrent: () => void,
  ) {}

  get completed(): boolean {
    return this.reachedEnd && this.outstanding === undefined && this.cursor === this.source.byteLength;
  }

  async next(): Promise<VaultTransferExportChunk> {
    this.assertUsable();
    if (this.outstanding) throw new VaultTransferControllerError('ack_required');
    if (this.cursor === this.source.byteLength) {
      this.reachedEnd = true;
      return Object.freeze({ done: true, totalBytes: this.source.byteLength });
    }
    const end = Math.min(this.cursor + this.chunkBytes, this.source.byteLength);
    const bytes = this.source.slice(this.cursor, end);
    this.outstanding = { sequence: this.sequence, end, bytes };
    return Object.freeze({
      done: false,
      sequence: this.sequence,
      bytes,
      requiresAcknowledgement: true,
    });
  }

  acknowledge(sequence: number): void {
    try {
      this.assertUsable();
      if (!this.outstanding || sequence !== this.outstanding.sequence) {
        throw new VaultTransferControllerError('invalid_sequence');
      }
      const acknowledged = this.outstanding;
      this.outstanding = undefined;
      this.cursor = acknowledged.end;
      this.sequence += 1;
      zeroBytes(acknowledged.bytes);
    } catch (error) {
      this.destroy();
      throw normalizeControllerError(error, 'invalid_sequence');
    }
  }

  assertCurrent(): void {
    this.assertUsable();
  }

  destroy(): void {
    const outstanding = this.outstanding;
    this.outstanding = undefined;
    this.destroyed = true;
    if (outstanding) zeroBytes(outstanding.bytes);
  }

  private assertUsable(): void {
    if (this.destroyed || this.signal.aborted) {
      throw new VaultTransferControllerError('cancelled');
    }
    this.assertTransferCurrent();
  }
}

function previewFormat(format: VaultTransferSourceFormat): VaultTransferPreviewFormat {
  if (format === 'csv') return 'bitwarden-csv';
  if (format === 'zip') return 'bitwarden-zip';
  return 'bitwarden-json';
}

async function fingerprintPreview(
  sourceFormat: VaultTransferSourceFormat,
  preview: VaultTransferPreview,
): Promise<string> {
  const canonical = JSON.stringify({
    sourceFormat,
    format: preview.format,
    scope: preview.scope,
    counts: {
      folders: preview.counts.folders,
      collections: preview.counts.collections,
      items: preview.counts.items,
      attachments: preview.counts.attachments,
    },
    diagnostics: {
      errors: preview.diagnostics.errors,
      warnings: preview.diagnostics.warnings,
      unsupported: preview.diagnostics.unsupported,
      omittedCount: preview.diagnostics.omittedCount,
    },
    organizationTargetRequired: preview.organizationTargetRequired,
    hasUnknownOutcome: preview.hasUnknownOutcome,
    canCommit: preview.canCommit,
  });
  const bytes = new TextEncoder().encode(canonical);
  try {
    return await digestBytes(bytes);
  } finally {
    bytes.fill(0);
  }
}

async function digestBytes(bytes: Readonly<Uint8Array>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function encodePassword(password: string): Uint8Array {
  validatePasswordShape(password);
  const encoded = new TextEncoder().encode(password);
  if (encoded.byteLength < 1 || encoded.byteLength > MAX_VAULT_TRANSFER_PASSWORD_BYTES) {
    zeroBytes(encoded);
    throw new VaultTransferControllerError('invalid_request');
  }
  return encoded;
}

function validatePasswordShape(password: string): void {
  if (typeof password !== 'string'
    || password.length < 1
    || password.length > MAX_VAULT_TRANSFER_PASSWORD_BYTES) {
    throw new VaultTransferControllerError('invalid_request');
  }
}

function readPassword(state: ImportState): string | undefined {
  return state.passwordBytes === undefined ? undefined : new TextDecoder().decode(state.passwordBytes);
}

function takePassword(state: ImportState): string | undefined {
  const bytes = state.passwordBytes;
  if (bytes === undefined) return undefined;
  delete state.passwordBytes;
  try {
    return new TextDecoder().decode(bytes);
  } finally {
    zeroBytes(bytes);
  }
}

function clearPassword(state: TransferState): void {
  if (state.direction !== 'import' || state.passwordBytes === undefined) return;
  const bytes = state.passwordBytes;
  delete state.passwordBytes;
  zeroBytes(bytes);
}

function canonicalControllerExportTarget(value: unknown): VaultTransferExportTarget {
  try {
    return canonicalizeVaultTransferExportTarget(
      value === undefined ? PERSONAL_VAULT_TRANSFER_EXPORT_TARGET : value,
    );
  } catch {
    throw new VaultTransferControllerError('invalid_request');
  }
}

function authorizationTargetMatches(
  authorization: unknown,
  target: VaultTransferExportTarget,
): boolean {
  if ((typeof authorization !== 'object' && typeof authorization !== 'function')
    || authorization === null) return true;
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(authorization, 'target');
  } catch {
    return false;
  }
  if (!descriptor) return true;
  if (!descriptor.enumerable || !('value' in descriptor)) return false;
  try {
    return sameVaultTransferExportTarget(
      canonicalizeVaultTransferExportTarget(descriptor.value),
      target,
    );
  } catch {
    return false;
  }
}

function validateExportPassword(format: VaultTransferExportFormat, password: string | undefined): void {
  if (format !== 'json' && format !== 'encrypted-json' && format !== 'csv' && format !== 'zip') {
    throw new VaultTransferControllerError('invalid_request');
  }
  if (format === 'encrypted-json') {
    if (password === undefined) return;
    const encoded = encodePassword(password);
    zeroBytes(encoded);
    return;
  }
  if (password !== undefined) throw new VaultTransferControllerError('unexpected_password');
}

function validateBuiltExport(
  value: BuiltVaultTransferExport,
  format: VaultTransferExportFormat,
): VaultTransferExportReview | undefined {
  const prototype = typeof value === 'object' && value !== null
    ? Object.getPrototypeOf(value) as unknown
    : undefined;
  const bytesDescriptor = typeof value === 'object' && value !== null
    ? Object.getOwnPropertyDescriptor(value, 'bytes')
    : undefined;
  const filenameDescriptor = typeof value === 'object' && value !== null
    ? Object.getOwnPropertyDescriptor(value, 'filename')
    : undefined;
  if (typeof value !== 'object' || value === null || Array.isArray(value)
    || (prototype !== Object.prototype && prototype !== null)
    || !bytesDescriptor || !('value' in bytesDescriptor)
    || !filenameDescriptor || !('value' in filenameDescriptor)
    || !(value.bytes instanceof Uint8Array)
    || !(value.bytes.buffer instanceof ArrayBuffer)
    || value.bytes.byteOffset !== 0
    || value.bytes.byteLength !== value.bytes.buffer.byteLength
    || typeof value.filename !== 'string'
    || value.filename.length < 1
    || value.filename.length > MAX_EXPORT_FILENAME_CHARS
    || !isSafeExportFilename(value.filename)
    || value.filename.endsWith('.')
    || value.filename.endsWith(' ')
    || value.filename === '.'
    || value.filename === '..') {
    throw new VaultTransferControllerError('export_failed');
  }
  const reviewDescriptor = Object.getOwnPropertyDescriptor(value, 'review');
  if (reviewDescriptor && (!reviewDescriptor.enumerable || !('value' in reviewDescriptor))) {
    throw new VaultTransferControllerError('export_failed');
  }
  const review = reviewDescriptor ? canonicalExportReview(reviewDescriptor.value) : undefined;
  if ((format === 'csv') !== (review !== undefined)) {
    throw new VaultTransferControllerError('export_failed');
  }
  return review;
}

function canonicalExportReview(value: unknown): VaultTransferExportReview {
  if (!isExactDataRecord(value, ['exportedItemCount', 'omittedItemCount', 'warnings'])) {
    throw new VaultTransferControllerError('export_failed');
  }
  const exportedItemCount = boundedExportReviewCount(value.exportedItemCount, true);
  const omittedItemCount = boundedExportReviewCount(value.omittedItemCount, true);
  const entries = value.warnings;
  if (!Array.isArray(entries)
    || Object.getPrototypeOf(entries) !== Array.prototype
    || entries.length > VAULT_TRANSFER_EXPORT_WARNING_CODES.length
    || Reflect.ownKeys(entries).length !== entries.length + 1) {
    throw new VaultTransferControllerError('export_failed');
  }
  const seen = new Set<VaultTransferExportWarningCode>();
  let previousIndex = -1;
  const warnings: VaultTransferExportWarning[] = [];
  for (let index = 0; index < entries.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(entries, String(index));
    if (!descriptor?.enumerable || !('value' in descriptor)
      || !isExactDataRecord(descriptor.value, ['code', 'count'])) {
      throw new VaultTransferControllerError('export_failed');
    }
    const entry = descriptor.value;
    const codeIndex = VAULT_TRANSFER_EXPORT_WARNING_CODES.indexOf(
      entry.code as VaultTransferExportWarningCode,
    );
    if (codeIndex < 0 || codeIndex <= previousIndex || seen.has(entry.code as VaultTransferExportWarningCode)) {
      throw new VaultTransferControllerError('export_failed');
    }
    const code = entry.code as VaultTransferExportWarningCode;
    seen.add(code);
    previousIndex = codeIndex;
    warnings.push(Object.freeze({ code, count: boundedExportReviewCount(entry.count, false) }));
  }
  return Object.freeze({
    exportedItemCount,
    omittedItemCount,
    warnings: Object.freeze(warnings),
  });
}

function isExactDataRecord(
  value: unknown,
  expectedKeys: readonly string[],
): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  const keys = Reflect.ownKeys(value);
  if ((prototype !== Object.prototype && prototype !== null) || keys.length !== expectedKeys.length) {
    return false;
  }
  return expectedKeys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && 'value' in descriptor;
  }) && keys.every((key) => typeof key === 'string' && expectedKeys.includes(key));
}

function boundedExportReviewCount(value: unknown, allowZero: boolean): number {
  if (!Number.isSafeInteger(value) || (value as number) < (allowZero ? 0 : 1) || (value as number) > 1_000_000) {
    throw new VaultTransferControllerError('export_failed');
  }
  return value as number;
}

function clearBuiltExport(value: unknown): void {
  try {
    if ((typeof value !== 'object' || value === null) && typeof value !== 'function') return;
    const bytes = (value as { readonly bytes?: unknown }).bytes;
    if (bytes instanceof Uint8Array) zeroBytes(bytes);
  } catch {
    // A malformed adapter result must not bypass controller teardown or stable error mapping.
  }
}

function zeroBytes(bytes: Uint8Array): void {
  try {
    Uint8Array.prototype.fill.call(bytes, 0);
  } catch {
    // Detached buffers are already inaccessible; teardown must still reach later cleanup steps.
  }
}

function isSafeExportFilename(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f || INVALID_EXPORT_FILENAME_CHARS.has(value[index]!)) return false;
  }
  return true;
}

function boundedPositiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive safe integer`);
  }
  return value;
}

function currentTimestamp(now: () => number): number {
  const value = now();
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new VaultTransferControllerError('invalid_request');
  }
  return value;
}

function replayBarrierReason(summary: VaultTransferJournalSummary): VaultTransferReplayBarrierReason {
  if (summary.unresolvedOutcomeUnknown) return 'outcome_unknown';
  if (summary.resultDeliveredAt !== null) return 'partial_result';
  return 'pending_result_delivery';
}

interface JournalOutcomeRead {
  readonly counts: VaultTransferImportOutcomeCounts;
  readonly sourceKeys: ReadonlySet<string>;
}

interface JournalOutcomeAudit extends JournalOutcomeRead {
  readonly summary: VaultTransferJournalSummary;
  readonly complete: boolean;
}

async function auditJournalOutcomes(
  journal: VaultTransferJournalDependency,
  transferId: string,
  accountIdentityDigest: string,
  expected: ReadonlySet<string>,
): Promise<JournalOutcomeAudit> {
  const summary = await journal.getSummary(transferId, accountIdentityDigest);
  if (summary.inFlight !== null) throw new VaultTransferControllerError('outcome_unknown');
  const read = await readJournalOutcomes(journal, transferId, accountIdentityDigest, summary);
  const complete = summary.outcomeCount === expected.size
    && read.sourceKeys.size === expected.size
    && [...expected].every((key) => read.sourceKeys.has(key));
  return { summary, counts: read.counts, sourceKeys: read.sourceKeys, complete };
}

async function readJournalOutcomeCounts(
  journal: VaultTransferJournalDependency,
  transferId: string,
  accountIdentityDigest: string,
  summary: VaultTransferJournalSummary,
): Promise<VaultTransferImportOutcomeCounts> {
  return (await readJournalOutcomes(journal, transferId, accountIdentityDigest, summary)).counts;
}

async function readJournalOutcomes(
  journal: VaultTransferJournalDependency,
  transferId: string,
  accountIdentityDigest: string,
  summary: VaultTransferJournalSummary,
): Promise<JournalOutcomeRead> {
  const mutable = { committed: 0, rejected: 0, skipped: 0, outcomeUnknown: 0 };
  const sourceKeys = new Set<string>();
  for (let pageIndex = 0; pageIndex < summary.outcomePageCount; pageIndex += 1) {
    const page = await journal.getOutcomePage(transferId, accountIdentityDigest, pageIndex);
    for (const outcome of page.outcomes) {
      sourceKeys.add(`${outcome.kind}:${outcome.sourceIndex}`);
      if (outcome.status === 'committed') mutable.committed += 1;
      else if (outcome.status === 'rejected') mutable.rejected += 1;
      else if (outcome.status === 'skipped') mutable.skipped += 1;
      else mutable.outcomeUnknown += 1;
    }
  }
  const counted = mutable.committed + mutable.rejected + mutable.skipped + mutable.outcomeUnknown;
  if (counted !== summary.outcomeCount || sourceKeys.size !== summary.outcomeCount) {
    throw new VaultTransferControllerError('journal_failed');
  }
  return { counts: Object.freeze(mutable), sourceKeys };
}

function journalPlanFromSource(source: VaultTransferSourceOk): readonly VaultTransferJournalPlanEntry[] {
  const ir = source.inspection.ir;
  if (!ir || source.attachmentCount > 0 || source.skippedAttachmentCount > 0) {
    throw new VaultTransferControllerError('commit_incomplete');
  }
  return Object.freeze([
    ...ir.folders.map((folder) => Object.freeze({
      kind: 'folder' as const,
      sourceIndex: folder.sourceIndex,
    })),
    ...ir.items.map((item) => Object.freeze({
      kind: 'item' as const,
      sourceIndex: item.sourceIndex,
    })),
  ]);
}

function importCommitResult(
  transferId: string,
  status: VaultTransferImportCommitResult['status'],
  counts: VaultTransferImportOutcomeCounts,
  requiresReconcile: boolean,
): VaultTransferImportCommitResult {
  return Object.freeze({
    transferId,
    status,
    counts: Object.freeze({ ...counts }),
    requiresReconcile,
  });
}

function normalizeControllerError(
  error: unknown,
  fallback: VaultTransferControllerErrorCode,
): VaultTransferControllerError {
  if (error instanceof VaultTransferControllerError) return error;
  if (error instanceof VaultTransferSessionError) return new VaultTransferControllerError(error.code);
  if (error instanceof VaultTransferJournalError) {
    if (error.code === 'reconcile_required') return new VaultTransferControllerError('outcome_unknown');
    return new VaultTransferControllerError('journal_failed');
  }
  return new VaultTransferControllerError(fallback);
}
