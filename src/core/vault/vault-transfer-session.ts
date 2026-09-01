export const DEFAULT_VAULT_TRANSFER_SESSION_TTL_MS = 10 * 60 * 1_000;
export const MAX_VAULT_TRANSFER_SESSION_TTL_MS = 60 * 60 * 1_000;
export const DEFAULT_MAX_VAULT_TRANSFER_SESSIONS = 4;
export const MAX_VAULT_TRANSFER_SESSIONS = 32;
export const DEFAULT_MAX_VAULT_TRANSFER_BYTES = 64 * 1024 * 1024;
export const MAX_VAULT_TRANSFER_BYTES = 512 * 1024 * 1024;
export const DEFAULT_MAX_VAULT_TRANSFER_CHUNK_BYTES = 256 * 1024;
export const MAX_VAULT_TRANSFER_CHUNK_BYTES = 4 * 1024 * 1024;
export const DEFAULT_MAX_VAULT_TRANSFER_RESIDENT_BYTES = 128 * 1024 * 1024;
export const MAX_VAULT_TRANSFER_RESIDENT_BYTES = 1024 * 1024 * 1024;
export const MAX_VAULT_TRANSFER_CHUNKS = 65_536;
export const DEFAULT_VAULT_TRANSFER_CALLBACK_DEADLINE_MS = 30_000;
export const MAX_VAULT_TRANSFER_CALLBACK_DEADLINE_MS = 5 * 60_000;

const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_ID_GENERATION_ATTEMPTS = 16;
const MAX_DEFAULT_VAULT_TRANSFER_CHUNKS = 8_192;

export type VaultTransferDirection = 'import' | 'export';

export interface VaultTransferLeases<AccountLease, SessionLease, EnterprisePolicyLease> {
  readonly account: AccountLease;
  readonly session: SessionLease;
  readonly enterprisePolicy: EnterprisePolicyLease;
}

export interface VaultTransferSessionOptions<AccountLease, SessionLease, EnterprisePolicyLease> {
  readonly captureLeases: () => VaultTransferLeases<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease
  >;
  /** Return false or throw when any captured lease is no longer current. */
  readonly assertLeasesCurrent: (
    leases: VaultTransferLeases<AccountLease, SessionLease, EnterprisePolicyLease>,
  ) => boolean | void;
  readonly now?: () => number;
  readonly createId?: () => string;
  readonly ttlMs?: number;
  readonly maxSessions?: number;
  readonly maxTotalBytes?: number;
  readonly maxChunkBytes?: number;
  readonly maxChunks?: number;
  readonly maxResidentBytes?: number;
  readonly inspectionDeadlineMs?: number;
  readonly confirmedAccessDeadlineMs?: number;
}

export interface BeginVaultTransferOptions {
  readonly direction: VaultTransferDirection;
  readonly expectedTotalBytes?: number;
}

export interface BegunVaultTransfer {
  readonly transferId: string;
  readonly direction: VaultTransferDirection;
  readonly nextSequence: 0;
  readonly maxChunkBytes: number;
  readonly maxTotalBytes: number;
  readonly maxChunks: number;
  readonly expiresAt: number;
}

export interface VaultTransferChunkAck {
  readonly transferId: string;
  readonly sequence: number;
  readonly totalBytes: number;
  readonly requiresAcknowledgement: true;
}

export interface SealedVaultTransfer {
  readonly transferId: string;
  readonly sourceDigest: string;
  readonly totalBytes: number;
}

export interface VaultTransferInspectionInput {
  /** A scratch copy that is zeroed immediately after the inspector settles. */
  readonly bytes: Readonly<Uint8Array>;
  readonly sourceDigest: string;
  readonly totalBytes: number;
  readonly direction: VaultTransferDirection;
}

export interface InspectedVaultTransfer<Preview> extends SealedVaultTransfer {
  readonly previewRevision: string;
  readonly preview: Preview;
}

export interface ConfirmedVaultTransfer extends SealedVaultTransfer {
  readonly confirmationId: string;
  readonly direction: VaultTransferDirection;
}

export interface VaultTransferConfirmedAccessInput extends SealedVaultTransfer {
  /** A one-use scratch copy that is synchronously zeroed on settle or teardown. */
  readonly bytes: Readonly<Uint8Array>;
  readonly direction: VaultTransferDirection;
}

export type VaultTransferSessionPhase =
  | 'uploading'
  | 'sealing'
  | 'sealed'
  | 'inspecting'
  | 'previewed'
  | 'confirmed';

export interface VaultTransferSessionStatus {
  readonly transferId: string;
  readonly direction: VaultTransferDirection;
  readonly phase: VaultTransferSessionPhase;
  readonly totalBytes: number;
  readonly expiresAt: number;
}

export type VaultTransferSessionErrorCode =
  | 'capacity'
  | 'not_found'
  | 'expired'
  | 'lease_changed'
  | 'invalid_state'
  | 'invalid_sequence'
  | 'ack_required'
  | 'invalid_chunk'
  | 'chunk_too_large'
  | 'too_many_chunks'
  | 'total_too_large'
  | 'resident_limit'
  | 'size_mismatch'
  | 'preview_mismatch'
  | 'confirmation_mismatch'
  | 'digest_failed'
  | 'source_digest_mismatch'
  | 'deadline_exceeded';

export class VaultTransferSessionError extends Error {
  constructor(
    readonly code: VaultTransferSessionErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'VaultTransferSessionError';
  }
}

interface SessionBase<AccountLease, SessionLease, EnterprisePolicyLease> {
  readonly transferId: string;
  readonly direction: VaultTransferDirection;
  readonly leases: VaultTransferLeases<AccountLease, SessionLease, EnterprisePolicyLease>;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly expectedTotalBytes: number | undefined;
  residentBytes: number;
}

interface UploadingState {
  readonly kind: 'uploading';
  readonly chunks: Uint8Array[];
  totalBytes: number;
  nextSequence: number;
  awaitingAcknowledgement: number | undefined;
}

interface SealingState {
  readonly kind: 'sealing';
  readonly bytes: Uint8Array;
  readonly totalBytes: number;
}

interface SealedState {
  readonly kind: 'sealed';
  readonly bytes: Uint8Array;
  readonly totalBytes: number;
  readonly sourceDigest: string;
}

interface InspectingState {
  readonly kind: 'inspecting';
  readonly bytes: Uint8Array;
  readonly totalBytes: number;
  readonly sourceDigest: string;
  readonly scratch: Uint8Array;
  scratchResident: boolean;
}

interface PreviewedState {
  readonly kind: 'previewed';
  readonly bytes: Uint8Array;
  readonly totalBytes: number;
  readonly sourceDigest: string;
  readonly previewRevision: string;
}

type PendingState = UploadingState | SealingState | SealedState | InspectingState | PreviewedState;

interface PendingSession<AccountLease, SessionLease, EnterprisePolicyLease>
  extends SessionBase<AccountLease, SessionLease, EnterprisePolicyLease> {
  state: PendingState;
}

interface ConfirmedSession<AccountLease, SessionLease, EnterprisePolicyLease>
  extends SessionBase<AccountLease, SessionLease, EnterprisePolicyLease> {
  readonly confirmationId: string;
  readonly bytes: Uint8Array;
  readonly totalBytes: number;
  readonly sourceDigest: string;
  state: ConfirmedState;
}

type ConfirmedState =
  | { readonly kind: 'ready' }
  | { readonly kind: 'verifying' }
  | { readonly kind: 'accessing'; readonly scratch: Uint8Array; scratchResident: boolean }
  | { readonly kind: 'consumed' };

/**
 * Owns short-lived plaintext for transfer flows. Protocol adapters must send an append ACK before
 * calling acknowledge; this keeps the next chunk behind explicit backpressure.
 */
export class VaultTransferSessionManager<AccountLease, SessionLease, EnterprisePolicyLease> {
  private readonly captureLeases: VaultTransferSessionOptions<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease
  >['captureLeases'];
  private readonly assertLeasesCurrent: VaultTransferSessionOptions<
    AccountLease,
    SessionLease,
    EnterprisePolicyLease
  >['assertLeasesCurrent'];
  private readonly now: () => number;
  private readonly createId: () => string;
  private readonly ttlMs: number;
  private readonly maxSessions: number;
  private readonly maxTotalBytes: number;
  private readonly maxChunkBytes: number;
  private readonly maxChunks: number;
  private readonly maxResidentBytes: number;
  private readonly inspectionDeadlineMs: number;
  private readonly confirmedAccessDeadlineMs: number;
  private currentResidentBytes = 0;
  private readonly pending = new Map<
    string,
    PendingSession<AccountLease, SessionLease, EnterprisePolicyLease>
  >();
  private readonly confirmed = new Map<
    string,
    ConfirmedSession<AccountLease, SessionLease, EnterprisePolicyLease>
  >();

  constructor(options: VaultTransferSessionOptions<AccountLease, SessionLease, EnterprisePolicyLease>) {
    this.captureLeases = options.captureLeases;
    this.assertLeasesCurrent = options.assertLeasesCurrent;
    this.now = options.now ?? (() => Date.now());
    this.createId = options.createId ?? (() => crypto.randomUUID());
    this.ttlMs = boundedPositiveInteger(
      options.ttlMs ?? DEFAULT_VAULT_TRANSFER_SESSION_TTL_MS,
      'ttlMs',
      MAX_VAULT_TRANSFER_SESSION_TTL_MS,
    );
    this.maxSessions = boundedPositiveInteger(
      options.maxSessions ?? DEFAULT_MAX_VAULT_TRANSFER_SESSIONS,
      'maxSessions',
      MAX_VAULT_TRANSFER_SESSIONS,
    );
    this.maxTotalBytes = boundedPositiveInteger(
      options.maxTotalBytes ?? DEFAULT_MAX_VAULT_TRANSFER_BYTES,
      'maxTotalBytes',
      MAX_VAULT_TRANSFER_BYTES,
    );
    this.maxChunkBytes = boundedPositiveInteger(
      options.maxChunkBytes ?? Math.min(DEFAULT_MAX_VAULT_TRANSFER_CHUNK_BYTES, this.maxTotalBytes),
      'maxChunkBytes',
      Math.min(MAX_VAULT_TRANSFER_CHUNK_BYTES, this.maxTotalBytes),
    );
    const minimumChunks = Math.ceil(this.maxTotalBytes / this.maxChunkBytes);
    if (minimumChunks > MAX_VAULT_TRANSFER_CHUNKS) {
      throw new RangeError('maxTotalBytes cannot be represented within the hard chunk-count limit');
    }
    const defaultMaxChunks = Math.min(
      MAX_VAULT_TRANSFER_CHUNKS,
      Math.max(minimumChunks, Math.min(MAX_DEFAULT_VAULT_TRANSFER_CHUNKS, minimumChunks * 2)),
    );
    this.maxChunks = boundedPositiveInteger(
      options.maxChunks ?? defaultMaxChunks,
      'maxChunks',
      MAX_VAULT_TRANSFER_CHUNKS,
    );
    if (this.maxChunks < minimumChunks) {
      throw new RangeError(`maxChunks must be at least ${minimumChunks} for the configured byte limits`);
    }
    this.maxResidentBytes = boundedPositiveInteger(
      options.maxResidentBytes ?? DEFAULT_MAX_VAULT_TRANSFER_RESIDENT_BYTES,
      'maxResidentBytes',
      MAX_VAULT_TRANSFER_RESIDENT_BYTES,
    );
    if (this.maxResidentBytes < this.maxTotalBytes * 2) {
      throw new RangeError('maxResidentBytes must be at least twice maxTotalBytes');
    }
    this.inspectionDeadlineMs = boundedPositiveInteger(
      options.inspectionDeadlineMs ?? DEFAULT_VAULT_TRANSFER_CALLBACK_DEADLINE_MS,
      'inspectionDeadlineMs',
      MAX_VAULT_TRANSFER_CALLBACK_DEADLINE_MS,
    );
    this.confirmedAccessDeadlineMs = boundedPositiveInteger(
      options.confirmedAccessDeadlineMs ?? DEFAULT_VAULT_TRANSFER_CALLBACK_DEADLINE_MS,
      'confirmedAccessDeadlineMs',
      MAX_VAULT_TRANSFER_CALLBACK_DEADLINE_MS,
    );
  }

  get residentBytes(): number {
    return this.currentResidentBytes;
  }

  begin(options: BeginVaultTransferOptions): BegunVaultTransfer {
    if (options.direction !== 'import' && options.direction !== 'export') {
      throw new TypeError('direction must be import or export');
    }
    const expectedTotalBytes = options.expectedTotalBytes;
    if (
      expectedTotalBytes !== undefined
      && (!Number.isSafeInteger(expectedTotalBytes)
        || expectedTotalBytes < 0
        || expectedTotalBytes > this.maxTotalBytes
        || expectedTotalBytes > this.maxResidentBytes)
    ) {
      throw new RangeError(`expectedTotalBytes must be between 0 and ${this.maxTotalBytes}`);
    }

    const now = this.currentTimestamp();
    this.sweepExpiredAt(now);
    this.sweepStaleLeases();
    if (this.pending.size + this.confirmed.size >= this.maxSessions) {
      throw new VaultTransferSessionError(
        'capacity',
        `Transfer session capacity (${this.maxSessions}) was reached`,
      );
    }

    const leases = this.captureLeases();
    this.assertCapturedLeases(leases);
    const transferId = this.uniqueId();
    const expiresAt = safeTimestampAddition(now, this.ttlMs);
    this.pending.set(transferId, {
      transferId,
      direction: options.direction,
      leases,
      createdAt: now,
      expiresAt,
      expectedTotalBytes,
      residentBytes: 0,
      state: {
        kind: 'uploading',
        chunks: [],
        totalBytes: 0,
        nextSequence: 0,
        awaitingAcknowledgement: undefined,
      },
    });
    return {
      transferId,
      direction: options.direction,
      nextSequence: 0,
      maxChunkBytes: this.maxChunkBytes,
      maxTotalBytes: this.maxTotalBytes,
      maxChunks: this.maxChunks,
      expiresAt,
    };
  }

  append(transferId: string, sequence: number, chunk: Uint8Array): VaultTransferChunkAck {
    const session = this.requirePending(transferId);
    const fail = (code: VaultTransferSessionErrorCode, message: string): never => {
      this.destroyPending(session);
      throw new VaultTransferSessionError(code, message);
    };
    if (session.state.kind !== 'uploading') {
      return fail('invalid_state', 'Chunks can only be appended while uploading');
    }
    if (session.state.awaitingAcknowledgement !== undefined) {
      return fail('ack_required', 'The previous chunk ACK must be acknowledged first');
    }
    if (!Number.isSafeInteger(sequence) || sequence < 0 || sequence !== session.state.nextSequence) {
      return fail('invalid_sequence', 'Transfer chunks must use the exact next sequence number');
    }
    if (!(chunk instanceof Uint8Array) || chunk.byteLength === 0) {
      return fail('invalid_chunk', 'Transfer chunks must be non-empty Uint8Array values');
    }
    if (chunk.byteLength > this.maxChunkBytes) {
      return fail('chunk_too_large', `Transfer chunks may not exceed ${this.maxChunkBytes} bytes`);
    }
    if (session.state.chunks.length >= this.maxChunks) {
      return fail('too_many_chunks', `Transfer may not exceed ${this.maxChunks} chunks`);
    }
    const nextTotal = session.state.totalBytes + chunk.byteLength;
    if (!Number.isSafeInteger(nextTotal) || nextTotal > this.maxTotalBytes) {
      return fail('total_too_large', `Transfer payload may not exceed ${this.maxTotalBytes} bytes`);
    }
    if (
      session.expectedTotalBytes !== undefined
      && nextTotal > session.expectedTotalBytes
    ) {
      return fail('total_too_large', 'Transfer payload exceeded its declared byte length');
    }

    this.reservePending(session, chunk.byteLength);
    let storedChunk: Uint8Array;
    try {
      storedChunk = chunk.slice();
    } catch (error) {
      this.destroyPending(session);
      throw error;
    }
    session.state.chunks.push(storedChunk);
    session.state.totalBytes = nextTotal;
    session.state.awaitingAcknowledgement = sequence;
    return {
      transferId,
      sequence,
      totalBytes: nextTotal,
      requiresAcknowledgement: true,
    };
  }

  acknowledge(transferId: string, sequence: number): void {
    const session = this.requirePending(transferId);
    const fail = (code: VaultTransferSessionErrorCode, message: string): never => {
      this.destroyPending(session);
      throw new VaultTransferSessionError(code, message);
    };
    if (session.state.kind !== 'uploading') {
      return fail('invalid_state', 'Chunk ACKs are only valid while uploading');
    }
    if (
      !Number.isSafeInteger(sequence)
      || sequence < 0
      || session.state.awaitingAcknowledgement !== sequence
    ) {
      return fail('invalid_sequence', 'Chunk ACK did not match the outstanding sequence');
    }
    session.state.awaitingAcknowledgement = undefined;
    session.state.nextSequence += 1;
  }

  async seal(transferId: string): Promise<SealedVaultTransfer> {
    const session = this.requirePending(transferId);
    const fail = (code: VaultTransferSessionErrorCode, message: string): never => {
      this.destroyPending(session);
      throw new VaultTransferSessionError(code, message);
    };
    if (session.state.kind !== 'uploading') {
      return fail('invalid_state', 'Only an uploading transfer can be sealed');
    }
    if (session.state.awaitingAcknowledgement !== undefined) {
      return fail('ack_required', 'The final chunk ACK must be acknowledged before sealing');
    }
    if (
      session.expectedTotalBytes !== undefined
      && session.state.totalBytes !== session.expectedTotalBytes
    ) {
      return fail('size_mismatch', 'Transfer payload did not match its declared byte length');
    }

    const uploading = session.state;
    this.reservePending(session, uploading.totalBytes);
    let bytes: Uint8Array;
    try {
      bytes = concatenateChunks(uploading.chunks, uploading.totalBytes);
    } catch (error) {
      this.destroyPending(session);
      throw error;
    }
    zeroChunks(uploading.chunks);
    this.releasePendingResident(session, uploading.totalBytes);
    const sealingState: SealingState = {
      kind: 'sealing',
      bytes,
      totalBytes: bytes.byteLength,
    };
    session.state = sealingState;

    let sourceDigest: string;
    try {
      sourceDigest = await sha256Hex(bytes);
    } catch (error) {
      this.destroyPending(session);
      throw new VaultTransferSessionError(
        'digest_failed',
        error instanceof Error ? `SHA-256 failed: ${error.message}` : 'SHA-256 failed',
      );
    }

    const current = this.pending.get(transferId);
    if (current !== session || session.state !== sealingState) {
      bytes.fill(0);
      throw new VaultTransferSessionError('not_found', 'Transfer was cancelled while sealing');
    }
    this.assertPendingCurrent(session);
    session.state = {
      kind: 'sealed',
      bytes,
      totalBytes: bytes.byteLength,
      sourceDigest,
    };
    return { transferId, sourceDigest, totalBytes: bytes.byteLength };
  }

  async inspect<Preview>(
    transferId: string,
    inspector: (input: VaultTransferInspectionInput) => Preview | Promise<Preview>,
  ): Promise<InspectedVaultTransfer<Preview>> {
    if (typeof inspector !== 'function') throw new TypeError('inspector must be a function');
    const session = this.requirePending(transferId);
    if (session.state.kind !== 'sealed') {
      this.destroyPending(session);
      throw new VaultTransferSessionError('invalid_state', 'Only a sealed transfer can be inspected');
    }

    const sealed = session.state;
    this.reservePending(session, sealed.totalBytes);
    let scratch: Uint8Array;
    try {
      scratch = sealed.bytes.slice();
    } catch (error) {
      this.destroyPending(session);
      throw error;
    }
    const inspectingState: InspectingState = {
      kind: 'inspecting',
      bytes: sealed.bytes,
      totalBytes: sealed.totalBytes,
      sourceDigest: sealed.sourceDigest,
      scratch,
      scratchResident: true,
    };
    session.state = inspectingState;
    let preview: Preview;
    try {
      preview = await withDeadline(
        Promise.resolve().then(() => inspector({
          bytes: scratch,
          sourceDigest: sealed.sourceDigest,
          totalBytes: sealed.totalBytes,
          direction: session.direction,
        })),
        this.inspectionDeadlineMs,
        () => {
          if (this.pending.get(transferId) === session && session.state === inspectingState) {
            this.destroyPending(session);
          }
        },
        new VaultTransferSessionError('deadline_exceeded', 'Transfer inspection exceeded its deadline'),
      );
    } catch (error) {
      this.destroyPending(session);
      throw error;
    } finally {
      this.releaseInspectionScratch(session, inspectingState);
    }

    const current = this.pending.get(transferId);
    if (current !== session || session.state !== inspectingState) {
      this.destroyPending(session);
      throw new VaultTransferSessionError('not_found', 'Transfer was cancelled while inspecting');
    }
    this.assertPendingCurrent(session);
    const previewRevision = this.uniqueId();
    session.state = {
      kind: 'previewed',
      bytes: sealed.bytes,
      totalBytes: sealed.totalBytes,
      sourceDigest: sealed.sourceDigest,
      previewRevision,
    };
    return {
      transferId,
      sourceDigest: sealed.sourceDigest,
      totalBytes: sealed.totalBytes,
      previewRevision,
      preview,
    };
  }

  /**
   * Consume the pending session before checking the preview token or leases. A failed confirmation
   * therefore cannot be corrected or replayed against plaintext left in memory.
   */
  confirm(
    transferId: string,
    previewRevision: string,
  ): ConfirmedVaultTransfer {
    assertUuidV4(transferId, 'transferId');
    const session = this.pending.get(transferId);
    if (!session) {
      const repeated = this.confirmed.get(transferId);
      if (repeated) this.destroyConfirmed(repeated);
      throw new VaultTransferSessionError('not_found', 'Transfer session was not found');
    }
    this.pending.delete(transferId);

    try {
      if (session.state.kind !== 'previewed') {
        throw new VaultTransferSessionError(
          'invalid_state',
          'Transfer confirmation requires an inspected preview',
        );
      }
      if (!UUID_V4_PATTERN.test(previewRevision) || previewRevision !== session.state.previewRevision) {
        throw new VaultTransferSessionError(
          'preview_mismatch',
          'Preview revision did not match this transfer',
        );
      }
      this.assertCurrent(session);
      const confirmationId = this.uniqueId([transferId, previewRevision]);
      const confirmed: ConfirmedSession<AccountLease, SessionLease, EnterprisePolicyLease> = {
        transferId: session.transferId,
        direction: session.direction,
        leases: session.leases,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
        expectedTotalBytes: session.expectedTotalBytes,
        residentBytes: session.residentBytes,
        confirmationId,
        bytes: session.state.bytes,
        totalBytes: session.state.totalBytes,
        sourceDigest: session.state.sourceDigest,
        state: { kind: 'ready' },
      };
      session.residentBytes = 0;
      this.confirmed.set(transferId, confirmed);
      return exposeConfirmed(confirmed);
    } catch (error) {
      this.destroyPending(session);
      throw error;
    }
  }

  /** Provide one isolated scratch buffer after revalidating leases, TTL, and the source digest. */
  async withConfirmedBytes<Result>(
    transferId: string,
    confirmationId: string,
    callback: (input: VaultTransferConfirmedAccessInput) => Result | Promise<Result>,
  ): Promise<Result> {
    if (typeof callback !== 'function') throw new TypeError('callback must be a function');
    const session = this.requireConfirmed(transferId);
    if (!UUID_V4_PATTERN.test(confirmationId) || confirmationId !== session.confirmationId) {
      this.destroyConfirmed(session);
      throw new VaultTransferSessionError(
        'confirmation_mismatch',
        'Confirmation identifier did not match this transfer',
      );
    }
    if (session.state.kind !== 'ready') {
      this.destroyConfirmed(session);
      throw new VaultTransferSessionError('invalid_state', 'Confirmed transfer access is single-use');
    }
    this.assertConfirmedCurrent(session);
    const verifyingState: ConfirmedState = { kind: 'verifying' };
    session.state = verifyingState;

    let currentDigest: string;
    try {
      currentDigest = await sha256Hex(session.bytes);
    } catch (error) {
      this.destroyConfirmed(session);
      throw new VaultTransferSessionError(
        'digest_failed',
        error instanceof Error ? `SHA-256 failed: ${error.message}` : 'SHA-256 failed',
      );
    }
    if (this.confirmed.get(transferId) !== session || session.state !== verifyingState) {
      this.destroyConfirmed(session);
      throw new VaultTransferSessionError('not_found', 'Confirmed transfer was cancelled while verifying');
    }
    if (currentDigest !== session.sourceDigest) {
      this.destroyConfirmed(session);
      throw new VaultTransferSessionError('source_digest_mismatch', 'Confirmed transfer digest changed');
    }
    this.assertConfirmedCurrent(session);
    this.reserveConfirmed(session, session.totalBytes);
    let scratch: Uint8Array;
    try {
      scratch = session.bytes.slice();
    } catch (error) {
      this.destroyConfirmed(session);
      throw error;
    }
    const accessingState: Extract<ConfirmedState, { readonly kind: 'accessing' }> = {
      kind: 'accessing',
      scratch,
      scratchResident: true,
    };
    session.state = accessingState;

    let result: Result;
    try {
      result = await withDeadline(
        Promise.resolve().then(() => callback({
          transferId,
          bytes: scratch,
          sourceDigest: session.sourceDigest,
          totalBytes: session.totalBytes,
          direction: session.direction,
        })),
        this.confirmedAccessDeadlineMs,
        () => {
          if (this.confirmed.get(transferId) === session && session.state === accessingState) {
            this.destroyConfirmed(session);
          }
        },
        new VaultTransferSessionError('deadline_exceeded', 'Confirmed transfer access exceeded its deadline'),
      );
    } catch (error) {
      this.destroyConfirmed(session);
      throw error;
    } finally {
      this.releaseConfirmedScratch(session, accessingState);
    }

    if (this.confirmed.get(transferId) !== session || session.state !== accessingState) {
      this.destroyConfirmed(session);
      throw new VaultTransferSessionError('not_found', 'Confirmed transfer was cancelled while in use');
    }
    this.assertConfirmedCurrent(session);
    session.state = { kind: 'consumed' };
    return result;
  }

  complete(transferId: string, confirmationId: string): SealedVaultTransfer {
    const session = this.requireConfirmed(transferId);
    this.confirmed.delete(transferId);
    try {
      if (!UUID_V4_PATTERN.test(confirmationId) || confirmationId !== session.confirmationId) {
        throw new VaultTransferSessionError(
          'confirmation_mismatch',
          'Confirmation identifier did not match this transfer',
        );
      }
      if (session.state.kind !== 'consumed') {
        throw new VaultTransferSessionError(
          'invalid_state',
          'Confirmed transfer must finish its single access before completion',
        );
      }
      this.assertCurrent(session);
      return {
        transferId,
        sourceDigest: session.sourceDigest,
        totalBytes: session.totalBytes,
      };
    } finally {
      this.destroyConfirmed(session);
    }
  }

  cancel(transferId: string): boolean {
    assertUuidV4(transferId, 'transferId');
    const pending = this.pending.get(transferId);
    if (pending) {
      this.destroyPending(pending);
      return true;
    }
    const confirmed = this.confirmed.get(transferId);
    if (confirmed) {
      this.destroyConfirmed(confirmed);
      return true;
    }
    return false;
  }

  status(transferId: string): VaultTransferSessionStatus | undefined {
    assertUuidV4(transferId, 'transferId');
    const now = this.currentTimestamp();
    const pending = this.pending.get(transferId);
    if (pending) {
      if (pending.expiresAt <= now) {
        this.destroyPending(pending);
        return undefined;
      }
      this.assertPendingCurrent(pending);
      return {
        transferId,
        direction: pending.direction,
        phase: pending.state.kind,
        totalBytes: pendingStateBytes(pending.state),
        expiresAt: pending.expiresAt,
      };
    }
    const confirmed = this.confirmed.get(transferId);
    if (!confirmed) return undefined;
    if (confirmed.expiresAt <= now) {
      this.destroyConfirmed(confirmed);
      return undefined;
    }
    this.assertConfirmedCurrent(confirmed);
    return {
      transferId,
      direction: confirmed.direction,
      phase: 'confirmed',
      totalBytes: confirmed.totalBytes,
      expiresAt: confirmed.expiresAt,
    };
  }

  sweepExpired(): number {
    return this.sweepExpiredAt(this.currentTimestamp());
  }

  sweepInvalid(): number {
    return this.sweepExpiredAt(this.currentTimestamp()) + this.sweepStaleLeases();
  }

  clearAll(): number {
    const count = this.pending.size + this.confirmed.size;
    for (const session of this.pending.values()) this.destroyPending(session);
    for (const session of this.confirmed.values()) this.destroyConfirmed(session);
    return count;
  }

  private requirePending(
    transferId: string,
  ): PendingSession<AccountLease, SessionLease, EnterprisePolicyLease> {
    assertUuidV4(transferId, 'transferId');
    const session = this.pending.get(transferId);
    if (!session) throw new VaultTransferSessionError('not_found', 'Transfer session was not found');
    this.assertPendingCurrent(session);
    return session;
  }

  private requireConfirmed(
    transferId: string,
  ): ConfirmedSession<AccountLease, SessionLease, EnterprisePolicyLease> {
    assertUuidV4(transferId, 'transferId');
    const session = this.confirmed.get(transferId);
    if (!session) throw new VaultTransferSessionError('not_found', 'Confirmed transfer was not found');
    return session;
  }

  private assertPendingCurrent(
    session: PendingSession<AccountLease, SessionLease, EnterprisePolicyLease>,
  ): void {
    try {
      this.assertCurrent(session);
    } catch (error) {
      this.destroyPending(session);
      throw error;
    }
  }

  private assertConfirmedCurrent(
    session: ConfirmedSession<AccountLease, SessionLease, EnterprisePolicyLease>,
  ): void {
    try {
      this.assertCurrent(session);
    } catch (error) {
      this.destroyConfirmed(session);
      throw error;
    }
  }

  private assertCurrent(
    session: SessionBase<AccountLease, SessionLease, EnterprisePolicyLease>,
  ): void {
    if (session.expiresAt <= this.currentTimestamp()) {
      throw new VaultTransferSessionError('expired', 'Transfer session expired');
    }
    this.assertCapturedLeases(session.leases);
  }

  private assertCapturedLeases(
    leases: VaultTransferLeases<AccountLease, SessionLease, EnterprisePolicyLease>,
  ): void {
    try {
      if (this.assertLeasesCurrent(leases) === false) {
        throw new Error('Lease validator returned false');
      }
    } catch {
      throw new VaultTransferSessionError(
        'lease_changed',
        'Account, session, or enterprise policy lease changed',
      );
    }
  }

  private destroyPending(
    session: PendingSession<AccountLease, SessionLease, EnterprisePolicyLease>,
  ): void {
    this.pending.delete(session.transferId);
    this.releaseAllResident(session);
    zeroPendingState(session.state);
  }

  private destroyConfirmed(
    session: ConfirmedSession<AccountLease, SessionLease, EnterprisePolicyLease>,
  ): void {
    this.confirmed.delete(session.transferId);
    this.releaseAllResident(session);
    session.bytes.fill(0);
    zeroConfirmedState(session.state);
  }

  private reservePending(
    session: PendingSession<AccountLease, SessionLease, EnterprisePolicyLease>,
    bytes: number,
  ): void {
    if (bytes === 0) return;
    if (this.currentResidentBytes + bytes > this.maxResidentBytes) {
      this.destroyPending(session);
      throw new VaultTransferSessionError(
        'resident_limit',
        `Transfer resident memory may not exceed ${this.maxResidentBytes} bytes`,
      );
    }
    this.currentResidentBytes += bytes;
    session.residentBytes += bytes;
  }

  private reserveConfirmed(
    session: ConfirmedSession<AccountLease, SessionLease, EnterprisePolicyLease>,
    bytes: number,
  ): void {
    if (bytes === 0) return;
    if (this.currentResidentBytes + bytes > this.maxResidentBytes) {
      this.destroyConfirmed(session);
      throw new VaultTransferSessionError(
        'resident_limit',
        `Transfer resident memory may not exceed ${this.maxResidentBytes} bytes`,
      );
    }
    this.currentResidentBytes += bytes;
    session.residentBytes += bytes;
  }

  private releasePendingResident(
    session: PendingSession<AccountLease, SessionLease, EnterprisePolicyLease>,
    bytes: number,
  ): void {
    this.releaseResident(session, bytes);
  }

  private releaseInspectionScratch(
    session: PendingSession<AccountLease, SessionLease, EnterprisePolicyLease>,
    state: InspectingState,
  ): void {
    state.scratch.fill(0);
    if (!state.scratchResident) return;
    state.scratchResident = false;
    this.releaseResident(session, state.scratch.byteLength);
  }

  private releaseConfirmedScratch(
    session: ConfirmedSession<AccountLease, SessionLease, EnterprisePolicyLease>,
    state: Extract<ConfirmedState, { readonly kind: 'accessing' }>,
  ): void {
    state.scratch.fill(0);
    if (!state.scratchResident) return;
    state.scratchResident = false;
    this.releaseResident(session, state.scratch.byteLength);
  }

  private releaseResident(
    session: { residentBytes: number },
    bytes: number,
  ): void {
    if (bytes === 0) return;
    if (bytes > session.residentBytes || bytes > this.currentResidentBytes) {
      throw new Error('Transfer resident memory accounting invariant failed');
    }
    session.residentBytes -= bytes;
    this.currentResidentBytes -= bytes;
  }

  private releaseAllResident(session: { residentBytes: number }): void {
    const bytes = session.residentBytes;
    session.residentBytes = 0;
    this.currentResidentBytes -= bytes;
    if (this.currentResidentBytes < 0) {
      this.currentResidentBytes = 0;
      throw new Error('Transfer resident memory accounting invariant failed');
    }
  }

  private sweepExpiredAt(now: number): number {
    let removed = 0;
    for (const session of this.pending.values()) {
      if (session.expiresAt > now) continue;
      this.destroyPending(session);
      removed += 1;
    }
    for (const session of this.confirmed.values()) {
      if (session.expiresAt > now) continue;
      this.destroyConfirmed(session);
      removed += 1;
    }
    return removed;
  }

  private sweepStaleLeases(): number {
    let removed = 0;
    for (const session of this.pending.values()) {
      try {
        this.assertCapturedLeases(session.leases);
      } catch {
        this.destroyPending(session);
        removed += 1;
      }
    }
    for (const session of this.confirmed.values()) {
      try {
        this.assertCapturedLeases(session.leases);
      } catch {
        this.destroyConfirmed(session);
        removed += 1;
      }
    }
    return removed;
  }

  private uniqueId(forbidden: readonly string[] = []): string {
    const used = new Set(forbidden);
    for (const [transferId, session] of this.pending) {
      used.add(transferId);
      if (session.state.kind === 'previewed') used.add(session.state.previewRevision);
    }
    for (const [transferId, session] of this.confirmed) {
      used.add(transferId);
      used.add(session.confirmationId);
    }
    for (let attempt = 0; attempt < MAX_ID_GENERATION_ATTEMPTS; attempt += 1) {
      const candidate = this.createId();
      assertUuidV4(candidate, 'createId result');
      if (!used.has(candidate)) return candidate;
    }
    throw new VaultTransferSessionError('capacity', 'Could not allocate a unique transfer identifier');
  }

  private currentTimestamp(): number {
    const value = this.now();
    if (!isTimestamp(value)) throw new RangeError('now must return a non-negative safe integer');
    return value;
  }
}

function exposeConfirmed<AccountLease, SessionLease, EnterprisePolicyLease>(
  session: ConfirmedSession<AccountLease, SessionLease, EnterprisePolicyLease>,
): ConfirmedVaultTransfer {
  return {
    transferId: session.transferId,
    confirmationId: session.confirmationId,
    direction: session.direction,
    sourceDigest: session.sourceDigest,
    totalBytes: session.totalBytes,
  };
}

function concatenateChunks(chunks: readonly Uint8Array[], totalBytes: number): Uint8Array {
  const output = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function zeroPendingState(state: PendingState): void {
  if (state.kind === 'uploading') {
    zeroChunks(state.chunks);
    return;
  }
  state.bytes.fill(0);
  if (state.kind === 'inspecting') {
    state.scratch.fill(0);
    state.scratchResident = false;
  }
}

function zeroConfirmedState(state: ConfirmedState): void {
  if (state.kind !== 'accessing') return;
  state.scratch.fill(0);
  state.scratchResident = false;
}

function zeroChunks(chunks: readonly Uint8Array[]): void {
  for (const chunk of chunks) chunk.fill(0);
}

function pendingStateBytes(state: PendingState): number {
  return state.kind === 'uploading' ? state.totalBytes : state.totalBytes;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function withDeadline<Result>(
  operation: Promise<Result>,
  deadlineMs: number,
  onDeadline: () => void,
  deadlineError: Error,
): Promise<Result> {
  return new Promise<Result>((resolve, reject) => {
    const timer = setTimeout(() => {
      try {
        onDeadline();
      } catch (error) {
        reject(error);
        return;
      }
      reject(deadlineError);
    }, deadlineMs);
    operation.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function safeTimestampAddition(timestamp: number, duration: number): number {
  const result = timestamp + duration;
  if (!Number.isSafeInteger(result)) throw new RangeError('Transfer expiry exceeds timestamp range');
  return result;
}

function assertUuidV4(value: string, name: string): void {
  if (typeof value !== 'string' || !UUID_V4_PATTERN.test(value)) {
    throw new TypeError(`${name} must be a canonical UUIDv4 string`);
  }
}

function isTimestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function boundedPositiveInteger(value: number, name: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new RangeError(`${name} must be an integer between 1 and ${maximum}`);
  }
  return value;
}
