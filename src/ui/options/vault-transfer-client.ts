import {
  MAX_VAULT_TRANSFER_PORT_TOTAL_BYTES,
  VAULT_TRANSFER_PORT_ERROR_MESSAGES,
  VAULT_TRANSFER_PORT_NAME,
  VAULT_TRANSFER_PORT_VERSION,
  VaultTransferPortProtocolError,
  canClearVaultTransferRecovery,
  decodeVaultTransferPortChunk,
  encodeVaultTransferPortChunk,
  parseVaultTransferClientMessage,
  parseVaultTransferWorkerMessage,
  type VaultTransferClientMessage,
  type VaultTransferExportBeginMessage,
  type VaultTransferExportFormat,
  type VaultTransferExportReview,
  type VaultTransferImportResultMessage,
  type VaultTransferImportSealMessage,
  type VaultTransferPortErrorCode,
  type VaultTransferPortPreviewModel,
  type VaultTransferRecoveryClearedMessage,
  type VaultTransferRecoveryStatus,
  type VaultTransferWorkerMessage,
} from '../../messaging/vault-transfer-port.js';
import {
  PERSONAL_VAULT_TRANSFER_EXPORT_TARGET,
  canonicalizeVaultTransferExportTarget,
  type VaultTransferExportTarget,
} from '../../core/vault/vault-transfer-target.js';

export const VAULT_TRANSFER_CLIENT_SLICE_BYTES = 64 * 1024;
export const DEFAULT_VAULT_TRANSFER_MESSAGE_TIMEOUT_MS = 30 * 1_000;
export const DEFAULT_VAULT_TRANSFER_OVERALL_TTL_MS = 10 * 60 * 1_000;

const MAX_MESSAGE_TIMEOUT_MS = 5 * 60 * 1_000;
const MAX_OVERALL_TTL_MS = 60 * 60 * 1_000;
const MAX_PASSWORD_CHARS = 1_024;

export const VAULT_TRANSFER_CLIENT_ERROR_MESSAGES = Object.freeze({
  ...VAULT_TRANSFER_PORT_ERROR_MESSAGES,
  busy: 'Another vault transfer is already active.',
  disposed: 'The vault transfer client is no longer available.',
  disconnected: 'The vault transfer connection closed unexpectedly.',
  timeout: 'The vault transfer timed out.',
  review_required: 'The CSV export requires an explicit loss review.',
} as const);

export type VaultTransferClientErrorCode = keyof typeof VAULT_TRANSFER_CLIENT_ERROR_MESSAGES;

export class VaultTransferClientError extends Error {
  constructor(readonly code: VaultTransferClientErrorCode) {
    super(VAULT_TRANSFER_CLIENT_ERROR_MESSAGES[code]);
    this.name = 'VaultTransferClientError';
  }
}

export interface VaultTransferClientEvent<Listener> {
  addListener(listener: Listener): void;
  removeListener?(listener: Listener): void;
}

export interface VaultTransferClientPort {
  readonly onMessage: VaultTransferClientEvent<(message: unknown) => void>;
  readonly onDisconnect: VaultTransferClientEvent<() => void>;
  postMessage(message: VaultTransferClientMessage): void;
  disconnect(): void;
}

export interface VaultTransferReadableSlice {
  arrayBuffer(): Promise<ArrayBuffer>;
}

/** The structural subset of File used by the client. The caller retains ownership of the file. */
export interface VaultTransferFile {
  readonly name: string;
  readonly size: number;
  slice(start: number, end: number): VaultTransferReadableSlice;
}

export interface VaultTransferDownloadArtifact {
  readonly blob: Blob;
  readonly fileName: string;
  readonly format: VaultTransferExportFormat;
  readonly review?: VaultTransferExportReview;
}

export interface VaultTransferClientTimers {
  setTimeout(callback: () => void, delayMs: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface VaultTransferClientDependencies {
  connectPort(name: typeof VAULT_TRANSFER_PORT_NAME): VaultTransferClientPort;
  readSlice(slice: VaultTransferReadableSlice): Promise<ArrayBuffer>;
  download?(artifact: VaultTransferDownloadArtifact): void | Promise<void>;
  confirmExportReview?(review: VaultTransferExportReview): boolean | Promise<boolean>;
  ackClientEvent?(ackId: string): Promise<unknown>;
  timers?: VaultTransferClientTimers;
  messageTimeoutMs?: number;
  overallTtlMs?: number;
}

type OperationMode = 'import' | 'export' | 'recovery';
type OperationPhase = 'starting' | 'uploading' | 'inspecting' | 'previewed' | 'committing'
  | 'result-acknowledging' | 'exporting';

interface PendingMessage {
  readonly timer: unknown;
  readonly resolve: (message: VaultTransferWorkerMessage) => void;
  readonly reject: (error: VaultTransferClientError) => void;
}

interface PendingResultAcknowledgement {
  readonly timer: unknown;
  readonly resolve: () => void;
}

interface ActiveOperation {
  readonly generation: number;
  readonly mode: OperationMode;
  readonly port: VaultTransferClientPort;
  readonly onMessage: (message: unknown) => void;
  readonly onDisconnect: () => void;
  readonly abortPromise: Promise<never>;
  readonly rejectAbort: (error: VaultTransferClientError) => void;
  phase: OperationPhase;
  transferId: string | undefined;
  previewRevision: string | undefined;
  queuedMessage: VaultTransferWorkerMessage | undefined;
  pendingMessage: PendingMessage | undefined;
  pendingResultAcknowledgement: PendingResultAcknowledgement | undefined;
  overallTimer: unknown;
  currentBytes: Uint8Array | undefined;
  blobParts: Blob[] | undefined;
  failure: VaultTransferClientError | undefined;
}

const DEFAULT_TIMERS: VaultTransferClientTimers = Object.freeze({
  setTimeout(callback: () => void, delayMs: number): unknown {
    return globalThis.setTimeout(callback, delayMs);
  },
  clearTimeout(handle: unknown): void {
    globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>);
  },
});

/**
 * Strict stop-and-wait client for the privileged options-page transfer Port. A client owns at most
 * one live Port, while selected File objects remain owned by the UI so password retries can reopen
 * a fresh transfer without retaining file bytes here.
 */
export class VaultTransferClient {
  private readonly timers: VaultTransferClientTimers;
  private readonly messageTimeoutMs: number;
  private readonly overallTtlMs: number;
  private generation = 0;
  private active: ActiveOperation | undefined;
  private disposed = false;

  constructor(private readonly dependencies: VaultTransferClientDependencies) {
    this.timers = dependencies.timers ?? DEFAULT_TIMERS;
    this.messageTimeoutMs = boundedDuration(
      dependencies.messageTimeoutMs ?? DEFAULT_VAULT_TRANSFER_MESSAGE_TIMEOUT_MS,
      MAX_MESSAGE_TIMEOUT_MS,
      'messageTimeoutMs',
    );
    this.overallTtlMs = boundedDuration(
      dependencies.overallTtlMs ?? DEFAULT_VAULT_TRANSFER_OVERALL_TTL_MS,
      MAX_OVERALL_TTL_MS,
      'overallTtlMs',
    );
  }

  async import(file: VaultTransferFile, password?: string): Promise<VaultTransferPortPreviewModel> {
    validateOptionalPassword(password);
    const begin = parseOwnMessage({
      version: VAULT_TRANSFER_PORT_VERSION,
      type: 'import.begin',
      expectedTotalBytes: file.size,
      fileName: file.name,
    });
    if (begin.type !== 'import.begin') throw clientError('invalid_message');

    const operation = this.start('import');
    try {
      this.post(operation, begin);
      const begun = await this.nextMessage(operation);
      if (begun.type !== 'import.begun') throw protocolError('invalid_message');
      operation.transferId = begun.transferId;
      operation.phase = 'uploading';

      const chunkBytes = begun.maxChunkBytes;
      let sequence = 0;
      let offset = 0;
      while (offset < file.size) {
        const end = Math.min(file.size, offset + chunkBytes);
        const expectedLength = end - offset;
        const bytes = new Uint8Array(expectedLength);
        operation.currentBytes = bytes;
        let encoded = '';
        try {
          let readOffset = offset;
          while (readOffset < end) {
            const readEnd = Math.min(end, readOffset + VAULT_TRANSFER_CLIENT_SLICE_BYTES);
            const buffer = await this.readFileSlice(operation, file, readOffset, readEnd);
            const sliceBytes = new Uint8Array(buffer);
            try {
              if (sliceBytes.byteLength !== readEnd - readOffset) {
                throw protocolError('size_mismatch');
              }
              bytes.set(sliceBytes, readOffset - offset);
            } finally {
              sliceBytes.fill(0);
            }
            readOffset = readEnd;
          }
          encoded = encodeVaultTransferPortChunk(bytes);
          this.post(operation, {
            version: VAULT_TRANSFER_PORT_VERSION,
            type: 'import.chunk',
            transferId: begun.transferId,
            sequence,
            byteLength: bytes.byteLength,
            dataBase64: encoded,
          });
        } finally {
          encoded = '';
          bytes.fill(0);
          if (operation.currentBytes === bytes) operation.currentBytes = undefined;
        }

        const acknowledgement = await this.nextMessage(operation);
        if (acknowledgement.type !== 'import.ack'
          || acknowledgement.transferId !== begun.transferId
          || acknowledgement.sequence !== sequence
          || acknowledgement.nextSequence !== sequence + 1
          || acknowledgement.byteLength !== expectedLength
          || acknowledgement.totalBytes !== end) {
          throw protocolError('invalid_sequence');
        }
        offset = end;
        sequence += 1;
      }

      operation.phase = 'inspecting';
      const seal: Mutable<VaultTransferImportSealMessage> = password === undefined
        ? {
            version: VAULT_TRANSFER_PORT_VERSION,
            type: 'import.seal',
            transferId: begun.transferId,
          }
        : {
            version: VAULT_TRANSFER_PORT_VERSION,
            type: 'import.seal',
            transferId: begun.transferId,
            password,
          };
      password = undefined;
      try {
        this.post(operation, seal);
      } finally {
        if (seal.password !== undefined) seal.password = '';
      }

      const preview = await this.nextMessage(operation);
      if (preview.type !== 'import.preview' || preview.transferId !== begun.transferId) {
        throw protocolError('invalid_message');
      }
      operation.previewRevision = preview.previewRevision;
      operation.phase = 'previewed';
      return preview.preview;
    } catch (error) {
      throw this.stopWithError(operation, error);
    }
  }

  async confirm(): Promise<VaultTransferImportResultMessage> {
    const operation = this.active;
    if (!operation || operation.mode !== 'import' || operation.phase !== 'previewed'
      || operation.transferId === undefined || operation.previewRevision === undefined) {
      throw clientError(this.disposed ? 'disposed' : 'invalid_state');
    }

    operation.phase = 'committing';
    try {
      this.post(operation, {
        version: VAULT_TRANSFER_PORT_VERSION,
        type: 'import.confirm',
        transferId: operation.transferId,
        previewRevision: operation.previewRevision,
      });
      const result = await this.nextMessage(operation);
      if (result.type !== 'import.result' || result.transferId !== operation.transferId) {
        throw protocolError('invalid_message');
      }
      if (shouldAcknowledgeImportResult(result)) {
        const delivery = this.waitForResultAcknowledgement(operation);
        try {
          this.post(operation, {
            version: VAULT_TRANSFER_PORT_VERSION,
            type: 'import.result.ack',
            transferId: result.transferId,
          });
        } catch {
          // The terminal result is already known. A lost delivery ACK must preserve the worker's
          // replay barrier without presenting the completed commit as a retryable client failure.
          return result;
        }
        await delivery;
        return result;
      }
      if (this.isCurrent(operation)) this.finish(operation);
      return result;
    } catch (error) {
      throw this.stopWithError(operation, error);
    }
  }

  async inspectRecovery(): Promise<VaultTransferRecoveryStatus> {
    const operation = this.start('recovery');
    try {
      this.post(operation, {
        version: VAULT_TRANSFER_PORT_VERSION,
        type: 'recovery.inspect',
      });
      const message = await this.nextMessage(operation);
      if (message.type !== 'recovery.status') throw protocolError('invalid_message');
      this.finish(operation);
      return message.status;
    } catch (error) {
      throw this.stopWithError(operation, error);
    }
  }

  async clearRecovery(status: VaultTransferRecoveryStatus): Promise<VaultTransferRecoveryClearedMessage> {
    if (!canClearVaultTransferRecovery(status)) {
      throw clientError('recovery_not_clearable');
    }
    const expectedBarriers = status.barriers
      .map(({ transferId, reason }) => ({ transferId, reason }))
      .sort((left, right) => compareAscii(left.transferId, right.transferId));
    const operation = this.start('recovery');
    try {
      this.post(operation, {
        version: VAULT_TRANSFER_PORT_VERSION,
        type: 'recovery.clear',
        expectedBarriers,
      });
      const message = await this.nextMessage(operation);
      if (message.type !== 'recovery.cleared'
        || message.cleared !== expectedBarriers.length) {
        throw protocolError('invalid_message');
      }
      this.finish(operation);
      return message;
    } catch (error) {
      throw this.stopWithError(operation, error);
    }
  }

  async export(
    format: VaultTransferExportFormat,
    authorizationId: string,
    filePassword?: string,
    target: VaultTransferExportTarget = PERSONAL_VAULT_TRANSFER_EXPORT_TARGET,
  ): Promise<VaultTransferDownloadArtifact> {
    validateAuthorizationId(authorizationId);
    validateOptionalPassword(filePassword);
    if (format !== 'encrypted-json' && filePassword !== undefined) {
      throw clientError('password_not_allowed');
    }
    const canonicalTarget = canonicalExportTarget(target);
    const untrustedBegin: Mutable<VaultTransferExportBeginMessage> = format === 'encrypted-json'
      && filePassword !== undefined
      ? {
          version: VAULT_TRANSFER_PORT_VERSION,
          type: 'export.begin',
          format,
          authorizationId,
          target: canonicalTarget,
          filePassword,
        }
      : {
          version: VAULT_TRANSFER_PORT_VERSION,
          type: 'export.begin',
          format,
          authorizationId,
          target: canonicalTarget,
        };
    const begin = parseOwnMessage(untrustedBegin) as Mutable<VaultTransferExportBeginMessage>;
    untrustedBegin.authorizationId = '';
    if ('filePassword' in untrustedBegin) untrustedBegin.filePassword = '';
    if (begin.type !== 'export.begin') throw clientError('invalid_message');

    let operation: ActiveOperation;
    try {
      operation = this.start('export');
    } catch (error) {
      begin.authorizationId = '';
      if ('filePassword' in begin) begin.filePassword = '';
      throw error;
    }
    operation.phase = 'exporting';
    const parts: Blob[] = [];
    operation.blobParts = parts;
    try {
      authorizationId = '';
      filePassword = undefined;
      try {
        this.post(operation, begin);
      } finally {
        begin.authorizationId = '';
        if ('filePassword' in begin) begin.filePassword = '';
      }

      const begun = await this.nextMessage(operation);
      if (begun.type !== 'export.begun' || begun.format !== format) {
        throw protocolError('invalid_message');
      }
      operation.transferId = begun.transferId;
      if (begun.review && (begun.review.omittedItemCount > 0 || begun.review.warnings.length > 0)) {
        const confirmReview = this.dependencies.confirmExportReview;
        if (!confirmReview) throw clientError('review_required');
        const accepted = await this.withAbort(
          operation,
          Promise.resolve().then(() => confirmReview(begun.review!)),
        );
        if (!accepted) throw clientError('cancelled');
      }

      let expectedSequence = 0;
      let totalBytes = 0;
      let clientEventAckId: string | undefined;
      for (;;) {
        const message = await this.nextMessage(operation);
        if (message.type === 'export.done') {
          if (message.transferId !== begun.transferId
            || message.format !== format
            || message.chunkCount !== expectedSequence
            || message.totalBytes !== totalBytes) {
            throw protocolError('size_mismatch');
          }
          clientEventAckId = message.clientEventAckId;
          break;
        }
        if (message.type !== 'export.chunk'
          || message.transferId !== begun.transferId
          || message.format !== format
          || message.sequence !== expectedSequence) {
          throw protocolError('invalid_sequence');
        }

        let bytes: Uint8Array | undefined;
        try {
          bytes = decodeVaultTransferPortChunk(message.dataBase64, message.byteLength);
          operation.currentBytes = bytes;
          const nextTotal = totalBytes + bytes.byteLength;
          if (!Number.isSafeInteger(nextTotal) || nextTotal > MAX_VAULT_TRANSFER_PORT_TOTAL_BYTES) {
            throw protocolError('total_too_large');
          }
          const ownedBytes = new Uint8Array(bytes.byteLength);
          try {
            ownedBytes.set(bytes);
            parts.push(new Blob([ownedBytes.buffer]));
          } finally {
            ownedBytes.fill(0);
          }
          totalBytes = nextTotal;
        } finally {
          bytes?.fill(0);
          if (operation.currentBytes === bytes) operation.currentBytes = undefined;
        }

        this.post(operation, {
          version: VAULT_TRANSFER_PORT_VERSION,
          type: 'export.ack',
          transferId: begun.transferId,
          sequence: expectedSequence,
        });
        expectedSequence += 1;
      }

      const artifact: VaultTransferDownloadArtifact = {
        blob: new Blob(parts, { type: mimeType(format) }),
        fileName: begun.fileName,
        format,
        ...(begun.review ? { review: begun.review } : {}),
      };
      parts.length = 0;
      operation.blobParts = undefined;
      const download = this.dependencies.download;
      if (download) {
        await this.withAbort(operation, Promise.resolve(download(artifact)));
      }
      this.finish(operation);
      if (download && clientEventAckId !== undefined) this.ackClientEvent(clientEventAckId);
      return artifact;
    } catch (error) {
      parts.length = 0;
      throw this.stopWithError(operation, error, 'export_failed');
    }
  }

  private ackClientEvent(ackId: string): void {
    const acknowledge = this.dependencies.ackClientEvent;
    if (!acknowledge) return;
    try {
      void Promise.resolve(acknowledge(ackId)).catch(() => undefined);
    } catch {
      // Event collection is best-effort and must not turn a completed download into a failure.
    }
  }

  cancel(): void {
    const operation = this.active;
    if (!operation) return;
    if (operation.transferId !== undefined) {
      try {
        this.post(operation, {
          version: VAULT_TRANSFER_PORT_VERSION,
          type: 'cancel',
          transferId: operation.transferId,
        });
      } catch {
        // Teardown below is authoritative when the Port is already unusable.
      }
    }
    if (this.active === operation) this.fail(operation, clientError('cancelled'));
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    const operation = this.active;
    if (operation) this.fail(operation, clientError('disposed'));
  }

  private start(mode: OperationMode): ActiveOperation {
    if (this.disposed) throw clientError('disposed');
    if (this.active) throw clientError('busy');

    const generation = ++this.generation;
    let port: VaultTransferClientPort;
    try {
      port = this.dependencies.connectPort(VAULT_TRANSFER_PORT_NAME);
    } catch {
      throw clientError('disconnected');
    }

    let rejectAbort: ((error: VaultTransferClientError) => void) | undefined;
    const abortPromise = new Promise<never>((_resolve, reject) => {
      rejectAbort = reject;
    });
    void abortPromise.catch(() => undefined);

    const operation: ActiveOperation = {
      generation,
      mode,
      port,
      phase: 'starting',
      transferId: undefined,
      previewRevision: undefined,
      queuedMessage: undefined,
      pendingMessage: undefined,
      pendingResultAcknowledgement: undefined,
      overallTimer: undefined,
      currentBytes: undefined,
      blobParts: undefined,
      failure: undefined,
      abortPromise,
      rejectAbort: rejectAbort!,
      onMessage: (message: unknown): void => {
        if (!this.isCurrent(operation)) return;
        this.receive(operation, message);
      },
      onDisconnect: (): void => {
        if (!this.isCurrent(operation)) return;
        if (operation.phase === 'result-acknowledging'
          && operation.pendingResultAcknowledgement !== undefined) {
          this.settleResultAcknowledgement(operation);
          this.teardown(operation);
          return;
        }
        this.fail(operation, clientError('disconnected'));
      },
    };
    this.active = operation;

    try {
      port.onMessage.addListener(operation.onMessage);
      port.onDisconnect.addListener(operation.onDisconnect);
      operation.overallTimer = this.timers.setTimeout(() => {
        if (this.isCurrent(operation)) this.fail(operation, clientError('timeout'));
      }, this.overallTtlMs);
    } catch {
      this.fail(operation, clientError('disconnected'));
      throw operation.failure!;
    }
    return operation;
  }

  private receive(operation: ActiveOperation, value: unknown): void {
    let message: VaultTransferWorkerMessage;
    try {
      message = parseVaultTransferWorkerMessage(value);
    } catch (error) {
      this.fail(operation, stableClientError(error, 'invalid_message'));
      return;
    }

    if (message.type === 'error') {
      const matches = operation.transferId === undefined
        ? message.transferId === null
        : message.transferId === operation.transferId;
      this.fail(operation, clientError(matches ? message.error.code : 'invalid_message'));
      return;
    }

    if (operation.phase === 'result-acknowledging') {
      this.fail(operation, clientError('invalid_message'));
      return;
    }

    if (operation.transferId === undefined
      && ((operation.mode === 'import' && message.type === 'import.begun')
        || (operation.mode === 'export' && message.type === 'export.begun'))) {
      operation.transferId = message.transferId;
    }

    const pending = operation.pendingMessage;
    if (pending) {
      operation.pendingMessage = undefined;
      this.timers.clearTimeout(pending.timer);
      pending.resolve(message);
      return;
    }
    if (operation.queuedMessage !== undefined) {
      this.fail(operation, clientError('invalid_message'));
      return;
    }
    operation.queuedMessage = message;
  }

  private nextMessage(operation: ActiveOperation): Promise<VaultTransferWorkerMessage> {
    this.assertCurrent(operation);
    if (operation.queuedMessage !== undefined) {
      const message = operation.queuedMessage;
      operation.queuedMessage = undefined;
      return Promise.resolve(message);
    }
    if (operation.pendingMessage !== undefined) {
      return Promise.reject(clientError('invalid_state'));
    }
    return new Promise<VaultTransferWorkerMessage>((resolve, reject) => {
      const timer = this.timers.setTimeout(() => {
        if (this.isCurrent(operation)) this.fail(operation, clientError('timeout'));
      }, this.messageTimeoutMs);
      operation.pendingMessage = { timer, resolve, reject };
    });
  }

  private waitForResultAcknowledgement(operation: ActiveOperation): Promise<void> {
    this.assertCurrent(operation);
    if (operation.pendingResultAcknowledgement !== undefined) {
      return Promise.reject(clientError('invalid_state'));
    }
    operation.phase = 'result-acknowledging';
    return new Promise<void>((resolve) => {
      const timer = this.timers.setTimeout(() => {
        if (!this.isCurrent(operation)) return;
        this.settleResultAcknowledgement(operation);
        this.teardown(operation);
      }, this.messageTimeoutMs);
      operation.pendingResultAcknowledgement = { timer, resolve };
    });
  }

  private post(operation: ActiveOperation, message: VaultTransferClientMessage): void {
    this.assertCurrent(operation);
    try {
      operation.port.postMessage(message);
    } catch {
      throw this.fail(operation, clientError('disconnected'));
    }
    this.assertCurrent(operation);
  }

  private async readFileSlice(
    operation: ActiveOperation,
    file: VaultTransferFile,
    start: number,
    end: number,
  ): Promise<ArrayBuffer> {
    const read = Promise.resolve().then(() => this.dependencies.readSlice(file.slice(start, end)));
    try {
      const buffer = await this.withAbort(operation, read);
      if (!(buffer instanceof ArrayBuffer)) throw protocolError('invalid_chunk');
      return buffer;
    } catch (error) {
      void read.then((lateBuffer) => zeroArrayBuffer(lateBuffer)).catch(() => undefined);
      throw error;
    }
  }

  private async withAbort<T>(operation: ActiveOperation, promise: Promise<T>): Promise<T> {
    this.assertCurrent(operation);
    return Promise.race([promise, operation.abortPromise]);
  }

  private stopWithError(
    operation: ActiveOperation,
    error: unknown,
    fallback: VaultTransferClientErrorCode = 'internal_error',
  ): VaultTransferClientError {
    if (operation.failure) return operation.failure;
    return this.fail(operation, stableClientError(error, fallback));
  }

  private fail(operation: ActiveOperation, error: VaultTransferClientError): VaultTransferClientError {
    if (operation.failure) return operation.failure;
    operation.failure = error;
    operation.currentBytes?.fill(0);
    operation.currentBytes = undefined;
    operation.blobParts?.splice(0);
    operation.blobParts = undefined;
    operation.queuedMessage = undefined;
    const pending = operation.pendingMessage;
    operation.pendingMessage = undefined;
    if (pending) {
      this.timers.clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.settleResultAcknowledgement(operation);
    operation.rejectAbort(error);
    this.teardown(operation);
    return error;
  }

  private finish(operation: ActiveOperation): void {
    this.assertCurrent(operation);
    this.teardown(operation);
  }

  private settleResultAcknowledgement(operation: ActiveOperation): void {
    const pending = operation.pendingResultAcknowledgement;
    operation.pendingResultAcknowledgement = undefined;
    if (!pending) return;
    this.timers.clearTimeout(pending.timer);
    pending.resolve();
  }

  private teardown(operation: ActiveOperation): void {
    if (this.active === operation) {
      this.active = undefined;
      this.generation += 1;
    }
    if (operation.overallTimer !== undefined) {
      this.timers.clearTimeout(operation.overallTimer);
      operation.overallTimer = undefined;
    }
    removeListener(operation.port.onMessage, operation.onMessage);
    removeListener(operation.port.onDisconnect, operation.onDisconnect);
    try {
      operation.port.disconnect();
    } catch {
      // A disconnected Port is already terminal.
    }
  }

  private assertCurrent(operation: ActiveOperation): void {
    if (!this.isCurrent(operation)) throw operation.failure ?? clientError('cancelled');
  }

  private isCurrent(operation: ActiveOperation): boolean {
    return this.active === operation && operation.generation === this.generation;
  }
}

type Mutable<T> = { -readonly [Key in keyof T]: T[Key] };

function parseOwnMessage(value: unknown): VaultTransferClientMessage {
  try {
    return parseVaultTransferClientMessage(value);
  } catch (error) {
    throw stableClientError(error, 'invalid_message');
  }
}

function stableClientError(
  error: unknown,
  fallback: VaultTransferClientErrorCode,
): VaultTransferClientError {
  if (error instanceof VaultTransferClientError) return error;
  if (error instanceof VaultTransferPortProtocolError) return clientError(error.code);
  return clientError(fallback);
}

function clientError(code: VaultTransferClientErrorCode): VaultTransferClientError {
  return new VaultTransferClientError(code);
}

function protocolError(code: VaultTransferPortErrorCode): VaultTransferPortProtocolError {
  return new VaultTransferPortProtocolError(code);
}

function boundedDuration(value: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError(`${label} must be a positive bounded integer`);
  }
  return value;
}

function validateOptionalPassword(password: string | undefined): void {
  if (password !== undefined
    && (typeof password !== 'string' || password.length < 1 || password.length > MAX_PASSWORD_CHARS)) {
    throw clientError('invalid_message');
  }
}

function validateAuthorizationId(value: string): void {
  if (
    typeof value !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)
  ) {
    throw clientError('invalid_message');
  }
}

function canonicalExportTarget(value: unknown): VaultTransferExportTarget {
  try {
    return canonicalizeVaultTransferExportTarget(value);
  } catch {
    throw clientError('invalid_message');
  }
}

function shouldAcknowledgeImportResult(result: VaultTransferImportResultMessage): boolean {
  return (result.status === 'completed' || result.status === 'partial')
    && result.counts.outcomeUnknown === 0;
}

function mimeType(format: VaultTransferExportFormat): string {
  if (format === 'zip') return 'application/zip';
  if (format === 'csv') return 'text/csv;charset=utf-8';
  return 'application/json';
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function zeroArrayBuffer(value: unknown): void {
  if (value instanceof ArrayBuffer) new Uint8Array(value).fill(0);
}

function removeListener<Listener>(
  event: VaultTransferClientEvent<Listener>,
  listener: Listener,
): void {
  try {
    event.removeListener?.(listener);
  } catch {
    // Listener removal is best effort after terminal teardown.
  }
}
