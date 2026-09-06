import browser from 'webextension-polyfill';
import {
  BINARY_TRANSFER_PORT_NAME,
  BINARY_TRANSFER_PORT_VERSION,
  BINARY_TRANSFER_TIMEOUT_MS,
  BINARY_TRANSFER_TTL_MS,
  MAX_BINARY_TRANSFER_CHUNK_BYTES,
  decodeBinaryTransferChunk,
  encodeBinaryTransferChunk,
  parseBinaryTransferClientMessage,
  parseBinaryTransferWorkerMessage,
  type BinaryTransferClientMessage,
  type BinaryTransferRequest,
  type BinaryTransferWorkerMessage,
} from '../messaging/binary-transfer-port.js';

export interface BinaryTransferClientPort {
  readonly onMessage: {
    addListener(listener: (message: unknown) => void): void;
    removeListener(listener: (message: unknown) => void): void;
  };
  readonly onDisconnect: {
    addListener(listener: () => void): void;
    removeListener(listener: () => void): void;
  };
  postMessage(message: BinaryTransferClientMessage): void;
  disconnect(): void;
}

/** Only the current slice is read; the caller keeps ownership of the selected file. */
export interface BinaryTransferFile {
  readonly size: number;
  slice(start: number, end: number): { arrayBuffer(): Promise<ArrayBuffer> };
}

export interface BinaryTransferClientTimers {
  setTimeout(callback: () => void, delayMs: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface BinaryTransferClientOptions {
  connectPort?(name: typeof BINARY_TRANSFER_PORT_NAME): BinaryTransferClientPort;
  signal?: AbortSignal;
  timers?: BinaryTransferClientTimers;
  messageTimeoutMs?: number;
  overallTimeoutMs?: number;
}

export interface BinaryTransferArtifact {
  readonly blob: Blob;
  readonly fileName: string;
}

export type BinaryTransferResult<T = unknown> =
  | { ok: true; data: T }
  | { ok: false; error: { code: string; message: string } };

type UploadRequest = Exclude<BinaryTransferRequest, { type: 'vault.getAttachment' }>;
type DownloadRequest = Extract<BinaryTransferRequest, { type: 'vault.getAttachment' }>;
type ExpectedMessage = BinaryTransferWorkerMessage['type'] | undefined;

class TransferError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
  }
}

const defaultTimers: BinaryTransferClientTimers = {
  setTimeout: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
  clearTimeout: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/** A single operation owns a Port and permits only one unacknowledged chunk in either direction. */
class BinaryTransferOperation {
  private readonly timers: BinaryTransferClientTimers;
  private readonly messageTimeoutMs: number;
  private readonly port: BinaryTransferClientPort;
  private readonly abortPromise: Promise<never>;
  private rejectAbort!: (error: TransferError) => void;
  private expected: ExpectedMessage;
  private queued: BinaryTransferWorkerMessage | undefined;
  private pending: ((message: BinaryTransferWorkerMessage) => void) | undefined;
  private messageTimer: unknown;
  private overallTimer: unknown;
  private failure: TransferError | undefined;
  private closed = false;
  private terminalReceived = false;
  private currentBytes: Uint8Array | undefined;
  private readonly parts: Blob[] = [];

  constructor(private readonly options: BinaryTransferClientOptions) {
    this.timers = options.timers ?? defaultTimers;
    this.messageTimeoutMs = boundedTimeout(options.messageTimeoutMs ?? BINARY_TRANSFER_TIMEOUT_MS);
    const overallTimeoutMs = boundedTimeout(options.overallTimeoutMs ?? BINARY_TRANSFER_TTL_MS);
    if (options.signal?.aborted) throw cancelled();
    this.port = (options.connectPort ?? ((name) => browser.runtime.connect({ name })))(BINARY_TRANSFER_PORT_NAME);
    this.abortPromise = new Promise<never>((_resolve, reject) => { this.rejectAbort = reject; });
    // Cancellation can occur between reads, before an awaited race has attached its own handler.
    void this.abortPromise.catch(() => undefined);
    this.port.onMessage.addListener(this.onMessage);
    this.port.onDisconnect.addListener(this.onDisconnect);
    options.signal?.addEventListener('abort', this.onAbort, { once: true });
    this.overallTimer = this.timers.setTimeout(() => this.fail(timeout()), overallTimeoutMs);
    if (options.signal?.aborted) this.onAbort();
  }

  async upload(request: UploadRequest, file: BinaryTransferFile): Promise<unknown> {
    await this.exchange({ version: BINARY_TRANSFER_PORT_VERSION, type: 'begin', request }, 'ready');
    let sequence = 0;
    for (let offset = 0; offset < request.expectedBytes; sequence += 1) {
      const end = Math.min(request.expectedBytes, offset + MAX_BINARY_TRANSFER_CHUNK_BYTES);
      const read = file.slice(offset, end).arrayBuffer().then((buffer) => {
        const bytes = new Uint8Array(buffer);
        if (this.closed || this.failure) {
          bytes.fill(0);
          throw this.failure ?? cancelled();
        }
        if (bytes.byteLength !== end - offset) {
          bytes.fill(0);
          throw invalidMessage('The file slice size changed during transfer.');
        }
        this.currentBytes = bytes;
        return bytes;
      });
      const bytes = await Promise.race([read, this.abortPromise]);
      let acknowledgement: Promise<BinaryTransferWorkerMessage>;
      try {
        acknowledgement = this.exchange({
          version: BINARY_TRANSFER_PORT_VERSION,
          type: 'chunk',
          sequence,
          byteLength: bytes.byteLength,
          dataBase64: encodeBinaryTransferChunk(bytes),
        }, 'ack');
      } finally {
        bytes.fill(0);
        this.currentBytes = undefined;
      }
      const response = await acknowledgement;
      if (response.type !== 'ack' || response.sequence !== sequence) {
        throw invalidMessage('The file transfer acknowledgement is out of order.');
      }
      offset = end;
    }
    const result = await this.exchange({ version: BINARY_TRANSFER_PORT_VERSION, type: 'seal' }, 'result');
    if (result.type !== 'result') throw invalidMessage();
    this.assertActive();
    return result.data;
  }

  async download(request: DownloadRequest): Promise<BinaryTransferArtifact> {
    const metadata = await this.exchange({ version: BINARY_TRANSFER_PORT_VERSION, type: 'begin', request }, 'download');
    if (metadata.type !== 'download') throw invalidMessage();
    let sequence = 0;
    let received = 0;
    while (received < metadata.totalBytes) {
      const message = await this.receive();
      if (message.type !== 'chunk' || message.sequence !== sequence
        || message.byteLength > metadata.totalBytes - received) throw invalidMessage();
      const bytes = decodeBinaryTransferChunk(message.dataBase64, message.byteLength);
      this.currentBytes = bytes;
      try {
        this.parts.push(new Blob([bytes as BlobPart]));
      } finally {
        bytes.fill(0);
        this.currentBytes = undefined;
      }
      received += message.byteLength;
      this.expect(received === metadata.totalBytes ? 'done' : 'chunk');
      this.post({ version: BINARY_TRANSFER_PORT_VERSION, type: 'ack', sequence });
      sequence += 1;
    }
    const done = await this.receive();
    if (done.type !== 'done' || done.chunkCount !== sequence || done.totalBytes !== received) {
      throw invalidMessage();
    }
    this.assertActive();
    const blob = new Blob(this.parts);
    this.parts.length = 0;
    return { blob, fileName: metadata.fileName };
  }

  complete(): void {
    this.assertActive();
    this.close(false);
  }

  close(cancel: boolean): void {
    if (this.closed) return;
    this.closed = true;
    if (cancel) {
      try { this.port.postMessage({ version: BINARY_TRANSFER_PORT_VERSION, type: 'cancel' }); } catch { /* The Port may already be disconnected. */ }
    }
    this.currentBytes?.fill(0);
    this.currentBytes = undefined;
    this.parts.length = 0;
    this.queued = undefined;
    this.pending = undefined;
    this.timers.clearTimeout(this.messageTimer);
    this.timers.clearTimeout(this.overallTimer);
    this.options.signal?.removeEventListener('abort', this.onAbort);
    this.port.onMessage.removeListener(this.onMessage);
    this.port.onDisconnect.removeListener(this.onDisconnect);
    try { this.port.disconnect(); } catch { /* Cleanup is idempotent after worker termination. */ }
  }

  private readonly onAbort = (): void => this.fail(cancelled());
  private readonly onDisconnect = (): void => {
    // The worker releases its Port immediately after posting a terminal message. Its payload still
    // has to pass the consumer's completion checks, and local cancellation continues to apply.
    if (!this.terminalReceived) this.fail(new TransferError('disconnected', 'The file transfer connection closed unexpectedly.'));
  };
  private readonly onMessage = (value: unknown): void => {
    if (this.closed || this.failure) return;
    try {
      const message = parseBinaryTransferWorkerMessage(value);
      if (!message) throw invalidMessage();
      if (message.type === 'error') throw new TransferError(message.error.code, message.error.message);
      if (message.type !== this.expected) throw invalidMessage();
      if (message.type === 'result' || message.type === 'done') this.terminalReceived = true;
      this.expected = undefined;
      this.timers.clearTimeout(this.messageTimer);
      // The first download chunk may arrive immediately after its metadata, before receive resumes.
      if (message.type === 'download') this.expect(message.totalBytes === 0 ? 'done' : 'chunk');
      if (this.pending) {
        const resolve = this.pending;
        this.pending = undefined;
        resolve(message);
      } else {
        if (this.queued) throw invalidMessage();
        this.queued = message;
      }
    } catch (error) {
      this.fail(error instanceof TransferError ? error : invalidMessage());
    }
  };

  private fail(error: TransferError): void {
    if (this.closed || this.failure) return;
    this.failure = error;
    this.rejectAbort(error);
    this.close(true);
  }

  private assertActive(): void {
    if (this.failure) throw this.failure;
    if (this.closed || this.options.signal?.aborted) throw cancelled();
  }

  private expect(type: Exclude<ExpectedMessage, undefined>): void {
    this.assertActive();
    this.expected = type;
    this.timers.clearTimeout(this.messageTimer);
    this.messageTimer = undefined;
    // Encryption and the worker's sequential network operations can legitimately exceed one
    // message interval. The overall operation deadline still bounds both execution phases.
    if (type !== 'result' && type !== 'download') {
      this.messageTimer = this.timers.setTimeout(() => this.fail(timeout()), this.messageTimeoutMs);
    }
  }

  private post(message: BinaryTransferClientMessage): void {
    this.assertActive();
    this.port.postMessage(message);
  }

  private exchange(message: BinaryTransferClientMessage, type: Exclude<ExpectedMessage, undefined>): Promise<BinaryTransferWorkerMessage> {
    this.expect(type);
    const response = this.receive();
    try { this.post(message); } catch (error) { this.fail(asTransferError(error)); }
    return response;
  }

  private async receive(): Promise<BinaryTransferWorkerMessage> {
    this.assertActive();
    if (this.queued) {
      const message = this.queued;
      this.queued = undefined;
      return message;
    }
    if (this.pending) throw invalidMessage();
    return Promise.race([
      new Promise<BinaryTransferWorkerMessage>((resolve) => { this.pending = resolve; }),
      this.abortPromise,
    ]);
  }
}

export async function uploadBinaryTransfer(
  request: UploadRequest,
  file: BinaryTransferFile,
  options: BinaryTransferClientOptions = {},
): Promise<BinaryTransferResult> {
  let operation: BinaryTransferOperation | undefined;
  let succeeded = false;
  try {
    validateBegin(request);
    if (!file || file.size !== request.expectedBytes) throw invalidMessage('The selected file size does not match the transfer.');
    operation = new BinaryTransferOperation(options);
    const data = await operation.upload(request, file);
    operation.complete();
    succeeded = true;
    return { ok: true, data };
  } catch (error) {
    const failure = asTransferError(error);
    return { ok: false, error: { code: failure.code, message: failure.message } };
  } finally {
    operation?.close(!succeeded);
  }
}

export async function downloadBinaryTransfer(
  request: DownloadRequest,
  options: BinaryTransferClientOptions = {},
): Promise<BinaryTransferResult<BinaryTransferArtifact>> {
  let operation: BinaryTransferOperation | undefined;
  let succeeded = false;
  try {
    validateBegin(request);
    operation = new BinaryTransferOperation(options);
    const data = await operation.download(request);
    operation.complete();
    succeeded = true;
    return { ok: true, data };
  } catch (error) {
    const failure = asTransferError(error);
    return { ok: false, error: { code: failure.code, message: failure.message } };
  } finally {
    operation?.close(!succeeded);
  }
}

function validateBegin(request: BinaryTransferRequest): void {
  try {
    parseBinaryTransferClientMessage({ version: BINARY_TRANSFER_PORT_VERSION, type: 'begin', request });
  } catch {
    throw invalidMessage();
  }
}

function invalidMessage(message = 'The file transfer received an invalid message.'): TransferError {
  return new TransferError('invalid_message', message);
}

function cancelled(): TransferError {
  return new TransferError('cancelled', 'The file transfer was cancelled.');
}

function timeout(): TransferError {
  return new TransferError('timeout', 'The file transfer timed out.');
}

function asTransferError(error: unknown): TransferError {
  return error instanceof TransferError ? error : new TransferError('transfer_failed', 'The file transfer could not be completed.');
}

function boundedTimeout(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > 60 * 60_000) throw invalidMessage();
  return value;
}
