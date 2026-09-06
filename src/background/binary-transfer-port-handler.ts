import { AppError } from '../core/errors.js';
import type { VaultFinalAuthorityBinder } from '../core/vault/vault-service.js';
import {
  BINARY_TRANSFER_PORT_NAME,
  BINARY_TRANSFER_TIMEOUT_MS,
  BINARY_TRANSFER_TTL_MS,
  BinaryTransferError,
  MAX_BINARY_TRANSFER_BYTES,
  MAX_BINARY_TRANSFER_CHUNK_BYTES,
  decodeBinaryTransferChunk,
  encodeBinaryTransferChunk,
  parseBinaryTransferClientMessage,
  type BinaryTransferClientMessage,
  type BinaryTransferRequest,
  type BinaryTransferWorkerMessage,
} from '../messaging/binary-transfer-port.js';
import type { VaultReleaseGate, VaultReleaseLease } from './vault-release-gate.js';

interface Event<Listener> {
  addListener(listener: Listener): void;
  removeListener(listener: Listener): void;
}

export interface BinaryTransferPort {
  readonly name: string;
  readonly sender?: { readonly id?: string; readonly url?: string; readonly documentId?: string };
  readonly onMessage: Event<(message: unknown) => void>;
  readonly onDisconnect: Event<() => void>;
  postMessage(message: BinaryTransferWorkerMessage): void;
  disconnect(): void;
}

export type BinaryTransferResult =
  | { readonly kind: 'result'; readonly data: unknown }
  | { readonly kind: 'download'; readonly fileName: string; readonly bytes: Uint8Array };

export interface BinaryTransferExecution {
  readonly signal: AbortSignal;
  /** The operation must check this before dispatching each remote mutation. */
  readonly assertCurrent: () => void;
  readonly bindFinalAuthority: VaultFinalAuthorityBinder;
  /** Record commitment before awaited activity bookkeeping can lose the response. */
  readonly markCommitted: () => void;
}

export interface BinaryTransferDependencies {
  readonly ready: PromiseLike<void>;
  readonly releaseGate: Pick<VaultReleaseGate, 'capture' | 'checkpoint' | 'assertAuthorities' | 'assert' | 'settlePendingAction'>;
  /** Capture only the active account and session identity after startup is ready. */
  captureAuthority(): () => void;
  /** Guard staged bytes until policy authority passes to the service's mutation operation. */
  captureAdmissionAuthority(): () => void;
  execute(request: BinaryTransferRequest, bytes: Uint8Array | undefined, execution: BinaryTransferExecution): Promise<BinaryTransferResult>;
  readonly idleTimeoutMs?: number;
  readonly overallTimeoutMs?: number;
}

interface State {
  active: boolean;
  busy: boolean;
  executing: boolean;
  committed: boolean;
  request: BinaryTransferRequest | undefined;
  bytes: Uint8Array | undefined;
  offset: number;
  sequence: number;
  readonly abort: AbortController;
  sessionLease: VaultReleaseLease['sessionLease'] | undefined;
  authority: (() => void) | undefined;
  admissionAuthority: (() => void) | undefined;
  finalAuthorities: Array<() => void>;
  pendingAck: { sequence: number; resolve(): void; reject(error: Error): void } | undefined;
  idleTimer: ReturnType<typeof setTimeout> | undefined;
  overallTimer: ReturnType<typeof setTimeout> | undefined;
  close(): void;
  fail(error: unknown): void;
}

/** One bounded transfer across trusted extension documents; no file bytes use runtime.sendMessage. */
export class BinaryTransferPortHandler {
  private readonly active = new Set<State>();

  constructor(private readonly dependencies: BinaryTransferDependencies) {}

  /** Called synchronously on lock, logout, or account switch. */
  invalidateAll(): void {
    for (const state of [...this.active]) state.fail(new AppError('locked', 'The active vault session changed.'));
  }

  /** A service mutation may publish its own reconciled policy before binding its final authority. */
  invalidatePolicy(): void {
    for (const state of [...this.active]) {
      if (!state.executing || state.finalAuthorities.length > 0) {
        state.fail(new AppError('denied', 'The vault policy changed during the file transfer.'));
      }
    }
  }

  handle(port: BinaryTransferPort, extensionBaseUrl: string, extensionId: string): boolean {
    if (!trustedDocument(port, extensionBaseUrl, extensionId)) {
      safeDisconnect(port);
      return false;
    }
    if (this.active.size >= 1) {
      try { port.postMessage({ version: 1, type: 'error', error: { code: 'capacity', message: 'Another file transfer is still finishing.' } }); } catch { /* The peer may already be gone. */ }
      safeDisconnect(port);
      return false;
    }
    const state: State = {
      active: true, busy: false, executing: false, committed: false, request: undefined, bytes: undefined, offset: 0, sequence: 0,
      abort: new AbortController(), sessionLease: undefined, authority: undefined,
      admissionAuthority: undefined,
      finalAuthorities: [], pendingAck: undefined, idleTimer: undefined, overallTimer: undefined,
      close: () => {
        if (!state.active) return;
        state.active = false;
        state.abort.abort();
        state.bytes?.fill(0);
        state.bytes = undefined;
        state.request = undefined;
        state.finalAuthorities = [];
        clearTimeout(state.idleTimer);
        clearTimeout(state.overallTimer);
        state.pendingAck?.reject(new BinaryTransferError('cancelled', 'The file transfer was cancelled.'));
        state.pendingAck = undefined;
        port.onMessage.removeListener(onMessage);
        port.onDisconnect.removeListener(onDisconnect);
        // A cancelled remote operation still owns the memory slot until its cleanup settles.
        if (!state.executing) this.active.delete(state);
      },
      fail: (error) => {
        if (!state.active) return;
        const failure = state.committed
          ? new AppError('committed_unsynced', 'The file change completed, but its result could not be confirmed. Sync before retrying.')
          : error instanceof AppError || error instanceof BinaryTransferError ? error : new BinaryTransferError('error');
        try { port.postMessage({ version: 1, type: 'error', error: { code: failure.code, message: failure.message } }); } catch { /* The peer may already be gone. */ }
        state.close();
        safeDisconnect(port);
      },
    };
    const onDisconnect = (): void => state.close();
    const onMessage = (value: unknown): void => {
      if (!state.active) return;
      let message: BinaryTransferClientMessage;
      try { message = parseBinaryTransferClientMessage(value); } catch (error) { state.fail(error); return; }
      if (message.type === 'cancel') { state.close(); safeDisconnect(port); return; }
      if (message.type === 'ack') {
        const ack = state.pendingAck;
        if (!ack || ack.sequence !== message.sequence) { state.fail(new BinaryTransferError('invalid_sequence')); return; }
        try { this.assertCurrent(state); } catch (error) { state.fail(error); return; }
        state.pendingAck = undefined;
        clearTimeout(state.idleTimer);
        ack.resolve();
        return;
      }
      if (state.busy) { state.fail(new BinaryTransferError('ack_required')); return; }
      state.busy = true;
      clearTimeout(state.idleTimer);
      void this.process(port, state, message).then(() => {
        state.busy = false;
        if (state.active) this.armIdle(state);
      }, (error: unknown) => state.fail(error));
    };
    this.active.add(state);
    port.onMessage.addListener(onMessage);
    port.onDisconnect.addListener(onDisconnect);
    this.armIdle(state);
    state.overallTimer = setTimeout(() => state.fail(new BinaryTransferError('timeout', 'The file transfer timed out.')), this.dependencies.overallTimeoutMs ?? BINARY_TRANSFER_TTL_MS);
    return true;
  }

  private async process(port: BinaryTransferPort, state: State, message: Exclude<BinaryTransferClientMessage, { type: 'ack' }>): Promise<void> {
    if (message.type === 'begin') {
      if (state.request) throw new BinaryTransferError('invalid_state');
      await this.dependencies.ready;
      if (!state.active) return;
      state.authority = this.dependencies.captureAuthority();
      state.admissionAuthority = this.dependencies.captureAdmissionAuthority();
      state.sessionLease = this.dependencies.releaseGate.capture().sessionLease;
      state.request = message.request;
      if (message.request.type === 'vault.getAttachment') {
        await this.execute(port, state);
      } else {
        this.assertCurrent(state);
        state.bytes = new Uint8Array(message.request.expectedBytes);
        await this.authorizedPost(port, state, { version: 1, type: 'ready' });
      }
      return;
    }
    this.assertCurrent(state);
    if (!state.request || state.request.type === 'vault.getAttachment' || !state.bytes) throw new BinaryTransferError('invalid_state');
    if (message.type === 'chunk') {
      if (message.sequence !== state.sequence || state.offset + message.byteLength > state.bytes.byteLength) throw new BinaryTransferError('invalid_sequence');
      const chunk = decodeBinaryTransferChunk(message.dataBase64, message.byteLength);
      try { state.bytes.set(chunk, state.offset); } finally { chunk.fill(0); }
      state.offset += message.byteLength;
      state.sequence += 1;
      port.postMessage({ version: 1, type: 'ack', sequence: message.sequence });
      return;
    }
    if (message.type !== 'seal' || state.offset !== state.bytes.byteLength) throw new BinaryTransferError('size_mismatch');
    await this.execute(port, state);
  }

  private async execute(port: BinaryTransferPort, state: State): Promise<void> {
    this.assertCurrent(state);
    state.executing = true;
    let result: BinaryTransferResult | undefined;
    try {
      result = await this.dependencies.execute(state.request!, state.bytes, {
        signal: state.abort.signal,
        assertCurrent: () => this.assertCurrent(state),
        bindFinalAuthority: (assertCurrent) => { this.assertCurrent(state); state.finalAuthorities.push(assertCurrent); },
        markCommitted: () => { state.committed = true; },
      });
      if (result.kind === 'result') state.committed = true;
      state.bytes?.fill(0);
      state.bytes = undefined;
      this.assertCurrent(state);
      if (state.finalAuthorities.length === 0) throw new BinaryTransferError('denied', 'File transfer authority is unavailable.');
      if (result.kind === 'result') {
        await this.authorizedPost(port, state, { version: 1, type: 'result', data: result.data });
      } else {
        if (!(result.bytes instanceof Uint8Array) || result.bytes.byteLength > MAX_BINARY_TRANSFER_BYTES) throw new BinaryTransferError('size_mismatch');
        state.bytes = result.bytes;
        await this.authorizedPost(port, state, { version: 1, type: 'download', fileName: result.fileName, totalBytes: result.bytes.byteLength });
        let sequence = 0;
        for (let offset = 0; offset < result.bytes.byteLength; offset += MAX_BINARY_TRANSFER_CHUNK_BYTES) {
          this.assertCurrent(state);
          const chunk = result.bytes.subarray(offset, offset + MAX_BINARY_TRANSFER_CHUNK_BYTES);
          const dataBase64 = encodeBinaryTransferChunk(chunk);
          const acknowledgement = new Promise<void>((resolve, reject) => { state.pendingAck = { sequence, resolve, reject }; });
          // A rejection may race the durable release checkpoint before it is awaited below.
          void acknowledgement.catch(() => undefined);
          await this.authorizedPost(port, state, { version: 1, type: 'chunk', sequence, byteLength: chunk.byteLength, dataBase64 });
          this.armIdle(state);
          await acknowledgement;
          chunk.fill(0);
          sequence += 1;
        }
        await this.authorizedPost(port, state, { version: 1, type: 'done', chunkCount: sequence, totalBytes: result.bytes.byteLength });
      }
      state.close();
      safeDisconnect(port);
    } finally {
      if (result?.kind === 'download') result.bytes.fill(0);
      state.executing = false;
      if (!state.active) this.active.delete(state);
    }
  }

  private assertCurrent(state: State): void {
    if (!state.active || state.abort.signal.aborted || !state.authority || !state.sessionLease) throw new BinaryTransferError('cancelled');
    state.authority();
    if (!state.executing) state.admissionAuthority?.();
  }

  private async authorizedPost(port: BinaryTransferPort, state: State, message: BinaryTransferWorkerMessage): Promise<void> {
    const gate = this.dependencies.releaseGate;
    await gate.settlePendingAction();
    this.assertCurrent(state);
    const proof = await gate.checkpoint(gate.capture(state.sessionLease));
    await gate.settlePendingAction();
    gate.assertAuthorities(proof, () => {
      this.assertCurrent(state);
      for (const assertCurrent of state.finalAuthorities) assertCurrent();
    });
    gate.assert(proof);
    if (!state.active) throw new BinaryTransferError('cancelled');
    port.postMessage(message);
  }

  private armIdle(state: State): void {
    clearTimeout(state.idleTimer);
    if (state.active) state.idleTimer = setTimeout(() => state.fail(new BinaryTransferError('timeout', 'The file transfer timed out.')), this.dependencies.idleTimeoutMs ?? BINARY_TRANSFER_TIMEOUT_MS);
  }
}

function trustedDocument(port: BinaryTransferPort, extensionBaseUrl: string, extensionId: string): boolean {
  if (!extensionId || port.name !== BINARY_TRANSFER_PORT_NAME || port.sender?.id !== extensionId || !port.sender.documentId?.trim()) return false;
  try {
    const expected = new URL('ui/popup/popup.html', extensionBaseUrl);
    const actual = new URL(port.sender.url ?? '');
    return actual.protocol === expected.protocol && actual.host === expected.host
      && !actual.username && !actual.password && !expected.username && !expected.password
      && (actual.pathname === expected.pathname || actual.pathname === '/ui/options/options.html')
      && !actual.search && !actual.hash;
  } catch { return false; }
}

function safeDisconnect(port: BinaryTransferPort): void {
  try { port.disconnect(); } catch { /* Teardown is already complete. */ }
}
