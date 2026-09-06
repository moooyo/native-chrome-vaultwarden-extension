import { describe, expect, it, vi } from 'vitest';
import { AppError } from '../core/errors.js';
import {
  BINARY_TRANSFER_PORT_NAME,
  MAX_BINARY_TRANSFER_CHUNK_BYTES,
  encodeBinaryTransferChunk,
  type BinaryTransferWorkerMessage,
} from '../messaging/binary-transfer-port.js';
import { BinaryTransferPortHandler, type BinaryTransferDependencies, type BinaryTransferPort } from './binary-transfer-port-handler.js';
import { SessionGate } from './session-gate.js';
import { VaultReleaseGate } from './vault-release-gate.js';

const ID = 'abcdefghijklmnopabcdefghijklmnop';
const BASE = `chrome-extension://${ID}/`;

class Event<Listener extends (...args: never[]) => void> {
  readonly listeners = new Set<Listener>();
  addListener(listener: Listener): void { this.listeners.add(listener); }
  removeListener(listener: Listener): void { this.listeners.delete(listener); }
}

class Port implements BinaryTransferPort {
  readonly name = BINARY_TRANSFER_PORT_NAME;
  readonly sender: { id: string; url: string; documentId: string };
  readonly onMessage = new Event<(message: unknown) => void>();
  readonly onDisconnect = new Event<() => void>();
  readonly sent: BinaryTransferWorkerMessage[] = [];
  disconnected = false;
  onPost: ((message: BinaryTransferWorkerMessage) => void) | undefined;
  retainChunks = false;
  constructor(url = `${BASE}ui/popup/popup.html`) { this.sender = { id: ID, url, documentId: 'document-a' }; }
  postMessage(message: BinaryTransferWorkerMessage): void {
    if (this.retainChunks || message.type !== 'chunk') this.sent.push(message);
    this.onPost?.(message);
  }
  receive(message: unknown): void { for (const listener of [...this.onMessage.listeners]) listener(message); }
  disconnect(): void {
    this.disconnected = true;
    for (const listener of [...this.onDisconnect.listeners]) listener();
  }
}

function harness(execute?: BinaryTransferDependencies['execute']) {
  const session = new SessionGate('unlocked');
  let account = 1;
  let policy = 1;
  let onCheckpoint: (() => Promise<void>) | undefined;
  const timeout = {
    captureRelease: () => ({ generation: 1, accountKey: 'a', sessionBindingId: 'b' }),
    checkpointRelease: async () => {
      await onCheckpoint?.();
      return { generation: 1, accountKey: 'a', sessionBindingId: 'b', issuedMonotonicAt: 1, monotonicDeadlineAt: 10 };
    },
    assertRelease: () => undefined,
  };
  const run = vi.fn(execute ?? (async (_request, _bytes, execution) => {
    execution.bindFinalAuthority(execution.assertCurrent);
    return { kind: 'result' as const, data: { created: true } };
  }));
  const handler = new BinaryTransferPortHandler({
    ready: Promise.resolve(), releaseGate: new VaultReleaseGate(timeout, session), execute: run,
    captureAuthority: () => {
      const captured = account;
      const lease = session.capture();
      return () => {
        session.assert(lease);
        if (account !== captured) throw new AppError('denied', 'The active account changed.');
      };
    },
    captureAdmissionAuthority: () => {
      const captured = policy;
      return () => { if (captured !== policy) throw new AppError('denied', 'The policy changed.'); };
    },
  });
  return {
    handler, run, session,
    changeAccount: () => { account += 1; },
    publishPolicy: () => { policy += 1; handler.invalidatePolicy(); },
    checkpoint: (hook: () => Promise<void>) => { onCheckpoint = hook; },
  };
}

function beginUpload(port: Port, expectedBytes: number): void {
  port.receive({ version: 1, type: 'begin', request: { type: 'sends.createFile', input: { name: 'Example' }, fileName: 'sample.bin', expectedBytes } });
}

function beginDownload(port: Port): void {
  port.receive({ version: 1, type: 'begin', request: { type: 'vault.getAttachment', cipherId: 'cipher-a', attachmentId: 'attachment-a' } });
}

function sendChunk(port: Port, sequence: number, bytes: Uint8Array): void {
  port.receive({ version: 1, type: 'chunk', sequence, byteLength: bytes.byteLength, dataBase64: encodeBinaryTransferChunk(bytes) });
}

async function flush(): Promise<void> { for (let i = 0; i < 30; i += 1) await Promise.resolve(); }

describe('BinaryTransferPortHandler', () => {
  it('binds the port to a trusted extension document and caps concurrent buffers', () => {
    const { handler } = harness();
    for (const url of ['https://example.com/', `${BASE}ui/popup/popup.html?untrusted`, `${BASE}ui/offscreen/offscreen.html`]) {
      const port = new Port(url);
      expect(handler.handle(port, BASE, ID)).toBe(false);
      expect(port.disconnected).toBe(true);
    }
    const port = new Port();
    port.sender.documentId = '';
    expect(handler.handle(port, BASE, ID)).toBe(false);
    const options = new Port(`${BASE}ui/options/options.html`);
    expect(handler.handle(options, BASE, ID)).toBe(true);
    expect(handler.handle(new Port(), BASE, ID)).toBe(false);
    options.disconnect();
    const popup = new Port();
    expect(handler.handle(popup, BASE, ID)).toBe(true);
    popup.disconnect();
  });

  it('uploads more than 64 MiB with bounded stop-and-wait messages and exact bytes', async () => {
    const size = 65 * 1024 * 1024 + 7;
    let borrowed: Uint8Array | undefined;
    const { handler, run } = harness(async (_request, bytes, execution) => {
      borrowed = bytes!;
      expect(bytes?.byteLength).toBe(size);
      expect(bytes?.every((value) => value === 173)).toBe(true);
      execution.bindFinalAuthority(execution.assertCurrent);
      return { kind: 'result', data: { created: true } };
    });
    const port = new Port();
    handler.handle(port, BASE, ID);
    beginUpload(port, size);
    await flush();
    expect(port.sent.at(-1)?.type).toBe('ready');
    let sequence = 0;
    for (let offset = 0; offset < size; offset += MAX_BINARY_TRANSFER_CHUNK_BYTES) {
      const bytes = new Uint8Array(Math.min(MAX_BINARY_TRANSFER_CHUNK_BYTES, size - offset)).fill(173);
      const encoded = encodeBinaryTransferChunk(bytes);
      expect(encoded.length).toBeLessThanOrEqual(Math.ceil(MAX_BINARY_TRANSFER_CHUNK_BYTES / 3) * 4);
      port.receive({ version: 1, type: 'chunk', sequence, byteLength: bytes.byteLength, dataBase64: encoded });
      await flush();
      expect(port.sent.at(-1)).toEqual({ version: 1, type: 'ack', sequence });
      sequence += 1;
    }
    port.receive({ version: 1, type: 'seal' });
    await flush();
    expect(run).toHaveBeenCalledOnce();
    expect(port.sent.at(-1)?.type).toBe('result');
    expect(borrowed?.every((value) => value === 0)).toBe(true);
    expect(port.disconnected).toBe(true);
  }, 60_000);

  it('requires exact download acknowledgements and wipes remaining bytes on cancellation', async () => {
    const bytes = new Uint8Array(MAX_BINARY_TRANSFER_CHUNK_BYTES * 2 + 1).fill(9);
    const { handler } = harness(async (_request, _bytes, execution) => {
      execution.bindFinalAuthority(execution.assertCurrent);
      return { kind: 'download', fileName: 'large.bin', bytes };
    });
    const port = new Port();
    const sequences: number[] = [];
    port.onPost = (message) => { if (message.type === 'chunk') sequences.push(message.sequence); };
    handler.handle(port, BASE, ID);
    beginDownload(port);
    await flush();
    expect(sequences).toEqual([0]);
    await flush();
    expect(sequences).toEqual([0]);
    port.receive({ version: 1, type: 'ack', sequence: 0 });
    await flush();
    expect(sequences).toEqual([0, 1]);
    port.receive({ version: 1, type: 'cancel' });
    await flush();
    expect(bytes.every((value) => value === 0)).toBe(true);
    expect(sequences).toEqual([0, 1]);
    expect(port.sent.some((message) => message.type === 'done')).toBe(false);
  });

  it('streams a download larger than 64 MiB without a whole-file response', async () => {
    const size = 65 * 1024 * 1024 + 1;
    const bytes = new Uint8Array(size).fill(42);
    const { handler } = harness(async (_request, _bytes, execution) => {
      execution.bindFinalAuthority(execution.assertCurrent);
      return { kind: 'download', fileName: 'large.bin', bytes };
    });
    const port = new Port();
    let transferred = 0;
    let sequence = 0;
    let finish!: () => void;
    const done = new Promise<void>((resolve) => { finish = resolve; });
    port.onPost = (message) => {
      if (message.type === 'chunk') {
        expect(message.sequence).toBe(sequence++);
        expect(message.byteLength).toBeLessThanOrEqual(MAX_BINARY_TRANSFER_CHUNK_BYTES);
        expect(JSON.stringify(message).length).toBeLessThan(400_000);
        transferred += message.byteLength;
        queueMicrotask(() => port.receive({ version: 1, type: 'ack', sequence: message.sequence }));
      }
      if (message.type === 'done') finish();
    };
    handler.handle(port, BASE, ID);
    beginDownload(port);
    await done;
    await flush();
    expect(transferred).toBe(size);
    expect(bytes.every((value) => value === 0)).toBe(true);
    expect(port.sent.at(-1)).toEqual({ version: 1, type: 'done', totalBytes: size, chunkCount: sequence });
  }, 60_000);

  it('rejects account changes before the staged upload can mutate remote state', async () => {
    const { handler, run, changeAccount } = harness();
    const port = new Port();
    handler.handle(port, BASE, ID);
    beginUpload(port, 1);
    await flush();
    sendChunk(port, 0, Uint8Array.of(5));
    await flush();
    changeAccount();
    port.receive({ version: 1, type: 'seal' });
    await flush();
    expect(run).not.toHaveBeenCalled();
    expect(port.sent.at(-1)).toMatchObject({ type: 'error', error: { code: 'denied' } });
  });

  it('hands admission policy to the service so a successful mutation can publish its own policy', async () => {
    const runtime = harness(async (_request, _bytes, execution) => {
      runtime.publishPolicy();
      execution.assertCurrent();
      execution.bindFinalAuthority(execution.assertCurrent);
      execution.markCommitted();
      return { kind: 'result', data: { created: true } };
    });
    const port = new Port();
    runtime.handler.handle(port, BASE, ID);
    beginUpload(port, 0);
    await flush();
    port.receive({ version: 1, type: 'seal' });
    await flush();
    expect(port.sent.at(-1)?.type).toBe('result');
  });

  it('invalidates staged bytes when policy changes before service admission', async () => {
    const runtime = harness();
    const port = new Port();
    runtime.handler.handle(port, BASE, ID);
    beginUpload(port, 1);
    await flush();
    runtime.publishPolicy();
    expect(port.disconnected).toBe(true);
    expect(runtime.run).not.toHaveBeenCalled();
  });

  it('reports commitment when response bookkeeping fails after a successful mutation', async () => {
    const runtime = harness(async (_request, _bytes, execution) => {
      execution.markCommitted();
      throw new AppError('locked', 'Vault is locked');
    });
    const port = new Port();
    runtime.handler.handle(port, BASE, ID);
    beginUpload(port, 0);
    await flush();
    port.receive({ version: 1, type: 'seal' });
    await flush();
    expect(port.sent.at(-1)).toMatchObject({ type: 'error', error: { code: 'committed_unsynced' } });
  });

  it('revokes a download at the durable checkpoint before posting any file bytes', async () => {
    const bytes = Uint8Array.of(42);
    const runtime = harness(async (_request, _bytes, execution) => {
      execution.bindFinalAuthority(execution.assertCurrent);
      return { kind: 'download', fileName: 'secret.bin', bytes };
    });
    let checkpoints = 0;
    runtime.checkpoint(async () => {
      checkpoints += 1;
      if (checkpoints === 2) runtime.session.handleTransition({ phase: 'start', transitionId: 1, reason: 'lock', identityChanged: false });
    });
    const port = new Port();
    port.retainChunks = true;
    runtime.handler.handle(port, BASE, ID);
    beginDownload(port);
    await flush();
    expect(port.sent.some((message) => message.type === 'download')).toBe(true);
    expect(port.sent.some((message) => message.type === 'chunk')).toBe(false);
    expect(bytes[0]).toBe(0);
    expect(port.disconnected).toBe(true);
  });

  it('cleans a disconnected in-flight upload and retains its capacity until cleanup settles', async () => {
    let finish!: () => void;
    const waiting = new Promise<void>((resolve) => { finish = resolve; });
    let borrowed: Uint8Array | undefined;
    let signal: AbortSignal | undefined;
    const { handler } = harness(async (_request, bytes, execution) => {
      borrowed = bytes;
      signal = execution.signal;
      await waiting;
      execution.assertCurrent();
      return { kind: 'result', data: null };
    });
    const port = new Port();
    handler.handle(port, BASE, ID);
    beginUpload(port, 1);
    await flush();
    sendChunk(port, 0, Uint8Array.of(91));
    await flush();
    port.receive({ version: 1, type: 'seal' });
    await flush();
    port.disconnect();
    expect(signal?.aborted).toBe(true);
    expect(borrowed?.[0]).toBe(0);
    expect(handler.handle(new Port(), BASE, ID)).toBe(false);
    finish();
    await flush();
    const next = new Port();
    expect(handler.handle(next, BASE, ID)).toBe(true);
    next.disconnect();
    expect(port.sent.some((message) => message.type === 'result')).toBe(false);
  });

  it('times out idle uploads and immediately clears transfers on lifecycle invalidation', async () => {
    vi.useFakeTimers();
    try {
      const { handler, run } = harness();
      const port = new Port();
      handler.handle(port, BASE, ID);
      beginUpload(port, 1);
      await flush();
      await vi.advanceTimersByTimeAsync(30_001);
      expect(port.sent.at(-1)).toMatchObject({ type: 'error', error: { code: 'timeout' } });
      const next = new Port();
      handler.handle(next, BASE, ID);
      beginUpload(next, 1);
      await flush();
      handler.invalidateAll();
      expect(next.disconnected).toBe(true);
      expect(run).not.toHaveBeenCalled();
    } finally { vi.useRealTimers(); }
  });
});
