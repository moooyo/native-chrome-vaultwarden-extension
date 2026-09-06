import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({ default: { runtime: { connect: vi.fn() } } }));

import {
  BINARY_TRANSFER_TTL_MS,
  MAX_ATTACHMENT_FILE_BYTES,
  MAX_BINARY_TRANSFER_BYTES,
  MAX_BINARY_TRANSFER_CHUNK_BYTES,
  MAX_SEND_FILE_BYTES,
  encodeBinaryTransferChunk,
  type BinaryTransferClientMessage,
  type BinaryTransferWorkerMessage,
} from '../messaging/binary-transfer-port.js';
import {
  downloadBinaryTransfer,
  uploadBinaryTransfer,
  type BinaryTransferClientPort,
  type BinaryTransferFile,
} from './binary-transfer-client.js';

class FakeEvent<Listener extends (...args: never[]) => void> {
  readonly listeners = new Set<Listener>();
  addListener(listener: Listener): void { this.listeners.add(listener); }
  removeListener(listener: Listener): void { this.listeners.delete(listener); }
  emit(...args: Parameters<Listener>): void {
    for (const listener of [...this.listeners]) listener(...args);
  }
}

class FakePort implements BinaryTransferClientPort {
  readonly onMessage = new FakeEvent<(message: unknown) => void>();
  readonly onDisconnect = new FakeEvent<() => void>();
  readonly sent: BinaryTransferClientMessage[] = [];
  onPost: ((message: BinaryTransferClientMessage) => void) | undefined;
  disconnected = false;
  retainChunks = true;
  maxMessageLength = 0;

  postMessage(message: BinaryTransferClientMessage): void {
    const json = JSON.stringify(message);
    this.maxMessageLength = Math.max(this.maxMessageLength, json.length);
    const cloned = JSON.parse(json) as BinaryTransferClientMessage;
    if (this.retainChunks || message.type !== 'chunk') this.sent.push(cloned);
    this.onPost?.(cloned);
  }

  emit(message: BinaryTransferWorkerMessage | unknown): void { this.onMessage.emit(message); }
  disconnect(): void { this.disconnected = true; }
}

class GeneratedFile implements BinaryTransferFile {
  readonly slices: Array<[number, number]> = [];
  lastBuffer: ArrayBuffer | undefined;
  previousBuffersWereWiped = true;

  constructor(readonly size: number) {}

  slice(start: number, end: number): { arrayBuffer(): Promise<ArrayBuffer> } {
    if (this.lastBuffer) {
      this.previousBuffersWereWiped &&= new Uint8Array(this.lastBuffer).every((byte) => byte === 0);
    }
    this.slices.push([start, end]);
    return {
      arrayBuffer: async () => {
        const bytes = new Uint8Array(end - start).fill(97);
        this.lastBuffer = bytes.buffer;
        return bytes.buffer;
      },
    };
  }
}

const sendRequest = (expectedBytes: number) => ({
  type: 'sends.createFile' as const,
  input: { name: 'Large Send', deletionHours: 168 },
  fileName: 'large.bin',
  expectedBytes,
});
const attachmentRequest = (expectedBytes: number) => ({
  type: 'vault.addAttachment' as const,
  cipherId: 'cipher-1',
  fileName: 'attachment.bin',
  expectedBytes,
});
const downloadRequest = { type: 'vault.getAttachment' as const, cipherId: 'cipher-1', attachmentId: 'attachment-1' };

function acknowledgeUploads(port: FakePort): void {
  port.onPost = (message) => {
    if (message.type === 'begin') port.emit({ version: 1, type: 'ready' });
    if (message.type === 'chunk') port.emit({ version: 1, type: 'ack', sequence: message.sequence });
    if (message.type === 'seal') port.emit({ version: 1, type: 'result', data: { send: { id: 'send-1' } } });
  };
}

afterEach(() => { vi.useRealTimers(); });

describe('binary file upload client', () => {
  it('uploads the full 100 MiB Send limit using bounded messages and wipes each read buffer', async () => {
    const port = new FakePort();
    port.retainChunks = false;
    const file = new GeneratedFile(MAX_SEND_FILE_BYTES);
    let uploaded = 0;
    let chunks = 0;
    port.onPost = (message) => {
      if (message.type === 'begin') port.emit({ version: 1, type: 'ready' });
      if (message.type === 'chunk') {
        expect(message.sequence).toBe(chunks);
        expect(message.byteLength).toBeLessThanOrEqual(MAX_BINARY_TRANSFER_CHUNK_BYTES);
        uploaded += message.byteLength;
        chunks += 1;
        port.emit({ version: 1, type: 'ack', sequence: message.sequence });
      }
      if (message.type === 'seal') port.emit({ version: 1, type: 'result', data: { send: { id: 'send-1' } } });
    };

    const result = await uploadBinaryTransfer(sendRequest(file.size), file, { connectPort: () => port });

    expect(result).toEqual({ ok: true, data: { send: { id: 'send-1' } } });
    expect(uploaded).toBe(MAX_SEND_FILE_BYTES);
    expect(chunks).toBe(MAX_SEND_FILE_BYTES / MAX_BINARY_TRANSFER_CHUNK_BYTES);
    expect(port.maxMessageLength).toBeLessThan(350_000);
    expect(file.slices.every(([start, end]) => end - start <= MAX_BINARY_TRANSFER_CHUNK_BYTES)).toBe(true);
    expect(file.previousBuffersWereWiped).toBe(true);
    expect(new Uint8Array(file.lastBuffer!).every((byte) => byte === 0)).toBe(true);
    expect(port.disconnected).toBe(true);
    expect(port.onMessage.listeners.size).toBe(0);
  }, 30_000);

  it('does not read a second slice until the first chunk is acknowledged', async () => {
    const port = new FakePort();
    const file = new GeneratedFile(MAX_BINARY_TRANSFER_CHUNK_BYTES + 1);
    port.onPost = (message) => {
      if (message.type === 'begin') port.emit({ version: 1, type: 'ready' });
      if (message.type === 'seal') port.emit({ version: 1, type: 'result', data: null });
    };
    const result = uploadBinaryTransfer(sendRequest(file.size), file, { connectPort: () => port });
    await vi.waitFor(() => expect(port.sent.filter((message) => message.type === 'chunk')).toHaveLength(1));
    expect(file.slices).toHaveLength(1);
    expect(new Uint8Array(file.lastBuffer!).every((byte) => byte === 0)).toBe(true);
    port.emit({ version: 1, type: 'ack', sequence: 0 });
    await vi.waitFor(() => expect(file.slices).toHaveLength(2));
    port.emit({ version: 1, type: 'ack', sequence: 1 });
    await expect(result).resolves.toEqual({ ok: true, data: null });
  });

  it('accepts an empty file without emitting a chunk', async () => {
    const port = new FakePort();
    acknowledgeUploads(port);
    const file = new GeneratedFile(0);
    await expect(uploadBinaryTransfer(sendRequest(0), file, { connectPort: () => port })).resolves.toMatchObject({ ok: true });
    expect(file.slices).toHaveLength(0);
    expect(port.sent.map((message) => message.type)).toEqual(['begin', 'seal']);
  });

  it('accepts a terminal upload result followed by immediate worker disconnection', async () => {
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type === 'begin') port.emit({ version: 1, type: 'ready' });
      if (message.type === 'seal') {
        port.emit({ version: 1, type: 'result', data: { saved: true } });
        port.onDisconnect.emit();
      }
    };
    await expect(uploadBinaryTransfer(sendRequest(0), new GeneratedFile(0), { connectPort: () => port }))
      .resolves.toEqual({ ok: true, data: { saved: true } });
  });

  it.each([
    sendRequest(MAX_SEND_FILE_BYTES + 1),
    attachmentRequest(MAX_ATTACHMENT_FILE_BYTES + 1),
    sendRequest(Number.NaN),
    sendRequest(-1),
  ])('rejects an invalid declared size before connecting: $expectedBytes', async (request) => {
    const connectPort = vi.fn();
    await expect(uploadBinaryTransfer(request, new GeneratedFile(request.expectedBytes), { connectPort })).resolves.toMatchObject({ ok: false });
    expect(connectPort).not.toHaveBeenCalled();
  });

  it('rejects a file whose reported size differs from the declaration before connecting', async () => {
    const connectPort = vi.fn();
    await expect(uploadBinaryTransfer(sendRequest(4), new GeneratedFile(3), { connectPort })).resolves.toMatchObject({ ok: false });
    expect(connectPort).not.toHaveBeenCalled();
  });

  it('rejects an unexpected slice length without sending those bytes', async () => {
    const port = new FakePort();
    acknowledgeUploads(port);
    const bytes = new Uint8Array([1, 2]);
    const file = { size: 1, slice: () => ({ arrayBuffer: async () => bytes.buffer }) };
    await expect(uploadBinaryTransfer(sendRequest(1), file, { connectPort: () => port }))
      .resolves.toMatchObject({ ok: false, error: { code: 'invalid_message' } });
    expect([...bytes]).toEqual([0, 0]);
    expect(port.sent.map((message) => message.type)).toEqual(['begin', 'cancel']);
  });

  it('does not open a Port for an already cancelled upload', async () => {
    const controller = new AbortController();
    controller.abort();
    const connectPort = vi.fn();
    await expect(uploadBinaryTransfer(sendRequest(1), new GeneratedFile(1), { connectPort, signal: controller.signal }))
      .resolves.toMatchObject({ ok: false, error: { code: 'cancelled' } });
    expect(connectPort).not.toHaveBeenCalled();
  });

  it('rejects out-of-order acknowledgements and sends cancellation', async () => {
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type === 'begin') port.emit({ version: 1, type: 'ready' });
      if (message.type === 'chunk') port.emit({ version: 1, type: 'ack', sequence: 1 });
    };
    await expect(uploadBinaryTransfer(sendRequest(1), new GeneratedFile(1), { connectPort: () => port })).resolves.toMatchObject({ ok: false, error: { code: 'invalid_message' } });
    expect(port.sent.at(-1)?.type).toBe('cancel');
    expect(port.disconnected).toBe(true);
  });

  it('cancels a pending file read and wipes its bytes when the read later resolves', async () => {
    const port = new FakePort();
    acknowledgeUploads(port);
    const controller = new AbortController();
    let resolve!: (buffer: ArrayBuffer) => void;
    const slice = vi.fn(() => ({ arrayBuffer: () => new Promise<ArrayBuffer>((done) => { resolve = done; }) }));
    const result = uploadBinaryTransfer(sendRequest(2), { size: 2, slice }, { connectPort: () => port, signal: controller.signal });
    await vi.waitFor(() => expect(slice).toHaveBeenCalledOnce());
    controller.abort();
    await expect(result).resolves.toMatchObject({ ok: false, error: { code: 'cancelled' } });
    const bytes = new Uint8Array([7, 9]);
    resolve(bytes.buffer);
    await vi.waitFor(() => expect([...bytes]).toEqual([0, 0]));
    expect(port.sent.map((message) => message.type)).toEqual(['begin', 'cancel']);
  });

  it('terminates the operation when an acknowledgement times out', async () => {
    vi.useFakeTimers();
    const port = new FakePort();
    port.onPost = (message) => { if (message.type === 'begin') port.emit({ version: 1, type: 'ready' }); };
    const result = uploadBinaryTransfer(sendRequest(1), new GeneratedFile(1), { connectPort: () => port, messageTimeoutMs: 20 });
    await vi.advanceTimersByTimeAsync(20);
    await expect(result).resolves.toMatchObject({ ok: false, error: { code: 'timeout' } });
    expect(port.disconnected).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('allows worker processing to take 40 seconds after an upload is sealed', async () => {
    vi.useFakeTimers();
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type === 'begin') port.emit({ version: 1, type: 'ready' });
      if (message.type === 'seal') {
        setTimeout(() => port.emit({ version: 1, type: 'result', data: { saved: true } }), 40_000);
      }
    };
    const result = uploadBinaryTransfer(sendRequest(0), new GeneratedFile(0), { connectPort: () => port });
    let settled = false;
    void result.then(() => { settled = true; });

    await vi.advanceTimersByTimeAsync(30_000);
    expect(settled).toBe(false);
    expect(port.disconnected).toBe(false);
    await vi.advanceTimersByTimeAsync(10_000);

    await expect(result).resolves.toEqual({ ok: true, data: { saved: true } });
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(['upload', 'download'] as const)('bounds worker %s execution by the overall operation deadline', async (kind) => {
    vi.useFakeTimers();
    const port = new FakePort();
    port.onPost = (message) => {
      if (kind === 'upload' && message.type === 'begin') port.emit({ version: 1, type: 'ready' });
    };
    const result = kind === 'upload'
      ? uploadBinaryTransfer(sendRequest(0), new GeneratedFile(0), { connectPort: () => port })
      : downloadBinaryTransfer(downloadRequest, { connectPort: () => port });
    let settled = false;
    void result.then(() => { settled = true; });

    await vi.advanceTimersByTimeAsync(30_000);
    expect(settled).toBe(false);
    expect(port.disconnected).toBe(false);
    await vi.advanceTimersByTimeAsync(BINARY_TRANSFER_TTL_MS - 30_000);

    await expect(result).resolves.toMatchObject({ ok: false, error: { code: 'timeout' } });
    expect(port.sent.at(-1)?.type).toBe('cancel');
    expect(port.disconnected).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('returns worker failures without changing the error code', async () => {
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type === 'begin') port.emit({ version: 1, type: 'error', error: { code: 'committed_unsynced', message: 'Saved; synchronization is required.' } });
    };
    await expect(uploadBinaryTransfer(sendRequest(0), new GeneratedFile(0), { connectPort: () => port })).resolves.toMatchObject({ ok: false, error: { code: 'committed_unsynced' } });
  });
});

describe('binary attachment download client', () => {
  it('allows 40 seconds of worker processing before the first download metadata', async () => {
    vi.useFakeTimers();
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type === 'begin') {
        setTimeout(() => {
          port.emit({ version: 1, type: 'download', fileName: 'file.bin', totalBytes: 1 });
          port.emit({ version: 1, type: 'chunk', sequence: 0, byteLength: 1, dataBase64: 'YQ==' });
        }, 40_000);
      }
      if (message.type === 'ack') port.emit({ version: 1, type: 'done', chunkCount: 1, totalBytes: 1 });
    };
    const result = downloadBinaryTransfer(downloadRequest, { connectPort: () => port });
    let settled = false;
    void result.then(() => { settled = true; });

    await vi.advanceTimersByTimeAsync(30_000);
    expect(settled).toBe(false);
    expect(port.disconnected).toBe(false);
    await vi.advanceTimersByTimeAsync(10_000);

    const response = await result;
    expect(response.ok && response.data.blob.size).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([0, 1])('applies the message idle deadline after delayed metadata for %i bytes arrives', async (totalBytes) => {
    vi.useFakeTimers();
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type === 'begin') {
        setTimeout(() => port.emit({ version: 1, type: 'download', fileName: 'file.bin', totalBytes }), 40_000);
      }
    };
    const result = downloadBinaryTransfer(downloadRequest, { connectPort: () => port });
    let settled = false;
    void result.then(() => { settled = true; });

    await vi.advanceTimersByTimeAsync(40_000);
    expect(settled).toBe(false);
    expect(port.disconnected).toBe(false);
    await vi.advanceTimersByTimeAsync(30_000);

    await expect(result).resolves.toMatchObject({ ok: false, error: { code: 'timeout' } });
    expect(port.sent.at(-1)?.type).toBe('cancel');
    expect(vi.getTimerCount()).toBe(0);
  });

  it('assembles an attachment larger than 64 MiB from acknowledged Blob chunks', async () => {
    const port = new FakePort();
    const totalBytes = 65 * 1024 * 1024 + 7;
    const fullChunk = encodeBinaryTransferChunk(new Uint8Array(MAX_BINARY_TRANSFER_CHUNK_BYTES).fill(97));
    let sequence = 0;
    let sentBytes = 0;
    const sendChunk = () => {
      if (sentBytes === totalBytes) {
        port.emit({ version: 1, type: 'done', chunkCount: sequence, totalBytes });
        return;
      }
      const byteLength = Math.min(MAX_BINARY_TRANSFER_CHUNK_BYTES, totalBytes - sentBytes);
      port.emit({
        version: 1,
        type: 'chunk',
        sequence,
        byteLength,
        dataBase64: byteLength === MAX_BINARY_TRANSFER_CHUNK_BYTES ? fullChunk : encodeBinaryTransferChunk(new Uint8Array(byteLength).fill(97)),
      });
      sentBytes += byteLength;
      sequence += 1;
    };
    port.onPost = (message) => {
      if (message.type === 'begin') {
        port.emit({ version: 1, type: 'download', fileName: 'large.bin', totalBytes });
        sendChunk();
      } else if (message.type === 'ack') {
        expect(message.sequence).toBe(sequence - 1);
        sendChunk();
      }
    };

    const result = await downloadBinaryTransfer(downloadRequest, { connectPort: () => port });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.fileName).toBe('large.bin');
    expect(result.data.blob.size).toBe(totalBytes);
    expect([...new Uint8Array(await result.data.blob.slice(-7).arrayBuffer())]).toEqual(Array(7).fill(97));
    expect(port.sent.filter((message) => message.type === 'ack')).toHaveLength(Math.ceil(totalBytes / MAX_BINARY_TRANSFER_CHUNK_BYTES));
    expect(port.maxMessageLength).toBeLessThan(1_000);
    expect(port.disconnected).toBe(true);
  }, 30_000);

  it('accepts a terminal download message followed by immediate worker disconnection', async () => {
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type !== 'begin') return;
      port.emit({ version: 1, type: 'download', fileName: 'empty.bin', totalBytes: 0 });
      port.emit({ version: 1, type: 'done', chunkCount: 0, totalBytes: 0 });
      port.onDisconnect.emit();
    };
    const result = await downloadBinaryTransfer(downloadRequest, { connectPort: () => port });
    expect(result.ok && result.data.blob.size).toBe(0);
  });

  it('still rejects an invalid completion after a terminal message and worker disconnection', async () => {
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type !== 'begin') return;
      port.emit({ version: 1, type: 'download', fileName: 'empty.bin', totalBytes: 0 });
      port.emit({ version: 1, type: 'done', chunkCount: 1, totalBytes: 0 });
      port.onDisconnect.emit();
    };
    await expect(downloadBinaryTransfer(downloadRequest, { connectPort: () => port }))
      .resolves.toMatchObject({ ok: false, error: { code: 'invalid_message' } });
  });

  it('honors local cancellation after the worker posts a terminal message', async () => {
    const port = new FakePort();
    const controller = new AbortController();
    port.onPost = (message) => {
      if (message.type !== 'begin') return;
      port.emit({ version: 1, type: 'download', fileName: 'empty.bin', totalBytes: 0 });
      port.emit({ version: 1, type: 'done', chunkCount: 0, totalBytes: 0 });
      port.onDisconnect.emit();
      controller.abort();
    };
    await expect(downloadBinaryTransfer(downloadRequest, { connectPort: () => port, signal: controller.signal }))
      .resolves.toMatchObject({ ok: false, error: { code: 'cancelled' } });
  });

  it.each([
    { version: 1, type: 'download', fileName: 'too-big.bin', totalBytes: MAX_BINARY_TRANSFER_BYTES + 1 },
    { version: 1, type: 'download', fileName: 'negative.bin', totalBytes: -1 },
    { version: 2, type: 'download', fileName: 'future.bin', totalBytes: 0 },
  ])('rejects invalid metadata before acknowledging bytes', async (message) => {
    const port = new FakePort();
    port.onPost = (sent) => { if (sent.type === 'begin') port.emit(message); };
    await expect(downloadBinaryTransfer(downloadRequest, { connectPort: () => port })).resolves.toMatchObject({ ok: false, error: { code: 'invalid_message' } });
    expect(port.sent.map((sent) => sent.type)).toEqual(['begin', 'cancel']);
  });

  it.each([
    { version: 1, type: 'chunk', sequence: 1, byteLength: 1, dataBase64: 'YQ==' },
    { version: 1, type: 'chunk', sequence: 0, byteLength: 2, dataBase64: 'YQ==' },
    { version: 1, type: 'done', chunkCount: 0, totalBytes: 0 },
  ])('rejects a malformed or premature download message', async (message) => {
    const port = new FakePort();
    port.onPost = (sent) => {
      if (sent.type !== 'begin') return;
      port.emit({ version: 1, type: 'download', fileName: 'file.bin', totalBytes: 1 });
      port.emit(message);
    };
    await expect(downloadBinaryTransfer(downloadRequest, { connectPort: () => port })).resolves.toMatchObject({ ok: false });
    expect(port.sent.some((message) => message.type === 'ack')).toBe(false);
  });

  it('cancels after receiving a chunk without returning a partial artifact', async () => {
    const port = new FakePort();
    const controller = new AbortController();
    port.onPost = (message) => {
      if (message.type === 'begin') {
        port.emit({ version: 1, type: 'download', fileName: 'file.bin', totalBytes: 2 });
        port.emit({ version: 1, type: 'chunk', sequence: 0, byteLength: 1, dataBase64: 'YQ==' });
      }
      if (message.type === 'ack') controller.abort();
    };
    await expect(downloadBinaryTransfer(downloadRequest, { connectPort: () => port, signal: controller.signal })).resolves.toMatchObject({ ok: false, error: { code: 'cancelled' } });
    expect(port.disconnected).toBe(true);
  });

  it('fails when the worker disconnects during a transfer', async () => {
    const port = new FakePort();
    port.onPost = (message) => { if (message.type === 'begin') port.onDisconnect.emit(); };
    await expect(downloadBinaryTransfer(downloadRequest, { connectPort: () => port })).resolves.toMatchObject({ ok: false, error: { code: 'disconnected' } });
    expect(port.onDisconnect.listeners.size).toBe(0);
  });
});
