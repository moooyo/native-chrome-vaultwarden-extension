import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  VAULT_TRANSFER_PORT_ERROR_MESSAGES,
  VAULT_TRANSFER_PORT_NAME,
  encodeVaultTransferPortChunk,
  type VaultTransferClientMessage,
  type VaultTransferExportReview,
  type VaultTransferPortPreviewModel,
} from '../../messaging/vault-transfer-port.js';
import {
  VAULT_TRANSFER_CLIENT_SLICE_BYTES,
  VaultTransferClient,
  VaultTransferClientError,
  type VaultTransferClientDependencies,
  type VaultTransferClientEvent,
  type VaultTransferClientPort,
  type VaultTransferFile,
  type VaultTransferReadableSlice,
} from './vault-transfer-client.js';

const TRANSFER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const TRANSFER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const PREVIEW_REVISION = '22222222-2222-4222-8222-222222222222';
const EXPORT_AUTHORIZATION_ID = '33333333-3333-4333-8333-333333333333';
const CLIENT_EVENT_ACK_ID = '44444444-4444-4444-8444-444444444444';
const ORGANIZATION_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const CSV_REVIEW: VaultTransferExportReview = {
  exportedItemCount: 1,
  omittedItemCount: 1,
  warnings: [{ code: 'ssh_key_items_omitted', count: 1 }],
};

const PREVIEW: VaultTransferPortPreviewModel = {
  format: 'json',
  scope: 'personal',
  phase: 'previewed',
  counts: { folders: 1, collections: 0, items: 2, attachments: 0 },
  diagnostics: { errors: [], warnings: [], unsupported: [] },
  organizationTargetRequired: false,
  hasUnknownOutcome: false,
  canCommit: true,
};

class FakeEvent<Listener extends (...args: never[]) => void>
implements VaultTransferClientEvent<Listener> {
  readonly listeners = new Set<Listener>();

  constructor(private readonly keepRemoved = false) {}

  addListener(listener: Listener): void {
    this.listeners.add(listener);
  }

  removeListener(listener: Listener): void {
    if (!this.keepRemoved) this.listeners.delete(listener);
  }

  emit(...args: Parameters<Listener>): void {
    for (const listener of [...this.listeners]) listener(...args);
  }
}

class FakePort implements VaultTransferClientPort {
  readonly onMessage = new FakeEvent<(message: unknown) => void>();
  readonly onDisconnect = new FakeEvent<() => void>();
  readonly sent: VaultTransferClientMessage[] = [];
  disconnected = false;
  throwOnType: VaultTransferClientMessage['type'] | undefined;
  onPost: ((message: VaultTransferClientMessage) => void) | undefined;

  constructor(keepRemovedListeners = false) {
    if (keepRemovedListeners) {
      Object.defineProperty(this, 'onMessage', {
        value: new FakeEvent<(message: unknown) => void>(true),
      });
      Object.defineProperty(this, 'onDisconnect', {
        value: new FakeEvent<() => void>(true),
      });
    }
  }

  postMessage(message: VaultTransferClientMessage): void {
    if (message.type === this.throwOnType) throw new Error('Raw port failure');
    const clone = JSON.parse(JSON.stringify(message)) as VaultTransferClientMessage;
    this.sent.push(clone);
    this.onPost?.(clone);
  }

  disconnect(): void {
    this.disconnected = true;
  }

  emit(message: unknown): void {
    this.onMessage.emit(JSON.parse(JSON.stringify(message)) as unknown);
  }

  drop(): void {
    this.onDisconnect.emit();
  }
}

interface FakeSlice extends VaultTransferReadableSlice {
  readonly start: number;
  readonly end: number;
}

class FakeFile implements VaultTransferFile {
  readonly ranges: Array<readonly [number, number]> = [];

  constructor(readonly name: string, readonly bytes: Uint8Array) {}

  get size(): number {
    return this.bytes.byteLength;
  }

  slice(start: number, end: number): FakeSlice {
    this.ranges.push([start, end]);
    return {
      start,
      end,
      arrayBuffer: async () => copyBytes(this.bytes.subarray(start, end)),
    };
  }
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('VaultTransferClient import', () => {
  it('uploads strict 64 KiB slices one ACK at a time and confirms the retained preview', async () => {
    const port = new FakePort();
    const source = new Uint8Array((VAULT_TRANSFER_CLIENT_SLICE_BYTES * 4) + 17)
      .map((_, index) => index % 251);
    const file = new FakeFile('vault.json', source);
    const readBuffers: ArrayBuffer[] = [];
    let uploaded = 0;
    port.onPost = (message) => {
      if (message.type === 'import.begin') {
        port.emit(importBegun(TRANSFER_A, 256 * 1024));
      } else if (message.type === 'import.chunk') {
        uploaded += message.byteLength;
        port.emit({
          version: 1,
          type: 'import.ack',
          transferId: TRANSFER_A,
          phase: 'uploading',
          sequence: message.sequence,
          nextSequence: message.sequence + 1,
          byteLength: message.byteLength,
          totalBytes: uploaded,
        });
      } else if (message.type === 'import.seal') {
        port.emit(importPreview(TRANSFER_A));
      } else if (message.type === 'import.confirm') {
        port.emit({
          version: 1,
          type: 'import.result',
          transferId: TRANSFER_A,
          phase: 'completed',
          status: 'completed',
          counts: { committed: 2, rejected: 0, skipped: 0, outcomeUnknown: 0 },
          mustSyncBeforeRetry: false,
        });
      } else if (message.type === 'import.result.ack') {
        port.drop();
      }
    };
    const client = createClient([port], async (slice) => {
      const buffer = await slice.arrayBuffer();
      readBuffers.push(buffer);
      return buffer;
    });

    await expect(client.import(file)).resolves.toEqual(PREVIEW);
    expect(file.ranges).toEqual([
      [0, 65_536],
      [65_536, 131_072],
      [131_072, 196_608],
      [196_608, 262_144],
      [262_144, 262_161],
    ]);
    expect(port.sent.map((message) => message.type)).toEqual([
      'import.begin', 'import.chunk', 'import.chunk', 'import.seal',
    ]);
    expect(readBuffers.every((buffer) => new Uint8Array(buffer).every((byte) => byte === 0)))
      .toBe(true);

    await expect(client.confirm()).resolves.toMatchObject({
      type: 'import.result',
      status: 'completed',
    });
    expect(port.sent.slice(-2)).toEqual([
      {
        version: 1,
        type: 'import.confirm',
        transferId: TRANSFER_A,
        previewRevision: PREVIEW_REVISION,
      },
      { version: 1, type: 'import.result.ack', transferId: TRANSFER_A },
    ]);
    expect(port.disconnected).toBe(true);
  });

  it('does not acknowledge a malformed import result', async () => {
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type === 'import.begin') port.emit(importBegun(TRANSFER_A));
      if (message.type === 'import.seal') port.emit(importPreview(TRANSFER_A));
      if (message.type === 'import.confirm') {
        port.emit({
          version: 1,
          type: 'import.result',
          transferId: TRANSFER_A,
          phase: 'completed',
          status: 'completed',
          counts: { committed: 1, rejected: 1, skipped: 0, outcomeUnknown: 0 },
          mustSyncBeforeRetry: false,
        });
      }
    };
    const client = createClient([port]);
    await client.import(new FakeFile('vault.json', new Uint8Array(0)));

    await expectClientError(client.confirm(), 'invalid_message');

    expect(port.sent.some((message) => message.type === 'import.result.ack')).toBe(false);
    expect(port.disconnected).toBe(true);
  });

  it('returns an accepted result even when posting its delivery ACK throws', async () => {
    const port = new FakePort();
    port.throwOnType = 'import.result.ack';
    port.onPost = (message) => {
      if (message.type === 'import.begin') port.emit(importBegun(TRANSFER_A));
      if (message.type === 'import.seal') port.emit(importPreview(TRANSFER_A));
      if (message.type === 'import.confirm') port.emit(importResult(TRANSFER_A, 'completed'));
    };
    const client = createClient([port]);
    await client.import(new FakeFile('vault.json', new Uint8Array(0)));

    await expect(client.confirm()).resolves.toMatchObject({
      type: 'import.result',
      status: 'completed',
    });

    expect(port.sent.some((message) => message.type === 'import.result.ack')).toBe(false);
    expect(port.disconnected).toBe(true);
  });

  it('waits for the handler disconnect after ACK and bounds a missing close', async () => {
    vi.useFakeTimers();
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type === 'import.begin') port.emit(importBegun(TRANSFER_A));
      if (message.type === 'import.seal') port.emit(importPreview(TRANSFER_A));
      if (message.type === 'import.confirm') port.emit(importResult(TRANSFER_A, 'completed'));
    };
    const client = createClient([port], undefined, undefined, {
      messageTimeoutMs: 25,
      overallTtlMs: 100,
    });
    await client.import(new FakeFile('vault.json', new Uint8Array(0)));
    const result = client.confirm();

    await expectClientError(client.export('json', EXPORT_AUTHORIZATION_ID), 'busy');
    expect(port.sent.at(-1)).toEqual({
      version: 1,
      type: 'import.result.ack',
      transferId: TRANSFER_A,
    });
    expect(port.disconnected).toBe(false);

    await vi.advanceTimersByTimeAsync(26);

    await expect(result).resolves.toMatchObject({ status: 'completed' });
    expect(port.disconnected).toBe(true);
  });

  it('acknowledges a known partial result but never acknowledges outcome_unknown', async () => {
    const partialPort = new FakePort();
    const unknownPort = new FakePort();
    partialPort.onPost = (message) => {
      if (message.type === 'import.begin') partialPort.emit(importBegun(TRANSFER_A));
      if (message.type === 'import.seal') partialPort.emit(importPreview(TRANSFER_A));
      if (message.type === 'import.confirm') {
        partialPort.emit(importResult(TRANSFER_A, 'partial'));
      }
      if (message.type === 'import.result.ack') partialPort.drop();
    };
    unknownPort.onPost = (message) => {
      if (message.type === 'import.begin') unknownPort.emit(importBegun(TRANSFER_B));
      if (message.type === 'import.seal') unknownPort.emit(importPreview(TRANSFER_B));
      if (message.type === 'import.confirm') {
        unknownPort.emit(importResult(TRANSFER_B, 'outcome_unknown'));
      }
    };
    const client = createClient([partialPort, unknownPort]);
    const file = new FakeFile('vault.json', new Uint8Array(0));

    await client.import(file);
    await expect(client.confirm()).resolves.toMatchObject({ status: 'partial' });
    expect(partialPort.sent.at(-1)).toEqual({
      version: 1,
      type: 'import.result.ack',
      transferId: TRANSFER_A,
    });

    await client.import(file);
    await expect(client.confirm()).resolves.toMatchObject({ status: 'outcome_unknown' });
    expect(unknownPort.sent.some((message) => message.type === 'import.result.ack')).toBe(false);
    expect(unknownPort.disconnected).toBe(true);
  });

  it('honors a smaller worker chunk cap and rejects a mismatched acknowledgement before reading more', async () => {
    const port = new FakePort();
    const file = new FakeFile('vault.json', new Uint8Array(12).fill(7));
    port.onPost = (message) => {
      if (message.type === 'import.begin') port.emit(importBegun(TRANSFER_A, 4));
      if (message.type === 'import.chunk') {
        port.emit({
          version: 1,
          type: 'import.ack',
          transferId: TRANSFER_A,
          phase: 'uploading',
          sequence: message.sequence + 1,
          nextSequence: message.sequence + 2,
          byteLength: message.byteLength,
          totalBytes: message.byteLength,
        });
      }
    };
    const client = createClient([port]);

    await expectClientError(client.import(file), 'invalid_sequence');
    expect(file.ranges).toEqual([[0, 4]]);
    expect(port.sent.filter((message) => message.type === 'import.chunk')).toHaveLength(1);
    expect(port.disconnected).toBe(true);
  });

  it('does not read or post the next import chunk until the exact ACK arrives', async () => {
    const port = new FakePort();
    const file = new FakeFile(
      'vault.json',
      new Uint8Array(VAULT_TRANSFER_CLIENT_SLICE_BYTES + 1).fill(3),
    );
    port.onPost = (message) => {
      if (message.type === 'import.begin') {
        port.emit(importBegun(TRANSFER_A, VAULT_TRANSFER_CLIENT_SLICE_BYTES));
      }
      if (message.type === 'import.seal') port.emit(importPreview(TRANSFER_A));
    };
    const client = createClient([port]);
    const pending = client.import(file);
    await waitUntil(() => port.sent.some((message) => message.type === 'import.chunk'));

    expect(file.ranges).toEqual([[0, VAULT_TRANSFER_CLIENT_SLICE_BYTES]]);
    expect(port.sent.filter((message) => message.type === 'import.chunk')).toHaveLength(1);
    port.emit({
      version: 1,
      type: 'import.ack',
      transferId: TRANSFER_A,
      phase: 'uploading',
      sequence: 0,
      nextSequence: 1,
      byteLength: VAULT_TRANSFER_CLIENT_SLICE_BYTES,
      totalBytes: VAULT_TRANSFER_CLIENT_SLICE_BYTES,
    });
    await waitUntil(() => port.sent.filter((message) => message.type === 'import.chunk').length === 2);

    expect(file.ranges).toEqual([
      [0, VAULT_TRANSFER_CLIENT_SLICE_BYTES],
      [VAULT_TRANSFER_CLIENT_SLICE_BYTES, VAULT_TRANSFER_CLIENT_SLICE_BYTES + 1],
    ]);
    port.emit({
      version: 1,
      type: 'import.ack',
      transferId: TRANSFER_A,
      phase: 'uploading',
      sequence: 1,
      nextSequence: 2,
      byteLength: 1,
      totalBytes: VAULT_TRANSFER_CLIENT_SLICE_BYTES + 1,
    });
    await expect(pending).resolves.toEqual(PREVIEW);
    client.cancel();
  });

  it('uses worker-sized wire chunks so the default 64 MiB limit stays below 512 chunks', async () => {
    const port = new FakePort();
    const source = new Uint8Array(VAULT_TRANSFER_CLIENT_SLICE_BYTES * 16).fill(5);
    const file = new FakeFile('vault.json', source);
    let uploaded = 0;
    port.onPost = (message) => {
      if (message.type === 'import.begin') port.emit(importBegun(TRANSFER_A, 256 * 1024));
      if (message.type === 'import.chunk') {
        uploaded += message.byteLength;
        port.emit({
          version: 1,
          type: 'import.ack',
          transferId: TRANSFER_A,
          phase: 'uploading',
          sequence: message.sequence,
          nextSequence: message.sequence + 1,
          byteLength: message.byteLength,
          totalBytes: uploaded,
        });
      }
      if (message.type === 'import.seal') port.emit(importPreview(TRANSFER_A));
    };
    const client = createClient([port]);

    await client.import(file);

    expect(file.ranges).toHaveLength(16);
    expect(port.sent.filter((message) => message.type === 'import.chunk')).toHaveLength(4);
    expect(Math.ceil((64 * 1024 * 1024) / (256 * 1024))).toBeLessThanOrEqual(512);
    client.cancel();
  });

  it('returns password_required without echoing the password and permits retrying the same File', async () => {
    const first = new FakePort();
    const second = new FakePort();
    const file = new FakeFile('encrypted.json', new Uint8Array(0));
    first.onPost = (message) => {
      if (message.type === 'import.begin') first.emit(importBegun(TRANSFER_A));
      if (message.type === 'import.seal') {
        first.emit(workerError('password_required', TRANSFER_A, 'inspecting'));
      }
    };
    second.onPost = (message) => {
      if (message.type === 'import.begin') second.emit(importBegun(TRANSFER_B));
      if (message.type === 'import.seal') second.emit(importPreview(TRANSFER_B));
    };
    const client = createClient([first, second]);

    const firstError = await captureError(client.import(file));
    expect(firstError).toMatchObject({ code: 'password_required' });
    expect(JSON.stringify(firstError)).not.toContain('correct horse');
    await expect(client.import(file, 'correct horse')).resolves.toEqual(PREVIEW);
    expect(second.sent.find((message) => message.type === 'import.seal')).toMatchObject({
      type: 'import.seal',
      password: 'correct horse',
    });
    const active = (client as unknown as { active?: Record<string, unknown> }).active;
    expect(active).toBeDefined();
    expect(active).not.toHaveProperty('password');
    client.cancel();
  });

  it('sends cancel after a transfer is begun and rejects a pending file read', async () => {
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type === 'import.begin') port.emit(importBegun(TRANSFER_A));
    };
    const never = new Promise<ArrayBuffer>(() => undefined);
    const client = createClient([port], () => never);
    const pending = client.import(new FakeFile('vault.json', new Uint8Array([1])));
    await flushMicrotasks();

    client.cancel();

    await expectClientError(pending, 'cancelled');
    expect(port.sent.at(-1)).toEqual({ version: 1, type: 'cancel', transferId: TRANSFER_A });
    expect(port.disconnected).toBe(true);
  });
});

describe('VaultTransferClient export', () => {
  it('confirms a bounded CSV review before download and ACKs only after download succeeds', async () => {
    const port = new FakePort();
    const order: string[] = [];
    const confirmExportReview = vi.fn(async (review: VaultTransferExportReview) => {
      order.push('review');
      expect(review).toEqual(CSV_REVIEW);
      return true;
    });
    const download = vi.fn(async () => { order.push('download'); });
    const ackClientEvent = vi.fn(async () => { order.push('ack'); });
    const bytes = new TextEncoder().encode('folder,name\r\nWork,Example');
    port.onPost = (message) => {
      if (message.type === 'export.begin') {
        port.emit(exportBegun(TRANSFER_A, 'csv', 'vault.csv', CSV_REVIEW));
        queueMicrotask(() => port.emit(exportChunk(TRANSFER_A, 'csv', 0, bytes)));
      } else if (message.type === 'export.ack') {
        port.emit(exportDone(TRANSFER_A, 'csv', 1, bytes.byteLength, CLIENT_EVENT_ACK_ID));
      }
    };
    const client = createClient(
      [port], undefined, download, undefined, ackClientEvent, confirmExportReview,
    );

    const artifact = await client.export('csv', EXPORT_AUTHORIZATION_ID);

    expect(artifact.blob.type).toBe('text/csv;charset=utf-8');
    expect(artifact.fileName).toBe('vault.csv');
    expect(artifact.review).toEqual(CSV_REVIEW);
    expect(port.sent[0]).toEqual({
      version: 1, type: 'export.begin', format: 'csv',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'personal' },
    });
    expect(order).toEqual(['review', 'download', 'ack']);
  });

  it('cancels a lossy CSV when review is declined without downloading or ACKing the event', async () => {
    const port = new FakePort();
    const download = vi.fn(async () => undefined);
    const ackClientEvent = vi.fn(async () => undefined);
    const confirmExportReview = vi.fn(async () => false);
    port.onPost = (message) => {
      if (message.type === 'export.begin') {
        port.emit(exportBegun(TRANSFER_A, 'csv', 'vault.csv', CSV_REVIEW));
      }
    };
    const client = createClient(
      [port], undefined, download, undefined, ackClientEvent, confirmExportReview,
    );

    await expectClientError(client.export('csv', EXPORT_AUTHORIZATION_ID), 'cancelled');

    expect(confirmExportReview).toHaveBeenCalledOnce();
    expect(download).not.toHaveBeenCalled();
    expect(ackClientEvent).not.toHaveBeenCalled();
    expect(port.disconnected).toBe(true);
  });

  it('fails closed when a lossy CSV has no explicit review dependency', async () => {
    const port = new FakePort();
    const download = vi.fn(async () => undefined);
    port.onPost = (message) => {
      if (message.type === 'export.begin') {
        port.emit(exportBegun(TRANSFER_A, 'csv', 'vault.csv', CSV_REVIEW));
      }
    };
    const client = createClient([port], undefined, download);

    await expectClientError(client.export('csv', EXPORT_AUTHORIZATION_ID), 'review_required');
    expect(download).not.toHaveBeenCalled();
  });

  it('owns each Blob part, zeroes decoded arrays, ACKs exact sequences, and downloads once', async () => {
    const port = new FakePort();
    const order: string[] = [];
    const download = vi.fn(async () => {
      order.push('download:start');
      await Promise.resolve();
      order.push('download:done');
    });
    const ackClientEvent = vi.fn(async () => { order.push('event:ack'); });
    const fill = vi.spyOn(Uint8Array.prototype, 'fill');
    const chunks = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5])];
    port.onPost = (message) => {
      if (message.type === 'export.begin') {
        port.emit(exportBegun(TRANSFER_A, 'zip', 'vault.zip'));
        queueMicrotask(() => port.emit(exportChunk(TRANSFER_A, 'zip', 0, chunks[0]!)));
      } else if (message.type === 'export.ack' && message.sequence === 0) {
        port.emit(exportChunk(TRANSFER_A, 'zip', 1, chunks[1]!));
      } else if (message.type === 'export.ack' && message.sequence === 1) {
        port.emit(exportDone(TRANSFER_A, 'zip', 2, 5, CLIENT_EVENT_ACK_ID));
      }
    };
    const client = createClient([port], undefined, download, undefined, ackClientEvent);

    const artifact = await client.export('zip', EXPORT_AUTHORIZATION_ID);

    expect(new Uint8Array(await artifact.blob.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
    expect(artifact.blob.type).toBe('application/zip');
    expect(artifact.fileName).toBe('vault.zip');
    expect(download).toHaveBeenCalledOnce();
    expect(ackClientEvent).toHaveBeenCalledOnce();
    expect(ackClientEvent).toHaveBeenCalledWith(CLIENT_EVENT_ACK_ID);
    expect(order).toEqual(['download:start', 'download:done', 'event:ack']);
    expect(port.sent[0]).toEqual({
      version: 1,
      type: 'export.begin',
      format: 'zip',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'personal' },
    });
    expect(JSON.stringify(client)).not.toContain(EXPORT_AUTHORIZATION_ID);
    expect(port.sent.filter((message) => message.type === 'export.ack')).toEqual([
      { version: 1, type: 'export.ack', transferId: TRANSFER_A, sequence: 0 },
      { version: 1, type: 'export.ack', transferId: TRANSFER_A, sequence: 1 },
    ]);
    expect(port.sent.some((message) => 'dataBase64' in message)).toBe(false);
    expect(fill.mock.calls.filter(([value]) => value === 0).length).toBeGreaterThanOrEqual(4);
    expect(port.disconnected).toBe(true);
  });

  it('does not ACK when no download dependency is available', async () => {
    const port = new FakePort();
    const ackClientEvent = vi.fn(async () => undefined);
    port.onPost = (message) => {
      if (message.type === 'export.begin') {
        port.emit(exportBegun(TRANSFER_A, 'json', 'vault.json'));
        queueMicrotask(() => port.emit(exportDone(
          TRANSFER_A,
          'json',
          0,
          0,
          CLIENT_EVENT_ACK_ID,
        )));
      }
    };
    const client = createClient([port], undefined, undefined, undefined, ackClientEvent);

    await expect(client.export('json', EXPORT_AUTHORIZATION_ID)).resolves.toMatchObject({
      fileName: 'vault.json',
      format: 'json',
    });

    expect(ackClientEvent).not.toHaveBeenCalled();
  });

  it('does not ACK when the download rejects', async () => {
    const port = new FakePort();
    const download = vi.fn(async () => { throw new Error('download failed'); });
    const ackClientEvent = vi.fn(async () => undefined);
    port.onPost = (message) => {
      if (message.type === 'export.begin') {
        port.emit(exportBegun(TRANSFER_A, 'json', 'vault.json'));
        queueMicrotask(() => port.emit(exportDone(
          TRANSFER_A,
          'json',
          0,
          0,
          CLIENT_EVENT_ACK_ID,
        )));
      }
    };
    const client = createClient([port], undefined, download, undefined, ackClientEvent);

    await expectClientError(client.export('json', EXPORT_AUTHORIZATION_ID), 'export_failed');

    expect(download).toHaveBeenCalledOnce();
    expect(ackClientEvent).not.toHaveBeenCalled();
  });

  it.each(['cancel', 'disconnect'] as const)(
    'does not ACK when the export is interrupted by %s during download',
    async (interruption) => {
      const port = new FakePort();
      let resolveDownload!: () => void;
      const download = vi.fn(() => new Promise<void>((resolve) => { resolveDownload = resolve; }));
      const ackClientEvent = vi.fn(async () => undefined);
      port.onPost = (message) => {
        if (message.type === 'export.begin') {
          port.emit(exportBegun(TRANSFER_A, 'json', 'vault.json'));
          queueMicrotask(() => port.emit(exportDone(
            TRANSFER_A,
            'json',
            0,
            0,
            CLIENT_EVENT_ACK_ID,
          )));
        }
      };
      const client = createClient([port], undefined, download, undefined, ackClientEvent);
      const pending = client.export('json', EXPORT_AUTHORIZATION_ID);
      await flushMicrotasks();
      expect(download).toHaveBeenCalledOnce();

      if (interruption === 'cancel') client.cancel();
      else port.drop();

      await expectClientError(pending, interruption === 'cancel' ? 'cancelled' : 'disconnected');
      resolveDownload();
      await flushMicrotasks();
      expect(ackClientEvent).not.toHaveBeenCalled();
    },
  );

  it('does not ACK an export.done message for another format', async () => {
    const port = new FakePort();
    const download = vi.fn(async () => undefined);
    const ackClientEvent = vi.fn(async () => undefined);
    port.onPost = (message) => {
      if (message.type === 'export.begin') {
        port.emit(exportBegun(TRANSFER_A, 'json', 'vault.json'));
        queueMicrotask(() => port.emit(exportDone(
          TRANSFER_A,
          'zip',
          0,
          0,
          CLIENT_EVENT_ACK_ID,
        )));
      }
    };
    const client = createClient([port], undefined, download, undefined, ackClientEvent);

    await expectClientError(client.export('json', EXPORT_AUTHORIZATION_ID), 'size_mismatch');

    expect(download).not.toHaveBeenCalled();
    expect(ackClientEvent).not.toHaveBeenCalled();
  });

  it('ACKs only once when a duplicate export.done arrives during download', async () => {
    const port = new FakePort();
    const ackClientEvent = vi.fn(async () => undefined);
    const duplicate = exportDone(TRANSFER_A, 'json', 0, 0, CLIENT_EVENT_ACK_ID);
    const download = vi.fn(async () => { port.emit(duplicate); });
    port.onPost = (message) => {
      if (message.type === 'export.begin') {
        port.emit(exportBegun(TRANSFER_A, 'json', 'vault.json'));
        queueMicrotask(() => port.emit(duplicate));
      }
    };
    const client = createClient([port], undefined, download, undefined, ackClientEvent);

    await expect(client.export('json', EXPORT_AUTHORIZATION_ID)).resolves.toMatchObject({
      fileName: 'vault.json',
      format: 'json',
    });

    expect(download).toHaveBeenCalledOnce();
    expect(ackClientEvent).toHaveBeenCalledOnce();
    expect(ackClientEvent).toHaveBeenCalledWith(CLIENT_EVENT_ACK_ID);
  });

  it('keeps a completed export successful when the client-event ACK rejects', async () => {
    const port = new FakePort();
    const download = vi.fn(async () => undefined);
    const ackClientEvent = vi.fn(async () => { throw new Error('ACK failed'); });
    port.onPost = (message) => {
      if (message.type === 'export.begin') {
        port.emit(exportBegun(TRANSFER_A, 'json', 'vault.json'));
        queueMicrotask(() => port.emit(exportDone(
          TRANSFER_A,
          'json',
          0,
          0,
          CLIENT_EVENT_ACK_ID,
        )));
      }
    };
    const client = createClient([port], undefined, download, undefined, ackClientEvent);

    await expect(client.export('json', EXPORT_AUTHORIZATION_ID)).resolves.toMatchObject({
      fileName: 'vault.json',
      format: 'json',
    });
    await flushMicrotasks();

    expect(download).toHaveBeenCalledOnce();
    expect(ackClientEvent).toHaveBeenCalledOnce();
  });

  it('rejects a wrong sequence without acknowledging it and clears owned byte views', async () => {
    const port = new FakePort();
    const fill = vi.spyOn(Uint8Array.prototype, 'fill');
    port.onPost = (message) => {
      if (message.type === 'export.begin') {
        port.emit(exportBegun(TRANSFER_A, 'json', 'vault.json'));
        queueMicrotask(() => port.emit(exportChunk(
          TRANSFER_A,
          'json',
          1,
          new Uint8Array([9]),
        )));
      }
    };
    const client = createClient([port]);

    await expectClientError(
      client.export('json', EXPORT_AUTHORIZATION_ID),
      'invalid_sequence',
    );
    expect(port.sent.filter((message) => message.type === 'export.ack')).toHaveLength(0);
    expect(fill.mock.calls.some(([value]) => value === 0)).toBe(true);
    expect(port.disconnected).toBe(true);
  });

  it('distinguishes account-encrypted from file-password JSON without retaining passwords', async () => {
    const accountPort = new FakePort();
    const filePort = new FakePort();
    for (const port of [accountPort, filePort]) {
      port.onPost = (message) => {
        if (message.type === 'export.begin') {
          port.emit(exportBegun(TRANSFER_A, 'encrypted-json', 'vault.encrypted.json'));
          queueMicrotask(() => port.emit(exportDone(TRANSFER_A, 'encrypted-json', 0, 0)));
        }
      };
    }
    const client = createClient([accountPort, filePort]);

    await expectClientError(
      client.export('json', EXPORT_AUTHORIZATION_ID, 'not-allowed'),
      'password_not_allowed',
    );
    await expect(client.export('encrypted-json', EXPORT_AUTHORIZATION_ID)).resolves.toMatchObject({
      fileName: 'vault.encrypted.json',
      format: 'encrypted-json',
    });
    await expect(client.export(
      'encrypted-json', EXPORT_AUTHORIZATION_ID, 'export password',
    )).resolves.toMatchObject({
      fileName: 'vault.encrypted.json',
      format: 'encrypted-json',
    });
    expect(accountPort.sent[0]).toEqual({
      version: 1,
      type: 'export.begin',
      format: 'encrypted-json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'personal' },
    });
    expect(filePort.sent[0]).toEqual({
      version: 1,
      type: 'export.begin',
      format: 'encrypted-json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'personal' },
      filePassword: 'export password',
    });
    expect(JSON.stringify(client)).not.toContain('export password');
  });

  it('rejects empty passwords before opening a Port', async () => {
    const port = new FakePort();
    const client = createClient([port]);

    await expectClientError(
      client.import(new FakeFile('vault.json', new Uint8Array(0)), ''),
      'invalid_message',
    );
    await expectClientError(
      client.export('encrypted-json', EXPORT_AUTHORIZATION_ID, ''),
      'invalid_message',
    );
    await expectClientError(client.export('json', 'not-a-grant'), 'invalid_message');
    expect(port.sent).toHaveLength(0);
    expect(port.disconnected).toBe(false);
  });

  it('canonicalizes one organization target and sends it explicitly', async () => {
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type === 'export.begin') {
        port.emit(exportBegun(TRANSFER_A, 'json', 'organization.json'));
        queueMicrotask(() => port.emit(exportDone(TRANSFER_A, 'json', 0, 0)));
      }
    };
    const client = createClient([port]);

    await expect(client.export(
      'json',
      EXPORT_AUTHORIZATION_ID,
      undefined,
      { kind: 'organization', organizationId: ORGANIZATION_ID.toUpperCase() },
    )).resolves.toMatchObject({ fileName: 'organization.json' });

    expect(port.sent[0]).toEqual({
      version: 1,
      type: 'export.begin',
      format: 'json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'organization', organizationId: ORGANIZATION_ID },
    });
  });

  it('rejects invalid targets and organization ZIP before opening a Port', async () => {
    const port = new FakePort();
    const client = createClient([port]);

    await expectClientError(client.export(
      'json',
      EXPORT_AUTHORIZATION_ID,
      undefined,
      { kind: 'organization', organizationId: 'not-an-id' } as never,
    ), 'invalid_message');
    await expectClientError(client.export(
      'zip',
      EXPORT_AUTHORIZATION_ID,
      undefined,
      { kind: 'organization', organizationId: ORGANIZATION_ID },
    ), 'invalid_message');
    expect(port.sent).toHaveLength(0);
    expect(port.disconnected).toBe(false);
  });
});

describe('VaultTransferClient recovery', () => {
  const status = {
    count: 1,
    unresolvedUnknownCount: 1,
    reconcileRequiredCount: 0,
    omittedCount: 0,
    barriers: [{
      transferId: TRANSFER_A,
      reason: 'outcome_unknown' as const,
      reconciled: true,
      clearable: true,
    }],
  };

  it('uses one fresh Port for each status and explicit clear operation', async () => {
    const inspectPort = new FakePort();
    const clearPort = new FakePort();
    inspectPort.onPost = (message) => {
      if (message.type === 'recovery.inspect') {
        inspectPort.emit({ version: 1, type: 'recovery.status', phase: 'completed', status });
      }
    };
    clearPort.onPost = (message) => {
      if (message.type === 'recovery.clear') {
        clearPort.emit({ version: 1, type: 'recovery.cleared', phase: 'completed', cleared: 1 });
      }
    };
    const client = createClient([inspectPort, clearPort]);

    await expect(client.inspectRecovery()).resolves.toEqual(status);
    await expect(client.clearRecovery(status)).resolves.toEqual({
      version: 1,
      type: 'recovery.cleared',
      phase: 'completed',
      cleared: 1,
    });

    expect(inspectPort.sent).toEqual([{ version: 1, type: 'recovery.inspect' }]);
    expect(clearPort.sent).toEqual([{
      version: 1,
      type: 'recovery.clear',
      expectedBarriers: [{ transferId: TRANSFER_A, reason: 'outcome_unknown' }],
    }]);
    expect(inspectPort.disconnected).toBe(true);
    expect(clearPort.disconnected).toBe(true);
  });

  it('rejects malformed recovery status without retaining secret fields', async () => {
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type === 'recovery.inspect') {
        port.emit({
          version: 1,
          type: 'recovery.status',
          phase: 'completed',
          status: { ...status, sourceDigest: 'PRIVATE SOURCE DIGEST' },
        });
      }
    };
    const client = createClient([port]);

    const error = await captureError(client.inspectRecovery());

    expect(error).toMatchObject({ code: 'invalid_message' });
    expect(JSON.stringify(error)).not.toContain('PRIVATE SOURCE DIGEST');
    expect(JSON.stringify(client)).not.toContain('PRIVATE SOURCE DIGEST');
    expect(port.disconnected).toBe(true);
  });

  it('preserves the fixed not-clearable error from the worker', async () => {
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type === 'recovery.clear') {
        port.emit(workerError('recovery_not_clearable', null, 'inspecting'));
      }
    };
    const client = createClient([port]);

    await expectClientError(client.clearRecovery(status), 'recovery_not_clearable');
    expect(port.disconnected).toBe(true);
  });

  it('rejects a cleared count that is not bound to the requested snapshot', async () => {
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type === 'recovery.clear') {
        port.emit({ version: 1, type: 'recovery.cleared', phase: 'completed', cleared: 2 });
      }
    };
    const client = createClient([port]);

    await expectClientError(client.clearRecovery(status), 'invalid_message');
    expect(port.disconnected).toBe(true);
  });
});

describe('VaultTransferClient lifecycle', () => {
  it('maps disconnects and post failures to stable errors', async () => {
    const disconnected = new FakePort();
    disconnected.onPost = (message) => {
      if (message.type === 'import.begin') disconnected.drop();
    };
    const throwing = new FakePort();
    throwing.throwOnType = 'import.begin';
    const client = createClient([disconnected, throwing]);
    const file = new FakeFile('vault.json', new Uint8Array(0));

    await expectClientError(client.import(file), 'disconnected');
    await expectClientError(client.import(file), 'disconnected');
    expect(throwing.disconnected).toBe(true);
  });

  it('does not retain an encrypted export password when Port creation fails', async () => {
    const password = 'connect-failure-password';
    const client = new VaultTransferClient({
      connectPort() {
        throw new Error('Raw connection failure');
      },
      readSlice: (slice) => slice.arrayBuffer(),
    });

    const error = await captureError(client.export(
      'encrypted-json', EXPORT_AUTHORIZATION_ID, password,
    ));

    expect(error).toMatchObject({ code: 'disconnected' });
    expect(JSON.stringify(error)).not.toContain(password);
    expect((client as unknown as { active?: unknown }).active).toBeUndefined();
    expect(Object.values(client as unknown as Record<string, unknown>)).not.toContain(password);
  });

  it('bounds an unanswered worker message with injected timers', async () => {
    vi.useFakeTimers();
    const port = new FakePort();
    const client = createClient([port], undefined, undefined, {
      messageTimeoutMs: 25,
      overallTtlMs: 100,
    });
    const pending = client.import(new FakeFile('vault.json', new Uint8Array(0)));
    const captured = captureError(pending);

    await vi.advanceTimersByTimeAsync(26);

    const error = await captured;
    expect(error).toBeInstanceOf(VaultTransferClientError);
    expect(error).toMatchObject({ code: 'timeout' });
    expect(port.disconnected).toBe(true);
  });

  it('expires a previewed transfer at the injected overall TTL', async () => {
    vi.useFakeTimers();
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type === 'import.begin') port.emit(importBegun(TRANSFER_A));
      if (message.type === 'import.seal') port.emit(importPreview(TRANSFER_A));
    };
    const client = createClient([port], undefined, undefined, {
      messageTimeoutMs: 25,
      overallTtlMs: 100,
    });
    await client.import(new FakeFile('vault.json', new Uint8Array(0)));

    await vi.advanceTimersByTimeAsync(101);

    expect(port.disconnected).toBe(true);
    await expectClientError(client.confirm(), 'invalid_state');
  });

  it('keeps stale A messages from affecting a later B operation even with broken listener removal', async () => {
    const first = new FakePort(true);
    const second = new FakePort();
    first.onPost = (message) => {
      if (message.type === 'import.begin') first.emit(importBegun(TRANSFER_A));
      if (message.type === 'import.seal') {
        first.emit(workerError('password_required', TRANSFER_A, 'inspecting'));
      }
    };
    second.onPost = (message) => {
      if (message.type === 'import.seal') second.emit(importPreview(TRANSFER_B));
    };
    const client = createClient([first, second]);
    const file = new FakeFile('vault.json', new Uint8Array(0));
    await expectClientError(client.import(file), 'password_required');

    const pendingB = client.import(file, 'new password');
    first.emit(importPreview(TRANSFER_A));
    second.emit(importBegun(TRANSFER_B));

    await expect(pendingB).resolves.toEqual(PREVIEW);
    client.cancel();
  });

  it('allows only one active operation and makes dispose terminal', async () => {
    const port = new FakePort();
    const client = createClient([port]);
    const pending = client.import(new FakeFile('vault.json', new Uint8Array(0)));

    await expectClientError(client.export('json', EXPORT_AUTHORIZATION_ID), 'busy');
    client.dispose();
    await expectClientError(pending, 'disposed');
    await expectClientError(
      client.import(new FakeFile('vault.json', new Uint8Array(0))),
      'disposed',
    );
  });

  it('rejects malformed worker messages through the fixed protocol map', async () => {
    const port = new FakePort();
    port.onPost = (message) => {
      if (message.type === 'import.begin') {
        port.emit({ version: 1, type: 'import.begun', secret: 'raw value' });
      }
    };
    const client = createClient([port]);

    const error = await captureError(client.import(new FakeFile('vault.json', new Uint8Array(0))));
    expect(error).toEqual(expect.objectContaining({
      code: 'invalid_message',
      message: VAULT_TRANSFER_PORT_ERROR_MESSAGES.invalid_message,
    }));
    expect(JSON.stringify(error)).not.toContain('raw value');
  });
});

function createClient(
  ports: FakePort[],
  readSlice: ((slice: VaultTransferReadableSlice) => Promise<ArrayBuffer>) | undefined = undefined,
  download?: VaultTransferClientDependencies['download'],
  timeouts?: { readonly messageTimeoutMs: number; readonly overallTtlMs: number },
  ackClientEvent?: VaultTransferClientDependencies['ackClientEvent'],
  confirmExportReview?: VaultTransferClientDependencies['confirmExportReview'],
): VaultTransferClient {
  const dependencies: VaultTransferClientDependencies = {
    connectPort(name) {
      expect(name).toBe(VAULT_TRANSFER_PORT_NAME);
      const port = ports.shift();
      if (!port) throw new Error('No fake Port available');
      return port;
    },
    readSlice: readSlice ?? ((slice) => slice.arrayBuffer()),
    timers: {
      setTimeout: (callback, delayMs) => setTimeout(callback, delayMs),
      clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
    },
    ...(download ? { download } : {}),
    ...(ackClientEvent ? { ackClientEvent } : {}),
    ...(confirmExportReview ? { confirmExportReview } : {}),
    ...(timeouts ?? {}),
  };
  return new VaultTransferClient(dependencies);
}

function importBegun(transferId: string, maxChunkBytes = 256 * 1024) {
  return {
    version: 1,
    type: 'import.begun',
    transferId,
    phase: 'uploading',
    maxChunkBytes,
    maxEncodedChunkChars: Math.ceil(maxChunkBytes / 3) * 4,
  };
}

function importPreview(transferId: string) {
  return {
    version: 1,
    type: 'import.preview',
    transferId,
    previewRevision: PREVIEW_REVISION,
    preview: PREVIEW,
  };
}

function importResult(
  transferId: string,
  status: 'completed' | 'partial' | 'outcome_unknown',
) {
  if (status === 'completed') {
    return {
      version: 1,
      type: 'import.result',
      transferId,
      phase: 'completed',
      status,
      counts: { committed: 2, rejected: 0, skipped: 0, outcomeUnknown: 0 },
      mustSyncBeforeRetry: false,
    };
  }
  if (status === 'partial') {
    return {
      version: 1,
      type: 'import.result',
      transferId,
      phase: 'completed',
      status,
      counts: { committed: 1, rejected: 1, skipped: 0, outcomeUnknown: 0 },
      mustSyncBeforeRetry: true,
    };
  }
  return {
    version: 1,
    type: 'import.result',
    transferId,
    phase: 'completed',
    status,
    counts: { committed: 0, rejected: 0, skipped: 0, outcomeUnknown: 1 },
    mustSyncBeforeRetry: true,
  };
}

function exportBegun(
  transferId: string,
  format: 'json' | 'encrypted-json' | 'csv' | 'zip',
  fileName: string,
  review?: VaultTransferExportReview,
) {
  return {
    version: 1, type: 'export.begun', transferId, format, phase: 'exporting', fileName,
    ...(review ? { review } : {}),
  };
}

function exportChunk(
  transferId: string,
  format: 'json' | 'encrypted-json' | 'csv' | 'zip',
  sequence: number,
  bytes: Uint8Array,
) {
  return {
    version: 1,
    type: 'export.chunk',
    transferId,
    format,
    phase: 'exporting',
    sequence,
    byteLength: bytes.byteLength,
    dataBase64: encodeVaultTransferPortChunk(bytes),
  };
}

function exportDone(
  transferId: string,
  format: 'json' | 'encrypted-json' | 'csv' | 'zip',
  chunkCount: number,
  totalBytes: number,
  clientEventAckId?: string,
) {
  return {
    version: 1,
    type: 'export.done',
    transferId,
    format,
    phase: 'completed',
    chunkCount,
    totalBytes,
    ...(clientEventAckId === undefined ? {} : { clientEventAckId }),
  };
}

function workerError(
  code: keyof typeof VAULT_TRANSFER_PORT_ERROR_MESSAGES,
  transferId: string | null,
  phase: string,
) {
  return {
    version: 1,
    type: 'error',
    transferId,
    phase,
    error: { code, message: VAULT_TRANSFER_PORT_ERROR_MESSAGES[code] },
  };
}

function copyBytes(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function expectClientError(promise: Promise<unknown>, code: string): Promise<void> {
  const error = await captureError(promise);
  expect(error).toBeInstanceOf(VaultTransferClientError);
  expect(error).toMatchObject({ code });
}

async function captureError(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('Expected operation to reject');
}

async function flushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

async function waitUntil(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (predicate()) return;
    await flushMicrotasks();
  }
  throw new Error('Condition was not reached');
}
