import { describe, expect, it, vi } from 'vitest';
import type { VaultTransferPreview } from '../core/vault/vault-transfer-preview.js';
import {
  VAULT_TRANSFER_PORT_NAME,
  VAULT_TRANSFER_PORT_VERSION,
  encodeVaultTransferPortChunk,
  parseVaultTransferWorkerMessage,
  type VaultTransferExportReview,
  type VaultTransferWorkerMessage,
} from '../messaging/vault-transfer-port.js';
import { VaultTransferControllerError } from './vault-transfer-controller.js';
import {
  VaultTransferPortHandler,
  type VaultTransferPortEvent,
  type VaultTransferPortLike,
} from './vault-transfer-port-handler.js';

const EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop';
const EXTENSION_BASE_URL = `chrome-extension://${EXTENSION_ID}/`;
const OPTIONS_URL = `${EXTENSION_BASE_URL}ui/options/options.html`;
const IMPORT_ID = '00000000-0000-4000-8000-000000000001';
const SECOND_IMPORT_ID = '00000000-0000-4000-8000-000000000002';
const EXPORT_ID = '00000000-0000-4000-8000-000000000003';
const PREVIEW_REVISION = '00000000-0000-4000-8000-000000000004';
const EXPORT_AUTHORIZATION_ID = '00000000-0000-4000-8000-000000000005';
const CLIENT_EVENT_ACK_ID = '00000000-0000-4000-8000-000000000006';
const ORGANIZATION_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

type PortController = ConstructorParameters<typeof VaultTransferPortHandler>[0];
type MessageListener = (message: unknown) => void;
type DisconnectListener = () => void;

class MessageEvent implements VaultTransferPortEvent<MessageListener> {
  readonly listeners = new Set<MessageListener>();

  addListener(listener: MessageListener): void {
    this.listeners.add(listener);
  }

  removeListener(listener: MessageListener): void {
    this.listeners.delete(listener);
  }

  emit(message: unknown): void {
    for (const listener of [...this.listeners]) listener(message);
  }
}

class DisconnectEvent implements VaultTransferPortEvent<DisconnectListener> {
  readonly listeners = new Set<DisconnectListener>();

  addListener(listener: DisconnectListener): void {
    this.listeners.add(listener);
  }

  removeListener(listener: DisconnectListener): void {
    this.listeners.delete(listener);
  }

  emit(): void {
    for (const listener of [...this.listeners]) listener();
  }
}

class TestPort implements VaultTransferPortLike {
  readonly onMessage = new MessageEvent();
  readonly onDisconnect = new DisconnectEvent();
  readonly sent: VaultTransferWorkerMessage[] = [];
  readonly name: string;
  readonly sender?: { readonly id?: string; readonly url?: string; readonly documentId?: string };
  disconnectCount = 0;
  throwOnType: VaultTransferWorkerMessage['type'] | undefined;
  postHook: ((message: VaultTransferWorkerMessage) => void) | undefined;

  constructor(options: {
    readonly name?: string;
    readonly sender?: { readonly id?: string; readonly url?: string; readonly documentId?: string };
  } = {}) {
    this.name = options.name ?? VAULT_TRANSFER_PORT_NAME;
    if (options.sender !== undefined) this.sender = options.sender;
  }

  postMessage(message: VaultTransferWorkerMessage): void {
    parseVaultTransferWorkerMessage(message);
    this.postHook?.(message);
    if (message.type === this.throwOnType) throw new Error('PRIVATE POST FAILURE');
    this.sent.push(structuredClone(message));
  }

  disconnect(): void {
    this.disconnectCount += 1;
    this.onDisconnect.emit();
  }

  receive(message: unknown): void {
    this.onMessage.emit(message);
  }
}

interface ControllerHarness {
  readonly controller: PortController;
  readonly beginImport: ReturnType<typeof vi.fn>;
  readonly appendImportChunk: ReturnType<typeof vi.fn>;
  readonly acknowledgeImportChunk: ReturnType<typeof vi.fn>;
  readonly sealAndInspectImport: ReturnType<typeof vi.fn>;
  readonly confirmImport: ReturnType<typeof vi.fn>;
  readonly commitConfirmedImport: ReturnType<typeof vi.fn>;
  readonly acknowledgeImportResult: ReturnType<typeof vi.fn>;
  readonly beginExport: ReturnType<typeof vi.fn>;
  readonly streamExport: ReturnType<typeof vi.fn>;
  readonly inspectReplayBarriers: ReturnType<typeof vi.fn>;
  readonly clearReplayBarrier: ReturnType<typeof vi.fn>;
  readonly disconnect: ReturnType<typeof vi.fn>;
  readonly exportedChunks: Uint8Array[];
}

function createControllerHarness(options: {
  readonly importIds?: readonly string[];
  readonly exportBytes?: Uint8Array;
  readonly exportChunkBytes?: number;
  readonly exportFormat?: 'json' | 'encrypted-json' | 'csv' | 'zip';
  readonly exportReview?: VaultTransferExportReview;
  readonly assertExportCurrent?: () => void;
  readonly recoveryStatus?: {
    readonly count: number;
    readonly unresolvedUnknownCount: number;
    readonly reconcileRequiredCount: number;
    readonly omittedCount: number;
    readonly barriers: readonly {
      readonly transferId: string;
      readonly reason: 'outcome_unknown' | 'partial_result' | 'pending_result_delivery';
      readonly reconciled: boolean;
      readonly clearable: boolean;
    }[];
  };
} = {}): ControllerHarness {
  const importIds = [...(options.importIds ?? [IMPORT_ID])];
  const exportBytes = options.exportBytes ?? new Uint8Array([1, 2, 3, 4]);
  const exportChunkBytes = options.exportChunkBytes ?? 2;
  const exportFormat = options.exportFormat ?? 'json';
  const exportFilename = exportFormat === 'csv' ? 'vault.csv' : 'vault.json';
  const exportedChunks: Uint8Array[] = [];
  const beginImport = vi.fn(() => ({
    transferId: importIds.shift() ?? SECOND_IMPORT_ID,
    direction: 'import' as const,
    nextSequence: 0 as const,
    maxChunkBytes: 64 * 1024,
    maxTotalBytes: 1024 * 1024,
    maxChunks: 32,
    expiresAt: 10_000,
  }));
  const appendImportChunk = vi.fn((transferId: string, sequence: number, chunk: Uint8Array) => ({
    transferId,
    sequence,
    totalBytes: chunk.byteLength,
    requiresAcknowledgement: true as const,
  }));
  const acknowledgeImportChunk = vi.fn();
  const sealAndInspectImport = vi.fn(async (transferId: string) => ({
    transferId,
    sourceFormat: 'json' as const,
    previewCapability: PREVIEW_REVISION,
    preview: safePreview(),
  }));
  const confirmImport = vi.fn((transferId: string) => ({ transferId, status: 'confirmed' as const }));
  const commitConfirmedImport = vi.fn(async (transferId: string) => ({
    transferId,
    status: 'completed' as const,
    counts: { committed: 1, rejected: 0, skipped: 0, outcomeUnknown: 0 },
    requiresReconcile: false,
  }));
  const acknowledgeImportResult = vi.fn(async () => undefined);
  const beginExport = vi.fn(async () => ({
    transferId: EXPORT_ID,
    format: exportFormat,
    filename: exportFilename,
    totalBytes: exportBytes.byteLength,
    chunkBytes: exportChunkBytes,
    expiresAt: 10_000,
    ...(options.exportReview ? { review: options.exportReview } : {}),
  }));
  const disconnect = vi.fn(async () => ({ cancelled: true, requiresReconcile: false }));
  const inspectReplayBarriers = vi.fn(async () => options.recoveryStatus ?? ({
    count: 0,
    unresolvedUnknownCount: 0,
    reconcileRequiredCount: 0,
    omittedCount: 0,
    barriers: [],
  }));
  const clearReplayBarrier = vi.fn(async () => undefined);
  const streamExport = vi.fn(async (
    transferId: string,
    consume: Parameters<PortController['streamExport']>[1],
  ) => {
    let cursor = 0;
    let sequence = 0;
    let reachedEnd = false;
    let outstanding: { sequence: number; end: number; bytes: Uint8Array } | undefined;
    const producer = {
      async next() {
        if (outstanding) throw new VaultTransferControllerError('ack_required');
        if (cursor === exportBytes.byteLength) {
          reachedEnd = true;
          return { done: true as const, totalBytes: exportBytes.byteLength };
        }
        const end = Math.min(cursor + exportChunkBytes, exportBytes.byteLength);
        const bytes = exportBytes.slice(cursor, end);
        exportedChunks.push(bytes);
        outstanding = { sequence, end, bytes };
        return {
          done: false as const,
          sequence,
          bytes,
          requiresAcknowledgement: true as const,
        };
      },
      acknowledge(receivedSequence: number) {
        if (!outstanding || outstanding.sequence !== receivedSequence) {
          throw new VaultTransferControllerError('invalid_sequence');
        }
        outstanding.bytes.fill(0);
        cursor = outstanding.end;
        sequence += 1;
        outstanding = undefined;
      },
      assertCurrent() {
        options.assertExportCurrent?.();
      },
    };
    try {
      await consume({
        transferId,
        format: exportFormat,
        filename: exportFilename,
        totalBytes: exportBytes.byteLength,
        signal: new AbortController().signal,
        producer,
      });
      if (!reachedEnd || outstanding !== undefined) {
        throw new VaultTransferControllerError('export_incomplete');
      }
      return {
        transferId,
        format: exportFormat,
        status: 'completed' as const,
        totalBytes: exportBytes.byteLength,
      };
    } finally {
      outstanding?.bytes.fill(0);
    }
  });

  const controller: PortController = {
    beginImport,
    appendImportChunk,
    acknowledgeImportChunk,
    sealAndInspectImport,
    confirmImport,
    commitConfirmedImport,
    acknowledgeImportResult,
    beginExport,
    streamExport,
    inspectReplayBarriers,
    clearReplayBarrier,
    disconnect,
  };
  return {
    controller,
    beginImport,
    appendImportChunk,
    acknowledgeImportChunk,
    sealAndInspectImport,
    confirmImport,
    commitConfirmedImport,
    acknowledgeImportResult,
    beginExport,
    streamExport,
    inspectReplayBarriers,
    clearReplayBarrier,
    disconnect,
    exportedChunks,
  };
}

function safePreview(overrides: Partial<VaultTransferPreview> = {}): VaultTransferPreview {
  return {
    format: 'bitwarden-json',
    scope: 'personal',
    counts: { folders: 0, collections: 0, items: 1, attachments: 0 },
    diagnostics: { errors: [], warnings: [], unsupported: [], omittedCount: 0 },
    organizationTargetRequired: false,
    hasUnknownOutcome: false,
    canCommit: true,
    ...overrides,
  };
}

function trustedPort(url = OPTIONS_URL): TestPort {
  return new TestPort({ sender: { id: EXTENSION_ID, url, documentId: 'options-document' } });
}

function importBegin(expectedTotalBytes = 3) {
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'import.begin' as const,
    expectedTotalBytes,
    fileName: 'vault.json',
  };
}

function importChunk(transferId = IMPORT_ID, bytes = new Uint8Array([1, 2, 3])) {
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'import.chunk' as const,
    transferId,
    sequence: 0,
    byteLength: bytes.byteLength,
    dataBase64: encodeVaultTransferPortChunk(bytes),
  };
}

async function waitForType(port: TestPort, type: VaultTransferWorkerMessage['type'], count = 1) {
  await vi.waitFor(() => {
    expect(port.sent.filter((message) => message.type === type)).toHaveLength(count);
  });
  return port.sent.filter((message) => message.type === type);
}

async function reachPreview(port: TestPort, password?: string): Promise<void> {
  port.receive(importBegin());
  await waitForType(port, 'import.begun');
  port.receive(importChunk());
  await waitForType(port, 'import.ack');
  port.receive({
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'import.seal',
    transferId: IMPORT_ID,
    ...(password === undefined ? {} : { password }),
  });
  await waitForType(port, 'import.preview');
}

function deferred<Value>() {
  let resolve!: (value: Value) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<Value>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe('VaultTransferPortHandler sender boundary', () => {
  it('accepts only the exact extension-owned options page and permits query/hash suffixes', () => {
    const harness = createControllerHarness();
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort(`${OPTIONS_URL}?mode=import#picker`);

    expect(handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID)).toBe(true);
    expect(port.onMessage.listeners.size).toBe(1);
    expect(port.disconnectCount).toBe(0);
  });

  it.each([
    ['wrong name', new TestPort({ name: 'other', sender: { id: EXTENSION_ID, url: OPTIONS_URL } })],
    ['missing sender', new TestPort()],
    ['other extension', new TestPort({ sender: { id: 'other', url: OPTIONS_URL } })],
    ['content page', new TestPort({ sender: { id: EXTENSION_ID, url: 'https://example.com/ui/options/options.html' } })],
    ['credential-bearing URL', trustedPort(`chrome-extension://user:secret@${EXTENSION_ID}/ui/options/options.html`)],
    ['other extension page', trustedPort(`${EXTENSION_BASE_URL}ui/popup/popup.html`)],
    ['lookalike path', trustedPort(`${OPTIONS_URL}/child`)],
  ])('rejects and disconnects %s', (_label, port) => {
    const harness = createControllerHarness();
    const handler = new VaultTransferPortHandler(harness.controller);

    expect(handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID)).toBe(false);
    expect(port.disconnectCount).toBe(1);
    expect(port.onMessage.listeners.size).toBe(0);
  });

  it('rejects malformed envelopes with one fixed error and no exception text', async () => {
    const harness = createControllerHarness();
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({ ...importBegin(), extra: 'PRIVATE VALUE' });
    await waitForType(port, 'error');

    expect(port.sent).toEqual([expect.objectContaining({
      type: 'error',
      transferId: null,
      error: {
        code: 'invalid_message',
        message: 'The vault transfer message is invalid.',
      },
    })]);
    expect(JSON.stringify(port.sent)).not.toContain('PRIVATE VALUE');
    expect(port.disconnectCount).toBe(1);
  });

  it('installs listeners synchronously but queues ordinary messages until readiness resolves', async () => {
    const harness = createControllerHarness();
    const ready = deferred<void>();
    const handler = new VaultTransferPortHandler(harness.controller, ready.promise);
    const port = trustedPort();

    expect(handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID)).toBe(true);
    expect(port.onMessage.listeners.size).toBe(1);
    port.receive(importBegin());
    await Promise.resolve();
    expect(harness.beginImport).not.toHaveBeenCalled();
    expect(port.sent).toEqual([]);

    ready.resolve();
    await waitForType(port, 'import.begun');
    expect(harness.beginImport).toHaveBeenCalledOnce();
  });

  it('fails closed instead of queueing a second ordinary message behind readiness', async () => {
    const harness = createControllerHarness();
    const ready = deferred<void>();
    const handler = new VaultTransferPortHandler(harness.controller, ready.promise);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive(importBegin());
    port.receive(importBegin());
    await waitForType(port, 'error');
    ready.resolve();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      error: expect.objectContaining({ code: 'invalid_state' }),
    }));
    expect(harness.beginImport).not.toHaveBeenCalled();
    expect(port.disconnectCount).toBe(1);
  });

  it('returns only internal_error and disconnects when readiness rejects', async () => {
    const harness = createControllerHarness();
    const ready = deferred<void>();
    const handler = new VaultTransferPortHandler(harness.controller, ready.promise);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    port.receive(importBegin());

    ready.reject(new VaultTransferControllerError('outcome_unknown'));
    await waitForType(port, 'error');

    expect(port.sent).toEqual([expect.objectContaining({
      type: 'error',
      transferId: null,
      phase: 'idle',
      error: {
        code: 'internal_error',
        message: 'The vault transfer could not be completed.',
      },
    })]);
    expect(harness.beginImport).not.toHaveBeenCalled();
    expect(harness.disconnect).not.toHaveBeenCalled();
    expect(port.disconnectCount).toBe(1);
  });

  it('does not execute queued controller work after disconnecting before readiness', async () => {
    const harness = createControllerHarness();
    const ready = deferred<void>();
    const handler = new VaultTransferPortHandler(harness.controller, ready.promise);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    port.receive(importBegin());

    port.disconnect();
    ready.resolve();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(harness.beginImport).not.toHaveBeenCalled();
    expect(harness.disconnect).not.toHaveBeenCalled();
    expect(port.sent).toEqual([]);
  });

  it('fails an export ACK immediately while readiness is still pending', async () => {
    const harness = createControllerHarness();
    const ready = deferred<void>();
    const handler = new VaultTransferPortHandler(harness.controller, ready.promise);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({ version: 1, type: 'export.ack', transferId: EXPORT_ID, sequence: 0 });
    await waitForType(port, 'error');

    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      type: 'error',
      error: expect.objectContaining({ code: 'invalid_sequence' }),
    }));
    expect(harness.beginExport).not.toHaveBeenCalled();
  });
});

describe('VaultTransferPortHandler recovery flow', () => {
  const unknownBarrier = {
    count: 1,
    unresolvedUnknownCount: 1,
    reconcileRequiredCount: 1,
    omittedCount: 0,
    barriers: [{
      transferId: IMPORT_ID,
      reason: 'outcome_unknown' as const,
      reconciled: false,
      clearable: false,
    }],
  };

  it('reports a lost-result startup barrier using only bounded recovery fields', async () => {
    const harness = createControllerHarness({ recoveryStatus: unknownBarrier });
    harness.inspectReplayBarriers.mockResolvedValueOnce({
      ...unknownBarrier,
      accountIdentityDigest: 'a'.repeat(64),
      sourceDigest: 'b'.repeat(64),
      rawError: 'PRIVATE SERVER ERROR',
    });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({ version: 1, type: 'recovery.inspect' });
    await waitForType(port, 'recovery.status');

    expect(port.sent).toEqual([{
      version: 1,
      type: 'recovery.status',
      phase: 'completed',
      status: unknownBarrier,
    }]);
    expect(JSON.stringify(port.sent)).not.toMatch(/accountIdentityDigest|sourceDigest|PRIVATE/);
    expect(harness.clearReplayBarrier).not.toHaveBeenCalled();
  });

  it('rejects clearing an unknown outcome until every visible barrier is reconciled', async () => {
    const harness = createControllerHarness({ recoveryStatus: unknownBarrier });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1,
      type: 'recovery.clear',
      expectedBarriers: [{ transferId: IMPORT_ID, reason: 'outcome_unknown' }],
    });
    await waitForType(port, 'error');

    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      type: 'error',
      transferId: null,
      phase: 'inspecting',
      error: {
        code: 'recovery_not_clearable',
        message: 'Vault transfer recovery records must be reconciled before clearing.',
      },
    }));
    expect(harness.clearReplayBarrier).not.toHaveBeenCalled();
  });

  it('clears an explicitly requested complete reconciled set exactly once', async () => {
    const clearable = {
      ...unknownBarrier,
      reconcileRequiredCount: 0,
      barriers: [{
        ...unknownBarrier.barriers[0]!,
        reconciled: true,
        clearable: true,
      }],
    };
    const harness = createControllerHarness({ recoveryStatus: clearable });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1,
      type: 'recovery.clear',
      expectedBarriers: [{ transferId: IMPORT_ID, reason: 'outcome_unknown' }],
    });
    await waitForType(port, 'recovery.cleared');

    expect(harness.inspectReplayBarriers).toHaveBeenCalledOnce();
    expect(harness.clearReplayBarrier).toHaveBeenCalledOnce();
    expect(harness.clearReplayBarrier).toHaveBeenCalledWith(IMPORT_ID);
    expect(port.sent).toEqual([{
      version: 1,
      type: 'recovery.cleared',
      phase: 'completed',
      cleared: 1,
    }]);
  });

  it('refuses an omitted recovery set even when every visible entry is clearable', async () => {
    const harness = createControllerHarness({
      recoveryStatus: {
        count: 2,
        unresolvedUnknownCount: 1,
        reconcileRequiredCount: 0,
        omittedCount: 1,
        barriers: [{
          transferId: IMPORT_ID,
          reason: 'outcome_unknown',
          reconciled: true,
          clearable: true,
        }],
      },
    });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1,
      type: 'recovery.clear',
      expectedBarriers: [{ transferId: IMPORT_ID, reason: 'outcome_unknown' }],
    });
    await waitForType(port, 'error');

    expect(harness.clearReplayBarrier).not.toHaveBeenCalled();
    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      error: expect.objectContaining({ code: 'recovery_not_clearable' }),
    }));
  });

  it('rejects a clear when the displayed barrier snapshot no longer matches', async () => {
    const clearable = {
      ...unknownBarrier,
      reconcileRequiredCount: 0,
      barriers: [{
        ...unknownBarrier.barriers[0]!,
        reconciled: true,
        clearable: true,
      }],
    };
    const harness = createControllerHarness({ recoveryStatus: clearable });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1,
      type: 'recovery.clear',
      expectedBarriers: [{ transferId: SECOND_IMPORT_ID, reason: 'outcome_unknown' }],
    });
    await waitForType(port, 'error');

    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      error: expect.objectContaining({ code: 'recovery_not_clearable' }),
    }));
    expect(harness.clearReplayBarrier).not.toHaveBeenCalled();
  });

  it('fails closed when a controller returns malformed recovery status', async () => {
    const harness = createControllerHarness();
    harness.inspectReplayBarriers.mockResolvedValueOnce({
      ...unknownBarrier,
      barriers: [{ ...unknownBarrier.barriers[0]!, transferId: 'PRIVATE INVALID ID' }],
    });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({ version: 1, type: 'recovery.inspect' });
    await waitForType(port, 'error');

    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      error: expect.objectContaining({ code: 'invalid_message' }),
    }));
    expect(JSON.stringify(port.sent)).not.toContain('PRIVATE INVALID ID');
  });
});

describe('VaultTransferPortHandler import flow', () => {
  it('posts the import ACK before acknowledging the controller and zeroes the decoded chunk', async () => {
    const harness = createControllerHarness();
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    port.postHook = (message) => {
      if (message.type === 'import.ack') {
        expect(harness.acknowledgeImportChunk).not.toHaveBeenCalled();
      }
    };

    port.receive(importBegin());
    await waitForType(port, 'import.begun');
    port.receive(importChunk());
    await waitForType(port, 'import.ack');

    expect(harness.acknowledgeImportChunk).toHaveBeenCalledWith(IMPORT_ID, 0);
    const received = harness.appendImportChunk.mock.calls[0]?.[2] as Uint8Array;
    expect(Array.from(received)).toEqual([0, 0, 0]);
    const postOrder = port.sent.findIndex((message) => message.type === 'import.ack');
    expect(postOrder).toBeGreaterThanOrEqual(0);
  });

  it('zeroes the decoded chunk and disconnects the transfer when posting an ACK throws', async () => {
    const harness = createControllerHarness();
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive(importBegin());
    await waitForType(port, 'import.begun');
    port.throwOnType = 'import.ack';
    port.receive(importChunk());
    await waitForType(port, 'error');

    const received = harness.appendImportChunk.mock.calls[0]?.[2] as Uint8Array;
    expect(Array.from(received)).toEqual([0, 0, 0]);
    expect(harness.acknowledgeImportChunk).not.toHaveBeenCalled();
    expect(harness.disconnect).toHaveBeenCalledWith(IMPORT_ID);
    expect(port.disconnectCount).toBe(1);
  });

  it('sanitizes and aggregates preview diagnostics without returning values, indexes, or passwords', async () => {
    const harness = createControllerHarness();
    harness.sealAndInspectImport.mockResolvedValueOnce({
      transferId: IMPORT_ID,
      sourceFormat: 'encrypted-json',
      previewCapability: PREVIEW_REVISION,
      preview: safePreview({
        counts: { folders: 2, collections: 0, items: 3, attachments: 1 },
        diagnostics: {
          errors: [
            { category: 'error', code: 'malformed_json', sourceIndex: 17 },
            { category: 'error', code: 'malformed_json' },
          ],
          warnings: [{ category: 'warning', code: 'transfer_notice', sourceIndex: 22 }],
          unsupported: [
            { category: 'unsupported', code: 'custom_fields_unsupported', sourceIndex: 9 },
            { category: 'unsupported', code: 'ssh_linked_fields_unsupported', sourceIndex: 10 },
          ],
          omittedCount: 4,
        },
        canCommit: false,
      }),
    });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    await reachPreview(port, 'PRIVATE PASSWORD');
    const [preview] = port.sent.filter((message) => message.type === 'import.preview');

    expect(harness.sealAndInspectImport).toHaveBeenCalledWith(IMPORT_ID, 'PRIVATE PASSWORD');
    expect(preview).toEqual(expect.objectContaining({
      preview: expect.objectContaining({
        format: 'encrypted-json',
        counts: { folders: 2, collections: 0, items: 3, attachments: 1 },
        diagnostics: {
          errors: [{ code: 'malformed_input', count: 2 }],
          warnings: [
            { code: 'diagnostics_omitted', count: 4 },
            { code: 'other', count: 1 },
          ],
          unsupported: [{ code: 'unsupported_data', count: 2 }],
        },
      }),
    }));
    const serialized = JSON.stringify(preview);
    expect(serialized).not.toContain('PRIVATE PASSWORD');
    expect(serialized).not.toContain('sourceIndex');
    expect(serialized).not.toContain('malformed_json');
    expect(serialized).not.toContain('custom_fields_unsupported');
    expect(serialized).not.toContain('ssh_linked_fields_unsupported');
  });

  it('keeps omitted non-blocking diagnostics in warnings so a committable preview stays valid', async () => {
    const harness = createControllerHarness();
    harness.sealAndInspectImport.mockResolvedValueOnce({
      transferId: IMPORT_ID,
      sourceFormat: 'json',
      previewCapability: PREVIEW_REVISION,
      preview: safePreview({
        diagnostics: { errors: [], warnings: [], unsupported: [], omittedCount: 7 },
        canCommit: true,
      }),
    });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    await reachPreview(port);

    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      type: 'import.preview',
      preview: expect.objectContaining({
        canCommit: true,
        diagnostics: {
          errors: [],
          warnings: [{ code: 'diagnostics_omitted', count: 7 }],
          unsupported: [],
        },
      }),
    }));
  });

  it('confirms before committing and returns a fixed unknown-outcome result', async () => {
    const harness = createControllerHarness();
    harness.commitConfirmedImport.mockResolvedValueOnce({
      transferId: IMPORT_ID,
      status: 'outcome_unknown',
      counts: { committed: 1, rejected: 0, skipped: 0, outcomeUnknown: 1 },
      requiresReconcile: true,
    });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    await reachPreview(port);

    port.receive({
      version: VAULT_TRANSFER_PORT_VERSION,
      type: 'import.confirm',
      transferId: IMPORT_ID,
      previewRevision: PREVIEW_REVISION,
    });
    await waitForType(port, 'import.result');

    expect(harness.confirmImport).toHaveBeenCalledWith(IMPORT_ID, PREVIEW_REVISION);
    expect(harness.confirmImport.mock.invocationCallOrder[0])
      .toBeLessThan(harness.commitConfirmedImport.mock.invocationCallOrder[0] ?? 0);
    expect(port.sent.at(-1)).toEqual({
      version: VAULT_TRANSFER_PORT_VERSION,
      type: 'import.result',
      transferId: IMPORT_ID,
      phase: 'completed',
      status: 'outcome_unknown',
      counts: { committed: 1, rejected: 0, skipped: 0, outcomeUnknown: 1 },
      mustSyncBeforeRetry: true,
    });
    expect(harness.acknowledgeImportResult).not.toHaveBeenCalled();
  });

  it('keeps a completed result behind the durable delivery barrier until its exact ACK', async () => {
    const harness = createControllerHarness();
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    await reachPreview(port);
    port.receive({
      version: 1,
      type: 'import.confirm',
      transferId: IMPORT_ID,
      previewRevision: PREVIEW_REVISION,
    });
    await waitForType(port, 'import.result');

    expect(harness.acknowledgeImportResult).not.toHaveBeenCalled();
    expect(port.disconnectCount).toBe(0);
    port.receive({ version: 1, type: 'import.result.ack', transferId: IMPORT_ID });
    await vi.waitFor(() => {
      expect(harness.acknowledgeImportResult).toHaveBeenCalledWith(IMPORT_ID);
      expect(port.disconnectCount).toBe(1);
    });
    expect(harness.disconnect).toHaveBeenCalledWith(IMPORT_ID);
    expect(port.sent.some((message) => message.type === 'error')).toBe(false);
  });

  it('passes a known partial result ACK to the controller even when reconciliation remains required', async () => {
    const harness = createControllerHarness();
    harness.commitConfirmedImport.mockResolvedValueOnce({
      transferId: IMPORT_ID,
      status: 'partial',
      counts: { committed: 1, rejected: 1, skipped: 0, outcomeUnknown: 0 },
      requiresReconcile: true,
    });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    await reachPreview(port);
    port.receive({
      version: 1,
      type: 'import.confirm',
      transferId: IMPORT_ID,
      previewRevision: PREVIEW_REVISION,
    });
    await waitForType(port, 'import.result');

    port.receive({ version: 1, type: 'import.result.ack', transferId: IMPORT_ID });
    await vi.waitFor(() => expect(harness.acknowledgeImportResult).toHaveBeenCalledWith(IMPORT_ID));
    expect(port.sent.find((message) => message.type === 'import.result')).toEqual(
      expect.objectContaining({ status: 'partial', mustSyncBeforeRetry: true }),
    );
  });

  it('rejects a result ACK before a result is awaiting delivery', async () => {
    const harness = createControllerHarness();
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({ version: 1, type: 'import.result.ack', transferId: IMPORT_ID });
    await waitForType(port, 'error');

    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      type: 'error',
      phase: 'idle',
      error: expect.objectContaining({ code: 'invalid_state' }),
    }));
    expect(harness.acknowledgeImportResult).not.toHaveBeenCalled();
  });

  it('rejects a result ACK for the wrong transfer without releasing the barrier', async () => {
    const harness = createControllerHarness();
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    await reachPreview(port);
    port.receive({
      version: 1,
      type: 'import.confirm',
      transferId: IMPORT_ID,
      previewRevision: PREVIEW_REVISION,
    });
    await waitForType(port, 'import.result');

    port.receive({ version: 1, type: 'import.result.ack', transferId: SECOND_IMPORT_ID });
    await waitForType(port, 'error');

    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      type: 'error',
      phase: 'completed',
      error: expect.objectContaining({ code: 'invalid_sequence' }),
    }));
    expect(harness.acknowledgeImportResult).not.toHaveBeenCalled();
    expect(harness.disconnect).toHaveBeenCalledWith(IMPORT_ID);
  });

  it('fails closed on a duplicate result ACK while durable acknowledgement is pending', async () => {
    const harness = createControllerHarness();
    const acknowledgement = deferred<void>();
    harness.acknowledgeImportResult.mockImplementationOnce(() => acknowledgement.promise);
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    await reachPreview(port);
    port.receive({
      version: 1,
      type: 'import.confirm',
      transferId: IMPORT_ID,
      previewRevision: PREVIEW_REVISION,
    });
    await waitForType(port, 'import.result');

    const ack = { version: 1 as const, type: 'import.result.ack' as const, transferId: IMPORT_ID };
    port.receive(ack);
    await vi.waitFor(() => expect(harness.acknowledgeImportResult).toHaveBeenCalledOnce());
    port.receive(ack);
    await waitForType(port, 'error');
    acknowledgement.resolve();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(harness.acknowledgeImportResult).toHaveBeenCalledTimes(1);
    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      type: 'error',
      phase: 'completed',
      error: expect.objectContaining({ code: 'invalid_sequence' }),
    }));
  });

  it('does not acknowledge result delivery when the Port disconnects after receiving the result', async () => {
    const harness = createControllerHarness();
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    await reachPreview(port);
    port.receive({
      version: 1,
      type: 'import.confirm',
      transferId: IMPORT_ID,
      previewRevision: PREVIEW_REVISION,
    });
    await waitForType(port, 'import.result');

    port.disconnect();
    await vi.waitFor(() => expect(harness.disconnect).toHaveBeenCalledWith(IMPORT_ID));

    expect(harness.acknowledgeImportResult).not.toHaveBeenCalled();
  });

  it('leaves the barrier intact when import.result cannot be posted', async () => {
    const harness = createControllerHarness();
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    await reachPreview(port);
    port.throwOnType = 'import.result';

    port.receive({
      version: 1,
      type: 'import.confirm',
      transferId: IMPORT_ID,
      previewRevision: PREVIEW_REVISION,
    });
    await waitForType(port, 'error');

    expect(harness.acknowledgeImportResult).not.toHaveBeenCalled();
    expect(harness.disconnect).toHaveBeenCalledWith(IMPORT_ID);
  });

  it('does not release an unknown-outcome barrier when the client acknowledges the result', async () => {
    const harness = createControllerHarness();
    harness.commitConfirmedImport.mockResolvedValueOnce({
      transferId: IMPORT_ID,
      status: 'outcome_unknown',
      counts: { committed: 0, rejected: 0, skipped: 0, outcomeUnknown: 1 },
      requiresReconcile: true,
    });
    harness.acknowledgeImportResult.mockRejectedValueOnce(
      new VaultTransferControllerError('not_found'),
    );
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    await reachPreview(port);
    port.receive({
      version: 1,
      type: 'import.confirm',
      transferId: IMPORT_ID,
      previewRevision: PREVIEW_REVISION,
    });
    await waitForType(port, 'import.result');

    port.receive({ version: 1, type: 'import.result.ack', transferId: IMPORT_ID });
    await waitForType(port, 'error');

    expect(harness.acknowledgeImportResult).toHaveBeenCalledWith(IMPORT_ID);
    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      type: 'error',
      phase: 'completed',
      error: {
        code: 'not_found',
        message: 'The vault transfer is no longer available.',
      },
    }));
  });

  it('maps commit failures to a stable error and never echoes the underlying exception', async () => {
    const harness = createControllerHarness();
    harness.commitConfirmedImport.mockRejectedValueOnce(
      new VaultTransferControllerError('commit_failed'),
    );
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    await reachPreview(port);

    port.receive({
      version: VAULT_TRANSFER_PORT_VERSION,
      type: 'import.confirm',
      transferId: IMPORT_ID,
      previewRevision: PREVIEW_REVISION,
    });
    await waitForType(port, 'error');

    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      type: 'error',
      error: {
        code: 'commit_failed',
        message: 'The vault transfer could not be completed.',
      },
    }));
    expect(harness.disconnect).toHaveBeenCalledWith(IMPORT_ID);
  });

  it('prevents a disconnected import completion from posting into another active Port', async () => {
    const harness = createControllerHarness({ importIds: [IMPORT_ID, SECOND_IMPORT_ID] });
    const first = deferred<{
      transferId: string;
      sourceFormat: 'json';
      previewCapability: string;
      preview: VaultTransferPreview;
    }>();
    const second = deferred<{
      transferId: string;
      sourceFormat: 'json';
      previewCapability: string;
      preview: VaultTransferPreview;
    }>();
    harness.sealAndInspectImport
      .mockImplementationOnce(() => first.promise)
      .mockImplementationOnce(() => second.promise);
    const handler = new VaultTransferPortHandler(harness.controller);
    const firstPort = trustedPort();
    const secondPort = trustedPort();
    handler.handle(firstPort, EXTENSION_BASE_URL, EXTENSION_ID);
    handler.handle(secondPort, EXTENSION_BASE_URL, EXTENSION_ID);

    firstPort.receive(importBegin());
    secondPort.receive(importBegin());
    await waitForType(firstPort, 'import.begun');
    await waitForType(secondPort, 'import.begun');
    firstPort.receive(importChunk(IMPORT_ID));
    secondPort.receive(importChunk(SECOND_IMPORT_ID));
    await waitForType(firstPort, 'import.ack');
    await waitForType(secondPort, 'import.ack');
    firstPort.receive({ version: 1, type: 'import.seal', transferId: IMPORT_ID });
    secondPort.receive({ version: 1, type: 'import.seal', transferId: SECOND_IMPORT_ID });
    await vi.waitFor(() => expect(harness.sealAndInspectImport).toHaveBeenCalledTimes(2));

    firstPort.disconnect();
    second.resolve({
      transferId: SECOND_IMPORT_ID,
      sourceFormat: 'json',
      previewCapability: PREVIEW_REVISION,
      preview: safePreview(),
    });
    await waitForType(secondPort, 'import.preview');
    first.resolve({
      transferId: IMPORT_ID,
      sourceFormat: 'json',
      previewCapability: PREVIEW_REVISION,
      preview: safePreview(),
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(firstPort.sent.some((message) => message.type === 'import.preview')).toBe(false);
    expect(secondPort.sent.filter((message) => message.type === 'import.preview')).toHaveLength(1);
    expect(harness.disconnect).toHaveBeenCalledWith(IMPORT_ID);
  });

  it('cancels through controller.disconnect and closes the Port without a synthetic error', async () => {
    const harness = createControllerHarness();
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    port.receive(importBegin());
    await waitForType(port, 'import.begun');

    port.receive({ version: 1, type: 'cancel', transferId: IMPORT_ID });
    await vi.waitFor(() => expect(harness.disconnect).toHaveBeenCalledWith(IMPORT_ID));

    expect(port.disconnectCount).toBe(1);
    expect(port.sent.some((message) => message.type === 'error')).toBe(false);
  });

  it('drops a commit result that completes after the Port disconnected', async () => {
    const harness = createControllerHarness();
    const commit = deferred<Awaited<ReturnType<PortController['commitConfirmedImport']>>>();
    harness.commitConfirmedImport.mockImplementationOnce(() => commit.promise);
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    await reachPreview(port);

    port.receive({
      version: 1,
      type: 'import.confirm',
      transferId: IMPORT_ID,
      previewRevision: PREVIEW_REVISION,
    });
    await vi.waitFor(() => expect(harness.commitConfirmedImport).toHaveBeenCalledOnce());
    port.disconnect();
    commit.resolve({
      transferId: IMPORT_ID,
      status: 'completed',
      counts: { committed: 1, rejected: 0, skipped: 0, outcomeUnknown: 0 },
      requiresReconcile: false,
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(port.sent.some((message) => message.type === 'import.result')).toBe(false);
    expect(harness.disconnect).toHaveBeenCalledWith(IMPORT_ID);
  });
});

describe('VaultTransferPortHandler export flow', () => {
  it('withholds an export chunk when its durable release checkpoint fails', async () => {
    const harness = createControllerHarness();
    const vaultReleaseGate = {
      capture: vi.fn(() => ({ sessionLease: { generation: 1 }, timeoutLease: {} })),
      checkpoint: vi.fn(async () => { throw new Error('checkpoint unavailable'); }),
      assert: vi.fn(),
      settlePendingAction: vi.fn(async () => undefined),
    };
    const handler = new VaultTransferPortHandler(
      harness.controller,
      Promise.resolve(),
      vaultReleaseGate as never,
    );
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1, type: 'export.begin', format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    await waitForType(port, 'error');

    expect(vaultReleaseGate.checkpoint).toHaveBeenCalledOnce();
    expect(vaultReleaseGate.settlePendingAction).toHaveBeenCalledOnce();
    expect(vaultReleaseGate.assert).not.toHaveBeenCalled();
    expect(port.sent.some((message) => message.type === 'export.chunk')).toBe(false);
    expect(harness.exportedChunks.every((chunk) => chunk.every((byte) => byte === 0))).toBe(true);
  });

  it('rechecks the original transfer authority after the checkpoint await', async () => {
    let revoked = false;
    const harness = createControllerHarness({
      assertExportCurrent: () => {
        if (revoked) throw new VaultTransferControllerError('lease_changed');
      },
    });
    const pending = deferred<object>();
    const vaultReleaseGate = {
      capture: vi.fn(() => ({ sessionLease: { generation: 1 }, timeoutLease: {} })),
      checkpoint: vi.fn(() => pending.promise),
      assertAuthorities: vi.fn((_proof: object, assertCurrent: () => void) => assertCurrent()),
      assert: vi.fn(),
    };
    const handler = new VaultTransferPortHandler(
      harness.controller,
      Promise.resolve(),
      vaultReleaseGate as never,
    );
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    port.receive({
      version: 1, type: 'export.begin', format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    await vi.waitFor(() => expect(vaultReleaseGate.checkpoint).toHaveBeenCalledOnce());
    revoked = true;
    pending.resolve({});
    await waitForType(port, 'error');

    expect(vaultReleaseGate.assertAuthorities).toHaveBeenCalledOnce();
    expect(vaultReleaseGate.assert).not.toHaveBeenCalled();
    expect(port.sent.some((message) => message.type === 'export.chunk')).toBe(false);
  });

  it('reasserts the original export lease immediately before posting a secret chunk', async () => {
    const assertExportCurrent = vi.fn(() => {
      throw new VaultTransferControllerError('lease_changed');
    });
    const harness = createControllerHarness({ assertExportCurrent });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1, type: 'export.begin', format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    await waitForType(port, 'error');

    expect(assertExportCurrent).toHaveBeenCalledOnce();
    expect(port.sent.some((message) => message.type === 'export.chunk')).toBe(false);
    expect(harness.exportedChunks.every((chunk) => chunk.every((byte) => byte === 0))).toBe(true);
    expect(harness.disconnect).toHaveBeenCalledWith(EXPORT_ID);
  });

  it('maps an invalid or expired export grant to one fixed error', async () => {
    const harness = createControllerHarness();
    harness.beginExport.mockRejectedValueOnce(
      new VaultTransferControllerError('export_authorization_invalid'),
    );
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1, type: 'export.begin', format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    await waitForType(port, 'error');

    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      type: 'error',
      error: {
        code: 'export_authorization_invalid',
        message: 'Vault export verification is invalid or expired.',
      },
    }));
  });

  it('uses the ACK fast path and never produces the next chunk before the exact ACK', async () => {
    const harness = createControllerHarness({ exportBytes: new Uint8Array([1, 2, 3, 4]), exportChunkBytes: 2 });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1, type: 'export.begin', format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    await waitForType(port, 'export.begun');
    await waitForType(port, 'export.chunk');
    expect(port.sent.filter((message) => message.type === 'export.chunk')).toHaveLength(1);

    port.receive({ version: 1, type: 'export.ack', transferId: EXPORT_ID, sequence: 0 });
    await waitForType(port, 'export.chunk', 2);
    expect(Array.from(harness.exportedChunks[0] ?? [])).toEqual([0, 0]);
    expect(port.sent.some((message) => message.type === 'export.done')).toBe(false);

    port.receive({ version: 1, type: 'export.ack', transferId: EXPORT_ID, sequence: 1 });
    await waitForType(port, 'export.done');
    expect(Array.from(harness.exportedChunks[1] ?? [])).toEqual([0, 0]);
    expect(port.sent.at(-1)).toEqual({
      version: 1,
      type: 'export.done',
      transferId: EXPORT_ID,
      format: 'json',
      phase: 'completed',
      chunkCount: 2,
      totalBytes: 4,
    });
  });

  it('attaches one worker-owned export event acknowledgement for the exact options document', async () => {
    const harness = createControllerHarness({
      exportBytes: new Uint8Array([1]),
      exportChunkBytes: 1,
    });
    const issuePersonalExportAck = vi.fn(async () => CLIENT_EVENT_ACK_ID);
    const handler = new VaultTransferPortHandler(
      harness.controller,
      Promise.resolve(),
      undefined,
      issuePersonalExportAck,
    );
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1, type: 'export.begin', format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    await waitForType(port, 'export.chunk');
    port.receive({ version: 1, type: 'export.ack', transferId: EXPORT_ID, sequence: 0 });
    await waitForType(port, 'export.done');

    expect(issuePersonalExportAck).toHaveBeenCalledWith('options-document');
    expect(port.sent.at(-1)).toMatchObject({
      type: 'export.done',
      clientEventAckId: CLIENT_EVENT_ACK_ID,
    });
  });

  it('fails closed on an early or mismatched export ACK', async () => {
    const harness = createControllerHarness();
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1, type: 'export.begin', format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    await waitForType(port, 'export.chunk');
    port.receive({ version: 1, type: 'export.ack', transferId: EXPORT_ID, sequence: 9 });
    await waitForType(port, 'error');

    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      type: 'error',
      error: {
        code: 'invalid_sequence',
        message: 'The vault transfer chunk sequence is invalid.',
      },
    }));
    expect(harness.disconnect).toHaveBeenCalledWith(EXPORT_ID);
    expect(harness.exportedChunks.every((chunk) => chunk.every((byte) => byte === 0))).toBe(true);
  });

  it('treats a repeated matching export ACK as a protocol violation', async () => {
    const harness = createControllerHarness();
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);
    port.receive({
      version: 1, type: 'export.begin', format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    await waitForType(port, 'export.chunk');

    const acknowledgement = { version: 1 as const, type: 'export.ack' as const, transferId: EXPORT_ID, sequence: 0 };
    port.receive(acknowledgement);
    port.receive(acknowledgement);
    await waitForType(port, 'error');

    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      type: 'error',
      error: expect.objectContaining({ code: 'invalid_sequence' }),
    }));
    expect(harness.disconnect).toHaveBeenCalledWith(EXPORT_ID);
  });

  it('passes an encrypted-export password only to the controller and never returns it over the Port', async () => {
    const harness = createControllerHarness({ exportFormat: 'encrypted-json' });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1,
      type: 'export.begin',
      format: 'encrypted-json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      filePassword: 'PRIVATE EXPORT PASSWORD',
    });
    await waitForType(port, 'export.chunk');

    expect(harness.beginExport).toHaveBeenCalledWith({
      format: 'encrypted-json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'personal' },
      filePassword: 'PRIVATE EXPORT PASSWORD',
    });
    expect(JSON.stringify(port.sent)).not.toContain('PRIVATE EXPORT PASSWORD');
    port.disconnect();
  });

  it('passes account-encrypted export without synthesizing a file password', async () => {
    const harness = createControllerHarness({ exportFormat: 'encrypted-json' });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1,
      type: 'export.begin',
      format: 'encrypted-json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    await waitForType(port, 'export.chunk');

    expect(harness.beginExport).toHaveBeenCalledWith({
      format: 'encrypted-json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'personal' },
    });
    expect(harness.beginExport.mock.calls[0]?.[0]).not.toHaveProperty('filePassword');
    port.disconnect();
  });

  it('passes passwordless CSV review metadata to the client before any download acknowledgement', async () => {
    const review: VaultTransferExportReview = {
      exportedItemCount: 1,
      omittedItemCount: 1,
      warnings: [{ code: 'ssh_key_items_omitted', count: 1 }],
    };
    const harness = createControllerHarness({ exportFormat: 'csv', exportReview: review });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1, type: 'export.begin', format: 'csv', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    await waitForType(port, 'export.begun');

    expect(harness.beginExport).toHaveBeenCalledWith({
      format: 'csv', authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'personal' },
    });
    expect(port.sent.find((message) => message.type === 'export.begun')).toMatchObject({
      format: 'csv', fileName: 'vault.csv', review,
    });
    port.disconnect();
  });

  it('forwards one canonical organization target and issues the organization export ACK', async () => {
    const harness = createControllerHarness({ exportBytes: new Uint8Array(0) });
    const issuePersonalExportAck = vi.fn(async () => CLIENT_EVENT_ACK_ID);
    const issueOrganizationExportAck = vi.fn(async () => CLIENT_EVENT_ACK_ID);
    const handler = new VaultTransferPortHandler(
      harness.controller,
      Promise.resolve(),
      undefined,
      issuePersonalExportAck,
      issueOrganizationExportAck,
    );
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1,
      type: 'export.begin',
      format: 'json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'organization', organizationId: ORGANIZATION_ID.toUpperCase() },
    });
    await waitForType(port, 'export.done');

    expect(harness.beginExport).toHaveBeenCalledWith({
      format: 'json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'organization', organizationId: ORGANIZATION_ID },
    });
    expect(issuePersonalExportAck).not.toHaveBeenCalled();
    expect(issueOrganizationExportAck).toHaveBeenCalledWith('options-document', ORGANIZATION_ID);
    expect(port.sent.at(-1)).toMatchObject({ clientEventAckId: CLIENT_EVENT_ACK_ID });
  });

  it('rechecks export authority after preparing an organization event receipt', async () => {
    let current = true;
    const harness = createControllerHarness({
      exportBytes: new Uint8Array(0),
      assertExportCurrent: () => {
        if (!current) throw new Error('export authority changed');
      },
    });
    const issueOrganizationExportAck = vi.fn(async () => {
      current = false;
      return CLIENT_EVENT_ACK_ID;
    });
    const handler = new VaultTransferPortHandler(
      harness.controller,
      Promise.resolve(),
      undefined,
      undefined,
      issueOrganizationExportAck,
    );
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1,
      type: 'export.begin',
      format: 'json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'organization', organizationId: ORGANIZATION_ID },
    });
    await waitForType(port, 'error');

    expect(issueOrganizationExportAck).toHaveBeenCalledOnce();
    expect(port.sent.some((message) => message.type === 'export.done')).toBe(false);
    expect(port.sent.at(-1)).toMatchObject({
      type: 'error',
      error: { code: 'export_failed' },
    });
  });

  it('rejects organization ZIP before invoking the controller', async () => {
    const harness = createControllerHarness({ exportFormat: 'zip' });
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1,
      type: 'export.begin',
      format: 'zip',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'organization', organizationId: ORGANIZATION_ID },
    });
    await waitForType(port, 'error');

    expect(port.sent.at(-1)).toMatchObject({
      type: 'error',
      error: { code: 'invalid_message' },
    });
    expect(harness.beginExport).not.toHaveBeenCalled();
  });

  it('disconnects and zeroes the outstanding export chunk when postMessage throws', async () => {
    const harness = createControllerHarness();
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    port.throwOnType = 'export.chunk';
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1, type: 'export.begin', format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    await waitForType(port, 'error');
    await vi.waitFor(() => {
      expect(harness.exportedChunks[0]?.every((byte) => byte === 0)).toBe(true);
    });

    expect(harness.disconnect).toHaveBeenCalledWith(EXPORT_ID);
    expect(port.disconnectCount).toBe(1);
  });

  it('cancels an export waiting for ACK when the Port disconnects and never posts done', async () => {
    const harness = createControllerHarness();
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1, type: 'export.begin', format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    await waitForType(port, 'export.chunk');
    port.disconnect();
    await vi.waitFor(() => expect(harness.disconnect).toHaveBeenCalledWith(EXPORT_ID));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(port.sent.some((message) => message.type === 'export.done')).toBe(false);
    expect(harness.exportedChunks.every((chunk) => chunk.every((byte) => byte === 0))).toBe(true);
  });

  it('disconnects a late export build result without reviving the closed Port', async () => {
    const harness = createControllerHarness();
    const begun = deferred<Awaited<ReturnType<PortController['beginExport']>>>();
    harness.beginExport.mockImplementationOnce(() => begun.promise);
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1, type: 'export.begin', format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    await vi.waitFor(() => expect(harness.beginExport).toHaveBeenCalledOnce());
    port.disconnect();
    begun.resolve({
      transferId: EXPORT_ID,
      format: 'json',
      filename: 'vault.json',
      totalBytes: 4,
      chunkBytes: 2,
      expiresAt: 10_000,
    });
    await vi.waitFor(() => expect(harness.disconnect).toHaveBeenCalledWith(EXPORT_ID));

    expect(port.sent).toEqual([]);
    expect(harness.streamExport).not.toHaveBeenCalled();
  });

  it('returns only the stable outcome-unknown error when export streaming fails that way', async () => {
    const harness = createControllerHarness();
    harness.streamExport.mockRejectedValueOnce(new VaultTransferControllerError('outcome_unknown'));
    const handler = new VaultTransferPortHandler(harness.controller);
    const port = trustedPort();
    handler.handle(port, EXTENSION_BASE_URL, EXTENSION_ID);

    port.receive({
      version: 1, type: 'export.begin', format: 'json', authorizationId: EXPORT_AUTHORIZATION_ID,
    });
    await waitForType(port, 'error');

    expect(port.sent.at(-1)).toEqual(expect.objectContaining({
      type: 'error',
      error: {
        code: 'outcome_unknown',
        message: 'The vault transfer outcome is unknown. Sync before retrying.',
      },
    }));
    expect(JSON.stringify(port.sent)).not.toContain('VaultTransferControllerError');
  });
});
