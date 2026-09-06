import { uploadBinaryTransfer, downloadBinaryTransfer } from '../../src/ui/binary-transfer-client.ts';
import {
  BINARY_TRANSFER_PORT_NAME,
  MAX_BINARY_TRANSFER_CHUNK_BYTES,
} from '../../src/messaging/binary-transfer-port.ts';
import { digestBytes, fillPayload } from './payload.mjs';

let clientStats = freshClientStats();
let rawPort;
let rawState;
let operation;

function observedConnection({ abort, cancelAfterAck = false, holdDownloadAck = false } = {}) {
  return (name) => {
    const nativePort = chrome.runtime.connect({ name });
    nativePort.onMessage.addListener((message) => {
      if (message.type === 'ack') {
        clientStats.uploadAcks += 1;
        clientStats.pendingUploadChunks -= 1;
        if (cancelAfterAck) abort.abort();
      }
      if (message.type === 'chunk') clientStats.downloadChunks += 1;
    });
    // All observed messages still cross a native runtime Port. Only the explicit stalled-download
    // scenario withholds an outgoing ACK, as a real paused or unresponsive consumer would.
    return {
      onMessage: nativePort.onMessage,
      onDisconnect: nativePort.onDisconnect,
      postMessage(message) {
        if (message.type === 'chunk') {
          clientStats.uploadChunks += 1;
          clientStats.pendingUploadChunks += 1;
          clientStats.maxPendingUploadChunks = Math.max(clientStats.maxPendingUploadChunks, clientStats.pendingUploadChunks);
        }
        if (message.type === 'ack' && holdDownloadAck) {
          clientStats.heldAck = message.sequence;
          return;
        }
        nativePort.postMessage(message);
      },
      disconnect: () => nativePort.disconnect(),
    };
  };
}

function makeFile(size) {
  const parts = [];
  for (let offset = 0; offset < size; offset += MAX_BINARY_TRANSFER_CHUNK_BYTES) {
    const bytes = fillPayload(new Uint8Array(Math.min(MAX_BINARY_TRANSFER_CHUNK_BYTES, size - offset)), offset);
    parts.push(new Blob([bytes]));
    bytes.fill(0);
  }
  return new File(parts, 'synthetic-upload.bin', { type: 'application/octet-stream' });
}

function downloadRequest() {
  return { type: 'vault.getAttachment', cipherId: 'synthetic-cipher', attachmentId: 'synthetic-attachment' };
}

globalThis.binaryTransportPage = {
  async upload({ kind, size, cancelAfterAck = false }) {
    clientStats = freshClientStats();
    const abort = new AbortController();
    const file = makeFile(size);
    const request = kind === 'send'
      ? { type: 'sends.createFile', input: { name: 'Synthetic browser verification' }, fileName: file.name, expectedBytes: size }
      : { type: 'vault.addAttachment', cipherId: 'synthetic-cipher', fileName: file.name, expectedBytes: size };
    const result = await uploadBinaryTransfer(request, file, {
      connectPort: observedConnection({ abort, cancelAfterAck }),
      signal: abort.signal,
    });
    return { result, ...clientStats };
  },
  async download() {
    clientStats = freshClientStats();
    const result = await downloadBinaryTransfer(downloadRequest(), { connectPort: observedConnection() });
    if (!result.ok) return { result, ...clientStats };
    const bytes = new Uint8Array(await result.data.blob.arrayBuffer());
    try {
      return {
        result: { ok: true, fileName: result.data.fileName, byteLength: result.data.blob.size, sha256: await digestBytes(bytes) },
        ...clientStats,
      };
    } finally {
      bytes.fill(0);
    }
  },
  startStalledDownload() {
    clientStats = freshClientStats();
    operation = downloadBinaryTransfer(downloadRequest(), {
      connectPort: observedConnection({ holdDownloadAck: true }),
    }).then((result) => {
      clientStats.finished = true;
      return result.ok
        ? { ok: true, byteLength: result.data.blob.size }
        : result;
    });
  },
  finishStalledDownload: () => operation,
  clientSnapshot: () => ({ ...clientStats }),
  startRawDownload() {
    rawState = { chunks: [], done: false, disconnected: false, errors: [] };
    rawPort = chrome.runtime.connect({ name: BINARY_TRANSFER_PORT_NAME });
    rawPort.onMessage.addListener((message) => {
      if (message.type === 'chunk') rawState.chunks.push({ sequence: message.sequence, byteLength: message.byteLength });
      if (message.type === 'done') rawState.done = true;
      if (message.type === 'error') rawState.errors.push(message.error.code);
    });
    rawPort.onDisconnect.addListener(() => { rawState.disconnected = true; });
    rawPort.postMessage({ version: 1, type: 'begin', request: downloadRequest() });
  },
  rawSnapshot: () => ({ ...rawState }),
  acknowledge: (sequence) => rawPort.postMessage({ version: 1, type: 'ack', sequence }),
  cancelRaw() {
    rawPort.postMessage({ version: 1, type: 'cancel' });
    // Let the worker process the protocol cancellation and close its end of the actual Port.
  },
};

function freshClientStats() {
  return {
    uploadChunks: 0, uploadAcks: 0, pendingUploadChunks: 0, maxPendingUploadChunks: 0,
    downloadChunks: 0, heldAck: null, finished: false,
  };
}
