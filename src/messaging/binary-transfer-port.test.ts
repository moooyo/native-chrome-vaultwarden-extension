import { describe, expect, it } from 'vitest';
import {
  MAX_ATTACHMENT_FILE_BYTES,
  MAX_BINARY_TRANSFER_CHUNK_BYTES,
  MAX_SEND_FILE_BYTES,
  decodeBinaryTransferChunk,
  encodeBinaryTransferChunk,
  parseBinaryTransferClientMessage,
} from './binary-transfer-port.js';

describe('binary transfer protocol', () => {
  it('preserves supported Send and attachment capacities while bounding each chunk', () => {
    for (const request of [
      { type: 'sends.createFile', input: { name: 'Large Send' }, fileName: 'file.bin', expectedBytes: MAX_SEND_FILE_BYTES },
      { type: 'vault.addAttachment', cipherId: 'cipher-a', fileName: 'file.bin', expectedBytes: MAX_ATTACHMENT_FILE_BYTES },
    ]) {
      expect(parseBinaryTransferClientMessage({ version: 1, type: 'begin', request })).toMatchObject({ request });
      expect(() => parseBinaryTransferClientMessage({ version: 1, type: 'begin', request: { ...request, expectedBytes: request.expectedBytes + 1 } })).toThrow();
    }
    const bytes = new Uint8Array(MAX_BINARY_TRANSFER_CHUNK_BYTES).fill(255);
    expect(decodeBinaryTransferChunk(encodeBinaryTransferChunk(bytes), bytes.byteLength)).toEqual(bytes);
    expect(() => encodeBinaryTransferChunk(new Uint8Array(MAX_BINARY_TRANSFER_CHUNK_BYTES + 1))).toThrow();
  });

  it('rejects malformed sequences, oversized strings, noncanonical base64, and hidden request fields', () => {
    const valid = { version: 1, type: 'chunk', sequence: 0, byteLength: 1, dataBase64: 'AQ==' };
    expect(parseBinaryTransferClientMessage(valid)).toEqual(valid);
    for (const change of [
      { sequence: -1 }, { sequence: 0.5 }, { byteLength: 2 }, { byteLength: 0 },
      { dataBase64: 'AR==' }, { dataBase64: 'AQ' },
      { dataBase64: 'A'.repeat(Math.ceil(MAX_BINARY_TRANSFER_CHUNK_BYTES / 3) * 4 + 4) },
      { accountId: 'another-account' },
    ]) expect(() => parseBinaryTransferClientMessage({ ...valid, ...change })).toThrow();
    expect(() => parseBinaryTransferClientMessage({ version: 1, type: 'begin', request: { type: 'vault.getField', id: 'cipher-a', field: 'login.password' } })).toThrow();
    expect(() => parseBinaryTransferClientMessage({ version: 1, type: 'begin', request: { type: 'vault.getAttachment', cipherId: 'cipher-a', attachmentId: 'attachment-a', documentId: 'other-document' } })).toThrow();
  });
});
