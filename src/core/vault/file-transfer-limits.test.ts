import { describe, expect, it } from 'vitest';
import { LEGACY_FILE_MESSAGE_MAX_JSON_BYTES, assertLegacyFileMessageBudget, base64EncodedLength } from './file-transfer-limits.js';

describe('legacy file message budget', () => {
  it('derives the remaining base64 budget from the complete UTF-8 JSON envelope', () => {
    const envelope = { ok: true, data: { fileName: 'report-\u00e9.pdf', dataB64: '' } };
    const overhead = new TextEncoder().encode(JSON.stringify(envelope)).byteLength;
    expect(() => assertLegacyFileMessageBudget(envelope, LEGACY_FILE_MESSAGE_MAX_JSON_BYTES - overhead)).not.toThrow();
    expect(() => assertLegacyFileMessageBudget(envelope, LEGACY_FILE_MESSAGE_MAX_JSON_BYTES - overhead + 1)).toThrow('chunked file transfer');
  });

  it('rejects a 48 MiB file before constructing its 64 MiB base64 plus JSON response', () => {
    const encodedLength = base64EncodedLength(48 * 1024 * 1024);
    expect(encodedLength).toBe(LEGACY_FILE_MESSAGE_MAX_JSON_BYTES);
    expect(() => assertLegacyFileMessageBudget({ ok: true, data: { fileName: 'a', dataB64: '' } }, encodedLength)).toThrow('chunked file transfer');
    expect(() => assertLegacyFileMessageBudget({ dataB64: '' }, base64EncodedLength(3))).not.toThrow();
  });
});
