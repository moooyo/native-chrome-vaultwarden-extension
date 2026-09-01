import { describe, expect, it, vi } from 'vitest';
import {
  MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES,
  MAX_VAULT_TRANSFER_PORT_ENCODED_CHUNK_CHARS,
  MAX_VAULT_TRANSFER_PORT_TOTAL_BYTES,
  VAULT_TRANSFER_PORT_ERROR_MESSAGES,
  VAULT_TRANSFER_PORT_NAME,
  VaultTransferPortProtocolError,
  canClearVaultTransferRecovery,
  createVaultTransferPortErrorMessage,
  decodeVaultTransferPortChunk,
  encodeVaultTransferPortChunk,
  importPasswordForDetectedFormat,
  parseVaultTransferClientMessage,
  parseVaultTransferWorkerMessage,
  type VaultTransferClientMessage,
  type VaultTransferPortPreviewModel,
  type VaultTransferRecoveryStatus,
  type VaultTransferWorkerMessage,
} from './vault-transfer-port.js';

const TRANSFER_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const PREVIEW_REVISION = '22222222-2222-4222-8222-222222222222';
const EXPORT_AUTHORIZATION_ID = '33333333-3333-4333-8333-333333333333';
const ORGANIZATION_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

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

const RECOVERY_STATUS: VaultTransferRecoveryStatus = {
  count: 1,
  unresolvedUnknownCount: 1,
  reconcileRequiredCount: 0,
  omittedCount: 0,
  barriers: [{
    transferId: TRANSFER_ID,
    reason: 'outcome_unknown',
    reconciled: true,
    clearable: true,
  }],
};

function jsonClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function expectProtocolCode(action: () => unknown, code: string): void {
  try {
    action();
    throw new Error('Expected protocol parsing to fail');
  } catch (error) {
    expect(error).toBeInstanceOf(VaultTransferPortProtocolError);
    expect((error as VaultTransferPortProtocolError).code).toBe(code);
  }
}

describe('vault transfer port chunk codec', () => {
  it('zeroes parser-only decoded copies in both chunk directions', () => {
    const fill = vi.spyOn(Uint8Array.prototype, 'fill');
    const encoded = encodeVaultTransferPortChunk(new Uint8Array([1, 2, 3]));
    try {
      parseVaultTransferClientMessage({
        version: 1,
        type: 'import.chunk',
        transferId: TRANSFER_ID,
        sequence: 0,
        byteLength: 3,
        dataBase64: encoded,
      });
      parseVaultTransferWorkerMessage({
        version: 1,
        type: 'export.chunk',
        transferId: TRANSFER_ID,
        format: 'json',
        phase: 'exporting',
        sequence: 0,
        byteLength: 3,
        dataBase64: encoded,
      });
      expect(fill.mock.calls.filter(([value]) => value === 0)).toHaveLength(2);
    } finally {
      fill.mockRestore();
    }
  });

  it('uses a stable MV3 port name and a 256 KiB binary chunk ceiling', () => {
    expect(VAULT_TRANSFER_PORT_NAME).toBe('vault-transfer-v1');
    expect(MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES).toBe(256 * 1024);
    expect(MAX_VAULT_TRANSFER_PORT_ENCODED_CHUNK_CHARS).toBe(349_528);
  });

  it('round-trips canonical padded base64 without sharing the input buffer', () => {
    const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
    const encoded = encodeVaultTransferPortChunk(bytes);
    const decoded = decodeVaultTransferPortChunk(encoded, bytes.byteLength);

    expect(encoded).toBe('AAEC/f7/');
    expect(decoded).toEqual(bytes);
    expect(decoded).not.toBe(bytes);
  });

  it('accepts the exact maximum chunk and rejects bytes above it before encoding', () => {
    const maximum = new Uint8Array(MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES).fill(0xa5);
    const encoded = encodeVaultTransferPortChunk(maximum);
    expect(encoded).toHaveLength(MAX_VAULT_TRANSFER_PORT_ENCODED_CHUNK_CHARS);
    expect(decodeVaultTransferPortChunk(encoded, maximum.byteLength)).toEqual(maximum);

    expectProtocolCode(
      () => encodeVaultTransferPortChunk(new Uint8Array(MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES + 1)),
      'chunk_too_large',
    );
  });

  it.each([
    ['', 'empty'],
    ['Zg', 'unpadded'],
    ['Zg===', 'overpadded'],
    ['Zh==', 'non-zero padding bits'],
    ['Zg==\n', 'whitespace'],
    ['_w==', 'base64url alphabet'],
    ['****', 'invalid alphabet'],
  ])('rejects non-canonical base64: %s (%s)', (encoded) => {
    expectProtocolCode(() => decodeVaultTransferPortChunk(encoded), 'invalid_chunk');
  });

  it('checks the encoded cap and declared decoded length', () => {
    const oversized = 'AAAA'.repeat((MAX_VAULT_TRANSFER_PORT_ENCODED_CHUNK_CHARS / 4) + 1);
    expectProtocolCode(() => decodeVaultTransferPortChunk(oversized), 'chunk_too_large');
    expectProtocolCode(() => decodeVaultTransferPortChunk('Zg==', 2), 'invalid_chunk');
  });
});

describe('client to worker messages', () => {
  const messages: VaultTransferClientMessage[] = [
    { version: 1, type: 'import.begin', expectedTotalBytes: 3, fileName: 'vault.json' },
    {
      version: 1,
      type: 'import.chunk',
      transferId: TRANSFER_ID,
      sequence: 0,
      byteLength: 3,
      dataBase64: 'AQID',
    },
    { version: 1, type: 'import.seal', transferId: TRANSFER_ID },
    { version: 1, type: 'import.seal', transferId: TRANSFER_ID, password: 'correct horse' },
    {
      version: 1,
      type: 'import.confirm',
      transferId: TRANSFER_ID,
      previewRevision: PREVIEW_REVISION,
    },
    { version: 1, type: 'import.result.ack', transferId: TRANSFER_ID },
    { version: 1, type: 'cancel', transferId: TRANSFER_ID },
    {
      version: 1, type: 'export.begin', format: 'json',
      authorizationId: EXPORT_AUTHORIZATION_ID, target: { kind: 'personal' },
    },
    {
      version: 1, type: 'export.begin', format: 'csv',
      authorizationId: EXPORT_AUTHORIZATION_ID, target: { kind: 'personal' },
    },
    {
      version: 1, type: 'export.begin', format: 'zip',
      authorizationId: EXPORT_AUTHORIZATION_ID, target: { kind: 'personal' },
    },
    {
      version: 1, type: 'export.begin', format: 'encrypted-json',
      authorizationId: EXPORT_AUTHORIZATION_ID, target: { kind: 'personal' },
      filePassword: 'correct horse',
    },
    { version: 1, type: 'export.ack', transferId: TRANSFER_ID, sequence: 0 },
    { version: 1, type: 'recovery.inspect' },
    {
      version: 1,
      type: 'recovery.clear',
      expectedBarriers: [{ transferId: TRANSFER_ID, reason: 'outcome_unknown' }],
    },
  ];

  it('round-trips every supported message through Chrome-compatible JSON serialization', () => {
    for (const message of messages) {
      expect(parseVaultTransferClientMessage(jsonClone(message))).toEqual(message);
    }
  });

  it('keeps import format worker-authoritative and confirmationId worker-private', () => {
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1,
      type: 'import.begin',
      expectedTotalBytes: 3,
      fileName: 'vault.json',
      format: 'json',
    }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1,
      type: 'import.confirm',
      transferId: TRANSFER_ID,
      previewRevision: PREVIEW_REVISION,
      confirmationId: '33333333-3333-4333-8333-333333333333',
    }), 'invalid_message');
  });

  it('allows a seal password to be consumed only after authoritative encrypted-JSON detection', () => {
    const encrypted = parseVaultTransferClientMessage({
      version: 1,
      type: 'import.seal',
      transferId: TRANSFER_ID,
      password: 'secret value',
    });
    expect(encrypted.type).toBe('import.seal');
    if (encrypted.type !== 'import.seal') throw new Error('Unexpected message');
    expect(importPasswordForDetectedFormat(encrypted, 'encrypted-json')).toBe('secret value');
    expectProtocolCode(() => importPasswordForDetectedFormat(encrypted, 'json'), 'password_not_allowed');
    expectProtocolCode(() => importPasswordForDetectedFormat(encrypted, 'csv'), 'password_not_allowed');
    expectProtocolCode(() => importPasswordForDetectedFormat(encrypted, 'zip'), 'password_not_allowed');

    const plain = parseVaultTransferClientMessage({
      version: 1,
      type: 'import.seal',
      transferId: TRANSFER_ID,
    });
    if (plain.type !== 'import.seal') throw new Error('Unexpected message');
    expect(importPasswordForDetectedFormat(plain, 'json')).toBeUndefined();
    expectProtocolCode(() => importPasswordForDetectedFormat(plain, 'encrypted-json'), 'password_required');
  });

  it('uses exact encrypted-JSON shapes for account-bound and file-password exports', () => {
    expect(parseVaultTransferClientMessage({
      version: 1, type: 'export.begin', format: 'encrypted-json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
    })).toEqual({
      version: 1, type: 'export.begin', format: 'encrypted-json',
      authorizationId: EXPORT_AUTHORIZATION_ID, target: { kind: 'personal' },
    });
    expect(parseVaultTransferClientMessage({
      version: 1, type: 'export.begin', format: 'encrypted-json',
      authorizationId: EXPORT_AUTHORIZATION_ID, target: { kind: 'personal' },
      filePassword: 'file-secret',
    })).toMatchObject({
      format: 'encrypted-json', target: { kind: 'personal' }, filePassword: 'file-secret',
    });
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1, type: 'export.begin', format: 'encrypted-json',
      authorizationId: EXPORT_AUTHORIZATION_ID, filePassword: '',
    }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1, type: 'export.begin', format: 'json',
      authorizationId: EXPORT_AUTHORIZATION_ID, filePassword: 'must-not-be-used',
    }), 'password_not_allowed');
    expect(parseVaultTransferClientMessage({
      version: 1, type: 'export.begin', format: 'csv',
      authorizationId: EXPORT_AUTHORIZATION_ID,
    })).toMatchObject({ format: 'csv', target: { kind: 'personal' } });
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1, type: 'export.begin', format: 'csv',
      authorizationId: EXPORT_AUTHORIZATION_ID, filePassword: 'must-not-be-used',
    }), 'password_not_allowed');
  });

  it('defaults legacy exports to personal and canonicalizes exact organization targets', () => {
    expect(parseVaultTransferClientMessage({
      version: 1, type: 'export.begin', format: 'json',
      authorizationId: EXPORT_AUTHORIZATION_ID,
    })).toEqual({
      version: 1, type: 'export.begin', format: 'json',
      authorizationId: EXPORT_AUTHORIZATION_ID, target: { kind: 'personal' },
    });

    const supplied = {
      kind: 'organization' as const,
      organizationId: ORGANIZATION_ID.toUpperCase(),
    };
    const parsed = parseVaultTransferClientMessage({
      version: 1, type: 'export.begin', format: 'json',
      authorizationId: EXPORT_AUTHORIZATION_ID, target: supplied,
    });
    expect(parsed).toMatchObject({
      type: 'export.begin',
      target: { kind: 'organization', organizationId: ORGANIZATION_ID },
    });
    if (parsed.type !== 'export.begin') throw new Error('Unexpected message');
    expect(parsed.target).not.toBe(supplied);
    expect(Object.isFrozen(parsed.target)).toBe(true);

    for (const target of [
      { kind: 'organization' },
      { kind: 'organization', organizationId: 'not-an-id' },
      { kind: 'organization', organizationId: ORGANIZATION_ID, extra: true },
      { kind: 'personal', organizationId: ORGANIZATION_ID },
    ]) {
      expectProtocolCode(() => parseVaultTransferClientMessage({
        version: 1, type: 'export.begin', format: 'json',
        authorizationId: EXPORT_AUTHORIZATION_ID, target,
      }), 'invalid_message');
    }
  });

  it('rejects organization ZIP exports at the protocol boundary', () => {
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1, type: 'export.begin', format: 'zip',
      authorizationId: EXPORT_AUTHORIZATION_ID,
      target: { kind: 'organization', organizationId: ORGANIZATION_ID },
    }), 'invalid_message');
  });

  it('requires every export begin to carry one canonical opaque authorization', () => {
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1, type: 'export.begin', format: 'json',
    }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1, type: 'export.begin', format: 'json', authorizationId: 'not-a-grant',
    }), 'invalid_message');
  });

  it('requires each export acknowledgement to bind a transfer and exact sequence', () => {
    expect(parseVaultTransferClientMessage({
      version: 1, type: 'export.ack', transferId: TRANSFER_ID, sequence: 17,
    })).toEqual({ version: 1, type: 'export.ack', transferId: TRANSFER_ID, sequence: 17 });
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1, type: 'export.ack', transferId: TRANSFER_ID, sequence: 1.5,
    }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1, type: 'export.ack', transferId: TRANSFER_ID, sequence: 0, nextSequence: 1,
    }), 'invalid_message');
  });

  it('accepts only an exact transfer-bound import result acknowledgement', () => {
    expect(parseVaultTransferClientMessage({
      version: 1,
      type: 'import.result.ack',
      transferId: TRANSFER_ID,
    })).toEqual({ version: 1, type: 'import.result.ack', transferId: TRANSFER_ID });
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1,
      type: 'import.result.ack',
      transferId: TRANSFER_ID,
      status: 'completed',
    }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1,
      type: 'import.result.ack',
      transferId: TRANSFER_ID.toUpperCase(),
    }), 'invalid_message');
  });

  it('rejects binary structured-clone values instead of treating them as chunk data', () => {
    for (const dataBase64 of [new Uint8Array([1, 2, 3]), new ArrayBuffer(3)]) {
      expectProtocolCode(() => parseVaultTransferClientMessage({
        version: 1,
        type: 'import.chunk',
        transferId: TRANSFER_ID,
        sequence: 0,
        byteLength: 3,
        dataBase64,
      }), 'invalid_message');
    }
  });

  it('rejects length, sequence, version, UUID, and filename defects', () => {
    const begin = { version: 1, type: 'import.begin', expectedTotalBytes: 3, fileName: 'vault.json' };
    for (const expectedTotalBytes of [-1, 1.5, Number.NaN, MAX_VAULT_TRANSFER_PORT_TOTAL_BYTES + 1]) {
      expectProtocolCode(
        () => parseVaultTransferClientMessage({ ...begin, expectedTotalBytes }),
        'invalid_message',
      );
    }
    for (const fileName of ['', '.', '..', '../vault.json', 'folder\\vault.json', 'bad\u0000.json']) {
      expectProtocolCode(() => parseVaultTransferClientMessage({ ...begin, fileName }), 'invalid_message');
    }
    expectProtocolCode(
      () => parseVaultTransferClientMessage({ ...begin, version: 2 }),
      'unsupported_version',
    );
    expectProtocolCode(
      () => parseVaultTransferClientMessage({ type: 'import.begin', expectedTotalBytes: 3, fileName: 'vault.json' }),
      'invalid_message',
    );
    expectProtocolCode(
      () => parseVaultTransferClientMessage({ ...begin, version: '1' }),
      'invalid_message',
    );
    expectProtocolCode(
      () => parseVaultTransferClientMessage({ ...begin, version: Number.NaN }),
      'invalid_message',
    );
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1,
      type: 'import.chunk',
      transferId: TRANSFER_ID.toUpperCase(),
      sequence: 0,
      byteLength: 3,
      dataBase64: 'AQID',
    }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1,
      type: 'import.chunk',
      transferId: TRANSFER_ID,
      sequence: -1,
      byteLength: 3,
      dataBase64: 'AQID',
    }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1,
      type: 'import.chunk',
      transferId: TRANSFER_ID,
      sequence: 0,
      byteLength: 2,
      dataBase64: 'AQID',
    }), 'invalid_chunk');
  });

  it('rejects unknown, inherited, accessor, and non-enumerable fields', () => {
    const valid = { version: 1, type: 'cancel', transferId: TRANSFER_ID };
    expectProtocolCode(
      () => parseVaultTransferClientMessage({ ...valid, secret: 'do not accept' }),
      'invalid_message',
    );
    expectProtocolCode(
      () => parseVaultTransferClientMessage(Object.create(valid) as unknown),
      'invalid_message',
    );

    const accessor = { ...valid } as Record<string, unknown>;
    Object.defineProperty(accessor, 'transferId', { enumerable: true, get: () => TRANSFER_ID });
    expectProtocolCode(() => parseVaultTransferClientMessage(accessor), 'invalid_message');

    const hidden = { ...valid } as Record<string, unknown>;
    Object.defineProperty(hidden, 'secret', { enumerable: false, value: 'hidden' });
    expectProtocolCode(() => parseVaultTransferClientMessage(hidden), 'invalid_message');

    const versionAccessor = { ...valid } as Record<string, unknown>;
    Object.defineProperty(versionAccessor, 'version', { enumerable: true, get: () => 1 });
    expectProtocolCode(() => parseVaultTransferClientMessage(versionAccessor), 'invalid_message');
  });

  it('does not include supplied passwords in stable protocol failures', () => {
    const password = 'top-secret-password';
    try {
      parseVaultTransferClientMessage({
        version: 1, type: 'export.begin', format: 'json',
        authorizationId: EXPORT_AUTHORIZATION_ID, filePassword: password,
      });
      throw new Error('Expected protocol parsing to fail');
    } catch (error) {
      expect(String(error)).not.toContain(password);
      expect(JSON.stringify(error)).not.toContain(password);
    }
  });
});

describe('worker to client messages', () => {
  const messages: VaultTransferWorkerMessage[] = [
    {
      version: 1,
      type: 'import.begun',
      transferId: TRANSFER_ID,
      phase: 'uploading',
      maxChunkBytes: MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES,
      maxEncodedChunkChars: MAX_VAULT_TRANSFER_PORT_ENCODED_CHUNK_CHARS,
    },
    {
      version: 1,
      type: 'import.ack',
      transferId: TRANSFER_ID,
      phase: 'uploading',
      sequence: 0,
      nextSequence: 1,
      byteLength: 3,
      totalBytes: 3,
    },
    {
      version: 1,
      type: 'import.preview',
      transferId: TRANSFER_ID,
      previewRevision: PREVIEW_REVISION,
      preview: PREVIEW,
    },
    {
      version: 1,
      type: 'import.result',
      transferId: TRANSFER_ID,
      phase: 'completed',
      status: 'completed',
      counts: { committed: 3, rejected: 0, skipped: 0, outcomeUnknown: 0 },
      mustSyncBeforeRetry: false,
    },
    {
      version: 1,
      type: 'export.begun',
      transferId: TRANSFER_ID,
      format: 'zip',
      phase: 'exporting',
      fileName: 'vault.zip',
    },
    {
      version: 1,
      type: 'export.chunk',
      transferId: TRANSFER_ID,
      format: 'zip',
      phase: 'exporting',
      sequence: 0,
      byteLength: 3,
      dataBase64: 'AQID',
    },
    {
      version: 1,
      type: 'export.done',
      transferId: TRANSFER_ID,
      format: 'zip',
      phase: 'completed',
      chunkCount: 1,
      totalBytes: 3,
      clientEventAckId: PREVIEW_REVISION,
    },
    {
      version: 1,
      type: 'recovery.status',
      phase: 'completed',
      status: RECOVERY_STATUS,
    },
    {
      version: 1,
      type: 'recovery.cleared',
      phase: 'completed',
      cleared: 1,
    },
    createVaultTransferPortErrorMessage('expired', TRANSFER_ID, 'uploading'),
  ];

  it('round-trips every supported message through Chrome-compatible JSON serialization', () => {
    for (const message of messages) {
      expect(parseVaultTransferWorkerMessage(jsonClone(message))).toEqual(message);
      expect(JSON.stringify(message)).not.toContain('password');
    }
  });

  it('binds acknowledgements and terminal result invariants', () => {
    const ack = messages[1]!;
    expectProtocolCode(() => parseVaultTransferWorkerMessage({ ...ack, nextSequence: 2 }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferWorkerMessage({ ...ack, totalBytes: 2 }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferWorkerMessage({
      ...ack, sequence: 3, nextSequence: 4, totalBytes: 3,
    }), 'invalid_message');

    const completed = messages[3]!;
    expectProtocolCode(() => parseVaultTransferWorkerMessage({
      ...completed,
      counts: { committed: 2, rejected: 1, skipped: 0, outcomeUnknown: 0 },
    }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferWorkerMessage({
      ...completed,
      status: 'outcome_unknown',
      counts: { committed: 2, rejected: 0, skipped: 0, outcomeUnknown: 0 },
      mustSyncBeforeRetry: true,
    }), 'invalid_message');
  });

  it('validates type-specific format and phase literals', () => {
    const begun = messages[0]!;
    expectProtocolCode(
      () => parseVaultTransferWorkerMessage({ ...begun, phase: 'inspecting' }),
      'invalid_message',
    );
    expectProtocolCode(() => parseVaultTransferWorkerMessage({
      ...begun,
      maxEncodedChunkChars: MAX_VAULT_TRANSFER_PORT_ENCODED_CHUNK_CHARS - 4,
    }), 'invalid_message');

    const chunk = messages[5]!;
    expect(parseVaultTransferWorkerMessage({ ...chunk, format: 'csv' }))
      .toMatchObject({ type: 'export.chunk', format: 'csv' });
    expectProtocolCode(
      () => parseVaultTransferWorkerMessage({ ...chunk, phase: 'completed' }),
      'invalid_message',
    );
  });

  it('requires a bounded value-free review exactly for CSV export', () => {
    const review = {
      exportedItemCount: 2,
      omittedItemCount: 1,
      warnings: [
        { code: 'ssh_key_items_omitted', count: 1 },
        { code: 'passkeys_omitted', count: 2 },
      ],
    };
    const begun = {
      version: 1, type: 'export.begun', transferId: TRANSFER_ID, format: 'csv',
      phase: 'exporting', fileName: 'vault.csv', review,
    };
    expect(parseVaultTransferWorkerMessage(begun)).toEqual(begun);
    expectProtocolCode(
      () => parseVaultTransferWorkerMessage({ ...begun, review: undefined }),
      'invalid_message',
    );
    expectProtocolCode(
      () => parseVaultTransferWorkerMessage({ ...begun, format: 'json' }),
      'invalid_message',
    );
    expectProtocolCode(() => parseVaultTransferWorkerMessage({
      ...begun,
      review: {
        ...review,
        warnings: [{ code: 'passkeys_omitted', count: 1, path: '$.items[0].login' }],
      },
    }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferWorkerMessage({
      ...begun,
      review: {
        ...review,
        warnings: [
          { code: 'passkeys_omitted', count: 1 },
          { code: 'ssh_key_items_omitted', count: 1 },
        ],
      },
    }), 'invalid_message');
  });

  it('requires empty and non-empty export terminal counts to agree', () => {
    const done = messages[6]!;
    expectProtocolCode(
      () => parseVaultTransferWorkerMessage({ ...done, chunkCount: 0, totalBytes: 3 }),
      'invalid_message',
    );
    expectProtocolCode(
      () => parseVaultTransferWorkerMessage({ ...done, chunkCount: 1, totalBytes: 0 }),
      'invalid_message',
    );
    expectProtocolCode(
      () => parseVaultTransferWorkerMessage({ ...done, chunkCount: 4, totalBytes: 3 }),
      'invalid_message',
    );
    expect(parseVaultTransferWorkerMessage({ ...done, chunkCount: 0, totalBytes: 0 }))
      .toMatchObject({ chunkCount: 0, totalBytes: 0 });
    expectProtocolCode(
      () => parseVaultTransferWorkerMessage({ ...done, clientEventAckId: 'not-a-uuid' }),
      'invalid_message',
    );
  });

  it('allows only aggregate, categorized preview diagnostics', () => {
    const previewMessage = messages[2]!;
    const sanitized = {
      ...PREVIEW,
      canCommit: false,
      diagnostics: {
        errors: [{ code: 'malformed_input', count: 1 }],
        warnings: [{ code: 'partial_result', count: 2 }],
        unsupported: [],
      },
    };
    expect(parseVaultTransferWorkerMessage({ ...previewMessage, preview: sanitized }))
      .toMatchObject({ preview: sanitized });

    for (const entry of [
      { code: 'malformed_input', count: 1, message: 'raw imported password' },
      { code: 'malformed_input', count: 1, path: '$.items[0].login.password' },
      { code: 'malformed_input', count: 1, sourceIndex: 0 },
      { code: 'secret_value_here', count: 1 },
    ]) {
      expectProtocolCode(() => parseVaultTransferWorkerMessage({
        ...previewMessage,
        preview: {
          ...PREVIEW,
          canCommit: false,
          diagnostics: { errors: [entry], warnings: [], unsupported: [] },
        },
      }), 'invalid_message');
    }
  });

  it('rejects duplicate or unbounded diagnostics and contradictory canCommit state', () => {
    const previewMessage = messages[2]!;
    const diagnostic = { code: 'other', count: 1 };
    for (const errors of [
      [diagnostic, diagnostic],
      Array.from({ length: 33 }, () => diagnostic),
    ]) {
      expectProtocolCode(() => parseVaultTransferWorkerMessage({
        ...previewMessage,
        preview: {
          ...PREVIEW,
          canCommit: false,
          diagnostics: { errors, warnings: [], unsupported: [] },
        },
      }), 'invalid_message');
    }
    expectProtocolCode(() => parseVaultTransferWorkerMessage({
      ...previewMessage,
      preview: {
        ...PREVIEW,
        diagnostics: { errors: [{ code: 'other', count: 1 }], warnings: [], unsupported: [] },
      },
    }), 'invalid_message');

    const diagnosticsWithProperty = [{ code: 'other', count: 1 }];
    Object.assign(diagnosticsWithProperty, { secret: 'not serialized as an array item' });
    expectProtocolCode(() => parseVaultTransferWorkerMessage({
      ...previewMessage,
      preview: {
        ...PREVIEW,
        canCommit: false,
        diagnostics: { errors: diagnosticsWithProperty, warnings: [], unsupported: [] },
      },
    }), 'invalid_message');

    const sparse = new Array(1) as unknown[];
    expectProtocolCode(() => parseVaultTransferWorkerMessage({
      ...previewMessage,
      preview: {
        ...PREVIEW,
        canCommit: false,
        diagnostics: { errors: sparse, warnings: [], unsupported: [] },
      },
    }), 'invalid_message');
  });

  it('rebuilds nested previews instead of returning attacker-owned objects', () => {
    const source = jsonClone(messages[2]!) as Extract<VaultTransferWorkerMessage, { type: 'import.preview' }>;
    const parsed = parseVaultTransferWorkerMessage(source);
    if (parsed.type !== 'import.preview') throw new Error('Unexpected message');
    expect(parsed.preview).not.toBe(source.preview);
    expect(parsed.preview.counts).not.toBe(source.preview.counts);
    expect(parsed.preview.diagnostics).not.toBe(source.preview.diagnostics);
  });

  it('accepts only fixed safe error messages and no detail fields', () => {
    const error = createVaultTransferPortErrorMessage('outcome_unknown', TRANSFER_ID, 'committing');
    expect(error.error.message).toBe(VAULT_TRANSFER_PORT_ERROR_MESSAGES.outcome_unknown);
    expect(parseVaultTransferWorkerMessage(error)).toEqual(error);

    expectProtocolCode(() => parseVaultTransferWorkerMessage({
      ...error,
      error: { ...error.error, message: 'Failed on password hunter2' },
    }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferWorkerMessage({
      ...error,
      error: { ...error.error, detail: 'server response body' },
    }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferWorkerMessage({
      ...error,
      error: { code: 'new_server_error', message: 'Something happened.' },
    }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferWorkerMessage({
      ...error,
      error: { code: 'toString', message: Function.prototype.toString.toString() },
    }), 'invalid_message');
    expectProtocolCode(
      () => createVaultTransferPortErrorMessage('toString' as never, null, 'idle'),
      'invalid_message',
    );
  });

  it('rejects confirmationId on every worker-visible preview/result surface', () => {
    for (const index of [2, 3]) {
      expectProtocolCode(() => parseVaultTransferWorkerMessage({
        ...messages[index]!,
        confirmationId: '33333333-3333-4333-8333-333333333333',
      }), 'invalid_message');
    }
  });

  it('accepts only bounded secret-free recovery status fields', () => {
    const parsed = parseVaultTransferWorkerMessage({
      version: 1,
      type: 'recovery.status',
      phase: 'completed',
      status: RECOVERY_STATUS,
    });
    expect(parsed).toMatchObject({ type: 'recovery.status', status: RECOVERY_STATUS });
    if (parsed.type !== 'recovery.status') throw new Error('Unexpected message');
    expect(canClearVaultTransferRecovery(parsed.status)).toBe(true);
    expect(JSON.stringify(parsed)).not.toMatch(/account|digest|source|error/i);

    for (const secret of [
      { accountIdentityDigest: 'a'.repeat(64) },
      { sourceDigest: 'b'.repeat(64) },
      { rawError: 'private server response' },
    ]) {
      expectProtocolCode(() => parseVaultTransferWorkerMessage({
        version: 1,
        type: 'recovery.status',
        phase: 'completed',
        status: { ...RECOVERY_STATUS, ...secret },
      }), 'invalid_message');
    }
  });

  it('rejects malformed, incomplete, duplicate, and contradictory recovery status', () => {
    const base = {
      version: 1,
      type: 'recovery.status',
      phase: 'completed',
      status: RECOVERY_STATUS,
    };
    for (const status of [
      { ...RECOVERY_STATUS, count: 2 },
      { ...RECOVERY_STATUS, omittedCount: 1 },
      { ...RECOVERY_STATUS, unresolvedUnknownCount: 0 },
      {
        ...RECOVERY_STATUS,
        barriers: [RECOVERY_STATUS.barriers[0], RECOVERY_STATUS.barriers[0]],
        count: 2,
      },
      {
        ...RECOVERY_STATUS,
        barriers: [{ ...RECOVERY_STATUS.barriers[0], reconciled: false, clearable: true }],
      },
      {
        ...RECOVERY_STATUS,
        barriers: [{ ...RECOVERY_STATUS.barriers[0], reason: 'server_error' }],
      },
    ]) {
      expectProtocolCode(() => parseVaultTransferWorkerMessage({ ...base, status }), 'invalid_message');
    }
    expectProtocolCode(() => parseVaultTransferWorkerMessage({
      version: 1,
      type: 'recovery.cleared',
      phase: 'completed',
      cleared: 0,
    }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferWorkerMessage({
      version: 1,
      type: 'recovery.cleared',
      phase: 'completed',
      cleared: 33,
    }), 'invalid_message');
  });

  it('does not permit clearing an omitted or unreconciled recovery set', () => {
    expect(canClearVaultTransferRecovery({
      ...RECOVERY_STATUS,
      count: 2,
      omittedCount: 1,
    })).toBe(false);
    expect(canClearVaultTransferRecovery({
      ...RECOVERY_STATUS,
      barriers: [{ ...RECOVERY_STATUS.barriers[0]!, reconciled: false, clearable: false }],
    })).toBe(false);
    expect(canClearVaultTransferRecovery({
      count: 0,
      unresolvedUnknownCount: 0,
      reconcileRequiredCount: 0,
      omittedCount: 0,
      barriers: [],
    })).toBe(false);
  });

  it('requires a non-empty canonical recovery snapshot on clear requests', () => {
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1,
      type: 'recovery.clear',
      expectedBarriers: [],
    }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1,
      type: 'recovery.clear',
      expectedBarriers: [
        { transferId: TRANSFER_ID, reason: 'outcome_unknown' },
        { transferId: PREVIEW_REVISION, reason: 'partial_result' },
      ],
    }), 'invalid_message');
    expectProtocolCode(() => parseVaultTransferClientMessage({
      version: 1,
      type: 'recovery.clear',
      expectedBarriers: [{
        transferId: TRANSFER_ID,
        reason: 'outcome_unknown',
        sourceDigest: 'private',
      }],
    }), 'invalid_message');
  });
});
