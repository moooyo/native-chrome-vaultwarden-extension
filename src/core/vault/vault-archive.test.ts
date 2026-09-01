import { describe, expect, it } from 'vitest';
import { strFromU8, strToU8, zipSync, type Zippable } from 'fflate';
import {
  BITWARDEN_VAULT_ARCHIVE_DATA_NAME,
  MIYU_VAULT_ARCHIVE_MANIFEST_NAME,
  MIYU_VAULT_ARCHIVE_MANIFEST_VERSION,
  readVaultArchive,
  writeVaultArchive,
} from './vault-archive.js';

const dataJson = strToU8(JSON.stringify({ encrypted: false, folders: [], items: [] }));

function rawArchive(entries: Record<string, Uint8Array>, level: 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 = 6): Uint8Array {
  const zippable = Object.create(null) as Zippable;
  for (const [path, data] of Object.entries(entries)) zippable[path] = data;
  return zipSync(zippable, { level, mtime: new Date('1980-01-02T00:00:00.000Z') });
}

function manifestBytes(overrides: Record<string, unknown> = {}): Uint8Array {
  return strToU8(JSON.stringify({
    format: 'miyu-vault-archive',
    version: MIYU_VAULT_ARCHIVE_MANIFEST_VERSION,
    critical: ['format', 'version', 'attachments'],
    attachments: [],
    ...overrides,
  }));
}

describe('vault archive round trips', () => {
  it('writes and reads a Bitwarden-style data.json plus attachment entries', () => {
    const first = strToU8('first attachment');
    const second = new Uint8Array([0, 1, 2, 3, 255]);
    const written = writeVaultArchive({
      dataJson,
      attachments: [
        { path: 'attachments/GitHub/readme.txt', data: first },
        { path: 'attachments/GitHub/avatar.bin', data: second },
      ],
    });

    expect(written.ok).toBe(true);
    expect(written.archive).toBeInstanceOf(Uint8Array);
    expect(written.diagnostics).toEqual([]);

    const read = readVaultArchive(written.archive!);
    expect(read.ok).toBe(true);
    expect(strFromU8(read.dataJson!)).toBe(strFromU8(dataJson));
    expect(read.manifest).toBeNull();
    expect(read.attachments.map((attachment) => attachment.path)).toEqual([
      'attachments/GitHub/readme.txt',
      'attachments/GitHub/avatar.bin',
    ]);
    expect([...read.attachments[1]!.data]).toEqual([...second]);
  });

  it('round-trips stable manifest mappings and persisted skipped-attachment diagnostics', () => {
    const written = writeVaultArchive({
      dataJson,
      includeManifest: true,
      attachments: [{
        path: 'attachments/Deploy/key.pub',
        data: strToU8('ssh-ed25519 AAAA'),
        itemToken: 'item-token-1',
        attachmentId: 'attachment-1',
      }],
      skippedAttachments: [{
        path: 'attachments/Deploy/private.key',
        itemToken: 'item-token-1',
        attachmentId: 'attachment-2',
        reason: 'Download failed',
      }],
    });

    expect(written.ok).toBe(true);
    expect(written.diagnostics).toContainEqual(expect.objectContaining({
      severity: 'warning', code: 'attachment_skipped', attachmentId: 'attachment-2',
    }));

    const read = readVaultArchive(written.archive!);
    expect(read.ok).toBe(true);
    expect(read.manifest).toMatchObject({
      version: 1,
      attachments: [{
        path: 'attachments/Deploy/key.pub', itemToken: 'item-token-1', attachmentId: 'attachment-1',
      }],
    });
    expect(read.attachments[0]).toMatchObject({ itemToken: 'item-token-1', attachmentId: 'attachment-1' });
    expect(read.skippedAttachments).toEqual([expect.objectContaining({ attachmentId: 'attachment-2', reason: 'Download failed' })]);
    expect(read.diagnostics).toContainEqual(expect.objectContaining({ code: 'attachment_skipped', attachmentId: 'attachment-2' }));
  });

  it('accepts conventional empty attachment directory entries', () => {
    const archive = rawArchive({
      [BITWARDEN_VAULT_ARCHIVE_DATA_NAME]: dataJson,
      'attachments/': new Uint8Array(),
      'attachments/Item/': new Uint8Array(),
      'attachments/Item/file.txt': strToU8('file'),
    });
    const read = readVaultArchive(archive);
    expect(read.ok).toBe(true);
    expect(read.attachments).toHaveLength(1);
  });
});

describe('vault archive path and structure validation', () => {
  it.each([
    ['../outside.txt', 'path_traversal'],
    ['/absolute.txt', 'absolute_entry_path'],
    ['C:/absolute.txt', 'absolute_entry_path'],
    ['attachments\\Item\\file.txt', 'path_traversal'],
    ['attachments/Item/../file.txt', 'path_traversal'],
    ['attachments/Item/bad\0name.txt', 'nul_in_entry_path'],
  ])('rejects unsafe writer path %s', (path, code) => {
    const written = writeVaultArchive({ dataJson, attachments: [{ path, data: strToU8('x') }] });
    expect(written.ok).toBe(false);
    expect(written.archive).toBeNull();
    expect(written.diagnostics).toContainEqual(expect.objectContaining({ code }));
  });

  it('rejects unsafe paths before extracting a hostile archive', () => {
    const archive = rawArchive({
      [BITWARDEN_VAULT_ARCHIVE_DATA_NAME]: dataJson,
      'attachments/Item/../../outside.txt': strToU8('secret'),
    });
    const read = readVaultArchive(archive);
    expect(read.ok).toBe(false);
    expect(read.dataJson).toBeNull();
    expect(read.diagnostics).toContainEqual(expect.objectContaining({ code: 'path_traversal' }));
  });

  it('rejects duplicate paths using case- and Unicode-normalized comparison', () => {
    const archive = rawArchive({
      [BITWARDEN_VAULT_ARCHIVE_DATA_NAME]: dataJson,
      'attachments/Item/File.txt': strToU8('one'),
      'attachments/item/file.txt': strToU8('two'),
    });
    const read = readVaultArchive(archive);
    expect(read.ok).toBe(false);
    expect(read.diagnostics).toContainEqual(expect.objectContaining({ code: 'duplicate_entry_path' }));
  });

  it('rejects a directory entry carrying file data', () => {
    const archive = rawArchive({
      [BITWARDEN_VAULT_ARCHIVE_DATA_NAME]: dataJson,
      'attachments/Item/': strToU8('not a directory'),
    });
    const read = readVaultArchive(archive);
    expect(read.ok).toBe(false);
    expect(read.diagnostics).toContainEqual(expect.objectContaining({ code: 'directory_masquerade' }));
  });

  it('rejects files that masquerade as an ancestor directory', () => {
    const archive = rawArchive({
      [BITWARDEN_VAULT_ARCHIVE_DATA_NAME]: dataJson,
      'attachments/Item': strToU8('file'),
      'attachments/Item/nested.txt': strToU8('nested'),
    });
    const read = readVaultArchive(archive);
    expect(read.ok).toBe(false);
    expect(read.diagnostics).toContainEqual(expect.objectContaining({ code: 'directory_masquerade' }));
  });

  it('rejects missing data.json and unknown root entries', () => {
    const missing = readVaultArchive(rawArchive({ 'attachments/Item/file.txt': strToU8('x') }));
    expect(missing.ok).toBe(false);
    expect(missing.diagnostics).toContainEqual(expect.objectContaining({ code: 'missing_data_json' }));

    const unknown = readVaultArchive(rawArchive({
      [BITWARDEN_VAULT_ARCHIVE_DATA_NAME]: dataJson,
      'extra.json': strToU8('{}'),
    }));
    expect(unknown.ok).toBe(false);
    expect(unknown.diagnostics).toContainEqual(expect.objectContaining({ code: 'unknown_archive_entry' }));
  });

  it('rejects damaged ZIP bytes', () => {
    const read = readVaultArchive(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 1, 2, 3]));
    expect(read.ok).toBe(false);
    expect(read.diagnostics).toContainEqual(expect.objectContaining({ code: 'damaged_zip' }));
  });
});

describe('MiYu archive manifest validation', () => {
  it('rejects an unknown field declared critical', () => {
    const archive = rawArchive({
      [BITWARDEN_VAULT_ARCHIVE_DATA_NAME]: dataJson,
      [MIYU_VAULT_ARCHIVE_MANIFEST_NAME]: manifestBytes({
        critical: ['format', 'version', 'attachments', 'futureMode'],
        futureMode: { required: true },
      }),
    });
    const read = readVaultArchive(archive);
    expect(read.ok).toBe(false);
    expect(read.diagnostics).toContainEqual(expect.objectContaining({ code: 'unknown_critical_manifest_field' }));
  });

  it('warns for unknown non-critical manifest fields without blocking restore', () => {
    const archive = rawArchive({
      [BITWARDEN_VAULT_ARCHIVE_DATA_NAME]: dataJson,
      [MIYU_VAULT_ARCHIVE_MANIFEST_NAME]: manifestBytes({ producerNote: 'future-compatible metadata' }),
    });
    const read = readVaultArchive(archive);
    expect(read.ok).toBe(true);
    expect(read.diagnostics).toContainEqual(expect.objectContaining({
      severity: 'warning', code: 'unknown_manifest_field',
    }));
  });

  it('rejects mappings to missing entries and duplicate stable attachment identities', () => {
    const archive = rawArchive({
      [BITWARDEN_VAULT_ARCHIVE_DATA_NAME]: dataJson,
      'attachments/Item/one.txt': strToU8('one'),
      [MIYU_VAULT_ARCHIVE_MANIFEST_NAME]: manifestBytes({
        attachments: [
          { path: 'attachments/Item/one.txt', itemToken: 'item', attachmentId: 'same' },
          { path: 'attachments/Item/missing.txt', itemToken: 'item', attachmentId: 'same' },
        ],
      }),
    });
    const read = readVaultArchive(archive);
    expect(read.ok).toBe(false);
    expect(read.diagnostics).toContainEqual(expect.objectContaining({ code: 'missing_manifest_attachment' }));
    expect(read.diagnostics).toContainEqual(expect.objectContaining({ code: 'duplicate_attachment_identity' }));
  });

  it('requires stable ids when the writer includes a manifest', () => {
    const written = writeVaultArchive({
      dataJson,
      includeManifest: true,
      attachments: [{ path: 'attachments/Item/file.txt', data: strToU8('x') }],
    });
    expect(written.ok).toBe(false);
    expect(written.diagnostics).toContainEqual(expect.objectContaining({ code: 'invalid_attachment_identity' }));
  });
});

describe('vault archive resource limits', () => {
  const sourceArchive = rawArchive({
    [BITWARDEN_VAULT_ARCHIVE_DATA_NAME]: dataJson,
    'attachments/Item/a.txt': strToU8('alpha'),
    'attachments/Item/b.txt': strToU8('beta'),
  }, 0);

  it('enforces the compressed archive input limit before parsing', () => {
    const read = readVaultArchive(sourceArchive, { limits: { maxArchiveBytes: sourceArchive.byteLength - 1 } });
    expect(read.ok).toBe(false);
    expect(read.diagnostics).toContainEqual(expect.objectContaining({ code: 'archive_too_large' }));
  });

  it('enforces total compressed and uncompressed limits from central-directory metadata', () => {
    const compressed = readVaultArchive(sourceArchive, { limits: { maxTotalCompressedBytes: 1 } });
    expect(compressed.ok).toBe(false);
    expect(compressed.diagnostics).toContainEqual(expect.objectContaining({ code: 'total_compressed_too_large' }));

    const uncompressed = readVaultArchive(sourceArchive, { limits: { maxTotalUncompressedBytes: dataJson.byteLength } });
    expect(uncompressed.ok).toBe(false);
    expect(uncompressed.diagnostics).toContainEqual(expect.objectContaining({ code: 'total_uncompressed_too_large' }));
  });

  it('enforces entry count and individual entry limits', () => {
    const entries = readVaultArchive(sourceArchive, { limits: { maxEntries: 2 } });
    expect(entries.ok).toBe(false);
    expect(entries.diagnostics).toContainEqual(expect.objectContaining({ code: 'entry_count_exceeded' }));

    const single = readVaultArchive(sourceArchive, { limits: { maxEntryUncompressedBytes: 4 } });
    expect(single.ok).toBe(false);
    expect(single.diagnostics).toContainEqual(expect.objectContaining({ code: 'entry_uncompressed_too_large' }));
  });

  it('rejects a declared compression ratio above the configured limit before inflation', () => {
    const bombLike = rawArchive({
      [BITWARDEN_VAULT_ARCHIVE_DATA_NAME]: dataJson,
      'attachments/Item/repeated.txt': strToU8('A'.repeat(20_000)),
    }, 9);
    const read = readVaultArchive(bombLike, { limits: { maxCompressionRatio: 2 } });
    expect(read.ok).toBe(false);
    expect(read.dataJson).toBeNull();
    expect(read.diagnostics).toContainEqual(expect.objectContaining({ code: 'compression_ratio_exceeded' }));
  });

  it('applies the same entry and total-uncompressed limits while writing', () => {
    const written = writeVaultArchive({
      dataJson,
      attachments: [{ path: 'attachments/Item/file.txt', data: strToU8('12345') }],
    }, {
      limits: { maxEntryUncompressedBytes: 4, maxTotalUncompressedBytes: dataJson.byteLength + 4 },
    });
    expect(written.ok).toBe(false);
    expect(written.archive).toBeNull();
    expect(written.diagnostics).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: 'entry_uncompressed_too_large' }),
      expect.objectContaining({ code: 'total_uncompressed_too_large' }),
    ]));
  });

  it('rejects invalid limit overrides as programmer errors', () => {
    expect(() => readVaultArchive(sourceArchive, { limits: { maxEntries: 0 } })).toThrow(RangeError);
    expect(() => readVaultArchive(sourceArchive, { limits: { maxCompressionRatio: Number.POSITIVE_INFINITY } })).toThrow(RangeError);
  });
});
