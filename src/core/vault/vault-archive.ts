import { strFromU8, strToU8, unzipSync, zipSync, type UnzipFileInfo, type Zippable } from 'fflate';

export const MIYU_VAULT_ARCHIVE_MANIFEST_VERSION = 1 as const;
export const MIYU_VAULT_ARCHIVE_MANIFEST_NAME = 'miyu-manifest.json';
export const BITWARDEN_VAULT_ARCHIVE_DATA_NAME = 'data.json';

const MANIFEST_FORMAT = 'miyu-vault-archive';

export type VaultArchiveDiagnosticSeverity = 'warning' | 'error';

export interface VaultArchiveDiagnostic {
  severity: VaultArchiveDiagnosticSeverity;
  code: string;
  message: string;
  entryPath?: string;
  itemToken?: string;
  attachmentId?: string;
}

export interface VaultArchiveLimits {
  maxArchiveBytes: number;
  maxTotalCompressedBytes: number;
  maxTotalUncompressedBytes: number;
  maxEntries: number;
  maxEntryCompressedBytes: number;
  maxEntryUncompressedBytes: number;
  maxDataJsonBytes: number;
  maxManifestBytes: number;
  maxCompressionRatio: number;
  maxPathChars: number;
  maxIdentifierChars: number;
  maxDiagnostics: number;
}

export const DEFAULT_VAULT_ARCHIVE_LIMITS: Readonly<VaultArchiveLimits> = Object.freeze({
  maxArchiveBytes: 128 * 1024 * 1024,
  maxTotalCompressedBytes: 128 * 1024 * 1024,
  maxTotalUncompressedBytes: 256 * 1024 * 1024,
  maxEntries: 5_000,
  maxEntryCompressedBytes: 128 * 1024 * 1024,
  maxEntryUncompressedBytes: 128 * 1024 * 1024,
  maxDataJsonBytes: 32 * 1024 * 1024,
  maxManifestBytes: 2 * 1024 * 1024,
  maxCompressionRatio: 200,
  maxPathChars: 1_024,
  maxIdentifierChars: 1_024,
  maxDiagnostics: 1_000,
});

export interface VaultArchiveAttachmentInput {
  /** Full Bitwarden-style path, for example `attachments/Item/file.txt`. */
  path: string;
  data: Uint8Array;
  itemToken?: string;
  attachmentId?: string;
}

export interface VaultArchiveSkippedAttachment {
  reason: string;
  itemToken?: string;
  attachmentId?: string;
  path?: string;
}

export interface VaultArchiveWriteInput {
  dataJson: Uint8Array;
  attachments?: VaultArchiveAttachmentInput[];
  /** Adds a versioned stable-id mapping. All included attachments then require both stable ids. */
  includeManifest?: boolean;
  skippedAttachments?: VaultArchiveSkippedAttachment[];
}

export interface VaultArchiveWriteOptions {
  limits?: Partial<VaultArchiveLimits>;
  compressionLevel?: 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;
}

export interface VaultArchiveWriteResult {
  ok: boolean;
  archive: Uint8Array | null;
  diagnostics: VaultArchiveDiagnostic[];
}

export interface MiYuVaultArchiveAttachmentMapping {
  path: string;
  itemToken: string;
  attachmentId: string;
}

export interface MiYuVaultArchiveManifestV1 {
  format: typeof MANIFEST_FORMAT;
  version: typeof MIYU_VAULT_ARCHIVE_MANIFEST_VERSION;
  critical: string[];
  attachments: MiYuVaultArchiveAttachmentMapping[];
  skippedAttachments?: VaultArchiveSkippedAttachment[];
}

export interface VaultArchiveAttachment {
  path: string;
  data: Uint8Array;
  itemToken?: string;
  attachmentId?: string;
}

export interface VaultArchiveReadOptions {
  limits?: Partial<VaultArchiveLimits>;
}

export interface VaultArchiveReadResult {
  ok: boolean;
  dataJson: Uint8Array | null;
  attachments: VaultArchiveAttachment[];
  manifest: MiYuVaultArchiveManifestV1 | null;
  skippedAttachments: VaultArchiveSkippedAttachment[];
  diagnostics: VaultArchiveDiagnostic[];
}

interface ArchiveContext {
  limits: VaultArchiveLimits;
  diagnostics: VaultArchiveDiagnostic[];
  diagnosticsTruncated: boolean;
}

interface AuditedEntry {
  path: string;
  compressedSize: number;
  uncompressedSize: number;
  directory: boolean;
}

interface AuditedArchive {
  files: Record<string, Uint8Array>;
  entries: AuditedEntry[];
}

interface ManifestParseResult {
  manifest: MiYuVaultArchiveManifestV1 | null;
  mappings: Map<string, MiYuVaultArchiveAttachmentMapping>;
  skipped: VaultArchiveSkippedAttachment[];
}

class ArchiveValidationAbort extends Error {}

/** Build an in-memory Bitwarden-style ZIP. No file, storage, network, or crypto side effects occur. */
export function writeVaultArchive(
  input: VaultArchiveWriteInput,
  options: VaultArchiveWriteOptions = {},
): VaultArchiveWriteResult {
  const context = createContext(options.limits);
  const attachments = input.attachments ?? [];
  const skippedAttachments = input.skippedAttachments ?? [];
  const includeManifest = input.includeManifest === true;
  const registry = new ArchivePathRegistry(context);

  validateJsonDocument(input.dataJson, BITWARDEN_VAULT_ARCHIVE_DATA_NAME, context);
  validateEntrySize(BITWARDEN_VAULT_ARCHIVE_DATA_NAME, input.dataJson.byteLength, context);
  if (input.dataJson.byteLength > context.limits.maxDataJsonBytes) {
    addLimitDiagnostic(context, 'data_json_too_large', BITWARDEN_VAULT_ARCHIVE_DATA_NAME, input.dataJson.byteLength, context.limits.maxDataJsonBytes);
  }
  registry.addFile(BITWARDEN_VAULT_ARCHIVE_DATA_NAME);

  const seenStableIds = new Set<string>();
  let totalUncompressed = input.dataJson.byteLength;
  for (const attachment of attachments) {
    validateAttachmentPath(attachment.path, context);
    registry.addFile(attachment.path);
    if (!(attachment.data instanceof Uint8Array)) {
      addDiagnostic(context, {
        severity: 'error', code: 'invalid_attachment_data', message: 'Attachment data must be a Uint8Array.', entryPath: attachment.path,
      });
      continue;
    }
    validateEntrySize(attachment.path, attachment.data.byteLength, context);
    totalUncompressed += attachment.data.byteLength;
    if (includeManifest) {
      const itemToken = validateIdentifier(attachment.itemToken, 'itemToken', attachment.path, context);
      const attachmentId = validateIdentifier(attachment.attachmentId, 'attachmentId', attachment.path, context);
      if (itemToken && attachmentId) {
        const stableKey = `${itemToken}\u0000${attachmentId}`;
        if (seenStableIds.has(stableKey)) {
          addDiagnostic(context, {
            severity: 'error', code: 'duplicate_attachment_identity', message: 'Stable attachment identities must be unique.',
            entryPath: attachment.path, itemToken, attachmentId,
          });
        }
        seenStableIds.add(stableKey);
      }
    }
  }

  if (skippedAttachments.length > context.limits.maxEntries) {
    addLimitDiagnostic(context, 'manifest_records_limit_exceeded', MIYU_VAULT_ARCHIVE_MANIFEST_NAME, skippedAttachments.length, context.limits.maxEntries);
  }
  for (const skipped of skippedAttachments.slice(0, context.limits.maxEntries)) {
    validateSkippedAttachment(skipped, context, includeManifest);
    addSkippedDiagnostic(context, skipped);
  }

  const entryCount = 1 + attachments.length + (includeManifest ? 1 : 0);
  if (entryCount > context.limits.maxEntries) {
    addLimitDiagnostic(context, 'entry_count_exceeded', undefined, entryCount, context.limits.maxEntries);
  }
  if (totalUncompressed > context.limits.maxTotalUncompressedBytes) {
    addLimitDiagnostic(context, 'total_uncompressed_too_large', undefined, totalUncompressed, context.limits.maxTotalUncompressedBytes);
  }

  let manifestBytes: Uint8Array | undefined;
  if (includeManifest) {
    const manifest: MiYuVaultArchiveManifestV1 = {
      format: MANIFEST_FORMAT,
      version: MIYU_VAULT_ARCHIVE_MANIFEST_VERSION,
      critical: ['format', 'version', 'attachments'],
      attachments: attachments.flatMap((attachment) =>
        attachment.itemToken && attachment.attachmentId
          ? [{ path: attachment.path, itemToken: attachment.itemToken, attachmentId: attachment.attachmentId }]
          : []),
      ...(skippedAttachments.length > 0 ? { skippedAttachments } : {}),
    };
    manifestBytes = strToU8(JSON.stringify(manifest));
    registry.addFile(MIYU_VAULT_ARCHIVE_MANIFEST_NAME);
    validateEntrySize(MIYU_VAULT_ARCHIVE_MANIFEST_NAME, manifestBytes.byteLength, context);
    if (manifestBytes.byteLength > context.limits.maxManifestBytes) {
      addLimitDiagnostic(context, 'manifest_too_large', MIYU_VAULT_ARCHIVE_MANIFEST_NAME, manifestBytes.byteLength, context.limits.maxManifestBytes);
    }
    totalUncompressed += manifestBytes.byteLength;
    if (totalUncompressed > context.limits.maxTotalUncompressedBytes) {
      addLimitDiagnostic(context, 'total_uncompressed_too_large', undefined, totalUncompressed, context.limits.maxTotalUncompressedBytes);
    }
  }

  if (hasErrors(context)) return { ok: false, archive: null, diagnostics: context.diagnostics };

  const entries = Object.create(null) as Zippable;
  entries[BITWARDEN_VAULT_ARCHIVE_DATA_NAME] = input.dataJson;
  for (const attachment of attachments) entries[attachment.path] = attachment.data;
  if (manifestBytes) entries[MIYU_VAULT_ARCHIVE_MANIFEST_NAME] = manifestBytes;

  let archive: Uint8Array;
  try {
    archive = zipSync(entries, { level: options.compressionLevel ?? 6, mtime: new Date('1980-01-02T00:00:00.000Z') });
  } catch (error) {
    addDamagedZipDiagnostic(context, error, 'ZIP creation failed');
    return { ok: false, archive: null, diagnostics: context.diagnostics };
  }
  if (archive.byteLength > context.limits.maxArchiveBytes) {
    addLimitDiagnostic(context, 'archive_too_large', undefined, archive.byteLength, context.limits.maxArchiveBytes);
    return { ok: false, archive: null, diagnostics: context.diagnostics };
  }

  const audit = auditAndUnzip(archive, context, false);
  if (!audit || hasErrors(context)) return { ok: false, archive: null, diagnostics: context.diagnostics };
  return { ok: true, archive, diagnostics: context.diagnostics };
}

/** Read and validate an in-memory Bitwarden-style ZIP without writing or decrypting its contents. */
export function readVaultArchive(
  archive: Uint8Array,
  options: VaultArchiveReadOptions = {},
): VaultArchiveReadResult {
  const context = createContext(options.limits);
  const failed = (): VaultArchiveReadResult => ({
    ok: false,
    dataJson: null,
    attachments: [],
    manifest: null,
    skippedAttachments: [],
    diagnostics: context.diagnostics,
  });
  if (!(archive instanceof Uint8Array)) {
    addDiagnostic(context, {
      severity: 'error', code: 'invalid_archive_data', message: 'Archive data must be a Uint8Array.',
    });
    return failed();
  }
  if (archive.byteLength > context.limits.maxArchiveBytes) {
    addLimitDiagnostic(context, 'archive_too_large', undefined, archive.byteLength, context.limits.maxArchiveBytes);
    return failed();
  }
  if (archive.byteLength === 0) {
    addDiagnostic(context, { severity: 'error', code: 'damaged_zip', message: 'The ZIP archive is empty.' });
    return failed();
  }

  const audited = auditAndUnzip(archive, context, true);
  if (!audited) return failed();
  const dataJson = audited.files[BITWARDEN_VAULT_ARCHIVE_DATA_NAME];
  if (!dataJson) {
    addDiagnostic(context, {
      severity: 'error', code: 'missing_data_json', message: 'The archive does not contain a root data.json entry.',
      entryPath: BITWARDEN_VAULT_ARCHIVE_DATA_NAME,
    });
    return failed();
  }
  validateJsonDocument(dataJson, BITWARDEN_VAULT_ARCHIVE_DATA_NAME, context);

  const manifestBytes = audited.files[MIYU_VAULT_ARCHIVE_MANIFEST_NAME];
  const manifestResult = manifestBytes
    ? parseManifest(manifestBytes, audited, context)
    : { manifest: null, mappings: new Map<string, MiYuVaultArchiveAttachmentMapping>(), skipped: [] };

  const attachments: VaultArchiveAttachment[] = [];
  for (const entry of audited.entries) {
    if (entry.directory || !entry.path.startsWith('attachments/')) continue;
    const data = audited.files[entry.path];
    if (!data) continue;
    const mapping = manifestResult.mappings.get(entry.path);
    const attachment: VaultArchiveAttachment = { path: entry.path, data };
    if (mapping) {
      attachment.itemToken = mapping.itemToken;
      attachment.attachmentId = mapping.attachmentId;
    } else if (manifestResult.manifest) {
      addDiagnostic(context, {
        severity: 'warning', code: 'attachment_unmapped', message: 'Attachment is not mapped by the MiYu manifest.',
        entryPath: entry.path,
      });
    }
    attachments.push(attachment);
  }

  return {
    ok: !hasErrors(context),
    dataJson,
    attachments,
    manifest: manifestResult.manifest,
    skippedAttachments: manifestResult.skipped,
    diagnostics: context.diagnostics,
  };
}

function auditAndUnzip(archive: Uint8Array, context: ArchiveContext, extract: boolean): AuditedArchive | null {
  const entries: AuditedEntry[] = [];
  const registry = new ArchivePathRegistry(context);
  let totalCompressed = 0;
  let totalUncompressed = 0;
  try {
    const files = unzipSync(archive, {
      filter(info) {
        if (entries.length >= context.limits.maxEntries) {
          addLimitDiagnostic(context, 'entry_count_exceeded', info.name, entries.length + 1, context.limits.maxEntries);
          throw new ArchiveValidationAbort();
        }
        const directory = info.name.endsWith('/');
        validateArchiveEntry(info, directory, context);
        if (directory) registry.addDirectory(info.name);
        else registry.addFile(info.name);
        totalCompressed += info.size;
        totalUncompressed += info.originalSize;
        if (totalCompressed > context.limits.maxTotalCompressedBytes) {
          addLimitDiagnostic(context, 'total_compressed_too_large', info.name, totalCompressed, context.limits.maxTotalCompressedBytes);
        }
        if (totalUncompressed > context.limits.maxTotalUncompressedBytes) {
          addLimitDiagnostic(context, 'total_uncompressed_too_large', info.name, totalUncompressed, context.limits.maxTotalUncompressedBytes);
        }
        entries.push({
          path: info.name,
          compressedSize: info.size,
          uncompressedSize: info.originalSize,
          directory,
        });
        if (hasErrors(context)) throw new ArchiveValidationAbort();
        return extract && !directory;
      },
    });
    if (extract) {
      let actualTotal = 0;
      for (const entry of entries) {
        if (entry.directory) continue;
        const data = files[entry.path];
        if (!data || data.byteLength !== entry.uncompressedSize) {
          addDiagnostic(context, {
            severity: 'error', code: 'damaged_zip', message: 'An extracted entry does not match its declared size.', entryPath: entry.path,
          });
          return null;
        }
        actualTotal += data.byteLength;
      }
      if (actualTotal > context.limits.maxTotalUncompressedBytes) {
        addLimitDiagnostic(context, 'total_uncompressed_too_large', undefined, actualTotal, context.limits.maxTotalUncompressedBytes);
        return null;
      }
    }
    return { files, entries };
  } catch (error) {
    if (!(error instanceof ArchiveValidationAbort)) addDamagedZipDiagnostic(context, error, 'ZIP parsing failed');
    return null;
  }
}

function validateArchiveEntry(info: UnzipFileInfo, directory: boolean, context: ArchiveContext): void {
  validateSafePath(info.name, context);
  if (directory) {
    // A DEFLATE encoder may emit a non-empty compressed stream for an empty directory marker.
    // The declared uncompressed size is the property that distinguishes it from file data.
    if (info.originalSize !== 0) {
      addDiagnostic(context, {
        severity: 'error', code: 'directory_masquerade', message: 'Directory entries must not contain file data.', entryPath: info.name,
      });
    }
    if (!info.name.startsWith('attachments/')) {
      addDiagnostic(context, {
        severity: 'error', code: 'unknown_archive_entry', message: 'Only attachment directories are allowed.', entryPath: info.name,
      });
    }
    return;
  }
  if (!isAllowedFilePath(info.name)) {
    const attachmentAncestorFile = info.name.startsWith('attachments/') && info.name.split('/').length < 3;
    addDiagnostic(context, {
      severity: 'error',
      code: attachmentAncestorFile ? 'directory_masquerade' : 'unknown_archive_entry',
      message: attachmentAncestorFile
        ? 'An attachment ancestor path must be a directory, not a file.'
        : 'Only data.json, miyu-manifest.json, and attachment files are allowed.',
      entryPath: info.name,
    });
  }
  if (info.size > context.limits.maxEntryCompressedBytes) {
    addLimitDiagnostic(context, 'entry_compressed_too_large', info.name, info.size, context.limits.maxEntryCompressedBytes);
  }
  validateEntrySize(info.name, info.originalSize, context);
  if (info.name === BITWARDEN_VAULT_ARCHIVE_DATA_NAME && info.originalSize > context.limits.maxDataJsonBytes) {
    addLimitDiagnostic(context, 'data_json_too_large', info.name, info.originalSize, context.limits.maxDataJsonBytes);
  }
  if (info.name === MIYU_VAULT_ARCHIVE_MANIFEST_NAME && info.originalSize > context.limits.maxManifestBytes) {
    addLimitDiagnostic(context, 'manifest_too_large', info.name, info.originalSize, context.limits.maxManifestBytes);
  }
  const ratio = info.originalSize === 0 ? 1 : (info.size === 0 ? Number.POSITIVE_INFINITY : info.originalSize / info.size);
  if (ratio > context.limits.maxCompressionRatio) {
    addDiagnostic(context, {
      severity: 'error',
      code: 'compression_ratio_exceeded',
      message: `Entry compression ratio ${ratio.toFixed(2)} exceeds the limit of ${context.limits.maxCompressionRatio}.`,
      entryPath: info.name,
    });
  }
  if (info.compression !== 0 && info.compression !== 8) {
    addDiagnostic(context, {
      severity: 'error', code: 'unsupported_compression', message: `ZIP compression method ${info.compression} is not supported.`,
      entryPath: info.name,
    });
  }
}

function parseManifest(
  bytes: Uint8Array,
  audited: AuditedArchive,
  context: ArchiveContext,
): ManifestParseResult {
  const empty = (): ManifestParseResult => ({ manifest: null, mappings: new Map(), skipped: [] });
  let raw: unknown;
  try {
    raw = JSON.parse(strFromU8(bytes)) as unknown;
  } catch (error) {
    addDiagnostic(context, {
      severity: 'error', code: 'invalid_manifest', message: errorMessage('MiYu manifest is not valid UTF-8 JSON', error),
      entryPath: MIYU_VAULT_ARCHIVE_MANIFEST_NAME,
    });
    return empty();
  }
  if (!isRecord(raw)) {
    addDiagnostic(context, {
      severity: 'error', code: 'invalid_manifest', message: 'MiYu manifest must be a JSON object.',
      entryPath: MIYU_VAULT_ARCHIVE_MANIFEST_NAME,
    });
    return empty();
  }

  const allowed = new Set(['format', 'version', 'critical', 'attachments', 'skippedAttachments']);
  const critical = readCriticalFields(raw.critical, context);
  for (const key of Object.keys(raw)) {
    if (allowed.has(key)) continue;
    const isCritical = critical.includes(key);
    addDiagnostic(context, {
      severity: isCritical ? 'error' : 'warning',
      code: isCritical ? 'unknown_critical_manifest_field' : 'unknown_manifest_field',
      message: isCritical
        ? `Manifest requires unsupported field ${key}.`
        : `Manifest contains unrecognized non-critical field ${key}.`,
      entryPath: MIYU_VAULT_ARCHIVE_MANIFEST_NAME,
    });
  }
  for (const key of critical) {
    if (allowed.has(key)) continue;
    if (Object.prototype.hasOwnProperty.call(raw, key)) continue;
    addDiagnostic(context, {
      severity: 'error', code: 'unknown_critical_manifest_field', message: `Manifest requires unsupported field ${key}.`,
      entryPath: MIYU_VAULT_ARCHIVE_MANIFEST_NAME,
    });
  }
  if (raw.format !== MANIFEST_FORMAT) {
    addDiagnostic(context, {
      severity: 'error', code: 'unsupported_manifest_format', message: 'MiYu manifest format is not supported.',
      entryPath: MIYU_VAULT_ARCHIVE_MANIFEST_NAME,
    });
  }
  if (raw.version !== MIYU_VAULT_ARCHIVE_MANIFEST_VERSION) {
    addDiagnostic(context, {
      severity: 'error', code: 'unsupported_manifest_version', message: `MiYu manifest version ${String(raw.version)} is not supported.`,
      entryPath: MIYU_VAULT_ARCHIVE_MANIFEST_NAME,
    });
  }
  if (!Array.isArray(raw.attachments)) {
    addDiagnostic(context, {
      severity: 'error', code: 'invalid_manifest', message: 'MiYu manifest attachments must be an array.',
      entryPath: MIYU_VAULT_ARCHIVE_MANIFEST_NAME,
    });
    return empty();
  }
  if (raw.attachments.length > context.limits.maxEntries) {
    addLimitDiagnostic(context, 'manifest_records_limit_exceeded', MIYU_VAULT_ARCHIVE_MANIFEST_NAME, raw.attachments.length, context.limits.maxEntries);
    return empty();
  }

  const archiveFiles = new Set(audited.entries.filter((entry) => !entry.directory).map((entry) => entry.path));
  const mappings = new Map<string, MiYuVaultArchiveAttachmentMapping>();
  const stableIds = new Set<string>();
  for (const [index, value] of raw.attachments.entries()) {
    if (!isRecord(value)) {
      addManifestRecordDiagnostic(context, 'Manifest attachment mappings must be objects.', index);
      continue;
    }
    for (const key of Object.keys(value)) {
      if (!['path', 'itemToken', 'attachmentId'].includes(key)) {
        addManifestRecordDiagnostic(context, `Manifest attachment mapping contains unknown field ${key}.`, index, 'unknown_manifest_field');
      }
    }
    const path = readManifestString(value.path, 'path', index, context);
    const itemToken = readManifestString(value.itemToken, 'itemToken', index, context);
    const attachmentId = readManifestString(value.attachmentId, 'attachmentId', index, context);
    if (!path || !itemToken || !attachmentId) continue;
    validateAttachmentPath(path, context);
    const stableKey = `${itemToken}\u0000${attachmentId}`;
    if (mappings.has(path)) addManifestRecordDiagnostic(context, `Manifest maps attachment path ${path} more than once.`, index, 'duplicate_manifest_path');
    if (stableIds.has(stableKey)) addManifestRecordDiagnostic(context, 'Manifest stable attachment identities must be unique.', index, 'duplicate_attachment_identity');
    if (!archiveFiles.has(path)) addManifestRecordDiagnostic(context, `Manifest attachment path ${path} is missing from the ZIP.`, index, 'missing_manifest_attachment');
    mappings.set(path, { path, itemToken, attachmentId });
    stableIds.add(stableKey);
  }

  const skipped = parseManifestSkipped(raw.skippedAttachments, stableIds, context);
  const manifest: MiYuVaultArchiveManifestV1 = {
    format: MANIFEST_FORMAT,
    version: MIYU_VAULT_ARCHIVE_MANIFEST_VERSION,
    critical,
    attachments: [...mappings.values()],
    ...(skipped.length > 0 ? { skippedAttachments: skipped } : {}),
  };
  return { manifest, mappings, skipped };
}

function readCriticalFields(value: unknown, context: ArchiveContext): string[] {
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === 'string')) {
    addDiagnostic(context, {
      severity: 'error', code: 'invalid_manifest', message: 'MiYu manifest critical must be an array of field names.',
      entryPath: MIYU_VAULT_ARCHIVE_MANIFEST_NAME,
    });
    return [];
  }
  const unique = new Set<string>();
  for (const entry of value) {
    if (!entry || entry.length > context.limits.maxIdentifierChars) {
      addDiagnostic(context, {
        severity: 'error', code: 'invalid_manifest', message: 'Manifest critical field names must be bounded non-empty strings.',
        entryPath: MIYU_VAULT_ARCHIVE_MANIFEST_NAME,
      });
      continue;
    }
    if (unique.has(entry)) {
      addDiagnostic(context, {
        severity: 'error', code: 'invalid_manifest', message: `Manifest critical field ${entry} is duplicated.`,
        entryPath: MIYU_VAULT_ARCHIVE_MANIFEST_NAME,
      });
    }
    unique.add(entry);
  }
  return [...unique];
}

function parseManifestSkipped(
  value: unknown,
  stableIds: Set<string>,
  context: ArchiveContext,
): VaultArchiveSkippedAttachment[] {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    addDiagnostic(context, {
      severity: 'error', code: 'invalid_manifest', message: 'Manifest skippedAttachments must be an array.',
      entryPath: MIYU_VAULT_ARCHIVE_MANIFEST_NAME,
    });
    return [];
  }
  if (value.length > context.limits.maxEntries) {
    addLimitDiagnostic(context, 'manifest_records_limit_exceeded', MIYU_VAULT_ARCHIVE_MANIFEST_NAME, value.length, context.limits.maxEntries);
    return [];
  }
  const skipped: VaultArchiveSkippedAttachment[] = [];
  for (const [index, raw] of value.entries()) {
    if (!isRecord(raw)) {
      addManifestRecordDiagnostic(context, 'Skipped attachment records must be objects.', index);
      continue;
    }
    for (const key of Object.keys(raw)) {
      if (!['reason', 'itemToken', 'attachmentId', 'path'].includes(key)) {
        addManifestRecordDiagnostic(context, `Skipped attachment record contains unknown field ${key}.`, index, 'unknown_manifest_field');
      }
    }
    const skippedEntry: VaultArchiveSkippedAttachment = {
      reason: typeof raw.reason === 'string' ? raw.reason : '',
      ...(typeof raw.itemToken === 'string' ? { itemToken: raw.itemToken } : {}),
      ...(typeof raw.attachmentId === 'string' ? { attachmentId: raw.attachmentId } : {}),
      ...(typeof raw.path === 'string' ? { path: raw.path } : {}),
    };
    validateSkippedAttachment(skippedEntry, context, true);
    if (skippedEntry.itemToken && skippedEntry.attachmentId) {
      const stableKey = `${skippedEntry.itemToken}\u0000${skippedEntry.attachmentId}`;
      if (stableIds.has(stableKey)) {
        addManifestRecordDiagnostic(context, 'An attachment cannot be both included and skipped.', index, 'contradictory_attachment_status');
      }
      stableIds.add(stableKey);
    }
    skipped.push(skippedEntry);
    addSkippedDiagnostic(context, skippedEntry);
  }
  return skipped;
}

function readManifestString(
  value: unknown,
  field: string,
  index: number,
  context: ArchiveContext,
): string | undefined {
  if (typeof value !== 'string' || value.length === 0 || value.length > context.limits.maxIdentifierChars) {
    addManifestRecordDiagnostic(context, `Manifest ${field} must be a bounded non-empty string.`, index);
    return undefined;
  }
  return value;
}

function addManifestRecordDiagnostic(context: ArchiveContext, message: string, index: number, code = 'invalid_manifest'): void {
  addDiagnostic(context, {
    severity: 'error', code, message: `${message} Record ${index}.`, entryPath: MIYU_VAULT_ARCHIVE_MANIFEST_NAME,
  });
}

class ArchivePathRegistry {
  private readonly explicitEntries = new Set<string>();
  private readonly files = new Set<string>();
  private readonly directories = new Set<string>();

  constructor(private readonly context: ArchiveContext) {}

  addFile(path: string): void {
    const canonical = canonicalPath(path);
    if (this.explicitEntries.has(canonical)) {
      this.duplicate(path);
      return;
    }
    this.explicitEntries.add(canonical);
    if (this.directories.has(canonical)) {
      this.masquerade(path);
      return;
    }
    for (const ancestor of pathAncestors(canonical)) {
      if (this.files.has(ancestor)) {
        this.masquerade(path);
        return;
      }
      this.directories.add(ancestor);
    }
    this.files.add(canonical);
  }

  addDirectory(path: string): void {
    const canonical = canonicalPath(path.slice(0, -1));
    const explicit = `${canonical}/`;
    if (this.explicitEntries.has(explicit)) {
      this.duplicate(path);
      return;
    }
    this.explicitEntries.add(explicit);
    if (this.files.has(canonical)) {
      this.masquerade(path);
      return;
    }
    for (const ancestor of pathAncestors(canonical)) {
      if (this.files.has(ancestor)) {
        this.masquerade(path);
        return;
      }
      this.directories.add(ancestor);
    }
    this.directories.add(canonical);
  }

  private duplicate(path: string): void {
    addDiagnostic(this.context, {
      severity: 'error', code: 'duplicate_entry_path', message: 'ZIP entry paths must be unique, including case and Unicode normalization.',
      entryPath: path,
    });
  }

  private masquerade(path: string): void {
    addDiagnostic(this.context, {
      severity: 'error', code: 'directory_masquerade', message: 'A ZIP path cannot be both a file and a directory.', entryPath: path,
    });
  }
}

function validateSafePath(path: string, context: ArchiveContext): void {
  if (!path || path.length > context.limits.maxPathChars) {
    addDiagnostic(context, {
      severity: 'error', code: 'invalid_entry_path', message: 'ZIP entry path is empty or exceeds the configured length.', entryPath: path,
    });
    return;
  }
  if (path.includes('\0')) {
    addDiagnostic(context, {
      severity: 'error', code: 'nul_in_entry_path', message: 'ZIP entry paths must not contain NUL.', entryPath: path,
    });
  }
  if (path.includes('\\')) {
    addDiagnostic(context, {
      severity: 'error', code: 'path_traversal', message: 'ZIP entry paths must use forward slashes only.', entryPath: path,
    });
  }
  if (path.startsWith('/') || /^[A-Za-z]:/.test(path)) {
    addDiagnostic(context, {
      severity: 'error', code: 'absolute_entry_path', message: 'ZIP entry paths must be relative.', entryPath: path,
    });
  }
  const core = path.endsWith('/') ? path.slice(0, -1) : path;
  const segments = core.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    addDiagnostic(context, {
      severity: 'error', code: 'path_traversal', message: 'ZIP entry paths must not contain empty, dot, or parent segments.', entryPath: path,
    });
  }
}

function validateAttachmentPath(path: string, context: ArchiveContext): void {
  validateSafePath(path, context);
  const segments = path.split('/');
  if (path.endsWith('/') || segments.length < 3 || segments[0] !== 'attachments' || segments.some((segment) => !segment)) {
    addDiagnostic(context, {
      severity: 'error', code: 'invalid_attachment_path',
      message: 'Attachment paths must use attachments/<item>/<file> with a non-empty file name.', entryPath: path,
    });
  }
}

function isAllowedFilePath(path: string): boolean {
  if (path === BITWARDEN_VAULT_ARCHIVE_DATA_NAME || path === MIYU_VAULT_ARCHIVE_MANIFEST_NAME) return true;
  const segments = path.split('/');
  return !path.endsWith('/') && segments.length >= 3 && segments[0] === 'attachments' && segments.every(Boolean);
}

function canonicalPath(path: string): string {
  return path.normalize('NFC').toLocaleLowerCase('en-US');
}

function pathAncestors(path: string): string[] {
  const parts = path.split('/');
  const ancestors: string[] = [];
  for (let index = 1; index < parts.length; index++) ancestors.push(parts.slice(0, index).join('/'));
  return ancestors;
}

function validateEntrySize(path: string, size: number, context: ArchiveContext): void {
  if (size > context.limits.maxEntryUncompressedBytes) {
    addLimitDiagnostic(context, 'entry_uncompressed_too_large', path, size, context.limits.maxEntryUncompressedBytes);
  }
}

function validateIdentifier(
  value: string | undefined,
  field: 'itemToken' | 'attachmentId',
  path: string,
  context: ArchiveContext,
): string | undefined {
  if (!value || value.length > context.limits.maxIdentifierChars || value.includes('\0')) {
    addDiagnostic(context, {
      severity: 'error', code: 'invalid_attachment_identity',
      message: `${field} must be a bounded non-empty string without NUL.`, entryPath: path,
    });
    return undefined;
  }
  return value;
}

function validateSkippedAttachment(
  skipped: VaultArchiveSkippedAttachment,
  context: ArchiveContext,
  requireIdentity: boolean,
): void {
  if (!skipped.reason || skipped.reason.length > context.limits.maxIdentifierChars) {
    addDiagnostic(context, {
      severity: 'error', code: 'invalid_skipped_attachment', message: 'Skipped attachment reason must be a bounded non-empty string.',
      ...(skipped.path ? { entryPath: skipped.path } : {}),
    });
  }
  if (skipped.path) validateAttachmentPath(skipped.path, context);
  if (requireIdentity || skipped.itemToken !== undefined) {
    validateIdentifier(skipped.itemToken, 'itemToken', skipped.path ?? MIYU_VAULT_ARCHIVE_MANIFEST_NAME, context);
  }
  if (requireIdentity || skipped.attachmentId !== undefined) {
    validateIdentifier(skipped.attachmentId, 'attachmentId', skipped.path ?? MIYU_VAULT_ARCHIVE_MANIFEST_NAME, context);
  }
}

function addSkippedDiagnostic(context: ArchiveContext, skipped: VaultArchiveSkippedAttachment): void {
  addDiagnostic(context, {
    severity: 'warning',
    code: 'attachment_skipped',
    message: skipped.reason,
    ...(skipped.path ? { entryPath: skipped.path } : {}),
    ...(skipped.itemToken ? { itemToken: skipped.itemToken } : {}),
    ...(skipped.attachmentId ? { attachmentId: skipped.attachmentId } : {}),
  });
}

function validateJsonDocument(bytes: Uint8Array, path: string, context: ArchiveContext): void {
  try {
    const parsed = JSON.parse(strFromU8(bytes)) as unknown;
    if (!isRecord(parsed)) throw new Error('root must be an object');
  } catch (error) {
    addDiagnostic(context, {
      severity: 'error', code: 'invalid_data_json', message: errorMessage('data.json is not a valid UTF-8 JSON object', error),
      entryPath: path,
    });
  }
}

function createContext(overrides: Partial<VaultArchiveLimits> | undefined): ArchiveContext {
  const limits: VaultArchiveLimits = { ...DEFAULT_VAULT_ARCHIVE_LIMITS, ...overrides };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isFinite(value) || value <= 0 || (name !== 'maxCompressionRatio' && !Number.isSafeInteger(value))) {
      throw new RangeError(`${name} must be a positive ${name === 'maxCompressionRatio' ? 'finite number' : 'safe integer'}`);
    }
  }
  return { limits, diagnostics: [], diagnosticsTruncated: false };
}

function addDiagnostic(context: ArchiveContext, diagnostic: VaultArchiveDiagnostic): void {
  if (context.diagnostics.length < context.limits.maxDiagnostics) {
    context.diagnostics.push(diagnostic);
    return;
  }
  if (context.diagnosticsTruncated) return;
  context.diagnosticsTruncated = true;
  context.diagnostics[context.diagnostics.length - 1] = {
    severity: 'error', code: 'diagnostics_truncated', message: 'Archive diagnostics exceeded the configured limit.',
  };
}

function addLimitDiagnostic(
  context: ArchiveContext,
  code: string,
  entryPath: string | undefined,
  actual: number,
  limit: number,
): void {
  addDiagnostic(context, {
    severity: 'error', code, message: `Value ${actual} exceeds the configured limit of ${limit}.`,
    ...(entryPath ? { entryPath } : {}),
  });
}

function addDamagedZipDiagnostic(context: ArchiveContext, error: unknown, prefix: string): void {
  addDiagnostic(context, {
    severity: 'error', code: 'damaged_zip', message: errorMessage(prefix, error),
  });
}

function errorMessage(prefix: string, error: unknown): string {
  return error instanceof Error && error.message ? `${prefix}: ${error.message}` : prefix;
}

function hasErrors(context: ArchiveContext): boolean {
  return context.diagnostics.some((diagnostic) => diagnostic.severity === 'error');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
