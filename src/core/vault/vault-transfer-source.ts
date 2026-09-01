import {
  DEFAULT_VAULT_ARCHIVE_LIMITS,
  readVaultArchive,
  type VaultArchiveLimits,
  type VaultArchiveReadResult,
} from './vault-archive.js';
import { decryptEncryptedExport } from './vault-io.js';
import {
  DEFAULT_VAULT_TRANSFER_LIMITS,
  inspectVaultTransferCsv,
  inspectVaultTransferJson,
  type VaultTransferInspection,
  type VaultTransferLimits,
} from './vault-transfer.js';

export const DEFAULT_MAX_VAULT_TRANSFER_SOURCE_BYTES = 64 * 1024 * 1024;

export const VAULT_TRANSFER_SOURCE_ARCHIVE_LIMITS: Readonly<VaultArchiveLimits> = Object.freeze({
  ...DEFAULT_VAULT_ARCHIVE_LIMITS,
  maxArchiveBytes: 64 * 1024 * 1024,
  maxTotalCompressedBytes: 64 * 1024 * 1024,
  maxTotalUncompressedBytes: 64 * 1024 * 1024,
  maxEntryCompressedBytes: 64 * 1024 * 1024,
  maxEntryUncompressedBytes: 64 * 1024 * 1024,
  maxDataJsonBytes: 32 * 1024 * 1024,
});

export type VaultTransferSourceFormat = 'json' | 'encrypted-json' | 'csv' | 'zip';

export interface VaultTransferSourceAttachmentMetadata {
  readonly path: string;
  readonly byteLength: number;
  /** Present only when the validated archive manifest supplied the mapping. */
  readonly itemToken?: string;
  /** Present only when the validated archive manifest supplied the mapping. */
  readonly attachmentId?: string;
}

export type VaultTransferSourceLimits = Partial<VaultTransferLimits> & {
  /** Bounds the uploaded envelope before any decoding, decryption, or ZIP parsing. */
  readonly maxSourceBytes?: number;
  /** Archive-specific limits passed to the authoritative ZIP reader. */
  readonly archive?: Partial<VaultArchiveLimits>;
};

export interface InspectVaultTransferSourceOptions {
  /** Supply only when retrying the same source after a password_required result. */
  readonly password?: string;
  readonly limits?: VaultTransferSourceLimits;
  /** Worker-only account-key boundary. `null` intentionally hides wrong-account versus tamper. */
  readonly inspectAccountEncrypted?: (
    content: string,
    limits: Readonly<VaultTransferLimits>,
  ) => Promise<VaultTransferInspection | null>;
}

export interface VaultTransferSourceOk {
  readonly status: 'ok';
  readonly format: VaultTransferSourceFormat;
  readonly inspection: VaultTransferInspection;
  readonly attachmentCount: number;
  readonly attachments: readonly VaultTransferSourceAttachmentMetadata[];
  readonly skippedAttachmentCount: number;
}

export interface VaultTransferSourcePasswordRequired {
  readonly status: 'password_required';
  readonly format: 'encrypted-json' | 'zip';
}

export type VaultTransferSourceFailureCode =
  | 'invalid_input'
  | 'empty_input'
  | 'source_too_large'
  | 'input_too_large'
  | 'decrypted_input_too_large'
  | 'invalid_utf8'
  | 'invalid_archive'
  | 'unsupported_encrypted_export'
  | 'unexpected_password'
  | 'decryption_failed';

export interface VaultTransferSourceFailed {
  readonly status: 'failed';
  /** Stable machine-readable code. Source text and parser error messages are never returned. */
  readonly code: VaultTransferSourceFailureCode;
}

export type VaultTransferSourceResult =
  | VaultTransferSourceOk
  | VaultTransferSourcePasswordRequired
  | VaultTransferSourceFailed;

interface ResolvedSourceLimits {
  maxSourceBytes: number;
  transfer: VaultTransferLimits;
  archive: VaultArchiveLimits;
}

interface EmptyAttachmentSummary {
  attachmentCount: 0;
  attachments: readonly [];
  skippedAttachmentCount: 0;
}

const EMPTY_ATTACHMENT_LIST: readonly [] = Object.freeze([]) as readonly [];
const EMPTY_ATTACHMENTS: EmptyAttachmentSummary = Object.freeze({
  attachmentCount: 0,
  attachments: EMPTY_ATTACHMENT_LIST,
  skippedAttachmentCount: 0,
});

const STRICT_UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

/**
 * Authoritatively identify and inspect uploaded vault-transfer bytes.
 *
 * The source name and extension are intentionally absent from this API. ZIP is selected only by
 * its byte signature, while all text is decoded as strict UTF-8 before content inspection.
 */
export async function inspectVaultTransferSource(
  source: Uint8Array,
  options: InspectVaultTransferSourceOptions = {},
): Promise<VaultTransferSourceResult> {
  if (!(source instanceof Uint8Array)) return failed('invalid_input');
  const limits = resolveSourceLimits(options.limits);
  if (source.byteLength === 0) return failed('empty_input');
  if (source.byteLength > limits.maxSourceBytes) return failed('source_too_large');

  if (hasZipSignature(source)) {
    return inspectArchiveSource(source, options.password, limits);
  }

  const decoded = decodeStrictUtf8(source);
  if (decoded === null) return failed('invalid_utf8');
  return inspectDecodedText(
    decoded,
    source.byteLength,
    options.password,
    limits.transfer,
    'text',
    options.inspectAccountEncrypted,
  );
}

async function inspectArchiveSource(
  source: Uint8Array,
  password: string | undefined,
  limits: ResolvedSourceLimits,
): Promise<VaultTransferSourceResult> {
  const archive = readVaultArchive(source, { limits: limits.archive });
  if (!archive.ok || archive.dataJson === null) {
    clearArchivePayloads(archive);
    return failed('invalid_archive');
  }

  try {
    const decoded = decodeStrictUtf8(archive.dataJson);
    if (decoded === null) return failed('invalid_utf8');
    const inspected = await inspectDecodedText(
      decoded,
      archive.dataJson.byteLength,
      password,
      limits.transfer,
      'zip',
      undefined,
    );
    if (inspected.status !== 'ok') return inspected;

    const attachments = archive.attachments.map<VaultTransferSourceAttachmentMetadata>((attachment) => ({
      path: attachment.path,
      byteLength: attachment.data.byteLength,
      ...(attachment.itemToken === undefined ? {} : { itemToken: attachment.itemToken }),
      ...(attachment.attachmentId === undefined ? {} : { attachmentId: attachment.attachmentId }),
    }));
    return {
      ...inspected,
      format: 'zip',
      attachmentCount: attachments.length,
      attachments,
      skippedAttachmentCount: archive.skippedAttachments.length,
    };
  } finally {
    clearArchivePayloads(archive);
  }
}

async function inspectDecodedText(
  content: string,
  encodedBytes: number,
  password: string | undefined,
  limits: VaultTransferLimits,
  container: 'text' | 'zip',
  inspectAccountEncrypted: InspectVaultTransferSourceOptions['inspectAccountEncrypted'],
): Promise<VaultTransferSourceResult> {
  const trimmed = content.trimStart();
  if (trimmed.length === 0) return failed('empty_input');

  // Only an object can be a password-protected envelope. Reject oversized CSV, arrays, and scalar
  // JSON before asking JSON.parse or the CSV parser to traverse attacker-controlled input.
  if (encodedBytes > limits.maxInputBytes && !trimmed.startsWith('{')) {
    return failed('input_too_large');
  }

  const parsed = tryParseJson(content);
  const jsonLike = parsed.parsed || trimmed.startsWith('{') || trimmed.startsWith('[');
  if (!jsonLike) {
    if (encodedBytes > limits.maxInputBytes) return failed('input_too_large');
    if (password !== undefined) return failed('unexpected_password');
    return ok('csv', inspectVaultTransferCsv(content, { limits }));
  }

  if (parsed.parsed && isRecord(parsed.value) && parsed.value.encrypted === true) {
    if (parsed.value.passwordProtected !== true) {
      if (container !== 'text' || inspectAccountEncrypted === undefined) {
        return failed('unsupported_encrypted_export');
      }
      if (encodedBytes > limits.maxInputBytes) return failed('input_too_large');
      if (password !== undefined) return failed('unexpected_password');
      const inspection = await inspectAccountEncrypted(content, limits);
      return inspection === null ? failed('decryption_failed') : ok('encrypted-json', inspection);
    }
    const protectedFormat = container === 'zip' ? 'zip' : 'encrypted-json';
    if (password === undefined) return { status: 'password_required', format: protectedFormat };

    let plaintext: string;
    try {
      plaintext = await decryptEncryptedExport(content, password);
    } catch {
      return failed('decryption_failed');
    }
    const plaintextBytes = utf8ByteLength(plaintext);
    if (plaintextBytes > limits.maxInputBytes) return failed('decrypted_input_too_large');
    return ok(protectedFormat, inspectVaultTransferJson(plaintext, { limits }));
  }

  if (encodedBytes > limits.maxInputBytes) return failed('input_too_large');
  if (password !== undefined) return failed('unexpected_password');
  return ok(container === 'zip' ? 'zip' : 'json', inspectVaultTransferJson(content, { limits }));
}

function ok(format: VaultTransferSourceFormat, inspection: VaultTransferInspection): VaultTransferSourceOk {
  return { status: 'ok', format, inspection, ...EMPTY_ATTACHMENTS };
}

function failed(code: VaultTransferSourceFailureCode): VaultTransferSourceFailed {
  return { status: 'failed', code };
}

function tryParseJson(content: string): { parsed: true; value: unknown } | { parsed: false } {
  try {
    return { parsed: true, value: JSON.parse(content) as unknown };
  } catch {
    return { parsed: false };
  }
}

function decodeStrictUtf8(bytes: Uint8Array): string | null {
  try {
    return STRICT_UTF8_DECODER.decode(bytes);
  } catch {
    return null;
  }
}

function hasZipSignature(bytes: Uint8Array): boolean {
  if (bytes.byteLength < 4 || bytes[0] !== 0x50 || bytes[1] !== 0x4b) return false;
  const third = bytes[2];
  const fourth = bytes[3];
  return (third === 0x03 && fourth === 0x04)
    || (third === 0x05 && fourth === 0x06)
    || (third === 0x07 && fourth === 0x08);
}

function clearArchivePayloads(archive: VaultArchiveReadResult): void {
  archive.dataJson?.fill(0);
  for (const attachment of archive.attachments) attachment.data.fill(0);
}

function resolveSourceLimits(overrides: VaultTransferSourceLimits | undefined): ResolvedSourceLimits {
  const {
    maxSourceBytes = DEFAULT_MAX_VAULT_TRANSFER_SOURCE_BYTES,
    archive: archiveOverrides,
    ...transferOverrides
  } = overrides ?? {};
  if (!Number.isSafeInteger(maxSourceBytes) || maxSourceBytes < 1) {
    throw new RangeError('maxSourceBytes must be a positive safe integer');
  }

  const transfer: VaultTransferLimits = { ...DEFAULT_VAULT_TRANSFER_LIMITS, ...transferOverrides };
  for (const [name, value] of Object.entries(transfer)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new RangeError(`${name} must be a positive safe integer`);
    }
  }

  const requestedArchive: VaultArchiveLimits = { ...DEFAULT_VAULT_ARCHIVE_LIMITS, ...archiveOverrides };
  for (const [name, value] of Object.entries(requestedArchive)) {
    const integerRequired = name !== 'maxCompressionRatio';
    if (!Number.isFinite(value) || value <= 0 || (integerRequired && !Number.isSafeInteger(value))) {
      throw new RangeError(`${name} must be a positive ${integerRequired ? 'safe integer' : 'finite number'}`);
    }
  }
  const archiveBudget = Math.min(maxSourceBytes, VAULT_TRANSFER_SOURCE_ARCHIVE_LIMITS.maxTotalUncompressedBytes);
  const archive: VaultArchiveLimits = {
    maxArchiveBytes: Math.min(
      requestedArchive.maxArchiveBytes,
      VAULT_TRANSFER_SOURCE_ARCHIVE_LIMITS.maxArchiveBytes,
      maxSourceBytes,
    ),
    maxTotalCompressedBytes: Math.min(
      requestedArchive.maxTotalCompressedBytes,
      VAULT_TRANSFER_SOURCE_ARCHIVE_LIMITS.maxTotalCompressedBytes,
      maxSourceBytes,
    ),
    maxTotalUncompressedBytes: Math.min(requestedArchive.maxTotalUncompressedBytes, archiveBudget),
    maxEntries: Math.min(requestedArchive.maxEntries, VAULT_TRANSFER_SOURCE_ARCHIVE_LIMITS.maxEntries),
    maxEntryCompressedBytes: Math.min(
      requestedArchive.maxEntryCompressedBytes,
      VAULT_TRANSFER_SOURCE_ARCHIVE_LIMITS.maxEntryCompressedBytes,
      maxSourceBytes,
    ),
    maxEntryUncompressedBytes: Math.min(
      requestedArchive.maxEntryUncompressedBytes,
      VAULT_TRANSFER_SOURCE_ARCHIVE_LIMITS.maxEntryUncompressedBytes,
      archiveBudget,
    ),
    maxDataJsonBytes: Math.min(
      requestedArchive.maxDataJsonBytes,
      VAULT_TRANSFER_SOURCE_ARCHIVE_LIMITS.maxDataJsonBytes,
      archiveBudget,
    ),
    maxManifestBytes: Math.min(
      requestedArchive.maxManifestBytes,
      VAULT_TRANSFER_SOURCE_ARCHIVE_LIMITS.maxManifestBytes,
      archiveBudget,
    ),
    maxCompressionRatio: Math.min(
      requestedArchive.maxCompressionRatio,
      VAULT_TRANSFER_SOURCE_ARCHIVE_LIMITS.maxCompressionRatio,
    ),
    maxPathChars: Math.min(requestedArchive.maxPathChars, VAULT_TRANSFER_SOURCE_ARCHIVE_LIMITS.maxPathChars),
    maxIdentifierChars: Math.min(
      requestedArchive.maxIdentifierChars,
      VAULT_TRANSFER_SOURCE_ARCHIVE_LIMITS.maxIdentifierChars,
    ),
    maxDiagnostics: Math.min(requestedArchive.maxDiagnostics, VAULT_TRANSFER_SOURCE_ARCHIVE_LIMITS.maxDiagnostics),
  };
  return { maxSourceBytes, transfer, archive };
}

function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x7f) bytes += 1;
    else if (code <= 0x7ff) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const low = value.charCodeAt(index + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        bytes += 4;
        index++;
      } else bytes += 3;
    } else bytes += 3;
  }
  return bytes;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
