import { base64ToBytes, bytesToBase64 } from '../core/crypto/encoding.js';
import {
  VAULT_TRANSFER_EXPORT_WARNING_CODES,
  type VaultTransferExportReview,
  type VaultTransferExportWarning,
  type VaultTransferExportWarningCode,
} from '../core/vault/vault-transfer-export-review.js';
import {
  PERSONAL_VAULT_TRANSFER_EXPORT_TARGET,
  canonicalizeVaultTransferExportTarget,
  type VaultTransferExportTarget,
} from '../core/vault/vault-transfer-target.js';

export type {
  VaultTransferExportReview,
  VaultTransferExportWarning,
  VaultTransferExportWarningCode,
} from '../core/vault/vault-transfer-export-review.js';

export const VAULT_TRANSFER_PORT_NAME = 'vault-transfer-v1';
export const VAULT_TRANSFER_PORT_VERSION = 1 as const;
export const MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES = 256 * 1024;
export const MAX_VAULT_TRANSFER_PORT_ENCODED_CHUNK_CHARS =
  Math.ceil(MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES / 3) * 4;
export const MAX_VAULT_TRANSFER_PORT_TOTAL_BYTES = 512 * 1024 * 1024;

const MAX_FILE_NAME_CHARS = 255;
const MAX_PASSWORD_CHARS = 1_024;
const MAX_SEQUENCE = 0xffff_ffff;
const MAX_RESULT_COUNT = 1_000_000;
const MAX_DIAGNOSTIC_GROUP_ENTRIES = 32;
export const MAX_VAULT_TRANSFER_RECOVERY_BARRIERS = 32;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CANONICAL_BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export type VaultTransferImportFormat = 'json' | 'encrypted-json' | 'csv' | 'zip';
export type VaultTransferExportFormat = 'json' | 'encrypted-json' | 'csv' | 'zip';
export type VaultTransferPortPhase =
  | 'idle'
  | 'uploading'
  | 'inspecting'
  | 'previewed'
  | 'committing'
  | 'exporting'
  | 'completed'
  | 'cancelled';

export interface VaultTransferImportBeginMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'import.begin';
  readonly expectedTotalBytes: number;
  readonly fileName: string;
}

export interface VaultTransferImportChunkMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'import.chunk';
  readonly transferId: string;
  readonly sequence: number;
  readonly byteLength: number;
  readonly dataBase64: string;
}

export interface VaultTransferImportSealMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'import.seal';
  readonly transferId: string;
  readonly password?: string;
}

export interface VaultTransferImportConfirmMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'import.confirm';
  readonly transferId: string;
  readonly previewRevision: string;
}

export interface VaultTransferImportResultAckMessage {
  /** Acknowledge only after the client has accepted the terminal import result. */
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'import.result.ack';
  readonly transferId: string;
}

export interface VaultTransferCancelMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'cancel';
  readonly transferId: string;
}

export type VaultTransferExportBeginMessage =
  | {
      readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
      readonly type: 'export.begin';
      readonly format: 'json' | 'csv' | 'zip';
      readonly authorizationId: string;
      readonly target: VaultTransferExportTarget;
    }
  | {
      readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
      readonly type: 'export.begin';
      readonly format: 'encrypted-json';
      readonly authorizationId: string;
      readonly target: VaultTransferExportTarget;
      /** Omitted for an account-encrypted export; present for a password-protected file export. */
      readonly filePassword?: string;
    };

export interface VaultTransferExportAckMessage {
  /** The worker must not post the next export chunk until this exact sequence is received. */
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'export.ack';
  readonly transferId: string;
  readonly sequence: number;
}

export interface VaultTransferRecoveryInspectMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'recovery.inspect';
}

export type VaultTransferClientMessage =
  | VaultTransferImportBeginMessage
  | VaultTransferImportChunkMessage
  | VaultTransferImportSealMessage
  | VaultTransferImportConfirmMessage
  | VaultTransferImportResultAckMessage
  | VaultTransferCancelMessage
  | VaultTransferExportBeginMessage
  | VaultTransferExportAckMessage
  | VaultTransferRecoveryInspectMessage
  | VaultTransferRecoveryClearMessage;

export interface VaultTransferImportBegunMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'import.begun';
  readonly transferId: string;
  readonly phase: 'uploading';
  readonly maxChunkBytes: number;
  readonly maxEncodedChunkChars: number;
}

export interface VaultTransferImportAckMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'import.ack';
  readonly transferId: string;
  readonly phase: 'uploading';
  readonly sequence: number;
  readonly nextSequence: number;
  readonly byteLength: number;
  readonly totalBytes: number;
}

export const VAULT_TRANSFER_PORT_DIAGNOSTIC_CODES = [
  'malformed_input',
  'unsupported_format',
  'unsupported_data',
  'unknown_data',
  'limit_exceeded',
  'missing_reference',
  'unavailable_resource',
  'policy_blocked',
  'organization_target_required',
  'capability_blocked',
  'attachment_unavailable',
  'partial_result',
  'outcome_unknown',
  'diagnostics_omitted',
  'other',
] as const;

export type VaultTransferPortDiagnosticCode =
  (typeof VAULT_TRANSFER_PORT_DIAGNOSTIC_CODES)[number];

export interface VaultTransferPortSanitizedDiagnostic {
  /** A fixed category only. Raw messages, paths, indexes, and record values never cross the port. */
  readonly code: VaultTransferPortDiagnosticCode;
  readonly count: number;
}

export interface VaultTransferPortPreviewModel {
  readonly format: VaultTransferImportFormat;
  readonly scope: 'personal' | 'organization';
  readonly phase: 'previewed';
  readonly counts: {
    readonly folders: number;
    readonly collections: number;
    readonly items: number;
    readonly attachments: number;
  };
  readonly diagnostics: {
    readonly errors: readonly VaultTransferPortSanitizedDiagnostic[];
    readonly warnings: readonly VaultTransferPortSanitizedDiagnostic[];
    readonly unsupported: readonly VaultTransferPortSanitizedDiagnostic[];
  };
  readonly organizationTargetRequired: boolean;
  readonly hasUnknownOutcome: boolean;
  readonly canCommit: boolean;
}

export interface VaultTransferImportPreviewMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'import.preview';
  readonly transferId: string;
  readonly previewRevision: string;
  readonly preview: VaultTransferPortPreviewModel;
}

export interface VaultTransferImportResultMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'import.result';
  readonly transferId: string;
  readonly phase: 'completed';
  readonly status: 'blocked' | 'completed' | 'partial' | 'outcome_unknown';
  readonly counts: {
    readonly committed: number;
    readonly rejected: number;
    readonly skipped: number;
    readonly outcomeUnknown: number;
  };
  readonly mustSyncBeforeRetry: boolean;
}

export interface VaultTransferExportBegunMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'export.begun';
  readonly transferId: string;
  readonly format: VaultTransferExportFormat;
  readonly phase: 'exporting';
  readonly fileName: string;
  /** Present for CSV so the client can require disclosure before download. */
  readonly review?: VaultTransferExportReview;
}

export interface VaultTransferExportChunkMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'export.chunk';
  readonly transferId: string;
  readonly format: VaultTransferExportFormat;
  readonly phase: 'exporting';
  /** Exactly one matching `export.ack` is required before the next chunk may be posted. */
  readonly sequence: number;
  readonly byteLength: number;
  readonly dataBase64: string;
}

export interface VaultTransferExportDoneMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'export.done';
  readonly transferId: string;
  readonly format: VaultTransferExportFormat;
  readonly phase: 'completed';
  readonly chunkCount: number;
  readonly totalBytes: number;
  /** Opaque worker-owned proof; present only when this personal export is auditable. */
  readonly clientEventAckId?: string;
}

export const VAULT_TRANSFER_RECOVERY_REASONS = [
  'outcome_unknown',
  'partial_result',
  'pending_result_delivery',
] as const;

export type VaultTransferRecoveryReason =
  (typeof VAULT_TRANSFER_RECOVERY_REASONS)[number];

export interface VaultTransferRecoveryClearExpectation {
  readonly transferId: string;
  readonly reason: VaultTransferRecoveryReason;
}

export interface VaultTransferRecoveryClearMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'recovery.clear';
  readonly expectedBarriers: readonly VaultTransferRecoveryClearExpectation[];
}

export interface VaultTransferRecoveryBarrier {
  readonly transferId: string;
  readonly reason: VaultTransferRecoveryReason;
  readonly reconciled: boolean;
  readonly clearable: boolean;
}

export interface VaultTransferRecoveryStatus {
  readonly count: number;
  readonly unresolvedUnknownCount: number;
  readonly reconcileRequiredCount: number;
  readonly omittedCount: number;
  readonly barriers: readonly VaultTransferRecoveryBarrier[];
}

export interface VaultTransferRecoveryStatusMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'recovery.status';
  readonly phase: 'completed';
  readonly status: VaultTransferRecoveryStatus;
}

export interface VaultTransferRecoveryClearedMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'recovery.cleared';
  readonly phase: 'completed';
  readonly cleared: number;
}

export const VAULT_TRANSFER_PORT_ERROR_MESSAGES = Object.freeze({
  invalid_message: 'The vault transfer message is invalid.',
  unsupported_version: 'The vault transfer protocol version is not supported.',
  capacity: 'Too many vault transfer operations are active.',
  not_found: 'The vault transfer is no longer available.',
  expired: 'The vault transfer expired.',
  lease_changed: 'The active vault session changed.',
  invalid_state: 'The vault transfer is not in the required state.',
  invalid_sequence: 'The vault transfer chunk sequence is invalid.',
  ack_required: 'The previous vault transfer chunk is awaiting acknowledgement.',
  invalid_chunk: 'The vault transfer chunk is invalid.',
  chunk_too_large: 'The vault transfer chunk is too large.',
  total_too_large: 'The vault transfer is too large.',
  size_mismatch: 'The vault transfer size does not match the declared size.',
  preview_mismatch: 'The vault transfer preview is no longer current.',
  password_required: 'A password is required for this encrypted vault transfer.',
  password_not_allowed: 'A password is not allowed for this vault transfer format.',
  inspection_failed: 'The vault transfer could not be inspected safely.',
  commit_failed: 'The vault transfer could not be completed.',
  export_authorization_invalid: 'Vault export verification is invalid or expired.',
  export_failed: 'The vault export could not be completed.',
  cancelled: 'The vault transfer was cancelled.',
  outcome_unknown: 'The vault transfer outcome is unknown. Sync before retrying.',
  recovery_not_clearable: 'Vault transfer recovery records must be reconciled before clearing.',
  internal_error: 'The vault transfer could not be completed.',
} as const);

export type VaultTransferPortErrorCode = keyof typeof VAULT_TRANSFER_PORT_ERROR_MESSAGES;

export interface VaultTransferPortErrorMessage {
  readonly version: typeof VAULT_TRANSFER_PORT_VERSION;
  readonly type: 'error';
  readonly transferId: string | null;
  readonly phase: VaultTransferPortPhase;
  readonly error: {
    readonly code: VaultTransferPortErrorCode;
    readonly message: (typeof VAULT_TRANSFER_PORT_ERROR_MESSAGES)[VaultTransferPortErrorCode];
  };
}

export type VaultTransferWorkerMessage =
  | VaultTransferImportBegunMessage
  | VaultTransferImportAckMessage
  | VaultTransferImportPreviewMessage
  | VaultTransferImportResultMessage
  | VaultTransferExportBegunMessage
  | VaultTransferExportChunkMessage
  | VaultTransferExportDoneMessage
  | VaultTransferRecoveryStatusMessage
  | VaultTransferRecoveryClearedMessage
  | VaultTransferPortErrorMessage;

export class VaultTransferPortProtocolError extends Error {
  constructor(readonly code: VaultTransferPortErrorCode) {
    super(VAULT_TRANSFER_PORT_ERROR_MESSAGES[code]);
    this.name = 'VaultTransferPortProtocolError';
  }
}

/** Encode one non-empty port chunk as canonical padded RFC 4648 base64. */
export function encodeVaultTransferPortChunk(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 1) invalidMessage();
  if (bytes.byteLength > MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES) {
    throw new VaultTransferPortProtocolError('chunk_too_large');
  }
  const encoded = bytesToBase64(bytes);
  if (encoded.length > MAX_VAULT_TRANSFER_PORT_ENCODED_CHUNK_CHARS) {
    throw new VaultTransferPortProtocolError('chunk_too_large');
  }
  return encoded;
}

/** Decode only canonical padded RFC 4648 base64 and optionally bind its decoded length. */
export function decodeVaultTransferPortChunk(
  encoded: string,
  expectedByteLength?: number,
): Uint8Array {
  if (typeof encoded !== 'string' || encoded.length < 4) invalidChunk();
  if (encoded.length > MAX_VAULT_TRANSFER_PORT_ENCODED_CHUNK_CHARS) {
    throw new VaultTransferPortProtocolError('chunk_too_large');
  }
  if (!CANONICAL_BASE64_PATTERN.test(encoded)) invalidChunk();
  if (expectedByteLength !== undefined) {
    const expected = boundedInteger(expectedByteLength, 1, MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES);
    if (encoded.length !== encodedLength(expected)) invalidChunk();
  }

  let decoded: Uint8Array;
  try {
    decoded = base64ToBytes(encoded);
  } catch {
    invalidChunk();
  }
  if (decoded.byteLength < 1 || decoded.byteLength > MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES) {
    invalidChunk();
  }
  if (bytesToBase64(decoded) !== encoded) invalidChunk();
  if (expectedByteLength !== undefined && decoded.byteLength !== expectedByteLength) invalidChunk();
  return decoded;
}

/**
 * Apply the worker's authoritative format detection before using an import password. Callers must
 * not inspect or derive from the password until this check succeeds.
 */
export function importPasswordForDetectedFormat(
  message: VaultTransferImportSealMessage,
  detectedFormat: VaultTransferImportFormat,
): string | undefined {
  if (detectedFormat === 'encrypted-json') {
    if (message.password === undefined) {
      throw new VaultTransferPortProtocolError('password_required');
    }
    return message.password;
  }
  if (message.password !== undefined) {
    throw new VaultTransferPortProtocolError('password_not_allowed');
  }
  return undefined;
}

export function createVaultTransferPortErrorMessage(
  code: VaultTransferPortErrorCode,
  transferId: string | null,
  phase: VaultTransferPortPhase,
): VaultTransferPortErrorMessage {
  if (!hasOwn(VAULT_TRANSFER_PORT_ERROR_MESSAGES, code)) invalidMessage();
  if (transferId !== null) parseUuidV4(transferId);
  parsePhase(phase);
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'error',
    transferId,
    phase,
    error: { code, message: VAULT_TRANSFER_PORT_ERROR_MESSAGES[code] },
  };
}

export function parseVaultTransferClientMessage(value: unknown): VaultTransferClientMessage {
  const message = parseEnvelope(value);
  switch (message.type) {
    case 'import.begin':
      return parseImportBegin(message);
    case 'import.chunk':
      return parseImportChunk(message);
    case 'import.seal':
      return parseImportSeal(message);
    case 'import.confirm':
      return parseImportConfirm(message);
    case 'import.result.ack':
      return parseImportResultAck(message);
    case 'cancel':
      return parseCancel(message);
    case 'export.begin':
      return parseExportBegin(message);
    case 'export.ack':
      return parseExportAck(message);
    case 'recovery.inspect':
      return parseRecoveryInspect(message);
    case 'recovery.clear':
      return parseRecoveryClear(message);
    default:
      return invalidMessage();
  }
}

export function parseVaultTransferWorkerMessage(value: unknown): VaultTransferWorkerMessage {
  const message = parseEnvelope(value);
  switch (message.type) {
    case 'import.begun':
      return parseImportBegun(message);
    case 'import.ack':
      return parseImportAck(message);
    case 'import.preview':
      return parseImportPreview(message);
    case 'import.result':
      return parseImportResult(message);
    case 'export.begun':
      return parseExportBegun(message);
    case 'export.chunk':
      return parseExportChunk(message);
    case 'export.done':
      return parseExportDone(message);
    case 'recovery.status':
      return parseRecoveryStatusMessage(message);
    case 'recovery.cleared':
      return parseRecoveryClearedMessage(message);
    case 'error':
      return parseErrorMessage(message);
    default:
      return invalidMessage();
  }
}

function parseImportBegin(message: Record<string, unknown>): VaultTransferImportBeginMessage {
  exactKeys(message, ['version', 'type', 'expectedTotalBytes', 'fileName']);
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'import.begin',
    expectedTotalBytes: boundedInteger(
      message.expectedTotalBytes,
      0,
      MAX_VAULT_TRANSFER_PORT_TOTAL_BYTES,
    ),
    fileName: parseFileName(message.fileName),
  };
}

function parseImportChunk(message: Record<string, unknown>): VaultTransferImportChunkMessage {
  exactKeys(message, [
    'version', 'type', 'transferId', 'sequence', 'byteLength', 'dataBase64',
  ]);
  const byteLength = boundedInteger(message.byteLength, 1, MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES);
  const dataBase64 = requiredString(message.dataBase64);
  validateVaultTransferPortChunk(dataBase64, byteLength);
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'import.chunk',
    transferId: parseUuidV4(message.transferId),
    sequence: boundedInteger(message.sequence, 0, MAX_SEQUENCE),
    byteLength,
    dataBase64,
  };
}

function parseImportSeal(message: Record<string, unknown>): VaultTransferImportSealMessage {
  exactKeys(message, ['version', 'type', 'transferId'], ['password']);
  const base = {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'import.seal' as const,
    transferId: parseUuidV4(message.transferId),
  };
  if (!hasOwn(message, 'password')) return base;
  return { ...base, password: parsePassword(message.password) };
}

function parseImportConfirm(message: Record<string, unknown>): VaultTransferImportConfirmMessage {
  exactKeys(message, ['version', 'type', 'transferId', 'previewRevision']);
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'import.confirm',
    transferId: parseUuidV4(message.transferId),
    previewRevision: parseUuidV4(message.previewRevision),
  };
}

function parseImportResultAck(message: Record<string, unknown>): VaultTransferImportResultAckMessage {
  exactKeys(message, ['version', 'type', 'transferId']);
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'import.result.ack',
    transferId: parseUuidV4(message.transferId),
  };
}

function parseCancel(message: Record<string, unknown>): VaultTransferCancelMessage {
  exactKeys(message, ['version', 'type', 'transferId']);
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'cancel',
    transferId: parseUuidV4(message.transferId),
  };
}

function parseExportBegin(message: Record<string, unknown>): VaultTransferExportBeginMessage {
  exactKeys(message, ['version', 'type', 'format', 'authorizationId'], ['filePassword', 'target']);
  const format = parseExportFormat(message.format);
  const authorizationId = parseUuidV4(message.authorizationId);
  const target = parseExportTarget(message);
  if (format === 'zip' && target.kind === 'organization') {
    return invalidMessage();
  }
  if (format === 'encrypted-json') {
    if (!hasOwn(message, 'filePassword')) {
      return {
        version: VAULT_TRANSFER_PORT_VERSION,
        type: 'export.begin',
        format,
        authorizationId,
        target,
      };
    }
    return {
      version: VAULT_TRANSFER_PORT_VERSION,
      type: 'export.begin',
      format,
      authorizationId,
      target,
      filePassword: parsePassword(message.filePassword),
    };
  }
  if (hasOwn(message, 'filePassword')) {
    throw new VaultTransferPortProtocolError('password_not_allowed');
  }
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'export.begin',
    format,
    authorizationId,
    target,
  };
}

function parseExportTarget(message: Record<string, unknown>): VaultTransferExportTarget {
  try {
    return canonicalizeVaultTransferExportTarget(
      hasOwn(message, 'target') ? message.target : PERSONAL_VAULT_TRANSFER_EXPORT_TARGET,
    );
  } catch {
    return invalidMessage();
  }
}

function parseExportAck(message: Record<string, unknown>): VaultTransferExportAckMessage {
  exactKeys(message, ['version', 'type', 'transferId', 'sequence']);
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'export.ack',
    transferId: parseUuidV4(message.transferId),
    sequence: boundedInteger(message.sequence, 0, MAX_SEQUENCE),
  };
}

function parseRecoveryInspect(message: Record<string, unknown>): VaultTransferRecoveryInspectMessage {
  exactKeys(message, ['version', 'type']);
  return { version: VAULT_TRANSFER_PORT_VERSION, type: 'recovery.inspect' };
}

function parseRecoveryClear(message: Record<string, unknown>): VaultTransferRecoveryClearMessage {
  exactKeys(message, ['version', 'type', 'expectedBarriers']);
  const entries = strictArray(message.expectedBarriers, MAX_VAULT_TRANSFER_RECOVERY_BARRIERS);
  if (entries.length < 1) invalidMessage();
  let previousTransferId = '';
  const expectedBarriers = entries.map((entry) => {
    const expected = plainRecord(entry);
    exactKeys(expected, ['transferId', 'reason']);
    const transferId = parseUuidV4(expected.transferId);
    if (transferId <= previousTransferId) invalidMessage();
    previousTransferId = transferId;
    return {
      transferId,
      reason: oneOf(expected.reason, VAULT_TRANSFER_RECOVERY_REASONS),
    };
  });
  return { version: VAULT_TRANSFER_PORT_VERSION, type: 'recovery.clear', expectedBarriers };
}

function parseImportBegun(message: Record<string, unknown>): VaultTransferImportBegunMessage {
  exactKeys(message, [
    'version', 'type', 'transferId', 'phase', 'maxChunkBytes', 'maxEncodedChunkChars',
  ]);
  const maxChunkBytes = boundedInteger(message.maxChunkBytes, 1, MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES);
  const maxEncodedChunkChars = boundedInteger(
    message.maxEncodedChunkChars,
    4,
    MAX_VAULT_TRANSFER_PORT_ENCODED_CHUNK_CHARS,
  );
  if (maxEncodedChunkChars !== encodedLength(maxChunkBytes)) invalidMessage();
  requireLiteral(message.phase, 'uploading');
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'import.begun',
    transferId: parseUuidV4(message.transferId),
    phase: 'uploading',
    maxChunkBytes,
    maxEncodedChunkChars,
  };
}

function parseImportAck(message: Record<string, unknown>): VaultTransferImportAckMessage {
  exactKeys(message, [
    'version', 'type', 'transferId', 'phase', 'sequence', 'nextSequence', 'byteLength',
    'totalBytes',
  ]);
  requireLiteral(message.phase, 'uploading');
  const sequence = boundedInteger(message.sequence, 0, MAX_SEQUENCE);
  const nextSequence = boundedInteger(message.nextSequence, 1, MAX_SEQUENCE + 1);
  if (nextSequence !== sequence + 1) invalidMessage();
  const byteLength = boundedInteger(message.byteLength, 1, MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES);
  const totalBytes = boundedInteger(message.totalBytes, 1, MAX_VAULT_TRANSFER_PORT_TOTAL_BYTES);
  if (byteLength > totalBytes) invalidMessage();
  if (sequence + 1 > totalBytes) invalidMessage();
  if (totalBytes > (sequence + 1) * MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES) invalidMessage();
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'import.ack',
    transferId: parseUuidV4(message.transferId),
    phase: 'uploading',
    sequence,
    nextSequence,
    byteLength,
    totalBytes,
  };
}

function parseImportPreview(message: Record<string, unknown>): VaultTransferImportPreviewMessage {
  exactKeys(message, ['version', 'type', 'transferId', 'previewRevision', 'preview']);
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'import.preview',
    transferId: parseUuidV4(message.transferId),
    previewRevision: parseUuidV4(message.previewRevision),
    preview: parsePreviewModel(message.preview),
  };
}

function parseImportResult(message: Record<string, unknown>): VaultTransferImportResultMessage {
  exactKeys(message, [
    'version', 'type', 'transferId', 'phase', 'status', 'counts', 'mustSyncBeforeRetry',
  ]);
  requireLiteral(message.phase, 'completed');
  const status = oneOf(message.status, ['blocked', 'completed', 'partial', 'outcome_unknown'] as const);
  const counts = parseResultCounts(message.counts);
  const mustSyncBeforeRetry = requiredBoolean(message.mustSyncBeforeRetry);
  if (status === 'completed' && (counts.rejected !== 0 || counts.skipped !== 0 || counts.outcomeUnknown !== 0)) {
    invalidMessage();
  }
  if (status === 'outcome_unknown' && counts.outcomeUnknown < 1) invalidMessage();
  if (counts.outcomeUnknown > 0 && !mustSyncBeforeRetry) invalidMessage();
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'import.result',
    transferId: parseUuidV4(message.transferId),
    phase: 'completed',
    status,
    counts,
    mustSyncBeforeRetry,
  };
}

function parseExportBegun(message: Record<string, unknown>): VaultTransferExportBegunMessage {
  exactKeys(message, ['version', 'type', 'transferId', 'format', 'phase', 'fileName'], ['review']);
  requireLiteral(message.phase, 'exporting');
  const format = parseExportFormat(message.format);
  const review = hasOwn(message, 'review') ? parseExportReview(message.review) : undefined;
  if ((format === 'csv') !== (review !== undefined)) invalidMessage();
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'export.begun',
    transferId: parseUuidV4(message.transferId),
    format,
    phase: 'exporting',
    fileName: parseFileName(message.fileName),
    ...(review ? { review } : {}),
  };
}

function parseExportReview(value: unknown): VaultTransferExportReview {
  const review = plainRecord(value);
  exactKeys(review, ['exportedItemCount', 'omittedItemCount', 'warnings']);
  const entries = strictArray(review.warnings, VAULT_TRANSFER_EXPORT_WARNING_CODES.length);
  const seen = new Set<VaultTransferExportWarningCode>();
  let previousIndex = -1;
  const warnings: VaultTransferExportWarning[] = entries.map((entry) => {
    const warning = plainRecord(entry);
    exactKeys(warning, ['code', 'count']);
    const code = oneOf(warning.code, VAULT_TRANSFER_EXPORT_WARNING_CODES);
    const codeIndex = VAULT_TRANSFER_EXPORT_WARNING_CODES.indexOf(code);
    if (seen.has(code) || codeIndex <= previousIndex) invalidMessage();
    seen.add(code);
    previousIndex = codeIndex;
    return { code, count: boundedInteger(warning.count, 1, MAX_RESULT_COUNT) };
  });
  return {
    exportedItemCount: boundedInteger(review.exportedItemCount, 0, MAX_RESULT_COUNT),
    omittedItemCount: boundedInteger(review.omittedItemCount, 0, MAX_RESULT_COUNT),
    warnings,
  };
}

function parseExportChunk(message: Record<string, unknown>): VaultTransferExportChunkMessage {
  exactKeys(message, [
    'version', 'type', 'transferId', 'format', 'phase', 'sequence', 'byteLength', 'dataBase64',
  ]);
  requireLiteral(message.phase, 'exporting');
  const byteLength = boundedInteger(message.byteLength, 1, MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES);
  const dataBase64 = requiredString(message.dataBase64);
  validateVaultTransferPortChunk(dataBase64, byteLength);
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'export.chunk',
    transferId: parseUuidV4(message.transferId),
    format: parseExportFormat(message.format),
    phase: 'exporting',
    sequence: boundedInteger(message.sequence, 0, MAX_SEQUENCE),
    byteLength,
    dataBase64,
  };
}

function parseExportDone(message: Record<string, unknown>): VaultTransferExportDoneMessage {
  exactKeys(message, [
    'version', 'type', 'transferId', 'format', 'phase', 'chunkCount', 'totalBytes',
  ], ['clientEventAckId']);
  requireLiteral(message.phase, 'completed');
  const chunkCount = boundedInteger(message.chunkCount, 0, MAX_SEQUENCE + 1);
  const totalBytes = boundedInteger(message.totalBytes, 0, MAX_VAULT_TRANSFER_PORT_TOTAL_BYTES);
  if ((chunkCount === 0) !== (totalBytes === 0)) invalidMessage();
  if (chunkCount > totalBytes) invalidMessage();
  if (totalBytes > chunkCount * MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES) invalidMessage();
  const clientEventAckId = hasOwn(message, 'clientEventAckId')
    ? parseUuidV4(message.clientEventAckId)
    : undefined;
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'export.done',
    transferId: parseUuidV4(message.transferId),
    format: parseExportFormat(message.format),
    phase: 'completed',
    chunkCount,
    totalBytes,
    ...(clientEventAckId ? { clientEventAckId } : {}),
  };
}

function parseRecoveryStatusMessage(
  message: Record<string, unknown>,
): VaultTransferRecoveryStatusMessage {
  exactKeys(message, ['version', 'type', 'phase', 'status']);
  requireLiteral(message.phase, 'completed');
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'recovery.status',
    phase: 'completed',
    status: parseRecoveryStatus(message.status),
  };
}

function parseRecoveryClearedMessage(
  message: Record<string, unknown>,
): VaultTransferRecoveryClearedMessage {
  exactKeys(message, ['version', 'type', 'phase', 'cleared']);
  requireLiteral(message.phase, 'completed');
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'recovery.cleared',
    phase: 'completed',
    cleared: boundedInteger(message.cleared, 1, MAX_VAULT_TRANSFER_RECOVERY_BARRIERS),
  };
}

function parseErrorMessage(message: Record<string, unknown>): VaultTransferPortErrorMessage {
  exactKeys(message, ['version', 'type', 'transferId', 'phase', 'error']);
  const transferId = message.transferId === null ? null : parseUuidV4(message.transferId);
  const phase = parsePhase(message.phase);
  const error = plainRecord(message.error);
  exactKeys(error, ['code', 'message']);
  const code = parseErrorCode(error.code);
  if (error.message !== VAULT_TRANSFER_PORT_ERROR_MESSAGES[code]) invalidMessage();
  return {
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'error',
    transferId,
    phase,
    error: { code, message: VAULT_TRANSFER_PORT_ERROR_MESSAGES[code] },
  };
}

function parsePreviewModel(value: unknown): VaultTransferPortPreviewModel {
  const preview = plainRecord(value);
  exactKeys(preview, [
    'format', 'scope', 'phase', 'counts', 'diagnostics', 'organizationTargetRequired',
    'hasUnknownOutcome', 'canCommit',
  ]);
  requireLiteral(preview.phase, 'previewed');
  const format = parseImportFormat(preview.format);
  const scope = oneOf(preview.scope, ['personal', 'organization'] as const);
  const counts = parsePreviewCounts(preview.counts);
  const diagnostics = parsePreviewDiagnostics(preview.diagnostics);
  const organizationTargetRequired = requiredBoolean(preview.organizationTargetRequired);
  const hasUnknownOutcome = requiredBoolean(preview.hasUnknownOutcome);
  const canCommit = requiredBoolean(preview.canCommit);
  if (canCommit && (
    diagnostics.errors.length > 0
    || diagnostics.unsupported.length > 0
    || organizationTargetRequired
    || hasUnknownOutcome
  )) {
    invalidMessage();
  }
  return {
    format,
    scope,
    phase: 'previewed',
    counts,
    diagnostics,
    organizationTargetRequired,
    hasUnknownOutcome,
    canCommit,
  };
}

function parsePreviewCounts(value: unknown): VaultTransferPortPreviewModel['counts'] {
  const counts = plainRecord(value);
  exactKeys(counts, ['folders', 'collections', 'items', 'attachments']);
  return {
    folders: boundedInteger(counts.folders, 0, MAX_RESULT_COUNT),
    collections: boundedInteger(counts.collections, 0, MAX_RESULT_COUNT),
    items: boundedInteger(counts.items, 0, MAX_RESULT_COUNT),
    attachments: boundedInteger(counts.attachments, 0, MAX_RESULT_COUNT),
  };
}

function parsePreviewDiagnostics(value: unknown): VaultTransferPortPreviewModel['diagnostics'] {
  const diagnostics = plainRecord(value);
  exactKeys(diagnostics, ['errors', 'warnings', 'unsupported']);
  return {
    errors: parseDiagnosticGroup(diagnostics.errors),
    warnings: parseDiagnosticGroup(diagnostics.warnings),
    unsupported: parseDiagnosticGroup(diagnostics.unsupported),
  };
}

function parseDiagnosticGroup(value: unknown): VaultTransferPortSanitizedDiagnostic[] {
  const entries = strictArray(value, MAX_DIAGNOSTIC_GROUP_ENTRIES);
  const seen = new Set<VaultTransferPortDiagnosticCode>();
  return entries.map((entry) => {
    const diagnostic = plainRecord(entry);
    exactKeys(diagnostic, ['code', 'count']);
    const code = oneOf(diagnostic.code, VAULT_TRANSFER_PORT_DIAGNOSTIC_CODES);
    if (seen.has(code)) invalidMessage();
    seen.add(code);
    return { code, count: boundedInteger(diagnostic.count, 1, MAX_RESULT_COUNT) };
  });
}

function parseResultCounts(value: unknown): VaultTransferImportResultMessage['counts'] {
  const counts = plainRecord(value);
  exactKeys(counts, ['committed', 'rejected', 'skipped', 'outcomeUnknown']);
  return {
    committed: boundedInteger(counts.committed, 0, MAX_RESULT_COUNT),
    rejected: boundedInteger(counts.rejected, 0, MAX_RESULT_COUNT),
    skipped: boundedInteger(counts.skipped, 0, MAX_RESULT_COUNT),
    outcomeUnknown: boundedInteger(counts.outcomeUnknown, 0, MAX_RESULT_COUNT),
  };
}

function parseRecoveryStatus(value: unknown): VaultTransferRecoveryStatus {
  const status = plainRecord(value);
  exactKeys(status, [
    'count', 'unresolvedUnknownCount', 'reconcileRequiredCount', 'omittedCount', 'barriers',
  ]);
  const count = boundedInteger(status.count, 0, MAX_RESULT_COUNT);
  const unresolvedUnknownCount = boundedInteger(status.unresolvedUnknownCount, 0, count);
  const reconcileRequiredCount = boundedInteger(status.reconcileRequiredCount, 0, count);
  const omittedCount = boundedInteger(status.omittedCount, 0, count);
  const entries = strictArray(status.barriers, MAX_VAULT_TRANSFER_RECOVERY_BARRIERS);
  if (entries.length + omittedCount !== count) invalidMessage();
  const seen = new Set<string>();
  let visibleUnknownCount = 0;
  const barriers = entries.map((entry) => {
    const barrier = plainRecord(entry);
    exactKeys(barrier, ['transferId', 'reason', 'reconciled', 'clearable']);
    const transferId = parseUuidV4(barrier.transferId);
    if (seen.has(transferId)) invalidMessage();
    seen.add(transferId);
    const reason = oneOf(barrier.reason, VAULT_TRANSFER_RECOVERY_REASONS);
    if (reason === 'outcome_unknown') visibleUnknownCount += 1;
    const reconciled = requiredBoolean(barrier.reconciled);
    const clearable = requiredBoolean(barrier.clearable);
    if (clearable && !reconciled) invalidMessage();
    return { transferId, reason, reconciled, clearable };
  });
  if (visibleUnknownCount > unresolvedUnknownCount) invalidMessage();
  return {
    count,
    unresolvedUnknownCount,
    reconcileRequiredCount,
    omittedCount,
    barriers,
  };
}

/** A clear operation is safe only when the complete visible set was reconciled by the controller. */
export function canClearVaultTransferRecovery(status: VaultTransferRecoveryStatus): boolean {
  return status.count > 0
    && status.omittedCount === 0
    && status.count === status.barriers.length
    && status.barriers.every((barrier) => barrier.clearable && barrier.reconciled);
}

function parseEnvelope(value: unknown): Record<string, unknown> {
  const message = plainRecord(value);
  if (!hasOwn(message, 'version') || !Number.isSafeInteger(message.version)) invalidMessage();
  if (message.version !== VAULT_TRANSFER_PORT_VERSION) {
    throw new VaultTransferPortProtocolError('unsupported_version');
  }
  if (typeof message.type !== 'string') invalidMessage();
  return message;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string')) invalidMessage();
  const allowed = new Set([...required, ...optional]);
  if (keys.length < required.length || keys.length > allowed.size) invalidMessage();
  for (const key of required) {
    if (!hasOwn(value, key)) invalidMessage();
  }
  for (const key of keys) {
    if (typeof key !== 'string' || !allowed.has(key)) invalidMessage();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) invalidMessage();
  }
}

function plainRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) invalidMessage();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalidMessage();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') invalidMessage();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) invalidMessage();
  }
  return value as Record<string, unknown>;
}

function strictArray(value: unknown, maximumLength: number): unknown[] {
  if (
    !Array.isArray(value)
    || Object.getPrototypeOf(value) !== Array.prototype
    || value.length > maximumLength
  ) {
    invalidMessage();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !hasOwn(value, 'length')) invalidMessage();
  for (let index = 0; index < value.length; index += 1) {
    const key = String(index);
    if (!hasOwn(value, key)) invalidMessage();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) invalidMessage();
  }
  for (const key of keys) {
    if (key !== 'length' && (typeof key !== 'string' || !/^(?:0|[1-9]\d*)$/.test(key))) {
      invalidMessage();
    }
  }
  return value;
}

function parseUuidV4(value: unknown): string {
  if (typeof value !== 'string' || !UUID_V4_PATTERN.test(value)) invalidMessage();
  return value;
}

function parseFileName(value: unknown): string {
  const fileName = requiredString(value);
  if (
    fileName.length > MAX_FILE_NAME_CHARS
    || fileName === '.'
    || fileName === '..'
    || fileName.includes('/')
    || fileName.includes('\\')
  ) {
    invalidMessage();
  }
  for (let index = 0; index < fileName.length; index += 1) {
    const codeUnit = fileName.charCodeAt(index);
    if (codeUnit <= 0x1f || codeUnit === 0x7f) invalidMessage();
  }
  return fileName;
}

function parsePassword(value: unknown): string {
  const password = requiredString(value);
  if (password.length > MAX_PASSWORD_CHARS) invalidMessage();
  return password;
}

function parseImportFormat(value: unknown): VaultTransferImportFormat {
  return oneOf(value, ['json', 'encrypted-json', 'csv', 'zip'] as const);
}

function parseExportFormat(value: unknown): VaultTransferExportFormat {
  return oneOf(value, ['json', 'encrypted-json', 'csv', 'zip'] as const);
}

function parsePhase(value: unknown): VaultTransferPortPhase {
  return oneOf(value, [
    'idle', 'uploading', 'inspecting', 'previewed', 'committing', 'exporting', 'completed',
    'cancelled',
  ] as const);
}

function parseErrorCode(value: unknown): VaultTransferPortErrorCode {
  if (typeof value !== 'string' || !hasOwn(VAULT_TRANSFER_PORT_ERROR_MESSAGES, value)) invalidMessage();
  return value as VaultTransferPortErrorCode;
}

function oneOf<const T extends readonly string[]>(value: unknown, allowed: T): T[number] {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) invalidMessage();
  return value as T[number];
}

function requireLiteral<const T extends string>(value: unknown, expected: T): T {
  if (value !== expected) invalidMessage();
  return expected;
}

function requiredString(value: unknown): string {
  if (typeof value !== 'string' || value.length < 1) invalidMessage();
  return value;
}

function requiredBoolean(value: unknown): boolean {
  if (typeof value !== 'boolean') invalidMessage();
  return value;
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    invalidMessage();
  }
  return value as number;
}

function encodedLength(byteLength: number): number {
  return Math.ceil(byteLength / 3) * 4;
}

/** Validate a wire chunk without leaving the parser's throwaway decoded copy in memory. */
function validateVaultTransferPortChunk(encoded: string, expectedByteLength: number): void {
  let decoded: Uint8Array | undefined;
  try {
    decoded = decodeVaultTransferPortChunk(encoded, expectedByteLength);
  } finally {
    decoded?.fill(0);
  }
}

function hasOwn(value: object, key: PropertyKey): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function invalidChunk(): never {
  throw new VaultTransferPortProtocolError('invalid_chunk');
}

function invalidMessage(): never {
  throw new VaultTransferPortProtocolError('invalid_message');
}
