import type { VaultTransferDiagnostic, VaultTransferInspection } from '../../../core/vault/vault-transfer.js';
import {
  inspectPersonalImportCapabilities,
  type PersonalImportCapabilityError,
  type PersonalImportCapabilityPolicy,
} from '../../../core/vault/vault-transfer-commit.js';
import { t } from '../../i18n/index.js';
import type {
  ImportPreviewFormat,
  SanitizedImportPreviewDiagnostic,
  SanitizedImportPreviewViewModel,
} from './import-preview.js';

const MAX_DIAGNOSTICS_PER_CATEGORY = 32;
const MAX_PATH_CHARS = 180;
const SAFE_PATH_SEGMENTS = new Set([
  'version', 'format', 'scope', 'encrypted', 'folders', 'collections', 'items', 'id', 'name',
  'type', 'organizationId', 'folderId', 'collectionIds', 'notes', 'favorite', 'reprompt',
  'fields', 'value', 'linkedId', 'passwordHistory', 'password', 'lastUsedDate', 'login',
  'username', 'totp', 'uris', 'uri', 'match', 'fido2Credentials', 'credentialId', 'keyType',
  'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId', 'counter', 'discoverable', 'userHandle',
  'userName', 'rpName', 'userDisplayName', 'creationDate', 'revisionDate', 'deletedDate',
  'archivedDate', 'secureNote', 'card', 'identity', 'sshKey', 'bankAccount', 'driversLicense',
  'passport', 'attachments', 'key', 'rows', 'headers', 'path',
]);

const UNSUPPORTED_CODES = new Set([
  'encrypted_input_requires_decryption',
  'unknown_field',
  'unknown_fields',
  'unknown_item_type',
  'unsupported_known_data',
  'item_type_unsupported',
]);

export interface SanitizedImportPreviewOptions {
  format?: ImportPreviewFormat;
  attachmentCount?: number;
  hasUnknownOutcome?: boolean;
}

/** Convert transfer and capability diagnostics into a bounded model that carries no raw values. */
export function toSanitizedImportPreview(
  inspection: VaultTransferInspection,
  capabilities: PersonalImportCapabilityPolicy,
  options: SanitizedImportPreviewOptions = {},
): SanitizedImportPreviewViewModel {
  const ir = inspection.ir;
  const capabilityErrors = inspectPersonalImportCapabilities(inspection, capabilities);
  const errors: SanitizedImportPreviewDiagnostic[] = [];
  const warnings: SanitizedImportPreviewDiagnostic[] = [];
  const unsupported: SanitizedImportPreviewDiagnostic[] = [];

  for (const diagnostic of inspection.diagnostics) {
    const sanitized = sanitizeTransferDiagnostic(diagnostic);
    if (isUnsupportedCode(diagnostic.code)) unsupported.push(sanitized);
    else if (diagnostic.severity === 'warning') warnings.push(sanitized);
    else errors.push(sanitized);
  }
  for (const error of capabilityErrors) {
    const sanitized = sanitizeCapabilityError(error);
    if (isUnsupportedCode(error.code)) unsupported.push(sanitized);
    else errors.push(sanitized);
  }

  const boundedErrors = boundDiagnostics(errors);
  const boundedWarnings = boundDiagnostics(warnings);
  const boundedUnsupported = boundDiagnostics(unsupported);
  const organizationTargetRequired = ir?.scope === 'organization';
  const hasUnknownOutcome = options.hasUnknownOutcome === true;
  return {
    format: options.format ?? transferFormat(ir?.format),
    scope: ir?.scope ?? 'personal',
    counts: {
      folders: safeCount(ir?.folders.length ?? 0),
      collections: safeCount(ir?.collections.length ?? 0),
      items: safeCount(ir?.items.length ?? 0),
      attachments: safeCount(options.attachmentCount ?? 0),
    },
    diagnostics: {
      errors: boundedErrors,
      warnings: boundedWarnings,
      unsupported: boundedUnsupported,
    },
    organizationTargetRequired,
    hasUnknownOutcome,
    canCommit: inspection.canCommit
      && ir !== null
      && capabilityErrors.length === 0
      && !organizationTargetRequired
      && !hasUnknownOutcome,
  };
}

function sanitizeTransferDiagnostic(diagnostic: VaultTransferDiagnostic): SanitizedImportPreviewDiagnostic {
  const unsupported = isUnsupportedCode(diagnostic.code);
  return compactDiagnostic({
    code: safeCode(diagnostic.code),
    message: unsupported
      ? t('options.data.preview.diagnosticUnsupported')
      : (diagnostic.severity === 'warning'
          ? t('options.data.preview.diagnosticWarning')
          : t('options.data.preview.diagnosticError')),
    ...(diagnostic.sourceIndex !== undefined ? { sourceIndex: diagnostic.sourceIndex } : {}),
    ...(diagnostic.path !== undefined ? { path: diagnostic.path } : {}),
  });
}

function sanitizeCapabilityError(error: PersonalImportCapabilityError): SanitizedImportPreviewDiagnostic {
  return compactDiagnostic({
    code: safeCode(error.code),
    message: isUnsupportedCode(error.code)
      ? t('options.data.preview.diagnosticUnsupported')
      : t('options.data.preview.diagnosticError'),
    ...(error.sourceIndex !== undefined ? { sourceIndex: error.sourceIndex } : {}),
    ...(error.path !== undefined ? { path: error.path } : {}),
  });
}

function compactDiagnostic(input: {
  code: string;
  message: string;
  sourceIndex?: number;
  path?: string;
}): SanitizedImportPreviewDiagnostic {
  const diagnostic: SanitizedImportPreviewDiagnostic = { code: input.code, message: input.message };
  if (typeof input.sourceIndex === 'number' && Number.isSafeInteger(input.sourceIndex) && input.sourceIndex >= 0) {
    diagnostic.sourceIndex = input.sourceIndex;
  }
  const path = sanitizePath(input.path);
  if (path) diagnostic.path = path;
  return diagnostic;
}

function isUnsupportedCode(code: string): boolean {
  return UNSUPPORTED_CODES.has(code) || code.endsWith('_unsupported');
}

function safeCode(code: string): string {
  return /^[a-z0-9_]{1,80}$/.test(code) ? code : 'transfer_diagnostic';
}

function sanitizePath(path: string | undefined): string | undefined {
  if (!path || path[0] !== '$') return undefined;
  let output = '$';
  let cursor = 1;
  while (cursor < path.length && output.length < MAX_PATH_CHARS) {
    if (path[cursor] === '.') {
      const match = /^\.([A-Za-z_$][A-Za-z0-9_$]*)/.exec(path.slice(cursor));
      if (!match) return undefined;
      const segment = match[1]!;
      output += SAFE_PATH_SEGMENTS.has(segment) ? `.${segment}` : '.[unknown]';
      cursor += match[0].length;
      continue;
    }
    if (path[cursor] === '[') {
      const match = /^\[(\d+)\]/.exec(path.slice(cursor));
      if (!match) {
        output += '[unknown]';
        break;
      }
      output += `[${match[1]}]`;
      cursor += match[0].length;
      continue;
    }
    return undefined;
  }
  return output.slice(0, MAX_PATH_CHARS);
}

function boundDiagnostics(items: SanitizedImportPreviewDiagnostic[]): SanitizedImportPreviewDiagnostic[] {
  if (items.length <= MAX_DIAGNOSTICS_PER_CATEGORY) return items;
  return [
    ...items.slice(0, MAX_DIAGNOSTICS_PER_CATEGORY - 1),
    { code: 'diagnostics_omitted', message: t('options.data.preview.diagnosticsOmitted') },
  ];
}

function transferFormat(format: 'bitwarden-json' | 'bitwarden-csv' | undefined): ImportPreviewFormat {
  return format === 'bitwarden-csv' ? 'bitwarden-csv' : 'bitwarden-json';
}

function safeCount(value: number): number {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}
