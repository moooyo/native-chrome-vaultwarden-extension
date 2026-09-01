import type { SshKeyCipherData, SshKeyCipherRequestData } from '../api/types.js';
import { parseEncString } from '../crypto/encstring.js';
import type { CompleteDecryptedSshKey, DecryptedSshKey } from './models.js';
import type { RawSyncCipherCompatibilityResult } from './vault-sync-cipher-compat.js';

export const SSH_KEY_FIELDS = ['privateKey', 'publicKey', 'keyFingerprint'] as const;

export type SshKeyField = typeof SSH_KEY_FIELDS[number];

const MAX_WIRE_LENGTH: Readonly<Record<SshKeyField, number>> = Object.freeze({
  privateKey: 5_000,
  publicKey: 5_000,
  keyFingerprint: 1_000,
});

// Largest UTF-8 payload that is guaranteed to fit the server's EncString limit after AES padding
// and base64 expansion. Exact encrypted size is validated again after encryption.
const MAX_PLAINTEXT_BYTES: Readonly<Record<SshKeyField, number>> = Object.freeze({
  privateKey: 3_695,
  publicKey: 3_695,
  keyFingerprint: 687,
});

/**
 * Parse a structured SSH payload returned by the server. This validates only the
 * Bitwarden container and EncString representation; OpenSSH key syntax remains deliberately opaque.
 */
export function parseSshKeyCipherData(value: unknown): SshKeyCipherData {
  const record = requireSshKeyRecord(value, 'encrypted');
  const parsed: SshKeyCipherData = {
    privateKey: requireEncString(record.privateKey, 'privateKey'),
  };
  const publicKey = optionalEncString(record.publicKey, 'publicKey');
  if (publicKey) parsed.publicKey = publicKey;
  const keyFingerprint = optionalEncString(record.keyFingerprint, 'keyFingerprint');
  if (keyFingerprint) parsed.keyFingerprint = keyFingerprint;
  return parsed;
}

/** Validate plaintext SSH strings supplied to the core writer without parsing OpenSSH key syntax. */
export function parseDecryptedSshKey(value: unknown): DecryptedSshKey {
  const record = requireSshKeyRecord(value, 'decrypted');
  const parsed: DecryptedSshKey = {
    privateKey: requirePlaintext(record.privateKey, 'privateKey'),
  };
  const publicKey = optionalPlaintext(record.publicKey, 'publicKey');
  if (publicKey) parsed.publicKey = publicKey;
  const keyFingerprint = optionalPlaintext(record.keyFingerprint, 'keyFingerprint');
  if (keyFingerprint) parsed.keyFingerprint = keyFingerprint;
  return parsed;
}

/** Writers require the complete triple produced by the SSH key codec or an equivalent trusted source. */
export function parseCompleteDecryptedSshKey(value: unknown): CompleteDecryptedSshKey {
  const parsed = parseDecryptedSshKey(value);
  if (!parsed.publicKey || !parsed.keyFingerprint) {
    throw new TypeError('SSH writer requires privateKey, publicKey, and keyFingerprint');
  }
  return parsed as CompleteDecryptedSshKey;
}

/** Verify the encrypted request emitted by this client is a complete, server-sized triple. */
export function parseCompleteSshKeyCipherData(value: unknown): SshKeyCipherRequestData {
  const parsed = parseSshKeyCipherData(value);
  if (!parsed.publicKey || !parsed.keyFingerprint) {
    throw new TypeError('SSH request requires privateKey, publicKey, and keyFingerprint');
  }
  return parsed as SshKeyCipherRequestData;
}

export function validateSshKeyPlaintextField(value: unknown, field: SshKeyField): string {
  return requirePlaintext(value, field);
}

const SSH_CONFLICTING_PAYLOAD_FIELDS = [
  'login', 'card', 'identity', 'secureNote', 'bankAccount', 'driversLicense', 'passport',
] as const;

/** Plaintext writers must not carry a server `data` authority or another cipher payload shape. */
export function assertSshCipherPayloadExclusivity(value: object): void {
  assertSshPayloadFieldsAbsent(value);
  const record = value as Record<string, unknown>;
  if (record.data !== undefined && record.data !== null) {
    throw new TypeError('SSH cipher must not contain data payload data');
  }
}

/**
 * Raw readers may retain the server's redundant `data` representation only when the caller passes
 * the successful compatibility result for that raw cipher. All other type payloads remain invalid.
 */
export function assertValidatedRawSshCipherPayloadExclusivity(
  value: object,
  compatibility: Extract<RawSyncCipherCompatibilityResult, { readonly ok: true }>,
): void {
  if (compatibility.ok !== true) {
    throw new TypeError('SSH raw payload requires validated compatibility');
  }
  assertSshPayloadFieldsAbsent(value);
  const data = (value as Record<string, unknown>).data;
  if (data !== undefined && data !== null && compatibility.dataMode !== 'redundant-plain-data') {
    throw new TypeError('SSH raw data requires an exact redundant projection');
  }
}

function assertSshPayloadFieldsAbsent(value: object): void {
  const record = value as Record<string, unknown>;
  for (const field of SSH_CONFLICTING_PAYLOAD_FIELDS) {
    if (record[field] !== undefined && record[field] !== null) {
      throw new TypeError(`SSH cipher must not contain ${field} payload data`);
    }
  }
}

function requireSshKeyRecord(
  value: unknown,
  kind: 'encrypted' | 'decrypted',
): Record<SshKeyField, unknown> {
  if (!isRecord(value)) throw new TypeError(`SSH ${kind} payload must be an object`);
  const keys = Object.keys(value);
  if (
    !Object.prototype.hasOwnProperty.call(value, 'privateKey')
    || keys.some((field) => !SSH_KEY_FIELDS.includes(field as SshKeyField))
  ) {
    throw new TypeError(`SSH ${kind} payload must contain privateKey and no unknown fields`);
  }
  return value as Record<SshKeyField, unknown>;
}

function optionalEncString(value: unknown, field: SshKeyField): string | undefined {
  return value === undefined || value === null ? undefined : requireEncString(value, field);
}

function requireEncString(value: unknown, field: SshKeyField): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_WIRE_LENGTH[field]) {
    throw new TypeError(`SSH ${field} must be a bounded non-empty EncString`);
  }
  try {
    const parsed = parseEncString(value);
    if (
      parsed.iv.byteLength !== 16
      || parsed.ct.byteLength === 0
      || parsed.ct.byteLength % 16 !== 0
      || parsed.mac.byteLength !== 32
    ) throw new Error('invalid EncString dimensions');
  } catch {
    throw new TypeError(`SSH ${field} must be a valid encType 2 EncString`);
  }
  return value;
}

function requirePlaintext(value: unknown, field: SshKeyField): string {
  if (
    typeof value !== 'string'
    || value.trim().length === 0
    || new TextEncoder().encode(value).byteLength > MAX_PLAINTEXT_BYTES[field]
    || value.includes('\0')
  ) {
    throw new TypeError(`SSH ${field} must be bounded non-empty text without NUL`);
  }
  return value;
}

function optionalPlaintext(value: unknown, field: SshKeyField): string | undefined {
  return value === undefined || value === null ? undefined : requirePlaintext(value, field);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}
