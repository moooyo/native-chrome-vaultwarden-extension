import type { SyncResponse } from './types.js';

export const MAX_SYNC_PROFILE_ID_LENGTH = 1_024;
export const MAX_SECURITY_STAMP_LENGTH = 1_024;
const MAX_SYNC_PROFILE_EMAIL_LENGTH = 254;

export interface SyncSecurityProfile {
  readonly profileId: string;
  readonly accountIdentity: string;
  readonly securityStamp: string | undefined;
}

/**
 * Parse the security-sensitive sync profile fields without trusting TypeScript annotations,
 * prototypes, accessors, or serializer aliases. The stamp remains opaque and case-sensitive.
 */
export function parseSyncSecurityProfile(value: unknown): SyncSecurityProfile {
  const profile = requirePlainRecord(value, 'sync profile');
  const profileId = requireCanonicalBoundedString(
    readRequiredDataProperty(profile, 'id'),
    'sync profile id',
    MAX_SYNC_PROFILE_ID_LENGTH,
  );
  const email = requireBoundedString(
    readRequiredDataProperty(profile, 'email'),
    'sync profile email',
    MAX_SYNC_PROFILE_EMAIL_LENGTH,
  );
  const accountIdentity = email.trim().toLowerCase();
  if (!accountIdentity || !/^[^@\s]+@[^@\s]+$/u.test(accountIdentity)) {
    throw new TypeError('sync profile email is invalid');
  }

  const camel = readOptionalDataProperty(profile, 'securityStamp');
  const pascal = readOptionalDataProperty(profile, 'SecurityStamp');
  if (camel.present && pascal.present && !sameAliasValue(camel.value, pascal.value)) {
    throw new TypeError('sync profile security stamp aliases conflict');
  }
  const rawStamp = camel.present ? camel.value : pascal.present ? pascal.value : undefined;
  const securityStamp = rawStamp == null
    ? undefined
    : requireCanonicalBoundedString(
        rawStamp,
        'sync profile security stamp',
        MAX_SECURITY_STAMP_LENGTH,
      );
  return Object.freeze({ profileId, accountIdentity, securityStamp });
}

/** Validate the minimum sync shape and its security-sensitive profile fields at the wire boundary. */
export function parseSyncResponse(value: unknown): SyncResponse {
  const response = requirePlainRecord(value, 'sync response');
  const profile = readRequiredDataProperty(response, 'profile');
  parseSyncSecurityProfile(profile);
  if (!Array.isArray(readRequiredDataProperty(response, 'ciphers'))) {
    throw new TypeError('sync response ciphers must be an array');
  }
  return value as SyncResponse;
}

function sameAliasValue(left: unknown, right: unknown): boolean {
  return (left == null && right == null) || left === right;
}

function requirePlainRecord(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(`${name} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${name} must be a plain object`);
  }
  return value as Record<string, unknown>;
}

function readRequiredDataProperty(record: Record<string, unknown>, key: string): unknown {
  const property = readOptionalDataProperty(record, key);
  if (!property.present) throw new TypeError(`sync response is missing ${key}`);
  return property.value;
}

function readOptionalDataProperty(
  record: Record<string, unknown>,
  key: string,
): { readonly present: boolean; readonly value?: unknown } {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor) return Object.freeze({ present: false });
  if (!descriptor.enumerable || !('value' in descriptor)) {
    throw new TypeError(`sync profile ${key} must be an enumerable data property`);
  }
  return Object.freeze({ present: true, value: descriptor.value });
}

function requireBoundedString(value: unknown, name: string, maximum: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum) {
    throw new TypeError(`${name} is invalid`);
  }
  if (containsControlCharacter(value)) throw new TypeError(`${name} is invalid`);
  return value;
}

function requireCanonicalBoundedString(value: unknown, name: string, maximum: number): string {
  const parsed = requireBoundedString(value, name, maximum);
  if (parsed.trim() !== parsed) throw new TypeError(`${name} is invalid`);
  return parsed;
}

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
}
