export const ClientEventType = Object.freeze({
  User_ClientExportedVault: 1007,
  Cipher_ClientViewed: 1107,
  Cipher_ClientToggledPasswordVisible: 1108,
  Cipher_ClientToggledHiddenFieldVisible: 1109,
  Cipher_ClientToggledCardCodeVisible: 1110,
  Cipher_ClientCopiedPassword: 1111,
  Cipher_ClientCopiedHiddenField: 1112,
  Cipher_ClientCopiedCardCode: 1113,
  Cipher_ClientAutofilled: 1114,
  Cipher_ClientToggledCardNumberVisible: 1117,
  Cipher_ClientToggledTOTPSeedVisible: 1118,
  Organization_ClientExportedVault: 1602,
  Organization_ItemOrganization_Accepted: 1618,
  Organization_ItemOrganization_Declined: 1619,
} as const);

export type ClientEventType = (typeof ClientEventType)[keyof typeof ClientEventType];

export type CipherClientEventType =
  | typeof ClientEventType.Cipher_ClientViewed
  | typeof ClientEventType.Cipher_ClientToggledPasswordVisible
  | typeof ClientEventType.Cipher_ClientToggledHiddenFieldVisible
  | typeof ClientEventType.Cipher_ClientToggledCardCodeVisible
  | typeof ClientEventType.Cipher_ClientCopiedPassword
  | typeof ClientEventType.Cipher_ClientCopiedHiddenField
  | typeof ClientEventType.Cipher_ClientCopiedCardCode
  | typeof ClientEventType.Cipher_ClientAutofilled
  | typeof ClientEventType.Cipher_ClientToggledCardNumberVisible
  | typeof ClientEventType.Cipher_ClientToggledTOTPSeedVisible;

export type ClientEvent =
  | {
      readonly type: typeof ClientEventType.User_ClientExportedVault;
      readonly date: string;
    }
  | {
      readonly type:
        | typeof ClientEventType.Organization_ClientExportedVault
        | typeof ClientEventType.Organization_ItemOrganization_Accepted
        | typeof ClientEventType.Organization_ItemOrganization_Declined;
      readonly date: string;
      readonly organizationId: string;
    }
  | {
      readonly type: CipherClientEventType;
      readonly date: string;
      readonly cipherId: string;
      readonly organizationId: string;
    };

export type ClientEventWire = ClientEvent;

/**
 * Minimal worker-owned authority projection for client audit events. Organizations are confirmed,
 * enabled direct memberships only; provider-only visibility must never authorize collection.
 */
export interface ClientEventAuthorityProjection {
  readonly serverUrl: string;
  readonly userId: string;
  readonly organizations: readonly {
    readonly id: string;
    /** True only when the authoritative sync value is exactly true. */
    readonly useEvents: boolean;
  }[];
  readonly ciphers: readonly {
    readonly id: string;
    readonly organizationId: string | null;
  }[];
}

export const MAX_CLIENT_EVENT_BATCH_EVENTS = 50;
export const MAX_CLIENT_EVENT_BATCH_UTF8_BYTES = 32 * 1024;

const CANONICAL_UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CANONICAL_ISO_DATE_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const CIPHER_EVENT_TYPES = new Set<number>([
  ClientEventType.Cipher_ClientViewed,
  ClientEventType.Cipher_ClientToggledPasswordVisible,
  ClientEventType.Cipher_ClientToggledHiddenFieldVisible,
  ClientEventType.Cipher_ClientToggledCardCodeVisible,
  ClientEventType.Cipher_ClientCopiedPassword,
  ClientEventType.Cipher_ClientCopiedHiddenField,
  ClientEventType.Cipher_ClientCopiedCardCode,
  ClientEventType.Cipher_ClientAutofilled,
  ClientEventType.Cipher_ClientToggledCardNumberVisible,
  ClientEventType.Cipher_ClientToggledTOTPSeedVisible,
]);

/** Parse a trigger-independent client audit event into its canonical wire-safe form. */
export function parseClientEvent(value: unknown): ClientEvent {
  if (!isPlainRecord(value)) throw new TypeError('Client event must be a plain object');
  const type = dataValue(value, 'type');
  const date = requireCanonicalEventDate(dataValue(value, 'date'));

  if (type === ClientEventType.User_ClientExportedVault) {
    requireExactDataKeys(value, ['type', 'date']);
    return Object.freeze({ type, date });
  }
  if (type === ClientEventType.Organization_ClientExportedVault
    || type === ClientEventType.Organization_ItemOrganization_Accepted
    || type === ClientEventType.Organization_ItemOrganization_Declined) {
    requireExactDataKeys(value, ['type', 'date', 'organizationId']);
    return Object.freeze({
      type,
      date,
      organizationId: requireCanonicalUuid(dataValue(value, 'organizationId'), 'organizationId'),
    });
  }
  if (typeof type === 'number' && CIPHER_EVENT_TYPES.has(type)) {
    requireExactDataKeys(value, ['type', 'date', 'cipherId', 'organizationId']);
    return Object.freeze({
      type: type as CipherClientEventType,
      date,
      cipherId: requireCanonicalUuid(dataValue(value, 'cipherId'), 'cipherId'),
      organizationId: requireCanonicalUuid(dataValue(value, 'organizationId'), 'organizationId'),
    });
  }
  throw new TypeError('Unsupported client event type');
}

/** Return an object containing only fields accepted by POST /events/collect. */
export function toClientEventWire(value: unknown): ClientEventWire {
  return parseClientEvent(value);
}

/** Serialize one bounded event batch without allowing internal queue metadata onto the wire. */
export function serializeClientEventBatch(values: readonly unknown[]): string {
  if (!Array.isArray(values) || !hasDenseArrayShape(values)) {
    throw new TypeError('Client event batch must be a dense array');
  }
  if (values.length < 1 || values.length > MAX_CLIENT_EVENT_BATCH_EVENTS) {
    throw new RangeError(`Client event batch must contain 1-${MAX_CLIENT_EVENT_BATCH_EVENTS} events`);
  }
  const events = values.map(parseClientEvent);
  const serialized = JSON.stringify(events);
  if (utf8ByteLength(serialized) > MAX_CLIENT_EVENT_BATCH_UTF8_BYTES) {
    throw new RangeError('Client event batch exceeds its UTF-8 byte limit');
  }
  return serialized;
}

export function clientEventBatchUtf8Bytes(values: readonly ClientEvent[]): number {
  return utf8ByteLength(JSON.stringify(values.map(parseClientEvent)));
}

export function clientEventDateTimestamp(value: string): number {
  requireCanonicalEventDate(value);
  return Date.parse(value);
}

function requireCanonicalEventDate(value: unknown): string {
  if (typeof value !== 'string' || !CANONICAL_ISO_DATE_PATTERN.test(value)) {
    throw new TypeError('Client event date must be a canonical ISO timestamp');
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new TypeError('Client event date must be a canonical ISO timestamp');
  }
  return value;
}

function requireCanonicalUuid(value: unknown, field: string): string {
  if (typeof value !== 'string' || !CANONICAL_UUID_PATTERN.test(value)) {
    throw new TypeError(`Client event ${field} must be a canonical UUID`);
  }
  return value;
}

function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function requireExactDataKeys(record: Record<string, unknown>, expected: readonly string[]): void {
  const keys = Reflect.ownKeys(record);
  const expectedKeys = new Set(expected);
  if (keys.length !== expected.length
    || keys.some((key) => typeof key !== 'string' || !expectedKeys.has(key))) {
    throw new TypeError('Client event has unexpected fields');
  }
  for (const key of expected) dataValue(record, key);
}

function dataValue(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor?.enumerable || !('value' in descriptor)) {
    throw new TypeError(`Client event is missing ${key}`);
  }
  return descriptor.value;
}

function hasDenseArrayShape(value: readonly unknown[]): boolean {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes('length')) return false;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !('value' in descriptor)) return false;
  }
  return true;
}
