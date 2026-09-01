import { base64ToBytes, bytesToBase64 } from '../crypto/encoding.js';
import { serializeSymmetricKey, type SymmetricKey } from '../crypto/keys.js';
import { rsaOaepEncrypt } from '../crypto/primitives.js';
import { FINGERPRINT_WORDLIST } from '../generator/wordlist.js';
import {
  DEVICE_LOGIN_REQUEST_TTL_MS,
  DeviceLoginProtocolError,
  deriveDeviceLoginFingerprint,
  parseAuthRequestResponse,
  type ParsedAuthRequestResponse,
} from './device-login.js';

const MAX_CLOCK_SKEW_MS = 5 * 60_000;
const MAX_DEVICE_IDENTIFIER_LENGTH = 255;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ISO_DATE_COMPONENTS =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,7})?(?:Z|[+-](\d{2}):(\d{2}))$/;
const UNSAFE_DISPLAY_TEXT = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u;

export interface DeviceLoginApprovalContext {
  /** Email from the currently unlocked account. */
  readonly accountEmail: string;
  /** Stable identifier of the device sending the approval or rejection. */
  readonly approvalDeviceIdentifier: string;
}

export interface DeviceLoginApprovalView {
  readonly id: string;
  readonly fingerprint: string;
  readonly requestDeviceType?: string;
  readonly requestDeviceTypeValue: number;
  readonly requestDeviceIdentifier: string;
  readonly requestIpAddress?: string;
  readonly requestCountryName?: string;
  readonly creationDate: string;
  readonly creationTime: number;
  readonly expiresAt: number;
  readonly requestDeviceId?: string;
  readonly origin?: string;
}

export interface DeviceLoginApprovalBody {
  readonly key: string;
  readonly deviceIdentifier: string;
  readonly requestApproved: true;
}

export interface DeviceLoginRejectionBody {
  readonly deviceIdentifier: string;
  readonly requestApproved: false;
}

export interface PreparedDeviceLoginApproval {
  readonly request: DeviceLoginApprovalView;
  readonly body: DeviceLoginApprovalBody;
}

export interface PreparedDeviceLoginRejection {
  readonly request: DeviceLoginApprovalView;
  readonly body: DeviceLoginRejectionBody;
}

interface ValidatedPendingRequest {
  readonly parsed: ParsedAuthRequestResponse;
  readonly view: DeviceLoginApprovalView;
}

/**
 * Validate a pending request for display in the currently authenticated account context.
 *
 * Auth-request responses do not carry an account id or email. The integrating layer must fetch the
 * response through the authenticated API client bound to the same unlocked account that supplies
 * `accountEmail` (and, when approving, `userKey`).
 */
export async function inspectPendingDeviceLoginRequest(
  rawResponse: unknown,
  context: DeviceLoginApprovalContext,
  now: number = Date.now(),
): Promise<DeviceLoginApprovalView> {
  return (await validatePendingRequest(rawResponse, context, now)).view;
}

/** Validate, fingerprint, and prepare an approved Bitwarden auth-request PUT body. */
export async function prepareDeviceLoginApproval(
  rawResponse: unknown,
  context: DeviceLoginApprovalContext & { readonly userKey: SymmetricKey },
  now: number = Date.now(),
): Promise<PreparedDeviceLoginApproval> {
  const validated = await validatePendingRequest(rawResponse, context, now);
  const rawUserKey = serializeValidatedUserKey(context.userKey);
  const publicKey = base64ToBytes(validated.parsed.publicKey);
  let ciphertext: Uint8Array | undefined;
  let encryptedKey: string;

  try {
    ciphertext = await rsaOaepEncrypt(publicKey, rawUserKey, 'SHA-1');
    if (ciphertext.byteLength !== 256) fail('encrypted user key has an invalid length');
    encryptedKey = `4.${bytesToBase64(ciphertext)}`;
  } catch (error) {
    if (error instanceof DeviceLoginProtocolError) throw error;
    fail('user key encryption failed');
  } finally {
    rawUserKey.fill(0);
    publicKey.fill(0);
    ciphertext?.fill(0);
  }

  const body: DeviceLoginApprovalBody = Object.freeze({
    key: encryptedKey,
    deviceIdentifier: validateApprovalDeviceIdentifier(context.approvalDeviceIdentifier),
    requestApproved: true,
  });
  return Object.freeze({ request: validated.view, body });
}

/** Validate, fingerprint, and prepare a denial body without touching or emitting key material. */
export async function prepareDeviceLoginRejection(
  rawResponse: unknown,
  context: DeviceLoginApprovalContext,
  now: number = Date.now(),
): Promise<PreparedDeviceLoginRejection> {
  const validated = await validatePendingRequest(rawResponse, context, now);
  const body: DeviceLoginRejectionBody = Object.freeze({
    deviceIdentifier: validateApprovalDeviceIdentifier(context.approvalDeviceIdentifier),
    requestApproved: false,
  });
  return Object.freeze({ request: validated.view, body });
}

async function validatePendingRequest(
  rawResponse: unknown,
  context: DeviceLoginApprovalContext,
  now: number,
): Promise<ValidatedPendingRequest> {
  validateApprovalDeviceIdentifier(context.approvalDeviceIdentifier);
  const parsed = parseAuthRequestResponse(rawResponse, now);
  if (parsed.requestApproved || parsed.answered) fail('auth request is no longer pending');
  if (parsed.key !== undefined || parsed.masterPasswordHash !== undefined) {
    fail('pending auth request contains response key material');
  }
  if (parsed.expired) fail('auth request is expired');
  if (parsed.creationTime > now + MAX_CLOCK_SKEW_MS) {
    fail('auth request creation date is outside the allowed clock skew');
  }
  assertCalendarDate(parsed.creationDate);
  assertDisplayText(parsed.requestDeviceIdentifier, 'requestDeviceIdentifier');
  assertOptionalDisplayText(parsed.requestDeviceType, 'requestDeviceType');
  assertOptionalDisplayText(parsed.requestIpAddress, 'requestIpAddress');
  assertOptionalDisplayText(parsed.requestCountryName, 'requestCountryName');
  assertOptionalDisplayText(parsed.origin, 'origin');

  const requestDeviceId = normalizeOptionalUuid(parsed.requestDeviceId, 'requestDeviceId');
  const publicKey = base64ToBytes(parsed.publicKey);
  let fingerprint: string;
  try {
    fingerprint = await deriveDeviceLoginFingerprint(
      context.accountEmail,
      publicKey,
      FINGERPRINT_WORDLIST,
    );
  } finally {
    publicKey.fill(0);
  }

  const view: DeviceLoginApprovalView = Object.freeze({
    id: parsed.id,
    fingerprint,
    ...(parsed.requestDeviceType ? { requestDeviceType: parsed.requestDeviceType } : {}),
    requestDeviceTypeValue: parsed.requestDeviceTypeValue,
    requestDeviceIdentifier: parsed.requestDeviceIdentifier,
    ...(parsed.requestIpAddress ? { requestIpAddress: parsed.requestIpAddress } : {}),
    ...(parsed.requestCountryName ? { requestCountryName: parsed.requestCountryName } : {}),
    creationDate: parsed.creationDate,
    creationTime: parsed.creationTime,
    expiresAt: parsed.creationTime + DEVICE_LOGIN_REQUEST_TTL_MS,
    ...(requestDeviceId !== undefined ? { requestDeviceId } : {}),
    ...(parsed.origin ? { origin: parsed.origin } : {}),
  });
  return Object.freeze({ parsed, view });
}

function serializeValidatedUserKey(userKey: SymmetricKey): Uint8Array {
  if (
    typeof userKey !== 'object'
    || userKey === null
    || !(userKey.encKey instanceof Uint8Array)
    || userKey.encKey.byteLength !== 32
    || !(userKey.macKey instanceof Uint8Array)
    || userKey.macKey.byteLength !== 32
  ) {
    fail('unlocked account user key is invalid');
  }
  return serializeSymmetricKey(userKey);
}

function validateApprovalDeviceIdentifier(value: unknown): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_DEVICE_IDENTIFIER_LENGTH
  ) {
    fail('approval device identifier is invalid');
  }
  assertDisplayText(value, 'approvalDeviceIdentifier');
  return value;
}

function normalizeOptionalUuid(value: string | undefined, label: string): string | undefined {
  if (value === undefined || value.length === 0) return undefined;
  if (value.length !== 36 || !UUID_PATTERN.test(value)) fail(`${label} must be a canonical UUID`);
  return value.toLowerCase();
}

function assertCalendarDate(value: string): void {
  const match = ISO_DATE_COMPONENTS.exec(value);
  if (!match) fail('creationDate is invalid');
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = match[7] === undefined ? 0 : Number(match[7]);
  const offsetMinute = match[8] === undefined ? 0 : Number(match[8]);
  const daysInMonth = month >= 1 && month <= 12
    ? new Date(Date.UTC(year, month, 0)).getUTCDate()
    : 0;
  if (
    day < 1
    || day > daysInMonth
    || hour > 23
    || minute > 59
    || second > 59
    || offsetHour > 23
    || offsetMinute > 59
  ) {
    fail('creationDate is invalid');
  }
}

function assertOptionalDisplayText(value: string | undefined, label: string): void {
  if (value !== undefined) assertDisplayText(value, label);
}

function assertDisplayText(value: string, label: string): void {
  if (UNSAFE_DISPLAY_TEXT.test(value)) {
    fail(`${label} contains unsafe display characters`);
  }
}

function fail(message: string): never {
  throw new DeviceLoginProtocolError(message);
}
