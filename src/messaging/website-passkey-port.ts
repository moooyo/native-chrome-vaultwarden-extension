import { base64UrlToBytes, bytesToBase64Url } from '../core/crypto/encoding.js';
import {
  MAX_PASSKEY_CHALLENGE_BYTES,
  MAX_PASSKEY_CREDENTIAL_DESCRIPTORS,
  MAX_PASSKEY_CREDENTIAL_ID_BYTES,
  MAX_PASSKEY_USER_HANDLE_BYTES,
} from '../core/vault/fido2-limits.js';

export const WEBSITE_PASSKEY_PORT_NAME = 'website-passkey-v1';
export const WEBSITE_PASSKEY_PORT_VERSION = 1 as const;
export const WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE = 'websitePasskey.configChanged';

export const MIN_WEBSITE_PASSKEY_TIMEOUT_MS = 30_000;
export const MAX_ORDINARY_WEBSITE_PASSKEY_TIMEOUT_MS = 180_000;
export const MAX_WEBSITE_PASSKEY_TIMEOUT_MS = 600_000;
export const DEFAULT_WEBSITE_PASSKEY_TIMEOUT_MS = 120_000;
export const DEFAULT_WEBSITE_PASSKEY_UV_TIMEOUT_MS = 300_000;
export const MAX_WEBSITE_PASSKEY_DESCRIPTORS = MAX_PASSKEY_CREDENTIAL_DESCRIPTORS;
export const MAX_WEBSITE_PASSKEY_CREDENTIAL_ID_BYTES = MAX_PASSKEY_CREDENTIAL_ID_BYTES;
export const MAX_WEBSITE_PASSKEY_CHALLENGE_BYTES = MAX_PASSKEY_CHALLENGE_BYTES;
export const MAX_WEBSITE_PASSKEY_RESULT_CHARS = 1_048_576;
export const MAX_WEBSITE_PASSKEY_AUTHENTICATOR_DATA_BYTES = 65_536;
export const MAX_WEBSITE_PASSKEY_CLIENT_DATA_JSON_BYTES = 65_536;
export const MAX_WEBSITE_PASSKEY_SIGNATURE_BYTES = 16_384;
export const MAX_WEBSITE_PASSKEY_ATTESTATION_OBJECT_BYTES = 1_048_576;
export const MAX_WEBSITE_PASSKEY_PUBLIC_KEY_SPKI_BYTES = 16_384;
export const MAX_WEBSITE_PASSKEY_USER_HANDLE_BYTES = MAX_PASSKEY_USER_HANDLE_BYTES;
export const MAX_WEBSITE_PASSKEY_CANDIDATES = 128;

const MAX_DISPLAY_CHARS = 4_096;
const MAX_DOM_EXCEPTION_MESSAGE_CHARS = 1_024;
const MAX_PUBLIC_KEY_PARAMS = 32;
const MAX_TRANSPORTS = 6;
const MAX_TIMEOUT_INPUT = 0xffff_ffff;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CANONICAL_BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

export const WEBSITE_PASSKEY_TRANSPORTS = [
  'ble', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb',
] as const;
export type WebsitePasskeyTransport = (typeof WEBSITE_PASSKEY_TRANSPORTS)[number];

export type WebsitePasskeyUserVerification = 'discouraged' | 'preferred' | 'required';
export type WebsitePasskeyOrdinaryMediation = 'optional' | 'required';
export type WebsitePasskeyMediation = 'conditional' | WebsitePasskeyOrdinaryMediation;
export type WebsitePasskeyResidentKey = 'discouraged' | 'preferred' | 'required';
export type WebsitePasskeyAuthenticatorAttachment = 'cross-platform' | 'platform';
export type WebsitePasskeyAttestation = 'direct' | 'enterprise' | 'indirect' | 'none';

export interface CanonicalWebsitePasskeyDescriptor {
  readonly id: string;
  readonly type: 'public-key';
  readonly transports: readonly WebsitePasskeyTransport[];
}

export interface CanonicalWebsitePasskeyGetRequest {
  readonly bridgeRequestId: string;
  readonly kind: 'get';
  readonly rpId: string;
  readonly challenge: string;
  readonly allowCredentials: readonly CanonicalWebsitePasskeyDescriptor[];
  readonly userVerification: WebsitePasskeyUserVerification;
  readonly mediation: WebsitePasskeyMediation;
  readonly timeout: number;
}

export interface CanonicalWebsitePasskeyCreateRequest {
  readonly bridgeRequestId: string;
  readonly kind: 'create';
  readonly rp: { readonly id: string; readonly name: string };
  readonly user: { readonly id: string; readonly name: string; readonly displayName: string };
  readonly challenge: string;
  readonly pubKeyCredParams: readonly [{ readonly type: 'public-key'; readonly alg: -7 }];
  readonly excludeCredentials: readonly CanonicalWebsitePasskeyDescriptor[];
  readonly authenticatorSelection: {
    readonly residentKey: WebsitePasskeyResidentKey;
    readonly requireResidentKey: boolean;
    readonly userVerification: WebsitePasskeyUserVerification;
    readonly authenticatorAttachment?: WebsitePasskeyAuthenticatorAttachment;
  };
  readonly attestation: WebsitePasskeyAttestation;
  readonly extensions: { readonly credProps: boolean };
  readonly timeout: number;
}

export type CanonicalWebsitePasskeyRequest = CanonicalWebsitePasskeyGetRequest | CanonicalWebsitePasskeyCreateRequest;

export const WEBSITE_PASSKEY_UNSUPPORTED_REASONS = [
  'silent_mediation', 'required_user_verification',
  'unsupported_algorithm', 'unsupported_attachment',
] as const;
export type WebsitePasskeyUnsupportedReason = (typeof WEBSITE_PASSKEY_UNSUPPORTED_REASONS)[number];
export type WebsitePasskeyRequestDecision =
  | { readonly status: 'accepted'; readonly request: CanonicalWebsitePasskeyRequest }
  | {
      readonly status: 'fallback';
      readonly bridgeRequestId: string;
      readonly request: CanonicalWebsitePasskeyRequest;
      readonly reason: WebsitePasskeyUnsupportedReason;
    };

export interface PasskeyAssertionResultSnapshot {
  readonly kind: 'get';
  readonly authenticatorAttachment: 'platform';
  readonly transports: readonly ['internal'];
  readonly credentialId: string;
  readonly authenticatorData: string;
  readonly clientDataJSON: string;
  readonly signature: string;
  readonly userHandle?: string;
}

export interface PasskeyRegistrationResultSnapshot {
  readonly kind: 'create';
  readonly authenticatorAttachment: 'platform';
  readonly transports: readonly ['internal'];
  readonly credProps: { readonly rk: boolean } | null;
  readonly credentialId: string;
  readonly attestationObject: string;
  readonly clientDataJSON: string;
  readonly authData: string;
  readonly publicKeySpki: string;
  readonly publicKeyAlgorithm: -7;
}

export type PasskeyCeremonyResultSnapshot = PasskeyAssertionResultSnapshot | PasskeyRegistrationResultSnapshot;

export interface WebsitePasskeyDisplayChoice {
  readonly id: string;
  readonly name: string;
  readonly username?: string;
}

export type WebsitePasskeyApprovalModel =
  | {
      readonly ceremonyId: string;
      readonly kind: 'get';
      readonly origin: string;
      readonly rpId: string;
      readonly state: 'awaiting' | 'executing';
      readonly candidates: readonly WebsitePasskeyDisplayChoice[];
    }
  | {
      readonly ceremonyId: string;
      readonly kind: 'create';
      readonly origin: string;
      readonly rpId: string;
      readonly state: 'awaiting' | 'executing';
      readonly targets: readonly WebsitePasskeyDisplayChoice[];
    };

export type WebsitePasskeySelection =
  | { readonly kind: 'credential'; readonly credentialId: string }
  | { readonly kind: 'new' }
  | { readonly kind: 'target'; readonly cipherId: string };

export type WebsitePasskeyDecisionOutcome =
  | 'completed'
  | 'fallback'
  | 'failed'
  | 'uncertain'
  | 'unavailable';

export const WEBSITE_PASSKEY_FALLBACK_REASONS = [
  'excluded_domain', 'no_match', 'unsupported', 'user_selected_browser',
] as const;
export type WebsitePasskeyFallbackReason = (typeof WEBSITE_PASSKEY_FALLBACK_REASONS)[number];
export const WEBSITE_PASSKEY_PREFLIGHT_FALLBACK_REASONS = ['capacity'] as const;
export type WebsitePasskeyPreflightFallbackReason =
  (typeof WEBSITE_PASSKEY_PREFLIGHT_FALLBACK_REASONS)[number];

export const WEBSITE_PASSKEY_DOM_EXCEPTION_NAMES = [
  'AbortError', 'ConstraintError', 'DataError', 'InvalidStateError', 'NotAllowedError',
  'NotSupportedError', 'OperationError', 'SecurityError', 'UnknownError',
] as const;
export type WebsitePasskeyDomExceptionName = (typeof WEBSITE_PASSKEY_DOM_EXCEPTION_NAMES)[number];

export interface WebsitePasskeyBeginMessage {
  readonly version: typeof WEBSITE_PASSKEY_PORT_VERSION;
  readonly type: 'begin';
  readonly request: CanonicalWebsitePasskeyRequest;
}

export interface WebsitePasskeyResumeMessage {
  readonly version: typeof WEBSITE_PASSKEY_PORT_VERSION;
  readonly type: 'resume';
  readonly request: CanonicalWebsitePasskeyRequest;
}

export interface WebsitePasskeyHelloMessage {
  readonly version: typeof WEBSITE_PASSKEY_PORT_VERSION;
  readonly type: 'hello';
}

export interface WebsitePasskeyBoundClientMessage {
  readonly version: typeof WEBSITE_PASSKEY_PORT_VERSION;
  readonly type: 'cancel';
  readonly ceremonyId: string;
  readonly bridgeRequestId: string;
}

export interface WebsitePasskeyAckMessage {
  readonly version: typeof WEBSITE_PASSKEY_PORT_VERSION;
  readonly type: 'ack';
  readonly ceremonyId: string;
  readonly bridgeRequestId: string;
  readonly outcomeId: string;
}

export interface WebsitePasskeyConditionalSelectMessage {
  readonly version: typeof WEBSITE_PASSKEY_PORT_VERSION;
  readonly type: 'conditionalSelect';
  readonly ceremonyId: string;
  readonly bridgeRequestId: string;
  readonly credentialId: string;
}

export type WebsitePasskeyClientMessage =
  | WebsitePasskeyHelloMessage
  | WebsitePasskeyBeginMessage
  | WebsitePasskeyResumeMessage
  | WebsitePasskeyBoundClientMessage
  | WebsitePasskeyConditionalSelectMessage
  | WebsitePasskeyAckMessage;
export type WebsitePasskeyClientMessageDecision =
  | { readonly status: 'accepted'; readonly message: WebsitePasskeyClientMessage }
  | {
      readonly status: 'fallback';
      readonly bridgeRequestId: string;
      readonly request: CanonicalWebsitePasskeyRequest;
      readonly reason: WebsitePasskeyUnsupportedReason;
    };

export interface WebsitePasskeyAcceptedMessage {
  readonly version: typeof WEBSITE_PASSKEY_PORT_VERSION;
  readonly type: 'accepted';
  readonly ceremonyId: string;
  readonly bridgeRequestId: string;
  readonly deadlineAt: number;
}

/** Public hold state relayed through the isolated bridge; it contains no candidate or vault data. */
export interface WebsitePasskeyUnlockPendingMessage {
  readonly version: typeof WEBSITE_PASSKEY_PORT_VERSION;
  readonly type: 'unlockPending';
  readonly continuationId: string;
  readonly bridgeRequestId: string;
  readonly deadlineAt: number;
}

/** Private worker-to-isolated-world message. Candidate details must never cross into MAIN world. */
export interface WebsitePasskeyConditionalActiveMessage {
  readonly version: typeof WEBSITE_PASSKEY_PORT_VERSION;
  readonly type: 'conditionalActive';
  readonly ceremonyId: string;
  readonly bridgeRequestId: string;
  readonly deadlineAt: number;
  readonly candidates: readonly WebsitePasskeyDisplayChoice[];
}

export interface WebsitePasskeyConfigMessage {
  readonly version: typeof WEBSITE_PASSKEY_PORT_VERSION;
  readonly type: 'config';
  readonly enabled: boolean;
}

export type WebsitePasskeyPreflightOutcome =
  | { readonly status: 'fallback'; readonly reason: WebsitePasskeyPreflightFallbackReason }
  | {
      readonly status: 'error';
      readonly error: { readonly name: 'NotAllowedError'; readonly message: string };
    };

export interface WebsitePasskeyPreflightOutcomeMessage {
  readonly version: typeof WEBSITE_PASSKEY_PORT_VERSION;
  readonly type: 'preflightOutcome';
  readonly bridgeRequestId: string;
  readonly outcome: WebsitePasskeyPreflightOutcome;
}

export type WebsitePasskeyOutcome =
  | { readonly status: 'success'; readonly result: PasskeyCeremonyResultSnapshot }
  | { readonly status: 'fallback'; readonly reason: WebsitePasskeyFallbackReason }
  | { readonly status: 'error'; readonly error: { readonly name: WebsitePasskeyDomExceptionName; readonly message: string } };

export interface WebsitePasskeyOutcomeMessage {
  readonly version: typeof WEBSITE_PASSKEY_PORT_VERSION;
  readonly type: 'outcome';
  readonly ceremonyId: string;
  readonly bridgeRequestId: string;
  readonly outcomeId: string;
  readonly outcome: WebsitePasskeyOutcome;
}

export type WebsitePasskeyServerMessage =
  | WebsitePasskeyConfigMessage
  | WebsitePasskeyPreflightOutcomeMessage
  | WebsitePasskeyUnlockPendingMessage
  | WebsitePasskeyAcceptedMessage
  | WebsitePasskeyConditionalActiveMessage
  | WebsitePasskeyOutcomeMessage;
export type WebsitePasskeyPortErrorCode = 'invalid_message' | 'unsupported_version';

export interface WebsitePasskeyConfigChangedMessage {
  readonly type: typeof WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE;
}

export interface WebsitePasskeyConfigChangedAck {
  readonly websitePasskey: true;
}

export class WebsitePasskeyPortProtocolError extends Error {
  constructor(readonly code: WebsitePasskeyPortErrorCode) {
    super(code === 'unsupported_version'
      ? 'The website passkey protocol version is not supported.'
      : 'The website passkey message is invalid.');
    this.name = 'WebsitePasskeyPortProtocolError';
  }
}

export function parseWebsitePasskeyConfigChangedMessage(
  value: unknown,
): WebsitePasskeyConfigChangedMessage {
  const message = plainRecord(value);
  exactKeys(message, ['type']);
  if (dataProperty(message, 'type') !== WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE) invalidMessage();
  return Object.freeze({ type: WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE });
}

export function parseWebsitePasskeyConfigChangedAck(
  value: unknown,
): WebsitePasskeyConfigChangedAck {
  const ack = plainRecord(value);
  exactKeys(ack, ['websitePasskey']);
  if (dataProperty(ack, 'websitePasskey') !== true) invalidMessage();
  return Object.freeze({ websitePasskey: true });
}

export function createWebsitePasskeyPreflightOutcomeMessage(
  rawBridgeRequestId: string,
  admission: 'busy' | 'cancelled' | 'expired' | 'unavailable' | 'capacity',
): WebsitePasskeyPreflightOutcomeMessage {
  const canonicalBridgeRequestId = bridgeRequestId(rawBridgeRequestId);
  if (admission === 'capacity') {
    return Object.freeze({
      version: WEBSITE_PASSKEY_PORT_VERSION,
      type: 'preflightOutcome',
      bridgeRequestId: canonicalBridgeRequestId,
      outcome: Object.freeze({ status: 'fallback', reason: 'capacity' }),
    });
  }
  if (admission !== 'busy' && admission !== 'cancelled'
      && admission !== 'expired' && admission !== 'unavailable') return invalidMessage();
  const message = admission === 'busy'
    ? 'Another passkey request is already in progress for this document.'
    : admission === 'expired'
      ? 'The passkey request timed out before the vault was unlocked.'
      : admission === 'cancelled'
        ? 'The passkey request was cancelled before the vault was unlocked.'
        : 'The passkey request could not be resumed after the vault was unlocked.';
  return Object.freeze({
    version: WEBSITE_PASSKEY_PORT_VERSION,
    type: 'preflightOutcome',
    bridgeRequestId: canonicalBridgeRequestId,
    outcome: Object.freeze({
      status: 'error',
      error: Object.freeze({
        name: 'NotAllowedError',
        message,
      }),
    }),
  });
}

/** Parse and rebuild one request without retaining any caller-owned object or array. */
export function canonicalizeWebsitePasskeyRequest(value: unknown): CanonicalWebsitePasskeyRequest {
  const parsed = parseWebsitePasskeyRequest(value);
  return parsed.request;
}

/** Separate supported semantics from wire validity so recognized requests can fall back natively. */
export function decideWebsitePasskeySupport(value: unknown): WebsitePasskeyRequestDecision {
  const parsed = parseWebsitePasskeyRequest(value);
  if (parsed.unsupportedReason !== undefined) {
    return Object.freeze({
      status: 'fallback' as const,
      bridgeRequestId: parsed.request.bridgeRequestId,
      request: parsed.request,
      reason: parsed.unsupportedReason,
    });
  }
  return Object.freeze({ status: 'accepted' as const, request: parsed.request });
}

/** Stable serialization used as the sole input to the registry's request digest. */
export function serializeCanonicalWebsitePasskeyRequest(value: unknown): string {
  return JSON.stringify(canonicalizeWebsitePasskeyRequest(value));
}

export function parsePasskeyCeremonyResultSnapshot(
  value: unknown,
  expectedKind?: CanonicalWebsitePasskeyRequest['kind'],
): PasskeyCeremonyResultSnapshot {
  const result = plainRecord(value);
  const kind = oneOf(dataProperty(result, 'kind'), ['create', 'get'] as const);
  if (expectedKind !== undefined && kind !== expectedKind) invalidMessage();
  return kind === 'get' ? parseAssertionResult(result) : parseRegistrationResult(result);
}

export function parseWebsitePasskeyClientMessage(value: unknown): WebsitePasskeyClientMessageDecision {
  const message = parseEnvelope(value);
  switch (message.type) {
    case 'hello':
      exactKeys(message, ['version', 'type']);
      return {
        status: 'accepted',
        message: { version: WEBSITE_PASSKEY_PORT_VERSION, type: 'hello' },
      };
    case 'begin': {
      exactKeys(message, ['version', 'type', 'request']);
      const decision = decideWebsitePasskeySupport(dataProperty(message, 'request'));
      if (decision.status === 'fallback') return decision;
      return {
        status: 'accepted',
        message: { version: WEBSITE_PASSKEY_PORT_VERSION, type: 'begin', request: decision.request },
      };
    }
    case 'resume': {
      exactKeys(message, ['version', 'type', 'request']);
      return {
        status: 'accepted',
        message: {
          version: WEBSITE_PASSKEY_PORT_VERSION,
          type: 'resume',
          request: canonicalizeWebsitePasskeyRequest(dataProperty(message, 'request')),
        },
      };
    }
    case 'cancel': {
      exactKeys(message, ['version', 'type', 'ceremonyId', 'bridgeRequestId']);
      return {
        status: 'accepted',
        message: {
          version: WEBSITE_PASSKEY_PORT_VERSION,
          type: message.type,
          ceremonyId: uuidV4(dataProperty(message, 'ceremonyId')),
          bridgeRequestId: bridgeRequestId(dataProperty(message, 'bridgeRequestId')),
        },
      };
    }
    case 'conditionalSelect': {
      exactKeys(message, [
        'version', 'type', 'ceremonyId', 'bridgeRequestId', 'credentialId',
      ]);
      return {
        status: 'accepted',
        message: {
          version: WEBSITE_PASSKEY_PORT_VERSION,
          type: 'conditionalSelect',
          ceremonyId: uuidV4(dataProperty(message, 'ceremonyId')),
          bridgeRequestId: bridgeRequestId(dataProperty(message, 'bridgeRequestId')),
          credentialId: canonicalBase64Url(
            dataProperty(message, 'credentialId'), 1, MAX_WEBSITE_PASSKEY_CREDENTIAL_ID_BYTES,
          ),
        },
      };
    }
    case 'ack': {
      exactKeys(message, ['version', 'type', 'ceremonyId', 'bridgeRequestId', 'outcomeId']);
      return {
        status: 'accepted',
        message: {
          version: WEBSITE_PASSKEY_PORT_VERSION,
          type: 'ack',
          ceremonyId: uuidV4(dataProperty(message, 'ceremonyId')),
          bridgeRequestId: bridgeRequestId(dataProperty(message, 'bridgeRequestId')),
          outcomeId: uuidV4(dataProperty(message, 'outcomeId')),
        },
      };
    }
    default:
      return invalidMessage();
  }
}

export function parseWebsitePasskeyServerMessage(value: unknown): WebsitePasskeyServerMessage {
  const message = parseEnvelope(value);
  switch (message.type) {
    case 'config': {
      exactKeys(message, ['version', 'type', 'enabled']);
      const enabled = dataProperty(message, 'enabled');
      if (typeof enabled !== 'boolean') invalidMessage();
      return { version: WEBSITE_PASSKEY_PORT_VERSION, type: 'config', enabled };
    }
    case 'accepted':
      exactKeys(message, ['version', 'type', 'ceremonyId', 'bridgeRequestId', 'deadlineAt']);
      return {
        version: WEBSITE_PASSKEY_PORT_VERSION,
        type: 'accepted',
        ceremonyId: uuidV4(dataProperty(message, 'ceremonyId')),
        bridgeRequestId: bridgeRequestId(dataProperty(message, 'bridgeRequestId')),
        deadlineAt: boundedInteger(dataProperty(message, 'deadlineAt'), 0, Number.MAX_SAFE_INTEGER),
      };
    case 'unlockPending':
      exactKeys(message, ['version', 'type', 'continuationId', 'bridgeRequestId', 'deadlineAt']);
      return {
        version: WEBSITE_PASSKEY_PORT_VERSION,
        type: 'unlockPending',
        continuationId: uuidV4(dataProperty(message, 'continuationId')),
        bridgeRequestId: bridgeRequestId(dataProperty(message, 'bridgeRequestId')),
        deadlineAt: boundedInteger(dataProperty(message, 'deadlineAt'), 0, Number.MAX_SAFE_INTEGER),
      };
    case 'conditionalActive':
      exactKeys(message, [
        'version', 'type', 'ceremonyId', 'bridgeRequestId', 'deadlineAt', 'candidates',
      ]);
      return {
        version: WEBSITE_PASSKEY_PORT_VERSION,
        type: 'conditionalActive',
        ceremonyId: uuidV4(dataProperty(message, 'ceremonyId')),
        bridgeRequestId: bridgeRequestId(dataProperty(message, 'bridgeRequestId')),
        deadlineAt: boundedInteger(dataProperty(message, 'deadlineAt'), 0, Number.MAX_SAFE_INTEGER),
        candidates: parseDisplayChoices(dataProperty(message, 'candidates')),
      };
    case 'preflightOutcome':
      exactKeys(message, ['version', 'type', 'bridgeRequestId', 'outcome']);
      return {
        version: WEBSITE_PASSKEY_PORT_VERSION,
        type: 'preflightOutcome',
        bridgeRequestId: bridgeRequestId(dataProperty(message, 'bridgeRequestId')),
        outcome: parsePreflightOutcome(dataProperty(message, 'outcome')),
      };
    case 'outcome':
      exactKeys(message, ['version', 'type', 'ceremonyId', 'bridgeRequestId', 'outcomeId', 'outcome']);
      return {
        version: WEBSITE_PASSKEY_PORT_VERSION,
        type: 'outcome',
        ceremonyId: uuidV4(dataProperty(message, 'ceremonyId')),
        bridgeRequestId: bridgeRequestId(dataProperty(message, 'bridgeRequestId')),
        outcomeId: uuidV4(dataProperty(message, 'outcomeId')),
        outcome: parseOutcome(dataProperty(message, 'outcome')),
      };
    default:
      return invalidMessage();
  }
}

interface ParsedRequest {
  readonly request: CanonicalWebsitePasskeyRequest;
  readonly unsupportedReason?: WebsitePasskeyUnsupportedReason;
}

function parseWebsitePasskeyRequest(value: unknown): ParsedRequest {
  const request = plainRecord(value);
  const kind = oneOf(dataProperty(request, 'kind'), ['create', 'get'] as const);
  return kind === 'get' ? parseGetRequest(request) : parseCreateRequest(request);
}

function parseGetRequest(request: Record<string, unknown>): ParsedRequest {
  exactKeys(
    request,
    ['bridgeRequestId', 'kind', 'rpId', 'challenge', 'allowCredentials'],
    ['userVerification', 'mediation', 'timeout'],
  );
  const id = bridgeRequestId(dataProperty(request, 'bridgeRequestId'));
  const userVerification = optionalOneOf(
    request, 'userVerification', ['discouraged', 'preferred', 'required'] as const, 'preferred',
  );
  const mediation = optionalOneOf(
    request, 'mediation', ['conditional', 'optional', 'required', 'silent'] as const, 'optional',
  );
  const canonical = Object.freeze({
    bridgeRequestId: id,
    kind: 'get' as const,
    rpId: parseRpId(dataProperty(request, 'rpId')),
    challenge: canonicalBase64Url(
      dataProperty(request, 'challenge'), 1, MAX_WEBSITE_PASSKEY_CHALLENGE_BYTES,
    ),
    allowCredentials: parseDescriptors(dataProperty(request, 'allowCredentials')),
    userVerification,
    mediation: mediation === 'silent' ? 'optional' as const : mediation,
    timeout: parseTimeout(request, userVerification),
  });
  const unsupportedReason = mediation === 'silent'
    ? 'silent_mediation' as const
    : userVerification === 'required'
      ? 'required_user_verification' as const
      : undefined;
  return Object.freeze({ request: canonical, ...(unsupportedReason === undefined ? {} : { unsupportedReason }) });
}

function parseCreateRequest(request: Record<string, unknown>): ParsedRequest {
  exactKeys(
    request,
    ['bridgeRequestId', 'kind', 'rp', 'user', 'challenge', 'pubKeyCredParams', 'excludeCredentials'],
    ['authenticatorSelection', 'attestation', 'extensions', 'timeout'],
  );
  const id = bridgeRequestId(dataProperty(request, 'bridgeRequestId'));
  const selection = parseAuthenticatorSelection(optionalDataProperty(request, 'authenticatorSelection'));
  const supportsEs256 = parsePublicKeyParams(dataProperty(request, 'pubKeyCredParams'));
  const canonical = Object.freeze({
    bridgeRequestId: id,
    kind: 'create' as const,
    rp: parseRp(dataProperty(request, 'rp')),
    user: parseUser(dataProperty(request, 'user')),
    challenge: canonicalBase64Url(
      dataProperty(request, 'challenge'), 1, MAX_WEBSITE_PASSKEY_CHALLENGE_BYTES,
    ),
    pubKeyCredParams: Object.freeze([
      Object.freeze({ type: 'public-key' as const, alg: -7 as const }),
    ]) as CanonicalWebsitePasskeyCreateRequest['pubKeyCredParams'],
    excludeCredentials: parseDescriptors(dataProperty(request, 'excludeCredentials')),
    authenticatorSelection: selection,
    attestation: optionalOneOf(
      request, 'attestation', ['direct', 'enterprise', 'indirect', 'none'] as const, 'none',
    ),
    extensions: parseExtensions(optionalDataProperty(request, 'extensions')),
    timeout: parseTimeout(request, selection.userVerification),
  });
  const unsupportedReason = selection.userVerification === 'required'
    ? 'required_user_verification' as const
    : !supportsEs256
    ? 'unsupported_algorithm' as const
    : selection.authenticatorAttachment === 'cross-platform'
      ? 'unsupported_attachment' as const
      : undefined;
  return Object.freeze({ request: canonical, ...(unsupportedReason === undefined ? {} : { unsupportedReason }) });
}

function parseRp(value: unknown): CanonicalWebsitePasskeyCreateRequest['rp'] {
  const entity = plainRecord(value);
  exactKeys(entity, ['id', 'name']);
  return Object.freeze({
    id: parseRpId(dataProperty(entity, 'id')),
    name: displayString(dataProperty(entity, 'name')),
  });
}

function parseUser(value: unknown): CanonicalWebsitePasskeyCreateRequest['user'] {
  const entity = plainRecord(value);
  exactKeys(entity, ['id', 'name', 'displayName']);
  return Object.freeze({
    id: canonicalBase64Url(dataProperty(entity, 'id'), 1, 64),
    name: displayString(dataProperty(entity, 'name')),
    displayName: displayString(dataProperty(entity, 'displayName')),
  });
}

function parsePublicKeyParams(value: unknown): boolean {
  const values = strictArray(value, MAX_PUBLIC_KEY_PARAMS, false);
  let supportsEs256 = false;
  for (const entry of values) {
    const param = plainRecord(entry);
    exactKeys(param, ['type', 'alg']);
    const type = dataProperty(param, 'type');
    const alg = dataProperty(param, 'alg');
    if (type !== 'public-key' || !Number.isSafeInteger(alg) || Object.is(alg, -0)) invalidMessage();
    if (alg === -7) supportsEs256 = true;
  }
  return supportsEs256;
}

function parseAuthenticatorSelection(value: unknown): CanonicalWebsitePasskeyCreateRequest['authenticatorSelection'] {
  if (value === undefined) {
    return Object.freeze({
      residentKey: 'discouraged', requireResidentKey: false, userVerification: 'preferred',
    });
  }
  const selection = plainRecord(value);
  exactKeys(selection, [], [
    'residentKey', 'requireResidentKey', 'userVerification', 'authenticatorAttachment',
  ]);
  const requireResidentKey = optionalBoolean(selection, 'requireResidentKey', false);
  const residentKey = optionalOneOf(
    selection,
    'residentKey',
    ['discouraged', 'preferred', 'required'] as const,
    requireResidentKey ? 'required' : 'discouraged',
  );
  const userVerification = optionalOneOf(
    selection,
    'userVerification',
    ['discouraged', 'preferred', 'required'] as const,
    'preferred',
  );
  const attachment = optionalOneOf(
    selection,
    'authenticatorAttachment',
    ['cross-platform', 'platform'] as const,
    undefined,
  );
  return Object.freeze({
    residentKey,
    requireResidentKey,
    userVerification,
    ...(attachment === undefined ? {} : { authenticatorAttachment: attachment }),
  });
}

function parseExtensions(value: unknown): CanonicalWebsitePasskeyCreateRequest['extensions'] {
  if (value === undefined) return Object.freeze({ credProps: false });
  const extensions = plainRecord(value);
  exactKeys(extensions, [], ['credProps']);
  return Object.freeze({ credProps: optionalBoolean(extensions, 'credProps', false) });
}

function parseDescriptors(value: unknown): readonly CanonicalWebsitePasskeyDescriptor[] {
  const values = strictArray(value, MAX_WEBSITE_PASSKEY_DESCRIPTORS);
  const seen = new Set<string>();
  return Object.freeze(values.map((entry) => {
    const descriptor = plainRecord(entry);
    exactKeys(descriptor, ['id', 'type'], ['transports']);
    if (dataProperty(descriptor, 'type') !== 'public-key') invalidMessage();
    const id = canonicalBase64Url(
      dataProperty(descriptor, 'id'), 1, MAX_WEBSITE_PASSKEY_CREDENTIAL_ID_BYTES,
    );
    if (seen.has(id)) invalidMessage();
    seen.add(id);
    return Object.freeze({
      id,
      type: 'public-key' as const,
      transports: parseTransports(optionalDataProperty(descriptor, 'transports')),
    });
  }));
}

function parseTransports(value: unknown): readonly WebsitePasskeyTransport[] {
  if (value === undefined) return Object.freeze([]);
  const values = strictArray(value, MAX_TRANSPORTS);
  const unique = new Set<WebsitePasskeyTransport>();
  for (const item of values) {
    const transport = oneOf(item, WEBSITE_PASSKEY_TRANSPORTS);
    if (unique.has(transport)) invalidMessage();
    unique.add(transport);
  }
  return Object.freeze([...unique].sort());
}

function parseTimeout(
  value: Record<string, unknown>,
  userVerification: WebsitePasskeyUserVerification,
): number {
  const fallback = userVerification === 'discouraged'
    ? DEFAULT_WEBSITE_PASSKEY_TIMEOUT_MS
    : DEFAULT_WEBSITE_PASSKEY_UV_TIMEOUT_MS;
  const maximum = userVerification === 'required'
    ? MAX_WEBSITE_PASSKEY_TIMEOUT_MS
    : MAX_ORDINARY_WEBSITE_PASSKEY_TIMEOUT_MS;
  if (!hasOwn(value, 'timeout')) return Math.min(fallback, maximum);
  const requested = boundedInteger(dataProperty(value, 'timeout'), 1, MAX_TIMEOUT_INPUT);
  return Math.max(MIN_WEBSITE_PASSKEY_TIMEOUT_MS, Math.min(requested, maximum));
}

function parseOutcome(value: unknown): WebsitePasskeyOutcome {
  const outcome = plainRecord(value);
  const status = oneOf(dataProperty(outcome, 'status'), ['error', 'fallback', 'success'] as const);
  switch (status) {
    case 'success':
      exactKeys(outcome, ['status', 'result']);
      return Object.freeze({
        status,
        result: parsePasskeyCeremonyResultSnapshot(dataProperty(outcome, 'result')),
      });
    case 'fallback':
      exactKeys(outcome, ['status', 'reason']);
      return Object.freeze({
        status,
        reason: oneOf(dataProperty(outcome, 'reason'), WEBSITE_PASSKEY_FALLBACK_REASONS),
      });
    case 'error': {
      exactKeys(outcome, ['status', 'error']);
      const error = plainRecord(dataProperty(outcome, 'error'));
      exactKeys(error, ['name', 'message']);
      return Object.freeze({
        status,
        error: Object.freeze({
          name: oneOf(dataProperty(error, 'name'), WEBSITE_PASSKEY_DOM_EXCEPTION_NAMES),
          message: boundedString(dataProperty(error, 'message'), 1, MAX_DOM_EXCEPTION_MESSAGE_CHARS),
        }),
      });
    }
  }
}

function parsePreflightOutcome(value: unknown): WebsitePasskeyPreflightOutcome {
  const outcome = plainRecord(value);
  const status = oneOf(dataProperty(outcome, 'status'), ['error', 'fallback'] as const);
  if (status === 'fallback') {
    exactKeys(outcome, ['status', 'reason']);
    return Object.freeze({
      status,
      reason: oneOf(dataProperty(outcome, 'reason'), WEBSITE_PASSKEY_PREFLIGHT_FALLBACK_REASONS),
    });
  }
  exactKeys(outcome, ['status', 'error']);
  const error = plainRecord(dataProperty(outcome, 'error'));
  exactKeys(error, ['name', 'message']);
  if (dataProperty(error, 'name') !== 'NotAllowedError') invalidMessage();
  return Object.freeze({
    status,
    error: Object.freeze({
      name: 'NotAllowedError',
      message: boundedString(dataProperty(error, 'message'), 1, MAX_DOM_EXCEPTION_MESSAGE_CHARS),
    }),
  });
}

function parseDisplayChoices(value: unknown): readonly WebsitePasskeyDisplayChoice[] {
  const choices = strictArray(value, MAX_WEBSITE_PASSKEY_CANDIDATES, false);
  const seen = new Set<string>();
  return Object.freeze(choices.map((value) => {
    const choice = plainRecord(value);
    exactKeys(choice, ['id', 'name'], ['username']);
    const id = canonicalBase64Url(
      dataProperty(choice, 'id'), 1, MAX_WEBSITE_PASSKEY_CREDENTIAL_ID_BYTES,
    );
    if (seen.has(id)) invalidMessage();
    seen.add(id);
    return Object.freeze({
      id,
      name: displayString(dataProperty(choice, 'name')),
      ...(hasOwn(choice, 'username')
        ? { username: displayString(dataProperty(choice, 'username')) }
        : {}),
    });
  }));
}

function parseAssertionResult(result: Record<string, unknown>): PasskeyAssertionResultSnapshot {
  exactKeys(
    result,
    [
      'kind', 'authenticatorAttachment', 'transports', 'credentialId', 'authenticatorData',
      'clientDataJSON', 'signature',
    ],
    ['userHandle'],
  );
  parseSoftwareAuthenticator(result);
  return Object.freeze({
    kind: 'get',
    authenticatorAttachment: 'platform',
    transports: Object.freeze(['internal'] as const),
    credentialId: canonicalBase64Url(
      dataProperty(result, 'credentialId'), 1, MAX_WEBSITE_PASSKEY_CREDENTIAL_ID_BYTES,
    ),
    authenticatorData: canonicalBase64Url(
      dataProperty(result, 'authenticatorData'), 1, MAX_WEBSITE_PASSKEY_AUTHENTICATOR_DATA_BYTES,
    ),
    clientDataJSON: canonicalBase64Url(
      dataProperty(result, 'clientDataJSON'), 1, MAX_WEBSITE_PASSKEY_CLIENT_DATA_JSON_BYTES,
    ),
    signature: canonicalBase64Url(
      dataProperty(result, 'signature'), 1, MAX_WEBSITE_PASSKEY_SIGNATURE_BYTES,
    ),
    ...(hasOwn(result, 'userHandle')
      ? {
          userHandle: canonicalBase64Url(
            dataProperty(result, 'userHandle'), 1, MAX_WEBSITE_PASSKEY_USER_HANDLE_BYTES,
          ),
        }
      : {}),
  });
}

function parseRegistrationResult(result: Record<string, unknown>): PasskeyRegistrationResultSnapshot {
  exactKeys(result, [
    'kind', 'authenticatorAttachment', 'transports', 'credProps', 'credentialId',
    'attestationObject', 'clientDataJSON', 'authData', 'publicKeySpki', 'publicKeyAlgorithm',
  ]);
  parseSoftwareAuthenticator(result);
  const rawCredProps = dataProperty(result, 'credProps');
  let credProps: { readonly rk: boolean } | null;
  if (rawCredProps === null) {
    credProps = null;
  } else {
    const parsed = plainRecord(rawCredProps);
    exactKeys(parsed, ['rk']);
    const rk = dataProperty(parsed, 'rk');
    if (typeof rk !== 'boolean') invalidMessage();
    credProps = Object.freeze({ rk });
  }
  return Object.freeze({
    kind: 'create',
    authenticatorAttachment: 'platform',
    transports: Object.freeze(['internal'] as const),
    credProps,
    credentialId: canonicalBase64Url(
      dataProperty(result, 'credentialId'), 1, MAX_WEBSITE_PASSKEY_CREDENTIAL_ID_BYTES,
    ),
    attestationObject: canonicalBase64Url(
      dataProperty(result, 'attestationObject'), 1, MAX_WEBSITE_PASSKEY_ATTESTATION_OBJECT_BYTES,
    ),
    clientDataJSON: canonicalBase64Url(
      dataProperty(result, 'clientDataJSON'), 1, MAX_WEBSITE_PASSKEY_CLIENT_DATA_JSON_BYTES,
    ),
    authData: canonicalBase64Url(
      dataProperty(result, 'authData'), 1, MAX_WEBSITE_PASSKEY_AUTHENTICATOR_DATA_BYTES,
    ),
    publicKeySpki: canonicalBase64Url(
      dataProperty(result, 'publicKeySpki'), 1, MAX_WEBSITE_PASSKEY_PUBLIC_KEY_SPKI_BYTES,
    ),
    publicKeyAlgorithm: exactEs256Algorithm(dataProperty(result, 'publicKeyAlgorithm')),
  });
}

function parseSoftwareAuthenticator(result: Record<string, unknown>): void {
  if (dataProperty(result, 'authenticatorAttachment') !== 'platform') invalidMessage();
  const transports = strictArray(dataProperty(result, 'transports'), 1, false);
  if (transports.length !== 1 || transports[0] !== 'internal') invalidMessage();
}

function parseEnvelope(value: unknown): Record<string, unknown> {
  const message = plainRecord(value);
  const version = dataProperty(message, 'version');
  if (!Number.isSafeInteger(version) || Object.is(version, -0)) invalidMessage();
  if (version !== WEBSITE_PASSKEY_PORT_VERSION) {
    throw new WebsitePasskeyPortProtocolError('unsupported_version');
  }
  if (typeof dataProperty(message, 'type') !== 'string') invalidMessage();
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
  for (const key of required) if (!hasOwn(value, key)) invalidMessage();
  for (const key of keys) {
    if (typeof key !== 'string' || !allowed.has(key)) invalidMessage();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      invalidMessage();
    }
  }
}

function plainRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) invalidMessage();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalidMessage();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') invalidMessage();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      invalidMessage();
    }
  }
  return value as Record<string, unknown>;
}

function strictArray(value: unknown, maximumLength: number, allowEmpty = true): unknown[] {
  if (
    !Array.isArray(value)
    || Object.getPrototypeOf(value) !== Array.prototype
    || value.length > maximumLength
    || (!allowEmpty && value.length === 0)
  ) invalidMessage();
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !hasOwn(value, 'length')) invalidMessage();
  const entries: unknown[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      invalidMessage();
    }
    entries.push(descriptor.value);
  }
  for (const key of keys) {
    if (key !== 'length' && (typeof key !== 'string' || !/^(?:0|[1-9]\d*)$/.test(key))) {
      invalidMessage();
    }
  }
  return entries;
}

function dataProperty(value: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
    invalidMessage();
  }
  return descriptor.value;
}

function optionalDataProperty(value: Record<string, unknown>, key: string): unknown {
  return hasOwn(value, key) ? dataProperty(value, key) : undefined;
}

function optionalOneOf<const Values extends readonly string[], Fallback extends Values[number] | undefined>(
  value: Record<string, unknown>,
  key: string,
  allowed: Values,
  fallback: Fallback,
): Values[number] | Fallback {
  return hasOwn(value, key) ? oneOf(dataProperty(value, key), allowed) : fallback;
}

function optionalBoolean(value: Record<string, unknown>, key: string, fallback: boolean): boolean {
  if (!hasOwn(value, key)) return fallback;
  const item = dataProperty(value, key);
  if (typeof item !== 'boolean') invalidMessage();
  return item;
}

function oneOf<const Values extends readonly string[]>(value: unknown, allowed: Values): Values[number] {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) invalidMessage();
  return value as Values[number];
}

function bridgeRequestId(value: unknown): string {
  return uuidV4(value);
}

function exactEs256Algorithm(value: unknown): -7 {
  if (value !== -7) invalidMessage();
  return -7;
}

function parseRpId(value: unknown): string {
  const text = boundedString(value, 1, 253, true);
  const parsed = text.toLowerCase();
  if (/[^a-z0-9.-]/.test(parsed) || parsed.startsWith('.') || parsed.endsWith('.') || parsed.includes('..')) {
    invalidMessage();
  }
  return parsed;
}

function displayString(value: unknown): string {
  return boundedString(value, 1, MAX_DISPLAY_CHARS);
}

function boundedString(value: unknown, minimum: number, maximum: number, trimExact = false): string {
  if (typeof value !== 'string' || value.length < minimum || value.length > maximum) invalidMessage();
  if (trimExact && value.trim() !== value) invalidMessage();
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || codeUnit === 0x7f) invalidMessage();
  }
  return value;
}

function canonicalBase64Url(value: unknown, minimumBytes: number, maximumBytes: number): string {
  if (typeof value !== 'string' || !CANONICAL_BASE64URL_PATTERN.test(value)) invalidMessage();
  if (value.length > Math.ceil(maximumBytes / 3) * 4) invalidMessage();
  let bytes: Uint8Array;
  try { bytes = base64UrlToBytes(value); } catch { return invalidMessage(); }
  if (
    bytes.byteLength < minimumBytes
    || bytes.byteLength > maximumBytes
    || bytesToBase64Url(bytes) !== value
  ) invalidMessage();
  return value;
}

function uuidV4(value: unknown): string {
  if (typeof value !== 'string' || value.length !== 36 || !UUID_V4_PATTERN.test(value)) invalidMessage();
  return value;
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (
    !Number.isSafeInteger(value)
    || Object.is(value, -0)
    || (value as number) < minimum
    || (value as number) > maximum
  ) invalidMessage();
  return value as number;
}

function hasOwn(value: object, key: PropertyKey): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function invalidMessage(): never {
  throw new WebsitePasskeyPortProtocolError('invalid_message');
}
