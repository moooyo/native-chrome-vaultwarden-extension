import { getDomain } from 'tldts';
import { base64UrlToBytes, bytesToBase64Url, utf8ToBytes } from '../crypto/encoding.js';

const MAX_ORIGIN_LENGTH = 2_048;
const MAX_RP_ID_LENGTH = 253;
const MIN_CHALLENGE_BYTES = 16;
const MAX_CHALLENGE_BYTES = 128;
const MAX_CREDENTIALS = 64;
const MAX_CREDENTIAL_ID_BYTES = 1_024;
const MAX_TIMEOUT_MS = 5 * 60_000;
const MAX_AUTHENTICATOR_DATA_BYTES = 8 * 1_024;
const MAX_CLIENT_DATA_BYTES = 8 * 1_024;
const MAX_SIGNATURE_BYTES = 1_024;
const MAX_USER_HANDLE_BYTES = 64;
const MAX_UVM_ENTRIES = 16;
const MAX_ASSERTION_TOKEN_LENGTH = 32 * 1_024;

const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_BACKUP_ELIGIBLE = 0x08;
const FLAG_BACKUP_STATE = 0x10;
const FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;
const FLAG_EXTENSION_DATA = 0x80;

const REQUEST_OPTION_KEYS = new Set([
  'allowCredentials', 'challenge', 'errorMessage', 'extensions', 'rpId', 'status', 'timeout',
  'userVerification',
]);
const CREDENTIAL_DESCRIPTOR_KEYS = new Set(['id', 'transports', 'type']);
const REQUEST_EXTENSION_KEYS = new Set(['appid', 'uvm']);
const ASSERTION_KEYS = new Set([
  'authenticatorAttachment', 'clientExtensionResults', 'getClientExtensionResults', 'id', 'rawId',
  'response', 'toJSON', 'type',
]);
const ASSERTION_RESPONSE_KEYS = new Set([
  'authenticatorData', 'clientDataJSON', 'signature', 'userHandle',
]);
const CLIENT_DATA_KEYS = new Set(['challenge', 'crossOrigin', 'origin', 'tokenBinding', 'type']);
const TOKEN_BINDING_KEYS = new Set(['id', 'status']);
const CLIENT_EXTENSION_RESULT_KEYS = new Set(['appid', 'uvm']);
const ASSERTION_TOKEN_KEYS = new Set(['extensions', 'id', 'rawId', 'response', 'type']);
const ASSERTION_TOKEN_RESPONSE_KEYS = new Set([
  'authenticatorData', 'clientDataJson', 'signature', 'userHandle',
]);
const AUTHENTICATOR_TRANSPORTS = new Set<AuthenticatorTransport>([
  'ble', 'hybrid', 'internal', 'nfc', 'usb',
]);
const USER_VERIFICATION_REQUIREMENTS = new Set<UserVerificationRequirement>([
  'discouraged', 'preferred', 'required',
]);

export interface Fido2TwoFactorRelyingParty {
  /** Exact Web Vault/server origin on which navigator.credentials.get will run. */
  origin: string;
  /** Expected WebAuthn RP ID. It must be valid for origin and match provider metadata. */
  rpId: string;
}

export interface Fido2TwoFactorRequest {
  readonly origin: string;
  readonly rpId: string;
  /** Canonical unpadded base64url challenge retained for assertion binding. */
  readonly challenge: string;
  /** Canonical JSON expected by the official V1 webauthn connector's data parameter. */
  readonly connectorData: string;
  /** Pass this object directly to navigator.credentials.get. */
  readonly navigatorRequest: Readonly<{ publicKey: PublicKeyCredentialRequestOptions }>;
}

interface RequestBinding {
  readonly origin: string;
  readonly rpId: string;
  readonly challenge: string;
  readonly allowedCredentialIds: ReadonlySet<string>;
  readonly userVerification?: UserVerificationRequirement;
  readonly appid?: string;
  readonly requestsUvm: boolean;
  consumed: boolean;
}

interface ParsedRequestExtensions {
  readonly browserValue?: AuthenticationExtensionsClientInputs;
  readonly connectorValue?: Readonly<Record<string, unknown>>;
  readonly appid?: string;
  readonly requestsUvm: boolean;
}

interface ParsedClientExtensionResults {
  readonly wireValue: Record<string, unknown>;
  readonly appidUsed: boolean;
}

const requestBindings = new WeakMap<Fido2TwoFactorRequest, RequestBinding>();
const validatedDeviceSubmissions = new WeakSet<ValidatedFido2TwoFactorSubmission>();

/** Runtime-only proof that one provider 7 assertion passed this module's one-shot validator. */
export interface ValidatedFido2TwoFactorSubmission {
  readonly token: string;
  readonly remember: boolean;
  readonly origin: string;
}

interface ParsedAllowCredentials {
  readonly values: PublicKeyCredentialDescriptor[];
  readonly connectorValues: ReadonlyArray<Readonly<Record<string, unknown>>>;
  readonly ids: ReadonlySet<string>;
}

/** Parse and bind provider 7 metadata from a token error, provider map, or direct provider value. */
export function parseFido2TwoFactorRequest(
  metadata: unknown,
  expected: Fido2TwoFactorRelyingParty,
): Fido2TwoFactorRequest {
  const relyingParty = parseExpectedRelyingParty(expected);
  const options = extractProviderOptions(metadata);
  assertKnownKeys(options, REQUEST_OPTION_KEYS, 'request options');
  if (options.status !== undefined && options.status !== 'ok') fail('request status is not ok');
  if (options.errorMessage !== undefined && options.errorMessage !== '') fail('request contains an error');

  const challenge = decodeCanonicalBase64Url(
    options.challenge, 'challenge', MIN_CHALLENGE_BYTES, MAX_CHALLENGE_BYTES,
  );
  const rpId = parseRpId(options.rpId, 'request rpId');
  if (rpId !== relyingParty.rpId) fail('request rpId does not match the expected RP ID');
  const descriptors = parseAllowCredentials(options.allowCredentials);
  const timeout = parseOptionalInteger(options.timeout, 'timeout', 1, MAX_TIMEOUT_MS);
  const userVerification = parseUserVerification(options.userVerification);
  const extensions = parseRequestExtensions(options.extensions, relyingParty.origin);

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: toArrayBuffer(challenge.bytes),
    rpId,
    allowCredentials: descriptors.values,
    ...(timeout !== undefined ? { timeout } : {}),
    ...(userVerification !== undefined ? { userVerification } : {}),
    ...(extensions.browserValue !== undefined ? { extensions: extensions.browserValue } : {}),
  };
  Object.freeze(publicKey.allowCredentials);
  if (publicKey.extensions) Object.freeze(publicKey.extensions);
  Object.freeze(publicKey);

  const connectorData = JSON.stringify({
    challenge: challenge.encoded,
    ...(timeout !== undefined ? { timeout } : {}),
    rpId,
    allowCredentials: descriptors.connectorValues,
    ...(userVerification !== undefined ? { userVerification } : {}),
    ...(extensions.connectorValue !== undefined ? { extensions: extensions.connectorValue } : {}),
  });

  const result: Fido2TwoFactorRequest = Object.freeze({
    origin: relyingParty.origin,
    rpId,
    challenge: challenge.encoded,
    connectorData,
    navigatorRequest: Object.freeze({ publicKey }),
  });
  requestBindings.set(result, {
    origin: relyingParty.origin,
    rpId,
    challenge: challenge.encoded,
    allowedCredentialIds: descriptors.ids,
    ...(userVerification !== undefined ? { userVerification } : {}),
    ...(extensions.appid !== undefined ? { appid: extensions.appid } : {}),
    requestsUvm: extensions.requestsUvm,
    consumed: false,
  });
  return result;
}

/** Serialize a credential assertion to the provider 7 two_factor_token JSON contract. */
export async function serializeFido2TwoFactorAssertion(
  assertion: unknown,
  request: Fido2TwoFactorRequest,
): Promise<string> {
  return validateAndSerializeAssertion(assertion, consumeRequestBinding(request));
}

/** Validate and canonicalize the JSON token returned by the official server-origin connector. */
export async function validateFido2TwoFactorAssertionToken(
  token: unknown,
  request: Fido2TwoFactorRequest,
): Promise<string> {
  const binding = consumeRequestBinding(request);
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_ASSERTION_TOKEN_LENGTH) {
    fail('assertion token is missing or too large');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(token);
  } catch {
    fail('assertion token is not valid JSON');
  }
  const wire = requirePlainRecord(parsed, 'assertion token');
  assertKnownKeys(wire, ASSERTION_TOKEN_KEYS, 'assertion token');
  if (!Object.prototype.hasOwnProperty.call(wire, 'extensions')) {
    fail('assertion token is missing extensions');
  }
  const response = requirePlainRecord(wire.response, 'assertion token response');
  assertKnownKeys(response, ASSERTION_TOKEN_RESPONSE_KEYS, 'assertion token response');
  return validateAndSerializeAssertion({
    id: wire.id,
    rawId: wire.rawId,
    type: wire.type,
    clientExtensionResults: wire.extensions,
    response: {
      authenticatorData: response.authenticatorData,
      clientDataJSON: response.clientDataJson,
      signature: response.signature,
      ...(response.userHandle !== undefined ? { userHandle: response.userHandle } : {}),
    },
  }, binding);
}

export async function validateFido2TwoFactorSubmission(
  token: unknown,
  request: Fido2TwoFactorRequest,
  remember: boolean,
): Promise<ValidatedFido2TwoFactorSubmission> {
  if (typeof remember !== 'boolean') fail('assertion remember flag is invalid');
  const submission = Object.freeze({
    token: await validateFido2TwoFactorAssertionToken(token, request),
    remember,
    origin: request.origin,
  });
  validatedDeviceSubmissions.add(submission);
  return submission;
}

/** Consume a validator-issued device-login submission exactly once at the AuthService boundary. */
export function consumeValidatedFido2TwoFactorSubmission(
  submission: ValidatedFido2TwoFactorSubmission,
): ValidatedFido2TwoFactorSubmission {
  if (!validatedDeviceSubmissions.has(submission)) {
    fail('device-login assertion was not issued by this validator or was already consumed');
  }
  validatedDeviceSubmissions.delete(submission);
  return submission;
}

function consumeRequestBinding(request: Fido2TwoFactorRequest): RequestBinding {
  const binding = requestBindings.get(request);
  if (!binding) fail('request binding was not issued by this parser');
  if (binding.consumed) fail('request binding has already been consumed');
  binding.consumed = true;
  return binding;
}

async function validateAndSerializeAssertion(
  assertion: unknown,
  binding: RequestBinding,
): Promise<string> {
  const credential = requireObject(assertion, 'assertion');
  assertKnownKeys(credential, ASSERTION_KEYS, 'assertion');
  if (credential.type !== 'public-key') fail('assertion type must be public-key');
  if (credential.authenticatorAttachment !== undefined
      && credential.authenticatorAttachment !== null
      && credential.authenticatorAttachment !== 'platform'
      && credential.authenticatorAttachment !== 'cross-platform') {
    fail('assertion authenticatorAttachment is invalid');
  }

  const id = decodeCanonicalBase64Url(credential.id, 'credential id', 1, MAX_CREDENTIAL_ID_BYTES);
  const rawId = readBinary(credential.rawId, 'rawId', 1, MAX_CREDENTIAL_ID_BYTES);
  if (id.encoded !== rawId.encoded) fail('credential id and rawId do not match');
  if (!binding.allowedCredentialIds.has(rawId.encoded)) {
    fail('credential is not present in allowCredentials');
  }

  const response = requireObject(credential.response, 'assertion response');
  assertKnownKeys(response, ASSERTION_RESPONSE_KEYS, 'assertion response');
  const authenticatorData = readBinary(
    response.authenticatorData, 'authenticatorData', 37, MAX_AUTHENTICATOR_DATA_BYTES,
  );
  const clientData = readBinary(response.clientDataJSON, 'clientDataJSON', 1, MAX_CLIENT_DATA_BYTES);
  const signature = readBinary(response.signature, 'signature', 1, MAX_SIGNATURE_BYTES);
  const userHandle = response.userHandle === undefined || response.userHandle === null
    ? undefined
    : readBinary(response.userHandle, 'userHandle', 1, MAX_USER_HANDLE_BYTES);

  validateClientData(clientData.bytes, binding);
  const extensionResults = readClientExtensionResults(credential, binding);
  await validateAuthenticatorData(authenticatorData.bytes, binding, extensionResults.appidUsed);
  return JSON.stringify({
    id: id.encoded,
    rawId: rawId.encoded,
    type: 'public-key',
    extensions: extensionResults.wireValue,
    response: {
      authenticatorData: authenticatorData.encoded,
      clientDataJson: clientData.encoded,
      signature: signature.encoded,
      ...(userHandle ? { userHandle: userHandle.encoded } : {}),
    },
  });
}

function extractProviderOptions(metadata: unknown): Record<string, unknown> {
  const root = requirePlainRecord(metadata, 'provider metadata');
  if (Object.prototype.hasOwnProperty.call(root, 'TwoFactorProviders2')) {
    const providers = requirePlainRecord(root.TwoFactorProviders2, 'TwoFactorProviders2');
    if (!Object.prototype.hasOwnProperty.call(providers, '7')) fail('provider 7 metadata is missing');
    return requirePlainRecord(providers['7'], 'provider 7 metadata');
  }
  if (Object.prototype.hasOwnProperty.call(root, '7')) {
    return requirePlainRecord(root['7'], 'provider 7 metadata');
  }
  return root;
}

function parseExpectedRelyingParty(expected: Fido2TwoFactorRelyingParty): {
  origin: string;
  rpId: string;
} {
  const value = requirePlainRecord(expected, 'expected relying party');
  assertKnownKeys(value, new Set(['origin', 'rpId']), 'expected relying party');
  if (typeof value.origin !== 'string' || value.origin.length === 0 || value.origin.length > MAX_ORIGIN_LENGTH) {
    fail('expected origin is invalid');
  }
  let url: URL;
  try {
    url = new URL(value.origin);
  } catch {
    fail('expected origin is invalid');
  }
  const isLoopback = isLoopbackHostname(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback)) {
    fail('expected origin must use HTTPS or HTTP on loopback');
  }
  if (url.username || url.password || url.search || url.hash || (url.pathname !== '' && url.pathname !== '/')) {
    fail('expected origin must not contain credentials, a path, query, or fragment');
  }

  const rpId = parseRpId(value.rpId, 'expected rpId');
  const host = url.hostname.toLowerCase();
  if (!isRpIdValidForHost(rpId, host)) fail('expected rpId is not valid for the expected origin');
  return { origin: url.origin, rpId };
}

function parseAllowCredentials(value: unknown): ParsedAllowCredentials {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_CREDENTIALS) {
    fail(`allowCredentials must contain between 1 and ${MAX_CREDENTIALS} entries`);
  }
  const ids = new Set<string>();
  const connectorValues: Array<Readonly<Record<string, unknown>>> = [];
  const values = value.map((entry, index): PublicKeyCredentialDescriptor => {
    const descriptor = requirePlainRecord(entry, `allowCredentials[${index}]`);
    assertKnownKeys(descriptor, CREDENTIAL_DESCRIPTOR_KEYS, `allowCredentials[${index}]`);
    if (descriptor.type !== 'public-key') fail(`allowCredentials[${index}].type must be public-key`);
    const id = decodeCanonicalBase64Url(
      descriptor.id, `allowCredentials[${index}].id`, 1, MAX_CREDENTIAL_ID_BYTES,
    );
    if (ids.has(id.encoded)) fail('allowCredentials contains a duplicate credential id');
    ids.add(id.encoded);
    const transports = parseTransports(descriptor.transports, index);
    connectorValues.push(Object.freeze({
      type: 'public-key',
      id: id.encoded,
      ...(transports !== undefined ? { transports } : {}),
    }));
    return Object.freeze({
      type: 'public-key',
      id: toArrayBuffer(id.bytes),
      ...(transports !== undefined ? { transports } : {}),
    });
  });
  return { values, connectorValues: Object.freeze(connectorValues), ids };
}

function parseTransports(value: unknown, index: number): AuthenticatorTransport[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > AUTHENTICATOR_TRANSPORTS.size) {
    fail(`allowCredentials[${index}].transports is invalid`);
  }
  const transports: AuthenticatorTransport[] = [];
  for (const transport of value) {
    if (typeof transport !== 'string' || !AUTHENTICATOR_TRANSPORTS.has(transport as AuthenticatorTransport)) {
      fail(`allowCredentials[${index}].transports contains an unsupported transport`);
    }
    if (transports.includes(transport as AuthenticatorTransport)) {
      fail(`allowCredentials[${index}].transports contains a duplicate transport`);
    }
    transports.push(transport as AuthenticatorTransport);
  }
  return Object.freeze(transports) as AuthenticatorTransport[];
}

function parseUserVerification(value: unknown): UserVerificationRequirement | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string'
      || !USER_VERIFICATION_REQUIREMENTS.has(value as UserVerificationRequirement)) {
    fail('userVerification is invalid');
  }
  return value as UserVerificationRequirement;
}

function parseRequestExtensions(value: unknown, expectedOrigin: string): ParsedRequestExtensions {
  if (value === undefined) return { requestsUvm: false };
  const extensions = requirePlainRecord(value, 'request extensions');
  assertKnownKeys(extensions, REQUEST_EXTENSION_KEYS, 'request extensions');
  const browserValue: Record<string, unknown> = {};
  let appid: string | undefined;
  if (extensions.appid !== undefined) {
    appid = parseAppId(extensions.appid, expectedOrigin);
    browserValue.appid = appid;
  }
  let requestsUvm = false;
  if (extensions.uvm !== undefined) {
    if (extensions.uvm !== true) fail('request extensions.uvm must be true');
    requestsUvm = true;
    browserValue.uvm = true;
  }
  return {
    ...(Object.keys(browserValue).length > 0
      ? { browserValue: browserValue as AuthenticationExtensionsClientInputs }
      : {}),
    ...(Object.keys(browserValue).length > 0
      ? { connectorValue: Object.freeze({ ...browserValue }) }
      : {}),
    ...(appid !== undefined ? { appid } : {}),
    requestsUvm,
  };
}

function parseAppId(value: unknown, expectedOrigin: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ORIGIN_LENGTH) {
    fail('request extensions.appid is invalid');
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail('request extensions.appid is invalid');
  }
  if (url.origin !== expectedOrigin
      || url.username
      || url.password
      || url.search
      || url.hash
      || !url.pathname.endsWith('/app-id.json')) {
    fail('request extensions.appid is not bound to the expected origin');
  }
  return url.href;
}

function readClientExtensionResults(
  credential: Record<string, unknown>,
  binding: RequestBinding,
): ParsedClientExtensionResults {
  const hasProperty = Object.prototype.hasOwnProperty.call(credential, 'clientExtensionResults');
  const getResults = credential.getClientExtensionResults;
  if (hasProperty && typeof getResults === 'function') {
    fail('assertion contains ambiguous client extension results');
  }
  let raw: unknown;
  if (hasProperty) {
    raw = credential.clientExtensionResults;
  } else if (typeof getResults === 'function') {
    try {
      raw = getResults.call(credential);
    } catch {
      fail('could not read client extension results');
    }
  } else {
    fail('assertion is missing client extension results');
  }

  const results = requirePlainRecord(raw, 'client extension results');
  assertKnownKeys(results, CLIENT_EXTENSION_RESULT_KEYS, 'client extension results');
  const wireValue: Record<string, unknown> = {};
  let appidUsed = false;
  if (results.appid !== undefined) {
    if (binding.appid === undefined || typeof results.appid !== 'boolean') {
      fail('client extension result appid was not requested or is invalid');
    }
    appidUsed = results.appid;
    wireValue.appid = results.appid;
  }
  if (results.uvm !== undefined) {
    if (!binding.requestsUvm) fail('client extension result uvm was not requested');
    wireValue.uvm = parseUvmResults(results.uvm);
  }
  return { wireValue, appidUsed };
}

function parseUvmResults(value: unknown): number[][] {
  if (!Array.isArray(value) || value.length > MAX_UVM_ENTRIES) {
    fail('client extension result uvm is invalid');
  }
  return value.map((entry, index) => {
    if (!Array.isArray(entry) || entry.length !== 3) {
      fail(`client extension result uvm[${index}] is invalid`);
    }
    return entry.map((part) => {
      if (!Number.isInteger(part) || (part as number) < 0 || (part as number) > 0xffff_ffff) {
        fail(`client extension result uvm[${index}] is invalid`);
      }
      return part as number;
    });
  });
}

function validateClientData(
  bytes: Uint8Array,
  binding: RequestBinding,
): void {
  let decoded: string;
  try {
    decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('clientDataJSON is not valid UTF-8');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded);
  } catch {
    fail('clientDataJSON is not valid JSON');
  }
  const clientData = requirePlainRecord(parsed, 'clientDataJSON');
  assertKnownKeys(clientData, CLIENT_DATA_KEYS, 'clientDataJSON');
  if (clientData.type !== 'webauthn.get') fail('clientDataJSON type is invalid');
  if (clientData.challenge !== binding.challenge) fail('clientDataJSON challenge does not match the request');
  if (clientData.origin !== binding.origin) fail('clientDataJSON origin does not match the request');
  if (clientData.crossOrigin !== undefined && clientData.crossOrigin !== false) {
    fail('cross-origin WebAuthn assertions are not accepted');
  }
  validateTokenBinding(clientData.tokenBinding);
}

function validateTokenBinding(value: unknown): void {
  if (value === undefined) return;
  const tokenBinding = requirePlainRecord(value, 'clientDataJSON tokenBinding');
  assertKnownKeys(tokenBinding, TOKEN_BINDING_KEYS, 'clientDataJSON tokenBinding');
  if (tokenBinding.status !== 'supported' && tokenBinding.status !== 'present') {
    fail('clientDataJSON tokenBinding status is invalid');
  }
  if (tokenBinding.status === 'present') {
    if (typeof tokenBinding.id !== 'string' || tokenBinding.id.length === 0 || tokenBinding.id.length > 1_024) {
      fail('clientDataJSON tokenBinding id is invalid');
    }
  } else if (tokenBinding.id !== undefined) {
    fail('clientDataJSON tokenBinding id is invalid');
  }
}

async function validateAuthenticatorData(
  bytes: Uint8Array,
  binding: RequestBinding,
  appidUsed: boolean,
): Promise<void> {
  const flags = bytes[32]!;
  if ((flags & FLAG_USER_PRESENT) === 0) fail('authenticatorData does not assert user presence');
  if ((flags & FLAG_ATTESTED_CREDENTIAL_DATA) !== 0) {
    fail('authenticatorData unexpectedly contains attested credential data');
  }
  if ((flags & FLAG_BACKUP_STATE) !== 0 && (flags & FLAG_BACKUP_ELIGIBLE) === 0) {
    fail('authenticatorData contains inconsistent backup flags');
  }
  if (binding.userVerification === 'required' && (flags & FLAG_USER_VERIFIED) === 0) {
    fail('authenticatorData does not assert required user verification');
  }
  if ((flags & FLAG_EXTENSION_DATA) === 0 && bytes.length !== 37) {
    fail('authenticatorData contains trailing data without the extension flag');
  }
  if ((flags & FLAG_EXTENSION_DATA) !== 0 && bytes.length === 37) {
    fail('authenticatorData extension flag has no extension data');
  }

  const rpIdInput = appidUsed ? binding.appid : binding.rpId;
  if (!rpIdInput) fail('authenticatorData selected an unavailable appid');
  const expectedHash = new Uint8Array(
    await globalThis.crypto.subtle.digest('SHA-256', utf8ToBytes(rpIdInput) as BufferSource),
  );
  if (!constantTimePrefixEqual(bytes, expectedHash)) {
    fail('authenticatorData RP ID hash does not match the request');
  }
}

function parseRpId(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_RP_ID_LENGTH) {
    fail(`${label} is invalid`);
  }
  const normalized = value.toLowerCase();
  if (normalized.endsWith('.') || normalized.includes('/') || normalized.includes(':')) {
    fail(`${label} is invalid`);
  }
  let parsedHost: string;
  try {
    const url = new URL(`https://${normalized}`);
    if (url.username || url.password || url.port || url.pathname !== '/') fail(`${label} is invalid`);
    parsedHost = url.hostname.toLowerCase();
  } catch {
    fail(`${label} is invalid`);
  }
  if (parsedHost !== normalized) fail(`${label} is not canonical`);
  return normalized;
}

function isRpIdValidForHost(rpId: string, host: string): boolean {
  if (rpId === 'localhost') return host === 'localhost';
  if (isLoopbackHostname(host)) return rpId === host;
  if (host !== rpId && !host.endsWith(`.${rpId}`)) return false;
  const rpDomain = getDomain(rpId, { allowPrivateDomains: true });
  const hostDomain = getDomain(host, { allowPrivateDomains: true });
  return Boolean(rpDomain && hostDomain && rpDomain.toLowerCase() === hostDomain.toLowerCase());
}

function isLoopbackHostname(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (host === 'localhost' || host === '[::1]') return true;
  const octets = host.split('.');
  return octets.length === 4
    && octets[0] === '127'
    && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

function readBinary(
  value: unknown,
  label: string,
  minimumBytes: number,
  maximumBytes: number,
): { bytes: Uint8Array; encoded: string } {
  if (typeof value === 'string') {
    return decodeCanonicalBase64Url(value, label, minimumBytes, maximumBytes);
  }
  let bytes: Uint8Array;
  if (value instanceof ArrayBuffer) {
    bytes = new Uint8Array(value.slice(0));
  } else if (ArrayBuffer.isView(value)) {
    bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
  } else {
    fail(`${label} must be a BufferSource or canonical base64url string`);
  }
  assertByteLength(bytes, label, minimumBytes, maximumBytes);
  return { bytes, encoded: bytesToBase64Url(bytes) };
}

function decodeCanonicalBase64Url(
  value: unknown,
  label: string,
  minimumBytes: number,
  maximumBytes: number,
): { bytes: Uint8Array; encoded: string } {
  if (typeof value !== 'string'
      || value.length === 0
      || value.length > Math.ceil(maximumBytes * 4 / 3) + 2
      || !/^[A-Za-z0-9_-]+$/.test(value)
      || value.length % 4 === 1) {
    fail(`${label} is not canonical base64url`);
  }
  let bytes: Uint8Array;
  try {
    bytes = base64UrlToBytes(value);
  } catch {
    fail(`${label} is not canonical base64url`);
  }
  assertByteLength(bytes, label, minimumBytes, maximumBytes);
  if (bytesToBase64Url(bytes) !== value) fail(`${label} is not canonical base64url`);
  return { bytes, encoded: value };
}

function assertByteLength(bytes: Uint8Array, label: string, minimum: number, maximum: number): void {
  if (bytes.byteLength < minimum || bytes.byteLength > maximum) {
    fail(`${label} byte length must be between ${minimum} and ${maximum}`);
  }
}

function parseOptionalInteger(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number,
): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    fail(`${label} must be an integer from ${minimum} to ${maximum}`);
  }
  return value as number;
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function requirePlainRecord(value: unknown, label: string): Record<string, unknown> {
  const record = requireObject(value, label);
  const prototype = Object.getPrototypeOf(record) as unknown;
  if (prototype !== Object.prototype && prototype !== null) fail(`${label} must be a plain object`);
  return record;
}

function assertKnownKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>, label: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(`${label} contains unsupported field: ${key}`);
  }
}

function constantTimePrefixEqual(value: Uint8Array, expected: Uint8Array): boolean {
  if (value.length < expected.length) return false;
  let difference = 0;
  for (let index = 0; index < expected.length; index++) {
    difference |= value[index]! ^ expected[index]!;
  }
  return difference === 0;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function fail(message: string): never {
  throw new Error(`Invalid FIDO2 two-factor data: ${message}`);
}
