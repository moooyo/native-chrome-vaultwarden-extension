import {
  base64UrlToBytes,
  bytesToBase64Url,
  constantTimeEqual,
  utf8ToBytes,
} from '../crypto/encoding.js';
import { normalizeServerEnvironmentUrl } from '../api/server-capabilities.js';

export const SSO_BROWSER_STATE_SUFFIX = ':clientId=browser';
export const SSO_PKCE_RANDOM_BYTES = 32;
export const SSO_STATE_RANDOM_BYTES = 32;

const MAX_EMAIL_LENGTH = 254;
const MAX_LOCAL_PART_LENGTH = 64;
const MAX_URL_LENGTH = 16 * 1024;
const MAX_AUTHORIZATION_CODE_LENGTH = 16 * 1024;
const PKCE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]+$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const AUTHORIZATION_CODE_PATTERN = /^[A-Za-z0-9._~-]+$/u;
const LOCAL_PART_PATTERN = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/u;
const DOMAIN_LABEL_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u;

export type SsoRandomBytes = (length: number) => Uint8Array;

export type SsoLoginPublicStatus =
  | { readonly status: 'none' }
  | {
      readonly status: 'waiting' | 'processing';
      readonly attemptId: string;
      readonly generation: number;
      readonly email: string;
      readonly expiresAt: number;
    }
  | {
      readonly status: 'outcome_unknown';
      readonly attemptId: string;
      readonly generation: number;
      readonly email: string;
      readonly createdAt: number;
      readonly expiresAt: number;
      readonly terminalAt: number;
    }
  | { readonly status: 'error'; readonly message: string };

export interface BuildSsoLoginUrlsInput {
  readonly vaultUrl: string;
  readonly identityUrl: string;
  /** Hosted environments advertise this service; Vaultwarden may legitimately omit it. */
  readonly ssoUrl?: string;
  readonly email: string;
  readonly state: string;
  readonly codeChallenge: string;
  readonly organizationIdentifier?: string;
}

export interface SsoLoginUrls {
  readonly vaultUrl: string;
  readonly identityUrl: string;
  readonly ssoUrl?: string;
  readonly startUrl: string;
  readonly connectorCallbackUrl: string;
  readonly connectorOrigin: string;
  readonly connectorPath: string;
  readonly identityTokenUrl: string;
}

export interface SsoCallbackBinding {
  readonly redirectUri: string;
  readonly state: string;
}

export interface ParsedSsoCallback {
  readonly code: string;
  readonly state: string;
  readonly scope?: 'api offline_access';
  readonly iss?: string;
  readonly organizationIdentifier?: string;
  readonly scrubbedUrl: string;
}

/** Normalize the account identity used to bind an SSO attempt. */
export function normalizeSsoEmail(input: unknown): string {
  if (typeof input !== 'string') throw new TypeError('SSO email must be a string');
  const email = input.trim().toLowerCase();
  if (
    email.length < 3
    || email.length > MAX_EMAIL_LENGTH
    || containsAsciiControl(email)
    || /\s/u.test(email)
  ) throw new TypeError('SSO email is invalid');

  const separator = email.indexOf('@');
  if (separator <= 0 || separator !== email.lastIndexOf('@')) {
    throw new TypeError('SSO email is invalid');
  }
  const local = email.slice(0, separator);
  const domain = email.slice(separator + 1);
  if (
    local.length > MAX_LOCAL_PART_LENGTH
    || local.startsWith('.')
    || local.endsWith('.')
    || local.includes('..')
    || !LOCAL_PART_PATTERN.test(local)
    || domain.length === 0
    || domain.length > 253
    || domain.includes('..')
  ) throw new TypeError('SSO email is invalid');

  const labels = domain.split('.');
  if (labels.some((label) => label.length > 63 || !DOMAIN_LABEL_PATTERN.test(label))) {
    throw new TypeError('SSO email is invalid');
  }
  return email;
}

/** Generate a 256-bit RFC 7636 verifier in canonical base64url form. */
export function generateSsoPkceVerifier(
  randomBytes: SsoRandomBytes = secureRandomBytes,
): string {
  return parseSsoPkceVerifier(randomBase64Url(SSO_PKCE_RANDOM_BYTES, randomBytes, 'PKCE'));
}

/** Validate an RFC 7636 verifier without silently trimming or rewriting it. */
export function parseSsoPkceVerifier(input: unknown): string {
  if (
    typeof input !== 'string'
    || input.length < 43
    || input.length > 128
    || !PKCE_VERIFIER_PATTERN.test(input)
    || containsAsciiControl(input)
  ) throw new TypeError('SSO PKCE verifier is invalid');
  return input;
}

/** Derive the RFC 7636 S256 challenge for a validated verifier. */
export async function deriveSsoPkceS256Challenge(verifier: unknown): Promise<string> {
  const parsed = parseSsoPkceVerifier(verifier);
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest(
    'SHA-256',
    utf8ToBytes(parsed) as BufferSource,
  ));
  try {
    return bytesToBase64Url(digest);
  } finally {
    digest.fill(0);
  }
}

/** Generate the browser-marked state expected by the standard web-vault connector. */
export function generateSsoState(
  randomBytes: SsoRandomBytes = secureRandomBytes,
): string {
  return parseSsoState(
    `${randomBase64Url(SSO_STATE_RANDOM_BYTES, randomBytes, 'state')}${SSO_BROWSER_STATE_SUFFIX}`,
  );
}

/** Validate the exact state shape emitted by generateSsoState. */
export function parseSsoState(input: unknown): string {
  if (typeof input !== 'string' || !input.endsWith(SSO_BROWSER_STATE_SUFFIX)) {
    throw new TypeError('SSO state is invalid');
  }
  const random = input.slice(0, -SSO_BROWSER_STATE_SUFFIX.length);
  assertCanonicalBase64Url(random, SSO_STATE_RANDOM_BYTES, 'SSO state');
  return input;
}

/** Build the standard browser SSO entry, connector callback, and fixed Identity token URL. */
export function buildSsoLoginUrls(input: BuildSsoLoginUrlsInput): SsoLoginUrls {
  const record = requireExactRecord(input, [
    'vaultUrl', 'identityUrl', 'email', 'state', 'codeChallenge',
    ...(Object.hasOwn(input, 'ssoUrl') ? ['ssoUrl'] : []),
    ...(Object.hasOwn(input, 'organizationIdentifier') ? ['organizationIdentifier'] : []),
  ], 'SSO URL input');
  const vaultUrl = canonicalServiceBase(record.vaultUrl, 'vaultUrl');
  const identityUrl = canonicalServiceBase(record.identityUrl, 'identityUrl');
  const ssoUrl = record.ssoUrl === undefined
    ? undefined
    : canonicalServiceBase(record.ssoUrl, 'ssoUrl');
  const email = normalizeSsoEmail(record.email);
  const state = parseSsoState(record.state);
  const codeChallenge = parseSsoCodeChallenge(record.codeChallenge);
  const organizationIdentifier = record.organizationIdentifier === undefined
    ? undefined
    : parseOrganizationIdentifier(record.organizationIdentifier);

  const connectorCallback = new URL('sso-connector.html', vaultUrl);
  const identityToken = new URL('connect/token', identityUrl);
  const start = new URL(vaultUrl);
  const parameters = [
    ['clientId', 'browser'],
    ['redirectUri', connectorCallback.toString()],
    ['state', state],
    ['codeChallenge', codeChallenge],
    ['email', email],
    ...(organizationIdentifier ? [['identifier', organizationIdentifier] as const] : []),
  ] as const;
  start.hash = `/sso?${parameters.map(([name, value]) => (
    `${name}=${encodeURIComponent(value)}`
  )).join('&')}`;

  return Object.freeze({
    vaultUrl,
    identityUrl,
    ...(ssoUrl === undefined ? {} : { ssoUrl }),
    startUrl: start.toString(),
    connectorCallbackUrl: connectorCallback.toString(),
    connectorOrigin: connectorCallback.origin,
    connectorPath: connectorCallback.pathname,
    identityTokenUrl: identityToken.toString(),
  });
}

/** Parse only an exact connector callback carrying one code and the expected state. */
export function parseSsoCallbackUrl(
  callbackUrl: unknown,
  bindingInput: SsoCallbackBinding,
): ParsedSsoCallback {
  const binding = requireExactRecord(bindingInput, ['redirectUri', 'state'], 'SSO callback binding');
  const redirectUri = parseRedirectUri(binding.redirectUri);
  const expectedState = parseSsoState(binding.state);
  const callback = parseBoundedUrl(callbackUrl, 'SSO callback URL');
  if (/%5fidentifier/iu.test(callback.toString())) {
    throw new TypeError('SSO callback state delimiter is not canonical');
  }
  if (callback.hash) throw new TypeError('SSO callback URL must not contain a fragment');
  const scrubbedUrl = scrubParsedCallback(callback, redirectUri);
  const entries = [...callback.searchParams.entries()];
  const allowedNames = new Set(['code', 'state', 'scope', 'iss']);
  if (
    entries.length < 2
    || entries.length > 4
    || entries.some(([name]) => !allowedNames.has(name))
    || entries.filter(([name]) => name === 'code').length !== 1
    || entries.filter(([name]) => name === 'state').length !== 1
    || entries.filter(([name]) => name === 'scope').length > 1
    || entries.filter(([name]) => name === 'iss').length > 1
  ) throw new TypeError('SSO callback URL must contain exactly one code and state');

  const code = parseSsoAuthorizationCode(callback.searchParams.get('code'));
  const returnedState = parseReturnedSsoState(callback.searchParams.get('state'));
  if (!constantTimeStringEqual(returnedState.baseState, expectedState)) {
    throw new TypeError('SSO callback state does not match');
  }
  const scopeValue = callback.searchParams.get('scope');
  if (scopeValue !== null && scopeValue !== 'api offline_access') {
    throw new TypeError('SSO callback scope is invalid');
  }
  const issuerValue = callback.searchParams.get('iss');
  const iss = issuerValue === null ? undefined : parseSsoIssuer(issuerValue);
  return Object.freeze({
    code,
    state: returnedState.baseState,
    ...(scopeValue === null ? {} : { scope: 'api offline_access' as const }),
    ...(iss === undefined ? {} : { iss }),
    ...(returnedState.organizationIdentifier === undefined
      ? {}
      : { organizationIdentifier: returnedState.organizationIdentifier }),
    scrubbedUrl,
  });
}

function parseReturnedSsoState(input: unknown): {
  readonly baseState: string;
  readonly organizationIdentifier?: string;
} {
  if (typeof input !== 'string') throw new TypeError('SSO callback state is invalid');
  const delimiter = '_identifier=';
  const first = input.indexOf(delimiter);
  if (first < 0) return Object.freeze({ baseState: parseSsoState(input) });
  if (input.indexOf(delimiter, first + delimiter.length) >= 0) {
    throw new TypeError('SSO callback state contains duplicate identifiers');
  }
  const baseState = parseSsoState(input.slice(0, first));
  const organizationIdentifier = input.slice(first + delimiter.length);
  if (
    organizationIdentifier.length === 0
    || organizationIdentifier.length > 256
    || !/^[A-Za-z0-9._~-]+$/u.test(organizationIdentifier)
    || containsAsciiControl(organizationIdentifier)
  ) throw new TypeError('SSO callback organization identifier is invalid');
  return Object.freeze({ baseState, organizationIdentifier });
}

function parseOrganizationIdentifier(input: unknown): string {
  if (
    typeof input !== 'string'
    || input.length === 0
    || input.length > 256
    || !/^[A-Za-z0-9._~-]+$/u.test(input)
    || containsAsciiControl(input)
  ) throw new TypeError('SSO organization identifier is invalid');
  return input;
}

function constantTimeStringEqual(left: string, right: string): boolean {
  const leftBytes = utf8ToBytes(left);
  const rightBytes = utf8ToBytes(right);
  try {
    return leftBytes.byteLength === rightBytes.byteLength
      && constantTimeEqual(leftBytes, rightBytes);
  } finally {
    leftBytes.fill(0);
    rightBytes.fill(0);
  }
}

/** Remove callback secrets only when the URL belongs to the exact registered connector. */
export function scrubSsoCallbackUrl(callbackUrl: unknown, redirectUriInput: unknown): string {
  const redirectUri = parseRedirectUri(redirectUriInput);
  return scrubParsedCallback(parseBoundedUrl(callbackUrl, 'SSO callback URL'), redirectUri);
}

export function parseSsoAuthorizationCode(input: unknown): string {
  if (
    typeof input !== 'string'
    || input.length === 0
    || input.length > MAX_AUTHORIZATION_CODE_LENGTH
    || !AUTHORIZATION_CODE_PATTERN.test(input)
    || containsAsciiControl(input)
  ) throw new TypeError('SSO authorization code is invalid');
  return input;
}

function parseSsoCodeChallenge(input: unknown): string {
  if (typeof input !== 'string') throw new TypeError('SSO PKCE challenge is invalid');
  assertCanonicalBase64Url(input, 32, 'SSO PKCE challenge');
  return input;
}

function parseSsoIssuer(input: unknown): string {
  if (typeof input !== 'string' || input.includes('\\')) {
    throw new TypeError('SSO callback issuer is invalid');
  }
  const issuer = parseBoundedUrl(input, 'SSO callback issuer');
  if (issuer.search || issuer.hash) {
    throw new TypeError('SSO callback issuer is invalid');
  }
  return issuer.toString();
}

function canonicalServiceBase(input: unknown, name: string): string {
  const normalized = normalizeServerEnvironmentUrl(input);
  if (!normalized) throw new TypeError(`SSO ${name} is invalid`);
  return normalized;
}

function parseRedirectUri(input: unknown): URL {
  const url = parseBoundedUrl(input, 'SSO redirect URI');
  if (
    (url.protocol !== 'https:' && !isLoopbackHttp(url))
    || url.username
    || url.password
    || url.search
    || url.hash
    || !url.pathname.endsWith('/sso-connector.html')
    || url.toString() !== input
  ) throw new TypeError('SSO redirect URI is invalid');
  return url;
}

function parseBoundedUrl(input: unknown, name: string): URL {
  if (
    typeof input !== 'string'
    || input.length === 0
    || input.length > MAX_URL_LENGTH
    || input.trim() !== input
    || containsAsciiControl(input)
  ) throw new TypeError(`${name} is invalid`);
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new TypeError(`${name} is invalid`);
  }
  if (url.protocol !== 'https:' && !isLoopbackHttp(url)) {
    throw new TypeError(`${name} is invalid`);
  }
  if (url.username || url.password || url.origin === 'null') {
    throw new TypeError(`${name} is invalid`);
  }
  return url;
}

function scrubParsedCallback(callback: URL, redirectUri: URL): string {
  const scrubbed = new URL(callback.toString());
  scrubbed.search = '';
  scrubbed.hash = '';
  if (scrubbed.toString() !== redirectUri.toString()) {
    throw new TypeError('SSO callback URL does not match the registered redirect URI');
  }
  return redirectUri.toString();
}

function randomBase64Url(length: number, source: SsoRandomBytes, name: string): string {
  const bytes = source(length);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== length) {
    throw new TypeError(`SSO ${name} random source returned invalid bytes`);
  }
  return bytesToBase64Url(new Uint8Array(bytes));
}

function secureRandomBytes(length: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

function assertCanonicalBase64Url(input: string, byteLength: number, name: string): void {
  if (!input || !BASE64URL_PATTERN.test(input)) throw new TypeError(`${name} is invalid`);
  let bytes: Uint8Array;
  try {
    bytes = base64UrlToBytes(input);
  } catch {
    throw new TypeError(`${name} is invalid`);
  }
  if (bytes.byteLength !== byteLength || bytesToBase64Url(bytes) !== input) {
    throw new TypeError(`${name} is invalid`);
  }
}

function requireExactRecord(
  input: unknown,
  expectedKeys: readonly string[],
  name: string,
): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new TypeError(`${name} is invalid`);
  }
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${name} is invalid`);
  }
  const keys = Reflect.ownKeys(input);
  if (
    keys.length !== expectedKeys.length
    || keys.some((key) => typeof key !== 'string' || !expectedKeys.includes(key))
  ) throw new TypeError(`${name} contains unsupported fields`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) {
      throw new TypeError(`${name} is invalid`);
    }
  }
  return input as Record<string, unknown>;
}

function isLoopbackHttp(url: URL): boolean {
  if (url.protocol !== 'http:') return false;
  const hostname = url.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) return true;
  if (hostname === '[::1]' || hostname === '::1') return true;
  const octets = hostname.split('.');
  return octets.length === 4
    && octets[0] === '127'
    && octets.every((part) => /^\d{1,3}$/u.test(part) && Number(part) <= 255);
}

function containsAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}
