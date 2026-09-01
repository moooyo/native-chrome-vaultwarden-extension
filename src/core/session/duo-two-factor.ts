import {
  base64UrlToBytes,
  bytesToUtf8,
  constantTimeEqual,
  utf8ToBytes,
} from '../crypto/encoding.js';
import {
  canonicalizeServerCapabilityUrl,
  normalizeServerEnvironmentUrl,
} from '../api/server-capabilities.js';
import { normalizeSsoEmail } from './sso-login.js';

export type DuoTwoFactorProvider = 2 | 6;
export type DuoTwoFactorFlow = 'password' | 'deviceLogin';

export interface DuoChallengeOwner {
  readonly flow: DuoTwoFactorFlow;
  readonly generation: number;
  readonly serverUrl: string;
  readonly email: string;
  readonly provider: DuoTwoFactorProvider;
  readonly bindingId: string;
}

export interface DuoAuthorization {
  readonly provider: DuoTwoFactorProvider;
  readonly authUrl: string;
  readonly duoHost: string;
  readonly redirectUri: string;
  readonly state: string;
}

export interface DuoProviderSeed {
  readonly provider: DuoTwoFactorProvider;
  readonly authUrl: string;
  readonly host?: string;
}

export interface DuoCallbackResult {
  readonly code: string;
  readonly state: string;
  readonly token: string;
  readonly scrubbedUrl: string;
}

const MAX_URL_LENGTH = 16 * 1024;
const MAX_TOKEN_PART_LENGTH = 16 * 1024;

export function createDuoChallengeOwner(input: DuoChallengeOwner): DuoChallengeOwner {
  const record = plainRecord(input, 'Duo challenge owner');
  const expected = ['flow', 'generation', 'serverUrl', 'email', 'provider', 'bindingId'];
  if (Object.keys(record).length !== expected.length
      || Object.keys(record).some((key) => !expected.includes(key))) {
    throw new TypeError('Duo challenge owner is invalid');
  }
  if (input.flow !== 'password' && input.flow !== 'deviceLogin') {
    throw new TypeError('Duo challenge flow is invalid');
  }
  if (!Number.isSafeInteger(input.generation) || input.generation <= 0) {
    throw new TypeError('Duo challenge generation is invalid');
  }
  if (input.provider !== 2 && input.provider !== 6) throw new TypeError('Duo provider is invalid');
  const bindingId = boundedTokenPart(input.bindingId, 'Duo binding id');
  return Object.freeze({
    flow: input.flow,
    generation: input.generation,
    serverUrl: canonicalizeServerCapabilityUrl(input.serverUrl),
    email: normalizeSsoEmail(input.email),
    provider: input.provider,
    bindingId,
  });
}

export function sameDuoChallengeOwner(left: DuoChallengeOwner, right: DuoChallengeOwner): boolean {
  const a = createDuoChallengeOwner(left);
  const b = createDuoChallengeOwner(right);
  return a.flow === b.flow && a.generation === b.generation
    && a.serverUrl === b.serverUrl && a.email === b.email
    && a.provider === b.provider && a.bindingId === b.bindingId;
}

/** Parse only the modern Duo Universal Prompt metadata emitted for providers 2 and 6. */
export function parseDuoAuthorization(
  providerMetadata: unknown,
  provider: number,
  trustedWebVaultUrl: string,
): DuoAuthorization {
  const seed = extractDuoProviderSeed(providerMetadata, provider);
  const authUrlValue = seed.authUrl;
  const hostValue = seed.host;
  const authUrl = boundedUrl(authUrlValue, 'Duo AuthUrl');
  const duoHost = parseDuoHost(authUrl.hostname);
  if (hostValue !== undefined && parseDuoHost(hostValue) !== duoHost) {
    throw new TypeError('Duo Host does not match AuthUrl');
  }
  if (
    authUrl.protocol !== 'https:'
    || authUrl.hostname !== duoHost
    || authUrl.port
    || authUrl.pathname !== '/oauth/v1/authorize'
    || authUrl.hash
  ) throw new TypeError('Duo AuthUrl is invalid');
  assertUniqueParameters(authUrl);
  if (authUrl.searchParams.get('response_type') !== 'code') {
    throw new TypeError('Duo response type is invalid');
  }
  const clientId = boundedTokenPart(authUrl.searchParams.get('client_id'), 'Duo client id');
  const expectedRedirect = duoConnectorUrl(trustedWebVaultUrl);
  const requestJwt = authUrl.searchParams.get('request');
  let state: string;
  let redirectUri: string | null;
  if (requestJwt !== null) {
    const claims = parseDuoRequestClaims(requestJwt, duoHost, clientId);
    state = claims.state;
    redirectUri = claims.redirectUri;
  } else {
    state = boundedTokenPart(authUrl.searchParams.get('state'), 'Duo state');
    redirectUri = authUrl.searchParams.get('redirect_uri');
  }
  if (redirectUri !== expectedRedirect) throw new TypeError('Duo redirect URI is invalid');
  return Object.freeze({
    provider: seed.provider,
    authUrl: authUrl.toString(),
    duoHost,
    redirectUri: expectedRedirect,
    state,
  });
}

/** Extract the bounded modern metadata for durable auth continuation storage. */
export function extractDuoProviderSeed(
  providerMetadata: unknown,
  provider: number,
): DuoProviderSeed {
  if (provider !== 2 && provider !== 6) throw new TypeError('Duo provider is invalid');
  const providers = plainRecord(providerMetadata, 'two-factor provider metadata');
  const data = plainRecord(own(providers, String(provider)), 'Duo provider metadata');
  const authUrl = boundedUrl(
    aliasedString(data, 'AuthUrl', 'authUrl', 'Duo AuthUrl'),
    'Duo AuthUrl',
  ).toString();
  const host = optionalAliasedString(data, 'Host', 'host', 'Duo Host');
  if (Object.hasOwn(data, 'Signature') || Object.hasOwn(data, 'signature')) {
    throw new TypeError('Legacy Duo Signature metadata is unsupported');
  }
  return Object.freeze({ provider, authUrl, ...(host === undefined ? {} : { host }) });
}

export function duoProviderMetadata(seed: DuoProviderSeed): Readonly<Record<string, unknown>> {
  if (seed.provider !== 2 && seed.provider !== 6) throw new TypeError('Duo provider is invalid');
  return Object.freeze({
    [seed.provider]: Object.freeze({
      AuthUrl: boundedUrl(seed.authUrl, 'Duo AuthUrl').toString(),
      ...(seed.host === undefined ? {} : { Host: seed.host }),
    }),
  });
}

/** Validate one exact Duo connector callback and compose the server token as code|state. */
export function parseDuoCallback(
  callbackUrl: unknown,
  authorization: Pick<DuoAuthorization, 'redirectUri' | 'state'>,
): DuoCallbackResult {
  const redirect = boundedUrl(authorization.redirectUri, 'Duo redirect URI');
  const callback = boundedUrl(callbackUrl, 'Duo callback URL');
  if (callback.origin !== redirect.origin || callback.pathname !== redirect.pathname || callback.hash) {
    throw new TypeError('Duo callback does not match the connector');
  }
  assertUniqueParameters(callback);
  const base = [...redirect.searchParams.entries()];
  const allowed = new Set([...base.map(([name]) => name), 'code', 'state']);
  const entries = [...callback.searchParams.entries()];
  if (
    entries.length !== base.length + 2
    || entries.some(([name]) => !allowed.has(name))
    || callback.searchParams.getAll('code').length !== 1
    || callback.searchParams.getAll('state').length !== 1
    || base.some(([name, value]) => (
      callback.searchParams.getAll(name).length !== 1
      || callback.searchParams.get(name) !== value
    ))
  ) throw new TypeError('Duo callback parameters are invalid');
  const code = boundedTokenPart(callback.searchParams.get('code'), 'Duo authorization code');
  const state = boundedTokenPart(callback.searchParams.get('state'), 'Duo callback state');
  if (!constantTimeStringEqual(state, boundedTokenPart(authorization.state, 'Duo state'))) {
    throw new TypeError('Duo callback state does not match');
  }
  return Object.freeze({
    code,
    state,
    token: `${code}|${state}`,
    scrubbedUrl: redirect.toString(),
  });
}

export function duoConnectorUrl(trustedWebVaultUrl: string): string {
  const base = normalizeServerEnvironmentUrl(trustedWebVaultUrl);
  if (!base) throw new TypeError('Trusted Web Vault URL is invalid');
  const connector = new URL('duo-redirect-connector.html', base);
  connector.searchParams.set('client', 'browser');
  return connector.toString();
}

function parseDuoHost(input: string): string {
  if (
    input !== input.toLowerCase()
    || input.length > 253
    || !input.startsWith('api-')
    || (!input.endsWith('.duosecurity.com') && !input.endsWith('.duofederal.com'))
    || !/^[a-z0-9.-]+$/u.test(input)
    || input.includes('..')
  ) throw new TypeError('Duo Host is invalid');
  return input;
}

function boundedUrl(input: unknown, name: string): URL {
  if (
    typeof input !== 'string'
    || input.length === 0
    || input.length > MAX_URL_LENGTH
    || input.trim() !== input
    || hasControl(input)
  ) throw new TypeError(`${name} is invalid`);
  let parsed: URL;
  try { parsed = new URL(input); } catch { throw new TypeError(`${name} is invalid`); }
  if (parsed.username || parsed.password || parsed.toString() !== input) {
    throw new TypeError(`${name} is invalid`);
  }
  return parsed;
}

function boundedTokenPart(input: unknown, name: string): string {
  if (
    typeof input !== 'string'
    || input.length === 0
    || input.length > MAX_TOKEN_PART_LENGTH
    || input.trim() !== input
    || input.includes('|')
    || hasControl(input)
  ) throw new TypeError(`${name} is invalid`);
  return input;
}

function assertUniqueParameters(url: URL): void {
  const names = [...url.searchParams.keys()];
  if (new Set(names).size !== names.length) throw new TypeError('Duo URL has duplicate parameters');
}

function aliasedString(
  record: Record<string, unknown>,
  canonical: string,
  alias: string,
  name: string,
): string {
  const canonicalValue = own(record, canonical);
  const aliasValue = own(record, alias);
  if (canonicalValue !== undefined && aliasValue !== undefined) {
    throw new TypeError(`${name} is duplicated`);
  }
  const value = canonicalValue ?? aliasValue;
  if (typeof value !== 'string') throw new TypeError(`${name} is invalid`);
  return value;
}

function optionalAliasedString(
  record: Record<string, unknown>,
  canonical: string,
  alias: string,
  name: string,
): string | undefined {
  const canonicalValue = own(record, canonical);
  const aliasValue = own(record, alias);
  if (canonicalValue !== undefined && aliasValue !== undefined) {
    throw new TypeError(`${name} is duplicated`);
  }
  const value = canonicalValue ?? aliasValue;
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new TypeError(`${name} is invalid`);
  return value;
}

function parseDuoRequestClaims(
  compactJwt: string,
  duoHost: string,
  clientId: string,
): { readonly state: string; readonly redirectUri: string } {
  if (
    compactJwt.length === 0
    || compactJwt.length > MAX_URL_LENGTH
    || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(compactJwt)
  ) throw new TypeError('Duo request JWT is invalid');
  const payloadSegment = compactJwt.split('.')[1]!;
  let decoded: unknown;
  try {
    decoded = JSON.parse(bytesToUtf8(base64UrlToBytes(payloadSegment))) as unknown;
  } catch {
    throw new TypeError('Duo request JWT payload is invalid');
  }
  const claims = plainRecord(decoded, 'Duo request JWT payload');
  const audience = own(claims, 'aud');
  const duoOrigin = `https://${duoHost}`;
  if (
    own(claims, 'response_type') !== 'code'
    || own(claims, 'client_id') !== clientId
    || own(claims, 'iss') !== clientId
    || (audience !== duoOrigin && audience !== `${duoOrigin}/oauth/v1/authorize`)
    || !validDuoExpiration(own(claims, 'exp'))
  ) throw new TypeError('Duo request JWT claims are invalid');
  return Object.freeze({
    state: boundedTokenPart(own(claims, 'state'), 'Duo state'),
    redirectUri: boundedUrl(own(claims, 'redirect_uri'), 'Duo redirect URI').toString(),
  });
}

function validDuoExpiration(value: unknown): boolean {
  if (typeof value === 'number') return Number.isSafeInteger(value) && value > 0;
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,15}$/u.test(value)) return false;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && String(parsed) === value;
}

function plainRecord(input: unknown, name: string): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new TypeError(`${name} is invalid`);
  }
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${name} is invalid`);
  }
  for (const key of Reflect.ownKeys(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (typeof key !== 'string' || !descriptor?.enumerable || !('value' in descriptor)) {
      throw new TypeError(`${name} is invalid`);
    }
  }
  return input as Record<string, unknown>;
}

function own(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
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

function hasControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}
