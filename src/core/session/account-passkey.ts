import type {
  AccountPasskeyRequestOptions,
} from '../api/account-passkey.js';
import { bytesToBase64Url, utf8ToBytes } from '../crypto/encoding.js';
import {
  INTERACTIVE_TWO_FACTOR_CONNECTOR_PATH,
  interactiveTwoFactorConnectorUrl,
} from './interactive-two-factor.js';

export const ACCOUNT_PASSKEY_CONNECTOR_PATH = INTERACTIVE_TWO_FACTOR_CONNECTOR_PATH;
export const ACCOUNT_PASSKEY_ATTEMPT_MAX_TTL_MS = 2 * 60 * 1000;

const MAX_DOCUMENT_ID_LENGTH = 512;

export interface AccountPasskeyConnectorContext {
  readonly tabId: number;
  readonly frameId: 0;
  readonly documentId: string;
  readonly url: string;
  readonly origin: string;
}

/** Connector-visible ceremony. The opaque Identity token intentionally stays in background state. */
export interface AccountPasskeyConnectorCeremony {
  readonly attemptId: string;
  readonly options: AccountPasskeyRequestOptions;
  readonly prfSalt: string;
  readonly expiresAt: number;
}

export function accountPasskeyConnectorUrl(serverUrl: string): string {
  return interactiveTwoFactorConnectorUrl(serverUrl);
}

export function parseAccountPasskeyConnectorContext(
  input: unknown,
  serverUrl: string,
): AccountPasskeyConnectorContext {
  if (!isRecord(input) || Object.getOwnPropertySymbols(input).length > 0) {
    throw new Error('Account passkey connector context is invalid');
  }
  const keys = Object.keys(input);
  if (keys.some((key) => !['tabId', 'frameId', 'documentId', 'url', 'origin'].includes(key))) {
    throw new Error('Account passkey connector context contains unsupported fields');
  }
  if (!Number.isSafeInteger(input.tabId) || (input.tabId as number) < 0 || input.frameId !== 0) {
    throw new Error('Account passkey connector must be a top-level tab');
  }
  if (
    typeof input.documentId !== 'string'
    || input.documentId.length === 0
    || input.documentId.length > MAX_DOCUMENT_ID_LENGTH
    || input.documentId.trim() !== input.documentId
    || containsAsciiControl(input.documentId)
  ) {
    throw new Error('Account passkey connector document id is invalid');
  }
  const expectedUrl = accountPasskeyConnectorUrl(serverUrl);
  if (input.url !== expectedUrl) throw new Error('Account passkey connector URL is invalid');
  const parsed = new URL(expectedUrl);
  if (parsed.protocol !== 'https:' && !isLoopbackHttp(parsed)) {
    throw new Error('Account passkey connector requires HTTPS or loopback HTTP');
  }
  if (Object.hasOwn(input, 'origin') && input.origin !== parsed.origin) {
    throw new Error('Account passkey connector origin is invalid');
  }
  return Object.freeze({
    tabId: input.tabId as number,
    frameId: 0,
    documentId: input.documentId,
    url: expectedUrl,
    origin: parsed.origin,
  });
}

export function assertAccountPasskeyRpIdForConnector(
  rpId: string,
  connector: AccountPasskeyConnectorContext,
): void {
  const hostname = new URL(connector.url).hostname.toLowerCase();
  const expected = rpId.toLowerCase();
  if (hostname !== expected && !hostname.endsWith(`.${expected}`)) {
    throw new Error('Account passkey RP ID is not valid for the connector origin');
  }
}

export function sameAccountPasskeyConnector(
  left: AccountPasskeyConnectorContext,
  right: AccountPasskeyConnectorContext,
): boolean {
  return left.tabId === right.tabId
    && left.frameId === right.frameId
    && left.documentId === right.documentId
    && left.url === right.url
    && left.origin === right.origin;
}

/** Official PRF input: SHA-256("passwordless-login"). */
export async function deriveAccountPasskeyPrfSalt(): Promise<string> {
  return bytesToBase64Url(new Uint8Array(
    await crypto.subtle.digest('SHA-256', utf8ToBytes('passwordless-login') as BufferSource),
  ));
}

function isLoopbackHttp(url: URL): boolean {
  if (url.protocol !== 'http:') return false;
  const hostname = url.hostname.toLowerCase();
  return hostname === 'localhost'
    || hostname.endsWith('.localhost')
    || hostname === '[::1]'
    || hostname === '::1'
    || /^127(?:\.\d{1,3}){3}$/u.test(hostname);
}

function containsAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
