import { canonicalizeServerCapabilityUrl } from '../api/server-capabilities.js';
import { bytesToBase64, utf8ToBytes } from '../crypto/encoding.js';

export const INTERACTIVE_TWO_FACTOR_CONNECTOR_PATH = 'webauthn-fallback-connector.html';

const MAX_BINDING_ID_LENGTH = 512;
const MAX_CONNECTOR_DATA_LENGTH = 32 * 1024;
const MAX_DOCUMENT_ID_LENGTH = 512;
const MAX_PARENT_URL_LENGTH = 2_048;

export type InteractiveTwoFactorFlow = 'password' | 'deviceLogin';
export type InteractiveTwoFactorLocale = 'en' | 'zh-CN';

/** Durable ceremony identity. Browser tab and callback bindings are deliberately excluded. */
export interface InteractiveTwoFactorOwner {
  readonly flow: InteractiveTwoFactorFlow;
  readonly generation: number;
  readonly serverUrl: string;
  readonly bindingId: string;
}

/** Canonical server-origin challenge retained by the owning authentication state store. */
export interface InteractiveTwoFactorChallenge {
  readonly owner: InteractiveTwoFactorOwner;
  readonly connectorData: string;
  readonly connectorUrl: string;
}

export interface InteractiveTwoFactorBeginInput {
  readonly owner: InteractiveTwoFactorOwner;
  readonly parentUrl: string;
  readonly locale: InteractiveTwoFactorLocale;
}

export interface InteractiveTwoFactorLaunch {
  readonly owner: InteractiveTwoFactorOwner;
  readonly url: string;
  readonly replace?: InteractiveTwoFactorConnectorCaller;
}

export interface InteractiveTwoFactorLaunchBinding {
  readonly owner: InteractiveTwoFactorOwner;
  readonly url: string;
}

export interface InteractiveTwoFactorTabBinding extends InteractiveTwoFactorLaunchBinding {
  readonly tabId: number;
  /** Browser-owned committed top-level document identity. */
  readonly documentId: string;
}

export interface InteractiveTwoFactorConnectorCaller {
  readonly url: string;
  readonly tabId: number;
  readonly documentId: string;
}

export interface InteractiveTwoFactorSubmission extends InteractiveTwoFactorTabBinding {
  readonly token: string;
  readonly remember: boolean;
}

/** Owner-bound connector lifecycle; durable state remains with the authentication flow. */
export interface InteractiveTwoFactorBroker<Result> {
  readonly begin: (input: InteractiveTwoFactorBeginInput) => Promise<InteractiveTwoFactorLaunch>;
  readonly cancelLaunch: (input: InteractiveTwoFactorLaunchBinding) => Promise<boolean>;
  readonly bindTab: (input: InteractiveTwoFactorTabBinding) => Promise<void>;
  readonly matchCaller: (
    input: InteractiveTwoFactorConnectorCaller,
  ) => InteractiveTwoFactorOwner | undefined;
  readonly complete: (input: InteractiveTwoFactorSubmission) => Promise<Result>;
}

export function interactiveTwoFactorConnectorUrl(serverUrl: string): string {
  return new URL(
    INTERACTIVE_TWO_FACTOR_CONNECTOR_PATH,
    canonicalizeServerCapabilityUrl(serverUrl),
  ).toString();
}

export function createInteractiveTwoFactorOwner(
  input: InteractiveTwoFactorOwner,
): InteractiveTwoFactorOwner {
  if (!isPlainRecord(input) || !hasExactKeys(input, [
    'flow', 'generation', 'serverUrl', 'bindingId',
  ])) throw new TypeError('Interactive two-factor owner is invalid');
  if (input.flow !== 'password' && input.flow !== 'deviceLogin') {
    throw new TypeError('Interactive two-factor flow is invalid');
  }
  if (!Number.isSafeInteger(input.generation) || input.generation <= 0) {
    throw new TypeError('Interactive two-factor generation is invalid');
  }
  if (
    typeof input.bindingId !== 'string'
    || input.bindingId.length === 0
    || input.bindingId.length > MAX_BINDING_ID_LENGTH
    || input.bindingId.trim() !== input.bindingId
    || hasControlCharacters(input.bindingId)
  ) throw new TypeError('Interactive two-factor binding id is invalid');
  return Object.freeze({
    flow: input.flow,
    generation: input.generation,
    serverUrl: canonicalizeServerCapabilityUrl(input.serverUrl),
    bindingId: input.bindingId,
  });
}

export function sameInteractiveTwoFactorOwner(
  left: InteractiveTwoFactorOwner,
  right: InteractiveTwoFactorOwner,
): boolean {
  const first = createInteractiveTwoFactorOwner(left);
  const second = createInteractiveTwoFactorOwner(right);
  return first.flow === second.flow
    && first.generation === second.generation
    && first.serverUrl === second.serverUrl
    && first.bindingId === second.bindingId;
}

export function parseInteractiveTwoFactorDocumentId(value: unknown): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_DOCUMENT_ID_LENGTH
    || value.trim() !== value
    || hasControlCharacters(value)
  ) throw new TypeError('Interactive two-factor document id is invalid');
  return value;
}

export function createInteractiveTwoFactorConnectorCaller(
  input: InteractiveTwoFactorConnectorCaller,
): InteractiveTwoFactorConnectorCaller {
  if (!isPlainRecord(input) || !hasExactKeys(input, ['url', 'tabId', 'documentId'])) {
    throw new TypeError('Interactive two-factor connector document is invalid');
  }
  if (!Number.isSafeInteger(input.tabId) || input.tabId < 0) {
    throw new TypeError('Interactive two-factor connector tab is invalid');
  }
  if (typeof input.url !== 'string' || input.url.length === 0 || input.url.length > 64 * 1024) {
    throw new TypeError('Interactive two-factor connector URL is invalid');
  }
  let url: URL;
  try {
    url = new URL(input.url);
  } catch {
    throw new TypeError('Interactive two-factor connector URL is invalid');
  }
  if (url.username || url.password || url.href !== input.url) {
    throw new TypeError('Interactive two-factor connector URL is invalid');
  }
  return Object.freeze({
    url: input.url,
    tabId: input.tabId,
    documentId: parseInteractiveTwoFactorDocumentId(input.documentId),
  });
}

export function createInteractiveTwoFactorChallenge(input: {
  readonly owner: InteractiveTwoFactorOwner;
  readonly connectorData: string;
  readonly connectorUrl: string;
}): InteractiveTwoFactorChallenge {
  if (!isPlainRecord(input) || !hasExactKeys(input, [
    'owner', 'connectorData', 'connectorUrl',
  ])) throw new TypeError('Interactive two-factor challenge is invalid');
  const owner = createInteractiveTwoFactorOwner(input.owner);
  if (
    typeof input.connectorData !== 'string'
    || input.connectorData.length === 0
    || input.connectorData.length > MAX_CONNECTOR_DATA_LENGTH
  ) throw new TypeError('Interactive two-factor connector data is invalid');
  let parsed: unknown;
  try {
    parsed = JSON.parse(input.connectorData) as unknown;
  } catch {
    throw new TypeError('Interactive two-factor connector data is invalid');
  }
  if (!isPlainRecord(parsed) || JSON.stringify(parsed) !== input.connectorData) {
    throw new TypeError('Interactive two-factor connector data is not canonical JSON');
  }
  const connectorUrl = interactiveTwoFactorConnectorUrl(owner.serverUrl);
  if (input.connectorUrl !== connectorUrl) {
    throw new TypeError('Interactive two-factor connector URL is invalid');
  }
  return Object.freeze({ owner, connectorData: input.connectorData, connectorUrl });
}

/** Build the official V1 fallback-connector URL without retaining its parent URL durably. */
export function createInteractiveTwoFactorLaunch(
  challengeInput: InteractiveTwoFactorChallenge,
  input: Omit<InteractiveTwoFactorBeginInput, 'owner'>,
  replace?: InteractiveTwoFactorConnectorCaller,
): InteractiveTwoFactorLaunch {
  const challenge = createInteractiveTwoFactorChallenge(challengeInput);
  if (input.locale !== 'en' && input.locale !== 'zh-CN') {
    throw new TypeError('Interactive two-factor locale is invalid');
  }
  if (
    typeof input.parentUrl !== 'string'
    || input.parentUrl.length === 0
    || input.parentUrl.length > MAX_PARENT_URL_LENGTH
  ) throw new TypeError('Interactive two-factor parent URL is invalid');
  let parent: URL;
  try {
    parent = new URL(input.parentUrl);
  } catch {
    throw new TypeError('Interactive two-factor parent URL is invalid');
  }
  if (
    (parent.protocol !== 'chrome-extension:' && parent.protocol !== 'moz-extension:')
    || parent.username
    || parent.password
  ) throw new TypeError('Interactive two-factor parent URL is invalid');
  const replacement = replace
    ? createInteractiveTwoFactorConnectorCaller(replace)
    : undefined;

  const connector = new URL(challenge.connectorUrl);
  connector.searchParams.set(
    'data',
    bytesToBase64(utf8ToBytes(challenge.connectorData)),
  );
  connector.searchParams.set('parent', encodeURIComponent(parent.toString()));
  connector.searchParams.set('v', '1');
  connector.searchParams.set('locale', input.locale);
  return Object.freeze({
    owner: challenge.owner,
    url: connector.toString(),
    ...(replacement ? { replace: replacement } : {}),
  });
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return Boolean(descriptor?.enumerable && 'value' in descriptor && descriptor.value !== undefined);
  });
}

function hasExactKeys(value: object, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length
    && actual.every((key, index) => key === sorted[index]);
}

function hasControlCharacters(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}
