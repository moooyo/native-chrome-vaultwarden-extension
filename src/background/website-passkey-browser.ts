import {
  WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE,
  WEBSITE_PASSKEY_PORT_NAME,
  parseWebsitePasskeyConfigChangedAck,
} from '../messaging/website-passkey-port.js';
import { VAULT_TRANSFER_PORT_NAME } from '../messaging/vault-transfer-port.js';
import type { WebsitePasskeyScriptState } from './website-passkey-script-manager.js';

const MAIN_SCRIPT_FILE = 'content/page-webauthn.js';
const BRIDGE_SCRIPT_FILE = 'content/webauthn-bridge.js';
const MAX_DOCUMENT_ID_LENGTH = 4_096;
const CONFIG_CHANGED_MESSAGE = Object.freeze({
  type: WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE,
});

export interface WebsitePasskeyBrowserTab {
  readonly id?: number;
}

export interface WebsitePasskeyBrowserFrame {
  readonly frameId?: number;
  readonly parentFrameId?: number;
  readonly documentId?: string;
  readonly url?: string;
}

export interface WebsitePasskeyDocumentMessageTarget {
  readonly frameId: number;
  readonly documentId: string;
}

export interface WebsitePasskeyInjectionTarget {
  readonly tabId: number;
  readonly documentIds: readonly [string];
}

export interface WebsitePasskeyInjectionResult {
  readonly frameId?: number;
  readonly documentId?: string;
  readonly error?: unknown;
}

export interface WebsitePasskeyBrowserLike {
  readonly tabs: {
    query(queryInfo: Record<string, never>): Promise<readonly WebsitePasskeyBrowserTab[]>;
    sendMessage(
      tabId: number,
      message: Readonly<{ type: typeof WEBSITE_PASSKEY_CONFIG_CHANGED_MESSAGE }>,
      options: WebsitePasskeyDocumentMessageTarget,
    ): Promise<unknown>;
  };
  readonly webNavigation: {
    getFrame(details: {
      readonly tabId: number;
      readonly frameId: number;
    }): Promise<WebsitePasskeyBrowserFrame | null | undefined>;
    getAllFrames?(details: {
      readonly tabId: number;
    }): Promise<readonly WebsitePasskeyBrowserFrame[] | null | undefined>;
  };
  readonly permissions: {
    contains(permissions: { readonly origins: readonly [string] }): Promise<boolean>;
  };
  readonly scripting: {
    executeScript(injection: {
      readonly target: WebsitePasskeyInjectionTarget;
      readonly files: readonly [string];
      readonly world: 'ISOLATED' | 'MAIN';
    }): Promise<readonly WebsitePasskeyInjectionResult[]>;
  };
}

export type WebsitePasskeyBrowserRuntimeErrorCode =
  | 'invalid_state'
  | 'tabs_query_failed'
  | 'permission_check_failed'
  | 'main_injection_failed'
  | 'bridge_injection_failed'
  | 'bridge_ack_missing';

/** Stable diagnostics deliberately exclude tab, document, URL, and browser error details. */
export class WebsitePasskeyBrowserRuntimeError extends Error {
  constructor(readonly code: WebsitePasskeyBrowserRuntimeErrorCode) {
    super(errorMessage(code));
    this.name = 'WebsitePasskeyBrowserRuntimeError';
  }
}

interface EligibleFrame {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly originPattern: string;
  readonly originIdentity: string;
}

/**
 * Refresh already-open eligible frames after the script manager changes policy. A missing receiver is
 * expected for old or inactive documents; active eligible documents are repaired only when the
 * extension still has host access to that exact origin.
 */
export function createWebsitePasskeyTopFrameNotifier(
  browserLike: WebsitePasskeyBrowserLike,
): (state: Readonly<WebsitePasskeyScriptState>) => Promise<void> {
  return async (state) => {
    const shouldInject = shouldInstallDynamicScripts(state);
    let tabs: readonly WebsitePasskeyBrowserTab[];
    try {
      tabs = await browserLike.tabs.query({});
      if (!Array.isArray(tabs)) throw new Error('invalid tabs result');
    } catch {
      throw new WebsitePasskeyBrowserRuntimeError('tabs_query_failed');
    }

    const uniqueTabIds = new Set<number>();
    for (const tab of tabs) {
      if (isTabId(tab?.id)) uniqueTabIds.add(tab.id);
    }
    const settled = await Promise.allSettled(
      [...uniqueTabIds].map(async (tabId) => {
        const frames = await readEligibleFrames(browserLike, tabId);
        const frameResults = await Promise.allSettled(
          frames.map((frame) => notifyFrame(browserLike, frame, shouldInject)),
        );
        const failure = frameResults.find((result) => result.status === 'rejected');
        if (failure?.status === 'rejected') throw failure.reason;
      }),
    );
    const failures = settled.flatMap((result) => (
      result.status === 'rejected'
        ? [sanitizeRuntimeError(result.reason)]
        : []
    ));
    if (failures.length > 0) {
      throw new AggregateError(failures, 'Website passkey top-frame refresh failed');
    }
  };
}

/** The URL policy is intentionally identical to the dynamic script match set. */
export function websitePasskeyOriginMatchPattern(rawUrl: string): string | undefined {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return undefined;
  }
  if (url.username !== '' || url.password !== '') return undefined;
  if (url.hostname.includes(':')) return undefined;
  if (url.protocol === 'https:') return `https://${url.hostname}/*`;
  if (
    url.protocol === 'http:'
    && (url.hostname === 'localhost' || url.hostname === '127.0.0.1')
  ) return `http://${url.hostname}/*`;
  return undefined;
}

async function notifyFrame(
  browserLike: WebsitePasskeyBrowserLike,
  frame: EligibleFrame,
  shouldInject: boolean,
): Promise<void> {
  if (await sendConfigChanged(browserLike, frame)) return;
  if (!shouldInject || !await isSameDocument(browserLike, frame)) return;

  let hasHostPermission: boolean;
  try {
    hasHostPermission = await browserLike.permissions.contains({
      origins: [frame.originPattern],
    });
  } catch {
    if (!await isSameDocument(browserLike, frame)) return;
    throw new WebsitePasskeyBrowserRuntimeError('permission_check_failed');
  }
  if (!hasHostPermission || !await isSameDocument(browserLike, frame)) return;

  if (!await injectFile(browserLike, frame, MAIN_SCRIPT_FILE, 'MAIN')) {
    if (!await isSameDocument(browserLike, frame)) return;
    throw new WebsitePasskeyBrowserRuntimeError('main_injection_failed');
  }
  if (!await injectFile(browserLike, frame, BRIDGE_SCRIPT_FILE, 'ISOLATED')) {
    if (!await isSameDocument(browserLike, frame)) return;
    throw new WebsitePasskeyBrowserRuntimeError('bridge_injection_failed');
  }
  if (await sendConfigChanged(browserLike, frame)) return;
  if (!await isSameDocument(browserLike, frame)) return;
  throw new WebsitePasskeyBrowserRuntimeError('bridge_ack_missing');
}

async function readEligibleTopFrame(
  browserLike: WebsitePasskeyBrowserLike,
  tabId: number,
): Promise<EligibleFrame | undefined> {
  let frame: WebsitePasskeyBrowserFrame | null | undefined;
  try {
    frame = await browserLike.webNavigation.getFrame({ tabId, frameId: 0 });
  } catch {
    return undefined;
  }
  if (
    !frame
    || !queriedFrameIdMatches(frame, 0)
    || !validDocumentId(frame.documentId)
    || typeof frame.url !== 'string'
  ) return undefined;
  const originPattern = websitePasskeyOriginMatchPattern(frame.url);
  if (!originPattern) return undefined;
  let originIdentity: string;
  try { originIdentity = new URL(frame.url).origin; } catch { return undefined; }
  return Object.freeze({ tabId, frameId: 0, documentId: frame.documentId, originPattern, originIdentity });
}

async function readEligibleFrames(
  browserLike: WebsitePasskeyBrowserLike,
  tabId: number,
): Promise<readonly EligibleFrame[]> {
  if (!browserLike.webNavigation.getAllFrames) {
    const top = await readEligibleTopFrame(browserLike, tabId);
    return top ? [top] : [];
  }
  let rawFrames: readonly WebsitePasskeyBrowserFrame[] | null | undefined;
  try { rawFrames = await browserLike.webNavigation.getAllFrames({ tabId }); } catch { return []; }
  if (!Array.isArray(rawFrames)) return [];
  const frames = new Map<number, WebsitePasskeyBrowserFrame & {
    frameId: number;
    parentFrameId: number;
    documentId: string;
    url: string;
    originIdentity: string;
    originPattern: string;
  }>();
  for (const raw of rawFrames) {
    if (!isTabId(raw?.frameId) || frames.has(raw.frameId)
      || !Number.isSafeInteger(raw.parentFrameId) || (raw.parentFrameId as number) < -1
      || !validDocumentId(raw.documentId) || typeof raw.url !== 'string') continue;
    const originPattern = websitePasskeyOriginMatchPattern(raw.url);
    if (!originPattern) continue;
    let originIdentity: string;
    try { originIdentity = new URL(raw.url).origin; } catch { continue; }
    frames.set(raw.frameId, {
      ...raw,
      frameId: raw.frameId,
      parentFrameId: raw.parentFrameId as number,
      documentId: raw.documentId,
      url: raw.url,
      originIdentity,
      originPattern,
    });
  }
  return Object.freeze([...frames.values()].map((frame) => Object.freeze({
    tabId,
    frameId: frame.frameId,
    documentId: frame.documentId,
    originPattern: frame.originPattern,
    originIdentity: frame.originIdentity,
  })));
}

async function isSameDocument(
  browserLike: WebsitePasskeyBrowserLike,
  expected: EligibleFrame,
): Promise<boolean> {
  let current: WebsitePasskeyBrowserFrame | null | undefined;
  try {
    current = await browserLike.webNavigation.getFrame({
      tabId: expected.tabId,
      frameId: expected.frameId,
    });
  } catch {
    return false;
  }
  if (!current
    || !queriedFrameIdMatches(current, expected.frameId)
    || current.documentId !== expected.documentId
    || typeof current.url !== 'string') return false;
  const originPattern = websitePasskeyOriginMatchPattern(current.url);
  let originIdentity: string;
  try { originIdentity = new URL(current.url).origin; } catch { return false; }
  return originPattern === expected.originPattern && originIdentity === expected.originIdentity;
}

async function sendConfigChanged(
  browserLike: WebsitePasskeyBrowserLike,
  frame: EligibleFrame,
): Promise<boolean> {
  let response: unknown;
  try {
    response = await browserLike.tabs.sendMessage(
      frame.tabId,
      CONFIG_CHANGED_MESSAGE,
      { frameId: frame.frameId, documentId: frame.documentId },
    );
  } catch {
    return false;
  }
  try {
    parseWebsitePasskeyConfigChangedAck(response);
    return true;
  } catch {
    return false;
  }
}

async function injectFile(
  browserLike: WebsitePasskeyBrowserLike,
  frame: EligibleFrame,
  file: string,
  world: 'ISOLATED' | 'MAIN',
): Promise<boolean> {
  try {
    const results = await browserLike.scripting.executeScript({
      target: { tabId: frame.tabId, documentIds: [frame.documentId] },
      files: [file],
      world,
    });
    if (!Array.isArray(results) || results.length !== 1) return false;
    const result = results[0];
    return result?.frameId === frame.frameId
      && result.documentId === frame.documentId
      && !Object.prototype.hasOwnProperty.call(result, 'error');
  } catch {
    return false;
  }
}

function shouldInstallDynamicScripts(state: Readonly<WebsitePasskeyScriptState>): boolean {
  if (
    typeof state !== 'object'
    || state === null
    || typeof state.enabled !== 'boolean'
    || (state.sessionState !== 'loggedOut'
      && state.sessionState !== 'locked'
      && state.sessionState !== 'unlocked')
    || !Number.isSafeInteger(state.policyGeneration)
    || state.policyGeneration < 0
  ) throw new WebsitePasskeyBrowserRuntimeError('invalid_state');
  return state.enabled && state.sessionState !== 'loggedOut';
}

function isTabId(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function queriedFrameIdMatches(frame: WebsitePasskeyBrowserFrame, expectedFrameId: number): boolean {
  return !Object.hasOwn(frame, 'frameId') || frame.frameId === expectedFrameId;
}

function validDocumentId(value: unknown): value is string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_DOCUMENT_ID_LENGTH
    || value.trim() !== value
  ) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return false;
  }
  return true;
}

function sanitizeRuntimeError(error: unknown): WebsitePasskeyBrowserRuntimeError {
  return error instanceof WebsitePasskeyBrowserRuntimeError
    ? error
    : new WebsitePasskeyBrowserRuntimeError('bridge_ack_missing');
}

function errorMessage(code: WebsitePasskeyBrowserRuntimeErrorCode): string {
  switch (code) {
    case 'invalid_state': return 'Website passkey script state is invalid.';
    case 'tabs_query_failed': return 'Website passkey tab enumeration failed.';
    case 'permission_check_failed': return 'Website passkey host access check failed.';
    case 'main_injection_failed': return 'Website passkey page script injection failed.';
    case 'bridge_injection_failed': return 'Website passkey bridge script injection failed.';
    case 'bridge_ack_missing': return 'Website passkey bridge did not acknowledge refresh.';
  }
}

export interface BackgroundDispatchablePort {
  readonly name: string;
  disconnect(): void;
}

export interface BackgroundPortHandler<Port> {
  handle(port: Port, extensionBaseUrl: string, extensionId: string): boolean;
}

export interface BackgroundPortDispatcherDependencies<Port extends BackgroundDispatchablePort> {
  readonly extensionBaseUrl: string;
  readonly extensionId: string;
  readonly vaultTransferHandler: BackgroundPortHandler<Port>;
  readonly websitePasskeyHandler: BackgroundPortHandler<Port>;
}

/** Return one onConnect listener so unrelated privileged handlers never observe the wrong Port. */
export function createBackgroundPortDispatcher<Port extends BackgroundDispatchablePort>(
  dependencies: BackgroundPortDispatcherDependencies<Port>,
): (port: Port) => void {
  return (port) => {
    try {
      if (port.name === VAULT_TRANSFER_PORT_NAME) {
        dependencies.vaultTransferHandler.handle(
          port,
          dependencies.extensionBaseUrl,
          dependencies.extensionId,
        );
        return;
      }
      if (port.name === WEBSITE_PASSKEY_PORT_NAME) {
        dependencies.websitePasskeyHandler.handle(
          port,
          dependencies.extensionBaseUrl,
          dependencies.extensionId,
        );
        return;
      }
    } catch {
      safeDisconnect(port);
      return;
    }
    safeDisconnect(port);
  };
}

function safeDisconnect(port: BackgroundDispatchablePort): void {
  try { port.disconnect(); } catch { /* The Port may already be disconnected. */ }
}
