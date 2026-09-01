import type { AccountPasskeyConnectorResult } from '../core/api/account-passkey.js';
import type { SessionState } from '../core/session/session-manager.js';
import {
  accountPasskeyConnectorUrl,
  parseAccountPasskeyConnectorContext,
  sameAccountPasskeyConnector,
  type AccountPasskeyConnectorCeremony,
  type AccountPasskeyConnectorContext,
} from '../core/session/account-passkey.js';
import type { AccountPasskeyAttemptRegistry } from './account-passkey-attempt-registry.js';
import {
  AccountPasskeyCoordinatorError,
  type AccountPasskeyCoordinatorErrorCode,
  type AccountPasskeyAttemptStatus,
  type AccountPasskeyCoordinator,
  type AccountPasskeySubmitOutcome,
} from './account-passkey-coordinator.js';

const CONNECTOR_READY_TIMEOUT_MS = 15_000;
const CONNECTOR_READY_POLL_MS = 100;
const POPUP_WIDTH = 420;
const POPUP_HEIGHT = 680;

export type AccountPasskeyBrowserOutcome =
  | 'unlocked'
  | 'locked'
  | 'restricted'
  | 'cancelled'
  | 'expired'
  | 'failed'
  | 'two_factor_unsupported'
  | 'outcome_unknown'
  | 'unavailable';

export type AccountPasskeyUnavailableReason =
  | 'host_access_unavailable'
  | 'connector_context_failed'
  | 'options_unavailable'
  | 'options_busy'
  | 'options_invalid_connector'
  | 'options_server_changed'
  | 'options_request_failed';

export type AccountPasskeyBrowserBeginResult =
  | Extract<AccountPasskeyAttemptStatus, { status: 'waiting' | 'outcome_unknown' }>
  | {
      readonly status: 'unavailable';
      readonly reason: AccountPasskeyUnavailableReason;
    };

export interface AccountPasskeyBrowserFrame {
  readonly frameId?: number;
  readonly documentId?: string;
  readonly url?: string;
}

export interface AccountPasskeyBrowserTab {
  readonly id?: number;
  readonly url?: string;
}

export interface AccountPasskeyBrowserScriptResult {
  readonly frameId?: number;
  readonly documentId?: string;
  readonly result?: unknown;
  readonly error?: unknown;
}

export interface AccountPasskeyBrowserApi {
  readonly tabs: {
    create(options: { readonly url: string; readonly active: true }): Promise<AccountPasskeyBrowserTab>;
    query(options: Record<string, never>): Promise<readonly AccountPasskeyBrowserTab[]>;
    remove(tabId: number): Promise<void>;
  };
  readonly webNavigation: {
    getFrame(options: { readonly tabId: number; readonly frameId: 0 }): Promise<AccountPasskeyBrowserFrame | null | undefined>;
  };
  readonly scripting: {
    executeScript(options: {
      readonly target: { readonly tabId: number; readonly documentIds: readonly [string] };
      readonly world: 'ISOLATED';
      readonly func: typeof performAccountPasskeyCeremony;
      readonly args: readonly [AccountPasskeyConnectorCeremony];
    }): Promise<readonly AccountPasskeyBrowserScriptResult[]>;
  };
  readonly permissions: {
    contains(options: { readonly origins: readonly [string] }): Promise<boolean>;
  };
  readonly windows: {
    create(options: {
      readonly url: string;
      readonly type: 'popup';
      readonly focused: true;
      readonly width: number;
      readonly height: number;
    }): Promise<unknown>;
  };
}

export interface AccountPasskeyBrowserDeps {
  readonly browser: AccountPasskeyBrowserApi;
  readonly coordinator: Pick<AccountPasskeyCoordinator, 'begin' | 'resume' | 'submit' | 'startup' | 'status' | 'cancel'>;
  readonly attempts: Pick<AccountPasskeyAttemptRegistry, 'read'>;
  readonly getServerUrl: () => Promise<string | undefined>;
  readonly getAuthState: () => Promise<SessionState>;
  readonly getPopupUrl: () => string;
  readonly now?: () => number;
  readonly sleep?: (milliseconds: number) => Promise<void>;
  readonly logger?: { warn(event: AccountPasskeyBrowserDiagnostic): void };
}

export type AccountPasskeyBrowserDiagnostic =
  | AccountPasskeyUnavailableReason
  | 'connector_open_failed'
  | 'ceremony_failed'
  | 'connector_cleanup_failed'
  | 'popup_open_failed'
  | 'startup_recovery_failed';

interface ActiveRun {
  readonly connector: AccountPasskeyConnectorContext;
  readonly attemptId: string;
  cancellation?: Promise<boolean>;
  closing: boolean;
  suppressPopup: boolean;
  settled: boolean;
}

type ScriptOutcome =
  | { readonly kind: 'success'; readonly result: AccountPasskeyConnectorResult }
  | { readonly kind: 'cancelled' | 'error' };

/**
 * Owns the browser side of account-passkey login. The assertion ceremony runs in Chrome's
 * isolated world for one browser-owned document, so the server page cannot observe the PRF output
 * or monkeypatch the WebAuthn result. The opaque continuation token never enters script args.
 */
export class AccountPasskeyBrowserOrchestrator {
  readonly #now: () => number;
  readonly #sleep: (milliseconds: number) => Promise<void>;
  #tail: Promise<void> = Promise.resolve();
  #active: ActiveRun | undefined;

  constructor(private readonly deps: AccountPasskeyBrowserDeps) {
    this.#now = deps.now ?? Date.now;
    this.#sleep = deps.sleep ?? ((milliseconds) => new Promise((resolve) => {
      setTimeout(resolve, milliseconds);
    }));
  }

  begin(): Promise<AccountPasskeyBrowserBeginResult> {
    return this.#serialize(async () => {
      const existing = await this.status();
      if (existing.status === 'waiting' || existing.status === 'outcome_unknown') return existing;
      if (await this.deps.getAuthState() !== 'loggedOut') {
        throw new Error('Account passkey login requires a logged-out session.');
      }
      const serverUrl = await this.deps.getServerUrl();
      if (!serverUrl) throw new Error('A server must be configured before account passkey login.');
      const connectorUrl = accountPasskeyConnectorUrl(serverUrl);
      let hasHostAccess: boolean;
      try {
        hasHostAccess = await this.deps.browser.permissions.contains({
          origins: [`${new URL(connectorUrl).origin}/*`],
        });
      } catch {
        hasHostAccess = false;
      }
      if (!hasHostAccess) {
        return Object.freeze({
          status: 'unavailable' as const,
          reason: 'host_access_unavailable' as const,
        });
      }
      let tabId: number | undefined;
      try {
        const tab = await this.deps.browser.tabs.create({ url: connectorUrl, active: true });
        if (!isTabId(tab.id)) throw new Error('Browser did not return a connector tab id.');
        tabId = tab.id;
      } catch {
        this.#warn('connector_open_failed');
        throw new Error('The account passkey connector could not be opened.');
      }

      let connector: AccountPasskeyConnectorContext;
      try {
        connector = await this.#waitForConnector(tabId, serverUrl, connectorUrl);
      } catch {
        await this.#closeTab(tabId);
        await this.#openOutcomePopup('unavailable');
        this.#warn('connector_context_failed');
        return Object.freeze({
          status: 'unavailable' as const,
          reason: 'connector_context_failed' as const,
        });
      }
      try {
        const ceremony = await this.deps.coordinator.begin(connector);
        const run = this.#activate(connector, ceremony.attemptId);
        void this.#run(run, ceremony);
        return Object.freeze({
          status: 'waiting' as const,
          attemptId: ceremony.attemptId,
          expiresAt: ceremony.expiresAt,
        });
      } catch (error) {
        const active = await this.deps.attempts.read().catch(() => undefined);
        if (active && active.status !== 'outcome_unknown'
            && active.connector.tabId === connector.tabId) {
          await this.deps.coordinator.cancel(active.connector, active.owner.attemptId)
            .catch(() => false);
        }
        await this.#closeTab(tabId);
        await this.#openOutcomePopup('unavailable');
        const reason = accountPasskeyBeginDiagnostic(error);
        this.#warn(reason);
        return Object.freeze({ status: 'unavailable' as const, reason });
      }
    });
  }

  async status(): Promise<AccountPasskeyAttemptStatus> {
    const current = await this.deps.attempts.read();
    if (
      this.#active
      && current
      && current.status !== 'outcome_unknown'
      && current.owner.attemptId === this.#active.attemptId
    ) {
      return Object.freeze({
        status: 'waiting',
        attemptId: current.owner.attemptId,
        expiresAt: current.expiresAt,
      });
    }
    return this.deps.coordinator.status();
  }

  cancel(): Promise<boolean> {
    return this.#serialize(async () => {
      const attempt = await this.deps.attempts.read();
      if (!attempt || attempt.status === 'outcome_unknown') return false;
      const run = this.#active;
      const cancellation = this.deps.coordinator.cancel(attempt.connector, attempt.owner.attemptId);
      if (run && run.attemptId === attempt.owner.attemptId) run.cancellation = cancellation;
      const cancelled = await cancellation;
      if (run && run.attemptId === attempt.owner.attemptId) run.closing = true;
      await this.#closeTab(attempt.connector.tabId);
      if (cancelled) {
        if (run && run.attemptId === attempt.owner.attemptId) {
          run.suppressPopup = true;
          run.closing = true;
          run.settled = true;
          this.#active = undefined;
        }
      }
      return cancelled;
    });
  }

  startup(): Promise<AccountPasskeyAttemptStatus> {
    return this.#serialize(async () => {
      const before = await this.deps.attempts.read();
      if (
        this.#active
        && before
        && before.status !== 'outcome_unknown'
        && before.owner.attemptId === this.#active.attemptId
      ) {
        return Object.freeze({
          status: 'waiting',
          attemptId: before.owner.attemptId,
          expiresAt: before.expiresAt,
        });
      }
      const status = await this.deps.coordinator.startup();
      if (status.status === 'waiting' && before?.status === 'waiting') {
        if (await this.deps.getAuthState() !== 'loggedOut') {
          await this.deps.coordinator.cancel(before.connector, before.owner.attemptId);
          await this.#closeTab(before.connector.tabId);
          return Object.freeze({ status: 'none' });
        }
        try {
          const exact = await this.#readExactConnector(before.connector);
          if (!exact) throw new Error('The connector document is no longer active.');
          const ceremony = await this.deps.coordinator.resume(exact);
          if (!ceremony) throw new Error('The account passkey attempt cannot be resumed.');
          const run = this.#activate(exact, ceremony.attemptId);
          void this.#run(run, ceremony);
          return status;
        } catch {
          await this.deps.coordinator.cancel(before.connector, before.owner.attemptId)
            .catch(() => false);
          await this.#closeTab(before.connector.tabId);
          this.#warn('startup_recovery_failed');
          return Object.freeze({ status: 'none' });
        }
      }

      if (before && before.status !== 'outcome_unknown') {
        await this.#closeTab(before.connector.tabId);
      } else if (before?.status === 'outcome_unknown') {
        await this.#closeConnectorTabs(before.owner.serverUrl);
      }
      return status;
    });
  }

  handleTabRemoved(tabId: number): Promise<void> {
    return this.#serialize(async () => {
      const run = this.#active;
      if (!run || run.connector.tabId !== tabId || run.closing || run.settled) return;
      const attempt = await this.deps.attempts.read();
      if (!attempt) return;
      if (attempt.owner.attemptId !== run.attemptId) {
        run.settled = true;
        this.#active = undefined;
        return;
      }
      if (attempt.status === 'outcome_unknown') return;
      const cancellation = this.deps.coordinator.cancel(attempt.connector, attempt.owner.attemptId);
      run.cancellation = cancellation;
      const cancelled = await cancellation.catch(() => false);
      if (cancelled) {
        run.suppressPopup = true;
        run.settled = true;
        this.#active = undefined;
      }
    });
  }

  async #run(run: ActiveRun, ceremony: AccountPasskeyConnectorCeremony): Promise<void> {
    let outcome: AccountPasskeyBrowserOutcome = 'failed';
    let script: ScriptOutcome | undefined;
    try {
      script = await this.#execute(run.connector, ceremony);
      if (run.settled) return;
      if (script.kind !== 'success') {
        await this.deps.coordinator.cancel(run.connector, run.attemptId).catch(() => false);
        outcome = script.kind === 'cancelled' ? 'cancelled' : 'failed';
      } else {
        const exact = await this.#readExactConnector(run.connector);
        if (!exact || !sameAccountPasskeyConnector(exact, run.connector)) {
          await this.deps.coordinator.cancel(run.connector, run.attemptId).catch(() => false);
          outcome = 'failed';
        } else {
          const submitted = await this.deps.coordinator.submit(
            exact,
            run.attemptId,
            script.result,
          );
          outcome = outcomeForSubmit(submitted);
        }
      }
    } catch {
      if (!run.settled) {
        await this.deps.coordinator.cancel(run.connector, run.attemptId).catch(() => false);
        this.#warn('ceremony_failed');
      }
    } finally {
      clearConnectorResultPrf(script);
      await this.#finishRun(run, outcome);
    }
  }

  async #execute(
    connector: AccountPasskeyConnectorContext,
    ceremony: AccountPasskeyConnectorCeremony,
  ): Promise<ScriptOutcome> {
    const results = await this.deps.browser.scripting.executeScript({
      target: { tabId: connector.tabId, documentIds: [connector.documentId] },
      world: 'ISOLATED',
      func: performAccountPasskeyCeremony,
      args: [ceremony],
    });
    if (!Array.isArray(results) || results.length !== 1) {
      if (Array.isArray(results)) {
        for (const result of results) clearUnknownConnectorResultPrf(result?.result);
      }
      return Object.freeze({ kind: 'error' });
    }
    const entry = results[0];
    if (
      entry?.frameId !== 0
      || entry.documentId !== connector.documentId
      || Object.prototype.hasOwnProperty.call(entry, 'error')
    ) {
      clearUnknownConnectorResultPrf(entry?.result);
      return Object.freeze({ kind: 'error' });
    }
    return parseScriptOutcome(entry.result);
  }

  #activate(connector: AccountPasskeyConnectorContext, attemptId: string): ActiveRun {
    const run: ActiveRun = {
      connector,
      attemptId,
      closing: false,
      suppressPopup: false,
      settled: false,
    };
    this.#active = run;
    return run;
  }

  async #finishRun(run: ActiveRun, outcome: AccountPasskeyBrowserOutcome): Promise<void> {
    if (await run.cancellation?.catch(() => false)) run.suppressPopup = true;
    if (run.settled && this.#active !== run) return;
    run.settled = true;
    run.closing = true;
    if (this.#active === run) this.#active = undefined;
    await this.#closeTab(run.connector.tabId);
    if (!run.suppressPopup) await this.#openOutcomePopup(outcome);
  }

  async #waitForConnector(
    tabId: number,
    serverUrl: string,
    connectorUrl: string,
  ): Promise<AccountPasskeyConnectorContext> {
    const startedAt = this.#currentTime();
    while (this.#currentTime() - startedAt <= CONNECTOR_READY_TIMEOUT_MS) {
      let frame: AccountPasskeyBrowserFrame | null | undefined;
      try {
        frame = await this.deps.browser.webNavigation.getFrame({ tabId, frameId: 0 });
      } catch {
        frame = undefined;
      }
      if (
        frame
        && (frame.frameId === undefined || frame.frameId === 0)
        && frame.url === connectorUrl
        && validDocumentId(frame.documentId)
      ) {
        return parseAccountPasskeyConnectorContext({
          tabId,
          frameId: 0,
          documentId: frame.documentId,
          url: frame.url,
        }, serverUrl);
      }
      await this.#sleep(CONNECTOR_READY_POLL_MS);
    }
    throw new Error('The account passkey connector did not become ready.');
  }

  async #readExactConnector(
    expected: AccountPasskeyConnectorContext,
  ): Promise<AccountPasskeyConnectorContext | undefined> {
    let frame: AccountPasskeyBrowserFrame | null | undefined;
    try {
      frame = await this.deps.browser.webNavigation.getFrame({
        tabId: expected.tabId,
        frameId: 0,
      });
    } catch {
      return undefined;
    }
    if (
      !frame
      || (frame.frameId !== undefined && frame.frameId !== 0)
      || frame.url !== expected.url
      || frame.documentId !== expected.documentId
      || !validDocumentId(frame.documentId)
    ) {
      return undefined;
    }
    return expected;
  }

  async #closeConnectorTabs(serverUrl: string): Promise<void> {
    const connectorUrl = accountPasskeyConnectorUrl(serverUrl);
    let tabs: readonly AccountPasskeyBrowserTab[];
    try {
      tabs = await this.deps.browser.tabs.query({});
    } catch {
      this.#warn('connector_cleanup_failed');
      return;
    }
    await Promise.all(tabs.flatMap((tab) => (
      tab.url === connectorUrl && isTabId(tab.id) ? [this.#closeTab(tab.id)] : []
    )));
  }

  async #closeTab(tabId: number): Promise<void> {
    try {
      await this.deps.browser.tabs.remove(tabId);
    } catch {
      this.#warn('connector_cleanup_failed');
    }
  }

  async #openOutcomePopup(outcome: AccountPasskeyBrowserOutcome): Promise<void> {
    let url: URL;
    try {
      url = new URL(this.deps.getPopupUrl());
      url.search = '';
      url.hash = '';
      url.searchParams.set('accountPasskey', outcome);
    } catch {
      this.#warn('popup_open_failed');
      return;
    }
    try {
      await this.deps.browser.windows.create({
        url: url.toString(),
        type: 'popup',
        focused: true,
        width: POPUP_WIDTH,
        height: POPUP_HEIGHT,
      });
    } catch {
      this.#warn('popup_open_failed');
    }
  }

  #currentTime(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) throw new Error('Account passkey clock is invalid.');
    return now;
  }

  #warn(event: AccountPasskeyBrowserDiagnostic): void {
    try { this.deps.logger?.warn(event); } catch { /* Diagnostics are best-effort. */ }
  }

  #serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const run = this.#tail.then(operation, operation);
    this.#tail = run.then(() => undefined, () => undefined);
    return run;
  }
}

/** Self-contained because Chrome serializes this function into the isolated execution world. */
export async function performAccountPasskeyCeremony(
  ceremony: AccountPasskeyConnectorCeremony,
): Promise<unknown> {
  const ownedBytes: Uint8Array<ArrayBuffer>[] = [];

  function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
    const base64 = value.replace(/-/gu, '+').replace(/_/gu, '/');
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    ownedBytes.push(bytes);
    return bytes;
  }

  function encodeBase64Url(value: ArrayBuffer | ArrayBufferView): string {
    const bytes = value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/gu, '');
  }

  function bytes(value: unknown): Uint8Array<ArrayBuffer> | undefined {
    const source = value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : ArrayBuffer.isView(value)
        ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
        : undefined;
    if (!source) return undefined;
    const copy = new Uint8Array(source.byteLength);
    copy.set(source);
    ownedBytes.push(copy);
    return copy;
  }

  const controller = new AbortController();
  const remaining = Math.max(1, Math.min(
    ceremony.options.timeout,
    ceremony.expiresAt - Date.now(),
  ));
  const timer = setTimeout(() => controller.abort(), remaining);
  try {
    if (
      typeof PublicKeyCredential !== 'function'
      || typeof AuthenticatorAssertionResponse !== 'function'
      || !navigator.credentials?.get
    ) return { kind: 'error' };
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: decodeBase64Url(ceremony.options.challenge),
        timeout: remaining,
        rpId: ceremony.options.rpId,
        allowCredentials: ceremony.options.allowCredentials.map((descriptor) => ({
          id: decodeBase64Url(descriptor.id),
          type: descriptor.type,
          ...(descriptor.transports ? { transports: [...descriptor.transports] } : {}),
        })),
        userVerification: ceremony.options.userVerification,
        extensions: {
          prf: { eval: { first: decodeBase64Url(ceremony.prfSalt) } },
        },
      },
      signal: controller.signal,
    });
    if (!(credential instanceof PublicKeyCredential)
        || !(credential.response instanceof AuthenticatorAssertionResponse)
        || credential.type !== 'public-key') return { kind: 'error' };
    const userHandle = bytes(credential.response.userHandle);
    if (!userHandle || userHandle.byteLength === 0) return { kind: 'error' };
    const rawId = encodeBase64Url(credential.rawId);
    if (credential.id !== rawId) return { kind: 'error' };

    const extensionResults = credential.getClientExtensionResults();
    const prf = typeof extensionResults === 'object' && extensionResults !== null
      ? (extensionResults as { prf?: { results?: { first?: unknown } } }).prf
      : undefined;
    const prfOutput = bytes(prf?.results?.first);
    if (prfOutput && prfOutput.byteLength !== 32) return { kind: 'error' };
    if (prfOutput?.every((value) => value === 0)) return { kind: 'error' };

    return {
      kind: 'success',
      result: {
        assertion: {
          id: credential.id,
          rawId,
          type: 'public-key',
          extensions: {},
          response: {
            authenticatorData: encodeBase64Url(credential.response.authenticatorData),
            signature: encodeBase64Url(credential.response.signature),
            clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
            userHandle: encodeBase64Url(userHandle),
          },
        },
        ...(prfOutput ? { prfOutput: Array.from(prfOutput) } : {}),
      },
    };
  } catch (error) {
    const name = typeof error === 'object' && error !== null && 'name' in error
      ? String((error as { name?: unknown }).name)
      : '';
    return name === 'NotAllowedError' || name === 'AbortError'
      ? { kind: 'cancelled' }
      : { kind: 'error' };
  } finally {
    clearTimeout(timer);
    for (const value of ownedBytes) value.fill(0);
  }
}

function parseScriptOutcome(input: unknown): ScriptOutcome {
  if (!isPlainRecord(input) || typeof input.kind !== 'string') {
    clearUnknownConnectorResultPrf(input);
    return Object.freeze({ kind: 'error' });
  }
  if (input.kind === 'cancelled' || input.kind === 'error') {
    if (Reflect.ownKeys(input).length === 1) return Object.freeze({ kind: input.kind });
    clearUnknownConnectorResultPrf(input);
    return Object.freeze({ kind: 'error' });
  }
  if (input.kind !== 'success' || Reflect.ownKeys(input).length !== 2 || !('result' in input)) {
    clearUnknownConnectorResultPrf(input);
    return Object.freeze({ kind: 'error' });
  }
  return Object.freeze({
    kind: 'success',
    result: input.result as AccountPasskeyConnectorResult,
  });
}

function clearConnectorResultPrf(outcome: ScriptOutcome | undefined): void {
  if (outcome?.kind !== 'success') return;
  const source = outcome.result.prfOutput;
  if (!Array.isArray(source) || source.length !== 32) return;
  try { source.fill(0); } catch { /* Best-effort after the parser's mandatory clear. */ }
}

function clearUnknownConnectorResultPrf(input: unknown): void {
  if (!isPlainRecord(input)) return;
  const result = input.result;
  if (!isPlainRecord(result)) return;
  const source = result.prfOutput;
  if (!Array.isArray(source) || source.length !== 32) return;
  try { source.fill(0); } catch { /* Invalid results are discarded immediately. */ }
}

function outcomeForSubmit(outcome: AccountPasskeySubmitOutcome): AccountPasskeyBrowserOutcome {
  switch (outcome.status) {
    case 'unlocked': return 'unlocked';
    case 'locked': return 'locked';
    case 'restricted': return 'restricted';
    case 'two_factor_unsupported': return 'two_factor_unsupported';
    case 'outcome_unknown': return 'outcome_unknown';
    case 'expired': return 'expired';
    case 'failed':
    case 'replayed':
      return 'failed';
  }
}

function validDocumentId(value: unknown): value is string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 512
    || value.trim() !== value
  ) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return false;
  }
  return true;
}

function isTabId(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function accountPasskeyBeginDiagnostic(error: unknown): AccountPasskeyUnavailableReason {
  if (!(error instanceof AccountPasskeyCoordinatorError)) return 'options_unavailable';
  const diagnostics: Record<AccountPasskeyCoordinatorErrorCode, AccountPasskeyUnavailableReason> = {
    busy: 'options_busy',
    invalid_connector: 'options_invalid_connector',
    invalid_assertion: 'options_unavailable',
    server_changed: 'options_server_changed',
    request_failed: 'options_request_failed',
  };
  return diagnostics[error.code];
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}
