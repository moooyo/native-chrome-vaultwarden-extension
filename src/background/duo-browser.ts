import { ApiHttpError } from '../core/api/client.js';
import { AppError } from '../core/errors.js';
import {
  createDuoChallengeOwner,
  duoConnectorUrl,
  duoProviderMetadata,
  parseDuoAuthorization,
  parseDuoCallback,
  sameDuoChallengeOwner,
  type DuoChallengeOwner,
  type DuoProviderSeed,
  type DuoTwoFactorProvider,
} from '../core/session/duo-two-factor.js';
import {
  DuoAttemptWriteUncertainError,
  DuoAttemptStore,
  type ClaimedDuoAttempt,
  type DuoAttempt,
  type DuoSourceContext,
  type DuoSourceDocument,
} from './duo-attempt-store.js';

export type DuoBeginInput =
  | {
      readonly flow: 'password';
      readonly provider: DuoTwoFactorProvider;
      readonly continuationId: string;
      readonly remember: boolean;
    }
  | {
      readonly flow: 'deviceLogin';
      readonly provider: DuoTwoFactorProvider;
      readonly generation: number;
      readonly remember: boolean;
    };

export type DuoCancelInput =
  | {
      readonly flow: 'password';
      readonly continuationId: string;
    }
  | {
      readonly flow: 'deviceLogin';
      readonly generation: number;
      readonly provider: DuoTwoFactorProvider;
    };

export interface DuoChallengeBroker<Result> {
  prepare(input: DuoBeginInput): Promise<{
    readonly owner: DuoChallengeOwner;
    readonly seed: DuoProviderSeed;
  }>;
  complete(input: {
    readonly owner: DuoChallengeOwner;
    readonly token: string;
    readonly remember: boolean;
    readonly onGrantStarted: () => Promise<void>;
    readonly onGrantDispatched: () => void;
  }): Promise<Result>;
}

export interface DuoBrowserAuthorization {
  readonly serverUrl: string;
  readonly vaultUrl: string;
  readonly assertCurrent: () => void;
}

export interface DuoBrowserDeps {
  readonly store: DuoAttemptStore;
  readonly password: DuoChallengeBroker<unknown>;
  readonly deviceLogin: DuoChallengeBroker<unknown>;
  readonly authorize: (serverUrl: string) => Promise<DuoBrowserAuthorization>;
  readonly browser: {
    readonly action: {
      openPopup(): PromiseLike<void>;
    };
    readonly runtime: {
      getContexts(input: {
        readonly contextTypes: readonly ['POPUP'];
        readonly documentIds: readonly [string];
        readonly documentUrls: readonly [string];
      }): PromiseLike<readonly {
        readonly contextType?: string;
        readonly documentId?: string;
        readonly documentUrl?: string;
        readonly windowId?: number;
      }[]>;
    };
    readonly tabs: {
      create(input: {
        readonly url: string;
        readonly active: true;
        readonly windowId: number;
      }): PromiseLike<{ readonly id?: number }>;
      query(input: { readonly active: true; readonly windowId: number }): PromiseLike<readonly {
        readonly id?: number;
        readonly windowId?: number;
        readonly url?: string;
      }[]>;
      get(tabId: number): PromiseLike<{
        readonly id?: number;
        readonly windowId?: number;
        readonly url?: string;
        readonly active?: boolean;
      }>;
      update(tabId: number, input: {
        readonly url?: string;
        readonly active?: boolean;
      }): PromiseLike<unknown>;
      remove(tabId: number): PromiseLike<void>;
    };
    readonly windows: {
      update(windowId: number, input: { readonly focused: true }): PromiseLike<unknown>;
    };
    readonly webNavigation: {
      getFrame(input: { readonly tabId: number; readonly frameId: 0 }): PromiseLike<{
        readonly documentId?: string;
        readonly url: string;
      } | null>;
    };
    readonly scripting: {
      executeScript(input: {
        readonly target: { readonly tabId: number; readonly documentIds: [string] };
        readonly func: (expected: string, replacement: string) => boolean;
        readonly args: [string, string];
      }): PromiseLike<readonly { readonly result?: unknown }[]>;
    };
  };
  readonly popupUrl: string;
}

/** Browser-owned Duo Universal Prompt continuation for password, SSO, and device-login grants. */
export class DuoBrowserCoordinator {
  #restartReconciliation: Promise<void> | undefined;

  constructor(private readonly deps: DuoBrowserDeps) {}

  reconcileRestart(): Promise<void> {
    if (this.#restartReconciliation) return this.#restartReconciliation;
    const operation = this.#runRestartReconciliation();
    const tracked = operation.finally(() => {
      if (this.#restartReconciliation === tracked) this.#restartReconciliation = undefined;
    });
    this.#restartReconciliation = tracked;
    return this.#restartReconciliation;
  }

  async begin(
    input: DuoBeginInput,
    popupDocumentId: string,
  ): Promise<{ readonly status: 'waiting' }> {
    await this.cleanupExpiredAttemptIfPresent();
    const broker = input.flow === 'password' ? this.deps.password : this.deps.deviceLogin;
    const prepared = await broker.prepare(input);
    const owner = createDuoChallengeOwner(prepared.owner);
    if (
      owner.flow !== input.flow
      || owner.provider !== input.provider
      || (input.flow === 'password' && owner.bindingId !== input.continuationId)
      || (input.flow === 'deviceLogin' && owner.generation !== input.generation)
    ) {
      throw new AppError('denied', 'The Duo challenge binding is invalid.');
    }
    const source = await this.captureSourceContext(popupDocumentId);
    const authority = await this.deps.authorize(owner.serverUrl);
    authority.assertCurrent();
    if (authority.serverUrl !== owner.serverUrl) throw new AppError('session_expired', 'The Duo server changed.');
    const authorization = parseDuoAuthorization(
      duoProviderMetadata(prepared.seed),
      owner.provider,
      authority.vaultUrl,
    );
    const tab = await this.deps.browser.tabs.create({
      url: 'about:blank',
      active: true,
      windowId: source.windowId,
    });
    if (!Number.isSafeInteger(tab.id) || (tab.id as number) < 0) {
      throw new AppError('error', 'The browser did not create a Duo tab.');
    }
    const tabId = tab.id as number;
    let attempt: Awaited<ReturnType<DuoAttemptStore['createOrReplaceWaiting']>>['attempt'] | undefined;
    try {
      await this.assertDuoTabCurrent(tabId, source.windowId, 'about:blank');
      authority.assertCurrent();
      if (source.document) await this.assertSourceCurrent(source.document, false);
      const created = await this.deps.store.createOrReplaceWaiting({
        challenge: owner,
        authorization,
        tabId,
        remember: input.remember,
        source,
      });
      attempt = created.attempt;
      if (created.replaced) {
        await Promise.resolve(this.deps.browser.tabs.remove(created.replaced.tabId)).catch(() => undefined);
      }
      authority.assertCurrent();
      if (source.document) await this.assertSourceCurrent(source.document, false);
      await this.deps.browser.tabs.update(tabId, { url: authorization.authUrl, active: true });
      authority.assertCurrent();
      await this.assertDuoTabCurrent(tabId, source.windowId, authorization.authUrl);
      return Object.freeze({ status: 'waiting' });
    } catch (error) {
      const cleanupOwner = attempt?.owner
        ?? (error instanceof DuoAttemptWriteUncertainError ? error.owner : undefined);
      if (cleanupOwner) await this.clearExact(cleanupOwner);
      if (error instanceof DuoAttemptWriteUncertainError) {
        await Promise.allSettled(error.relatedTabIds.map(
          (relatedTabId) => Promise.resolve(this.deps.browser.tabs.remove(relatedTabId)),
        ));
      }
      await Promise.resolve(this.deps.browser.tabs.remove(tabId)).catch(() => undefined);
      throw error;
    }
  }

  async cancel(input: DuoCancelInput): Promise<boolean> {
    await this.cleanupExpiredAttemptIfPresent();
    const current = await this.deps.store.read();
    if (!current || current.status !== 'waiting' || !matchesCancelInput(current, input)) return false;
    return this.cancelWaitingAttempt(current);
  }

  async cancelDeviceLogin(generation: number): Promise<boolean> {
    await this.cleanupExpiredAttemptIfPresent();
    const current = await this.deps.store.read();
    if (!current || current.status !== 'waiting'
        || current.owner.challenge.flow !== 'deviceLogin'
        || current.owner.challenge.generation !== generation) return false;
    return this.cancelWaitingAttempt(current);
  }

  async cancelCurrent(): Promise<boolean> {
    await this.cleanupExpiredAttemptIfPresent();
    const current = await this.deps.store.read();
    if (!current || current.status !== 'waiting') return false;
    return this.cancelWaitingAttempt(current);
  }

  async retireInvalidWaiting(): Promise<boolean> {
    await this.cleanupExpiredAttemptIfPresent();
    const current = await this.deps.store.read();
    if (!current || current.status !== 'waiting') return false;
    const challenge = current.owner.challenge;
    const input: DuoBeginInput = challenge.flow === 'password'
      ? {
          flow: 'password',
          provider: challenge.provider,
          continuationId: challenge.bindingId,
          remember: current.remember,
        }
      : {
          flow: 'deviceLogin',
          provider: challenge.provider,
          generation: challenge.generation,
          remember: current.remember,
        };
    const broker = input.flow === 'password' ? this.deps.password : this.deps.deviceLogin;
    try {
      const prepared = await broker.prepare(input);
      if (sameDuoChallengeOwner(prepared.owner, challenge)) return false;
    } catch {
      // The bound auth continuation no longer exists; retire only this exact waiting attempt.
    }
    return this.cancelWaitingAttempt(current);
  }

  async handleNavigation(details: {
    readonly tabId: number;
    readonly frameId: number;
    readonly documentId?: string;
    readonly url: string;
  }): Promise<void> {
    if (details.frameId !== 0) return;
    if (await this.cleanupExpiredAttemptIfPresent()) return;
    const current = await this.deps.store.read();
    const sourceDocument = current?.source.document;
    if (current && current.status !== 'outcome_unknown' && sourceDocument?.tabId === details.tabId) {
      if (details.documentId !== sourceDocument.documentId || details.url !== sourceDocument.url) {
        await this.retireChangedSource(current);
      }
      return;
    }
    if (!details.documentId) return;
    if (!current || current.status !== 'waiting' || current.tabId !== details.tabId) return;
    if (!isConnectorNavigation(details.url, current.redirectUri)) return;
    let claimed;
    try {
      claimed = await this.deps.store.claimCallback(current.owner, {
        tabId: details.tabId,
        documentId: details.documentId,
        callbackUrl: details.url,
      });
    } catch (error) {
      const cleanupOwner = error instanceof DuoAttemptWriteUncertainError
        ? error.owner
        : current.owner;
      let scrubbed: boolean;
      try {
        await this.scrub(
          { tabId: details.tabId, documentId: details.documentId },
          details.url,
          current.redirectUri,
        );
        scrubbed = true;
      } catch {
        scrubbed = false;
      }
      if (scrubbed) {
        await this.clearExact(cleanupOwner);
        await Promise.resolve(this.deps.browser.tabs.remove(details.tabId)).catch(() => undefined);
      } else if (await this.closeOwnedTabAndProveGone(current)) {
        await this.clearExact(cleanupOwner);
      }
      return;
    }
    if (!claimed) return;
    let scrubbed = false;
    let grantPrepared = false;
    let grantDispatched = false;
    let settlementOwner = claimed.attempt.owner;
    let completion: unknown;
    let settlementError: unknown;
    try {
      await this.scrub(claimed.attempt, details.url, claimed.callback.scrubbedUrl);
      scrubbed = true;
      const authority = await this.deps.authorize(claimed.attempt.owner.challenge.serverUrl);
      authority.assertCurrent();
      if (
        authority.serverUrl !== claimed.attempt.owner.challenge.serverUrl
        || duoConnectorUrl(authority.vaultUrl) !== claimed.attempt.redirectUri
      ) throw new AppError('session_expired', 'The Duo server environment changed.');
      if (claimed.attempt.source.document) {
        await this.assertSourceCurrent(claimed.attempt.source.document, false);
      }
      const broker = claimed.attempt.owner.challenge.flow === 'password'
        ? this.deps.password
        : this.deps.deviceLogin;
      completion = await broker.complete({
        owner: claimed.attempt.owner.challenge,
        token: claimed.callback.token,
        remember: claimed.attempt.remember,
        onGrantStarted: async () => {
          authority.assertCurrent();
          if (claimed.attempt.source.document) {
            await this.assertSourceCurrent(claimed.attempt.source.document, false);
          }
          const submitting = await this.deps.store.startSubmission(claimed.attempt.owner);
          if (!submitting) {
            throw new AppError('session_expired', 'The Duo callback is no longer current.');
          }
          settlementOwner = submitting.owner;
          authority.assertCurrent();
          if (submitting.source.document) {
            await this.assertSourceCurrent(submitting.source.document, false);
          }
          grantPrepared = true;
        },
        onGrantDispatched: () => { grantDispatched = true; },
      });
      if (!grantPrepared) throw new AppError('denied', 'The Duo grant did not start safely.');
      await this.deps.store.clear(settlementOwner);
    } catch (error) {
      settlementError = error;
      if (error instanceof DuoAttemptWriteUncertainError) settlementOwner = error.owner;
      if (scrubbed) {
        if (grantDispatched && !isDefiniteRejection(error)) {
          await this.deps.store.markOutcomeUnknown(settlementOwner).catch(() => undefined);
        } else {
          await this.clearExact(settlementOwner);
        }
      }
    }
    if (scrubbed) {
      await this.finishBrowserRoundTrip(
        claimed.attempt,
        claimed.callback.scrubbedUrl,
        !isUnlockedCompletion(completion),
      ).catch(() => undefined);
    }
    else if (settlementError !== undefined
        && await this.closeOwnedTabAndProveGone(claimed.attempt)) {
      await this.clearExact(settlementOwner);
    }
  }

  async handleTabRemoved(tabId: number): Promise<void> {
    if (await this.cleanupExpiredAttemptIfPresent()) return;
    const current = await this.deps.store.read();
    if (!current) return;
    if (current.source.document?.tabId === tabId) {
      if (current.status === 'outcome_unknown') {
        await Promise.resolve(this.deps.browser.tabs.remove(current.tabId)).catch(() => undefined);
      } else {
        await this.retireChangedSource(current);
      }
      return;
    }
    if (current.status === 'outcome_unknown' || current.tabId !== tabId) return;
    if (current.status === 'submitting') {
      await this.deps.store.markOutcomeUnknown(current.owner);
      return;
    }
    await this.clearExact(current.owner);
  }

  async #runRestartReconciliation(): Promise<void> {
    const expired = await this.deps.store.claimExpiredRestartCleanup();
    if (expired) {
      await this.cleanupExpiredRestartAttempt(expired);
      return;
    }
    const claimed = await this.deps.store.claimRestartCleanup();
    if (!claimed) {
      const current = await this.deps.store.read();
      if (current?.status === 'outcome_unknown') {
        await this.finishBrowserRoundTrip(current, current.redirectUri, true).catch(() => undefined);
      }
      return;
    }
    let scrubbed: boolean;
    try {
      const frame = await this.deps.browser.webNavigation.getFrame({ tabId: claimed.tabId, frameId: 0 });
      if (
        !frame
        || frame.documentId !== claimed.documentId
        || !isConnectorNavigation(frame.url, claimed.redirectUri)
      ) throw new AppError('denied', 'The prior Duo callback document changed.');
      await this.scrub(claimed, frame.url, claimed.redirectUri);
      scrubbed = true;
    } catch {
      scrubbed = false;
    }
    if (scrubbed) {
      await this.clearExact(claimed.owner);
      await this.finishBrowserRoundTrip(claimed, claimed.redirectUri, true).catch(() => undefined);
      return;
    }
    if (await this.closeOwnedTabAndProveGone(claimed)) await this.clearExact(claimed.owner);
  }

  private async cleanupExpiredRestartAttempt(attempt: DuoAttempt): Promise<void> {
    let scrubbed = false;
    let documentId: string | undefined;
    try {
      const frame = await this.deps.browser.webNavigation.getFrame({ tabId: attempt.tabId, frameId: 0 });
      if (attempt.status === 'outcome_unknown') {
        if (frame?.documentId !== attempt.documentId || frame.url !== attempt.redirectUri) {
          throw new AppError('denied', 'The expired Duo callback document changed.');
        }
        documentId = attempt.documentId;
        scrubbed = true;
      } else if (frame?.documentId && isConnectorNavigation(frame.url, attempt.redirectUri)) {
        const callback = parseDuoCallback(frame.url, attempt);
        documentId = frame.documentId;
        await this.scrub(
          { tabId: attempt.tabId, documentId },
          frame.url,
          callback.scrubbedUrl,
        );
        scrubbed = true;
      }
    } catch {
      scrubbed = false;
    }
    if (scrubbed && documentId) {
      await this.deps.store.clearExpiredRestartCleanup(attempt.owner).catch(() => false);
      await this.finishBrowserRoundTrip({
        tabId: attempt.tabId,
        source: attempt.source,
        documentId,
      }, attempt.redirectUri, true).catch(() => undefined);
      return;
    }
    let closed = false;
    try {
      await this.deps.browser.tabs.remove(attempt.tabId);
      closed = true;
    } catch {
      try {
        await this.deps.browser.tabs.get(attempt.tabId);
      } catch {
        closed = true;
      }
    }
    if (closed) await this.deps.store.clearExpiredRestartCleanup(attempt.owner).catch(() => false);
  }

  private async cleanupExpiredAttemptIfPresent(): Promise<boolean> {
    const expired = await this.deps.store.claimExpiredRestartCleanup();
    if (!expired) return false;
    await this.cleanupExpiredRestartAttempt(expired);
    return true;
  }

  private async captureSourceContext(popupDocumentId: string): Promise<DuoSourceContext> {
    const documentId = boundedBrowserString(popupDocumentId, 512, 'Popup document id');
    const contexts = await this.deps.browser.runtime.getContexts({
      contextTypes: ['POPUP'],
      documentIds: [documentId],
      documentUrls: [this.deps.popupUrl],
    });
    if (contexts.length !== 1) throw new AppError('denied', 'The Popup source is unavailable.');
    const context = contexts[0]!;
    if (
      context.contextType !== 'POPUP'
      || context.documentId !== documentId
      || context.documentUrl !== this.deps.popupUrl
      || !Number.isSafeInteger(context.windowId)
      || (context.windowId as number) < 0
    ) throw new AppError('denied', 'The Popup source is invalid.');
    const windowId = context.windowId as number;
    const tabs = await this.deps.browser.tabs.query({ active: true, windowId });
    if (tabs.length !== 1) throw new AppError('denied', 'The active source tab is unavailable.');
    const tab = tabs[0]!;
    if (!Number.isSafeInteger(tab.id) || (tab.id as number) < 0
        || tab.windowId !== windowId) {
      throw new AppError('denied', 'The active source tab is invalid.');
    }
    let sourceDocument: DuoSourceDocument | undefined;
    try {
      const frame = await this.deps.browser.webNavigation.getFrame({ tabId: tab.id as number, frameId: 0 });
      if (frame && typeof frame.documentId === 'string'
          && typeof tab.url === 'string' && frame.url === tab.url) {
        sourceDocument = createSourceDocument({
          tabId: tab.id as number,
          windowId,
          documentId: frame.documentId,
          url: tab.url,
        });
        await this.assertSourceCurrent(sourceDocument, true);
      }
    } catch {
      sourceDocument = undefined;
    }
    return Object.freeze({
      windowId,
      ...(sourceDocument ? { document: sourceDocument } : {}),
    });
  }

  private async assertSourceCurrent(source: DuoSourceDocument, requireActive: boolean): Promise<void> {
    const tab = await this.deps.browser.tabs.get(source.tabId);
    const frame = await this.deps.browser.webNavigation.getFrame({ tabId: source.tabId, frameId: 0 });
    if (
      tab.id !== source.tabId
      || tab.windowId !== source.windowId
      || tab.url !== source.url
      || !frame
      || frame.documentId !== source.documentId
      || frame.url !== source.url
    ) throw new AppError('session_expired', 'The Duo source document changed.');
    if (requireActive) {
      const active = await this.deps.browser.tabs.query({ active: true, windowId: source.windowId });
      if (active.length !== 1 || active[0]?.id !== source.tabId) {
        throw new AppError('session_expired', 'The Duo source tab is no longer active.');
      }
    }
  }

  private async assertDuoTabCurrent(tabId: number, windowId: number, url: string): Promise<void> {
    const tab = await this.deps.browser.tabs.get(tabId);
    if (tab.id !== tabId || tab.windowId !== windowId || tab.url !== url || tab.active !== true) {
      throw new AppError('session_expired', 'The Duo tab changed during launch.');
    }
  }

  private async finishBrowserRoundTrip(
    attempt: Pick<DuoAttempt, 'tabId' | 'source'> & Partial<Pick<ClaimedDuoAttempt, 'documentId'>>,
    expectedDuoUrl: string | undefined,
    openPopup: boolean,
  ): Promise<void> {
    let sourceCurrent: boolean;
    try {
      const source = attempt.source.document;
      await this.deps.browser.windows.update(attempt.source.windowId, { focused: true });
      if (source) {
        await this.assertSourceCurrent(source, false);
        await this.deps.browser.tabs.update(source.tabId, { active: true });
        await this.assertSourceCurrent(source, true);
      }
      sourceCurrent = source !== undefined;
    } catch {
      sourceCurrent = false;
    }
    const duoCurrent = await this.isDuoDocumentCurrent(attempt, expectedDuoUrl);
    if (sourceCurrent && duoCurrent) {
      await Promise.resolve(this.deps.browser.tabs.remove(attempt.tabId)).catch(() => undefined);
      if (openPopup) {
        await Promise.resolve(this.deps.browser.action.openPopup())
          .catch(() => undefined);
      }
      return;
    }
    if (!attempt.source.document && duoCurrent) {
      await Promise.resolve(this.deps.browser.windows.update(attempt.source.windowId, { focused: true }))
        .catch(() => undefined);
      await Promise.resolve(this.deps.browser.tabs.remove(attempt.tabId)).catch(() => undefined);
      if (openPopup) await Promise.resolve(this.deps.browser.action.openPopup()).catch(() => undefined);
      return;
    }
    if (!sourceCurrent && openPopup && duoCurrent) {
      await this.deps.browser.tabs.update(attempt.tabId, { url: this.deps.popupUrl, active: true });
    }
  }

  private async isDuoDocumentCurrent(
    attempt: Pick<DuoAttempt, 'tabId'> & Partial<Pick<ClaimedDuoAttempt, 'documentId' | 'authUrl'>>,
    expectedUrl: string | undefined,
  ): Promise<boolean> {
    try {
      if (expectedUrl === undefined || attempt.documentId === undefined) {
        if (!attempt.authUrl) return false;
        const tab = await this.deps.browser.tabs.get(attempt.tabId);
        if (tab.id !== attempt.tabId || typeof tab.url !== 'string') return false;
        return new URL(tab.url).origin === new URL(attempt.authUrl).origin;
      }
      const frame = await this.deps.browser.webNavigation.getFrame({ tabId: attempt.tabId, frameId: 0 });
      return Boolean(
        frame
        && frame.documentId === attempt.documentId
        && frame.url === expectedUrl,
      );
    } catch {
      return false;
    }
  }

  private async retireChangedSource(
    attempt: Exclude<DuoAttempt, { readonly status: 'outcome_unknown' }>,
  ): Promise<void> {
    if (attempt.status === 'submitting') {
      await this.deps.store.markOutcomeUnknown(attempt.owner).catch(() => undefined);
      await Promise.resolve(this.deps.browser.tabs.remove(attempt.tabId)).catch(() => undefined);
    } else {
      if (await this.closeOwnedTabAndProveGone(attempt)) await this.clearExact(attempt.owner);
    }
  }

  private async closeOwnedTabAndProveGone(
    attempt: Pick<DuoAttempt, 'tabId' | 'source'>,
  ): Promise<boolean> {
    try {
      const tab = await this.deps.browser.tabs.get(attempt.tabId);
      if (tab.id !== attempt.tabId || tab.windowId !== attempt.source.windowId) return false;
    } catch {
      return true;
    }
    try {
      await this.deps.browser.tabs.remove(attempt.tabId);
    } catch {
      // A rejected removal still gets one exact absence check below.
    }
    try {
      await this.deps.browser.tabs.get(attempt.tabId);
      return false;
    } catch {
      return true;
    }
  }

  private async scrub(
    attempt: Pick<ClaimedDuoAttempt, 'tabId' | 'documentId'>,
    expected: string,
    replacement: string,
  ): Promise<void> {
    const result = await this.deps.browser.scripting.executeScript({
      target: { tabId: attempt.tabId, documentIds: [attempt.documentId] },
      func: scrubDuoCallback,
      args: [expected, replacement],
    });
    if (result.length !== 1 || result[0]?.result !== true) {
      throw new AppError('denied', 'The Duo callback could not be cleared safely.');
    }
  }

  private async clearExact(owner: Parameters<DuoAttemptStore['clear']>[0]): Promise<boolean> {
    try {
      if (await this.deps.store.clear(owner)) return true;
    } catch {
      // Retry once: storage may have committed the exact removal before rejecting its Promise.
    }
    try { return await this.deps.store.clear(owner); } catch { return false; }
  }

  private async cancelWaitingAttempt(
    attempt: Extract<DuoAttempt, { readonly status: 'waiting' }>,
  ): Promise<boolean> {
    const cancelled = await this.deps.store.cancelWaiting(attempt.owner);
    if (cancelled) {
      await this.finishBrowserRoundTrip(attempt, undefined, false).catch(() => undefined);
    }
    return cancelled;
  }
}

export function scrubDuoCallback(expected: string, replacement: string): boolean {
  if (globalThis.location.href !== expected) return false;
  globalThis.history.replaceState(null, '', replacement);
  return globalThis.location.href === replacement;
}

function isConnectorNavigation(actual: string, redirectUri: string): boolean {
  try {
    const callback = new URL(actual);
    const redirect = new URL(redirectUri);
    return callback.origin === redirect.origin && callback.pathname === redirect.pathname;
  } catch {
    return false;
  }
}

function matchesCancelInput(
  attempt: Extract<DuoAttempt, { readonly status: 'waiting' }>,
  input: DuoCancelInput,
): boolean {
  const challenge = attempt.owner.challenge;
  return input.flow === 'password'
    ? challenge.flow === 'password' && challenge.bindingId === input.continuationId
    : challenge.flow === 'deviceLogin'
      && challenge.generation === input.generation
      && challenge.provider === input.provider;
}

function createSourceDocument(input: {
  readonly tabId?: number;
  readonly windowId?: number;
  readonly documentId?: string;
  readonly url?: string;
}): DuoSourceDocument {
  if (!Number.isSafeInteger(input.tabId) || (input.tabId as number) < 0
      || !Number.isSafeInteger(input.windowId) || (input.windowId as number) < 0) {
    throw new AppError('denied', 'The Duo source tab is invalid.');
  }
  const documentId = boundedBrowserString(input.documentId, 512, 'Source document id');
  const urlValue = boundedBrowserString(input.url, 16 * 1024, 'Source URL');
  let url: URL;
  try { url = new URL(urlValue); } catch { throw new AppError('denied', 'The Duo source URL is invalid.'); }
  if (
    (url.protocol !== 'https:' && url.protocol !== 'http:')
    || url.username
    || url.password
    || url.toString() !== urlValue
  ) throw new AppError('denied', 'The Duo source URL is invalid.');
  return Object.freeze({
    tabId: input.tabId as number,
    windowId: input.windowId as number,
    documentId,
    url: urlValue,
  });
}

function boundedBrowserString(
  input: unknown,
  maxLength: number,
  name: string,
): string {
  if (typeof input !== 'string' || input.length === 0 || input.length > maxLength
      || input.trim() !== input || hasControlCharacter(input)) {
    throw new AppError('denied', `${name} is invalid.`);
  }
  return input;
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function isUnlockedCompletion(value: unknown): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return record.kind === 'unlocked' || record.status === 'unlocked';
}

function isDefiniteRejection(error: unknown): boolean {
  return error instanceof ApiHttpError
    && error.status >= 400 && error.status < 500
    && error.status !== 408 && error.status !== 429;
}

export function assertPreparedDuoOwner(actual: DuoChallengeOwner, expected: DuoChallengeOwner): void {
  if (!sameDuoChallengeOwner(actual, expected)) throw new AppError('session_expired', 'The Duo challenge changed.');
}
