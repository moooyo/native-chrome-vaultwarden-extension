import {
  ApiHttpError,
  ApiUnsupportedSsoAccountError,
} from '../core/api/client.js';
import { AppError } from '../core/errors.js';
import type { AuthResult, CompleteSsoLoginInput } from '../core/session/auth-service.js';
import {
  buildSsoLoginUrls,
  deriveSsoPkceS256Challenge,
  generateSsoPkceVerifier,
  generateSsoState,
  normalizeSsoEmail,
  parseSsoCallbackUrl,
  type SsoLoginPublicStatus,
} from '../core/session/sso-login.js';
import {
  SsoAttemptStore,
  type BoundSsoCallback,
  type ClaimedSsoAttempt,
  type SsoAttempt,
  type SsoAttemptBinding,
  type SsoSourceContext,
  type SsoSourceDocument,
  type WaitingSsoAttempt,
} from './sso-attempt-store.js';
import type { SsoLaunchAuthorization } from './sso-capability.js';

export interface SsoNavigationDetails {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId?: string;
  readonly url: string;
}

export interface SsoBrowserDeps {
  readonly store: SsoAttemptStore;
  readonly authorize: () => Promise<SsoLaunchAuthorization>;
  readonly auth: {
    completeSsoLogin(input: CompleteSsoLoginInput): Promise<AuthResult>;
    getPendingSsoHandoff(): Promise<{
      readonly attemptId: string;
      readonly attemptGeneration: number;
      readonly serverUrl: string;
      readonly identityUrl: string;
      readonly email: string;
    } | undefined>;
  };
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
      remove(tabId: number): PromiseLike<void>;
      update(tabId: number, input: {
        readonly url?: string;
        readonly active?: boolean;
      }): PromiseLike<unknown>;
    };
    readonly windows: {
      update(windowId: number, input: { readonly focused: true }): PromiseLike<unknown>;
    };
    readonly webNavigation: {
      getFrame(input: {
        readonly tabId: number;
        readonly frameId: 0;
      }): PromiseLike<{ readonly documentId?: string; readonly url: string } | null>;
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

/** Owns the browser tab and the one-shot transition from an SSO callback to AuthService. */
export class SsoBrowserCoordinator {
  #terminal: SsoLoginPublicStatus | undefined;
  #restartReconciliation: Promise<void> | undefined;

  constructor(private readonly deps: SsoBrowserDeps) {
    assertExtensionPopupUrl(deps.popupUrl);
  }

  reconcileRestart(): Promise<void> {
    if (this.#restartReconciliation) return this.#restartReconciliation;
    const operation = this.#runRestartReconciliation();
    const tracked = operation.finally(() => {
      if (this.#restartReconciliation === tracked) this.#restartReconciliation = undefined;
    });
    this.#restartReconciliation = tracked;
    return tracked;
  }

  async begin(
    emailInput: string,
    popupDocumentId: string,
    organizationIdentifier?: string,
  ): Promise<SsoLoginPublicStatus> {
    const email = normalizeSsoEmail(emailInput);
    await this.cleanupExpiredAttemptIfPresent();
    await this.reconcileHandoff();
    const source = await this.captureSourceContext(popupDocumentId);
    if (await this.deps.store.read()) {
      throw new AppError('denied', 'An SSO sign-in is already active.');
    }
    this.#terminal = undefined;
    const authorization = await this.deps.authorize();
    authorization.assertCurrent();
    const verifier = generateSsoPkceVerifier();
    const state = generateSsoState();
    const codeChallenge = await deriveSsoPkceS256Challenge(verifier);
    authorization.assertCurrent();
    const urls = buildSsoLoginUrls({
      vaultUrl: authorization.vaultUrl,
      identityUrl: authorization.identityUrl,
      ...(authorization.ssoUrl ? { ssoUrl: authorization.ssoUrl } : {}),
      email,
      state,
      codeChallenge,
      ...(organizationIdentifier === undefined ? {} : { organizationIdentifier }),
    });
    const tab = await this.deps.browser.tabs.create({
      url: 'about:blank',
      active: true,
      windowId: source.windowId,
    });
    if (!Number.isSafeInteger(tab.id) || (tab.id as number) < 0) {
      throw new AppError('error', 'The browser did not create an SSO tab.');
    }
    const tabId = tab.id as number;
    let created: SsoAttempt | undefined;
    try {
      await this.assertSsoTabCurrent(tabId, source.windowId, 'about:blank');
      authorization.assertCurrent();
      const attempt = await this.deps.store.create({
        serverUrl: authorization.serverUrl,
        identityUrl: authorization.identityUrl,
        serverGeneration: authorization.serverGeneration,
        capabilityGeneration: authorization.capabilityGeneration,
        emailIntent: email,
        tabId,
        connectorOrigin: urls.connectorOrigin,
        connectorPath: urls.connectorPath,
        state,
        verifier,
        redirectUri: urls.connectorCallbackUrl,
        emailTwoFactorMode: authorization.emailTwoFactorMode,
        source,
        ...(organizationIdentifier === undefined ? {} : { organizationIdentifier }),
      });
      created = attempt;
      authorization.assertCurrent();
      await this.deps.browser.tabs.update(tabId, { url: urls.startUrl, active: true });
      authorization.assertCurrent();
      await this.assertSsoTabCurrent(tabId, source.windowId, urls.startUrl);
      return projectStatus(attempt);
    } catch (error) {
      if (created) await this.deps.store.clear(created.owner).catch(() => false);
      await Promise.resolve(this.deps.browser.tabs.remove(tabId)).catch(() => undefined);
      throw error;
    }
  }

  async status(expected?: SsoAttemptBinding): Promise<SsoLoginPublicStatus> {
    await this.cleanupExpiredAttemptIfPresent();
    await this.reconcileHandoff();
    const current = await this.deps.store.read();
    if (expected && (!current || !matchesAttemptBinding(current, expected))) {
      return Object.freeze({ status: 'none' });
    }
    return current ? projectStatus(current) : this.#terminal ?? Object.freeze({ status: 'none' });
  }

  async cancel(expected: SsoAttemptBinding): Promise<boolean> {
    await this.cleanupExpiredAttemptIfPresent();
    await this.reconcileHandoff();
    const current = await this.deps.store.read();
    if (!current || current.status !== 'waiting' || !matchesAttemptBinding(current, expected)) return false;
    this.#terminal = undefined;
    return this.cancelWaiting(current);
  }

  async cancelCurrent(): Promise<boolean> {
    await this.cleanupExpiredAttemptIfPresent();
    await this.reconcileHandoff();
    const current = await this.deps.store.read();
    this.#terminal = undefined;
    return current?.status === 'waiting' ? this.cancelWaiting(current) : false;
  }

  async reconcileHandoff(): Promise<boolean> {
    await this.cleanupExpiredAttemptIfPresent();
    const handoff = await this.deps.auth.getPendingSsoHandoff();
    return handoff ? this.deps.store.completeHandoff(handoff) : false;
  }

  async handleNavigation(details: SsoNavigationDetails): Promise<void> {
    if (
      details.frameId !== 0
      || !Number.isSafeInteger(details.tabId)
      || details.tabId < 0
    ) return;
    if (await this.cleanupExpiredAttemptIfPresent()) return;
    const current = await this.deps.store.read();
    const sourceDocument = current?.status === 'outcome_unknown'
      ? undefined
      : current?.source.document;
    if (current && sourceDocument?.tabId === details.tabId) {
      if (details.documentId !== sourceDocument.documentId || details.url !== sourceDocument.url) {
        await this.deps.store.dropSourceDocument(current.owner).catch(() => false);
      }
      return;
    }
    if (typeof details.documentId !== 'string' || !details.documentId) return;
    if (!current || current.status !== 'waiting' || current.tabId !== details.tabId) return;
    if (!isExpectedConnectorNavigation(current, details.url)) return;

    let bound;
    try {
      bound = await this.deps.store.bindCallbackDocument(current.owner, {
        tabId: details.tabId,
        documentId: details.documentId,
        callbackUrl: details.url,
      });
    } catch {
      await this.failBeforeExchange(
        current,
        { tabId: details.tabId, callbackDocumentId: details.documentId },
        details.url,
        'The SSO callback was rejected.',
      );
      return;
    }
    if (!bound) return;
    await this.processBoundCallback(bound, details.url);
  }

  private async processBoundCallback(bound: BoundSsoCallback, callbackUrl: string): Promise<void> {
    const claimed = await this.deps.store.claim(bound.attempt.owner);
    if (!claimed) return;

    let callbackScrubbed = false;
    let grantPrepared = false;
    let grantDispatched = false;
    let settlementOwner = claimed.owner;
    let settlementError: unknown;
    try {
      await this.scrubCallback(claimed, callbackUrl, bound.scrubbedUrl);
      callbackScrubbed = true;
      const authorization = await this.deps.authorize();
      assertAttemptAuthorization(claimed, authorization);
      assertIssuer(bound.iss, claimed);
      authorization.assertCurrent();
      await this.deps.auth.completeSsoLogin({
        ssoAttemptId: claimed.owner.attemptId,
        ssoAttemptGeneration: claimed.owner.generation,
        serverUrl: claimed.owner.serverUrl,
        identityUrl: claimed.owner.identityUrl,
        email: claimed.owner.emailIntent,
        code: bound.code,
        codeVerifier: claimed.verifier,
        redirectUri: claimed.redirectUri,
        emailTwoFactorMode: claimed.emailTwoFactorMode,
        assertCurrent: authorization.assertCurrent,
        onGrantStarted: async () => {
          authorization.assertCurrent();
          const submitting = await this.deps.store.startSubmission(claimed.owner);
          if (!submitting) throw new AppError('session_expired', 'The SSO callback is no longer current.');
          settlementOwner = submitting.owner;
          authorization.assertCurrent();
          grantPrepared = true;
        },
        onGrantDispatched: () => { grantDispatched = true; },
      });
      if (!grantPrepared) throw new AppError('denied', 'The SSO grant did not start safely.');
      await this.deps.store.clear(settlementOwner);
      this.#terminal = Object.freeze({ status: 'none' });
    } catch (error) {
      settlementError = error;
      if (callbackScrubbed) await this.settleExchangeFailure(settlementOwner, grantDispatched, error);
    }
    if (callbackScrubbed) {
      await this.finishBrowserRoundTrip(claimed, bound.scrubbedUrl, true).catch(() => undefined);
    } else {
      const retired = await this.closeUnscrubbedCallback(claimed, callbackUrl).catch(() => false);
      if (retired) {
        await this.deps.store.clear(settlementOwner).catch(() => false);
        this.#terminal = Object.freeze({
          status: 'error',
          message: publicSsoError(settlementError),
        });
      }
    }
  }

  private async settleExchangeFailure(
    owner: ClaimedSsoAttempt['owner'],
    grantDispatched: boolean,
    error: unknown,
  ): Promise<void> {
    if (grantDispatched && !isDefiniteExchangeRejection(error)) {
      await this.deps.store.markOutcomeUnknown(owner).catch(() => undefined);
      this.#terminal = undefined;
      return;
    }
    await this.deps.store.clear(owner).catch(() => false);
    this.#terminal = Object.freeze({
      status: 'error',
      message: publicSsoError(error),
    });
  }

  async #runRestartReconciliation(): Promise<void> {
    const cleanup = await this.deps.store.claimRestartCleanup();
    if (cleanup?.expired) {
      await this.cleanupExpiredRestartAttempt(cleanup.attempt);
      return;
    }
    const claimed = cleanup?.attempt;
    if (claimed && (claimed.status === 'claimed' || claimed.status === 'submitting')) {
      const handoff = await this.deps.auth.getPendingSsoHandoff();
      let callbackUrl = claimed.redirectUri;
      let scrubbed: boolean;
      try {
        const frame = await this.deps.browser.webNavigation.getFrame({
          tabId: claimed.tabId,
          frameId: 0,
        });
        if (!frame || frame.documentId !== claimed.callbackDocumentId) {
          throw new AppError('denied', 'The prior SSO callback document changed.');
        }
        callbackUrl = frame.url;
        const callback = parseSsoCallbackUrl(frame.url, {
          redirectUri: claimed.redirectUri,
          state: claimed.state,
        });
        assertIssuer(callback.iss, claimed);
        await this.scrubCallback(claimed, frame.url, callback.scrubbedUrl);
        callbackUrl = callback.scrubbedUrl;
        scrubbed = true;
      } catch {
        scrubbed = false;
      }
      if (!scrubbed) {
        const retired = await this.closeUnscrubbedCallback(claimed, callbackUrl).catch(() => false);
        if (!retired) return;
      }
      const handoffCompleted = handoff
        ? await this.deps.store.completeHandoff(handoff)
        : false;
      if (!handoffCompleted) {
        if (claimed.status === 'submitting') {
          await this.deps.store.markOutcomeUnknown(claimed.owner).catch(() => undefined);
        } else {
          await this.deps.store.clear(claimed.owner).catch(() => false);
        }
      }
      if (scrubbed) {
        await this.finishBrowserRoundTrip(claimed, callbackUrl, true).catch(() => undefined);
      }
      return;
    }

    const current = await this.deps.store.read();
    if (!current || current.status !== 'waiting') return;
    let frame: { readonly documentId?: string; readonly url: string } | null;
    try {
      frame = await this.deps.browser.webNavigation.getFrame({
        tabId: current.tabId,
        frameId: 0,
      });
    } catch {
      frame = null;
    }
    if (!frame) return;
    if (!isExpectedConnectorNavigation(current, frame.url)) {
      if (current.callbackDocumentId) await this.deps.store.clear(current.owner).catch(() => false);
      return;
    }
    if (typeof frame.documentId !== 'string' || !frame.documentId) return;
    if (current.callbackDocumentId && frame.documentId !== current.callbackDocumentId) {
      await this.deps.store.clear(current.owner).catch(() => false);
      return;
    }
    let bound: BoundSsoCallback | undefined;
    try {
      bound = await this.deps.store.bindCallbackDocument(current.owner, {
        tabId: current.tabId,
        documentId: frame.documentId,
        callbackUrl: frame.url,
      });
    } catch {
      const retired = await this.closeUnscrubbedCallback(
        { tabId: current.tabId, callbackDocumentId: frame.documentId },
        frame.url,
      ).catch(() => false);
      if (retired) await this.deps.store.clear(current.owner).catch(() => false);
      return;
    }
    if (bound) await this.processBoundCallback(bound, frame.url);
  }

  private async cleanupExpiredRestartAttempt(attempt: SsoAttempt): Promise<void> {
    let frame: { readonly documentId?: string; readonly url: string } | null;
    try {
      frame = await this.deps.browser.webNavigation.getFrame({ tabId: attempt.tabId, frameId: 0 });
    } catch {
      frame = null;
    }
    let scrubbedUrl: string | undefined;
    if (attempt.status === 'outcome_unknown') {
      if (frame?.documentId === attempt.callbackDocumentId && frame.url === attempt.redirectUri) {
        scrubbedUrl = attempt.redirectUri;
      }
    } else if (frame?.documentId
        && (!attempt.callbackDocumentId || frame.documentId === attempt.callbackDocumentId)
        && isExpectedConnectorNavigation(attempt, frame.url)) {
      try {
        const callback = parseSsoCallbackUrl(frame.url, {
          redirectUri: attempt.redirectUri,
          state: attempt.state,
        });
        assertIssuer(callback.iss, attempt);
        await this.scrubCallback(
          { tabId: attempt.tabId, callbackDocumentId: frame.documentId },
          frame.url,
          callback.scrubbedUrl,
        );
        scrubbedUrl = callback.scrubbedUrl;
      } catch {
        scrubbedUrl = undefined;
      }
    }
    if (scrubbedUrl && attempt.status !== 'outcome_unknown') {
      await this.deps.store.clearRestartCleanup(attempt.owner).catch(() => false);
      await this.finishBrowserRoundTrip({
        tabId: attempt.tabId,
        callbackDocumentId: frame!.documentId!,
        source: attempt.source,
      }, scrubbedUrl, true).catch(() => undefined);
      return;
    }
    if (scrubbedUrl && attempt.status === 'outcome_unknown') {
      await this.deps.store.clearRestartCleanup(attempt.owner).catch(() => false);
      await this.finishBrowserRoundTrip(attempt, scrubbedUrl, true).catch(() => undefined);
      return;
    }
    const callbackDocumentId = attempt.callbackDocumentId;
    const retired = callbackDocumentId
      ? await this.closeUnscrubbedCallback({
          tabId: attempt.tabId,
          callbackDocumentId,
        }, frame?.url ?? attempt.redirectUri).catch(() => false)
      : await this.removeOwnedTabIfPresent(attempt.tabId);
    if (retired) await this.deps.store.clearRestartCleanup(attempt.owner).catch(() => false);
  }

  private async cleanupExpiredAttemptIfPresent(): Promise<boolean> {
    const cleanup = await this.deps.store.claimRestartCleanup();
    if (!cleanup?.expired) return false;
    await this.cleanupExpiredRestartAttempt(cleanup.attempt);
    return true;
  }

  async handleTabRemoved(tabId: number): Promise<void> {
    if (!Number.isSafeInteger(tabId) || tabId < 0) return;
    if (await this.cleanupExpiredAttemptIfPresent()) return;
    const current = await this.deps.store.read();
    if (!current) return;
    if (current.status !== 'outcome_unknown' && current.source.document?.tabId === tabId) {
      await this.deps.store.dropSourceDocument(current.owner).catch(() => false);
      return;
    }
    if (current.tabId !== tabId || current.status === 'outcome_unknown') return;
    if (current.status === 'submitting') {
      await this.deps.store.markOutcomeUnknown(current.owner).catch(() => undefined);
    } else {
      await this.deps.store.clear(current.owner);
    }
  }

  private async failBeforeExchange(
    attempt: SsoAttempt,
    callbackDocument: Pick<ClaimedSsoAttempt, 'tabId' | 'callbackDocumentId'>,
    callbackUrl: string,
    message: string,
  ): Promise<void> {
    this.#terminal = Object.freeze({ status: 'error', message });
    if (await this.closeUnscrubbedCallback(callbackDocument, callbackUrl).catch(() => false)) {
      await this.deps.store.clear(attempt.owner).catch(() => false);
    }
  }

  private async scrubCallback(
    attempt: Pick<ClaimedSsoAttempt, 'tabId' | 'callbackDocumentId'>,
    callbackUrl: string,
    scrubbedUrl: string,
  ): Promise<void> {
    const results = await this.deps.browser.scripting.executeScript({
      target: { tabId: attempt.tabId, documentIds: [attempt.callbackDocumentId] },
      func: scrubExactCallback,
      args: [callbackUrl, scrubbedUrl],
    });
    if (results.length !== 1 || results[0]?.result !== true) {
      throw new AppError('denied', 'The SSO callback could not be cleared safely.');
    }
  }

  private async captureSourceContext(popupDocumentId: unknown): Promise<SsoSourceContext> {
    const documentId = boundedBrowserString(popupDocumentId, 'Popup document id', 512);
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
    if (!Number.isSafeInteger(tab.id) || (tab.id as number) < 0 || tab.windowId !== windowId) {
      throw new AppError('denied', 'The active source tab is invalid.');
    }
    let sourceDocument: SsoSourceDocument | undefined;
    try {
      const frame = await this.deps.browser.webNavigation.getFrame({
        tabId: tab.id as number,
        frameId: 0,
      });
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
      popupDocumentId: documentId,
      windowId,
      ...(sourceDocument ? { document: sourceDocument } : {}),
    });
  }

  private async assertSourceCurrent(source: SsoSourceDocument, requireActive: boolean): Promise<void> {
    const tab = await this.deps.browser.tabs.get(source.tabId);
    const frame = await this.deps.browser.webNavigation.getFrame({ tabId: source.tabId, frameId: 0 });
    if (
      tab.id !== source.tabId
      || tab.windowId !== source.windowId
      || tab.url !== source.url
      || !frame
      || frame.documentId !== source.documentId
      || frame.url !== source.url
    ) throw new AppError('session_expired', 'The SSO source document changed.');
    if (requireActive) {
      const active = await this.deps.browser.tabs.query({ active: true, windowId: source.windowId });
      if (active.length !== 1 || active[0]?.id !== source.tabId) {
        throw new AppError('session_expired', 'The SSO source tab is no longer active.');
      }
    }
  }

  private async assertSsoTabCurrent(tabId: number, windowId: number, url: string): Promise<void> {
    const tab = await this.deps.browser.tabs.get(tabId);
    if (tab.id !== tabId || tab.windowId !== windowId || tab.url !== url || tab.active !== true) {
      throw new AppError('session_expired', 'The SSO tab changed during launch.');
    }
  }

  private async finishBrowserRoundTrip(
    attempt: Pick<ClaimedSsoAttempt, 'tabId' | 'callbackDocumentId' | 'source'>,
    scrubbedUrl: string,
    openPopup: boolean,
  ): Promise<void> {
    let sourceCurrent = false;
    try {
      const source = attempt.source.document;
      await this.deps.browser.windows.update(attempt.source.windowId, { focused: true });
      if (source) {
        await this.assertSourceCurrent(source, false);
        await this.deps.browser.tabs.update(source.tabId, { active: true });
        await this.assertSourceCurrent(source, true);
        sourceCurrent = true;
      }
    } catch {
      sourceCurrent = false;
    }
    const callbackCurrent = await this.isCallbackDocumentCurrent(attempt, scrubbedUrl);
    if ((sourceCurrent || !attempt.source.document) && callbackCurrent) {
      await Promise.resolve(this.deps.browser.tabs.remove(attempt.tabId)).catch(() => undefined);
      if (openPopup) await Promise.resolve(this.deps.browser.action.openPopup()).catch(() => undefined);
      return;
    }
    if (!sourceCurrent && openPopup && callbackCurrent) {
      await this.deps.browser.tabs.update(attempt.tabId, { url: this.deps.popupUrl, active: true });
    }
  }

  private async isCallbackDocumentCurrent(
    attempt: Pick<ClaimedSsoAttempt, 'tabId' | 'callbackDocumentId'>,
    expectedUrl: string,
  ): Promise<boolean> {
    try {
      const frame = await this.deps.browser.webNavigation.getFrame({ tabId: attempt.tabId, frameId: 0 });
      return Boolean(
        frame
        && frame.documentId === attempt.callbackDocumentId
        && frame.url === expectedUrl,
      );
    } catch {
      return false;
    }
  }

  private async cancelWaiting(attempt: WaitingSsoAttempt): Promise<boolean> {
    const cleared = await this.deps.store.cancelWaiting(attempt.owner);
    if (cleared) {
      await Promise.resolve(this.deps.browser.tabs.remove(attempt.tabId)).catch(() => undefined);
      try {
        await this.deps.browser.windows.update(attempt.source.windowId, { focused: true });
        if (attempt.source.document) {
          await this.assertSourceCurrent(attempt.source.document, false);
          await this.deps.browser.tabs.update(attempt.source.document.tabId, { active: true });
        }
      } catch {
        // Cancellation remains authoritative even if the former source cannot be restored.
      }
    }
    return cleared;
  }

  private async closeUnscrubbedCallback(
    attempt: Pick<ClaimedSsoAttempt, 'tabId' | 'callbackDocumentId'>,
    callbackUrl: string,
  ): Promise<boolean> {
    try {
      const frame = await this.deps.browser.webNavigation.getFrame({
        tabId: attempt.tabId,
        frameId: 0,
      });
      if (frame && (frame.documentId !== attempt.callbackDocumentId || frame.url !== callbackUrl)) {
        return true;
      }
    } catch {
      // Browser uncertainty falls through to an exact owned-tab close attempt.
    }
    try {
      const tab = await this.deps.browser.tabs.get(attempt.tabId);
      if (tab.id !== attempt.tabId) return false;
      await this.deps.browser.tabs.remove(attempt.tabId);
    } catch {
      try {
        await this.deps.browser.tabs.get(attempt.tabId);
        return false;
      } catch {
        return true;
      }
    }
    try {
      await this.deps.browser.tabs.get(attempt.tabId);
      return false;
    } catch {
      return true;
    }
  }

  private async removeOwnedTabIfPresent(tabId: number): Promise<boolean> {
    try {
      const tab = await this.deps.browser.tabs.get(tabId);
      if (tab.id !== tabId) return false;
      await this.deps.browser.tabs.remove(tabId);
    } catch {
      // A missing tab proves there is no browser document left to scrub or close.
      return true;
    }
    try {
      await this.deps.browser.tabs.get(tabId);
      return false;
    } catch {
      return true;
    }
  }
}

/** Runs in the exact browser-owned callback document selected by executeScript. */
export function scrubExactCallback(expected: string, replacement: string): boolean {
  if (globalThis.location.href !== expected) return false;
  globalThis.history.replaceState(null, '', replacement);
  return globalThis.location.href === replacement;
}

function projectStatus(attempt: SsoAttempt): SsoLoginPublicStatus {
  if (attempt.status === 'outcome_unknown') {
    return Object.freeze({
      status: attempt.status,
      attemptId: attempt.owner.attemptId,
      generation: attempt.owner.attemptGeneration,
      email: attempt.owner.emailIntent,
      createdAt: attempt.createdAt,
      expiresAt: attempt.expiresAt,
      terminalAt: attempt.terminalAt,
    });
  }
  return Object.freeze({
    status: attempt.status === 'waiting' ? 'waiting' : 'processing',
    attemptId: attempt.owner.attemptId,
    generation: attempt.owner.attemptGeneration,
    email: attempt.owner.emailIntent,
    expiresAt: attempt.expiresAt,
  });
}

function matchesAttemptBinding(attempt: SsoAttempt, expected: SsoAttemptBinding): boolean {
  return typeof expected?.attemptId === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(expected.attemptId)
    && Number.isSafeInteger(expected.generation)
    && expected.generation > 0
    && attempt.owner.attemptId === expected.attemptId
    && attempt.owner.attemptGeneration === expected.generation;
}

function createSourceDocument(input: SsoSourceDocument): SsoSourceDocument {
  if (!Number.isSafeInteger(input.tabId) || input.tabId < 0
      || !Number.isSafeInteger(input.windowId) || input.windowId < 0) {
    throw new AppError('denied', 'The SSO source browser identity is invalid.');
  }
  const documentId = boundedBrowserString(input.documentId, 'Source document id', 512);
  const urlValue = boundedBrowserString(input.url, 'Source URL', 16 * 1024);
  let url: URL;
  try { url = new URL(urlValue); } catch { throw new AppError('denied', 'The SSO source URL is invalid.'); }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:')
      || url.username || url.password || url.toString() !== urlValue) {
    throw new AppError('denied', 'The SSO source URL is invalid.');
  }
  return Object.freeze({
    tabId: input.tabId,
    windowId: input.windowId,
    documentId,
    url: urlValue,
  });
}

function boundedBrowserString(input: unknown, name: string, maximum: number): string {
  if (typeof input !== 'string' || input.length === 0 || input.length > maximum
      || input.trim() !== input) {
    throw new AppError('denied', `${name} is invalid.`);
  }
  for (let index = 0; index < input.length; index += 1) {
    const code = input.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) throw new AppError('denied', `${name} is invalid.`);
  }
  return input;
}

function isExpectedConnectorNavigation(
  attempt: Pick<WaitingSsoAttempt, 'connectorOrigin' | 'connectorPath'>,
  value: string,
): boolean {
  try {
    const url = new URL(value);
    return url.origin === attempt.connectorOrigin && url.pathname === attempt.connectorPath;
  } catch {
    return false;
  }
}

function assertAttemptAuthorization(
  attempt: ClaimedSsoAttempt,
  authorization: SsoLaunchAuthorization,
): void {
  authorization.assertCurrent();
  if (
    authorization.serverUrl !== attempt.owner.serverUrl
    || authorization.identityUrl !== attempt.owner.identityUrl
    || authorization.serverGeneration !== attempt.owner.serverGeneration
    || authorization.emailTwoFactorMode !== attempt.emailTwoFactorMode
    || attempt.redirectUri !== new URL('sso-connector.html', authorization.vaultUrl).toString()
  ) throw new AppError('session_expired', 'The SSO server environment changed.');
}

function assertIssuer(
  issuer: string | undefined,
  attempt: Pick<ClaimedSsoAttempt, 'owner'>,
): void {
  if (!issuer) return;
  const actual = withoutTrailingSlash(new URL(issuer));
  const allowed = [
    withoutTrailingSlash(new URL(attempt.owner.serverUrl)),
    withoutTrailingSlash(new URL(attempt.owner.identityUrl)),
  ];
  if (!allowed.includes(actual)) {
    throw new AppError('denied', 'The SSO callback issuer is invalid.');
  }
}

function withoutTrailingSlash(url: URL): string {
  url.pathname = url.pathname.replace(/\/+$/u, '');
  return url.toString();
}

function isDefiniteExchangeRejection(error: unknown): boolean {
  return error instanceof ApiUnsupportedSsoAccountError
    || error instanceof ApiHttpError
      && error.status >= 400
      && error.status < 500
      && error.status !== 408
      && error.status !== 429;
}

function publicSsoError(error: unknown): string {
  if (error instanceof ApiUnsupportedSsoAccountError) return error.message;
  if (error instanceof AppError && error.code !== 'outcome_unknown') return error.message;
  return 'SSO sign-in could not be completed.';
}

function assertExtensionPopupUrl(value: string): void {
  const url = new URL(value);
  if (
    url.protocol !== 'chrome-extension:'
    || url.username
    || url.password
    || url.search
    || url.hash
    || !url.pathname.endsWith('/ui/popup/popup.html')
  ) throw new TypeError('SSO popup URL is invalid');
}
