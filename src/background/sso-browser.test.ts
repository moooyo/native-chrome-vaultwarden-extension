import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
      session: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
    },
  },
}));

import { ApiHttpError, ApiUnsupportedSsoAccountError } from '../core/api/client.js';
import { AppError } from '../core/errors.js';
import { createMemoryStore } from '../platform/store.js';
import { SsoAttemptStore, type WaitingSsoAttempt } from './sso-attempt-store.js';
import { SsoBrowserCoordinator, type SsoNavigationDetails } from './sso-browser.js';
import type { SsoLaunchAuthorization } from './sso-capability.js';

const SERVER = 'https://vault.example/tenant/';
const VAULT = 'https://vault.example/tenant/vault/';
const IDENTITY = 'https://vault.example/tenant/identity/';
const SSO = 'https://vault.example/tenant/sso/';
const POPUP = 'chrome-extension://extension-id/ui/popup/popup.html';
const EMAIL = 'user@example.com';
const ATTEMPT_ID = '11111111-1111-4111-8111-111111111111';
const WORKER_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const RESTARTED_WORKER_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const POPUP_DOCUMENT = 'popup-document';
const SOURCE_WINDOW = 7;
const SOURCE_TAB = 8;
const SOURCE_DOCUMENT = 'source-document';
const SOURCE_URL = 'https://app.example/login';

describe('SsoBrowserCoordinator begin lifecycle', () => {
  it('creates about:blank, persists the attempt, then navigates to the SSO start URL', async () => {
    const harness = makeHarness();
    const originalCreate = harness.store.create.bind(harness.store);
    vi.spyOn(harness.store, 'create').mockImplementation(async (input) => {
      harness.events.push('store:create');
      return originalCreate(input);
    });

    const status = await harness.coordinator.begin(' User@Example.COM ', POPUP_DOCUMENT);

    expect(status).toMatchObject({ status: 'waiting', email: EMAIL });
    expect(harness.events.slice(0, 3)).toEqual([
      'tabs:create:about:blank',
      'store:create',
      'tabs:update:start',
    ]);
    const waiting = await requireWaiting(harness.store);
    expect(waiting.owner).toMatchObject({
      serverUrl: SERVER,
      identityUrl: IDENTITY,
      serverGeneration: 7,
      emailIntent: EMAIL,
    });
    expect(harness.tabsUpdate.mock.calls[0]?.[1].url).toContain('#/sso?');
  });

  it('persists a server-required organization identifier before navigation', async () => {
    const harness = makeHarness();

    await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT, 'expected-org');

    const waiting = await requireWaiting(harness.store);
    expect(waiting.organizationIdentifier).toBe('expected-org');
    expect(harness.tabsUpdate.mock.calls[0]?.[1].url).toContain('identifier=expected-org');
  });

  it('exactly clears the persisted attempt when the initial tab update fails', async () => {
    const harness = makeHarness({ failStartUpdate: true });
    const clear = vi.spyOn(harness.store, 'clear');

    await expect(harness.coordinator.begin(EMAIL, POPUP_DOCUMENT)).rejects.toThrow('start update failed');

    expect(clear).toHaveBeenCalledOnce();
    await expect(harness.store.read()).resolves.toBeUndefined();
    expect(harness.tabsRemove).toHaveBeenCalledWith(42);
  });

  it('exactly clears the attempt when authorization expires after the start update', async () => {
    let assertions = 0;
    const harness = makeHarness({
      assertCurrent: () => {
        assertions += 1;
        if (assertions === 5) throw new AppError('denied', 'authorization expired');
      },
    });
    const clear = vi.spyOn(harness.store, 'clear');

    await expect(harness.coordinator.begin(EMAIL, POPUP_DOCUMENT)).rejects.toThrow('authorization expired');

    expect(harness.tabsUpdate).toHaveBeenCalledOnce();
    expect(clear).toHaveBeenCalledOnce();
    await expect(harness.store.read()).resolves.toBeUndefined();
    expect(harness.tabsRemove).toHaveBeenCalledWith(42);
  });
});

describe('SsoBrowserCoordinator callback boundary', () => {
  it('ignores off-path and off-origin navigation without consuming the waiting attempt', async () => {
    for (const location of ['origin', 'path'] as const) {
      const harness = makeHarness();
      await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
      const waiting = await requireWaiting(harness.store);
      const url = location === 'origin'
        ? `https://evil.example${waiting.connectorPath}?code=code&state=${encodeURIComponent(waiting.state)}`
        : `${waiting.connectorOrigin}/wrong/sso-connector.html?code=code&state=${encodeURIComponent(waiting.state)}`;

      await harness.coordinator.handleNavigation(details(url));

      expect(harness.completeSsoLogin).not.toHaveBeenCalled();
      await expect(harness.store.read()).resolves.toMatchObject({ status: 'waiting' });
    }
  });

  it('rejects wrong state, document, and issuer without exchanging', async () => {
    const stateHarness = makeHarness();
    await stateHarness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const stateWaiting = await requireWaiting(stateHarness.store);
    await stateHarness.coordinator.handleNavigation(details(callbackUrl(stateWaiting, {
      state: `${stateWaiting.state}x`,
    })));
    expect(stateHarness.completeSsoLogin).not.toHaveBeenCalled();

    const issuerHarness = makeHarness();
    await issuerHarness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const issuerWaiting = await requireWaiting(issuerHarness.store);
    await issuerHarness.coordinator.handleNavigation(details(callbackUrl(issuerWaiting, {
      issuer: 'https://evil.example/',
    })));
    expect(issuerHarness.completeSsoLogin).not.toHaveBeenCalled();

    const documentHarness = makeHarness();
    await documentHarness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const documentWaiting = await requireWaiting(documentHarness.store);
    const callback = callbackUrl(documentWaiting);
    const bound = await documentHarness.store.bindCallbackDocument(documentWaiting.owner, {
      tabId: 42,
      documentId: 'document-a',
      callbackUrl: callback,
    });
    expect(bound).toBeDefined();
    await documentHarness.coordinator.handleNavigation({
      ...details(callback),
      documentId: 'document-b',
    });
    expect(documentHarness.completeSsoLogin).not.toHaveBeenCalled();
  });

  it('claims an exact callback document once under concurrent delivery', async () => {
    const harness = makeHarness();
    await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const waiting = await requireWaiting(harness.store);
    const callback = callbackUrl(waiting);
    const navigation = details(callback);
    harness.setFrame(callback, navigation.documentId!);

    await Promise.all([
      harness.coordinator.handleNavigation(navigation),
      harness.coordinator.handleNavigation(navigation),
    ]);

    expect(harness.completeSsoLogin).toHaveBeenCalledOnce();
    await expect(harness.store.read()).resolves.toBeUndefined();
  });

  it('returns busy instead of replacing an active attempt from a stale begin', async () => {
    const harness = makeHarness();
    await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const first = await requireWaiting(harness.store);

    await expect(harness.coordinator.begin(EMAIL, POPUP_DOCUMENT)).rejects.toThrow(/already active/);
    await expect(harness.store.read()).resolves.toEqual(first);
    expect(harness.completeSsoLogin).not.toHaveBeenCalled();
  });

  it('binds status and cancellation to the stable attempt generation across ABA ids', async () => {
    const harness = makeHarness();
    await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const first = await requireWaiting(harness.store);
    const firstBinding = {
      attemptId: first.owner.attemptId,
      generation: first.owner.attemptGeneration,
    };
    await expect(harness.coordinator.status(firstBinding)).resolves.toMatchObject({
      status: 'waiting',
      ...firstBinding,
    });
    await expect(harness.coordinator.cancel(firstBinding)).resolves.toBe(true);

    await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const second = await requireWaiting(harness.store);
    expect(second.owner.attemptId).toBe(first.owner.attemptId);
    expect(second.owner.attemptGeneration).toBeGreaterThan(first.owner.attemptGeneration);
    await expect(harness.coordinator.status(firstBinding)).resolves.toEqual({ status: 'none' });
    await expect(harness.coordinator.cancel(firstBinding)).resolves.toBe(false);
    await expect(harness.store.read()).resolves.toEqual(second);
  });

  it('does not cancel a callback that already won the atomic claim', async () => {
    const harness = makeHarness();
    await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const waiting = await requireWaiting(harness.store);
    const bound = await harness.store.bindCallbackDocument(waiting.owner, {
      tabId: 42,
      documentId: 'document-a',
      callbackUrl: callbackUrl(waiting),
    });
    await harness.store.claim(bound!.attempt.owner);
    harness.tabsRemove.mockClear();

    await expect(harness.coordinator.cancel({
      attemptId: waiting.owner.attemptId,
      generation: waiting.owner.attemptGeneration,
    })).resolves.toBe(false);

    await expect(harness.store.read()).resolves.toMatchObject({ status: 'claimed' });
    expect(harness.tabsRemove).not.toHaveBeenCalled();
  });

  it('lets an exact durable SSO 2FA handoff supersede the outer claimed status', async () => {
    const harness = makeHarness({
      pendingHandoff: {
        attemptId: ATTEMPT_ID,
        attemptGeneration: 3,
        serverUrl: SERVER,
        identityUrl: IDENTITY,
        email: EMAIL,
      },
    });
    await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const waiting = await requireWaiting(harness.store);
    const bound = await harness.store.bindCallbackDocument(waiting.owner, {
      tabId: 42,
      documentId: 'document-a',
      callbackUrl: callbackUrl(waiting),
    });
    await harness.store.claim(bound!.attempt.owner);

    await expect(harness.coordinator.status()).resolves.toEqual({ status: 'none' });
    await expect(harness.store.read()).resolves.toBeUndefined();
  });
});

describe('SsoBrowserCoordinator settlement', () => {
  it('scrubs the exact callback document before exchanging', async () => {
    const harness = makeHarness();
    await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const waiting = await requireWaiting(harness.store);
    harness.events.length = 0;
    const callback = callbackUrl(waiting);
    const navigation = details(callback);
    harness.setFrame(callback, navigation.documentId!);

    await harness.coordinator.handleNavigation(navigation);

    expect(harness.events.indexOf('script:scrub')).toBeGreaterThanOrEqual(0);
    expect(harness.events.indexOf('auth:exchange'))
      .toBeGreaterThan(harness.events.indexOf('script:scrub'));
    expect(harness.executeScript).toHaveBeenCalledWith(expect.objectContaining({
      target: { tabId: 42, documentIds: ['document-a'] },
      args: [callback, waiting.redirectUri],
    }));
    expect(harness.completeSsoLogin).toHaveBeenCalledWith(expect.objectContaining({
      serverUrl: SERVER,
      identityUrl: IDENTITY,
      email: EMAIL,
      code: 'authorization-code',
      codeVerifier: waiting.verifier,
      redirectUri: waiting.redirectUri,
    }));
    expect(harness.focusWindow).toHaveBeenCalledWith(SOURCE_WINDOW, { focused: true });
    expect(harness.tabsUpdate).toHaveBeenCalledWith(SOURCE_TAB, { active: true });
    expect(harness.tabsRemove).toHaveBeenCalledWith(42);
    expect(harness.openPopup).toHaveBeenCalledOnce();
  });

  it.each([
    ['navigation', 'https://app.example/other', 'source-document-2'],
    ['document replacement', SOURCE_URL, 'source-document-2'],
  ] as const)('drops a stale source after %s but still authenticates into a neutral Popup', async (
    _label,
    sourceUrl,
    sourceDocumentId,
  ) => {
    const harness = makeHarness();
    await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    harness.navigateSource(sourceUrl, sourceDocumentId);
    await harness.coordinator.handleNavigation({
      tabId: SOURCE_TAB,
      frameId: 0,
      documentId: sourceDocumentId,
      url: sourceUrl,
    });
    await expect(harness.store.read()).resolves.toMatchObject({
      status: 'waiting',
      source: { popupDocumentId: POPUP_DOCUMENT, windowId: SOURCE_WINDOW },
    });
    expect((await harness.store.read())?.source.document).toBeUndefined();

    const waiting = await requireWaiting(harness.store);
    const callback = callbackUrl(waiting);
    harness.setFrame(callback, 'document-a');
    await harness.coordinator.handleNavigation(details(callback));

    expect(harness.completeSsoLogin).toHaveBeenCalledOnce();
    expect(harness.tabsUpdate).not.toHaveBeenCalledWith(SOURCE_TAB, { active: true });
    expect(harness.openPopup).toHaveBeenCalledOnce();
  });

  it('drops a closed source but still authenticates without a stale return target', async () => {
    const harness = makeHarness();
    await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    harness.closeSource();
    await harness.coordinator.handleTabRemoved(SOURCE_TAB);

    const waiting = await requireWaiting(harness.store);
    expect(waiting.source.document).toBeUndefined();
    const callback = callbackUrl(waiting);
    harness.setFrame(callback, 'document-a');
    await harness.coordinator.handleNavigation(details(callback));

    expect(harness.completeSsoLogin).toHaveBeenCalledOnce();
    expect(harness.openPopup).toHaveBeenCalledOnce();
  });

  it('rejects source ABA at restore time without affecting successful authentication', async () => {
    const harness = makeHarness();
    await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const waiting = await requireWaiting(harness.store);
    harness.navigateSource(SOURCE_URL, 'source-document-replaced');
    const callback = callbackUrl(waiting);
    harness.setFrame(callback, 'document-a');

    await harness.coordinator.handleNavigation(details(callback));

    expect(harness.completeSsoLogin).toHaveBeenCalledOnce();
    expect(harness.tabsUpdate).not.toHaveBeenCalledWith(SOURCE_TAB, { active: true });
    expect(harness.tabsUpdate).toHaveBeenCalledWith(42, { url: POPUP, active: true });
    expect(harness.openPopup).not.toHaveBeenCalled();
  });

  it('preserves a dispatched exchange while source navigation drops only its return proof', async () => {
    const harness = makeHarness({ holdExchange: true });
    await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const waiting = await requireWaiting(harness.store);
    const callback = callbackUrl(waiting);
    harness.setFrame(callback, 'document-a');
    const delivery = harness.coordinator.handleNavigation(details(callback));
    await harness.dispatchStarted;
    harness.navigateSource('https://app.example/after-dispatch', 'source-document-2');
    await harness.coordinator.handleNavigation({
      tabId: SOURCE_TAB,
      frameId: 0,
      documentId: 'source-document-2',
      url: 'https://app.example/after-dispatch',
    });
    harness.releaseExchange();
    await delivery;

    expect(harness.completeSsoLogin).toHaveBeenCalledOnce();
    await expect(harness.store.read()).resolves.toBeUndefined();
    expect(harness.openPopup).not.toHaveBeenCalled();
    expect(harness.tabsUpdate).toHaveBeenCalledWith(42, { url: POPUP, active: true });
  });

  it('scrubs callback secrets before a callback-time authorization failure', async () => {
    const harness = makeHarness({ callbackAuthorizationError: new Error('authorization failed') });

    await deliverValidCallback(harness);

    expect(harness.executeScript).toHaveBeenCalledOnce();
    expect(harness.completeSsoLogin).not.toHaveBeenCalled();
    await expect(harness.store.read()).resolves.toBeUndefined();
    await expect(harness.coordinator.status()).resolves.toMatchObject({ status: 'error' });
  });

  it('closes the exact callback tab when secret scrubbing fails', async () => {
    const harness = makeHarness({ scrubError: new Error('scrub failed') });
    const originalClear = harness.store.clear.bind(harness.store);
    vi.spyOn(harness.store, 'clear').mockImplementation(async (owner) => {
      harness.events.push('store:clear');
      return originalClear(owner);
    });

    await deliverValidCallback(harness);

    expect(harness.completeSsoLogin).not.toHaveBeenCalled();
    expect(harness.tabsRemove).toHaveBeenCalledWith(42);
    expect(harness.events.indexOf('store:clear')).toBeGreaterThan(
      harness.events.indexOf('tabs:remove'),
    );
    await expect(harness.store.read()).resolves.toBeUndefined();
  });

  it('retains the durable callback marker when an unscrubbed tab cannot be closed', async () => {
    const harness = makeHarness({
      scrubError: new Error('scrub failed'),
      failRemove: true,
    });
    const clear = vi.spyOn(harness.store, 'clear');

    await deliverValidCallback(harness);

    expect(harness.completeSsoLogin).not.toHaveBeenCalled();
    expect(clear).not.toHaveBeenCalled();
    await expect(harness.store.read()).resolves.toMatchObject({ status: 'claimed' });
  });

  it.each([
    ['network failure', new Error('connection reset')],
    ['server failure', new ApiHttpError(503, { error: 'unavailable' })],
  ])('marks an uncertain %s outcome unknown', async (_label, exchangeError) => {
    const harness = makeHarness({ exchangeError });
    await deliverValidCallback(harness);

    await expect(harness.coordinator.status()).resolves.toMatchObject({
      status: 'outcome_unknown',
      email: EMAIL,
    });
    await expect(harness.store.read()).resolves.toMatchObject({ status: 'outcome_unknown' });
  });

  it('treats a pre-grant server failure as safely retryable', async () => {
    const harness = makeHarness({
      preGrantError: new ApiHttpError(503, { error: 'prelogin unavailable' }),
    });

    await deliverValidCallback(harness);

    await expect(harness.store.read()).resolves.toBeUndefined();
    await expect(harness.coordinator.status()).resolves.toMatchObject({ status: 'error' });
  });

  it.each([
    ['client rejection', new ApiHttpError(400, { error: 'invalid_grant' })],
    ['unsupported account', new ApiUnsupportedSsoAccountError()],
  ])('treats %s as definite and clears the attempt', async (_label, exchangeError) => {
    const harness = makeHarness({ exchangeError });
    await deliverValidCallback(harness);

    await expect(harness.store.read()).resolves.toBeUndefined();
    await expect(harness.coordinator.status()).resolves.toMatchObject({ status: 'error' });
  });

  it('keeps auth success terminal when source focus and fallback Popup navigation fail', async () => {
    const harness = makeHarness({ failFocus: true, failPopupUpdate: true });
    const markUnknown = vi.spyOn(harness.store, 'markOutcomeUnknown');

    await deliverValidCallback(harness);

    expect(harness.completeSsoLogin).toHaveBeenCalledOnce();
    expect(markUnknown).not.toHaveBeenCalled();
    await expect(harness.store.read()).resolves.toBeUndefined();
    await expect(harness.coordinator.status()).resolves.toEqual({ status: 'none' });
    expect(harness.tabsUpdate.mock.calls.some(([, input]) => input.url === POPUP)).toBe(true);
  });

  it('clears a waiting attempt when its tab is removed', async () => {
    const harness = makeHarness();
    await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    await expect(harness.store.read()).resolves.toMatchObject({ status: 'waiting', tabId: 42 });

    await harness.coordinator.handleTabRemoved(42);

    await expect(harness.store.read()).resolves.toBeUndefined();
    expect(harness.completeSsoLogin).not.toHaveBeenCalled();
  });
});

describe('SsoBrowserCoordinator restart reconciliation', () => {
  it('routes same-worker TTL expiry through scrub cleanup without exchanging', async () => {
    let now = 1_000;
    const harness = makeHarness({ now: () => now });
    await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const waiting = await requireWaiting(harness.store);
    const callback = callbackUrl(waiting);
    harness.setFrame(callback, 'document-a');
    now = waiting.expiresAt;

    await harness.coordinator.handleNavigation(details(callback));

    expect(harness.executeScript).toHaveBeenCalledWith(expect.objectContaining({
      target: { tabId: 42, documentIds: ['document-a'] },
      args: [callback, waiting.redirectUri],
    }));
    expect(harness.completeSsoLogin).not.toHaveBeenCalled();
    await expect(harness.store.read()).resolves.toBeUndefined();
  });

  it('resumes one waiting callback that was bound before the worker stopped', async () => {
    const storage = createMemoryStore();
    const first = makeHarness({ storage });
    await first.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const waiting = await requireWaiting(first.store);
    const callback = callbackUrl(waiting);
    await first.store.bindCallbackDocument(waiting.owner, {
      tabId: 42,
      documentId: 'document-a',
      callbackUrl: callback,
    });

    const restarted = makeHarness({
      storage,
      workerId: RESTARTED_WORKER_ID,
      initialSsoExists: true,
      initialFrameUrl: callback,
      initialFrameDocumentId: 'document-a',
    });
    await restarted.coordinator.reconcileRestart();

    expect(restarted.executeScript).toHaveBeenCalledOnce();
    expect(restarted.completeSsoLogin).toHaveBeenCalledOnce();
    await expect(restarted.store.read()).resolves.toBeUndefined();
    expect(restarted.openPopup).toHaveBeenCalledOnce();
  });

  it('scrubs but never replays a callback claimed by a prior worker', async () => {
    const storage = createMemoryStore();
    const first = makeHarness({ storage });
    await first.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const waiting = await requireWaiting(first.store);
    const callback = callbackUrl(waiting);
    const bound = await first.store.bindCallbackDocument(waiting.owner, {
      tabId: 42,
      documentId: 'document-a',
      callbackUrl: callback,
    });
    await first.store.claim(bound!.attempt.owner);

    const restarted = makeHarness({
      storage,
      workerId: RESTARTED_WORKER_ID,
      initialSsoExists: true,
      initialFrameUrl: callback,
      initialFrameDocumentId: 'document-a',
    });
    await restarted.coordinator.reconcileRestart();

    expect(restarted.executeScript).toHaveBeenCalledOnce();
    expect(restarted.completeSsoLogin).not.toHaveBeenCalled();
    await expect(restarted.store.read()).resolves.toBeUndefined();
    expect(restarted.openPopup).toHaveBeenCalledOnce();
  });

  it('scrubs an expired unbound waiting callback before clearing its durable binding', async () => {
    let now = 1_000;
    const storage = createMemoryStore();
    const first = makeHarness({ storage, now: () => now });
    await first.coordinator.begin(EMAIL, POPUP_DOCUMENT);
    const waiting = await requireWaiting(first.store);
    const callback = callbackUrl(waiting);
    now = waiting.expiresAt;

    const restarted = makeHarness({
      storage,
      workerId: RESTARTED_WORKER_ID,
      now: () => now,
      initialSsoExists: true,
      initialFrameUrl: callback,
      initialFrameDocumentId: 'document-a',
    });
    await restarted.coordinator.reconcileRestart();

    expect(restarted.executeScript).toHaveBeenCalledWith(expect.objectContaining({
      target: { tabId: 42, documentIds: ['document-a'] },
      args: [callback, waiting.redirectUri],
    }));
    expect(restarted.completeSsoLogin).not.toHaveBeenCalled();
    await expect(restarted.store.read()).resolves.toBeUndefined();
  });
});

interface BrowserHarness {
  readonly coordinator: SsoBrowserCoordinator;
  readonly store: SsoAttemptStore;
  readonly events: string[];
  readonly tabsUpdate: ReturnType<typeof vi.fn>;
  readonly tabsRemove: ReturnType<typeof vi.fn>;
  readonly executeScript: ReturnType<typeof vi.fn>;
  readonly completeSsoLogin: ReturnType<typeof vi.fn>;
  readonly openPopup: ReturnType<typeof vi.fn>;
  readonly focusWindow: ReturnType<typeof vi.fn>;
  readonly dispatchStarted: Promise<void>;
  readonly releaseExchange: () => void;
  readonly setFrame: (url: string, documentId: string) => void;
  readonly navigateSource: (url: string, documentId: string) => void;
  readonly closeSource: () => void;
}

function makeHarness(options: {
  failStartUpdate?: boolean;
  failPopupUpdate?: boolean;
  exchangeError?: Error;
  preGrantError?: Error;
  callbackAuthorizationError?: Error;
  scrubError?: Error;
  pendingHandoff?: {
    readonly attemptId: string;
    readonly attemptGeneration: number;
    readonly serverUrl: string;
    readonly identityUrl: string;
    readonly email: string;
  };
  assertCurrent?: () => void;
  failFocus?: boolean;
  failRemove?: boolean;
  holdExchange?: boolean;
  storage?: ReturnType<typeof createMemoryStore>;
  workerId?: string;
  now?: () => number;
  initialSsoExists?: boolean;
  initialFrameUrl?: string;
  initialFrameDocumentId?: string;
} = {}): BrowserHarness {
  const events: string[] = [];
  const store = new SsoAttemptStore(options.storage ?? createMemoryStore(), {
    now: options.now ?? (() => 1_000),
    workerId: options.workerId ?? WORKER_ID,
    createAttemptId: () => ATTEMPT_ID,
  });
  let sourceExists = true;
  let sourceUrl = SOURCE_URL;
  let sourceDocumentId = SOURCE_DOCUMENT;
  let sourceActive = !options.initialSsoExists;
  let ssoExists = options.initialSsoExists ?? false;
  let ssoActive = ssoExists;
  let frameUrl = options.initialFrameUrl ?? 'about:blank';
  let frameDocumentId = options.initialFrameDocumentId ?? 'document-a';
  let releaseExchange = (): void => {};
  let notifyDispatch = (): void => {};
  const dispatchStarted = new Promise<void>((resolve) => { notifyDispatch = resolve; });
  const exchangeGate = new Promise<void>((resolve) => { releaseExchange = resolve; });
  const tabsCreate = vi.fn(async (input: { url: string; windowId: number }) => {
    events.push(`tabs:create:${input.url}`);
    expect(input.windowId).toBe(SOURCE_WINDOW);
    ssoExists = true;
    ssoActive = true;
    sourceActive = false;
    frameUrl = input.url;
    return { id: 42, windowId: SOURCE_WINDOW };
  });
  const tabsUpdate = vi.fn(async (tabId: number, input: { url?: string; active?: boolean }) => {
    if (tabId === SOURCE_TAB) {
      if (!sourceExists) throw new Error('source tab closed');
      if (input.active) {
        sourceActive = true;
        ssoActive = false;
      }
      return {};
    }
    if (!ssoExists) throw new Error('SSO tab closed');
    if (input.url === POPUP) {
      events.push('tabs:update:popup');
      if (options.failPopupUpdate) throw new Error('popup update failed');
    } else if (input.url !== undefined) {
      events.push('tabs:update:start');
      if (options.failStartUpdate) throw new Error('start update failed');
    }
    if (input.url !== undefined) frameUrl = input.url;
    if (input.active) {
      ssoActive = true;
      sourceActive = false;
    }
    return {};
  });
  const tabsRemove = vi.fn(async (tabId: number) => {
    events.push('tabs:remove');
    if (options.failRemove) throw new Error('tab removal failed');
    if (tabId === 42) {
      ssoExists = false;
      ssoActive = false;
      sourceActive = sourceExists;
    }
  });
  const tabsQuery = vi.fn(async () => {
    if (ssoExists && ssoActive) return [{ id: 42, windowId: SOURCE_WINDOW, url: frameUrl }];
    if (sourceExists && sourceActive) {
      return [{ id: SOURCE_TAB, windowId: SOURCE_WINDOW, url: sourceUrl }];
    }
    return [];
  });
  const tabsGet = vi.fn(async (tabId: number) => {
    if (tabId === SOURCE_TAB && sourceExists) {
      return { id: SOURCE_TAB, windowId: SOURCE_WINDOW, url: sourceUrl, active: sourceActive };
    }
    if (tabId === 42 && ssoExists) {
      return { id: 42, windowId: SOURCE_WINDOW, url: frameUrl, active: ssoActive };
    }
    throw new Error('tab not found');
  });
  const executeScript = vi.fn(async (input: { args: [string, string] }) => {
    events.push('script:scrub');
    if (options.scrubError) throw options.scrubError;
    frameUrl = input.args[1];
    return [{ result: true }];
  });
  const completeSsoLogin = vi.fn(async (input: {
    onGrantStarted(): Promise<void>;
    onGrantDispatched(): void;
  }) => {
    if (options.preGrantError) throw options.preGrantError;
    await input.onGrantStarted();
    input.onGrantDispatched();
    notifyDispatch();
    events.push('auth:exchange');
    if (options.holdExchange) await exchangeGate;
    if (options.exchangeError) throw options.exchangeError;
    return { kind: 'locked' as const };
  });
  const openPopup = vi.fn(async () => undefined);
  const focusWindow = vi.fn(async () => {
    if (options.failFocus) throw new Error('focus failed');
    return {};
  });
  const authorization: SsoLaunchAuthorization = Object.freeze({
    serverUrl: SERVER,
    serverGeneration: 7,
    capabilityGeneration: 11,
    vaultUrl: VAULT,
    identityUrl: IDENTITY,
    ssoUrl: SSO,
    emailTwoFactorMode: 'bitwarden-session',
    assertCurrent: options.assertCurrent ?? (() => undefined),
  });
  let authorizationCalls = 0;
  const coordinator = new SsoBrowserCoordinator({
    store,
    authorize: vi.fn(async () => {
      authorizationCalls += 1;
      if (authorizationCalls > 1 && options.callbackAuthorizationError) {
        throw options.callbackAuthorizationError;
      }
      return authorization;
    }),
    auth: {
      completeSsoLogin: completeSsoLogin as never,
      getPendingSsoHandoff: vi.fn(async () => options.pendingHandoff),
    },
    browser: {
      action: { openPopup },
      runtime: {
        getContexts: vi.fn(async () => [{
          contextType: 'POPUP',
          documentId: POPUP_DOCUMENT,
          documentUrl: POPUP,
          windowId: SOURCE_WINDOW,
        }]),
      },
      tabs: {
        create: tabsCreate as never,
        query: tabsQuery,
        get: tabsGet,
        update: tabsUpdate as never,
        remove: tabsRemove,
      },
      windows: { update: focusWindow },
      webNavigation: {
        getFrame: vi.fn(async ({ tabId }: { tabId: number }) => {
          if (tabId === SOURCE_TAB) {
            return sourceExists ? { documentId: sourceDocumentId, url: sourceUrl } : null;
          }
          return ssoExists ? { documentId: frameDocumentId, url: frameUrl } : null;
        }),
      },
      scripting: { executeScript: executeScript as never },
    },
    popupUrl: POPUP,
  });
  return {
    coordinator,
    store,
    events,
    tabsUpdate,
    tabsRemove,
    executeScript,
    completeSsoLogin,
    openPopup,
    focusWindow,
    dispatchStarted,
    releaseExchange,
    setFrame(url, documentId) {
      frameUrl = url;
      frameDocumentId = documentId;
    },
    navigateSource(url, documentId) {
      sourceUrl = url;
      sourceDocumentId = documentId;
    },
    closeSource() {
      sourceExists = false;
      sourceActive = false;
    },
  };
}

async function requireWaiting(store: SsoAttemptStore): Promise<WaitingSsoAttempt> {
  const current = await store.read();
  if (!current || current.status !== 'waiting') throw new Error('Expected a waiting SSO attempt');
  return current;
}

function callbackUrl(
  waiting: WaitingSsoAttempt,
  options: { state?: string; issuer?: string } = {},
): string {
  const state = options.state ?? waiting.state;
  const issuer = options.issuer ?? waiting.owner.identityUrl;
  return `${waiting.redirectUri}?code=authorization-code&state=${encodeURIComponent(state)}`
    + `&scope=api+offline_access&iss=${encodeURIComponent(issuer)}`;
}

function details(url: string): SsoNavigationDetails {
  return { tabId: 42, frameId: 0, documentId: 'document-a', url };
}

async function deliverValidCallback(harness: BrowserHarness): Promise<void> {
  await harness.coordinator.begin(EMAIL, POPUP_DOCUMENT);
  const waiting = await requireWaiting(harness.store);
  const navigation = details(callbackUrl(waiting));
  harness.setFrame(navigation.url, navigation.documentId!);
  await harness.coordinator.handleNavigation(navigation);
}
