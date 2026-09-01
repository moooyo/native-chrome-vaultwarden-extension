import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: {}, session: {} } },
}));

import { createMemoryStore } from '../platform/store.js';
import { ApiHttpError } from '../core/api/client.js';
import { AppError } from '../core/errors.js';
import type { KeyValueStore } from '../platform/store.js';
import { DUO_ATTEMPT_TTL_MS, DuoAttemptStore } from './duo-attempt-store.js';
import { DuoBrowserCoordinator } from './duo-browser.js';

const SERVER = 'https://vault.example/';
const EMAIL = 'user@example.com';
const REDIRECT = 'https://vault.example/duo-redirect-connector.html?client=browser';
const STATE = 'server-state';
const AUTH_URL = 'https://api-example.duosecurity.com/oauth/v1/authorize'
  + `?response_type=code&client_id=client-id&redirect_uri=${encodeURIComponent(REDIRECT)}`
  + `&state=${STATE}`;
const POPUP = 'chrome-extension://extension-id/ui/popup/popup.html';
const WORKER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const WORKER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const POPUP_DOCUMENT = 'popup-document';
const SOURCE_TAB = 7;
const SOURCE_WINDOW = 5;
const SOURCE_DOCUMENT = 'source-document';
const SOURCE_URL = 'https://app.example/login';

interface HarnessOptions {
  readonly updateError?: Error;
  readonly scrubResult?: boolean;
  readonly completeError?: unknown;
  readonly preGrantError?: unknown;
  readonly completeResult?: { readonly kind?: string; readonly status?: string };
  readonly callbackAuthority?: {
    readonly serverUrl: string;
    readonly vaultUrl: string;
    readonly assertCurrent?: () => void;
  };
  readonly deviceOwnerGeneration?: number;
  readonly storage?: KeyValueStore;
  readonly workerId?: string;
  readonly initialFrameUrl?: string;
  readonly restrictedSource?: boolean;
  readonly changeSourceBeforeGrant?: boolean;
  readonly now?: () => number;
  readonly removeError?: Error;
}

function harness(options: HarnessOptions = {}) {
  let frameUrl = options.initialFrameUrl ?? 'about:blank';
  let sourceUrl = options.restrictedSource ? 'chrome://settings/' : SOURCE_URL;
  let sourceDocumentId = SOURCE_DOCUMENT;
  let duoExists = options.initialFrameUrl !== undefined;
  let sourceActive = !duoExists;
  const complete = vi.fn(async (input: {
    onGrantStarted: () => Promise<void>;
    onGrantDispatched: () => void;
  }) => {
    if (options.preGrantError) throw options.preGrantError;
    if (options.changeSourceBeforeGrant) {
      sourceUrl = 'https://app.example/changed';
      sourceDocumentId = 'source-document-2';
    }
    await input.onGrantStarted();
    input.onGrantDispatched();
    if (options.completeError) throw options.completeError;
    return options.completeResult ?? { kind: 'locked' as const };
  });
  const deviceComplete = vi.fn(async (input: {
    onGrantStarted: () => Promise<void>;
    onGrantDispatched: () => void;
  }) => {
    if (options.preGrantError) throw options.preGrantError;
    if (options.changeSourceBeforeGrant) {
      sourceUrl = 'https://app.example/changed';
      sourceDocumentId = 'source-document-2';
    }
    await input.onGrantStarted();
    input.onGrantDispatched();
    if (options.completeError) throw options.completeError;
    return options.completeResult ?? { status: 'locked' as const };
  });
  const prepare = vi.fn(async () => ({
    owner: {
      flow: 'password' as const,
      generation: 9,
      serverUrl: SERVER,
      email: EMAIL,
      provider: 2 as const,
      bindingId: '22222222-2222-4222-8222-222222222222',
    },
    seed: { provider: 2 as const, authUrl: AUTH_URL, host: 'api-example.duosecurity.com' },
  }));
  const devicePrepare = vi.fn(async () => ({
    owner: {
      flow: 'deviceLogin' as const,
      generation: options.deviceOwnerGeneration ?? 12,
      serverUrl: SERVER,
      email: EMAIL,
      provider: 6 as const,
      bindingId: 'device-login-binding',
    },
    seed: { provider: 6 as const, authUrl: AUTH_URL, host: 'api-example.duosecurity.com' },
  }));
  const update = vi.fn(async (tabId: number, input: { url?: string; active?: boolean }) => {
    if (options.updateError && input.url === AUTH_URL) throw options.updateError;
    if (tabId === 42 && input.url) frameUrl = input.url;
    if (input.active === true) {
      sourceActive = tabId === SOURCE_TAB;
    }
    return {};
  });
  const remove = vi.fn(async (tabId: number) => {
    if (options.removeError) throw options.removeError;
    if (tabId === 42) {
      duoExists = false;
      sourceActive = true;
    }
  });
  const executeScript = vi.fn(async (input: { args: [string, string] }) => {
    frameUrl = input.args[1];
    return [{ result: options.scrubResult ?? true }];
  });
  const storage = options.storage ?? createMemoryStore();
  const store = new DuoAttemptStore(storage, {
    now: options.now ?? (() => 1_000),
    workerId: options.workerId ?? WORKER_A,
    createAttemptId: () => '11111111-1111-4111-8111-111111111111',
  });
  let authorizationCount = 0;
  const create = vi.fn(async (input: { windowId: number }) => {
    duoExists = true;
    sourceActive = false;
    frameUrl = 'about:blank';
    return { id: 42, windowId: input.windowId, url: frameUrl, active: true };
  });
  const query = vi.fn(async (input: { windowId: number }) => (
    input.windowId === SOURCE_WINDOW
      ? [sourceActive
          ? { id: SOURCE_TAB, windowId: SOURCE_WINDOW, url: sourceUrl }
          : { id: 42, windowId: SOURCE_WINDOW, url: frameUrl }]
      : []
  ));
  const get = vi.fn(async (tabId: number) => {
    if (tabId === SOURCE_TAB) {
      return {
        id: SOURCE_TAB,
        windowId: SOURCE_WINDOW,
        url: sourceUrl,
        active: sourceActive,
      };
    }
    if (tabId === 42 && duoExists) {
      return { id: 42, windowId: SOURCE_WINDOW, url: frameUrl, active: !sourceActive };
    }
    throw new Error('tab unavailable');
  });
  const openPopup = vi.fn(async () => undefined);
  const focusWindow = vi.fn(async () => ({}));
  const coordinator = new DuoBrowserCoordinator({
    store,
    password: { prepare, complete },
    deviceLogin: { prepare: devicePrepare as never, complete: deviceComplete },
    authorize: async () => {
      const callbackAuthority = authorizationCount++ > 0 ? options.callbackAuthority : undefined;
      return {
        serverUrl: callbackAuthority?.serverUrl ?? SERVER,
        vaultUrl: callbackAuthority?.vaultUrl ?? SERVER,
        assertCurrent: callbackAuthority?.assertCurrent ?? (() => {}),
      };
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
        create,
        query,
        get,
        update,
        remove,
      },
      windows: { update: focusWindow },
      webNavigation: {
        getFrame: vi.fn(async (input: { tabId: number }) => {
          if (input.tabId === SOURCE_TAB) {
            return options.restrictedSource
              ? null
              : { documentId: sourceDocumentId, url: sourceUrl };
          }
          return duoExists ? { documentId: 'doc-a', url: frameUrl } : null;
        }),
      },
      scripting: { executeScript: executeScript as never },
    },
    popupUrl: POPUP,
  });
  return {
    coordinator,
    store,
    storage,
    prepare,
    complete,
    devicePrepare,
    deviceComplete,
    update,
    remove,
    executeScript,
    create,
    query,
    get,
    openPopup,
    focusWindow,
    navigateSource(url: string, documentId: string) {
      sourceUrl = url;
      sourceDocumentId = documentId;
    },
  };
}

const beginInput = Object.freeze({
  flow: 'password' as const,
  provider: 2 as const,
  continuationId: '22222222-2222-4222-8222-222222222222',
  remember: true,
});

describe('DuoBrowserCoordinator', () => {
  it('persists before navigation, scrubs one callback, and submits code|state once', async () => {
    const h = harness();
    await expect(h.coordinator.begin(beginInput, POPUP_DOCUMENT)).resolves.toEqual({ status: 'waiting' });
    expect(h.create).toHaveBeenCalledWith({
      url: 'about:blank',
      active: true,
      windowId: SOURCE_WINDOW,
    });
    await expect(h.store.read()).resolves.toMatchObject({
      status: 'waiting',
      tabId: 42,
      remember: true,
      redirectUri: REDIRECT,
      state: STATE,
    });
    expect(h.update).toHaveBeenCalledWith(42, { url: AUTH_URL, active: true });
    const callback = `${REDIRECT}&code=authorization-code&state=${STATE}`;

    await Promise.all([
      h.coordinator.handleNavigation({ tabId: 42, frameId: 0, documentId: 'doc-a', url: callback }),
      h.coordinator.handleNavigation({ tabId: 42, frameId: 0, documentId: 'doc-a', url: callback }),
    ]);

    expect(h.executeScript).toHaveBeenCalledOnce();
    expect(h.complete).toHaveBeenCalledOnce();
    expect(h.complete).toHaveBeenCalledWith(expect.objectContaining({
      token: `authorization-code|${STATE}`,
      remember: true,
    }));
    await expect(h.store.read()).resolves.toBeUndefined();
    expect(h.update).toHaveBeenCalledWith(SOURCE_TAB, { active: true });
    expect(h.remove).toHaveBeenCalledWith(42);
    expect(h.openPopup).toHaveBeenCalledOnce();
  });

  it('returns an unlocked completion to the exact source tab without reopening Popup', async () => {
    const h = harness({ completeResult: { kind: 'unlocked' } });
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    await h.coordinator.handleNavigation({
      tabId: 42,
      frameId: 0,
      documentId: 'doc-a',
      url: `${REDIRECT}&code=code&state=${STATE}`,
    });

    expect(h.focusWindow).toHaveBeenCalledWith(SOURCE_WINDOW, { focused: true });
    expect(h.update).toHaveBeenCalledWith(SOURCE_TAB, { active: true });
    expect(h.remove).toHaveBeenCalledWith(42);
    expect(h.openPopup).not.toHaveBeenCalled();
  });

  it('allows authentication from a restricted source page without a document binding', async () => {
    const h = harness({ restrictedSource: true });
    await expect(h.coordinator.begin(beginInput, POPUP_DOCUMENT)).resolves.toEqual({ status: 'waiting' });
    await expect(h.store.read()).resolves.toMatchObject({
      source: { windowId: SOURCE_WINDOW },
    });
    const current = await h.store.read();
    expect(current?.source.document).toBeUndefined();
    expect(h.create).toHaveBeenCalledWith(expect.objectContaining({ windowId: SOURCE_WINDOW }));
  });

  it('retires the exact attempt when its bound source document navigates', async () => {
    const h = harness();
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    h.navigateSource('https://app.example/other', 'source-document-2');

    await h.coordinator.handleNavigation({
      tabId: SOURCE_TAB,
      frameId: 0,
      documentId: 'source-document-2',
      url: 'https://app.example/other',
    });

    await expect(h.store.read()).resolves.toBeUndefined();
    expect(h.complete).not.toHaveBeenCalled();
    expect(h.remove).toHaveBeenCalledWith(42);
  });

  it('retains a waiting marker when source-change cleanup cannot close its owned tab', async () => {
    const h = harness({ removeError: new Error('remove failed') });
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    h.navigateSource('https://app.example/other', 'source-document-2');

    await h.coordinator.handleNavigation({
      tabId: SOURCE_TAB,
      frameId: 0,
      documentId: 'source-document-2',
      url: 'https://app.example/other',
    });

    await expect(h.store.read()).resolves.toMatchObject({ status: 'waiting', tabId: 42 });
  });

  it('fails closed when the source changes before callback grant preparation', async () => {
    const h = harness();
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    h.navigateSource('https://app.example/other', 'source-document-2');

    await h.coordinator.handleNavigation({
      tabId: 42,
      frameId: 0,
      documentId: 'doc-a',
      url: `${REDIRECT}&code=code&state=${STATE}`,
    });

    expect(h.complete).not.toHaveBeenCalled();
    await expect(h.store.read()).resolves.toBeUndefined();
    expect(h.update).toHaveBeenCalledWith(42, { url: POPUP, active: true });
  });

  it('clears a pre-grant broker rejection without marking outcome unknown', async () => {
    const h = harness({ preGrantError: new AppError('session_expired', 'stale continuation') });
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    await h.coordinator.handleNavigation({
      tabId: 42,
      frameId: 0,
      documentId: 'doc-a',
      url: `${REDIRECT}&code=code&state=${STATE}`,
    });

    await expect(h.store.read()).resolves.toBeUndefined();
    expect(h.complete).toHaveBeenCalledOnce();
  });

  it('does not dispatch when the source changes inside grant preparation', async () => {
    const h = harness({ changeSourceBeforeGrant: true });
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    await h.coordinator.handleNavigation({
      tabId: 42,
      frameId: 0,
      documentId: 'doc-a',
      url: `${REDIRECT}&code=code&state=${STATE}`,
    });

    await expect(h.store.read()).resolves.toBeUndefined();
    expect(h.complete).toHaveBeenCalledOnce();
    expect(h.openPopup).not.toHaveBeenCalled();
  });

  it('does not replace the current attempt for a stale begin owner', async () => {
    const h = harness();
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    const current = await h.store.read();

    await expect(h.coordinator.begin({
      ...beginInput,
      continuationId: '33333333-3333-4333-8333-333333333333',
    }, POPUP_DOCUMENT)).rejects.toThrow(/binding/);

    await expect(h.store.read()).resolves.toEqual(current);
    expect(h.remove).not.toHaveBeenCalled();
  });

  it('cancels only the exact password continuation owner', async () => {
    const h = harness();
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    const current = await h.store.read();

    await expect(h.coordinator.cancel({
      flow: 'password',
      continuationId: '33333333-3333-4333-8333-333333333333',
    })).resolves.toBe(false);
    await expect(h.store.read()).resolves.toEqual(current);

    await expect(h.coordinator.cancel({
      flow: 'password',
      continuationId: beginInput.continuationId,
    })).resolves.toBe(true);
    await expect(h.store.read()).resolves.toBeUndefined();
    expect(h.remove).toHaveBeenCalledWith(42);
  });

  it('closes and clears an invalid callback without submitting', async () => {
    const h = harness();
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    await h.coordinator.handleNavigation({
      tabId: 42,
      frameId: 0,
      documentId: 'doc-a',
      url: `${REDIRECT}&code=code&state=wrong`,
    });
    expect(h.complete).not.toHaveBeenCalled();
    expect(h.remove).toHaveBeenCalledWith(42);
    expect(h.executeScript).toHaveBeenCalledWith(expect.objectContaining({
      args: [`${REDIRECT}&code=code&state=wrong`, REDIRECT],
    }));
    await expect(h.store.read()).resolves.toBeUndefined();
  });

  it('cleans a failed initial navigation and a removed waiting tab', async () => {
    const failed = harness({ updateError: new Error('update failed') });
    await expect(failed.coordinator.begin(beginInput, POPUP_DOCUMENT)).rejects.toThrow(/update failed/);
    await expect(failed.store.read()).resolves.toBeUndefined();
    expect(failed.remove).toHaveBeenCalledWith(42);

    const removed = harness();
    await removed.coordinator.begin(beginInput, POPUP_DOCUMENT);
    await removed.coordinator.handleTabRemoved(42);
    await expect(removed.store.read()).resolves.toBeUndefined();
  });

  it('never submits when callback scrubbing cannot be proved', async () => {
    const h = harness({ scrubResult: false });
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);

    await h.coordinator.handleNavigation({
      tabId: 42,
      frameId: 0,
      documentId: 'doc-a',
      url: `${REDIRECT}&code=code&state=${STATE}`,
    });

    expect(h.complete).not.toHaveBeenCalled();
    expect(h.remove).toHaveBeenCalledWith(42);
    await expect(h.store.read()).resolves.toBeUndefined();
  });

  it('retires the exact callback owner after a commit-then-reject claim and failed first cleanup', async () => {
    const backing = createMemoryStore();
    let rejectClaimWrite = false;
    let rejectFirstCleanup = true;
    const storage: KeyValueStore = {
      get: (key) => backing.get(key),
      set: async (key, value) => {
        await backing.set(key, value);
        if (rejectClaimWrite) throw new Error('committed then rejected');
      },
      remove: async (key) => {
        if (rejectClaimWrite && rejectFirstCleanup) {
          rejectFirstCleanup = false;
          throw new Error('cleanup rejected');
        }
        await backing.remove(key);
      },
      clear: () => backing.clear(),
    };
    const h = harness({ storage });
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    rejectClaimWrite = true;

    await h.coordinator.handleNavigation({
      tabId: 42,
      frameId: 0,
      documentId: 'doc-a',
      url: `${REDIRECT}&code=code&state=${STATE}`,
    });

    expect(h.complete).not.toHaveBeenCalled();
    await expect(h.store.read()).resolves.toBeUndefined();
  });

  it.each([
    ['server', { serverUrl: 'https://other.example/', vaultUrl: SERVER }],
    ['connector', { serverUrl: SERVER, vaultUrl: 'https://other.example/' }],
  ] as const)('rejects a fresh %s authority change before submission', async (_label, callbackAuthority) => {
    const h = harness({ callbackAuthority });
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);

    await h.coordinator.handleNavigation({
      tabId: 42,
      frameId: 0,
      documentId: 'doc-a',
      url: `${REDIRECT}&code=code&state=${STATE}`,
    });

    expect(h.complete).not.toHaveBeenCalled();
    await expect(h.store.read()).resolves.toBeUndefined();
  });

  it('honors a rejected fresh capability lease before submission', async () => {
    const h = harness({
      callbackAuthority: {
        serverUrl: SERVER,
        vaultUrl: SERVER,
        assertCurrent: () => { throw new AppError('session_expired', 'capability changed'); },
      },
    });
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    await h.coordinator.handleNavigation({
      tabId: 42,
      frameId: 0,
      documentId: 'doc-a',
      url: `${REDIRECT}&code=code&state=${STATE}`,
    });

    expect(h.complete).not.toHaveBeenCalled();
    await expect(h.store.read()).resolves.toBeUndefined();
  });

  it.each([
    ['network', new Error('network failed')],
    ['server 5xx', new ApiHttpError(503, { error: 'unavailable' })],
  ])('persists outcome_unknown after a %s submission failure and never replays', async (_label, error) => {
    const h = harness({ completeError: error });
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    const callback = `${REDIRECT}&code=code&state=${STATE}`;

    await h.coordinator.handleNavigation({
      tabId: 42,
      frameId: 0,
      documentId: 'doc-a',
      url: callback,
    });
    await expect(h.store.read()).resolves.toMatchObject({ status: 'outcome_unknown' });

    await h.coordinator.handleNavigation({
      tabId: 42,
      frameId: 0,
      documentId: 'doc-a',
      url: callback,
    });
    expect(h.complete).toHaveBeenCalledOnce();
  });

  it('retires a definite 4xx rejection without replaying the code', async () => {
    const h = harness({ completeError: new ApiHttpError(400, { error: 'invalid_grant' }) });
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    await h.coordinator.handleNavigation({
      tabId: 42,
      frameId: 0,
      documentId: 'doc-a',
      url: `${REDIRECT}&code=code&state=${STATE}`,
    });

    expect(h.complete).toHaveBeenCalledOnce();
    await expect(h.store.read()).resolves.toBeUndefined();
  });

  it('cancels a claimed callback when its tab closes before submission', async () => {
    const h = harness();
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    const waiting = await h.store.read();
    if (!waiting || waiting.status !== 'waiting') throw new Error('expected waiting Duo attempt');
    await h.store.claimCallback(waiting.owner, {
      tabId: 42,
      documentId: 'doc-a',
      callbackUrl: `${REDIRECT}&code=code&state=${STATE}`,
    });

    await h.coordinator.handleTabRemoved(42);
    await expect(h.store.read()).resolves.toBeUndefined();
    expect(h.complete).not.toHaveBeenCalled();
  });

  it('marks an in-flight submission unknown when its tab closes', async () => {
    const h = harness();
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    const waiting = await h.store.read();
    if (!waiting || waiting.status !== 'waiting') throw new Error('expected waiting Duo attempt');
    const claim = await h.store.claimCallback(waiting.owner, {
      tabId: 42,
      documentId: 'doc-a',
      callbackUrl: `${REDIRECT}&code=code&state=${STATE}`,
    });
    if (!claim) throw new Error('expected claimed Duo attempt');
    await h.store.startSubmission(claim.attempt.owner);

    await h.coordinator.handleTabRemoved(42);
    await expect(h.store.read()).resolves.toMatchObject({ status: 'outcome_unknown' });
  });

  it('uses the exact device-login broker and owner generation', async () => {
    const h = harness();
    await h.coordinator.begin({
      flow: 'deviceLogin',
      provider: 6,
      generation: 12,
      remember: false,
    }, POPUP_DOCUMENT);
    await h.coordinator.handleNavigation({
      tabId: 42,
      frameId: 0,
      documentId: 'doc-a',
      url: `${REDIRECT}&code=device-code&state=${STATE}`,
    });

    expect(h.prepare).not.toHaveBeenCalled();
    expect(h.complete).not.toHaveBeenCalled();
    expect(h.devicePrepare).toHaveBeenCalledWith({
      flow: 'deviceLogin', provider: 6, generation: 12, remember: false,
    });
    expect(h.deviceComplete).toHaveBeenCalledWith(expect.objectContaining({
      owner: expect.objectContaining({ flow: 'deviceLogin', provider: 6, generation: 12 }),
      token: `device-code|${STATE}`,
      remember: false,
    }));
  });

  it('rejects a device-login broker owner from another generation', async () => {
    const h = harness({ deviceOwnerGeneration: 13 });
    await expect(h.coordinator.begin({
      flow: 'deviceLogin',
      provider: 6,
      generation: 12,
      remember: false,
    }, POPUP_DOCUMENT)).rejects.toThrow(/binding/);
    await expect(h.store.read()).resolves.toBeUndefined();
  });

  it('scrubs but never submits a callback claimed by a prior worker', async () => {
    const storage = createMemoryStore();
    const first = harness({ storage, workerId: WORKER_A });
    await first.coordinator.begin(beginInput, POPUP_DOCUMENT);
    const waiting = await first.store.read();
    if (!waiting || waiting.status !== 'waiting') throw new Error('expected waiting Duo attempt');
    const callback = `${REDIRECT}&code=restart-code&state=${STATE}`;
    await first.store.claimCallback(waiting.owner, {
      tabId: 42,
      documentId: 'doc-a',
      callbackUrl: callback,
    });

    const restarted = harness({
      storage,
      workerId: WORKER_B,
      initialFrameUrl: callback,
    });
    await restarted.coordinator.reconcileRestart();

    expect(restarted.executeScript).toHaveBeenCalledWith(expect.objectContaining({
      target: { tabId: 42, documentIds: ['doc-a'] },
      args: [callback, REDIRECT],
    }));
    expect(restarted.complete).not.toHaveBeenCalled();
    expect(restarted.deviceComplete).not.toHaveBeenCalled();
    await expect(restarted.store.read()).resolves.toBeUndefined();
    expect(restarted.update).toHaveBeenCalledWith(SOURCE_TAB, { active: true });
    expect(restarted.remove).toHaveBeenCalledWith(42);
    expect(restarted.openPopup).toHaveBeenCalledOnce();
  });

  it('closes a prior claimed callback when restart scrubbing fails', async () => {
    const storage = createMemoryStore();
    const first = harness({ storage, workerId: WORKER_A });
    await first.coordinator.begin(beginInput, POPUP_DOCUMENT);
    const waiting = await first.store.read();
    if (!waiting || waiting.status !== 'waiting') throw new Error('expected waiting Duo attempt');
    const callback = `${REDIRECT}&code=restart-code&state=${STATE}`;
    await first.store.claimCallback(waiting.owner, {
      tabId: 42,
      documentId: 'doc-a',
      callbackUrl: callback,
    });

    const restarted = harness({
      storage,
      workerId: WORKER_B,
      initialFrameUrl: callback,
      scrubResult: false,
    });
    const clear = vi.spyOn(restarted.store, 'clear');
    await restarted.coordinator.reconcileRestart();

    expect(restarted.complete).not.toHaveBeenCalled();
    expect(restarted.remove).toHaveBeenCalledWith(42);
    expect(restarted.remove.mock.invocationCallOrder[0]).toBeLessThan(
      clear.mock.invocationCallOrder[0]!,
    );
    await expect(restarted.store.read()).resolves.toBeUndefined();
  });

  it('retains a prior-worker claim when an unscrubbed callback tab cannot be closed', async () => {
    const storage = createMemoryStore();
    const first = harness({ storage, workerId: WORKER_A });
    await first.coordinator.begin(beginInput, POPUP_DOCUMENT);
    const waiting = await first.store.read();
    if (!waiting || waiting.status !== 'waiting') throw new Error('expected waiting Duo attempt');
    const callback = `${REDIRECT}&code=restart-code&state=${STATE}`;
    await first.store.claimCallback(waiting.owner, {
      tabId: 42,
      documentId: 'doc-a',
      callbackUrl: callback,
    });
    const restarted = harness({
      storage,
      workerId: WORKER_B,
      initialFrameUrl: callback,
      scrubResult: false,
      removeError: new Error('remove failed'),
    });
    const clear = vi.spyOn(restarted.store, 'clear');

    await restarted.coordinator.reconcileRestart();

    expect(clear).not.toHaveBeenCalled();
    await expect(restarted.store.read()).resolves.toMatchObject({ status: 'claimed', tabId: 42 });
  });

  it('never cleans or replays a prior worker submission as if it were pre-grant', async () => {
    const storage = createMemoryStore();
    const first = harness({ storage, workerId: WORKER_A });
    await first.coordinator.begin(beginInput, POPUP_DOCUMENT);
    const waiting = await first.store.read();
    if (!waiting || waiting.status !== 'waiting') throw new Error('expected waiting Duo attempt');
    const callback = `${REDIRECT}&code=restart-code&state=${STATE}`;
    const claim = await first.store.claimCallback(waiting.owner, {
      tabId: 42,
      documentId: 'doc-a',
      callbackUrl: callback,
    });
    if (!claim) throw new Error('expected claimed Duo attempt');
    await first.store.startSubmission(claim.attempt.owner);

    const restarted = harness({ storage, workerId: WORKER_B, initialFrameUrl: REDIRECT });
    await restarted.coordinator.reconcileRestart();

    await expect(restarted.store.read()).resolves.toMatchObject({ status: 'outcome_unknown' });
    expect(restarted.executeScript).not.toHaveBeenCalled();
    expect(restarted.complete).not.toHaveBeenCalled();
  });

  it('scrubs and retires an expired callback after a worker restart without replaying it', async () => {
    let now = 1_000;
    const storage = createMemoryStore();
    const first = harness({ storage, workerId: WORKER_A, now: () => now });
    await first.coordinator.begin(beginInput, POPUP_DOCUMENT);
    const waiting = await first.store.read();
    if (!waiting || waiting.status !== 'waiting') throw new Error('expected waiting Duo attempt');
    const callback = `${REDIRECT}&code=expired-code&state=${STATE}`;
    await first.store.claimCallback(waiting.owner, {
      tabId: 42,
      documentId: 'doc-a',
      callbackUrl: callback,
    });
    now += DUO_ATTEMPT_TTL_MS;

    const restarted = harness({
      storage,
      workerId: WORKER_B,
      now: () => now,
      initialFrameUrl: callback,
    });
    await restarted.coordinator.reconcileRestart();

    expect(restarted.executeScript).toHaveBeenCalledWith(expect.objectContaining({
      target: { tabId: 42, documentIds: ['doc-a'] },
      args: [callback, REDIRECT],
    }));
    expect(restarted.complete).not.toHaveBeenCalled();
    await expect(restarted.store.read()).resolves.toBeUndefined();
  });

  it('routes same-worker TTL expiry through scrub cleanup instead of dropping ownership', async () => {
    let now = 1_000;
    const h = harness({ now: () => now });
    await h.coordinator.begin(beginInput, POPUP_DOCUMENT);
    const callback = `${REDIRECT}&code=expired-code&state=${STATE}`;
    await h.update(42, { url: callback, active: true });
    now += DUO_ATTEMPT_TTL_MS;

    await h.coordinator.handleNavigation({
      tabId: 42,
      frameId: 0,
      documentId: 'doc-a',
      url: callback,
    });

    expect(h.executeScript).toHaveBeenCalledWith(expect.objectContaining({
      args: [callback, REDIRECT],
    }));
    expect(h.complete).not.toHaveBeenCalled();
    await expect(h.store.read()).resolves.toBeUndefined();
  });
});
