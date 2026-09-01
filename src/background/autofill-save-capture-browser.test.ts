import { describe, expect, it, vi } from 'vitest';
import type { SymmetricKey } from '../core/crypto/keys.js';
import type { KeyValueStore } from '../platform/store.js';
import {
  AutofillPendingSaveStore,
  type AutofillPendingSaveDocumentContext,
  type AutofillPendingSaveInput,
} from './autofill-pending-save-store.js';
import {
  AutofillSaveCaptureCoordinator,
  type AutofillSaveCaptureSubmission,
} from './autofill-save-capture-coordinator.js';
import {
  registerAutofillSaveCaptureBrowserListeners,
  type AutofillSaveCaptureChromeApi,
} from './autofill-save-capture-browser.js';

interface InspectableStore extends Pick<KeyValueStore, 'get' | 'set'> {
  peek(key: string): unknown;
}

type BrowserCoordinator = Parameters<typeof registerAutofillSaveCaptureBrowserListeners>[1];
type BrowserFrame = { readonly documentId: string; readonly url: string } | null;

const ADMISSION_ID = '20000000-0000-4000-8000-000000000001';
const RUNTIME_INCARNATION = '10000000-0000-4000-8000-000000000001';
const SOURCE_URL = 'https://accounts.example.com/login?private=source';
const REQUEST_URL = 'https://accounts.example.com/session?private=request';
const REDIRECT_URL = 'https://api.example.com/session/continue?private=redirect';

const INPUT: AutofillPendingSaveInput = Object.freeze({
  tabId: 7,
  frameId: 0,
  sourceDocumentId: 'document-A',
  runtimeIncarnation: RUNTIME_INCARNATION,
  sourceUrl: SOURCE_URL,
  origin: 'https://accounts.example.com',
  sessionGeneration: 1,
  sessionBindingId: 'session-A',
  serverGeneration: 2,
  accountGeneration: 3,
  serverUrl: 'https://vault.example.com/',
  accountIdentity: 'user@example.com',
  policyGeneration: 4,
  enterprisePolicyGeneration: 5,
  enterprisePolicyRawGeneration: 'policy-A',
});

const CONTEXT: AutofillPendingSaveDocumentContext = Object.freeze({
  tabId: INPUT.tabId,
  frameId: INPUT.frameId,
  documentId: 'destination-document',
  runtimeIncarnation: RUNTIME_INCARNATION,
  frameUrl: 'https://accounts.example.com/complete',
  origin: INPUT.origin,
  sessionGeneration: INPUT.sessionGeneration,
  sessionBindingId: INPUT.sessionBindingId,
  serverGeneration: INPUT.serverGeneration,
  accountGeneration: INPUT.accountGeneration,
  serverUrl: INPUT.serverUrl,
  accountIdentity: INPUT.accountIdentity,
  policyGeneration: INPUT.policyGeneration,
  enterprisePolicyGeneration: INPUT.enterprisePolicyGeneration,
  enterprisePolicyRawGeneration: INPUT.enterprisePolicyRawGeneration,
});

const CREDENTIALS = Object.freeze({
  username: 'user@example.com',
  password: 'not-in-journal',
});

const COMMON = Object.freeze({
  requestId: 'request-1',
  tabId: INPUT.tabId,
  frameId: INPUT.frameId,
  documentId: INPUT.sourceDocumentId,
  documentUrl: INPUT.sourceUrl,
  originUrl: INPUT.sourceUrl,
  initiator: INPUT.origin,
  url: REQUEST_URL,
  method: 'POST',
  type: 'xmlhttprequest',
  timeStamp: 1_001,
});

function event() {
  let listener: ((details: Record<string, unknown>) => void) | undefined;
  const addListener = vi.fn((next: (details: Record<string, unknown>) => void) => {
    listener = next;
  });
  return {
    addListener,
    emit(details: Record<string, unknown>) { listener?.(details); },
  };
}

function browserHarness(
  coordinator: BrowserCoordinator,
  getFrameImplementation: (details: { tabId: number; frameId: number }) => Promise<BrowserFrame> =
    async () => ({ documentId: INPUT.sourceDocumentId, url: INPUT.sourceUrl }),
) {
  const onBeforeRequest = event();
  const onBeforeRedirect = event();
  const onCompleted = event();
  const onErrorOccurred = event();
  const warn = vi.fn();
  const getFrame = vi.fn(getFrameImplementation);
  const chromeApi = {
    webRequest: { onBeforeRequest, onBeforeRedirect, onCompleted, onErrorOccurred },
    webNavigation: { getFrame },
  } as unknown as AutofillSaveCaptureChromeApi;
  return {
    onBeforeRequest,
    onBeforeRedirect,
    onCompleted,
    onErrorOccurred,
    warn,
    getFrame,
    register: () => registerAutofillSaveCaptureBrowserListeners(chromeApi, coordinator, { warn }),
  };
}

function fixture() {
  const coordinator = {
    beginBeforeRequest: vi.fn(async (): Promise<string | undefined> => ADMISSION_ID),
    resolveBeforeRequest: vi.fn(async () => {}),
    failBeforeRequest: vi.fn(async () => {}),
    observeRedirect: vi.fn(async () => {}),
    observeCompleted: vi.fn(async () => {}),
    observeError: vi.fn(async () => {}),
    invalidateNetworkWindow: vi.fn(async () => {}),
  };
  return { ...browserHarness(coordinator), coordinator };
}

function memoryStore(): InspectableStore {
  const values = new Map<string, unknown>();
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const value = values.get(key);
      return value === undefined ? undefined : structuredClone(value) as T;
    },
    async set(key: string, value: unknown): Promise<void> {
      values.set(key, structuredClone(value));
    },
    peek(key: string): unknown {
      const value = values.get(key);
      return value === undefined ? undefined : structuredClone(value);
    },
  };
}

function ids(): () => string {
  let sequence = 0;
  return () => `30000000-0000-4000-8000-${String(++sequence).padStart(12, '0')}`;
}

function userKey(seed = 11): SymmetricKey {
  return {
    encKey: new Uint8Array(32).fill(seed),
    macKey: new Uint8Array(32).fill(seed + 1),
  };
}

function captureFixture() {
  let now = 1_000;
  const store = memoryStore();
  const pending = new AutofillPendingSaveStore({
    store,
    storageKey: 'browser-test-pending-save',
    now: () => now,
    ttlMs: 1_000,
    claimLeaseMs: 50,
    createId: ids(),
  });
  const confirmed = vi.fn();
  const coordinator = new AutofillSaveCaptureCoordinator({
    store,
    storageKey: 'browser-test-save-capture-journal',
    captures: pending,
    loadUserKey: async () => userKey(),
    onConfirmed: confirmed,
    scheduler: { schedule: vi.fn(), cancel: vi.fn() },
    now: () => now,
    beforeWindowMs: 10,
    afterWindowMs: 10,
    networkTtlMs: 100,
    maxRequests: 8,
  });
  return {
    ...browserHarness(coordinator),
    store,
    pending,
    coordinator,
    confirmed,
    setNow(value: number) { now = value; },
  };
}

async function activateAndStage(
  fixtureValue: ReturnType<typeof captureFixture>,
  submission: AutofillSaveCaptureSubmission = { kind: 'formless' },
) {
  await expect(fixtureValue.coordinator.activateRuntime({
    tabId: INPUT.tabId,
    frameId: INPUT.frameId,
    documentId: INPUT.sourceDocumentId,
    frameUrl: INPUT.sourceUrl,
    runtimeIncarnation: INPUT.runtimeIncarnation,
  })).resolves.toBe(true);
  return fixtureValue.coordinator.stage(INPUT, CREDENTIALS, userKey(), submission);
}

async function claim(pending: AutofillPendingSaveStore) {
  return pending.claim(CONTEXT, userKey(), async () => ({
    action: 'save' as const,
    suggestedName: 'Example',
  }));
}

function journalText(store: InspectableStore): string {
  return JSON.stringify(store.peek('browser-test-save-capture-journal'));
}

describe('registerAutofillSaveCaptureBrowserListeners', () => {
  it('registers non-blocking HTTP listeners without requestBody access', () => {
    const f = fixture();
    expect(f.register()).toBe(true);

    for (const entry of [f.onBeforeRequest, f.onBeforeRedirect, f.onCompleted, f.onErrorOccurred]) {
      expect(entry.addListener).toHaveBeenCalledWith(expect.any(Function), {
        urls: ['http://*/*', 'https://*/*'],
        types: ['main_frame', 'sub_frame', 'xmlhttprequest'],
      });
      expect(entry.addListener.mock.calls[0]).toHaveLength(2);
    }
  });

  it('admits and resolves Chromium XHR and navigation sources without Firefox-only URL fields', async () => {
    const f = fixture();
    f.register();
    f.onBeforeRequest.emit({
      ...COMMON,
      documentUrl: undefined,
      originUrl: undefined,
      requestBody: { raw: [{ bytes: new Uint8Array([1]) }] },
    });
    await vi.waitFor(() => expect(f.coordinator.resolveBeforeRequest).toHaveBeenCalledOnce());
    expect(f.coordinator.beginBeforeRequest).toHaveBeenCalledWith({
      requestId: COMMON.requestId,
      tabId: COMMON.tabId,
      frameId: COMMON.frameId,
      documentId: COMMON.documentId,
      timeStamp: COMMON.timeStamp,
    });
    expect(f.coordinator.resolveBeforeRequest).toHaveBeenCalledWith(ADMISSION_ID, {
      requestId: COMMON.requestId,
      tabId: COMMON.tabId,
      frameId: COMMON.frameId,
      documentId: COMMON.documentId,
      sourceDocumentUrl: COMMON.documentUrl,
      initiator: COMMON.initiator,
      url: COMMON.url,
      method: COMMON.method,
      type: COMMON.type,
      timeStamp: COMMON.timeStamp,
    });
    expect(JSON.stringify(f.coordinator.resolveBeforeRequest.mock.calls)).not.toContain('requestBody');

    f.coordinator.beginBeforeRequest.mockClear();
    f.coordinator.resolveBeforeRequest.mockClear();
    f.getFrame.mockResolvedValueOnce({
      documentId: 'source-document',
      url: COMMON.originUrl,
    });
    f.onBeforeRequest.emit({
      ...COMMON,
      requestId: 'navigation-without-origin-url',
      type: 'main_frame',
      documentUrl: undefined,
      originUrl: undefined,
    });
    await vi.waitFor(() => expect(f.coordinator.resolveBeforeRequest).toHaveBeenCalledWith(
      ADMISSION_ID,
      expect.objectContaining({
        documentId: 'source-document',
        sourceDocumentUrl: COMMON.originUrl,
        url: COMMON.url,
        type: 'main_frame',
      }),
    ));
    expect(f.coordinator.beginBeforeRequest).toHaveBeenCalledWith({
      requestId: 'navigation-without-origin-url',
      tabId: COMMON.tabId,
      frameId: COMMON.frameId,
      timeStamp: COMMON.timeStamp,
    });

    f.coordinator.beginBeforeRequest.mockClear();
    f.coordinator.resolveBeforeRequest.mockClear();
    f.onBeforeRequest.emit({
      ...COMMON,
      requestId: 'navigation-mismatched-origin-url',
      type: 'main_frame',
      originUrl: 'https://other.example.com/',
    });
    await Promise.resolve();
    expect(f.coordinator.beginBeforeRequest).not.toHaveBeenCalled();
    expect(f.coordinator.resolveBeforeRequest).not.toHaveBeenCalled();
  });

  it('forwards terminal and redirect evidence with method and resource type', async () => {
    const f = fixture();
    f.register();
    f.onBeforeRedirect.emit({
      ...COMMON,
      redirectUrl: 'https://app.example.com/complete',
      statusCode: 302,
    });
    f.onCompleted.emit({ ...COMMON, method: 'GET', statusCode: 200 });
    f.onErrorOccurred.emit({ ...COMMON, method: 'GET' });

    await vi.waitFor(() => expect(f.coordinator.observeError).toHaveBeenCalledOnce());

    expect(f.coordinator.observeRedirect).toHaveBeenCalledWith(expect.objectContaining({
      method: 'POST', type: 'xmlhttprequest', statusCode: 302,
    }));
    expect(f.coordinator.observeCompleted).toHaveBeenCalledWith(expect.objectContaining({
      method: 'GET', type: 'xmlhttprequest', statusCode: 200,
    }));
    expect(f.coordinator.observeError).toHaveBeenCalledWith(expect.objectContaining({
      method: 'GET', type: 'xmlhttprequest',
    }));
  });

  it('serializes source resolution ahead of fast redirect and completion events in one request lane', async () => {
    const f = fixture();
    let resolveFrame!: (frame: Exclude<BrowserFrame, null>) => void;
    f.getFrame.mockImplementationOnce(() => new Promise<Exclude<BrowserFrame, null>>((resolve) => {
      resolveFrame = resolve;
    }));
    f.register();
    f.onBeforeRequest.emit({
      ...COMMON,
      type: 'main_frame',
      documentId: 'target-document',
      documentUrl: 'https://app.example.com/complete',
    });
    f.onBeforeRedirect.emit({
      ...COMMON,
      type: 'main_frame',
      documentId: 'target-document',
      redirectUrl: 'https://app.example.com/complete',
      statusCode: 302,
    });
    f.onCompleted.emit({
      ...COMMON,
      type: 'main_frame',
      documentId: 'destination-document',
      url: 'https://app.example.com/complete',
      method: 'GET',
      statusCode: 200,
    });

    await vi.waitFor(() => expect(f.getFrame).toHaveBeenCalledOnce());
    expect(f.coordinator.resolveBeforeRequest).not.toHaveBeenCalled();
    expect(f.coordinator.observeRedirect).not.toHaveBeenCalled();
    expect(f.coordinator.observeCompleted).not.toHaveBeenCalled();
    resolveFrame({ documentId: INPUT.sourceDocumentId, url: COMMON.originUrl });
    await vi.waitFor(() => expect(f.coordinator.observeCompleted).toHaveBeenCalledOnce());

    expect(f.coordinator.resolveBeforeRequest.mock.invocationCallOrder[0])
      .toBeLessThan(f.coordinator.observeRedirect.mock.invocationCallOrder[0]!);
    expect(f.coordinator.observeRedirect.mock.invocationCallOrder[0])
      .toBeLessThan(f.coordinator.observeCompleted.mock.invocationCallOrder[0]!);
  });

  it('fails an admitted request closed when browser-owned source resolution is invalid', async () => {
    const f = fixture();
    f.getFrame.mockResolvedValueOnce({
      documentId: INPUT.sourceDocumentId,
      url: 'https://other.example.com/',
    });
    f.register();
    f.onBeforeRequest.emit(COMMON);

    await vi.waitFor(() => expect(f.coordinator.failBeforeRequest).toHaveBeenCalledWith(ADMISSION_ID));
    expect(f.coordinator.resolveBeforeRequest).not.toHaveBeenCalled();
    expect(f.warn).not.toHaveBeenCalled();
  });

  it('ignores malformed, bodyless GET starts and unavailable APIs', () => {
    const f = fixture();
    f.register();
    f.onBeforeRequest.emit({ ...COMMON, method: 'GET' });
    f.onBeforeRequest.emit({ ...COMMON, documentId: undefined });
    f.onCompleted.emit({ ...COMMON, statusCode: '200' });
    expect(f.coordinator.beginBeforeRequest).not.toHaveBeenCalled();
    expect(f.coordinator.resolveBeforeRequest).not.toHaveBeenCalled();
    expect(f.coordinator.observeCompleted).not.toHaveBeenCalled();
    expect(registerAutofillSaveCaptureBrowserListeners(undefined, f.coordinator)).toBe(false);
  });

  it('contains async failures behind fixed non-sensitive log events after failing the admission', async () => {
    const f = fixture();
    f.coordinator.resolveBeforeRequest.mockRejectedValueOnce(new Error('private URL must not be logged'));
    f.register();
    f.onBeforeRequest.emit(COMMON);
    await vi.waitFor(() => expect(f.warn).toHaveBeenCalledWith('before_request'));

    expect(f.coordinator.failBeforeRequest).toHaveBeenCalledWith(ADMISSION_ID);
    expect(f.warn).not.toHaveBeenCalledWith(expect.stringContaining('private'));
  });

  it('fails closed when admission setup throws before returning a promise', async () => {
    const f = fixture();
    f.coordinator.beginBeforeRequest.mockImplementationOnce(() => {
      throw new Error('private admission details must not be logged');
    });
    f.register();

    expect(() => f.onBeforeRequest.emit(COMMON)).not.toThrow();
    await vi.waitFor(() => expect(f.warn).toHaveBeenCalledWith('before_request'));

    expect(f.coordinator.invalidateNetworkWindow).toHaveBeenCalledOnce();
    expect(f.coordinator.invalidateNetworkWindow).toHaveBeenCalledWith(expect.any(Number));
    expect(f.getFrame).not.toHaveBeenCalled();
    expect(f.coordinator.resolveBeforeRequest).not.toHaveBeenCalled();
    expect(f.coordinator.failBeforeRequest).not.toHaveBeenCalled();
    expect(f.warn).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(f.warn.mock.calls)).not.toContain('private admission details');
  });

  it('invalidates the correlation window instead of dropping evidence when request lanes overflow', async () => {
    const f = fixture();
    f.getFrame.mockImplementation(() => new Promise(() => {}));
    f.register();
    for (let index = 0; index <= 128; index += 1) {
      f.onBeforeRequest.emit({
        ...COMMON,
        requestId: `request-${index}`,
        type: 'main_frame',
      });
    }

    expect(f.coordinator.invalidateNetworkWindow).toHaveBeenCalledOnce();
  });

  it('holds a successful completion behind every in-window before-request admission', async () => {
    const f = captureFixture();
    const metadata = await activateAndStage(f);
    let resolveSecondFrame!: (frame: Exclude<BrowserFrame, null>) => void;
    f.getFrame.mockResolvedValueOnce({
      documentId: INPUT.sourceDocumentId,
      url: INPUT.sourceUrl,
    });
    f.getFrame.mockImplementationOnce(() => new Promise<Exclude<BrowserFrame, null>>((resolve) => {
      resolveSecondFrame = resolve;
    }));
    f.register();
    f.onBeforeRequest.emit({ ...COMMON, requestId: 'candidate-A', timeStamp: 1_001 });
    f.onBeforeRequest.emit({
      ...COMMON,
      requestId: 'candidate-B',
      url: 'https://api.example.com/metric',
      timeStamp: 1_002,
    });
    f.onCompleted.emit({
      ...COMMON,
      requestId: 'candidate-A',
      statusCode: 200,
      timeStamp: 1_003,
    });

    await vi.waitFor(() => {
      expect(f.getFrame).toHaveBeenCalledTimes(2);
      expect(journalText(f.store)).toContain('"requestId":"candidate-B"');
      expect(journalText(f.store)).toContain('"phase":"succeeded"');
    });
    f.setNow(1_011);
    await f.coordinator.reconcile();

    await expect(f.pending.captureState(metadata.captureId)).resolves.toBe('unconfirmed');
    await expect(claim(f.pending)).resolves.toEqual({ action: 'none' });
    expect(f.confirmed).not.toHaveBeenCalled();

    resolveSecondFrame({ documentId: INPUT.sourceDocumentId, url: INPUT.sourceUrl });
    await vi.waitFor(async () => {
      await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    });
    expect(f.confirmed).not.toHaveBeenCalled();
  });

  it('fails an admitted capture closed when resolved request parsing rejects', async () => {
    const f = captureFixture();
    const metadata = await activateAndStage(f);
    f.register();
    f.onBeforeRequest.emit({
      ...COMMON,
      requestId: 'invalid-request-url',
      url: 'https://private:credential@accounts.example.com/session',
    });

    await vi.waitFor(() => expect(f.warn).toHaveBeenCalledWith('before_request'));
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(f.confirmed).not.toHaveBeenCalled();
  });

  it('expires an unresolved before-request admission as fail-closed evidence', async () => {
    const f = captureFixture();
    const metadata = await activateAndStage(f);
    f.getFrame.mockImplementationOnce(() => new Promise(() => {}));
    f.register();
    f.onBeforeRequest.emit({ ...COMMON, requestId: 'timed-out-resolution' });

    await vi.waitFor(() => expect(f.getFrame).toHaveBeenCalledOnce());
    f.setNow(1_102);
    await f.coordinator.reconcile();

    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(f.confirmed).not.toHaveBeenCalled();
  });

  it.each([307, 308] as const)(
    'accepts a method-preserving %i redirect continuation with the same request id',
    async (statusCode) => {
      const f = captureFixture();
      const metadata = await activateAndStage(f, {
        kind: 'native',
        actionUrl: REQUEST_URL,
        method: 'POST',
      });
      f.register();
      f.onBeforeRequest.emit({ ...COMMON, requestId: 'redirect-request', timeStamp: 1_001 });
      f.onBeforeRedirect.emit({
        ...COMMON,
        requestId: 'redirect-request',
        redirectUrl: REDIRECT_URL,
        statusCode,
        timeStamp: 1_002,
      });
      f.onBeforeRequest.emit({
        ...COMMON,
        requestId: 'redirect-request',
        url: REDIRECT_URL,
        timeStamp: 1_003,
      });
      f.onCompleted.emit({
        ...COMMON,
        requestId: 'redirect-request',
        url: REDIRECT_URL,
        statusCode: 204,
        timeStamp: 1_004,
      });

      await vi.waitFor(() => expect(journalText(f.store)).toContain('"phase":"succeeded"'));
      f.setNow(1_011);
      await f.coordinator.reconcile();

      expect(f.confirmed).toHaveBeenCalledWith(metadata);
      await expect(claim(f.pending)).resolves.toMatchObject({ action: 'save' });
    },
  );

  it('rejects same-request-id A-B-A reuse that does not match the redirect continuation', async () => {
    const f = captureFixture();
    const metadata = await activateAndStage(f, {
      kind: 'native',
      actionUrl: REQUEST_URL,
      method: 'POST',
    });
    f.register();
    f.onBeforeRequest.emit({ ...COMMON, requestId: 'aba-request', timeStamp: 1_001 });
    f.onBeforeRedirect.emit({
      ...COMMON,
      requestId: 'aba-request',
      redirectUrl: REDIRECT_URL,
      statusCode: 307,
      timeStamp: 1_002,
    });
    f.onBeforeRequest.emit({
      ...COMMON,
      requestId: 'aba-request',
      url: REQUEST_URL,
      timeStamp: 1_003,
    });

    await vi.waitFor(async () => {
      await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    });
    expect(f.confirmed).not.toHaveBeenCalled();
    expect(f.warn).not.toHaveBeenCalled();
  });
});
