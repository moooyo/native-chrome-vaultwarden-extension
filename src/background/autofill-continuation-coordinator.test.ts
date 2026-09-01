import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AutofillContinuationCoordinator } from './autofill-continuation-coordinator.js';
import { AutofillContinuationStore } from './autofill-continuation-store.js';

const TOP_RUNTIME = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const FRAME_RUNTIME = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NEXT_TOP_RUNTIME = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const NEXT_FRAME_RUNTIME = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';

function memoryStore() {
  const values = new Map<string, unknown>();
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const value = values.get(key);
      return value === undefined ? undefined : structuredClone(value) as T;
    },
    async set(key: string, value: unknown) { values.set(key, structuredClone(value)); },
    async remove(key: string) { values.delete(key); },
  };
}

function harness(options: {
  backing?: ReturnType<typeof memoryStore>;
  workerInstanceId?: string;
} = {}) {
  let state: 'locked' | 'unlocked' = 'locked';
  let popupOpen = true;
  let accountGeneration = 2;
  let sessionGeneration = 1;
  let autofillPolicyGeneration = 3;
  let verified = false;
  let topRuntimeIncarnation = TOP_RUNTIME;
  let frameRuntimeIncarnation = FRAME_RUNTIME;
  const account = () => Object.freeze({
    serverUrl: 'https://vault.example.com/',
    accountIdentity: 'user@example.com',
    serverGeneration: 1,
    accountGeneration,
  });
  const policy = () => Object.freeze({
    autofill: Object.freeze({ generation: autofillPolicyGeneration }),
    enterprise: Object.freeze({
      generation: 4,
      serverGeneration: 1,
      accountGeneration,
      serverUrl: 'https://vault.example.com/',
      accountIdentity: 'user@example.com',
      rawGeneration: 'raw-1',
    }),
  });
  const sendToDocument = vi.fn(async (
    _tabId,
    _frameId,
    _documentId,
    command: { type: string; expectedRuntimeIncarnation?: string },
  ) => (
    command.type === 'autofill.awaitFocus' ? { status: 'focused' } : undefined
  ));
  const issueCommand = vi.fn(() => '00000000-0000-4000-8000-000000000099');
  const sendFocusedFill = vi.fn(async () => undefined);
  const runCommand = vi.fn(async () => undefined);
  const openPopup = vi.fn(async () => undefined);
  const fill = vi.fn(async () => ({ status: 'filled' as const }));
  const readLoginCopyValue = vi.fn(async (
    _cipherId: string,
    field: 'password' | 'totp',
    assertRepromptAuthorized: () => void,
    bindFinalAuthority: (assertCurrent: () => void) => void,
  ) => {
    assertRepromptAuthorized();
    bindFinalAuthority(assertRepromptAuthorized);
    return field === 'totp' ? '123456' : 'password';
  });
  const writeSecretAndScheduleClear = vi.fn(async () => true);
  const writeTotpAndScheduleClear = vi.fn(async () => true);
  const getSuggestions = vi.fn(async () => ({ status: 'ready' as const, suggestions: [] }));
  const backing = options.backing ?? memoryStore();
  const store = new AutofillContinuationStore({ store: backing, now: () => Date.now() });
  const coordinator = new AutofillContinuationCoordinator({
    store,
    getState: async () => state,
    sessionGate: {
      capture: () => Object.freeze({ generation: sessionGeneration }),
      assert: (lease) => { if (lease.generation !== sessionGeneration || state !== 'unlocked') throw new Error('stale'); },
    },
    accountGate: {
      capture: account,
      assert: (lease) => { if (lease.accountGeneration !== accountGeneration) throw new Error('stale'); },
    },
    capturePolicy: policy,
    assertPolicy: (lease) => { if (lease.enterprise.accountGeneration !== accountGeneration) throw new Error('stale'); },
    workerInstanceId: options.workerInstanceId ?? '11111111-aaaa-4aaa-8aaa-111111111111',
    getStablePolicyDigest: async () => 'c'.repeat(64),
    verifyMasterPassword: async () => verified,
    getTab: async () => ({ id: 7, windowId: 3, active: true, url: 'https://example.com/login?code=secret#step' }),
    getFrame: async (_tabId, frameId) => ({
      frameId,
      documentId: frameId === 0 ? 'top-doc' : 'frame-doc',
      url: frameId === 0
        ? 'https://example.com/login?code=secret#step'
        : 'https://login.example.com/form?token=secret',
    }),
    isRuntimeCurrent: async (tabId, frameId, documentId, runtimeIncarnation) => tabId === 7
      && documentId === (frameId === 0 ? 'top-doc' : 'frame-doc')
      && runtimeIncarnation === (frameId === 0 ? topRuntimeIncarnation : frameRuntimeIncarnation),
    getRuntimeIncarnation: async (tabId, frameId, documentId) => tabId === 7
      && documentId === (frameId === 0 ? 'top-doc' : 'frame-doc')
      ? (frameId === 0 ? topRuntimeIncarnation : frameRuntimeIncarnation)
      : undefined,
    focusSource: vi.fn(async () => undefined),
    openPopup,
    openPopupFallback: vi.fn(async () => undefined),
    isPopupDocumentOpen: async () => popupOpen,
    sendToDocument,
    sendFocusedFill,
    runCommand,
    keyboardGrants: { issueCommand },
    tabAutofill: { getSuggestions, fill },
    getFillData: vi.fn(async (
      _cipherId,
      _kind,
      _roles,
      assertRepromptAuthorized,
      bindFinalAuthority,
    ) => {
      assertRepromptAuthorized();
      bindFinalAuthority(assertRepromptAuthorized);
      return {};
    }),
    readLoginCopyValue,
    clipboard: { writeSecretAndScheduleClear, writeTotpAndScheduleClear },
    now: () => Date.now(),
  });
  const source = {
    tabId: 7,
    windowId: 3,
    topDocumentId: 'top-doc',
    topRuntimeIncarnation: TOP_RUNTIME,
    topUrl: 'https://example.com/login?code=secret#step',
    frameId: 2,
    frameDocumentId: 'frame-doc',
    frameRuntimeIncarnation: FRAME_RUNTIME,
    frameUrl: 'https://login.example.com/form?token=secret',
  } as const;
  return {
    coordinator,
    backing,
    store,
    source,
    issueCommand,
    sendFocusedFill,
    runCommand,
    openPopup,
    sendToDocument,
    getSuggestions,
    fill,
    readLoginCopyValue,
    writeSecretAndScheduleClear,
    writeTotpAndScheduleClear,
    setState(value: 'locked' | 'unlocked') { state = value; },
    setPopupOpen(value: boolean) { popupOpen = value; },
    setVerified(value: boolean) { verified = value; },
    setTopRuntime(value: string) { topRuntimeIncarnation = value; },
    setFrameRuntime(value: string) { frameRuntimeIncarnation = value; },
    keyboardGrant() {
      return {
        tabId: 7,
        frameId: 2,
        documentId: 'frame-doc',
        runtimeIncarnation: FRAME_RUNTIME,
        frameUrl: source.frameUrl,
        topDocumentId: 'top-doc',
        topFrameUrl: source.topUrl,
        binding: { purpose: 'totp' as const },
        purpose: 'totp' as const,
        sessionLease: Object.freeze({ generation: sessionGeneration }),
        accountLease: account(),
        policyLease: policy(),
      } as unknown as Parameters<AutofillContinuationCoordinator['stageKeyboardReprompt']>[0];
    },
    bumpAccount() { accountGeneration += 1; },
    bumpSession() { sessionGeneration += 1; },
    bumpAutofillPolicyGeneration() { autofillPolicyGeneration += 1; },
  };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-09-01T00:00:00Z'));
});

afterEach(() => vi.useRealTimers());

describe('AutofillContinuationCoordinator', () => {
  it('waits for exact Popup closure and a real source focus acknowledgement before minting', async () => {
    const h = harness();
    await h.coordinator.stageLockedKeyboard({
      tabId: 7,
      windowId: 3,
      topDocumentId: 'top-doc',
      topFrameUrl: h.source.topUrl,
    });
    const status = await h.coordinator.status('popup-doc');
    expect(status.status).toBe('unlock_required');
    if (status.status !== 'unlock_required') throw new Error('expected continuation');
    h.setState('unlocked');
    h.bumpAutofillPolicyGeneration();
    await h.coordinator.reconcilePolicy();

    expect(await h.coordinator.resumeUnlock('popup-doc', status.continuationId)).toEqual({ status: 'started' });
    await Promise.resolve();
    expect(h.issueCommand).not.toHaveBeenCalled();
    h.setPopupOpen(false);
    await vi.advanceTimersByTimeAsync(30);
    await vi.waitFor(() => expect(h.issueCommand).toHaveBeenCalledOnce());

    expect(h.sendToDocument.mock.calls.some(([, , , command]) => (
      command.type === 'autofill.awaitFocus'
      && command.expectedRuntimeIncarnation === TOP_RUNTIME
    ))).toBe(true);
    expect(h.sendFocusedFill).toHaveBeenCalledOnce();
  });

  it('does not accept a focus acknowledgement after the owning runtime was replaced', async () => {
    const h = harness();
    h.sendToDocument.mockImplementation(async (_tabId, _frameId, _documentId, command) => {
      if (command.type !== 'autofill.awaitFocus') return undefined;
      h.setTopRuntime(NEXT_TOP_RUNTIME);
      return { status: 'focused' };
    });
    await h.coordinator.stageLockedKeyboard({
      tabId: 7,
      windowId: 3,
      topDocumentId: 'top-doc',
      topFrameUrl: h.source.topUrl,
    });
    const status = await h.coordinator.status('popup-doc');
    if (status.status !== 'unlock_required') throw new Error('expected continuation');
    h.setState('unlocked');
    expect(await h.coordinator.resumeUnlock('popup-doc', status.continuationId)).toEqual({ status: 'started' });
    h.setPopupOpen(false);

    await vi.advanceTimersByTimeAsync(30);
    await vi.waitFor(() => expect(h.sendToDocument).toHaveBeenCalled());
    expect(h.issueCommand).not.toHaveBeenCalled();
    expect(h.sendFocusedFill).not.toHaveBeenCalled();
  });

  it('invalidates a durable continuation when the frame runtime changes under the same document', async () => {
    const h = harness();
    await h.coordinator.stageLockedContext(h.source);
    h.setFrameRuntime(NEXT_FRAME_RUNTIME);

    expect(await h.coordinator.status('popup-doc')).toEqual({ status: 'none' });
    expect(await h.store.read()).toBeUndefined();
  });

  it('removes a continuation when its runtime changes while persistence is settling', async () => {
    const h = harness();
    const put = h.store.put.bind(h.store);
    vi.spyOn(h.store, 'put').mockImplementation(async (envelope) => {
      await put(envelope);
      h.setFrameRuntime(NEXT_FRAME_RUNTIME);
    });

    await expect(h.coordinator.stageLockedContext(h.source)).rejects.toThrow(/stale/i);
    expect(await h.store.read()).toBeUndefined();
    expect(h.openPopup).not.toHaveBeenCalled();
  });

  it('serializes concurrent continuation staging through one coordinator lane', async () => {
    const h = harness();
    let releaseFirst!: () => void;
    h.openPopup.mockImplementationOnce(() => new Promise<undefined>((resolve) => {
      releaseFirst = () => resolve(undefined);
    }));

    const first = h.coordinator.stageLockedContext(h.source);
    await vi.waitFor(() => expect(h.openPopup).toHaveBeenCalledOnce());
    const second = h.coordinator.stageLockedContext(h.source);
    await Promise.resolve();
    expect(h.openPopup).toHaveBeenCalledOnce();

    releaseFirst();
    await first;
    await second;
    expect(h.openPopup).toHaveBeenCalledTimes(2);
  });

  it('keeps an exact Popup-owned reprompt after a wrong password and consumes it after success', async () => {
    const h = harness();
    h.setState('unlocked');
    await h.coordinator.stageContextLoginReprompt(h.source, 'cipher-1', {
      kind: 'login', frameId: 2, documentId: 'frame-doc', runtimeIncarnation: FRAME_RUNTIME,
      formId: 'form-1', generation: 1,
      customPlanDigest: 'plan-digest',
    });
    const status = await h.coordinator.status('popup-doc');
    expect(status.status).toBe('reprompt_required');
    if (status.status !== 'reprompt_required') throw new Error('expected continuation');

    expect(await h.coordinator.authorizeReprompt('popup-doc', status.continuationId, 'wrong'))
      .toEqual({ verified: false });
    expect((await h.store.read())?.continuationId).toBe(status.continuationId);

    h.setVerified(true);
    expect(await h.coordinator.authorizeReprompt('popup-doc', status.continuationId, 'right'))
      .toEqual({ verified: true, result: { status: 'started' } });
    h.setPopupOpen(false);
    await vi.advanceTimersByTimeAsync(30);
    await vi.waitFor(() => expect(h.fill).toHaveBeenCalledOnce());
  });

  it('binds a keyboard proof and resume command to the exact frame runtime', async () => {
    const h = harness();
    h.setState('unlocked');
    const continuationId = await h.coordinator.stageKeyboardReprompt(h.keyboardGrant(), 'cipher-1');
    const status = await h.coordinator.status('popup-doc');
    if (status.status !== 'reprompt_required') throw new Error('expected continuation');
    h.setVerified(true);
    await h.coordinator.authorizeReprompt('popup-doc', continuationId, 'right');
    h.setPopupOpen(false);
    await vi.advanceTimersByTimeAsync(30);
    await vi.waitFor(() => expect(h.sendToDocument.mock.calls.some(([, , , command]) => (
      command.type === 'autofill.resumeKeyboardReprompt'
      && command.expectedRuntimeIncarnation === FRAME_RUNTIME
    ))).toBe(true));

    const redeemed = await h.coordinator.redeemKeyboardReprompt(continuationId, {
      tabId: 7,
      frameId: 2,
      documentId: 'frame-doc',
      runtimeIncarnation: FRAME_RUNTIME,
      url: h.source.frameUrl,
    });
    expect(redeemed).toMatchObject({ cipherId: 'cipher-1', runtimeIncarnation: FRAME_RUNTIME });
    expect(redeemed?.source.frameRuntimeIncarnation).toBe(FRAME_RUNTIME);
  });

  it('consumes a keyboard proof when a different runtime tries to redeem it', async () => {
    const h = harness();
    h.setState('unlocked');
    const continuationId = await h.coordinator.stageKeyboardReprompt(h.keyboardGrant(), 'cipher-1');
    const status = await h.coordinator.status('popup-doc');
    if (status.status !== 'reprompt_required') throw new Error('expected continuation');
    h.setVerified(true);
    await h.coordinator.authorizeReprompt('popup-doc', continuationId, 'right');
    h.setPopupOpen(false);
    await vi.advanceTimersByTimeAsync(30);
    await vi.waitFor(() => expect(h.sendToDocument.mock.calls.some(([, , , command]) => (
      command.type === 'autofill.resumeKeyboardReprompt'
    ))).toBe(true));

    expect(await h.coordinator.redeemKeyboardReprompt(continuationId, {
      tabId: 7,
      frameId: 2,
      documentId: 'frame-doc',
      runtimeIncarnation: NEXT_FRAME_RUNTIME,
      url: h.source.frameUrl,
    })).toBeUndefined();
    expect(await h.coordinator.redeemKeyboardReprompt(continuationId, {
      tabId: 7,
      frameId: 2,
      documentId: 'frame-doc',
      runtimeIncarnation: FRAME_RUNTIME,
      url: h.source.frameUrl,
    })).toBeUndefined();
  });

  it('consumes a keyboard proof before rejecting a noncanonical runtime', async () => {
    const h = harness();
    h.setState('unlocked');
    const continuationId = await h.coordinator.stageKeyboardReprompt(h.keyboardGrant(), 'cipher-1');
    const status = await h.coordinator.status('popup-doc');
    if (status.status !== 'reprompt_required') throw new Error('expected continuation');
    h.setVerified(true);
    await h.coordinator.authorizeReprompt('popup-doc', continuationId, 'right');
    h.setPopupOpen(false);
    await vi.advanceTimersByTimeAsync(30);

    expect(await h.coordinator.redeemKeyboardReprompt(continuationId, {
      tabId: 7,
      frameId: 2,
      documentId: 'frame-doc',
      runtimeIncarnation: FRAME_RUNTIME.toUpperCase(),
      url: h.source.frameUrl,
    })).toBeUndefined();
    expect(await h.coordinator.redeemKeyboardReprompt(continuationId, {
      tabId: 7,
      frameId: 2,
      documentId: 'frame-doc',
      runtimeIncarnation: FRAME_RUNTIME,
      url: h.source.frameUrl,
    })).toBeUndefined();
  });

  it('binds held-target resume and cancellation commands to the source runtime', async () => {
    const h = harness();
    h.setState('unlocked');
    await h.coordinator.stageContextStructuredReprompt(h.source, {
      cipherId: 'cipher-1',
      holdId: '11111111-1111-4111-8111-111111111111',
      scope: 'field',
      fillKind: 'card',
      roles: ['number'],
      runtimeIncarnation: FRAME_RUNTIME,
    });
    const cancellation = await h.coordinator.status('popup-doc');
    if (cancellation.status !== 'reprompt_required') throw new Error('expected continuation');
    expect(await h.coordinator.cancel('popup-doc', cancellation.continuationId)).toBe(true);
    expect(h.sendToDocument).toHaveBeenCalledWith(7, 2, 'frame-doc', expect.objectContaining({
      type: 'autofill.cancelHeldFillTarget',
      expectedRuntimeIncarnation: FRAME_RUNTIME,
    }));

    h.sendToDocument.mockClear();
    await h.coordinator.stageContextStructuredReprompt(h.source, {
      cipherId: 'cipher-1',
      holdId: '22222222-2222-4222-8222-222222222222',
      scope: 'field',
      fillKind: 'card',
      roles: ['number'],
      runtimeIncarnation: FRAME_RUNTIME,
    });
    const resume = await h.coordinator.status('popup-doc');
    if (resume.status !== 'reprompt_required') throw new Error('expected continuation');
    h.setVerified(true);
    await h.coordinator.authorizeReprompt('popup-doc', resume.continuationId, 'right');
    h.setPopupOpen(false);
    await vi.advanceTimersByTimeAsync(30);
    await vi.waitFor(() => expect(h.sendToDocument).toHaveBeenCalledWith(
      7,
      2,
      'frame-doc',
      expect.objectContaining({
        type: 'autofill.resumeHeldFillTarget',
        expectedRuntimeIncarnation: FRAME_RUNTIME,
      }),
    ));
  });

  it('fails closed after a worker restart instead of reviving a public envelope with unknown leases', async () => {
    const h = harness();
    await h.coordinator.stageLockedContext(h.source);
    const restarted = harness({
      backing: h.backing,
      workerInstanceId: '22222222-bbbb-4bbb-8bbb-222222222222',
    });

    expect(await restarted.coordinator.status('new-popup-doc')).toEqual({ status: 'none' });
    expect(await restarted.store.read()).toBeUndefined();
  });

  it('returns only exact-tab suggestions for locked context and never guesses a cipher', async () => {
    const h = harness();
    await h.coordinator.stageLockedContext(h.source);
    const status = await h.coordinator.status('popup-doc');
    if (status.status !== 'unlock_required') throw new Error('expected continuation');
    h.setState('unlocked');

    expect(await h.coordinator.resumeUnlock('popup-doc', status.continuationId)).toEqual({
      status: 'show_suggestions',
      tabId: 7,
      outcome: { status: 'ready', suggestions: [] },
    });
    expect(h.issueCommand).not.toHaveBeenCalled();
    expect(h.fill).not.toHaveBeenCalled();
  });

  it('withholds locked-context suggestions when authority changes during the async scan', async () => {
    const h = harness();
    await h.coordinator.stageLockedContext(h.source);
    const status = await h.coordinator.status('popup-doc');
    if (status.status !== 'unlock_required') throw new Error('expected continuation');
    h.setState('unlocked');
    h.getSuggestions.mockImplementationOnce(async () => {
      h.bumpAccount();
      return { status: 'ready' as const, suggestions: [] };
    });

    await expect(h.coordinator.resumeUnlock('popup-doc', status.continuationId))
      .resolves.toEqual({ status: 'stale' });
  });

  it('resumes the exact locked direct command only after Popup closure and source focus', async () => {
    const h = harness();
    await h.coordinator.stageLockedCommand('autofill-card', h.source);
    const status = await h.coordinator.status('popup-doc');
    expect(status).toMatchObject({ status: 'unlock_required', channel: 'keyboard' });
    if (status.status !== 'unlock_required') throw new Error('expected continuation');
    h.setState('unlocked');

    expect(await h.coordinator.resumeUnlock('popup-doc', status.continuationId))
      .toEqual({ status: 'started' });
    await Promise.resolve();
    expect(h.runCommand).not.toHaveBeenCalled();
    h.setPopupOpen(false);
    await vi.advanceTimersByTimeAsync(30);
    await vi.waitFor(() => expect(h.runCommand).toHaveBeenCalledWith(
      'autofill-card',
      { id: 7, windowId: 3 },
      expect.any(Function),
      {
        documentId: 'top-doc',
        runtimeIncarnation: TOP_RUNTIME,
        url: h.source.topUrl,
      },
    ));
  });

  it('resumes an exact command fill with a fresh reprompt authorization', async () => {
    const h = harness();
    h.setState('unlocked');
    await h.coordinator.stageCommandFillReprompt(h.source, {
      command: 'autofill-login',
      cipherId: 'cipher-1',
      target: {
        kind: 'login', frameId: 2, documentId: 'frame-doc', runtimeIncarnation: FRAME_RUNTIME,
        formId: 'form-1', generation: 1,
        customPlanDigest: 'plan-digest',
      },
    });
    const status = await h.coordinator.status('popup-doc');
    if (status.status !== 'reprompt_required') throw new Error('expected continuation');
    expect(status.channel).toBe('keyboard');
    h.setVerified(true);
    await h.coordinator.authorizeReprompt('popup-doc', status.continuationId, 'right');
    h.setPopupOpen(false);
    await vi.advanceTimersByTimeAsync(30);

    await vi.waitFor(() => expect(h.fill).toHaveBeenCalledWith(
      7,
      'cipher-1',
      expect.objectContaining({ kind: 'login', documentId: 'frame-doc' }),
      expect.any(Function),
      { assertCurrent: expect.any(Function) },
    ));
  });

  it('resumes password and TOTP context copies through their separate clipboard channels', async () => {
    for (const field of ['password', 'totp'] as const) {
      const h = harness();
      h.setState('unlocked');
      await h.coordinator.stageContextCopyReprompt(h.source, 'cipher-1', field);
      const status = await h.coordinator.status('popup-doc');
      if (status.status !== 'reprompt_required') throw new Error('expected continuation');
      expect(status.channel).toBe('context');
      h.setVerified(true);
      await h.coordinator.authorizeReprompt('popup-doc', status.continuationId, 'right');
      h.setPopupOpen(false);
      await vi.advanceTimersByTimeAsync(30);

      if (field === 'password') {
        await vi.waitFor(() => expect(h.writeSecretAndScheduleClear)
          .toHaveBeenCalledWith('password', expect.any(Function)));
        expect(h.writeTotpAndScheduleClear).not.toHaveBeenCalled();
      } else {
        await vi.waitFor(() => expect(h.writeTotpAndScheduleClear)
          .toHaveBeenCalledWith('123456', expect.any(Function)));
        expect(h.writeSecretAndScheduleClear).not.toHaveBeenCalled();
      }
    }
  });
});
