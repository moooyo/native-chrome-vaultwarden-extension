import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AutofillContinuationCoordinator } from './autofill-continuation-coordinator.js';
import { AutofillContinuationStore } from './autofill-continuation-store.js';

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
  const sendToDocument = vi.fn(async (_tabId, _frameId, _documentId, command: { type: string }) => (
    command.type === 'autofill.awaitFocus' ? { status: 'focused' } : undefined
  ));
  const issueCommand = vi.fn(() => '00000000-0000-4000-8000-000000000099');
  const sendFocusedFill = vi.fn(async () => undefined);
  const runCommand = vi.fn(async () => undefined);
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
    focusSource: vi.fn(async () => undefined),
    openPopup: vi.fn(async () => undefined),
    openPopupFallback: vi.fn(async () => undefined),
    isPopupDocumentOpen: async () => popupOpen,
    sendToDocument,
    sendFocusedFill,
    runCommand,
    keyboardGrants: { issueCommand },
    tabAutofill: { getSuggestions, fill },
    getFillData: vi.fn(async () => ({})),
    readLoginCopyValue,
    clipboard: { writeSecretAndScheduleClear, writeTotpAndScheduleClear },
    now: () => Date.now(),
  });
  const source = {
    tabId: 7,
    windowId: 3,
    topDocumentId: 'top-doc',
    topUrl: 'https://example.com/login?code=secret#step',
    frameId: 2,
    frameDocumentId: 'frame-doc',
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
    sendToDocument,
    fill,
    readLoginCopyValue,
    writeSecretAndScheduleClear,
    writeTotpAndScheduleClear,
    setState(value: 'locked' | 'unlocked') { state = value; },
    setPopupOpen(value: boolean) { popupOpen = value; },
    setVerified(value: boolean) { verified = value; },
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

    expect(h.sendToDocument.mock.calls.some(([, , , command]) => command.type === 'autofill.awaitFocus')).toBe(true);
    expect(h.sendFocusedFill).toHaveBeenCalledOnce();
  });

  it('keeps an exact Popup-owned reprompt after a wrong password and consumes it after success', async () => {
    const h = harness();
    h.setState('unlocked');
    await h.coordinator.stageContextLoginReprompt(h.source, 'cipher-1', {
      kind: 'login', frameId: 2, documentId: 'frame-doc', formId: 'form-1', generation: 1,
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
    ));
  });

  it('resumes an exact command fill with a fresh reprompt authorization', async () => {
    const h = harness();
    h.setState('unlocked');
    await h.coordinator.stageCommandFillReprompt(h.source, {
      command: 'autofill-login',
      cipherId: 'cipher-1',
      target: {
        kind: 'login', frameId: 2, documentId: 'frame-doc', formId: 'form-1', generation: 1,
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
