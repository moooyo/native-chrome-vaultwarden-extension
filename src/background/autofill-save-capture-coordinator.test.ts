import { describe, expect, it, vi } from 'vitest';
import type { SymmetricKey } from '../core/crypto/keys.js';
import type { KeyValueStore } from '../platform/store.js';
import {
  AutofillPendingSaveStore,
  type AutofillPendingSaveDocumentContext,
  type AutofillPendingSaveInput,
} from './autofill-pending-save-store.js';
import {
  AUTOFILL_SAVE_CAPTURE_NETWORK_SCHEMA_VERSION,
  AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY,
  AutofillSaveCaptureCoordinator,
  type AutofillSaveCaptureBeforeRequest,
  type AutofillSaveCaptureBeforeRequestAdmission,
  type AutofillSaveCaptureCompletedRequest,
  type AutofillSaveCaptureCoordinatorOptions,
  type AutofillSaveCaptureErrorRequest,
  type AutofillSaveCaptureSubmission,
} from './autofill-save-capture-coordinator.js';

interface InspectableStore extends Pick<KeyValueStore, 'get' | 'set'> {
  peek(key: string): unknown;
}

const RUNTIME_A = '20000000-0000-4000-8000-000000000001';
const RUNTIME_B = '20000000-0000-4000-8000-000000000002';
const RUNTIME_C = '20000000-0000-4000-8000-000000000003';
const DESTINATION_RUNTIME = '20000000-0000-4000-8000-000000000004';

const INPUT: AutofillPendingSaveInput = Object.freeze({
  tabId: 7,
  frameId: 0,
  sourceDocumentId: 'document-A',
  runtimeIncarnation: RUNTIME_A,
  sourceUrl: 'https://accounts.example.com/login',
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
const CREDENTIALS = Object.freeze({ username: 'user@example.com', password: 'not-in-journal' });
const CONTEXT: AutofillPendingSaveDocumentContext = Object.freeze({
  tabId: INPUT.tabId,
  frameId: INPUT.frameId,
  documentId: 'destination-document',
  runtimeIncarnation: DESTINATION_RUNTIME,
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

function userKey(seed = 11): SymmetricKey {
  return {
    encKey: new Uint8Array(32).fill(seed),
    macKey: new Uint8Array(32).fill(seed + 1),
  };
}

function ids(): () => string {
  let sequence = 0;
  return () => `10000000-0000-4000-8000-${String(++sequence).padStart(12, '0')}`;
}

function deferred(): { readonly promise: Promise<void>; readonly resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((settle) => { resolve = settle; });
  return { promise, resolve };
}

function fixture(options: {
  now?: number;
  maxRequests?: number;
  onConfirmed?: AutofillSaveCaptureCoordinatorOptions['onConfirmed'];
  assertCurrent?: AutofillSaveCaptureCoordinatorOptions['assertCurrent'];
  loadUserKey?: AutofillSaveCaptureCoordinatorOptions['loadUserKey'];
  clearUsernameRuntime?: AutofillSaveCaptureCoordinatorOptions['clearUsernameRuntime'];
  usernameStages?: AutofillSaveCaptureCoordinatorOptions['usernameStages'];
  maxJournalBytes?: number;
} = {}) {
  let now = options.now ?? 1_000;
  const store = memoryStore();
  const pending = new AutofillPendingSaveStore({
    store,
    storageKey: 'test-pending-save',
    now: () => now,
    ttlMs: 1_000,
    claimLeaseMs: 50,
    createId: ids(),
  });
  const schedule = vi.fn();
  const cancel = vi.fn();
  const confirmed = vi.fn(options.onConfirmed ?? (() => {}));
  const loadUserKey = vi.fn(options.loadUserKey ?? (async () => userKey()));
  const make = () => new AutofillSaveCaptureCoordinator({
    store,
    captures: pending,
    loadUserKey,
    ...(options.assertCurrent ? { assertCurrent: options.assertCurrent } : {}),
    ...(options.clearUsernameRuntime ? { clearUsernameRuntime: options.clearUsernameRuntime } : {}),
    ...(options.usernameStages ? { usernameStages: options.usernameStages } : {}),
    onConfirmed: confirmed,
    scheduler: { schedule, cancel },
    now: () => now,
    beforeWindowMs: 10,
    afterWindowMs: 10,
    networkTtlMs: 100,
    maxRequests: options.maxRequests ?? 8,
    ...(options.maxJournalBytes === undefined ? {} : { maxJournalBytes: options.maxJournalBytes }),
  });
  return {
    store,
    pending,
    make,
    schedule,
    cancel,
    confirmed,
    loadUserKey,
    now: () => now,
    setNow(value: number) { now = value; },
  };
}

async function activateRuntime(
  coordinator: AutofillSaveCaptureCoordinator,
  input: AutofillPendingSaveInput = INPUT,
  previousRuntimeIncarnation?: string,
): Promise<void> {
  const activated = await coordinator.activateRuntime({
    tabId: input.tabId,
    frameId: input.frameId,
    documentId: input.sourceDocumentId,
    frameUrl: input.sourceUrl,
    runtimeIncarnation: input.runtimeIncarnation,
    ...(previousRuntimeIncarnation === undefined ? {} : { previousRuntimeIncarnation }),
  });
  expect(activated).toBe(true);
}

async function runtimeAuthority(
  coordinator: AutofillSaveCaptureCoordinator,
  input: AutofillPendingSaveInput = INPUT,
) {
  const authority = await coordinator.captureRuntimeAuthority(
    input.tabId,
    input.frameId,
    input.sourceDocumentId,
    input.runtimeIncarnation,
  );
  expect(authority).toBeDefined();
  return authority!;
}

async function stageCapture(
  coordinator: AutofillSaveCaptureCoordinator,
  input: AutofillPendingSaveInput = INPUT,
  submission: AutofillSaveCaptureSubmission = { kind: 'formless' },
) {
  await activateRuntime(coordinator, input);
  return coordinator.stage(input, CREDENTIALS, userKey(), submission);
}

function before(overrides: Partial<AutofillSaveCaptureBeforeRequest> = {}): AutofillSaveCaptureBeforeRequest {
  return {
    requestId: 'request-1',
    tabId: INPUT.tabId,
    frameId: INPUT.frameId,
    documentId: INPUT.sourceDocumentId,
    sourceDocumentUrl: INPUT.sourceUrl,
    initiator: INPUT.origin,
    url: 'https://accounts.example.com/session',
    method: 'POST',
    type: 'xmlhttprequest',
    timeStamp: 1_001,
    ...overrides,
  };
}

function admission(
  overrides: Partial<AutofillSaveCaptureBeforeRequestAdmission> = {},
): AutofillSaveCaptureBeforeRequestAdmission {
  return {
    requestId: 'request-1',
    tabId: INPUT.tabId,
    frameId: INPUT.frameId,
    documentId: INPUT.sourceDocumentId,
    sourceDocumentUrl: INPUT.sourceUrl,
    timeStamp: 1_001,
    ...overrides,
  };
}

function usernameStageInput(input: AutofillPendingSaveInput = INPUT) {
  return {
    tabId: input.tabId,
    frameId: input.frameId,
    documentId: input.sourceDocumentId,
    runtimeIncarnation: input.runtimeIncarnation,
    origin: input.origin,
    sessionGeneration: input.sessionGeneration,
    sessionBindingId: input.sessionBindingId,
    serverGeneration: input.serverGeneration,
    accountGeneration: input.accountGeneration,
    serverUrl: input.serverUrl,
    accountIdentity: input.accountIdentity,
    policyGeneration: input.policyGeneration,
    enterprisePolicyGeneration: input.enterprisePolicyGeneration,
    enterprisePolicyRawGeneration: input.enterprisePolicyRawGeneration,
    username: CREDENTIALS.username,
  };
}

async function beginAdmission(
  coordinator: AutofillSaveCaptureCoordinator,
  overrides: Partial<AutofillSaveCaptureBeforeRequestAdmission> = {},
): Promise<string> {
  const admissionId = await coordinator.beginBeforeRequest(admission(overrides));
  expect(admissionId).toMatch(/^[0-9a-f-]{36}$/u);
  if (!admissionId) throw new Error('Expected a before-request admission');
  return admissionId;
}

function completed(overrides: Partial<AutofillSaveCaptureCompletedRequest> = {}): AutofillSaveCaptureCompletedRequest {
  return {
    requestId: 'request-1',
    tabId: INPUT.tabId,
    frameId: INPUT.frameId,
    documentId: INPUT.sourceDocumentId,
    url: 'https://accounts.example.com/session',
    method: 'POST',
    type: 'xmlhttprequest',
    statusCode: 200,
    timeStamp: 1_002,
    ...overrides,
  };
}

async function claim(
  pending: AutofillPendingSaveStore,
  context: AutofillPendingSaveDocumentContext = CONTEXT,
) {
  return pending.claim(context, userKey(), async () => ({
    action: 'save' as const,
    suggestedName: 'Example',
  }));
}

describe('AutofillSaveCaptureCoordinator', () => {
  it('asserts a captured runtime without storage reads or clock observations', async () => {
    const f = fixture();
    const coordinator = f.make();
    await activateRuntime(coordinator);
    const authority = await runtimeAuthority(coordinator);
    const read = vi.spyOn(f.store, 'get');
    f.setNow(-1);

    expect(() => authority.assertCurrent()).not.toThrow();
    expect(() => authority.assertCurrent()).not.toThrow();
    expect(read).not.toHaveBeenCalled();
  });

  it.each([
    ['global clear', (coordinator: AutofillSaveCaptureCoordinator) => coordinator.clear()],
    ['tab clear', (coordinator: AutofillSaveCaptureCoordinator) => coordinator.clearTab(INPUT.tabId)],
    ['navigation', (coordinator: AutofillSaveCaptureCoordinator) => (
      coordinator.noteDocumentNavigation(INPUT.tabId, INPUT.frameId, 'replacement-document')
    )],
    ['runtime replacement', (coordinator: AutofillSaveCaptureCoordinator) => coordinator.activateRuntime({
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      frameUrl: INPUT.sourceUrl,
      runtimeIncarnation: RUNTIME_B,
      previousRuntimeIncarnation: RUNTIME_A,
    })],
  ] as const)('synchronously revokes runtime authority before %s reaches storage', async (_label, revoke) => {
    const f = fixture();
    const coordinator = f.make();
    await activateRuntime(coordinator);
    const authority = await runtimeAuthority(coordinator);

    const revoked = revoke(coordinator);

    expect(() => authority.assertCurrent()).toThrow('Save-capture runtime authority changed');
    await revoked;
    expect(() => authority.assertCurrent()).toThrow('Save-capture runtime authority changed');
  });

  it('does not revive an old authority when the same runtime is activated after clear', async () => {
    const f = fixture();
    const coordinator = f.make();
    await activateRuntime(coordinator);
    const authority = await runtimeAuthority(coordinator);
    await coordinator.clear();
    await activateRuntime(coordinator);
    const replacementAuthority = await runtimeAuthority(coordinator);

    expect(() => authority.assertCurrent()).toThrow('Save-capture runtime authority changed');
    expect(() => replacementAuthority.assertCurrent()).not.toThrow();
  });

  it('preserves unrelated frame authority and revokes all children on top-document navigation', async () => {
    const f = fixture();
    const coordinator = f.make();
    const child = { ...INPUT, frameId: 1, sourceDocumentId: 'child-document', runtimeIncarnation: RUNTIME_B };
    const sibling = { ...INPUT, frameId: 2, sourceDocumentId: 'sibling-document', runtimeIncarnation: RUNTIME_C };
    await activateRuntime(coordinator);
    await activateRuntime(coordinator, child);
    await activateRuntime(coordinator, sibling);
    const topAuthority = await runtimeAuthority(coordinator);
    const childAuthority = await runtimeAuthority(coordinator, child);
    const siblingAuthority = await runtimeAuthority(coordinator, sibling);

    const childNavigation = coordinator.noteDocumentNavigation(INPUT.tabId, child.frameId, 'new-child');
    expect(() => childAuthority.assertCurrent()).toThrow('Save-capture runtime authority changed');
    expect(() => topAuthority.assertCurrent()).not.toThrow();
    expect(() => siblingAuthority.assertCurrent()).not.toThrow();
    await childNavigation;
    await coordinator.clearTab(INPUT.tabId + 1);
    expect(() => siblingAuthority.assertCurrent()).not.toThrow();

    const topNavigation = coordinator.noteDocumentNavigation(INPUT.tabId, 0, 'new-top');
    expect(() => topAuthority.assertCurrent()).toThrow('Save-capture runtime authority changed');
    expect(() => siblingAuthority.assertCurrent()).toThrow('Save-capture runtime authority changed');
    await topNavigation;
  });

  it.each(['reading', 'queued'] as const)(
    'rejects a runtime observation when clear overtakes its %s acquisition',
    async (phase) => {
      const f = fixture();
      const coordinator = f.make();
      await activateRuntime(coordinator);
      const readEntered = deferred();
      const releaseRead = deferred();
      const read = f.store.get.bind(f.store);
      let intercepted = false;
      vi.spyOn(f.store, 'get').mockImplementation(async <T>(key: string): Promise<T | undefined> => {
        const value = await read<T>(key);
        if (key === AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY && !intercepted) {
          intercepted = true;
          readEntered.resolve();
          await releaseRead.promise;
        }
        return value;
      });
      const capture = () => coordinator.captureRuntimeAuthority(
        INPUT.tabId, INPUT.frameId, INPUT.sourceDocumentId, INPUT.runtimeIncarnation,
      );
      const preceding = phase === 'queued' ? coordinator.reconcile() : undefined;
      const acquired = phase === 'reading' ? capture() : undefined;
      await readEntered.promise;
      const authority = acquired ?? capture();
      const cleared = coordinator.clear();
      releaseRead.resolve();

      await expect(authority).resolves.toBeUndefined();
      await preceding;
      await cleared;
    },
  );

  it.each(['missing', 'corrupt', 'unreadable'] as const)(
    'revokes old runtime authority when the persisted journal becomes %s',
    async (failure) => {
      const f = fixture();
      const coordinator = f.make();
      await activateRuntime(coordinator);
      const authority = await runtimeAuthority(coordinator);
      if (failure === 'unreadable') {
        vi.spyOn(f.store, 'get').mockRejectedValueOnce(new Error('journal unavailable'));
        await expect(coordinator.reconcile()).rejects.toThrow('journal unavailable');
      } else {
        await f.store.set(AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY, failure === 'missing' ? undefined : {});
        await coordinator.reconcile();
      }

      expect(() => authority.assertCurrent()).toThrow('Save-capture runtime authority changed');
    },
  );

  it('publishes only after one exact native request succeeds and its correlation window closes', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator, INPUT, {
      kind: 'native',
      actionUrl: 'https://accounts.example.com/session',
      method: 'POST',
    });
    expect(JSON.stringify(f.store.peek(AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY)))
      .not.toContain(CREDENTIALS.password);
    await expect(claim(f.pending)).resolves.toEqual({ action: 'none' });

    await coordinator.observeBeforeRequest(before());
    await coordinator.observeCompleted(completed());
    await expect(claim(f.pending)).resolves.toEqual({ action: 'none' });
    f.setNow(1_010);
    await coordinator.reconcile();

    expect(f.confirmed).toHaveBeenCalledWith(metadata);
    await expect(claim(f.pending)).resolves.toMatchObject({ action: 'save' });
  });

  it('persists only origins, sites, and URL fingerprints rather than sensitive paths or queries', async () => {
    const f = fixture();
    const coordinator = f.make();
    const sourceUrl = 'https://accounts.example.com/login/private?state=source-secret';
    const actionUrl = 'https://api.example.com/auth/private?ticket=action-secret';
    await stageCapture(coordinator, { ...INPUT, sourceUrl }, {
      kind: 'native', actionUrl, method: 'POST',
    });
    await coordinator.observeBeforeRequest(before({
      sourceDocumentUrl: sourceUrl,
      url: actionUrl,
    }));
    await coordinator.observeRedirect({
      requestId: 'request-1',
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      url: actionUrl,
      redirectUrl: 'https://app.example.com/complete/private?code=redirect-secret',
      method: 'POST',
      type: 'xmlhttprequest',
      statusCode: 302,
      timeStamp: 1_002,
    });

    const journal = JSON.stringify(f.store.peek(AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY));
    for (const secret of [
      '/login/private', 'source-secret', '/auth/private', 'action-secret',
      '/complete/private', 'redirect-secret', CREDENTIALS.password,
      INPUT.accountIdentity, INPUT.serverUrl,
    ]) expect(journal).not.toContain(secret);
    expect(journal).toContain('https://accounts.example.com');
    expect(journal).toContain('example.com');
    expect(journal).toMatch(/[0-9a-f]{64}/u);
  });

  it('correlates completion-before-capture across a worker restart', async () => {
    const f = fixture();
    const firstWorker = f.make();
    await activateRuntime(firstWorker);
    const admissionId = await beginAdmission(firstWorker, { timeStamp: 998 });
    await firstWorker.observeCompleted(completed({ timeStamp: 999 }));
    await firstWorker.resolveBeforeRequest(admissionId, before({ timeStamp: 998 }));
    await firstWorker.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });

    f.setNow(1_010);
    const restartedWorker = f.make();
    await restartedWorker.reconcile();

    expect(f.confirmed).toHaveBeenCalledOnce();
    await expect(claim(f.pending)).resolves.toMatchObject({ action: 'save' });
  });

  it('binds a navigation terminal to its source admission even when Chrome reports a new document id', async () => {
    const f = fixture();
    const coordinator = f.make();
    await activateRuntime(coordinator);
    const admissionId = await beginAdmission(coordinator, { timeStamp: 998 });
    await coordinator.observeCompleted(completed({
      documentId: 'destination-document',
      type: 'main_frame',
      timeStamp: 999,
    }));
    await coordinator.resolveBeforeRequest(admissionId, before({
      type: 'main_frame',
      timeStamp: 998,
    }));
    await coordinator.stage(INPUT, CREDENTIALS, userKey(), {
      kind: 'native',
      actionUrl: 'https://accounts.example.com/session',
      method: 'POST',
    });

    f.setNow(1_010);
    await f.make().reconcile();
    expect(f.confirmed).toHaveBeenCalledOnce();
  });

  it.each([
    ['HTTP failure', () => completed({ statusCode: 401 })],
    ['server failure', () => completed({ statusCode: 500 })],
    ['network error', () => ({
      requestId: 'request-1',
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      url: 'https://accounts.example.com/session',
      method: 'POST',
      type: 'xmlhttprequest',
      timeStamp: 1_002,
    })],
  ] as const)('discards an unconfirmed capture on %s', async (label, terminal) => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    await coordinator.observeBeforeRequest(before());
    if (label === 'network error') {
      await coordinator.observeError(terminal() as AutofillSaveCaptureErrorRequest);
    }
    else await coordinator.observeCompleted(terminal() as AutofillSaveCaptureCompletedRequest);

    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    f.setNow(1_010);
    await coordinator.reconcile();
    expect(f.confirmed).not.toHaveBeenCalled();
    await expect(claim(f.pending)).resolves.toEqual({ action: 'none' });
  });

  it.each([
    ['same origin', 'https://accounts.example.com/session', true],
    ['same-site subdomain', 'https://api.example.com/session', true],
    ['same-site scheme downgrade', 'http://api.example.com/session', false],
    ['cross-site', 'https://api.example.net/session', false],
  ] as const)('handles a unique formless SPA request at %s', async (_label, requestUrl, expected) => {
    const f = fixture();
    const coordinator = f.make();
    await stageCapture(coordinator);
    await coordinator.observeBeforeRequest(before({ url: requestUrl }));
    await coordinator.observeCompleted(completed({ url: requestUrl }));
    f.setNow(1_010);
    await coordinator.reconcile();

    expect(f.confirmed).toHaveBeenCalledTimes(expected ? 1 : 0);
    await expect(claim(f.pending)).resolves.toMatchObject({ action: expected ? 'save' : 'none' });
  });

  it('uses exact native action and method so an unrelated advertising XHR cannot confirm', async () => {
    const f = fixture();
    const coordinator = f.make();
    await stageCapture(coordinator, INPUT, {
      kind: 'native', actionUrl: 'https://accounts.example.com/session', method: 'POST',
    });
    await coordinator.observeBeforeRequest(before({
      requestId: 'advertising',
      url: 'https://ads.example.com/metric',
      timeStamp: 1_001,
    }));
    await coordinator.observeCompleted(completed({
      requestId: 'advertising',
      url: 'https://ads.example.com/metric',
      timeStamp: 1_002,
    }));
    f.setNow(1_010);
    await coordinator.reconcile();
    expect(f.confirmed).not.toHaveBeenCalled();

    await coordinator.observeBeforeRequest(before({ requestId: 'login', timeStamp: 1_003 }));
    await coordinator.observeCompleted(completed({ requestId: 'login', timeStamp: 1_004 }));
    await coordinator.reconcile();
    expect(f.confirmed).toHaveBeenCalledOnce();
  });

  it('holds a provisional success behind every admitted browser event in the correlation window', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    const pendingAdmission = await beginAdmission(coordinator, {
      requestId: 'request-B',
      timeStamp: 1_002,
    });
    await coordinator.observeBeforeRequest(before({ requestId: 'request-A' }));
    await coordinator.observeCompleted(completed({ requestId: 'request-A' }));

    f.setNow(1_010);
    await coordinator.reconcile();

    await expect(f.pending.captureState(metadata.captureId)).resolves.toBe('unconfirmed');
    expect(f.confirmed).not.toHaveBeenCalled();

    await coordinator.resolveBeforeRequest(pendingAdmission, before({
      requestId: 'request-B',
      url: 'https://api.example.com/metric',
      timeStamp: 1_002,
    }));

    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(f.confirmed).not.toHaveBeenCalled();
  });

  it('does not confirm while a newly admitted browser event waits behind asynchronous promotion', async () => {
    const keyRequested = deferred();
    const releaseKey = deferred();
    const f = fixture({
      loadUserKey: async () => {
        keyRequested.resolve();
        await releaseKey.promise;
        return userKey();
      },
    });
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    await coordinator.observeBeforeRequest(before({ requestId: 'request-A' }));
    await coordinator.observeCompleted(completed({ requestId: 'request-A' }));
    f.setNow(1_010);

    const reconciliation = coordinator.reconcile();
    await keyRequested.promise;
    const admissionPromise = coordinator.beginBeforeRequest(admission({
      requestId: 'request-B',
      timeStamp: 1_010,
    }));
    releaseKey.resolve();

    await reconciliation;
    const admissionId = await admissionPromise;
    expect(admissionId).toBeDefined();
    if (!admissionId) throw new Error('Expected a before-request admission');
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBe('unconfirmed');
    expect(f.confirmed).not.toHaveBeenCalled();

    await coordinator.resolveBeforeRequest(admissionId, before({
      requestId: 'request-B',
      url: 'https://api.example.com/metric',
      timeStamp: 1_010,
    }));
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
  });

  it('fails closed when an admitted browser event cannot be resolved', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    const admissionId = await beginAdmission(coordinator);

    await coordinator.failBeforeRequest(admissionId);

    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    await coordinator.resolveBeforeRequest(admissionId, before());
    f.setNow(1_010);
    await coordinator.reconcile();
    expect(f.confirmed).not.toHaveBeenCalled();
  });

  it('fails closed when a resolved browser event does not own its admission request id', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    const admissionId = await beginAdmission(coordinator, { requestId: 'request-A' });

    await coordinator.resolveBeforeRequest(admissionId, before({ requestId: 'request-B' }));

    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(f.confirmed).not.toHaveBeenCalled();
  });

  it('fails closed when more than one same-site mutation could own a formless capture', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    await coordinator.observeBeforeRequest(before({ requestId: 'request-A' }));
    await coordinator.observeBeforeRequest(before({
      requestId: 'request-B',
      url: 'https://api.example.com/metric',
      timeStamp: 1_002,
    }));

    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(f.confirmed).not.toHaveBeenCalled();
  });

  it('lets later failure evidence override an earlier provisional success before confirmation', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    await coordinator.observeBeforeRequest(before());
    await coordinator.observeCompleted(completed({ statusCode: 204 }));
    await coordinator.observeCompleted(completed({ statusCode: 500, timeStamp: 1_003 }));
    f.setNow(1_010);
    await coordinator.reconcile();

    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(f.confirmed).not.toHaveBeenCalled();
  });

  it('accepts a bounded same-site redirect chain only after its final 2xx completion', async () => {
    const f = fixture();
    const coordinator = f.make();
    await stageCapture(coordinator, INPUT, {
      kind: 'native', actionUrl: 'https://accounts.example.com/session', method: 'POST',
    });
    await coordinator.observeBeforeRequest(before({ type: 'main_frame' }));
    await coordinator.observeRedirect({
      requestId: 'request-1',
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      url: 'https://accounts.example.com/session',
      redirectUrl: 'https://app.example.com/complete',
      method: 'POST',
      type: 'main_frame',
      statusCode: 302,
      timeStamp: 1_002,
    });
    await coordinator.observeRedirect({
      requestId: 'request-1',
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: 'destination-document',
      url: 'https://app.example.com/complete',
      redirectUrl: 'https://app.example.com/done',
      method: 'GET',
      type: 'main_frame',
      statusCode: 302,
      timeStamp: 1_003,
    });
    await coordinator.observeCompleted(completed({
      documentId: 'destination-document',
      url: 'https://app.example.com/done',
      method: 'GET',
      type: 'main_frame',
      statusCode: 200,
      timeStamp: 1_004,
    }));
    f.setNow(1_010);
    await coordinator.reconcile();

    expect(f.confirmed).toHaveBeenCalledOnce();
  });

  it('requires a 307 or 308 redirect continuation to preserve the tracked mutation method', async () => {
    const accepted = fixture();
    const acceptedCoordinator = accepted.make();
    await stageCapture(acceptedCoordinator, INPUT, {
      kind: 'native', actionUrl: 'https://accounts.example.com/session', method: 'POST',
    });
    await acceptedCoordinator.observeBeforeRequest(before({ type: 'main_frame' }));
    await acceptedCoordinator.observeRedirect({
      requestId: 'request-1',
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      url: 'https://accounts.example.com/session',
      redirectUrl: 'https://app.example.com/complete',
      method: 'POST',
      type: 'main_frame',
      statusCode: 307,
      timeStamp: 1_002,
    });
    await acceptedCoordinator.observeBeforeRequest(before({
      url: 'https://app.example.com/complete',
      method: 'POST',
      type: 'main_frame',
      timeStamp: 1_003,
    }));
    await acceptedCoordinator.observeCompleted(completed({
      documentId: 'destination-document',
      url: 'https://app.example.com/complete',
      method: 'POST',
      type: 'main_frame',
      timeStamp: 1_004,
    }));
    accepted.setNow(1_010);
    await acceptedCoordinator.reconcile();
    expect(accepted.confirmed).toHaveBeenCalledOnce();

    const rejected = fixture();
    const rejectedCoordinator = rejected.make();
    const metadata = await stageCapture(rejectedCoordinator, INPUT, {
      kind: 'native', actionUrl: 'https://accounts.example.com/session', method: 'POST',
    });
    await rejectedCoordinator.observeBeforeRequest(before({ type: 'main_frame' }));
    await rejectedCoordinator.observeRedirect({
      requestId: 'request-1',
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      url: 'https://accounts.example.com/session',
      redirectUrl: 'https://app.example.com/complete',
      method: 'POST',
      type: 'main_frame',
      statusCode: 308,
      timeStamp: 1_002,
    });
    await rejectedCoordinator.observeCompleted(completed({
      documentId: 'destination-document',
      url: 'https://app.example.com/complete',
      method: 'GET',
      type: 'main_frame',
      timeStamp: 1_003,
    }));
    await expect(rejected.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(rejected.confirmed).not.toHaveBeenCalled();
  });

  it('keeps request failure terminal when a contradictory late 2xx completion arrives', async () => {
    const f = fixture();
    const coordinator = f.make();
    await activateRuntime(coordinator);
    await coordinator.observeBeforeRequest(before());
    await coordinator.observeCompleted(completed({ statusCode: 500 }));
    await coordinator.observeCompleted(completed({ statusCode: 204, timeStamp: 1_003 }));

    const metadata = await coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(f.confirmed).not.toHaveBeenCalled();
  });

  it('durably blocks malformed terminal evidence instead of adopting its fence without journal state', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    await coordinator.observeBeforeRequest(before());
    await coordinator.observeCompleted(completed({ statusCode: 204 }));
    await coordinator.observeCompleted(completed({
      url: 'javascript:invalid',
      timeStamp: 1_003,
    }));

    f.setNow(1_010);
    await coordinator.reconcile();
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(f.confirmed).not.toHaveBeenCalled();
  });

  it('rejects a cross-site redirect even if the final request reports success', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator, INPUT, {
      kind: 'native', actionUrl: 'https://accounts.example.com/session', method: 'POST',
    });
    await coordinator.observeBeforeRequest(before({ type: 'main_frame' }));
    await coordinator.observeRedirect({
      requestId: 'request-1',
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      url: 'https://accounts.example.com/session',
      redirectUrl: 'https://oauth.example.net/complete',
      method: 'POST',
      type: 'main_frame',
      statusCode: 302,
      timeStamp: 1_002,
    });

    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(f.confirmed).not.toHaveBeenCalled();
  });

  it('rejects wrong browser authority and a request outside the bounded window', async () => {
    const f = fixture();
    const coordinator = f.make();
    await stageCapture(coordinator);
    for (const request of [
      before({ tabId: 8 }),
      before({ requestId: 'wrong-frame', frameId: 1, type: 'sub_frame' }),
      before({ requestId: 'wrong-document', documentId: 'document-B' }),
      before({ requestId: 'wrong-url', sourceDocumentUrl: 'https://accounts.example.com/other' }),
      before({ requestId: 'too-late', timeStamp: 1_011 }),
    ]) {
      await coordinator.observeBeforeRequest(request);
      await coordinator.observeCompleted(completed({
        requestId: request.requestId,
        tabId: request.tabId,
        frameId: request.frameId,
        documentId: request.documentId,
        url: request.url,
        timeStamp: request.timeStamp + 1,
      }));
    }
    f.setNow(1_020);
    await coordinator.reconcile();

    expect(f.confirmed).not.toHaveBeenCalled();
    await expect(claim(f.pending)).resolves.toEqual({ action: 'none' });
  });

  it('keeps a successful capture quarantined while authority or UserKey is unavailable', async () => {
    let current = false;
    let keyAvailable = false;
    const f = fixture({
      assertCurrent: () => { if (!current) throw new Error('stale'); },
      loadUserKey: async () => keyAvailable ? userKey() : undefined,
    });
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    await coordinator.observeBeforeRequest(before());
    await coordinator.observeCompleted(completed());
    f.setNow(1_010);
    await coordinator.reconcile();
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBe('unconfirmed');

    current = true;
    await coordinator.reconcile();
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBe('unconfirmed');
    keyAvailable = true;
    await coordinator.reconcile();
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBe('confirmed');
  });

  it('does not let an unrelated tab runtime starve an in-flight confirmation', async () => {
    const keyLoadEntered = deferred();
    const releaseKeyLoad = deferred();
    const f = fixture({
      loadUserKey: async () => {
        keyLoadEntered.resolve();
        await releaseKeyLoad.promise;
        return userKey();
      },
    });
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    await coordinator.observeBeforeRequest(before());
    await coordinator.observeCompleted(completed());
    f.setNow(1_010);
    const confirmation = coordinator.reconcile();
    await keyLoadEntered.promise;
    const unrelatedActivation = coordinator.activateRuntime({
      tabId: 8,
      frameId: 0,
      documentId: 'other-document',
      frameUrl: 'https://other.example.com/login',
      runtimeIncarnation: RUNTIME_B,
    });
    releaseKeyLoad.resolve();

    await confirmation;
    await unrelatedActivation;
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBe('confirmed');
  });

  it('does not let out-of-window same-frame network churn starve an in-flight confirmation', async () => {
    const keyLoadEntered = deferred();
    const releaseKeyLoad = deferred();
    const f = fixture({
      loadUserKey: async () => {
        keyLoadEntered.resolve();
        await releaseKeyLoad.promise;
        return userKey();
      },
    });
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    await coordinator.observeBeforeRequest(before());
    await coordinator.observeCompleted(completed());
    f.setNow(1_010);
    const confirmation = coordinator.reconcile();
    await keyLoadEntered.promise;
    const churn = Array.from({ length: 4 }, (_, index) => coordinator.beginBeforeRequest(admission({
      requestId: `out-of-window-${index}`,
      timeStamp: 2_000 + index,
    })));
    releaseKeyLoad.resolve();

    await confirmation;
    await Promise.all(churn);
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBe('confirmed');
  });

  it('rolls back promotion when an in-window admission enters during the storage commit', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    await coordinator.observeBeforeRequest(before());
    await coordinator.observeCompleted(completed());
    f.setNow(1_010);
    const promotionWriteEntered = deferred();
    const releasePromotionWrite = deferred();
    const set = f.store.set.bind(f.store);
    let blockPromotion = true;
    vi.spyOn(f.store, 'set').mockImplementation(async (key, value) => {
      await set(key, value);
      if (blockPromotion && key === 'test-pending-save'
          && JSON.stringify(value).includes('"confirmation":"confirmed"')) {
        blockPromotion = false;
        promotionWriteEntered.resolve();
        await releasePromotionWrite.promise;
      }
    });

    const confirmation = coordinator.reconcile();
    await promotionWriteEntered.promise;
    const lateAdmission = coordinator.beginBeforeRequest(admission({
      requestId: 'late-in-window-admission',
    }));
    const competingClaim = f.pending.claim(
      CONTEXT,
      userKey(),
      async () => ({ action: 'save' as const, suggestedName: 'Must not display' }),
      metadata.captureId,
    );
    releasePromotionWrite.resolve();

    await confirmation;
    await expect(competingClaim).resolves.toEqual({ action: 'none' });
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBe('unconfirmed');
    expect(f.confirmed).not.toHaveBeenCalled();
    const admissionId = await lateAdmission;
    expect(admissionId).toMatch(/^[0-9a-f-]{36}$/u);
  });

  it('discards a promoted capture when its fence rollback write fails', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    await coordinator.observeBeforeRequest(before());
    await coordinator.observeCompleted(completed());
    f.setNow(1_010);
    const promotionWriteEntered = deferred();
    const releasePromotionWrite = deferred();
    const set = f.store.set.bind(f.store);
    let promotionWritten = false;
    let failRollback = true;
    vi.spyOn(f.store, 'set').mockImplementation(async (key, value) => {
      const serialized = JSON.stringify(value);
      if (promotionWritten && failRollback && key === 'test-pending-save'
          && serialized.includes('"confirmation":"unconfirmed"')) {
        failRollback = false;
        throw new Error('rollback storage unavailable');
      }
      await set(key, value);
      if (!promotionWritten && key === 'test-pending-save'
          && serialized.includes('"confirmation":"confirmed"')) {
        promotionWritten = true;
        promotionWriteEntered.resolve();
        await releasePromotionWrite.promise;
      }
    });

    const confirmation = coordinator.reconcile();
    await promotionWriteEntered.promise;
    const lateAdmission = coordinator.beginBeforeRequest(admission({
      requestId: 'rollback-failure-admission',
    }));
    releasePromotionWrite.resolve();

    await confirmation;
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(f.confirmed).not.toHaveBeenCalled();
    await lateAdmission;
  });

  it('retries a non-secret confirmation notification after restart without re-promoting credentials', async () => {
    let notifyAttempts = 0;
    const f = fixture({
      onConfirmed: () => {
        notifyAttempts += 1;
        if (notifyAttempts === 1) throw new Error('content unavailable');
      },
    });
    const firstWorker = f.make();
    const metadata = await stageCapture(firstWorker);
    await firstWorker.observeBeforeRequest(before());
    await firstWorker.observeCompleted(completed());
    f.setNow(1_010);
    await firstWorker.reconcile();
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBe('confirmed');
    expect(notifyAttempts).toBe(1);

    await f.make().reconcile();
    expect(notifyAttempts).toBe(2);
    expect(f.loadUserKey).toHaveBeenCalledTimes(1);
  });

  it('treats requestId ABA and request capacity overflow as global fail-closed evidence', async () => {
    const aba = fixture();
    const abaCoordinator = aba.make();
    const abaCapture = await stageCapture(abaCoordinator);
    await abaCoordinator.observeBeforeRequest(before());
    await abaCoordinator.observeBeforeRequest(before({ url: 'https://api.example.com/different' }));
    await expect(aba.pending.captureState(abaCapture.captureId)).resolves.toBeUndefined();

    const capacity = fixture({ maxRequests: 1 });
    const capacityCoordinator = capacity.make();
    const capacityCapture = await stageCapture(capacityCoordinator);
    await capacityCoordinator.observeBeforeRequest(before({ requestId: 'first' }));
    await capacityCoordinator.observeBeforeRequest(before({ requestId: 'second' }));
    await expect(capacity.pending.captureState(capacityCapture.captureId)).resolves.toBeUndefined();
  });

  it('discards every unconfirmed capture when the browser adapter cannot retain more evidence', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);

    await coordinator.invalidateNetworkWindow(f.now());

    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(f.confirmed).not.toHaveBeenCalled();
  });

  it('discards orphaned ciphertext and corrupt journal state during startup reconciliation', async () => {
    const f = fixture();
    const orphan = await f.pending.putUnconfirmed(INPUT, CREDENTIALS, userKey());
    await f.store.set(AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY, {
      schemaVersion: 1,
      revision: 1,
      blockedUntil: 0,
      captures: [],
      requests: [],
      outcomes: [],
      extra: true,
    });

    await f.make().reconcile();

    await expect(f.pending.captureState(orphan.captureId)).resolves.toBeUndefined();
    const journal = f.store.peek(AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY) as { blockedUntil: number };
    expect(journal.blockedUntil).toBeGreaterThan(f.now());
  });

  it('expires an unconfirmed capture and its request metadata without a fallback promotion', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    await coordinator.observeBeforeRequest(before());
    f.setNow(2_000);
    await coordinator.reconcile();

    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(f.confirmed).not.toHaveBeenCalled();
    const journal = f.store.peek(AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY) as {
      captures: unknown[];
      requests: unknown[];
    };
    expect(journal.captures).toEqual([]);
    expect(journal.requests).toEqual([]);
  });

  it('durably fails an unconfirmed capture when a pending browser admission expires', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    await beginAdmission(coordinator);

    f.setNow(1_102);
    await f.make().reconcile();

    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(f.confirmed).not.toHaveBeenCalled();
  });

  it('clears one tab without exposing or removing another tab capture', async () => {
    const f = fixture();
    const coordinator = f.make();
    const secondInput = {
      ...INPUT,
      tabId: 8,
      sourceDocumentId: 'document-B',
      runtimeIncarnation: RUNTIME_B,
    };
    const first = await stageCapture(coordinator);
    const second = await stageCapture(coordinator, secondInput);

    await coordinator.clearTab(INPUT.tabId);

    await expect(f.pending.captureState(first.captureId)).resolves.toBeUndefined();
    await expect(f.pending.captureState(second.captureId)).resolves.toBe('unconfirmed');
    expect(JSON.stringify(f.store.peek(AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY)))
      .not.toContain(CREDENTIALS.password);
  });

  it('clears a username stage after an earlier queued stage settles for the same tab', async () => {
    const stageEntered = deferred();
    const releaseStage = deferred();
    const usernameStages = {
      stage: vi.fn(async () => {
        stageEntered.resolve();
        await releaseStage.promise;
      }),
      consume: vi.fn(async () => undefined),
      clearRuntime: vi.fn(async () => {}),
      clearTab: vi.fn(async () => {}),
      clear: vi.fn(async () => {}),
    };
    const f = fixture({ usernameStages });
    const coordinator = f.make();
    await activateRuntime(coordinator);

    const staged = coordinator.stageUsername(usernameStageInput());
    await stageEntered.promise;
    const cleared = coordinator.clearTab(INPUT.tabId);
    releaseStage.resolve();
    await Promise.all([staged, cleared]);

    expect(usernameStages.clearTab).toHaveBeenCalledWith(INPUT.tabId);
    expect(usernameStages.stage.mock.invocationCallOrder[0])
      .toBeLessThan(usernameStages.clearTab.mock.invocationCallOrder[0]!);
  });

  it('clears every username stage after an earlier queued stage settles', async () => {
    const stageEntered = deferred();
    const releaseStage = deferred();
    const usernameStages = {
      stage: vi.fn(async () => {
        stageEntered.resolve();
        await releaseStage.promise;
      }),
      consume: vi.fn(async () => undefined),
      clearRuntime: vi.fn(async () => {}),
      clearTab: vi.fn(async () => {}),
      clear: vi.fn(async () => {}),
    };
    const f = fixture({ usernameStages });
    const coordinator = f.make();
    await activateRuntime(coordinator);

    const staged = coordinator.stageUsername(usernameStageInput());
    await stageEntered.promise;
    const cleared = coordinator.clear();
    releaseStage.resolve();
    await Promise.all([staged, cleared]);

    expect(usernameStages.clear).toHaveBeenCalledOnce();
    expect(usernameStages.stage.mock.invocationCallOrder[0])
      .toBeLessThan(usernameStages.clear.mock.invocationCallOrder[0]!);
  });

  it('still clears runtime authority when username-stage cleanup fails', async () => {
    const usernameStages = {
      stage: vi.fn(async () => {}),
      consume: vi.fn(async () => undefined),
      clearRuntime: vi.fn(async () => {}),
      clearTab: vi.fn(async () => { throw new Error('username cleanup unavailable'); }),
      clear: vi.fn(async () => {}),
    };
    const f = fixture({ usernameStages });
    const coordinator = f.make();
    await activateRuntime(coordinator);

    await expect(coordinator.clearTab(INPUT.tabId)).rejects.toThrow('username cleanup unavailable');
    await expect(coordinator.isRuntimeCurrent(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      INPUT.runtimeIncarnation,
    )).resolves.toBe(false);
  });

  it('retires a capture that committed before a same-document BFCache activation', async () => {
    const f = fixture();
    const coordinator = f.make();
    const inputB = { ...INPUT, runtimeIncarnation: RUNTIME_B };
    await activateRuntime(coordinator);
    const metadata = await coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBe('unconfirmed');

    await expect(coordinator.activateRuntime({
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      frameUrl: INPUT.sourceUrl,
      runtimeIncarnation: RUNTIME_B,
      previousRuntimeIncarnation: RUNTIME_A,
    })).resolves.toBe(true);
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    await expect(coordinator.isRuntimeCurrent(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      RUNTIME_A,
    )).resolves.toBe(false);
    await expect(coordinator.isRuntimeCurrent(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      RUNTIME_B,
    )).resolves.toBe(true);

    const staleKey = userKey();
    await expect(coordinator.stage(
      INPUT,
      CREDENTIALS,
      staleKey,
      { kind: 'formless' },
    )).rejects.toThrow(/stale/);
    expect([...staleKey.encKey]).toEqual(new Array(32).fill(0));
    const fresh = await coordinator.stage(inputB, CREDENTIALS, userKey(), { kind: 'formless' });
    await expect(f.pending.captureState(fresh.captureId)).resolves.toBe('unconfirmed');
  });

  it('fences an in-flight stage when BFCache retirement enters before its pending write commits', async () => {
    const f = fixture();
    const coordinator = f.make();
    await activateRuntime(coordinator);
    const putEntered = deferred();
    const releasePut = deferred();
    const putUnconfirmed = f.pending.putUnconfirmed.bind(f.pending);
    vi.spyOn(f.pending, 'putUnconfirmed').mockImplementation(
      async (input, credentials, ownedUserKey, beforeCommit) => {
        putEntered.resolve();
        await releasePut.promise;
        return putUnconfirmed(input, credentials, ownedUserKey, beforeCommit);
      },
    );

    const stagedKey = userKey();
    const staged = coordinator.stage(INPUT, CREDENTIALS, stagedKey, { kind: 'formless' });
    await putEntered.promise;
    const retirement = coordinator.activateRuntime({
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      frameUrl: INPUT.sourceUrl,
      runtimeIncarnation: RUNTIME_B,
      previousRuntimeIncarnation: RUNTIME_A,
    });
    releasePut.resolve();

    await expect(staged).rejects.toThrow(/fence/);
    expect([...stagedKey.encKey]).toEqual(new Array(32).fill(0));
    await expect(retirement).resolves.toBe(true);
    await expect(f.pending.listUnconfirmed()).resolves.toEqual([]);
    await expect(coordinator.isRuntimeCurrent(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      RUNTIME_B,
    )).resolves.toBe(true);
  });

  it('does not let a matching network admission cancel the capture being persisted for that submit', async () => {
    const f = fixture();
    const coordinator = f.make();
    await activateRuntime(coordinator);
    const putEntered = deferred();
    const releasePut = deferred();
    const putUnconfirmed = f.pending.putUnconfirmed.bind(f.pending);
    vi.spyOn(f.pending, 'putUnconfirmed').mockImplementation(
      async (input, credentials, ownedUserKey, beforeCommit) => {
        putEntered.resolve();
        await releasePut.promise;
        return putUnconfirmed(input, credentials, ownedUserKey, beforeCommit);
      },
    );

    const staged = coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
    await putEntered.promise;
    const admissionPromise = coordinator.beginBeforeRequest(admission());
    releasePut.resolve();

    const metadata = await staged;
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBe('unconfirmed');
    await expect(admissionPromise).resolves.toMatch(/^[0-9a-f-]{36}$/u);
  });

  it('holds a completion-before-capture behind an admission entering before stage publication', async () => {
    const f = fixture();
    const coordinator = f.make();
    await activateRuntime(coordinator);
    await coordinator.observeBeforeRequest(before({ requestId: 'request-A' }));
    await coordinator.observeCompleted(completed({ requestId: 'request-A' }));
    const putCommitted = deferred();
    const releasePut = deferred();
    const putUnconfirmed = f.pending.putUnconfirmed.bind(f.pending);
    vi.spyOn(f.pending, 'putUnconfirmed').mockImplementation(
      async (input, credentials, ownedUserKey, beforeCommit) => {
        const metadata = await putUnconfirmed(input, credentials, ownedUserKey, beforeCommit);
        putCommitted.resolve();
        await releasePut.promise;
        return metadata;
      },
    );

    const staged = coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
    await putCommitted.promise;
    const admissionPromise = coordinator.beginBeforeRequest(admission({ requestId: 'request-B' }));
    f.setNow(1_010);
    releasePut.resolve();

    const metadata = await staged;
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBe('unconfirmed');
    expect(f.confirmed).not.toHaveBeenCalled();
    const admissionId = await admissionPromise;
    expect(admissionId).toMatch(/^[0-9a-f-]{36}$/u);
    if (!admissionId) throw new Error('Expected a before-request admission');
    await coordinator.resolveBeforeRequest(
      admissionId,
      before({ requestId: 'request-B' }),
    );
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(f.confirmed).not.toHaveBeenCalled();
  });

  it('bounds unpublished stage interests and releases their exact capacity slot', async () => {
    const f = fixture({ maxRequests: 1 });
    const coordinator = f.make();
    await activateRuntime(coordinator);
    const putEntered = deferred();
    const releasePut = deferred();
    const putUnconfirmed = f.pending.putUnconfirmed.bind(f.pending);
    let blockFirstPut = true;
    vi.spyOn(f.pending, 'putUnconfirmed').mockImplementation(
      async (input, credentials, ownedUserKey, beforeCommit) => {
        if (blockFirstPut) {
          blockFirstPut = false;
          putEntered.resolve();
          await releasePut.promise;
        }
        return putUnconfirmed(input, credentials, ownedUserKey, beforeCommit);
      },
    );

    const first = coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
    await putEntered.promise;
    const overflowKey = userKey();
    await expect(coordinator.stage(
      INPUT,
      CREDENTIALS,
      overflowKey,
      { kind: 'formless' },
    )).rejects.toThrow(/capacity/);
    expect([...overflowKey.encKey]).toEqual(new Array(32).fill(0));
    releasePut.resolve();
    await first;

    await expect(coordinator.stage(
      INPUT,
      CREDENTIALS,
      userKey(),
      { kind: 'formless' },
    )).resolves.toMatchObject({ captureId: expect.stringMatching(/^[0-9a-f-]{36}$/u) });
  });

  it('preserves a runtime that activated before its matching navigation commit', async () => {
    const f = fixture();
    const coordinator = f.make();
    await activateRuntime(coordinator);
    const childInput = {
      ...INPUT,
      frameId: 1,
      sourceDocumentId: 'stale-child-document',
      runtimeIncarnation: RUNTIME_B,
      sourceUrl: 'https://accounts.example.com/embedded-login',
    };
    await activateRuntime(coordinator, childInput);

    await coordinator.noteDocumentNavigation(INPUT.tabId, 0, INPUT.sourceDocumentId);

    await expect(coordinator.isRuntimeCurrent(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      INPUT.runtimeIncarnation,
    )).resolves.toBe(true);
    await expect(coordinator.isRuntimeCurrent(
      childInput.tabId,
      childInput.frameId,
      childInput.sourceDocumentId,
      childInput.runtimeIncarnation,
    )).resolves.toBe(false);
  });

  it('evicts stale child runtimes when the top runtime resumes without a navigation commit', async () => {
    const f = fixture();
    const coordinator = f.make();
    await activateRuntime(coordinator);
    const childInput = {
      ...INPUT,
      frameId: 1,
      sourceDocumentId: 'stale-child-document',
      runtimeIncarnation: RUNTIME_B,
      sourceUrl: 'https://accounts.example.com/embedded-login',
    };
    await activateRuntime(coordinator, childInput);

    await expect(coordinator.activateRuntime({
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      frameUrl: INPUT.sourceUrl,
      runtimeIncarnation: INPUT.runtimeIncarnation,
    })).resolves.toBe(true);

    await expect(coordinator.isRuntimeCurrent(
      childInput.tabId,
      childInput.frameId,
      childInput.sourceDocumentId,
      childInput.runtimeIncarnation,
    )).resolves.toBe(false);
  });

  it('invalidates child-frame runtimes and in-flight storage when the top document navigates', async () => {
    const f = fixture();
    const coordinator = f.make();
    await activateRuntime(coordinator);
    const childInput = {
      ...INPUT,
      frameId: 1,
      sourceDocumentId: 'child-document',
      runtimeIncarnation: RUNTIME_B,
      sourceUrl: 'https://accounts.example.com/embedded-login',
    };
    await activateRuntime(coordinator, childInput);
    const putEntered = deferred();
    const releasePut = deferred();
    const putUnconfirmed = f.pending.putUnconfirmed.bind(f.pending);
    vi.spyOn(f.pending, 'putUnconfirmed').mockImplementation(
      async (input, credentials, ownedUserKey, beforeCommit) => {
        putEntered.resolve();
        await releasePut.promise;
        return putUnconfirmed(input, credentials, ownedUserKey, beforeCommit);
      },
    );

    const staged = coordinator.stage(childInput, CREDENTIALS, userKey(), { kind: 'formless' });
    await putEntered.promise;
    const navigation = coordinator.noteDocumentNavigation(INPUT.tabId, 0, 'replacement-top-document');
    releasePut.resolve();

    await expect(staged).rejects.toThrow(/fence/);
    await navigation;
    await expect(coordinator.isRuntimeCurrent(
      childInput.tabId,
      childInput.frameId,
      childInput.sourceDocumentId,
      childInput.runtimeIncarnation,
    )).resolves.toBe(false);
  });

  it('zeros owned keys when the coordinator journal read fails before storage takes ownership', async () => {
    const f = fixture();
    const coordinator = f.make();
    await activateRuntime(coordinator);
    const get = vi.spyOn(f.store, 'get');

    const stageKey = userKey();
    get.mockRejectedValueOnce(new Error('storage unavailable'));
    await expect(coordinator.stage(
      INPUT,
      CREDENTIALS,
      stageKey,
      { kind: 'formless' },
    )).rejects.toThrow(/storage unavailable/);
    expect([...stageKey.encKey]).toEqual(new Array(32).fill(0));
    expect([...stageKey.macKey]).toEqual(new Array(32).fill(0));

    const context = {
      ...CONTEXT,
      documentId: INPUT.sourceDocumentId,
      runtimeIncarnation: RUNTIME_A,
      frameUrl: INPUT.sourceUrl,
    };
    const claimKey = userKey();
    get.mockRejectedValueOnce(new Error('storage unavailable'));
    await expect(coordinator.claimPendingSave(
      context,
      claimKey,
      async () => ({ action: 'save' as const, suggestedName: 'Example' }),
    )).rejects.toThrow(/storage unavailable/);
    expect([...claimKey.encKey]).toEqual(new Array(32).fill(0));
    expect([...claimKey.macKey]).toEqual(new Array(32).fill(0));

    const takeKey = userKey();
    get.mockRejectedValueOnce(new Error('storage unavailable'));
    await expect(coordinator.takePendingSave(
      '10000000-0000-4000-8000-000000000999',
      context,
      takeKey,
    )).rejects.toThrow(/storage unavailable/);
    expect([...takeKey.encKey]).toEqual(new Array(32).fill(0));
    expect([...takeKey.macKey]).toEqual(new Array(32).fill(0));
  });

  it('persists the BFCache tombstone before cleanup and rejects a stage queued during retirement', async () => {
    const cleanupEntered = deferred();
    const releaseCleanup = deferred();
    const clearUsernameRuntime = vi.fn(async () => {
      cleanupEntered.resolve();
      await releaseCleanup.promise;
    });
    const f = fixture({ clearUsernameRuntime });
    const coordinator = f.make();
    const inputB = { ...INPUT, runtimeIncarnation: RUNTIME_B };
    await activateRuntime(coordinator);
    const admissionId = await beginAdmission(coordinator);
    await coordinator.observeCompleted(completed());

    const retirement = coordinator.activateRuntime({
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      frameUrl: INPUT.sourceUrl,
      runtimeIncarnation: RUNTIME_B,
      previousRuntimeIncarnation: RUNTIME_A,
    });
    await cleanupEntered.promise;

    const journalDuringCleanup = f.store.peek(AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY) as {
      retiredRuntimes: Array<{ runtimeIncarnation: string }>;
    };
    expect(journalDuringCleanup.retiredRuntimes).toContainEqual(expect.objectContaining({
      runtimeIncarnation: RUNTIME_A,
    }));

    const staleKey = userKey();
    const staleStage = coordinator.stage(INPUT, CREDENTIALS, staleKey, { kind: 'formless' });
    releaseCleanup.resolve();

    await expect(retirement).resolves.toBe(true);
    await expect(staleStage).rejects.toThrow(/stale/);
    expect([...staleKey.encKey]).toEqual(new Array(32).fill(0));
    expect(clearUsernameRuntime).toHaveBeenCalledWith(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      RUNTIME_A,
    );

    const journalAfterRetirement = f.store.peek(AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY) as {
      admissions: unknown[];
      outcomes: unknown[];
    };
    expect(journalAfterRetirement.admissions).toEqual([]);
    expect(journalAfterRetirement.outcomes).toEqual([]);

    await coordinator.resolveBeforeRequest(admissionId, before());
    const fresh = await coordinator.stage(inputB, CREDENTIALS, userKey(), { kind: 'formless' });
    await coordinator.observeCompleted(completed());
    f.setNow(1_010);
    await coordinator.reconcile();
    await expect(f.pending.captureState(fresh.captureId)).resolves.toBe('unconfirmed');
    expect(f.confirmed).not.toHaveBeenCalled();
  });

  it('keeps an in-memory retirement fence when the first tombstone write fails', async () => {
    const f = fixture();
    const coordinator = f.make();
    await activateRuntime(coordinator);
    const set = vi.spyOn(f.store, 'set');
    set.mockRejectedValueOnce(new Error('storage unavailable'));

    await expect(coordinator.activateRuntime({
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      frameUrl: INPUT.sourceUrl,
      runtimeIncarnation: RUNTIME_B,
      previousRuntimeIncarnation: RUNTIME_A,
    })).rejects.toThrow(/storage unavailable/);
    await expect(coordinator.isRuntimeCurrent(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      RUNTIME_A,
    )).resolves.toBe(false);

    const staleKey = userKey();
    await expect(coordinator.stage(
      INPUT,
      CREDENTIALS,
      staleKey,
      { kind: 'formless' },
    )).rejects.toThrow(/stale/);
    expect([...staleKey.encKey]).toEqual(new Array(32).fill(0));

    await expect(coordinator.activateRuntime({
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      frameUrl: INPUT.sourceUrl,
      runtimeIncarnation: RUNTIME_B,
      previousRuntimeIncarnation: RUNTIME_A,
    })).resolves.toBe(true);
  });

  it('does not install another runtime while same-document retirement cleanup is pending', async () => {
    let cleanupAvailable = false;
    const clearUsernameRuntime = vi.fn(async () => {
      if (!cleanupAvailable) throw new Error('cleanup unavailable');
    });
    const f = fixture({ clearUsernameRuntime });
    const coordinator = f.make();
    await activateRuntime(coordinator);

    await expect(coordinator.activateRuntime({
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      frameUrl: INPUT.sourceUrl,
      runtimeIncarnation: RUNTIME_B,
      previousRuntimeIncarnation: RUNTIME_A,
    })).rejects.toThrow(/cleanup unavailable/);
    await expect(coordinator.activateRuntime({
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      frameUrl: INPUT.sourceUrl,
      runtimeIncarnation: RUNTIME_C,
    })).resolves.toBe(false);
    await expect(coordinator.activateRuntime({
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      frameUrl: INPUT.sourceUrl,
      runtimeIncarnation: RUNTIME_C,
      previousRuntimeIncarnation: RUNTIME_B,
    })).resolves.toBe(false);
    await expect(coordinator.isRuntimeCurrent(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      RUNTIME_C,
    )).resolves.toBe(false);

    cleanupAvailable = true;
    await expect(coordinator.activateRuntime({
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      frameUrl: INPUT.sourceUrl,
      runtimeIncarnation: RUNTIME_B,
      previousRuntimeIncarnation: RUNTIME_A,
    })).resolves.toBe(true);
  });

  it('keeps a retired runtime fenced until cleanup succeeds on a retry', async () => {
    let cleanupAttempts = 0;
    const clearUsernameRuntime = vi.fn(async () => {
      cleanupAttempts += 1;
      if (cleanupAttempts === 1) throw new Error('cleanup unavailable');
    });
    const f = fixture({ clearUsernameRuntime });
    const coordinator = f.make();
    const activationB = {
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      frameUrl: INPUT.sourceUrl,
      runtimeIncarnation: RUNTIME_B,
      previousRuntimeIncarnation: RUNTIME_A,
    } as const;
    await activateRuntime(coordinator);
    const metadata = await coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
    await coordinator.observeBeforeRequest(before());
    await coordinator.observeCompleted(completed());

    await expect(coordinator.activateRuntime(activationB)).rejects.toThrow('cleanup unavailable');
    await expect(coordinator.isRuntimeCurrent(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      RUNTIME_A,
    )).resolves.toBe(false);
    await expect(coordinator.isRuntimeCurrent(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      RUNTIME_B,
    )).resolves.toBe(false);

    f.setNow(1_010);
    const afterFailure = f.make();
    await afterFailure.reconcile();
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
    expect(f.confirmed).not.toHaveBeenCalled();

    f.setNow(1_101);
    const restarted = f.make();
    await restarted.reconcile();
    await expect(restarted.isRuntimeCurrent(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      RUNTIME_A,
    )).resolves.toBe(false);
    await expect(restarted.stage(
      INPUT,
      CREDENTIALS,
      userKey(),
      { kind: 'formless' },
    )).rejects.toThrow(/stale/);

    await expect(restarted.activateRuntime(activationB)).resolves.toBe(true);
    await expect(restarted.isRuntimeCurrent(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      RUNTIME_B,
    )).resolves.toBe(true);
    expect(clearUsernameRuntime).toHaveBeenCalledTimes(3);
  });

  it('rejects an ABA activation that tries to revive a retired runtime incarnation', async () => {
    const f = fixture();
    const coordinator = f.make();
    await activateRuntime(coordinator);
    await activateRuntime(
      coordinator,
      { ...INPUT, runtimeIncarnation: RUNTIME_B },
      RUNTIME_A,
    );

    await expect(coordinator.activateRuntime({
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      frameUrl: INPUT.sourceUrl,
      runtimeIncarnation: RUNTIME_A,
      previousRuntimeIncarnation: RUNTIME_B,
    })).resolves.toBe(false);

    await expect(coordinator.isRuntimeCurrent(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      RUNTIME_A,
    )).resolves.toBe(false);
    await expect(coordinator.isRuntimeCurrent(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      RUNTIME_B,
    )).resolves.toBe(true);
  });

  it('preserves a confirmed capture across BFCache retirement and binds its claim to one runtime', async () => {
    const f = fixture({ onConfirmed: () => { throw new Error('keep notification pending'); } });
    const coordinator = f.make();
    const metadata = await stageCapture(coordinator);
    await coordinator.observeBeforeRequest(before());
    await coordinator.observeCompleted(completed());
    f.setNow(1_010);
    await coordinator.reconcile();
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBe('confirmed');

    await activateRuntime(
      coordinator,
      { ...INPUT, runtimeIncarnation: RUNTIME_B },
      RUNTIME_A,
    );
    await expect(coordinator.isRuntimeCurrent(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      RUNTIME_B,
    )).resolves.toBe(true);
    const contextB = {
      ...CONTEXT,
      documentId: INPUT.sourceDocumentId,
      runtimeIncarnation: RUNTIME_B,
      frameUrl: INPUT.sourceUrl,
    };
    const evaluate = async () => ({
      action: 'save' as const,
      suggestedName: 'Example',
    });
    const prompt = await coordinator.claimPendingSave(
      contextB,
      userKey(),
      evaluate,
      metadata.captureId,
    );
    expect(prompt).toMatchObject({ action: 'save' });
    await expect(coordinator.claimPendingSave(
      contextB,
      userKey(),
      evaluate,
      metadata.captureId,
    )).resolves.toEqual(prompt);

    const contextC = { ...contextB, runtimeIncarnation: RUNTIME_C };
    await expect(coordinator.isRuntimeCurrent(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
      RUNTIME_C,
    )).resolves.toBe(false);
    if (prompt.action !== 'save') throw new Error('Expected a save prompt');
    const staleClaimKey = userKey();
    await expect(coordinator.claimPendingSave(
      contextC,
      staleClaimKey,
      evaluate,
      metadata.captureId,
    )).rejects.toThrow(/stale/);
    expect([...staleClaimKey.encKey]).toEqual(new Array(32).fill(0));
    expect(await coordinator.dismissPendingSave(prompt.promptId, contextC)).toBe(false);
    const staleTakeKey = userKey();
    await expect(coordinator.takePendingSave(
      prompt.promptId,
      contextC,
      staleTakeKey,
    )).resolves.toBeUndefined();
    expect([...staleTakeKey.encKey]).toEqual(new Array(32).fill(0));
    await expect(coordinator.takePendingSave(
      prompt.promptId,
      contextB,
      userKey(),
    )).resolves.toMatchObject({
      credentials: CREDENTIALS,
      sourceUrl: INPUT.sourceUrl,
    });
  });

  it('aborts an in-flight pending claim when BFCache retirement changes its runtime fence', async () => {
    const f = fixture();
    const coordinator = f.make();
    await activateRuntime(coordinator);
    const metadata = await f.pending.putUnconfirmed(INPUT, CREDENTIALS, userKey());
    await expect(f.pending.confirmUnconfirmed(metadata, userKey())).resolves.toBe(true);
    const contextA = {
      ...CONTEXT,
      documentId: INPUT.sourceDocumentId,
      runtimeIncarnation: RUNTIME_A,
      frameUrl: INPUT.sourceUrl,
    };
    const evaluationEntered = deferred();
    const releaseEvaluation = deferred();
    const claimKey = userKey();
    const pendingClaim = coordinator.claimPendingSave(
      contextA,
      claimKey,
      async () => {
        evaluationEntered.resolve();
        await releaseEvaluation.promise;
        return { action: 'save' as const, suggestedName: 'Example' };
      },
      metadata.captureId,
    );
    await evaluationEntered.promise;
    const retirement = coordinator.activateRuntime({
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      documentId: INPUT.sourceDocumentId,
      frameUrl: INPUT.sourceUrl,
      runtimeIncarnation: RUNTIME_B,
      previousRuntimeIncarnation: RUNTIME_A,
    });
    releaseEvaluation.resolve();

    await expect(pendingClaim).rejects.toThrow(/fence/);
    expect([...claimKey.encKey]).toEqual(new Array(32).fill(0));
    await expect(retirement).resolves.toBe(true);
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBe('confirmed');

    const contextB = { ...contextA, runtimeIncarnation: RUNTIME_B };
    await expect(coordinator.claimPendingSave(
      contextB,
      userKey(),
      async () => ({ action: 'save' as const, suggestedName: 'Example' }),
      metadata.captureId,
    )).resolves.toMatchObject({ action: 'save' });
  });

  it('schedules bounded reconciliation and durably blocks malformed browser evidence', async () => {
    const f = fixture();
    const coordinator = f.make();
    const invalidKey = userKey();
    await expect(coordinator.stage(INPUT, CREDENTIALS, invalidKey, {
      kind: 'native', actionUrl: 'https://accounts.example.com/session', method: 'GET',
    } as never)).rejects.toThrow(/submission|method/);
    expect([...invalidKey.encKey]).toEqual(new Array(32).fill(0));

    const metadata = await stageCapture(coordinator);
    expect(f.schedule).toHaveBeenCalledWith(1_010);
    await coordinator.observeBeforeRequest(before({ method: 'GET' }));
    await expect(f.pending.captureState(metadata.captureId)).resolves.toBeUndefined();
  });

  it('persists a minimal blocked envelope before rejecting an oversized journal', async () => {
    const f = fixture({ maxJournalBytes: 2_048 });
    const coordinator = f.make();
    const oversizedInput = {
      ...INPUT,
      sourceDocumentId: 'd'.repeat(1_200),
    };
    await activateRuntime(coordinator, oversizedInput);
    const authority = await runtimeAuthority(coordinator, oversizedInput);
    const blockedWriteEntered = deferred();
    const releaseBlockedWrite = deferred();
    const write = f.store.set.bind(f.store);
    vi.spyOn(f.store, 'set').mockImplementation(async (key: string, value: unknown): Promise<void> => {
      if (key === AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY
          && (value as { runtimeFenceUntil?: number }).runtimeFenceUntil! > f.now()) {
        blockedWriteEntered.resolve();
        await releaseBlockedWrite.promise;
      }
      await write(key, value);
    });

    const staging = coordinator.stage(
      oversizedInput,
      CREDENTIALS,
      userKey(),
      { kind: 'formless' },
    );
    await blockedWriteEntered.promise;
    expect(() => authority.assertCurrent()).toThrow('Save-capture runtime authority changed');
    const rejected = expect(staging).rejects.toThrow(/capacity/);
    releaseBlockedWrite.resolve();
    await rejected;

    const journal = f.store.peek(AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY) as {
      schemaVersion: number;
      blockedUntil: number;
      runtimeFenceUntil: number;
      captures: unknown[];
      requests: unknown[];
      outcomes: unknown[];
      activeRuntimes: unknown[];
      retiredRuntimes: unknown[];
      admissions: unknown[];
    };
    expect(journal).toMatchObject({
      schemaVersion: AUTOFILL_SAVE_CAPTURE_NETWORK_SCHEMA_VERSION,
      captures: [],
      requests: [],
      outcomes: [],
      activeRuntimes: [],
      retiredRuntimes: [],
      admissions: [],
    });
    expect(journal.blockedUntil).toBeGreaterThan(f.now());
    expect(journal.runtimeFenceUntil).toBeGreaterThan(f.now());
    await expect(coordinator.activateRuntime({
      tabId: oversizedInput.tabId,
      frameId: oversizedInput.frameId,
      documentId: oversizedInput.sourceDocumentId,
      frameUrl: oversizedInput.sourceUrl,
      runtimeIncarnation: RUNTIME_C,
    })).resolves.toBe(false);
    await expect(f.pending.listUnconfirmed()).resolves.toEqual([]);
  });
});
