import { describe, expect, it, vi } from 'vitest';
import type { SymmetricKey } from '../core/crypto/keys.js';
import type { KeyValueStore } from '../platform/store.js';
import {
  AutofillPendingSaveStore,
  type AutofillPendingSaveDocumentContext,
  type AutofillPendingSaveInput,
} from './autofill-pending-save-store.js';
import {
  AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY,
  AutofillSaveCaptureCoordinator,
  type AutofillSaveCaptureBeforeRequest,
  type AutofillSaveCaptureCompletedRequest,
  type AutofillSaveCaptureCoordinatorOptions,
  type AutofillSaveCaptureErrorRequest,
} from './autofill-save-capture-coordinator.js';

interface InspectableStore extends Pick<KeyValueStore, 'get' | 'set'> {
  peek(key: string): unknown;
}

const INPUT: AutofillPendingSaveInput = Object.freeze({
  tabId: 7,
  frameId: 0,
  sourceDocumentId: 'document-A',
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

function fixture(options: {
  now?: number;
  maxRequests?: number;
  onConfirmed?: AutofillSaveCaptureCoordinatorOptions['onConfirmed'];
  assertCurrent?: AutofillSaveCaptureCoordinatorOptions['assertCurrent'];
  loadUserKey?: AutofillSaveCaptureCoordinatorOptions['loadUserKey'];
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

async function claim(pending: AutofillPendingSaveStore) {
  return pending.claim(CONTEXT, userKey(), async () => ({
    action: 'save' as const,
    suggestedName: 'Example',
  }));
}

describe('AutofillSaveCaptureCoordinator', () => {
  it('publishes only after one exact native request succeeds and its correlation window closes', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await coordinator.stage(INPUT, CREDENTIALS, userKey(), {
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
    await coordinator.stage({ ...INPUT, sourceUrl }, CREDENTIALS, userKey(), {
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
    await firstWorker.observeCompleted(completed({ timeStamp: 999 }));
    await firstWorker.observeBeforeRequest(before({ timeStamp: 998 }));
    await firstWorker.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });

    f.setNow(1_010);
    const restartedWorker = f.make();
    await restartedWorker.reconcile();

    expect(f.confirmed).toHaveBeenCalledOnce();
    await expect(claim(f.pending)).resolves.toMatchObject({ action: 'save' });
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
    const metadata = await coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
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
    await coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
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
    await coordinator.stage(INPUT, CREDENTIALS, userKey(), {
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

  it('fails closed when more than one same-site mutation could own a formless capture', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
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
    const metadata = await coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
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
    await coordinator.stage(INPUT, CREDENTIALS, userKey(), {
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
    await coordinator.observeCompleted(completed({
      documentId: 'destination-document',
      url: 'https://app.example.com/complete',
      method: 'GET',
      type: 'main_frame',
      statusCode: 200,
      timeStamp: 1_003,
    }));
    f.setNow(1_010);
    await coordinator.reconcile();

    expect(f.confirmed).toHaveBeenCalledOnce();
  });

  it('rejects a cross-site redirect even if the final request reports success', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await coordinator.stage(INPUT, CREDENTIALS, userKey(), {
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
    await coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
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
    const metadata = await coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
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

  it('retries a non-secret confirmation notification after restart without re-promoting credentials', async () => {
    let notifyAttempts = 0;
    const f = fixture({
      onConfirmed: () => {
        notifyAttempts += 1;
        if (notifyAttempts === 1) throw new Error('content unavailable');
      },
    });
    const firstWorker = f.make();
    const metadata = await firstWorker.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
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
    const abaCapture = await abaCoordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
    await abaCoordinator.observeBeforeRequest(before());
    await abaCoordinator.observeBeforeRequest(before({ url: 'https://api.example.com/different' }));
    await expect(aba.pending.captureState(abaCapture.captureId)).resolves.toBeUndefined();

    const capacity = fixture({ maxRequests: 1 });
    const capacityCoordinator = capacity.make();
    const capacityCapture = await capacityCoordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
    await capacityCoordinator.observeBeforeRequest(before({ requestId: 'first' }));
    await capacityCoordinator.observeBeforeRequest(before({ requestId: 'second' }));
    await expect(capacity.pending.captureState(capacityCapture.captureId)).resolves.toBeUndefined();
  });

  it('discards every unconfirmed capture when the browser adapter cannot retain more evidence', async () => {
    const f = fixture();
    const coordinator = f.make();
    const metadata = await coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });

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
    const metadata = await coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
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

  it('clears one tab without exposing or removing another tab capture', async () => {
    const f = fixture();
    const coordinator = f.make();
    const first = await coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
    const second = await coordinator.stage({
      ...INPUT,
      tabId: 8,
      sourceDocumentId: 'document-B',
    }, CREDENTIALS, userKey(), { kind: 'formless' });

    await coordinator.clearTab(INPUT.tabId);

    await expect(f.pending.captureState(first.captureId)).resolves.toBeUndefined();
    await expect(f.pending.captureState(second.captureId)).resolves.toBe('unconfirmed');
    expect(JSON.stringify(f.store.peek(AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY)))
      .not.toContain(CREDENTIALS.password);
  });

  it('drops only an unconfirmed BFCache document capture and preserves a confirmed prompt', async () => {
    const unconfirmed = fixture();
    const first = await unconfirmed.make().stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
    await unconfirmed.make().discardUnconfirmedDocument(
      INPUT.tabId,
      INPUT.frameId,
      INPUT.sourceDocumentId,
    );
    await expect(unconfirmed.pending.captureState(first.captureId)).resolves.toBeUndefined();

    const confirmed = fixture({ onConfirmed: () => { throw new Error('keep notification pending'); } });
    const coordinator = confirmed.make();
    const second = await coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
    await confirmed.pending.confirmUnconfirmed(second, userKey());
    await coordinator.discardUnconfirmedDocument(INPUT.tabId, INPUT.frameId, INPUT.sourceDocumentId);
    await expect(confirmed.pending.captureState(second.captureId)).resolves.toBe('confirmed');
  });

  it('schedules bounded reconciliation and rejects malformed methods before storing secrets', async () => {
    const f = fixture();
    const coordinator = f.make();
    const invalidKey = userKey();
    await expect(coordinator.stage(INPUT, CREDENTIALS, invalidKey, {
      kind: 'native', actionUrl: 'https://accounts.example.com/session', method: 'GET',
    } as never)).rejects.toThrow(/submission|method/);
    expect([...invalidKey.encKey]).toEqual(new Array(32).fill(0));

    await coordinator.stage(INPUT, CREDENTIALS, userKey(), { kind: 'formless' });
    expect(f.schedule).toHaveBeenCalledWith(1_010);
    await expect(coordinator.observeBeforeRequest(before({ method: 'GET' }))).rejects.toThrow(/method/);
  });

  it('persists a minimal blocked envelope before rejecting an oversized journal', async () => {
    const f = fixture({ maxJournalBytes: 256 });
    const coordinator = f.make();

    await expect(coordinator.stage({
      ...INPUT,
      sourceDocumentId: 'd'.repeat(400),
    }, CREDENTIALS, userKey(), { kind: 'formless' })).rejects.toThrow(/capacity/);

    const journal = f.store.peek(AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY) as {
      schemaVersion: number;
      blockedUntil: number;
      captures: unknown[];
      requests: unknown[];
      outcomes: unknown[];
    };
    expect(journal).toMatchObject({
      schemaVersion: 1,
      captures: [],
      requests: [],
      outcomes: [],
    });
    expect(journal.blockedUntil).toBeGreaterThan(f.now());
    await expect(f.pending.listUnconfirmed()).resolves.toEqual([]);
  });
});
