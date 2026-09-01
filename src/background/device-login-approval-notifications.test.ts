import { describe, expect, it, vi } from 'vitest';

import type { AccountLease } from '../core/session/account-gate.js';
import type { KeyValueStore } from '../platform/store.js';
import {
  DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM,
  DEVICE_LOGIN_APPROVAL_NOTIFICATION_PREFIX,
  DEVICE_LOGIN_APPROVAL_NOTIFICATION_STATE_KEY,
  DeviceLoginApprovalNotificationController,
  type DeviceLoginApprovalNotificationBrowser,
  type DeviceLoginApprovalNotificationContext,
} from './device-login-approval-notifications.js';

const NOW = Date.parse('2026-08-31T08:00:00.000Z');
const EXPIRES_AT = NOW + 10 * 60_000;
const REQUEST_A = 'f4b47b53-a174-4a40-bbd6-08b2bb6f9d34';
const REQUEST_B = 'c05e732e-77b1-457b-8f89-5b5ba1b4e1d2';
const POPUP_URL = 'chrome-extension://extension-id/ui/popup/popup.html';
const APPROVAL_POPUP_URL = `${POPUP_URL}?deviceLoginApprovals=1`;
const ICON_URL = 'chrome-extension://extension-id/icons/icon128.png';
const COPY = Object.freeze({
  title: 'Device login request',
  message: 'A device is waiting for approval. Open MiYu to review it before deciding.',
});

function accountLease(
  accountIdentity = 'alice@example.test',
  serverUrl = 'https://vault.example/tenant/',
  generation = 1,
): AccountLease {
  return Object.freeze({
    serverGeneration: generation,
    accountGeneration: generation,
    serverUrl,
    accountIdentity,
  });
}

function pending(requestId = REQUEST_A, expiresAt = EXPIRES_AT): unknown {
  return Object.freeze({
    view: Object.freeze({
      id: requestId,
      expiresAt,
      requestIpAddress: '203.0.113.9',
    }),
    decisionBinding: Object.freeze({
      requestId,
      proof: 'secret-decision-proof',
    }),
  });
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((accept) => { resolve = accept; });
  return { promise, resolve };
}

interface Harness {
  readonly controller: DeviceLoginApprovalNotificationController;
  readonly listPending: ReturnType<typeof vi.fn>;
  readonly createNotification: ReturnType<typeof vi.fn>;
  readonly clearNotification: ReturnType<typeof vi.fn>;
  readonly getAll: ReturnType<typeof vi.fn>;
  readonly getContexts: ReturnType<typeof vi.fn>;
  readonly createWindow: ReturnType<typeof vi.fn>;
  readonly updateWindow: ReturnType<typeof vi.fn>;
  readonly createAlarm: ReturnType<typeof vi.fn>;
  readonly clearAlarm: ReturnType<typeof vi.fn>;
  readonly logger: { warn: ReturnType<typeof vi.fn> };
  readonly store: Pick<KeyValueStore, 'get' | 'set' | 'remove'>;
  readonly visible: Map<string, unknown>;
  readonly contexts: DeviceLoginApprovalNotificationContext[];
  readonly alarms: Map<string, { when: number }>;
  readonly stored: Map<string, unknown>;
  setPending(value: readonly unknown[]): void;
  setNow(value: number): void;
  setLease(value: AccountLease): void;
  recreate(): DeviceLoginApprovalNotificationController;
}

function makeHarness(
  initialPending: readonly unknown[] = [pending()],
  options: {
    readonly onPopupPending?: (candidates: readonly unknown[]) => void | PromiseLike<void>;
  } = {},
): Harness {
  let now = NOW;
  let currentLease = accountLease();
  let pendingApprovals = initialPending;
  const visible = new Map<string, unknown>();
  const contexts: DeviceLoginApprovalNotificationContext[] = [];
  const alarms = new Map<string, { when: number }>();
  const stored = new Map<string, unknown>();
  const store: Pick<KeyValueStore, 'get' | 'set' | 'remove'> = {
    async get<T>(key: string): Promise<T | undefined> {
      return stored.get(key) as T | undefined;
    },
    async set(key: string, value: unknown): Promise<void> {
      stored.set(key, value);
    },
    async remove(key: string): Promise<void> {
      stored.delete(key);
    },
  };
  const listPending = vi.fn(async () => pendingApprovals);
  const createNotification = vi.fn(async (notificationId: string, options: unknown) => {
    visible.set(notificationId, options);
    return notificationId;
  });
  const clearNotification = vi.fn(async (notificationId: string) => visible.delete(notificationId));
  const getAll = vi.fn(async () => Object.fromEntries(visible));
  const getContexts = vi.fn(async () => contexts);
  const createWindow = vi.fn(async () => undefined);
  const updateWindow = vi.fn(async () => undefined);
  const createAlarm = vi.fn(async (name: string, options: { when: number }) => {
    alarms.set(name, options);
  });
  const clearAlarm = vi.fn(async (name: string) => alarms.delete(name));
  const logger = { warn: vi.fn() };
  const browser: DeviceLoginApprovalNotificationBrowser = {
    notifications: {
      create: createNotification,
      clear: clearNotification,
      getAll,
    },
    runtime: { getContexts },
    windows: { create: createWindow, update: updateWindow },
  };
  const deps = {
    listPending,
    captureAccountLease: () => currentLease,
    assertAccountLease: (lease: AccountLease) => {
      if (lease !== currentLease) throw new Error('stale account');
    },
    browser,
    alarms: { create: createAlarm, clear: clearAlarm },
    store,
    popupUrl: POPUP_URL,
    iconUrl: ICON_URL,
    getCopy: () => COPY,
    ...(options.onPopupPending ? { onPopupPending: options.onPopupPending } : {}),
    now: () => now,
    logger,
  };
  const recreate = () => new DeviceLoginApprovalNotificationController(deps);
  return {
    controller: recreate(),
    listPending,
    createNotification,
    clearNotification,
    getAll,
    getContexts,
    createWindow,
    updateWindow,
    createAlarm,
    clearAlarm,
    logger,
    store,
    visible,
    contexts,
    alarms,
    stored,
    setPending(value) { pendingApprovals = value; },
    setNow(value) { now = value; },
    setLease(value) { currentLease = value; },
    recreate,
  };
}

function seenEntries(harness: Harness): Array<{ notificationId: string; expiresAt: number }> {
  const state = harness.stored.get(DEVICE_LOGIN_APPROVAL_NOTIFICATION_STATE_KEY) as {
    schemaVersion?: unknown;
    entries?: Array<{ notificationId: string; expiresAt: number }>;
  } | undefined;
  return state?.entries ?? [];
}

function createdNotificationId(harness: Harness): string {
  const id = harness.createNotification.mock.calls[0]?.[0];
  if (typeof id !== 'string') throw new Error('notification was not created');
  return id;
}

describe('DeviceLoginApprovalNotificationController reconciliation', () => {
  it('accepts the locked-safe minimal discovery projection', async () => {
    const harness = makeHarness();
    harness.setPending([{ requestId: REQUEST_A, expiresAt: EXPIRES_AT }]);

    await harness.controller.refresh();

    expect(harness.createNotification).toHaveBeenCalledOnce();
    expect(seenEntries(harness)).toHaveLength(1);
  });

  it('creates one generic opaque notification from an authoritative pending list', async () => {
    const harness = makeHarness([pending(), pending()]);

    await harness.controller.refresh();

    expect(harness.listPending).toHaveBeenCalledOnce();
    expect(harness.createNotification).toHaveBeenCalledOnce();
    const [notificationId, options] = harness.createNotification.mock.calls[0]!;
    expect(notificationId).toMatch(new RegExp(`^${DEVICE_LOGIN_APPROVAL_NOTIFICATION_PREFIX}[A-Za-z0-9_-]{43}$`));
    expect(notificationId).not.toContain(REQUEST_A);
    expect(notificationId).not.toContain('alice@example.test');
    expect(options).toEqual({
      type: 'basic',
      iconUrl: ICON_URL,
      title: COPY.title,
      message: COPY.message,
      isClickable: true,
    });
    const serialized = JSON.stringify({ notificationId, options });
    expect(serialized).not.toContain(REQUEST_A);
    expect(serialized).not.toContain('203.0.113.9');
    expect(serialized).not.toContain('secret-decision-proof');
    const persisted = JSON.stringify(
      await harness.store.get<unknown>(DEVICE_LOGIN_APPROVAL_NOTIFICATION_STATE_KEY),
    );
    expect(persisted).not.toContain(REQUEST_A);
    expect(persisted).not.toContain('alice@example.test');
    expect(persisted).not.toContain('203.0.113.9');
    expect(persisted).not.toContain('secret-decision-proof');
    expect(harness.createAlarm).toHaveBeenCalledWith(
      DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM,
      { when: EXPIRES_AT },
    );
  });

  it('deduplicates the stable id across refreshes and a recreated MV3 worker controller', async () => {
    const harness = makeHarness();
    await harness.controller.refresh();
    const firstId = createdNotificationId(harness);

    await harness.controller.refresh();
    harness.visible.clear();
    await harness.recreate().refresh();

    expect(harness.createNotification).toHaveBeenCalledOnce();
    expect(firstId).toMatch(new RegExp(`^${DEVICE_LOGIN_APPROVAL_NOTIFICATION_PREFIX}`));
    expect(harness.visible.size).toBe(0);
  });

  it('persists seen only after an exact notification create settles', async () => {
    const harness = makeHarness();
    const created = deferred<string>();
    let requestedId = '';
    harness.createNotification.mockImplementationOnce((notificationId: string) => {
      requestedId = notificationId;
      return created.promise;
    });

    const refreshing = harness.controller.refresh();
    await vi.waitFor(() => expect(harness.createNotification).toHaveBeenCalledOnce());
    expect(seenEntries(harness)).toEqual([]);

    created.resolve(requestedId);
    await refreshing;
    expect(seenEntries(harness)).toEqual([{
      notificationId: requestedId,
      expiresAt: EXPIRES_AT,
    }]);
  });

  it.each(['rejects', 'returns a different id'] as const)(
    'retries when notification create %s',
    async (failure) => {
      const harness = makeHarness();
      if (failure === 'rejects') {
        harness.createNotification.mockRejectedValueOnce(new Error(`private ${REQUEST_A}`));
      } else {
        harness.createNotification.mockResolvedValueOnce('different-notification-id');
      }

      await harness.controller.refresh();
      expect(seenEntries(harness)).toEqual([]);
      expect(harness.createAlarm).toHaveBeenLastCalledWith(
        DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM,
        { when: NOW + 5_000 },
      );

      await harness.controller.refresh();
      expect(harness.createNotification).toHaveBeenCalledTimes(2);
      expect(seenEntries(harness)).toHaveLength(1);
      expect(harness.logger.warn).toHaveBeenCalledWith('notification_failed');
      expect(JSON.stringify(harness.logger.warn.mock.calls)).not.toContain(REQUEST_A);
    },
  );

  it('includes account and request identity in the opaque dedup key', async () => {
    const harness = makeHarness();
    await harness.controller.refresh();
    const firstId = createdNotificationId(harness);

    await harness.controller.clear();
    harness.setLease(accountLease('bob@example.test'));
    harness.setPending([pending(REQUEST_B)]);
    await harness.controller.refresh();

    const secondId = harness.createNotification.mock.calls[1]?.[0];
    expect(secondId).not.toBe(firstId);
    expect(String(secondId)).not.toContain('bob@example.test');
    expect(String(secondId)).not.toContain(REQUEST_B);
  });

  it('suppresses and clears notifications while an exact popup context is open', async () => {
    const harness = makeHarness();
    await harness.controller.refresh();
    const id = createdNotificationId(harness);
    harness.contexts.push({
      contextType: 'POPUP',
      documentUrl: POPUP_URL,
      windowId: 7,
    });

    await harness.controller.refresh();

    expect(harness.createNotification).toHaveBeenCalledOnce();
    expect(harness.clearNotification).toHaveBeenCalledWith(id);
    expect(harness.visible.size).toBe(0);
    expect(harness.createAlarm).toHaveBeenLastCalledWith(
      DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM,
      { when: EXPIRES_AT },
    );

    harness.contexts.length = 0;
    await harness.controller.refresh();
    expect(harness.createNotification).toHaveBeenCalledOnce();
  });

  it('keeps an unseen popup-open candidate retryable until the popup closes', async () => {
    const harness = makeHarness();
    harness.contexts.push({ contextType: 'POPUP', documentUrl: POPUP_URL, windowId: 7 });

    await harness.controller.refresh();

    expect(harness.createNotification).not.toHaveBeenCalled();
    expect(seenEntries(harness)).toEqual([]);
    expect(harness.createAlarm).toHaveBeenLastCalledWith(
      DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM,
      { when: NOW + 5_000 },
    );

    harness.contexts.length = 0;
    await harness.controller.handleAlarm(DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM);
    expect(harness.createNotification).toHaveBeenCalledOnce();
    expect(seenEntries(harness)).toHaveLength(1);
  });

  it('notifies an open popup without treating the callback as a system delivery', async () => {
    const popupPending = vi.fn(async (_candidates: readonly unknown[]) => undefined);
    const harness = makeHarness([pending()], { onPopupPending: popupPending });

    await harness.controller.popupOpened();

    expect(popupPending).toHaveBeenCalledOnce();
    expect(popupPending.mock.calls[0]?.[0]).toEqual([
      expect.objectContaining({ expiresAt: EXPIRES_AT }),
    ]);
    expect(harness.createNotification).not.toHaveBeenCalled();
    expect(seenEntries(harness)).toEqual([]);
    expect(harness.createAlarm).toHaveBeenLastCalledWith(
      DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM,
      { when: NOW + 5_000 },
    );
  });

  it('preserves confirmed delivery and retries after context discovery recovers', async () => {
    const harness = makeHarness();
    await harness.controller.refresh();
    const notificationId = createdNotificationId(harness);
    harness.getContexts.mockRejectedValueOnce(new Error(`private ${REQUEST_A}`));

    await expect(harness.controller.refresh()).resolves.toBeUndefined();

    expect(harness.createNotification).toHaveBeenCalledOnce();
    expect(harness.clearNotification).not.toHaveBeenCalledWith(notificationId);
    expect(harness.visible.has(notificationId)).toBe(true);
    expect(seenEntries(harness)).toEqual([{ notificationId, expiresAt: EXPIRES_AT }]);
    expect(harness.createAlarm).toHaveBeenLastCalledWith(
      DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM,
      { when: NOW + 5_000 },
    );
    expect(harness.logger.warn).toHaveBeenCalledWith('popup_query_failed');
    expect(harness.logger.warn).toHaveBeenCalledWith('refresh_failed');
    expect(JSON.stringify(harness.logger.warn.mock.calls)).not.toContain(REQUEST_A);

    await harness.controller.refresh();
    expect(harness.createNotification).toHaveBeenCalledOnce();
    expect(harness.visible.size).toBe(1);
  });

  it('clears settled and expired notifications through authoritative reconciliation', async () => {
    const harness = makeHarness();
    await harness.controller.refresh();
    const id = createdNotificationId(harness);

    harness.setPending([]);
    await harness.controller.refresh();
    expect(harness.clearNotification).toHaveBeenCalledWith(id);
    expect(harness.visible.size).toBe(0);

    harness.setPending([pending(REQUEST_B)]);
    await harness.controller.refresh();
    const expiringId = harness.createNotification.mock.calls[1]?.[0] as string;
    harness.setNow(EXPIRES_AT);
    await harness.controller.handleAlarm(DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM);
    expect(harness.clearNotification).toHaveBeenCalledWith(expiringId);
    expect(harness.visible.size).toBe(0);
  });

  it('invalidates a delayed refresh before explicit session cleanup can be undone', async () => {
    const listing = deferred<readonly unknown[]>();
    const harness = makeHarness();
    harness.listPending.mockImplementationOnce(() => listing.promise);

    const refresh = harness.controller.refresh();
    const clear = harness.controller.clear();
    listing.resolve([pending()]);
    await Promise.all([refresh, clear]);

    expect(harness.createNotification).not.toHaveBeenCalled();
    expect(harness.visible.size).toBe(0);
  });

  it('coalesces a refresh burst and makes every caller await the newest reconciliation', async () => {
    const first = deferred<readonly unknown[]>();
    const second = deferred<readonly unknown[]>();
    const harness = makeHarness();
    harness.listPending
      .mockImplementationOnce(() => first.promise)
      .mockImplementationOnce(() => second.promise);

    const initial = harness.controller.refresh();
    await vi.waitFor(() => expect(harness.listPending).toHaveBeenCalledOnce());
    const middle = harness.controller.refresh();
    const newest = harness.controller.refresh();
    expect(middle).toBe(initial);
    expect(newest).toBe(initial);

    let settled = false;
    void initial.then(() => { settled = true; });
    first.resolve([pending()]);
    await vi.waitFor(() => expect(harness.listPending).toHaveBeenCalledTimes(2));
    expect(settled).toBe(false);

    second.resolve([pending(REQUEST_B)]);
    await Promise.all([initial, middle, newest]);
    expect(harness.listPending).toHaveBeenCalledTimes(2);
    expect(harness.createNotification).toHaveBeenCalledOnce();
    expect(seenEntries(harness)).toHaveLength(1);
  });

  it('runs explicit clear as an unconditional barrier across an account ABA', async () => {
    const harness = makeHarness();
    const firstCreate = deferred<string>();
    let firstId = '';
    harness.createNotification.mockImplementationOnce((notificationId: string, options: unknown) => {
      firstId = notificationId;
      harness.visible.set(notificationId, options);
      return firstCreate.promise;
    });

    const stale = harness.controller.refresh();
    await vi.waitFor(() => expect(harness.createNotification).toHaveBeenCalledOnce());
    const clearing = harness.controller.clear();
    harness.setLease(accountLease('alice@example.test', 'https://vault.example/tenant/', 3));
    const newest = harness.controller.refresh();
    firstCreate.resolve(firstId);
    await Promise.all([stale, clearing, newest]);

    expect(harness.createNotification).toHaveBeenCalledTimes(2);
    const secondId = harness.createNotification.mock.calls[1]?.[0] as string;
    expect(secondId).not.toBe(firstId);
    expect(harness.clearNotification).toHaveBeenCalledWith(firstId);
    expect([...harness.visible.keys()]).toEqual([secondId]);
    expect(seenEntries(harness)).toEqual([{
      notificationId: secondId,
      expiresAt: EXPIRES_AT,
    }]);
  });

  it('recreates the same request when its authoritative expiry changes', async () => {
    const harness = makeHarness();
    await harness.controller.refresh();
    const id = createdNotificationId(harness);
    const extendedExpiry = EXPIRES_AT + 60_000;
    harness.setPending([pending(REQUEST_A, extendedExpiry)]);

    await harness.controller.refresh();

    expect(harness.createNotification).toHaveBeenCalledTimes(2);
    expect(harness.createNotification.mock.calls[1]?.[0]).toBe(id);
    expect(seenEntries(harness)).toEqual([{ notificationId: id, expiresAt: extendedExpiry }]);
    expect(harness.createAlarm).toHaveBeenLastCalledWith(
      DEVICE_LOGIN_APPROVAL_NOTIFICATION_EXPIRY_ALARM,
      { when: extendedExpiry },
    );
  });

  it('does not commit or retain a notification whose create crosses expiry', async () => {
    const harness = makeHarness();
    const create = deferred<string>();
    let notificationId = '';
    harness.createNotification.mockImplementationOnce((id: string, options: unknown) => {
      notificationId = id;
      harness.visible.set(id, options);
      return create.promise;
    });

    const refreshing = harness.controller.refresh();
    await vi.waitFor(() => expect(harness.createNotification).toHaveBeenCalledOnce());
    harness.setNow(EXPIRES_AT);
    create.resolve(notificationId);
    await refreshing;

    expect(seenEntries(harness)).toEqual([]);
    expect(harness.clearNotification).toHaveBeenCalledWith(notificationId);
    expect(harness.visible.size).toBe(0);
  });

  it('ignores malformed accessor candidates without invoking caller code', async () => {
    const harness = makeHarness();
    let getterCalls = 0;
    const malformed = {} as Record<string, unknown>;
    Object.defineProperty(malformed, 'view', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return { id: REQUEST_B, expiresAt: EXPIRES_AT };
      },
    });
    harness.setPending([malformed, pending()]);

    await harness.controller.refresh();

    expect(getterCalls).toBe(0);
    expect(harness.createNotification).toHaveBeenCalledOnce();
  });
});

describe('DeviceLoginApprovalNotificationController click boundary', () => {
  it('freshly reauthorizes a real notification before opening only the fixed approval list', async () => {
    const harness = makeHarness();
    await harness.controller.refresh();
    const notificationId = createdNotificationId(harness);

    await harness.controller.handleClick(notificationId);

    expect(harness.listPending).toHaveBeenCalledTimes(2);
    expect(harness.clearNotification).toHaveBeenCalledWith(notificationId);
    expect(harness.createWindow).toHaveBeenCalledWith({
      url: APPROVAL_POPUP_URL,
      type: 'popup',
      focused: true,
      width: 420,
      height: 680,
    });
    const opened = JSON.stringify(harness.createWindow.mock.calls);
    expect(opened).not.toContain(REQUEST_A);
    expect(opened).not.toContain('203.0.113.9');
  });

  it('does not trust arbitrary or stale managed-looking notification ids', async () => {
    const harness = makeHarness();
    await harness.controller.refresh();
    const listCalls = harness.listPending.mock.calls.length;

    await harness.controller.handleClick('unrelated-notification');
    expect(harness.listPending).toHaveBeenCalledTimes(listCalls);

    await harness.controller.handleClick(
      `${DEVICE_LOGIN_APPROVAL_NOTIFICATION_PREFIX}${'A'.repeat(43)}`,
    );
    expect(harness.listPending).toHaveBeenCalledTimes(listCalls + 1);
    expect(harness.createWindow).not.toHaveBeenCalled();

    const realId = createdNotificationId(harness);
    harness.setPending([]);
    await harness.controller.handleClick(realId);
    expect(harness.createWindow).not.toHaveBeenCalled();
  });

  it('does not open an approval after the freshly-read candidate expires', async () => {
    const harness = makeHarness();
    await harness.controller.refresh();
    const notificationId = createdNotificationId(harness);
    harness.setNow(EXPIRES_AT);

    await harness.controller.handleClick(notificationId);

    expect(harness.listPending).toHaveBeenCalledTimes(2);
    expect(harness.createWindow).not.toHaveBeenCalled();
  });

  it('does not open or consume an approval when context discovery crosses expiry', async () => {
    const harness = makeHarness();
    await harness.controller.refresh();
    const notificationId = createdNotificationId(harness);
    const contextLookup = deferred<readonly DeviceLoginApprovalNotificationContext[]>();
    harness.getContexts.mockImplementationOnce(() => contextLookup.promise);

    const clicking = harness.controller.handleClick(notificationId);
    await vi.waitFor(() => expect(harness.getContexts).toHaveBeenCalledTimes(2));
    harness.setNow(EXPIRES_AT);
    contextLookup.resolve([]);
    await clicking;

    expect(harness.createWindow).not.toHaveBeenCalled();
    expect(harness.updateWindow).not.toHaveBeenCalled();
    expect(harness.clearNotification).not.toHaveBeenCalled();
    expect(harness.visible.has(notificationId)).toBe(true);
    expect(harness.logger.warn).toHaveBeenCalledWith('click_failed');
  });

  it('does not let a delayed click authorization survive explicit clear', async () => {
    const harness = makeHarness();
    await harness.controller.refresh();
    const notificationId = createdNotificationId(harness);
    const fresh = deferred<readonly unknown[]>();
    harness.listPending.mockImplementationOnce(() => fresh.promise);

    const clicking = harness.controller.handleClick(notificationId);
    await vi.waitFor(() => expect(harness.listPending).toHaveBeenCalledTimes(2));
    const clearing = harness.controller.clear();
    fresh.resolve([pending()]);
    await Promise.all([clicking, clearing]);

    expect(harness.createWindow).not.toHaveBeenCalled();
    expect(harness.visible.size).toBe(0);
    expect(seenEntries(harness)).toEqual([]);
  });

  it('focuses only an existing exact approval-list popup context', async () => {
    const harness = makeHarness();
    await harness.controller.refresh();
    const notificationId = createdNotificationId(harness);
    harness.contexts.push(
      { contextType: 'TAB', documentUrl: `${APPROVAL_POPUP_URL}&requestId=${REQUEST_A}`, windowId: 8 },
      { contextType: 'TAB', documentUrl: APPROVAL_POPUP_URL, windowId: 9 },
    );

    await harness.controller.handleClick(notificationId);

    expect(harness.updateWindow).toHaveBeenCalledWith(9, { focused: true });
    expect(harness.createWindow).not.toHaveBeenCalled();
  });

  it('isolates browser failures behind fixed diagnostic codes', async () => {
    const harness = makeHarness();
    harness.createNotification.mockRejectedValueOnce(new Error(`secret ${REQUEST_A}`));

    await expect(harness.controller.refresh()).resolves.toBeUndefined();

    expect(harness.logger.warn).toHaveBeenCalledWith('notification_failed');
    expect(JSON.stringify(harness.logger.warn.mock.calls)).not.toContain(REQUEST_A);
  });
});
