import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: {}, session: {} } },
}));

import { createMemoryStore, type KeyValueStore } from '../platform/store.js';
import { ClientEventType, type ClientEventWire } from '../core/events/client-event.js';
import { CLIENT_EVENT_QUEUE_STORAGE_KEY } from './client-event-queue.js';
import {
  CLIENT_EVENT_LOGOUT_MARKER_STORAGE_KEY,
  CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY,
  CLIENT_EVENT_UPLOAD_ALARM,
  ClientEventFixedAlarmScheduler,
  ClientEventProductionError,
  ClientEventProductionTransport,
  ClientEventScopeDirectory,
  createClientEventProduction,
  type ClientEventAccountLeaseLike,
  type ClientEventCollectClient,
  type ClientEventProductionTransportDependencies,
} from './client-event-production.js';

const SERVER_A = 'https://vault-a.example/';
const SERVER_B = 'https://vault-b.example/';
const EMAIL_A = 'alice@example.com';
const EMAIL_B = 'bob@example.com';
const USER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const USER_C = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const ORG_A = '11111111-1111-4111-8111-111111111111';
const CIPHER_A = '22222222-2222-4222-8222-222222222222';
const NOW = 1_800_000_000_000;

interface TestLease extends ClientEventAccountLeaseLike {
  readonly generation: number;
}

const EVENT: ClientEventWire = Object.freeze({
  type: ClientEventType.Cipher_ClientViewed,
  date: '2026-09-01T08:09:10.123Z',
  cipherId: CIPHER_A,
  organizationId: ORG_A,
});

function deferred<Value>() {
  let resolve!: (value: Value | PromiseLike<Value>) => void;
  const promise = new Promise<Value>((done) => { resolve = done; });
  return { promise, resolve };
}

function binding(overrides: Partial<{
  serverUrl: string;
  accountIdentity: string;
  accountId: string;
}> = {}) {
  return {
    serverUrl: SERVER_A,
    accountIdentity: EMAIL_A,
    accountId: USER_A,
    ...overrides,
  };
}

function accountHarness() {
  let state = { serverUrl: SERVER_A, accountIdentity: EMAIL_A, generation: 1 };
  const captureAccountLease = vi.fn((): TestLease => Object.freeze({ ...state }));
  const assertAccountLease = vi.fn((lease: TestLease): void => {
    if (lease.generation !== state.generation
        || lease.serverUrl !== state.serverUrl
        || lease.accountIdentity !== state.accountIdentity) {
      throw new Error('account lease changed');
    }
  });
  return {
    captureAccountLease,
    assertAccountLease,
    switchAwayAndBack() {
      state = { ...state, generation: state.generation + 2 };
    },
    switchTo(serverUrl: string, accountIdentity: string) {
      state = { serverUrl, accountIdentity, generation: state.generation + 1 };
    },
  };
}

async function rawDirectory(store: KeyValueStore): Promise<unknown> {
  return store.get<unknown>(CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY);
}

function createProductionHarness(
  store: KeyValueStore = createMemoryStore(),
  overrides: {
    account?: ReturnType<typeof accountHarness>;
    collectClientEvents?: ClientEventCollectClient['collectClientEvents'];
  } = {},
) {
  const account = overrides.account ?? accountHarness();
  let id = 0;
  const runtime = createClientEventProduction({
    store,
    authority: {
      captureActive: () => ({
        serverUrl: SERVER_A,
        userId: USER_A,
        organizations: [{ id: ORG_A, useEvents: true }],
        ciphers: [{ id: CIPHER_A, organizationId: ORG_A }],
      }),
    },
    alarms: {
      get: async () => undefined,
      create: () => undefined,
      clear: async () => true,
    },
    captureAccountLease: account.captureAccountLease,
    assertAccountLease: account.assertAccountLease,
    executeAuthenticatedRequest: async <Result>(
      _lease: TestLease,
      rebuild: (accessToken: string) => Promise<Result>,
    ) => rebuild('access-a'),
    apiForServer: () => ({
      collectClientEvents: overrides.collectClientEvents
        ?? (async () => ({ ok: true as const })),
    }),
  }, {
    now: () => NOW,
    queue: {
      createId: () => `30000000-0000-4000-8000-${String(++id).padStart(12, '0')}`,
    },
  });
  return { store, account, runtime };
}

describe('ClientEventScopeDirectory', () => {
  it('canonicalizes, captures, lists, and removes exact account bindings', async () => {
    const store = createMemoryStore();
    const directory = new ClientEventScopeDirectory(store);

    const stored = await directory.upsert(binding({
      serverUrl: 'https://VAULT-A.example',
      accountIdentity: ' Alice@Example.COM ',
    }));
    const capture = await directory.capture({
      serverUrl: SERVER_A,
      accountIdentity: EMAIL_A,
    });

    expect(stored).toEqual({
      serverUrl: SERVER_A,
      accountIdentity: EMAIL_A,
      accountId: USER_A,
      scope: { serverUrl: SERVER_A, accountId: USER_A },
    });
    expect(capture?.binding).toEqual(stored);
    expect(() => directory.assertCurrent(capture!)).not.toThrow();
    await expect(directory.listExact()).resolves.toEqual([stored]);
    await expect(directory.remove({ serverUrl: SERVER_A, accountIdentity: EMAIL_A }))
      .resolves.toEqual(stored);
    await expect(directory.capture({ serverUrl: SERVER_A, accountIdentity: EMAIL_A }))
      .resolves.toBeUndefined();
    await expect(rawDirectory(store)).resolves.toBeUndefined();
  });

  it('enforces entry and byte capacity without evicting another account', async () => {
    const store = createMemoryStore();
    const directory = new ClientEventScopeDirectory(store, { maxEntries: 1 });
    await directory.upsert(binding());

    await expect(directory.upsert(binding({
      accountIdentity: 'bob@example.com',
      accountId: USER_B,
    }))).rejects.toMatchObject({ code: 'capacity' });
    await expect(directory.listExact()).resolves.toHaveLength(1);

    const small = new ClientEventScopeDirectory(createMemoryStore(), { maxStoredBytes: 64 });
    await expect(small.upsert(binding())).rejects.toMatchObject({ code: 'capacity' });
  });

  it.each([
    binding({ accountId: USER_A.toUpperCase() }),
    binding({ accountId: 'not-a-uuid' }),
    binding({ accountIdentity: 'not-an-email' }),
    binding({ serverUrl: 'http://remote.example' }),
  ])('rejects a malformed binding without writing: %j', async (invalid) => {
    const store = createMemoryStore();
    const directory = new ClientEventScopeDirectory(store);

    await expect(directory.upsert(invalid)).rejects.toBeInstanceOf(TypeError);
    await expect(rawDirectory(store)).resolves.toBeUndefined();
  });

  it('fails closed on current-schema corruption and never replaces it', async () => {
    const store = createMemoryStore();
    const corrupt = {
      schemaVersion: 1,
      entries: {
        [JSON.stringify([SERVER_A, EMAIL_A])]: {
          serverUrl: 'https://VAULT-A.example/',
          accountIdentity: EMAIL_A,
          accountId: USER_A,
        },
      },
    };
    await store.set(CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY, corrupt);
    const before = await rawDirectory(store);
    const directory = new ClientEventScopeDirectory(store);

    await expect(directory.capture(binding())).rejects.toMatchObject({ code: 'corrupt_state' });
    await expect(directory.upsert(binding())).rejects.toMatchObject({ code: 'corrupt_state' });
    await expect(directory.remove(binding())).rejects.toMatchObject({ code: 'corrupt_state' });
    await expect(rawDirectory(store)).resolves.toEqual(before);
  });

  it('classifies malformed current-schema entry fields as corrupt state', async () => {
    const store = createMemoryStore();
    await store.set(CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY, {
      schemaVersion: 1,
      entries: {
        [JSON.stringify([SERVER_A, EMAIL_A])]: {
          serverUrl: SERVER_A,
          accountIdentity: EMAIL_A,
          accountId: 'not-a-uuid',
        },
      },
    });

    await expect(new ClientEventScopeDirectory(store).listExact())
      .rejects.toMatchObject({ code: 'corrupt_state' });
  });

  it('preserves a future schema across every read and mutation attempt', async () => {
    const store = createMemoryStore();
    const future = {
      schemaVersion: 2,
      entries: {},
      futureState: { opaque: true },
    };
    await store.set(CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY, future);
    const before = await rawDirectory(store);
    const directory = new ClientEventScopeDirectory(store);

    for (const operation of [
      () => directory.capture(binding()),
      () => directory.listExact(),
      () => directory.upsert(binding()),
      () => directory.remove(binding()),
    ]) {
      await expect(operation()).rejects.toMatchObject({ code: 'unsupported_schema' });
    }
    await expect(rawDirectory(store)).resolves.toEqual(before);
  });

  it('invalidates a capture across remove-and-reinsert ABA even when values are identical', async () => {
    const store = createMemoryStore();
    const directory = new ClientEventScopeDirectory(store);
    await directory.upsert(binding());
    const oldCapture = await directory.capture(binding());
    await directory.remove(binding());
    await directory.upsert(binding());
    const newCapture = await directory.capture(binding());

    expect(() => directory.assertCurrent(oldCapture!)).toThrow(/changed/i);
    expect(() => directory.assertCurrent(newCapture!)).not.toThrow();
  });

  it('invalidates captures synchronously when a directory write becomes pending', async () => {
    const base = createMemoryStore();
    let holdWrites = false;
    let release!: () => void;
    const writeGate = new Promise<void>((resolve) => { release = resolve; });
    const store: KeyValueStore = {
      ...base,
      async set(key, value) {
        if (holdWrites && key === CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY) await writeGate;
        await base.set(key, value);
      },
    };
    const directory = new ClientEventScopeDirectory(store);
    await directory.upsert(binding());
    const capture = await directory.capture(binding());

    holdWrites = true;
    const pending = directory.upsert(binding({ accountId: USER_B }));
    expect(() => directory.assertCurrent(capture!)).toThrow(/changed/i);
    release();
    await pending;
  });

  it('shares the ABA generation across repository instances over the same store', async () => {
    const store = createMemoryStore();
    const first = new ClientEventScopeDirectory(store);
    const second = new ClientEventScopeDirectory(store);
    await first.upsert(binding());
    const capture = await first.capture(binding());

    await second.upsert(binding({ accountId: USER_B }));

    expect(() => first.assertCurrent(capture!)).toThrow(/changed/i);
  });

  it('reconciles a set that commits before rejecting', async () => {
    const base = createMemoryStore();
    let rejectAfterCommit = false;
    const store: KeyValueStore = {
      ...base,
      async set(key, value) {
        await base.set(key, value);
        if (rejectAfterCommit && key === CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY) {
          throw new Error('set rejected after commit');
        }
      },
    };
    const directory = new ClientEventScopeDirectory(store);
    await directory.upsert(binding());
    rejectAfterCommit = true;

    await expect(directory.upsert(binding({ accountId: USER_B })))
      .resolves.toMatchObject({ accountId: USER_B });
    await expect(directory.listExact()).resolves.toMatchObject([{ accountId: USER_B }]);
  });

  it('rejects a silently dropped set while retaining the previous binding', async () => {
    const base = createMemoryStore();
    let dropWrites = false;
    const store: KeyValueStore = {
      ...base,
      async set(key, value) {
        if (dropWrites && key === CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY) return;
        await base.set(key, value);
      },
    };
    const directory = new ClientEventScopeDirectory(store);
    await directory.upsert(binding());
    dropWrites = true;

    await expect(directory.upsert(binding({ accountId: USER_B })))
      .rejects.toMatchObject({ code: 'persistence_failed' });
    await expect(directory.listExact()).resolves.toMatchObject([{ accountId: USER_A }]);
  });

  it('preserves an externally replaced value and fails the directory closed', async () => {
    const base = createMemoryStore();
    let replaceExternally = false;
    const external = { schemaVersion: 2, entries: {}, external: true };
    const store: KeyValueStore = {
      ...base,
      async set(key, value) {
        await base.set(key, value);
        if (replaceExternally && key === CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY) {
          await base.set(key, external);
        }
      },
    };
    const directory = new ClientEventScopeDirectory(store);
    await directory.upsert(binding());
    replaceExternally = true;

    await expect(directory.upsert(binding({ accountId: USER_B })))
      .rejects.toMatchObject({ code: 'outcome_unknown' });
    await expect(rawDirectory(store)).resolves.toEqual(external);
    await expect(directory.listExact()).rejects.toMatchObject({ code: 'rollback_failed' });
  });

  it('reconciles commit-then-reject remove and detects a silently dropped remove', async () => {
    const committedBase = createMemoryStore();
    let rejectRemove = false;
    const commitThenRejectStore: KeyValueStore = {
      ...committedBase,
      async remove(key) {
        await committedBase.remove(key);
        if (rejectRemove && key === CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY) {
          throw new Error('remove rejected after commit');
        }
      },
    };
    const committed = new ClientEventScopeDirectory(commitThenRejectStore);
    await committed.upsert(binding());
    rejectRemove = true;
    await expect(committed.remove(binding())).resolves.toMatchObject({ accountId: USER_A });
    await expect(rawDirectory(commitThenRejectStore)).resolves.toBeUndefined();

    const droppedBase = createMemoryStore();
    let dropRemove = false;
    const droppedStore: KeyValueStore = {
      ...droppedBase,
      async remove(key) {
        if (dropRemove && key === CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY) return;
        await droppedBase.remove(key);
      },
    };
    const dropped = new ClientEventScopeDirectory(droppedStore);
    await dropped.upsert(binding());
    dropRemove = true;
    await expect(dropped.remove(binding())).rejects.toMatchObject({ code: 'persistence_failed' });
    await expect(dropped.listExact()).resolves.toMatchObject([{ accountId: USER_A }]);
  });
});

function transportHarness() {
  const store = createMemoryStore();
  const directory = new ClientEventScopeDirectory(store);
  const account = accountHarness();
  const collectClientEvents = vi.fn(async (
    _token: string,
    _events: readonly ClientEventWire[],
  ) => ({ ok: true as const }));
  const apiForServer = vi.fn((
    _serverUrl: string,
    assertCurrent: () => void,
  ): ClientEventCollectClient => ({
    async collectClientEvents(token, events) {
      assertCurrent();
      return collectClientEvents(token, events);
    },
  }));
  const authenticatedCalls: string[] = [];
  const executeAuthenticatedRequest = async <Result>(
    _lease: TestLease,
    rebuild: (accessToken: string) => Promise<Result>,
  ): Promise<Result> => {
    authenticatedCalls.push('access-a');
    return rebuild('access-a');
  };
  const deps: ClientEventProductionTransportDependencies<TestLease> = {
    directory,
    captureAccountLease: account.captureAccountLease,
    assertAccountLease: account.assertAccountLease,
    executeAuthenticatedRequest,
    apiForServer,
  };
  return {
    store,
    directory,
    account,
    collectClientEvents,
    apiForServer,
    authenticatedCalls,
    deps,
  };
}

describe('ClientEventProductionTransport', () => {
  it('pins upload to the exact directory binding, account lease, server, and request guard', async () => {
    const h = transportHarness();
    await h.directory.upsert(binding());
    const transport = new ClientEventProductionTransport(h.deps);

    await expect(transport.upload({ serverUrl: SERVER_A, accountId: USER_A }, [EVENT]))
      .resolves.toEqual({ ok: true });

    expect(h.apiForServer).toHaveBeenCalledWith(SERVER_A, expect.any(Function));
    expect(h.collectClientEvents).toHaveBeenCalledWith('access-a', [EVENT]);
    expect(h.authenticatedCalls).toEqual(['access-a']);
    expect(h.account.assertAccountLease.mock.calls.length).toBeGreaterThanOrEqual(4);
  });

  it('allows only the injected authenticated executor to rebuild once after 401', async () => {
    const h = transportHarness();
    await h.directory.upsert(binding());
    const unauthorized = new Error('401');
    h.collectClientEvents
      .mockRejectedValueOnce(unauthorized)
      .mockResolvedValueOnce({ ok: true });
    const tokens: string[] = [];
    h.deps.executeAuthenticatedRequest = async <Result>(
      _lease: TestLease,
      rebuild: (accessToken: string) => Promise<Result>,
    ): Promise<Result> => {
      tokens.push('old-token');
      try {
        return await rebuild('old-token');
      } catch (error) {
        if (error !== unauthorized) throw error;
      }
      tokens.push('new-token');
      return rebuild('new-token');
    };
    const transport = new ClientEventProductionTransport(h.deps);

    await expect(transport.upload({ serverUrl: SERVER_A, accountId: USER_A }, [EVENT]))
      .resolves.toEqual({ ok: true });

    expect(tokens).toEqual(['old-token', 'new-token']);
    expect(h.collectClientEvents.mock.calls.map(([token]) => token))
      .toEqual(['old-token', 'new-token']);
    expect(h.apiForServer).toHaveBeenCalledOnce();
  });

  it('rejects a wrong profile scope before creating a client or reading a token', async () => {
    const h = transportHarness();
    await h.directory.upsert(binding());
    let authenticatedCalls = 0;
    const originalExecute = h.deps.executeAuthenticatedRequest;
    h.deps.executeAuthenticatedRequest = async <Result>(
      lease: TestLease,
      rebuild: (accessToken: string) => Promise<Result>,
    ): Promise<Result> => {
      authenticatedCalls += 1;
      return originalExecute(lease, rebuild);
    };
    const transport = new ClientEventProductionTransport(h.deps);

    await expect(transport.upload({ serverUrl: SERVER_A, accountId: USER_B }, [EVENT]))
      .rejects.toEqual(new ClientEventProductionError(
        'scope_mismatch',
        'Client event upload scope does not match the active account',
    ));
    expect(h.apiForServer).not.toHaveBeenCalled();
    expect(authenticatedCalls).toBe(0);
  });

  it('rejects account A-B-A before authenticated execution', async () => {
    const h = transportHarness();
    await h.directory.upsert(binding());
    h.apiForServer.mockImplementationOnce((_serverUrl, assertCurrent) => {
      h.account.switchAwayAndBack();
      return {
        async collectClientEvents() {
          assertCurrent();
          return { ok: true };
        },
      };
    });
    let authenticatedCalls = 0;
    const originalExecute = h.deps.executeAuthenticatedRequest;
    h.deps.executeAuthenticatedRequest = async <Result>(
      lease: TestLease,
      rebuild: (accessToken: string) => Promise<Result>,
    ): Promise<Result> => {
      authenticatedCalls += 1;
      return originalExecute(lease, rebuild);
    };

    await expect(new ClientEventProductionTransport(h.deps).upload(
      { serverUrl: SERVER_A, accountId: USER_A },
      [EVENT],
    )).rejects.toThrow(/account lease changed/i);
    expect(authenticatedCalls).toBe(0);
  });

  it('rejects directory remove-and-reinsert ABA before the retry callback can fetch', async () => {
    const h = transportHarness();
    await h.directory.upsert(binding());
    h.deps.executeAuthenticatedRequest = async <Result>(
      _lease: TestLease,
      rebuild: (accessToken: string) => Promise<Result>,
    ): Promise<Result> => {
      await h.directory.remove(binding());
      await h.directory.upsert(binding());
      return rebuild('access-a');
    };

    await expect(new ClientEventProductionTransport(h.deps).upload(
      { serverUrl: SERVER_A, accountId: USER_A },
      [EVENT],
    )).rejects.toMatchObject({ code: 'changed' });
    expect(h.collectClientEvents).not.toHaveBeenCalled();
  });

  it('rejects a successful response when the account changes before final settlement', async () => {
    const h = transportHarness();
    await h.directory.upsert(binding());
    h.deps.executeAuthenticatedRequest = async <Result>(
      _lease: TestLease,
      rebuild: (accessToken: string) => Promise<Result>,
    ): Promise<Result> => {
      const result = await rebuild('access-a');
      h.account.switchAwayAndBack();
      return result;
    };

    await expect(new ClientEventProductionTransport(h.deps).upload(
      { serverUrl: SERVER_A, accountId: USER_A },
      [EVENT],
    )).rejects.toThrow(/account lease changed/i);
    expect(h.collectClientEvents).toHaveBeenCalledOnce();
  });
});

describe('ClientEventFixedAlarmScheduler', () => {
  it('uses one fixed PII-free alarm and ignores inactive scope schedule/cancel requests', async () => {
    const store = createMemoryStore();
    const directory = new ClientEventScopeDirectory(store);
    await directory.upsert(binding());
    const account = accountHarness();
    const get = vi.fn(async () => undefined);
    const create = vi.fn(async () => undefined);
    const clear = vi.fn(async () => true);
    const scheduler = new ClientEventFixedAlarmScheduler({
      directory,
      alarms: { get, create, clear },
      captureAccountLease: account.captureAccountLease,
      assertAccountLease: account.assertAccountLease,
    });

    await scheduler.schedule({
      scope: { serverUrl: SERVER_A, accountId: USER_A },
      when: NOW + 60_000,
      reason: 'periodic',
    });
    await scheduler.schedule({
      scope: { serverUrl: SERVER_A, accountId: USER_B },
      when: NOW + 30_000,
      reason: 'retry',
    });
    await scheduler.cancel({ serverUrl: SERVER_A, accountId: USER_B });

    expect(create).toHaveBeenCalledOnce();
    expect(create).toHaveBeenCalledWith(CLIENT_EVENT_UPLOAD_ALARM, { when: NOW + 60_000 });
    expect(CLIENT_EVENT_UPLOAD_ALARM).not.toMatch(/alice|vault-a|aaaaaaaa/u);
    expect(clear).not.toHaveBeenCalled();

    await scheduler.cancel({ serverUrl: SERVER_A, accountId: USER_A });
    expect(clear).toHaveBeenCalledWith(CLIENT_EVENT_UPLOAD_ALARM);
  });

  it('clears a just-created alarm when the account changes during creation', async () => {
    const store = createMemoryStore();
    const directory = new ClientEventScopeDirectory(store);
    await directory.upsert(binding());
    const account = accountHarness();
    const clear = vi.fn(async () => true);
    const scheduler = new ClientEventFixedAlarmScheduler({
      directory,
      alarms: {
        get: async () => undefined,
        async create() { account.switchAwayAndBack(); },
        clear,
      },
      captureAccountLease: account.captureAccountLease,
      assertAccountLease: account.assertAccountLease,
    });

    await expect(scheduler.schedule({
      scope: { serverUrl: SERVER_A, accountId: USER_A },
      when: NOW,
      reason: 'retry',
    })).rejects.toThrow(/account lease changed/i);
    expect(clear).toHaveBeenCalledWith(CLIENT_EVENT_UPLOAD_ALARM);
  });

  it('preserves the earliest active-scope deadline for the single alarm', async () => {
    const store = createMemoryStore();
    const directory = new ClientEventScopeDirectory(store);
    await directory.upsert(binding());
    const account = accountHarness();
    let scheduledTime: number | undefined;
    const create = vi.fn(async (_name: string, options: { readonly when: number }) => {
      scheduledTime = options.when;
    });
    const scheduler = new ClientEventFixedAlarmScheduler({
      directory,
      alarms: {
        get: async () => scheduledTime === undefined ? undefined : { scheduledTime },
        create,
        clear: async () => { scheduledTime = undefined; return true; },
      },
      captureAccountLease: account.captureAccountLease,
      assertAccountLease: account.assertAccountLease,
    });

    await scheduler.schedule({
      scope: { serverUrl: SERVER_A, accountId: USER_A },
      when: NOW + 10_000,
      reason: 'retry',
    });
    await scheduler.schedule({
      scope: { serverUrl: SERVER_A, accountId: USER_A },
      when: NOW + 60_000,
      reason: 'periodic',
    });
    await scheduler.schedule({
      scope: { serverUrl: SERVER_A, accountId: USER_A },
      when: NOW + 5_000,
      reason: 'retry',
    });

    expect(create.mock.calls.map(([, options]) => options.when))
      .toEqual([NOW + 10_000, NOW + 5_000]);
    expect(scheduledTime).toBe(NOW + 5_000);
  });

  it('serializes stale cleanup before a newly active account schedules the fixed alarm', async () => {
    const store = createMemoryStore();
    const directory = new ClientEventScopeDirectory(store);
    await directory.upsert(binding());
    await directory.upsert(binding({
      serverUrl: SERVER_B,
      accountIdentity: 'bob@example.com',
      accountId: USER_B,
    }));
    const account = accountHarness();
    const order: string[] = [];
    let scheduledTime: number | undefined;
    let markFirstCreate!: () => void;
    const firstCreate = new Promise<void>((resolve) => { markFirstCreate = resolve; });
    let release!: () => void;
    const createGate = new Promise<void>((resolve) => { release = resolve; });
    let createCount = 0;
    const scheduler = new ClientEventFixedAlarmScheduler({
      directory,
      alarms: {
        get: async () => scheduledTime === undefined ? undefined : { scheduledTime },
        async create(_name, options) {
          createCount += 1;
          if (createCount === 1) {
            order.push('create-a');
            account.switchTo(SERVER_B, 'bob@example.com');
            markFirstCreate();
            await createGate;
          } else {
            order.push('create-b');
          }
          scheduledTime = options.when;
        },
        async clear() {
          order.push('clear-stale');
          scheduledTime = undefined;
          return true;
        },
      },
      captureAccountLease: account.captureAccountLease,
      assertAccountLease: account.assertAccountLease,
    });

    const stale = scheduler.schedule({
      scope: { serverUrl: SERVER_A, accountId: USER_A },
      when: NOW + 10_000,
      reason: 'retry',
    });
    await firstCreate;
    const current = scheduler.schedule({
      scope: { serverUrl: SERVER_B, accountId: USER_B },
      when: NOW + 20_000,
      reason: 'periodic',
    });
    release();

    await expect(stale).rejects.toThrow(/account lease changed/i);
    await expect(current).resolves.toBeUndefined();
    expect(order).toEqual(['create-a', 'clear-stale', 'create-b']);
    expect(scheduledTime).toBe(NOW + 20_000);
  });
});

describe('createClientEventProduction', () => {
  it('assembles queue, uploader, service, fixed alarm, and active-scope flush', async () => {
    const store = createMemoryStore();
    const account = accountHarness();
    const get = vi.fn(async () => undefined);
    const create = vi.fn(async () => undefined);
    const clear = vi.fn(async () => true);
    const collect = vi.fn(async (
      _token: string,
      _events: readonly ClientEventWire[],
    ) => ({ ok: true as const }));
    const ids = [
      '10000000-0000-4000-8000-000000000001',
      '10000000-0000-4000-8000-000000000002',
    ];
    const runtime = createClientEventProduction({
      store,
      authority: {
        captureActive: (): unknown => ({
          serverUrl: SERVER_A,
          userId: USER_A,
          organizations: [{ id: ORG_A, useEvents: true }],
          ciphers: [{ id: CIPHER_A, organizationId: ORG_A }],
        }),
      },
      alarms: { get, create, clear },
      captureAccountLease: account.captureAccountLease,
      assertAccountLease: account.assertAccountLease,
      executeAuthenticatedRequest: async <Result>(
        _lease: TestLease,
        rebuild: (accessToken: string) => Promise<Result>,
      ) => rebuild('access-a'),
      apiForServer: (_serverUrl, assertCurrent) => ({
        async collectClientEvents(token, events) {
          assertCurrent();
          return collect(token, events);
        },
      }),
    }, {
      now: () => NOW,
      queue: { createId: () => ids.shift()! },
    });
    await expect(runtime.synchronizeActiveBinding()).resolves.toMatchObject(binding());
    const receipt = await runtime.prepare({
      type: ClientEventType.Cipher_ClientViewed,
      cipherId: CIPHER_A,
    });
    if (!receipt) throw new Error('Expected event receipt');

    await expect(runtime.commit(receipt)).resolves.toEqual({ kind: 'enqueued' });
    await expect(runtime.handleAlarm('another-alarm')).resolves.toBe(false);
    await expect(runtime.handleAlarm(CLIENT_EVENT_UPLOAD_ALARM)).resolves.toBe(true);

    expect(collect).toHaveBeenCalledWith('access-a', [{
      ...EVENT,
      date: new Date(NOW).toISOString(),
    }]);
    await expect(runtime.queue.inspect({ serverUrl: SERVER_A, accountId: USER_A }))
      .resolves.toMatchObject({ queued: 0, claimed: 0 });
    expect(create).toHaveBeenCalledWith(
      CLIENT_EVENT_UPLOAD_ALARM,
      expect.objectContaining({ when: NOW + 60_000 }),
    );
  });

  it('does not issue a receipt when the persistent scope binding cannot be verified', async () => {
    const base = createMemoryStore();
    const store: KeyValueStore = {
      ...base,
      async set(key, value) {
        if (key !== CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY) await base.set(key, value);
      },
    };
    const { runtime } = createProductionHarness(store);

    await expect(runtime.prepare({
      type: ClientEventType.Cipher_ClientViewed,
      cipherId: CIPHER_A,
    })).rejects.toMatchObject({ code: 'persistence_failed' });
    await expect(runtime.queue.inspect({ serverUrl: SERVER_A, accountId: USER_A }))
      .resolves.toMatchObject({ queued: 0, claimed: 0 });
    const removal = await runtime.captureAccountRemoval(EMAIL_A);
    await expect(runtime.completeAccountRemoval(removal)).resolves.toBe(true);
    await expect(runtime.queue.inspect({ serverUrl: SERVER_A, accountId: USER_A }))
      .resolves.toMatchObject({ queued: 0, claimed: 0 });
  });

  it('releases rather than acknowledges a sent batch when authority changes before settlement', async () => {
    const store = createMemoryStore();
    const account = accountHarness();
    const ids = [
      '20000000-0000-4000-8000-000000000001',
      '20000000-0000-4000-8000-000000000002',
    ];
    const collect = vi.fn(async () => ({ ok: true as const }));
    const runtime = createClientEventProduction({
      store,
      authority: {
        captureActive: () => ({
          serverUrl: SERVER_A,
          userId: USER_A,
          organizations: [{ id: ORG_A, useEvents: true }],
          ciphers: [{ id: CIPHER_A, organizationId: ORG_A }],
        }),
      },
      alarms: {
        get: async () => undefined,
        create: () => undefined,
        clear: async () => true,
      },
      captureAccountLease: account.captureAccountLease,
      assertAccountLease: account.assertAccountLease,
      executeAuthenticatedRequest: async <Result>(
        _lease: TestLease,
        rebuild: (accessToken: string) => Promise<Result>,
      ): Promise<Result> => {
        const result = await rebuild('access-a');
        account.switchAwayAndBack();
        return result;
      },
      apiForServer: (_serverUrl, assertCurrent) => ({
        async collectClientEvents() {
          assertCurrent();
          return collect();
        },
      }),
    }, {
      now: () => NOW,
      queue: { createId: () => ids.shift()!, random: () => 0.5 },
    });
    await runtime.synchronizeActiveBinding();
    const receipt = await runtime.service.prepare({
      type: ClientEventType.Cipher_ClientViewed,
      cipherId: CIPHER_A,
    });
    if (!receipt) throw new Error('Expected event receipt');
    await runtime.service.commit(receipt);

    await expect(runtime.flushActive()).resolves.toMatchObject({
      kind: 'retry_scheduled',
      count: 1,
    });
    await expect(runtime.queue.inspect({ serverUrl: SERVER_A, accountId: USER_A }))
      .resolves.toMatchObject({ queued: 1, claimed: 0 });
    expect(collect).toHaveBeenCalledOnce();
  });

  it('returns undefined when no active account binding exists', async () => {
    const store = createMemoryStore();
    const account = accountHarness();
    const runtime = createClientEventProduction({
      store,
      authority: { captureActive: () => undefined },
      alarms: {
        get: vi.fn(async () => undefined),
        create: vi.fn(),
        clear: vi.fn(async () => true),
      },
      captureAccountLease: account.captureAccountLease,
      assertAccountLease: account.assertAccountLease,
      executeAuthenticatedRequest: async <Result>(
        _lease: TestLease,
        rebuild: (accessToken: string) => Promise<Result>,
      ) => rebuild('access-a'),
      apiForServer: () => ({ collectClientEvents: async () => ({ ok: true }) }),
    });

    await expect(runtime.flushActive()).resolves.toBeUndefined();
  });

  it('fences active binding synchronization against a server mismatch and account ABA', async () => {
    const makeRuntime = (
      account: ReturnType<typeof accountHarness>,
      captureActive: () => unknown | PromiseLike<unknown>,
    ) => createClientEventProduction({
      store: createMemoryStore(),
      authority: { captureActive },
      alarms: {
        get: async () => undefined,
        create: () => undefined,
        clear: async () => true,
      },
      captureAccountLease: account.captureAccountLease,
      assertAccountLease: account.assertAccountLease,
      executeAuthenticatedRequest: async <Result>(
        _lease: TestLease,
        rebuild: (accessToken: string) => Promise<Result>,
      ) => rebuild('access-a'),
      apiForServer: () => ({ collectClientEvents: async () => ({ ok: true }) }),
    });

    const mismatchAccount = accountHarness();
    const mismatch = makeRuntime(mismatchAccount, () => ({
      serverUrl: 'https://wrong.example/',
      userId: USER_A,
      organizations: [],
      ciphers: [],
    }));
    await expect(mismatch.synchronizeActiveBinding()).rejects.toMatchObject({
      code: 'scope_mismatch',
    });
    await expect(mismatch.directory.listExact()).resolves.toEqual([]);

    const abaAccount = accountHarness();
    const aba = makeRuntime(abaAccount, async () => {
      abaAccount.switchAwayAndBack();
      return {
        serverUrl: SERVER_A,
        userId: USER_A,
        organizations: [],
        ciphers: [],
      };
    });
    await expect(aba.synchronizeActiveBinding()).rejects.toThrow(/account lease changed/i);
    await expect(aba.directory.listExact()).resolves.toEqual([]);
  });

  it('rolls back active binding synchronization when the account changes during persistence', async () => {
    const base = createMemoryStore();
    let block = true;
    let markWriteStarted!: () => void;
    const writeStarted = new Promise<void>((resolve) => { markWriteStarted = resolve; });
    let release!: () => void;
    const writeGate = new Promise<void>((resolve) => { release = resolve; });
    const store: KeyValueStore = {
      ...base,
      async set(key, value) {
        if (block && key === CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY) {
          block = false;
          markWriteStarted();
          await writeGate;
        }
        await base.set(key, value);
      },
    };
    const account = accountHarness();
    const runtime = createClientEventProduction({
      store,
      authority: {
        captureActive: () => ({
          serverUrl: SERVER_A,
          userId: USER_A,
          organizations: [],
          ciphers: [],
        }),
      },
      alarms: {
        get: async () => undefined,
        create: () => undefined,
        clear: async () => true,
      },
      captureAccountLease: account.captureAccountLease,
      assertAccountLease: account.assertAccountLease,
      executeAuthenticatedRequest: async <Result>(
        _lease: TestLease,
        rebuild: (accessToken: string) => Promise<Result>,
      ) => rebuild('access-a'),
      apiForServer: () => ({ collectClientEvents: async () => ({ ok: true }) }),
    });

    const pending = runtime.synchronizeActiveBinding();
    await writeStarted;
    account.switchAwayAndBack();
    release();

    await expect(pending).rejects.toThrow(/account lease changed/i);
    await expect(runtime.directory.listExact()).resolves.toEqual([]);
    await expect(rawDirectory(store)).resolves.toBeUndefined();
  });

  it('rolls back when the account changes during persistence readback', async () => {
    const base = createMemoryStore();
    let writeCompleted = false;
    let blockReadback = true;
    let markReadbackStarted!: () => void;
    const readbackStarted = new Promise<void>((resolve) => { markReadbackStarted = resolve; });
    let release!: () => void;
    const readbackGate = new Promise<void>((resolve) => { release = resolve; });
    const store: KeyValueStore = {
      ...base,
      async get<T>(key: string): Promise<T | undefined> {
        const value = await base.get<T>(key);
        if (writeCompleted && blockReadback && key === CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY) {
          blockReadback = false;
          markReadbackStarted();
          await readbackGate;
        }
        return value;
      },
      async set(key, value) {
        await base.set(key, value);
        if (key === CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY) writeCompleted = true;
      },
    };
    const account = accountHarness();
    const runtime = createClientEventProduction({
      store,
      authority: {
        captureActive: () => ({
          serverUrl: SERVER_A,
          userId: USER_A,
          organizations: [],
          ciphers: [],
        }),
      },
      alarms: {
        get: async () => undefined,
        create: () => undefined,
        clear: async () => true,
      },
      captureAccountLease: account.captureAccountLease,
      assertAccountLease: account.assertAccountLease,
      executeAuthenticatedRequest: async <Result>(
        _lease: TestLease,
        rebuild: (accessToken: string) => Promise<Result>,
      ) => rebuild('access-a'),
      apiForServer: () => ({ collectClientEvents: async () => ({ ok: true }) }),
    });

    const pending = runtime.synchronizeActiveBinding();
    await readbackStarted;
    account.switchAwayAndBack();
    release();

    await expect(pending).rejects.toThrow(/account lease changed/i);
    await expect(runtime.directory.listExact()).resolves.toEqual([]);
    await expect(rawDirectory(store)).resolves.toBeUndefined();
  });

  it('discards the exact logout scope and binding after a successful upload', async () => {
    const { runtime } = createProductionHarness();
    const stored = await runtime.synchronizeActiveBinding();
    await runtime.queue.enqueue(stored.scope, EVENT);
    const receipt = await runtime.captureLogout();
    await expect(runtime.logoutMarkers.listExact()).resolves.toEqual([stored]);
    await expect(runtime.logoutSucceededMarkers.listExact()).resolves.toEqual([]);

    await expect(runtime.flushBeforeLogout(receipt)).resolves.toEqual({
      kind: 'uploaded', count: 1,
    });
    await expect(runtime.completeLogout(receipt, true)).resolves.toBe(true);
    await expect(runtime.completeLogout(receipt, true)).resolves.toBe(false);
    await expect(runtime.queue.inspect(stored.scope)).resolves.toMatchObject({ queued: 0, claimed: 0 });
    await expect(runtime.directory.listExact()).resolves.toEqual([]);
    await expect(runtime.logoutMarkers.listExact()).resolves.toEqual([]);
  });

  it('discards the exact logout scope after a failed upload', async () => {
    const { runtime } = createProductionHarness(createMemoryStore(), {
      collectClientEvents: async () => ({ ok: false, status: 503 }),
    });
    const stored = await runtime.synchronizeActiveBinding();
    await runtime.queue.enqueue(stored.scope, EVENT);
    const receipt = await runtime.captureLogout();

    await expect(runtime.flushBeforeLogout(receipt)).resolves.toMatchObject({
      kind: 'retry_scheduled', status: 503,
    });
    await expect(runtime.completeLogout(receipt, true)).resolves.toBe(true);
    await expect(runtime.queue.inspect(stored.scope)).resolves.toMatchObject({ queued: 0, claimed: 0 });
    await expect(runtime.directory.listExact()).resolves.toEqual([]);
    await expect(runtime.logoutMarkers.listExact()).resolves.toEqual([]);
  });

  it('immediately discards logout plaintext while an upload transport is hung', async () => {
    const upload = deferred<{ readonly ok: false; readonly status: 503 }>();
    const collectClientEvents = vi.fn(() => upload.promise);
    const { runtime } = createProductionHarness(createMemoryStore(), { collectClientEvents });
    const stored = await runtime.synchronizeActiveBinding();
    await runtime.queue.enqueue(stored.scope, EVENT);
    const receipt = await runtime.captureLogout();

    const flushing = runtime.flushBeforeLogout(receipt);
    await vi.waitFor(() => expect(collectClientEvents).toHaveBeenCalledOnce());
    await expect(runtime.completeLogout(receipt, true)).resolves.toBe(true);
    await expect(runtime.queue.inspect(stored.scope)).resolves.toMatchObject({ queued: 0, claimed: 0 });
    await expect(runtime.directory.listExact()).resolves.toEqual([]);
    await expect(runtime.logoutMarkers.listExact()).resolves.toEqual([]);

    upload.resolve({ ok: false, status: 503 });
    await expect(flushing).resolves.toMatchObject({ kind: 'superseded', count: 1 });
    await expect(runtime.queue.inspect(stored.scope)).resolves.toMatchObject({ queued: 0, claimed: 0 });
  });

  it('preserves queued events when the owning logout fails', async () => {
    const { runtime } = createProductionHarness();
    const stored = await runtime.synchronizeActiveBinding();
    await runtime.queue.enqueue(stored.scope, EVENT);
    const receipt = await runtime.captureLogout();

    await expect(runtime.completeLogout(receipt, false)).resolves.toBe(true);
    await expect(runtime.queue.inspect(stored.scope)).resolves.toMatchObject({ queued: 1, claimed: 0 });
    await expect(runtime.directory.listExact()).resolves.toEqual([stored]);
    await expect(runtime.logoutMarkers.listExact()).resolves.toEqual([]);
  });

  it('does not let a late old-account upload delete a post-relogin event for the same scope', async () => {
    const upload = deferred<{ readonly ok: true }>();
    const collectClientEvents = vi.fn(() => upload.promise);
    const account = accountHarness();
    const { runtime } = createProductionHarness(createMemoryStore(), {
      account,
      collectClientEvents,
    });
    const stored = await runtime.synchronizeActiveBinding();
    await runtime.queue.enqueue(stored.scope, EVENT);
    const logout = await runtime.captureLogout();
    const flushing = runtime.flushBeforeLogout(logout);
    await vi.waitFor(() => expect(collectClientEvents).toHaveBeenCalledOnce());

    await expect(runtime.completeLogout(logout, true)).resolves.toBe(true);
    account.switchAwayAndBack();
    const prepared = await runtime.prepare({
      type: ClientEventType.Cipher_ClientViewed,
      cipherId: CIPHER_A,
    });
    if (!prepared) throw new Error('Expected post-login receipt');
    const committing = runtime.commit(prepared);
    upload.resolve({ ok: true });

    await expect(flushing).resolves.toMatchObject({ kind: 'superseded', count: 1 });
    await expect(committing).resolves.toEqual({ kind: 'enqueued' });
    await expect(runtime.queue.inspect(stored.scope)).resolves.toMatchObject({ queued: 1, claimed: 0 });
    await expect(runtime.directory.listExact()).resolves.toEqual([stored]);
  });

  it('orders a same-account relogin binding after a delayed logout directory removal', async () => {
    const base = createMemoryStore();
    let blockRemoval = true;
    let markRemovalStarted!: () => void;
    const removalStarted = new Promise<void>((resolve) => { markRemovalStarted = resolve; });
    let releaseRemoval!: () => void;
    const removalGate = new Promise<void>((resolve) => { releaseRemoval = resolve; });
    const store: KeyValueStore = {
      ...base,
      async remove(key) {
        if (blockRemoval && key === CLIENT_EVENT_SCOPE_DIRECTORY_STORAGE_KEY) {
          blockRemoval = false;
          markRemovalStarted();
          await removalGate;
        }
        await base.remove(key);
      },
    };
    const account = accountHarness();
    const { runtime } = createProductionHarness(store, { account });
    const stored = await runtime.synchronizeActiveBinding();
    await runtime.queue.enqueue(stored.scope, EVENT);
    const logout = await runtime.captureLogout();
    const completing = runtime.completeLogout(logout, true);
    await removalStarted;

    account.switchAwayAndBack();
    const preparing = runtime.prepare({
      type: ClientEventType.Cipher_ClientViewed,
      cipherId: CIPHER_A,
    });
    releaseRemoval();

    await expect(completing).resolves.toBe(true);
    const prepared = await preparing;
    if (!prepared) throw new Error('Expected post-login receipt');
    await expect(runtime.commit(prepared)).resolves.toEqual({ kind: 'enqueued' });
    await expect(runtime.queue.inspect(stored.scope)).resolves.toMatchObject({ queued: 1 });
    await expect(runtime.directory.listExact()).resolves.toEqual([stored]);
    await expect(runtime.logoutMarkers.listExact()).resolves.toEqual([]);
  });

  it('finishes confirmed cleanup before relogin after directory success and queue failure', async () => {
    const base = createMemoryStore();
    let failQueueDiscard = false;
    const store: KeyValueStore = {
      ...base,
      async set(key, value) {
        if (failQueueDiscard && key === CLIENT_EVENT_QUEUE_STORAGE_KEY) {
          failQueueDiscard = false;
          throw new Error('queue discard failed');
        }
        await base.set(key, value);
      },
    };
    const account = accountHarness();
    const { runtime } = createProductionHarness(store, { account });
    const stored = await runtime.synchronizeActiveBinding();
    await runtime.queue.enqueue(stored.scope, EVENT);
    const logout = await runtime.captureLogout();
    failQueueDiscard = true;

    await expect(runtime.completeLogout(logout, true)).resolves.toBe(false);
    await expect(runtime.directory.listExact()).resolves.toEqual([]);
    await expect(runtime.queue.inspect(stored.scope)).resolves.toMatchObject({ queued: 1 });
    await expect(runtime.logoutMarkers.listExact()).resolves.toEqual([]);
    await expect(runtime.logoutSucceededMarkers.listExact()).resolves.toEqual([stored]);

    account.switchAwayAndBack();
    const prepared = await runtime.prepare({
      type: ClientEventType.Cipher_ClientViewed,
      cipherId: CIPHER_A,
    });
    if (!prepared) throw new Error('Expected post-login receipt');
    await expect(runtime.commit(prepared)).resolves.toEqual({ kind: 'enqueued' });

    await expect(runtime.queue.inspect(stored.scope)).resolves.toMatchObject({ queued: 1 });
    await expect(runtime.directory.listExact()).resolves.toEqual([stored]);
    await expect(runtime.logoutSucceededMarkers.listExact()).resolves.toEqual([]);
  });

  it('recovers a successful logout interrupted before cleanup on worker restart', async () => {
    const store = createMemoryStore();
    const first = createProductionHarness(store).runtime;
    const stored = await first.synchronizeActiveBinding();
    await first.queue.enqueue(stored.scope, EVENT);
    await first.captureLogout();

    const restarted = createProductionHarness(store).runtime;
    await expect(restarted.reconcileLogoutDiscards([])).resolves.toEqual({
      discarded: 1, preserved: 0, failed: 0,
    });

    const verifiedRestart = createProductionHarness(store).runtime;
    await expect(verifiedRestart.queue.inspect(stored.scope))
      .resolves.toMatchObject({ queued: 0, claimed: 0 });
    await expect(verifiedRestart.directory.listExact()).resolves.toEqual([]);
    await expect(verifiedRestart.logoutMarkers.listExact()).resolves.toEqual([]);
  });

  it('unconditionally finishes confirmed logout cleanup after same-account restart', async () => {
    const store = createMemoryStore();
    const first = createProductionHarness(store).runtime;
    const stored = await first.synchronizeActiveBinding();
    await first.queue.enqueue(stored.scope, EVENT);
    await first.captureLogout();
    await first.logoutSucceededMarkers.upsert({
      serverUrl: stored.serverUrl,
      accountIdentity: stored.accountIdentity,
      accountId: stored.accountId,
    });
    await first.logoutMarkers.remove(stored, stored.accountId);

    const restarted = createProductionHarness(store).runtime;
    await expect(restarted.reconcileLogoutDiscards([{
      serverUrl: SERVER_A,
      accountIdentity: EMAIL_A,
    }])).resolves.toEqual({ discarded: 1, preserved: 0, failed: 0 });
    await expect(restarted.queue.inspect(stored.scope)).resolves.toMatchObject({ queued: 0 });
    await expect(restarted.directory.listExact()).resolves.toEqual([]);
    await expect(restarted.logoutSucceededMarkers.listExact()).resolves.toEqual([]);
  });

  it('preserves a pre-restart queue when the interrupted logout account remains registered', async () => {
    const store = createMemoryStore();
    const first = createProductionHarness(store).runtime;
    const stored = await first.synchronizeActiveBinding();
    await first.queue.enqueue(stored.scope, EVENT);
    await first.captureLogout();

    const restarted = createProductionHarness(store).runtime;
    await expect(restarted.reconcileLogoutDiscards([{
      serverUrl: SERVER_A,
      accountIdentity: EMAIL_A,
    }])).resolves.toEqual({ discarded: 0, preserved: 1, failed: 0 });
    await expect(restarted.queue.inspect(stored.scope)).resolves.toMatchObject({ queued: 1 });
    await expect(restarted.directory.listExact()).resolves.toEqual([stored]);
    await expect(restarted.logoutMarkers.listExact()).resolves.toEqual([]);
  });

  it('discards an old logout marker without removing a recreated same-email account', async () => {
    const store = createMemoryStore();
    const first = createProductionHarness(store).runtime;
    const oldBinding = await first.synchronizeActiveBinding();
    await first.queue.enqueue(oldBinding.scope, EVENT);
    await first.captureLogout();
    const replacement = await first.directory.upsert(binding({ accountId: USER_C }));
    await first.queue.enqueue(replacement.scope, EVENT);

    const restarted = createProductionHarness(store).runtime;
    await expect(restarted.reconcileLogoutDiscards([{
      serverUrl: SERVER_A,
      accountIdentity: EMAIL_A,
    }])).resolves.toEqual({ discarded: 1, preserved: 0, failed: 0 });
    await expect(restarted.queue.inspect(oldBinding.scope)).resolves.toMatchObject({ queued: 0 });
    await expect(restarted.queue.inspect(replacement.scope)).resolves.toMatchObject({ queued: 1 });
    await expect(restarted.directory.listExact()).resolves.toEqual([replacement]);
    await expect(restarted.logoutMarkers.listExact()).resolves.toEqual([]);
  });

  it('fails closed without replacing a future logout-marker schema during restart recovery', async () => {
    const store = createMemoryStore();
    const future = { schemaVersion: 2, entries: {}, futureState: true };
    await store.set(CLIENT_EVENT_LOGOUT_MARKER_STORAGE_KEY, future);
    const runtime = createProductionHarness(store).runtime;

    await expect(runtime.reconcileLogoutDiscards([]))
      .rejects.toMatchObject({ code: 'unsupported_schema' });
    await expect(store.get(CLIENT_EVENT_LOGOUT_MARKER_STORAGE_KEY)).resolves.toEqual(future);
  });

  it('captures and discards one exact inactive account binding after removal succeeds', async () => {
    const { runtime } = createProductionHarness();
    await runtime.synchronizeActiveBinding();
    const removed = await runtime.directory.upsert(binding({
      accountIdentity: EMAIL_B,
      accountId: USER_B,
    }));
    await runtime.queue.enqueue(removed.scope, EVENT);
    await runtime.queue.enqueue({ serverUrl: SERVER_A, accountId: USER_A }, EVENT);

    const receipt = await runtime.captureAccountRemoval(EMAIL_B);
    await expect(runtime.completeAccountRemoval(receipt)).resolves.toBe(true);
    await expect(runtime.completeAccountRemoval(receipt)).resolves.toBe(false);

    await expect(runtime.directory.listExact()).resolves.toEqual([
      expect.objectContaining({ accountIdentity: EMAIL_A, accountId: USER_A }),
    ]);
    await expect(runtime.queue.inspect(removed.scope)).resolves.toMatchObject({ queued: 0, claimed: 0 });
    await expect(runtime.queue.inspect({ serverUrl: SERVER_A, accountId: USER_A }))
      .resolves.toMatchObject({ queued: 1, claimed: 0 });
  });

  it('does not remove a replacement account binding captured under the same registry identity', async () => {
    const { runtime } = createProductionHarness();
    const oldBinding = await runtime.directory.upsert(binding({
      accountIdentity: EMAIL_B,
      accountId: USER_B,
    }));
    await runtime.queue.enqueue(oldBinding.scope, EVENT);
    const receipt = await runtime.captureAccountRemoval(EMAIL_B);
    const replacement = await runtime.directory.upsert(binding({
      accountIdentity: EMAIL_B,
      accountId: USER_C,
    }));

    await expect(runtime.completeAccountRemoval(receipt)).resolves.toBe(true);
    await expect(runtime.directory.listExact()).resolves.toEqual([replacement]);
    await expect(runtime.queue.inspect(oldBinding.scope)).resolves.toMatchObject({ queued: 0 });
  });

  it('discards only bindings captured for the old server after a successful server change', async () => {
    const { runtime } = createProductionHarness();
    const first = await runtime.directory.upsert(binding());
    const second = await runtime.directory.upsert(binding({
      accountIdentity: EMAIL_B,
      accountId: USER_B,
    }));
    const otherServer = await runtime.directory.upsert(binding({
      serverUrl: SERVER_B,
      accountIdentity: 'carol@example.com',
      accountId: USER_C,
    }));
    await Promise.all([
      runtime.queue.enqueue(first.scope, EVENT),
      runtime.queue.enqueue(second.scope, EVENT),
      runtime.queue.enqueue(otherServer.scope, EVENT),
    ]);

    const receipt = await runtime.captureServerChange(SERVER_A);
    await expect(runtime.completeServerChange(receipt)).resolves.toEqual({ discarded: 2, failed: 0 });
    await expect(runtime.completeServerChange(receipt)).resolves.toEqual({ discarded: 0, failed: 0 });
    await expect(runtime.directory.listExact()).resolves.toEqual([otherServer]);
    await expect(runtime.queue.inspect(first.scope)).resolves.toMatchObject({ queued: 0 });
    await expect(runtime.queue.inspect(second.scope)).resolves.toMatchObject({ queued: 0 });
    await expect(runtime.queue.inspect(otherServer.scope)).resolves.toMatchObject({ queued: 1 });
  });

  it('discards every queue, directory, and logout marker on a rotated server', async () => {
    const { runtime } = createProductionHarness();
    const first = await runtime.directory.upsert(binding());
    const second = await runtime.directory.upsert(binding({
      accountIdentity: EMAIL_B,
      accountId: USER_B,
    }));
    const otherServer = await runtime.directory.upsert(binding({
      serverUrl: SERVER_B,
      accountIdentity: 'carol@example.com',
      accountId: USER_C,
    }));
    await Promise.all([
      runtime.queue.enqueue(first.scope, EVENT),
      runtime.queue.enqueue(second.scope, EVENT),
      runtime.queue.enqueue(otherServer.scope, EVENT),
    ]);
    await runtime.logoutMarkers.upsert({
      serverUrl: second.serverUrl,
      accountIdentity: second.accountIdentity,
      accountId: second.accountId,
    });

    await expect(runtime.discardServerScopes(SERVER_A)).resolves.toEqual({
      discarded: 2, failed: 0,
    });
    await expect(runtime.queue.inspect(first.scope)).resolves.toMatchObject({ queued: 0 });
    await expect(runtime.queue.inspect(second.scope)).resolves.toMatchObject({ queued: 0 });
    await expect(runtime.queue.inspect(otherServer.scope)).resolves.toMatchObject({ queued: 1 });
    await expect(runtime.directory.listExact()).resolves.toEqual([otherServer]);
    await expect(runtime.logoutMarkers.listExact()).resolves.toEqual([]);
  });
});
