import { describe, expect, it, vi } from 'vitest';
import { AccountLeaseGate, type AccountLease } from '../core/session/account-gate.js';
import type { KeyValueStore } from '../platform/store.js';
import {
  ACCOUNT_SETTINGS_SCHEMA_VERSION,
  ACCOUNT_SETTINGS_STORAGE_KEY,
  AccountSettingsRepository,
  MAX_ACCOUNT_SETTINGS_ACCOUNTS,
  type AccountSettingsRecords,
} from './account-settings-repository.js';

const SERVER_A = 'https://vault.example/';
const SERVER_B = 'https://other.example/base/';

interface TestRecord {
  readonly schemaVersion: 1;
  readonly value: string;
}

type TestRecords = AccountSettingsRecords<TestRecord, TestRecord, TestRecord>;

function record(value: string): TestRecord {
  return Object.freeze({ schemaVersion: 1, value });
}

function records(tag: string): TestRecords {
  return {
    autofill: record(`autofill-${tag}`),
    websitePasskey: record(`passkey-${tag}`),
    httpAuth: record(`http-${tag}`),
  };
}

function parseRecord(value: unknown): TestRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('invalid record');
  const candidate = value as Record<string, unknown>;
  if (Object.keys(candidate).length !== 2
    || candidate.schemaVersion !== 1 || typeof candidate.value !== 'string') {
    throw new Error('invalid record');
  }
  return record(candidate.value);
}

function canonicalizeServerUrl(value: string): string {
  const url = new URL(value);
  if (!url.pathname.endsWith('/')) url.pathname += '/';
  return url.toString();
}

function scopeKey(serverUrl: string, email: string): string {
  return JSON.stringify([canonicalizeServerUrl(serverUrl), email.trim().toLowerCase()]);
}

interface MemoryStore {
  readonly store: Pick<KeyValueStore, 'get' | 'set' | 'remove'>;
  readonly values: Map<string, unknown>;
  readonly get: ReturnType<typeof vi.fn>;
  readonly set: ReturnType<typeof vi.fn>;
  readonly remove: ReturnType<typeof vi.fn>;
}

function memoryStore(initial?: unknown): MemoryStore {
  const values = new Map<string, unknown>();
  if (initial !== undefined) values.set(ACCOUNT_SETTINGS_STORAGE_KEY, structuredClone(initial));
  const get = vi.fn(async <T>(key: string): Promise<T | undefined> => {
    const value = values.get(key);
    await Promise.resolve();
    return value === undefined ? undefined : structuredClone(value) as T;
  });
  const set = vi.fn(async (key: string, value: unknown): Promise<void> => {
    await Promise.resolve();
    values.set(key, structuredClone(value));
  });
  const remove = vi.fn(async (key: string): Promise<void> => {
    await Promise.resolve();
    values.delete(key);
  });
  const store: Pick<KeyValueStore, 'get' | 'set' | 'remove'> = {
    get: <T>(key: string) => get(key) as Promise<T | undefined>,
    set,
    remove,
  };
  return { values, get, set, remove, store };
}

function repository(
  memory: MemoryStore,
  assertLease: (lease: AccountLease) => void,
): AccountSettingsRepository<TestRecord, TestRecord, TestRecord> {
  return new AccountSettingsRepository({
    store: memory.store,
    parsers: {
      autofill: parseRecord,
      websitePasskey: parseRecord,
      httpAuth: parseRecord,
    },
    canonicalizeServerUrl,
    assertLease,
  });
}

function gate(serverUrl = SERVER_A, email = 'alice@example.com'): AccountLeaseGate {
  const value = new AccountLeaseGate();
  value.initialize({ serverUrl, accountIdentity: email });
  return value;
}

function switchAccount(value: AccountLeaseGate, serverUrl: string, email: string): AccountLease {
  const transition = value.beginAccountTransition();
  value.endAccountTransition(transition, { serverUrl, accountIdentity: email });
  return value.capture();
}

function switchServer(value: AccountLeaseGate, serverUrl: string, email: string): AccountLease {
  const transition = value.beginServerTransition();
  value.endServerTransition(transition, { serverUrl, accountIdentity: email });
  return value.capture();
}

describe('AccountSettingsRepository', () => {
  it('stores one parser-validated record under the canonical server and normalized email scope', async () => {
    const memory = memoryStore();
    const accountGate = gate('https://vault.example', ' Alice@Example.COM ');
    const settings = repository(memory, (lease) => accountGate.assert(lease));
    const lease = accountGate.capture();

    await expect(settings.read(lease)).resolves.toBeUndefined();
    await expect(settings.update(lease, () => records('alice'))).resolves.toEqual(records('alice'));
    await expect(settings.read(lease)).resolves.toEqual(records('alice'));

    const stored = memory.values.get(ACCOUNT_SETTINGS_STORAGE_KEY) as {
      schemaVersion: number;
      accounts: Record<string, unknown>;
    };
    expect(stored.schemaVersion).toBe(ACCOUNT_SETTINGS_SCHEMA_VERSION);
    expect(Object.keys(stored.accounts)).toEqual([
      scopeKey(SERVER_A, 'alice@example.com'),
    ]);
    expect(stored.accounts[scopeKey(SERVER_A, 'alice@example.com')]).toMatchObject({
      serverUrl: SERVER_A,
      email: 'alice@example.com',
      ...records('alice'),
    });
  });

  it('isolates accounts and same-email identities on different canonical servers', async () => {
    const memory = memoryStore();
    const accountGate = gate();
    const settings = repository(memory, (lease) => accountGate.assert(lease));
    const aliceA = accountGate.capture();
    await settings.update(aliceA, () => records('alice-a'));

    const bobA = switchAccount(accountGate, SERVER_A, 'bob@example.com');
    await settings.update(bobA, () => records('bob-a'));
    const aliceB = switchServer(accountGate, SERVER_B, 'alice@example.com');
    await settings.update(aliceB, () => records('alice-b'));

    expect(await settings.read(aliceB)).toEqual(records('alice-b'));
    const bobAgain = switchServer(accountGate, SERVER_A, 'bob@example.com');
    expect(await settings.read(bobAgain)).toEqual(records('bob-a'));
    const aliceAgain = switchAccount(accountGate, SERVER_A, 'alice@example.com');
    expect(await settings.read(aliceAgain)).toEqual(records('alice-a'));
  });

  it('serializes all reads and updates so concurrent read-modify-write operations do not lose data', async () => {
    const memory = memoryStore();
    const lease = {
      serverGeneration: 0,
      accountGeneration: 0,
      serverUrl: SERVER_A,
      accountIdentity: 'alice@example.com',
    } as AccountLease;
    const settings = repository(memory, () => undefined);

    const first = settings.update(lease, () => records('one'));
    const second = settings.update(lease, (current) => ({
      ...current!,
      websitePasskey: record('passkey-two'),
    }));
    const read = settings.read(lease);

    await expect(first).resolves.toEqual(records('one'));
    await expect(second).resolves.toEqual({
      ...records('one'),
      websitePasskey: record('passkey-two'),
    });
    await expect(read).resolves.toEqual({
      ...records('one'),
      websitePasskey: record('passkey-two'),
    });
  });

  it('uses one FIFO across scopes so concurrent account creation cannot overwrite a peer', async () => {
    const memory = memoryStore();
    const settings = repository(memory, () => undefined);
    const alice = {
      serverGeneration: 0,
      accountGeneration: 0,
      serverUrl: SERVER_A,
      accountIdentity: 'alice@example.com',
    } as AccountLease;
    const bob = {
      serverGeneration: 0,
      accountGeneration: 0,
      serverUrl: SERVER_A,
      accountIdentity: 'bob@example.com',
    } as AccountLease;

    await Promise.all([
      settings.update(alice, () => records('alice')),
      settings.update(bob, () => records('bob')),
    ]);

    await expect(settings.read(alice)).resolves.toEqual(records('alice'));
    await expect(settings.read(bob)).resolves.toEqual(records('bob'));
    const stored = memory.values.get(ACCOUNT_SETTINGS_STORAGE_KEY) as { accounts: object };
    expect(Object.keys(stored.accounts)).toHaveLength(2);
  });

  it(`rejects a sixth scope while preserving the first ${MAX_ACCOUNT_SETTINGS_ACCOUNTS}`, async () => {
    const memory = memoryStore();
    const accountGate = gate();
    const settings = repository(memory, (lease) => accountGate.assert(lease));
    let lease = accountGate.capture();

    for (let index = 0; index < MAX_ACCOUNT_SETTINGS_ACCOUNTS; index += 1) {
      if (index > 0) lease = switchAccount(accountGate, SERVER_A, `user-${index}@example.com`);
      await settings.update(lease, () => records(String(index)));
    }
    const sixth = switchAccount(accountGate, SERVER_A, 'sixth@example.com');

    await expect(settings.update(sixth, () => records('sixth'))).rejects.toMatchObject({
      code: 'capacity',
    });
    const stored = memory.values.get(ACCOUNT_SETTINGS_STORAGE_KEY) as { accounts: object };
    expect(Object.keys(stored.accounts)).toHaveLength(MAX_ACCOUNT_SETTINGS_ACCOUNTS);
  });

  it.each([
    null,
    {},
    { schemaVersion: 1, accounts: {}, extra: true },
    { schemaVersion: 1, accounts: [] },
    { schemaVersion: 1, accounts: { notCanonical: {} } },
  ])('fails closed without replacing a malformed root envelope: %j', async (raw) => {
    const memory = memoryStore(raw);
    const accountGate = gate();
    const settings = repository(memory, (lease) => accountGate.assert(lease));
    const lease = accountGate.capture();

    await expect(settings.read(lease)).rejects.toMatchObject({ code: 'corrupt_envelope' });
    await expect(settings.update(lease, () => records('next'))).rejects.toMatchObject({
      code: 'corrupt_envelope',
    });
    expect(memory.values.get(ACCOUNT_SETTINGS_STORAGE_KEY)).toEqual(raw);
    expect(memory.set).not.toHaveBeenCalled();
  });

  it('fails closed without replacing a future envelope schema', async () => {
    const raw = { schemaVersion: 2, accounts: {} };
    const memory = memoryStore(raw);
    const accountGate = gate();
    const settings = repository(memory, (lease) => accountGate.assert(lease));

    await expect(settings.read(accountGate.capture())).rejects.toMatchObject({
      code: 'unsupported_schema',
    });
    expect(memory.values.get(ACCOUNT_SETTINGS_STORAGE_KEY)).toEqual(raw);
  });

  it('contains unknown fields and parser failures to their own scope', async () => {
    const memory = memoryStore();
    const accountGate = gate();
    const settings = repository(memory, (lease) => accountGate.assert(lease));
    const alice = accountGate.capture();
    await settings.update(alice, () => records('alice'));
    const bob = switchAccount(accountGate, SERVER_A, 'bob@example.com');
    await settings.update(bob, () => records('bob'));

    const envelope = memory.values.get(ACCOUNT_SETTINGS_STORAGE_KEY) as {
      schemaVersion: 1;
      accounts: Record<string, Record<string, unknown>>;
    };
    envelope.accounts[scopeKey(SERVER_A, 'alice@example.com')]!.extra = true;
    memory.values.set(ACCOUNT_SETTINGS_STORAGE_KEY, envelope);

    await expect(settings.read(bob)).resolves.toEqual(records('bob'));
    await expect(settings.update(bob, (current) => ({
      ...current!,
      httpAuth: record('http-bob-updated'),
    }))).resolves.toMatchObject({ httpAuth: record('http-bob-updated') });

    const aliceAgain = switchAccount(accountGate, SERVER_A, 'alice@example.com');
    await expect(settings.read(aliceAgain)).rejects.toMatchObject({ code: 'scope_unavailable' });

    const rawAfterUnknownField = memory.values.get(ACCOUNT_SETTINGS_STORAGE_KEY) as {
      accounts: Record<string, Record<string, unknown>>;
    };
    delete rawAfterUnknownField.accounts[scopeKey(SERVER_A, 'alice@example.com')]!.extra;
    rawAfterUnknownField.accounts[scopeKey(SERVER_A, 'alice@example.com')]!.autofill = {
      schemaVersion: 1,
      value: 42,
    };
    memory.values.set(ACCOUNT_SETTINGS_STORAGE_KEY, rawAfterUnknownField);

    await expect(settings.read(aliceAgain)).rejects.toMatchObject({ code: 'scope_unavailable' });
    const bobAgain = switchAccount(accountGate, SERVER_A, 'bob@example.com');
    await expect(settings.read(bobAgain)).resolves.toMatchObject({
      httpAuth: record('http-bob-updated'),
    });
  });

  it('rejects invalid complete update records before storage is changed', async () => {
    const memory = memoryStore();
    const accountGate = gate();
    const settings = repository(memory, (lease) => accountGate.assert(lease));

    await expect(settings.update(accountGate.capture(), () => ({
      ...records('bad'),
      autofill: { schemaVersion: 1, value: 1 } as never,
    }))).rejects.toMatchObject({ code: 'invalid_records' });
    expect(memory.set).not.toHaveBeenCalled();
    expect(memory.values.has(ACCOUNT_SETTINGS_STORAGE_KEY)).toBe(false);
  });

  it('rejects a read when its lease changes while storage is awaited', async () => {
    const memory = memoryStore();
    const accountGate = gate();
    const settings = repository(memory, (lease) => accountGate.assert(lease));
    const alice = accountGate.capture();
    let markReadStarted!: () => void;
    const readStarted = new Promise<void>((resolve) => { markReadStarted = resolve; });
    let releaseRead!: () => void;
    const readGate = new Promise<void>((resolve) => { releaseRead = resolve; });
    memory.get.mockImplementationOnce(async () => {
      markReadStarted();
      await readGate;
      return undefined;
    });

    const pending = settings.read(alice);
    await readStarted;
    switchAccount(accountGate, SERVER_A, 'bob@example.com');
    releaseRead();

    await expect(pending).rejects.toMatchObject({ code: 'session_expired' });
    expect(memory.set).not.toHaveBeenCalled();
  });

  it('rejects caller-captured leases across an A-B-A sequence before queued work can run', async () => {
    const memory = memoryStore();
    const accountGate = gate();
    const settings = repository(memory, (lease) => accountGate.assert(lease));
    const originalAlice = accountGate.capture();
    let releaseRead!: () => void;
    const readGate = new Promise<void>((resolve) => { releaseRead = resolve; });
    memory.get.mockImplementationOnce(async () => {
      await readGate;
      return undefined;
    });

    const first = settings.read(originalAlice);
    const queued = settings.update(originalAlice, () => records('stale'));
    switchAccount(accountGate, SERVER_A, 'bob@example.com');
    switchAccount(accountGate, SERVER_A, 'alice@example.com');
    releaseRead();

    await expect(first).rejects.toMatchObject({ code: 'session_expired' });
    await expect(queued).rejects.toMatchObject({ code: 'session_expired' });
    expect(memory.set).not.toHaveBeenCalled();
  });

  it('rolls back inside the FIFO when an A-B-A transition invalidates the lease after commit', async () => {
    const memory = memoryStore();
    const accountGate = gate();
    const settings = repository(memory, (lease) => accountGate.assert(lease));
    const originalLease = accountGate.capture();
    await settings.update(originalLease, () => records('old'));
    const before = structuredClone(memory.values.get(ACCOUNT_SETTINGS_STORAGE_KEY));

    memory.set.mockImplementationOnce(async (key: string, value: unknown) => {
      memory.values.set(key, structuredClone(value));
      switchAccount(accountGate, SERVER_A, 'bob@example.com');
      switchAccount(accountGate, SERVER_A, 'alice@example.com');
    });

    await expect(settings.update(originalLease, () => records('stale'))).rejects.toMatchObject({
      code: 'session_expired',
    });
    expect(memory.values.get(ACCOUNT_SETTINGS_STORAGE_KEY)).toEqual(before);
    await expect(settings.read(accountGate.capture())).resolves.toEqual(records('old'));
  });

  it('rolls back a rejected storage write and leaves the scope readable', async () => {
    const memory = memoryStore();
    const accountGate = gate();
    const settings = repository(memory, (lease) => accountGate.assert(lease));
    const lease = accountGate.capture();
    await settings.update(lease, () => records('old'));
    const before = structuredClone(memory.values.get(ACCOUNT_SETTINGS_STORAGE_KEY));
    memory.set.mockImplementationOnce(async () => { throw new Error('write failed'); });

    await expect(settings.update(lease, () => records('new'))).rejects.toThrow('write failed');
    expect(memory.values.get(ACCOUNT_SETTINGS_STORAGE_KEY)).toEqual(before);
    await expect(settings.read(lease)).resolves.toEqual(records('old'));
  });

  it('marks only the affected scope unavailable when rollback fails', async () => {
    const memory = memoryStore();
    const accountGate = gate();
    const settings = repository(memory, (lease) => accountGate.assert(lease));
    let lease = accountGate.capture();
    await settings.update(lease, () => records('alice'));
    lease = switchAccount(accountGate, SERVER_A, 'bob@example.com');
    await settings.update(lease, () => records('bob'));
    lease = switchAccount(accountGate, SERVER_A, 'alice@example.com');

    memory.set
      .mockImplementationOnce(async (key: string, value: unknown) => {
        memory.values.set(key, structuredClone(value));
        switchAccount(accountGate, SERVER_A, 'bob@example.com');
      })
      .mockImplementationOnce(async () => { throw new Error('rollback failed'); });

    await expect(settings.update(lease, () => records('uncertain'))).rejects.toMatchObject({
      code: 'rollback_failed',
    });
    await expect(settings.read(accountGate.capture())).resolves.toEqual(records('bob'));

    const aliceAgain = switchAccount(accountGate, SERVER_A, 'alice@example.com');
    const getCallsBefore = memory.get.mock.calls.length;
    await expect(settings.read(aliceAgain)).rejects.toMatchObject({ code: 'scope_unavailable' });
    expect(memory.get).toHaveBeenCalledTimes(getCallsBefore);
  });

  it('checks the supplied lease synchronously before accepting work', () => {
    const memory = memoryStore();
    const accountGate = gate();
    const settings = repository(memory, (lease) => accountGate.assert(lease));
    const stale = accountGate.capture();
    switchAccount(accountGate, SERVER_A, 'bob@example.com');
    switchAccount(accountGate, SERVER_A, 'alice@example.com');

    expect(() => settings.read(stale)).toThrowError(expect.objectContaining({ code: 'session_expired' }));
    expect(() => settings.update(stale, () => records('stale')))
      .toThrowError(expect.objectContaining({ code: 'session_expired' }));
    expect(memory.get).not.toHaveBeenCalled();
  });
});
