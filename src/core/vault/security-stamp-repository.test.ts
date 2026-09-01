import { describe, expect, it, vi } from 'vitest';
import type { KeyValueStore } from '../../platform/store.js';
import {
  MAX_SECURITY_STAMP_BASELINES,
  SECURITY_STAMP_SCHEMA_VERSION,
  SECURITY_STAMP_STORAGE_KEY,
  SecurityStampRepository,
  type SecurityStampScope,
} from './security-stamp-repository.js';

interface MemoryStore {
  readonly store: Pick<KeyValueStore, 'get' | 'set' | 'remove'>;
  readonly values: Map<string, unknown>;
  readonly get: ReturnType<typeof vi.fn>;
  readonly set: ReturnType<typeof vi.fn>;
  readonly remove: ReturnType<typeof vi.fn>;
}

function memoryStore(initial?: unknown): MemoryStore {
  const values = new Map<string, unknown>();
  if (initial !== undefined) values.set(SECURITY_STAMP_STORAGE_KEY, structuredClone(initial));
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
  return {
    values,
    get,
    set,
    remove,
    store: {
      get: <T>(key: string) => get(key) as Promise<T | undefined>,
      set,
      remove,
    },
  };
}

const SCOPE_A: SecurityStampScope = Object.freeze({
  serverUrl: 'https://vault.example/',
  profileId: 'profile-a',
  credentialId: 'credential-a',
});

function repository(memory: MemoryStore, prefix = 'revision') {
  let sequence = 0;
  return new SecurityStampRepository({
    store: memory.store,
    createRevision: () => `${prefix}-${++sequence}`,
  });
}

function compare(
  value: SecurityStampRepository,
  scope: SecurityStampScope,
  stamp: string | undefined,
  initialize = true,
  retainedCredentialIds: readonly string[] = [scope.credentialId],
) {
  return value.compareAndSet(scope, stamp, {
    initialize,
    retainedCredentialIds,
    assertCurrent: async () => {},
  });
}

describe('SecurityStampRepository', () => {
  it('durably initializes the first stamp and matches it without another write', async () => {
    const memory = memoryStore();
    const stamps = repository(memory);

    await expect(compare(stamps, SCOPE_A, 'stamp-a')).resolves.toEqual({ status: 'initialized' });
    await expect(compare(stamps, SCOPE_A, 'stamp-a')).resolves.toEqual({ status: 'matched' });

    expect(memory.set).toHaveBeenCalledOnce();
    expect(memory.values.get(SECURITY_STAMP_STORAGE_KEY)).toEqual({
      schemaVersion: SECURITY_STAMP_SCHEMA_VERSION,
      revision: 'revision-1',
      baselines: [{ ...SCOPE_A, securityStamp: 'stamp-a' }],
    });
  });

  it('keeps an existing baseline immutable on changed or missing stamps', async () => {
    const memory = memoryStore();
    const stamps = repository(memory);
    await compare(stamps, SCOPE_A, 'stamp-a');
    const before = structuredClone(memory.values.get(SECURITY_STAMP_STORAGE_KEY));

    await expect(compare(stamps, SCOPE_A, 'stamp-b')).resolves.toEqual({
      status: 'mismatch', reason: 'stamp_changed',
    });
    await expect(compare(stamps, SCOPE_A, undefined)).resolves.toEqual({
      status: 'mismatch', reason: 'stamp_missing',
    });

    expect(memory.values.get(SECURITY_STAMP_STORAGE_KEY)).toEqual(before);
    expect(memory.set).toHaveBeenCalledOnce();
  });

  it('allows a first missing stamp for old servers without creating storage', async () => {
    const memory = memoryStore();
    const stamps = repository(memory);

    await expect(compare(stamps, SCOPE_A, undefined)).resolves.toEqual({
      status: 'compatible_missing',
    });
    expect(memory.values.has(SECURITY_STAMP_STORAGE_KEY)).toBe(false);
    expect(memory.set).not.toHaveBeenCalled();
  });

  it('does not initialize a fresh credential from an old raw-cache stamp', async () => {
    const memory = memoryStore();
    const stamps = repository(memory);

    await expect(compare(stamps, SCOPE_A, 'old-cache-stamp', false)).resolves.toEqual({
      status: 'uninitialized',
    });
    expect(memory.set).not.toHaveBeenCalled();
  });

  it('binds one immutable profile id to a server credential', async () => {
    const memory = memoryStore();
    const stamps = repository(memory);
    await compare(stamps, SCOPE_A, 'stamp-a');

    await expect(compare(stamps, { ...SCOPE_A, profileId: 'profile-b' }, 'stamp-a'))
      .resolves.toEqual({ status: 'mismatch', reason: 'profile_changed' });
    expect(memory.set).toHaveBeenCalledOnce();
  });

  it('accepts a legitimate re-login under a new credential and retires its old baseline', async () => {
    const memory = memoryStore();
    const stamps = repository(memory);
    await compare(stamps, SCOPE_A, 'old-stamp');
    const nextScope = { ...SCOPE_A, credentialId: 'credential-new' };

    await expect(compare(stamps, nextScope, 'new-stamp')).resolves.toEqual({ status: 'initialized' });
    await expect(compare(stamps, nextScope, 'new-stamp')).resolves.toEqual({ status: 'matched' });
    expect(memory.values.get(SECURITY_STAMP_STORAGE_KEY)).toMatchObject({
      baselines: [{ ...nextScope, securityStamp: 'new-stamp' }],
    });
  });

  it('does not replace another still-retained credential bound to the same profile', async () => {
    const memory = memoryStore();
    const stamps = repository(memory);
    await compare(stamps, SCOPE_A, 'stamp-a');
    const competing = { ...SCOPE_A, credentialId: 'credential-b' };

    await expect(compare(
      stamps,
      competing,
      'stamp-b',
      true,
      [SCOPE_A.credentialId, competing.credentialId],
    )).resolves.toEqual({ status: 'mismatch', reason: 'profile_changed' });
    expect(memory.set).toHaveBeenCalledOnce();
  });

  it('preserves distinct accounts across an A-B-A switch', async () => {
    const memory = memoryStore();
    const stamps = repository(memory);
    const scopeB = {
      serverUrl: SCOPE_A.serverUrl,
      profileId: 'profile-b',
      credentialId: 'credential-b',
    };

    await compare(stamps, SCOPE_A, 'stamp-a');
    await compare(stamps, scopeB, 'stamp-b', true, [SCOPE_A.credentialId, scopeB.credentialId]);
    await expect(compare(stamps, SCOPE_A, 'stamp-a')).resolves.toEqual({ status: 'matched' });
    expect((memory.values.get(SECURITY_STAMP_STORAGE_KEY) as { baselines: unknown[] }).baselines)
      .toHaveLength(2);
  });

  it('persists across repository instances that model a worker restart', async () => {
    const memory = memoryStore();
    await compare(repository(memory, 'first'), SCOPE_A, 'stamp-a');

    await expect(compare(repository(memory, 'restart'), SCOPE_A, 'stamp-a'))
      .resolves.toEqual({ status: 'matched' });
    expect(memory.set).toHaveBeenCalledOnce();
  });

  it('clears opaque baseline state only through the explicit reset operation', async () => {
    const memory = memoryStore();
    const stamps = repository(memory);
    await compare(stamps, SCOPE_A, 'stamp-a');

    await stamps.clear();

    expect(memory.remove).toHaveBeenCalledWith(SECURITY_STAMP_STORAGE_KEY);
    expect(memory.values.has(SECURITY_STAMP_STORAGE_KEY)).toBe(false);
  });

  it('does not report an unconfirmed explicit reset as successful', async () => {
    const memory = memoryStore();
    const stamps = repository(memory);
    await compare(stamps, SCOPE_A, 'stamp-a');
    memory.remove.mockImplementationOnce(async () => {});

    await expect(stamps.clear()).rejects.toMatchObject({ code: 'write_unconfirmed' });
    expect(memory.values.has(SECURITY_STAMP_STORAGE_KEY)).toBe(true);
  });

  it('serializes compare-and-set across repository instances sharing one storage area', async () => {
    const memory = memoryStore();
    const first = repository(memory, 'first');
    const second = repository(memory, 'second');
    let releaseFirst!: () => void;
    const firstWriteGate = new Promise<void>((resolve) => { releaseFirst = resolve; });
    let firstStarted!: () => void;
    const firstStartedGate = new Promise<void>((resolve) => { firstStarted = resolve; });
    memory.set.mockImplementationOnce(async (key: string, value: unknown) => {
      firstStarted();
      await firstWriteGate;
      memory.values.set(key, structuredClone(value));
    });

    const initialize = compare(first, SCOPE_A, 'stamp-a');
    await firstStartedGate;
    const competing = compare(second, SCOPE_A, 'stamp-b');
    releaseFirst();

    await expect(initialize).resolves.toEqual({ status: 'initialized' });
    await expect(competing).resolves.toEqual({ status: 'mismatch', reason: 'stamp_changed' });
    expect(memory.values.get(SECURITY_STAMP_STORAGE_KEY)).toMatchObject({
      baselines: [{ securityStamp: 'stamp-a' }],
    });
  });

  it('rolls back its own revision when authority changes after the write', async () => {
    const memory = memoryStore();
    const stamps = repository(memory);
    let current = true;
    memory.set.mockImplementationOnce(async (key: string, value: unknown) => {
      memory.values.set(key, structuredClone(value));
      current = false;
    });

    await expect(stamps.compareAndSet(SCOPE_A, 'stamp-a', {
      initialize: true,
      retainedCredentialIds: [SCOPE_A.credentialId],
      assertCurrent: async () => {
        if (!current) throw new Error('stale authority');
      },
    })).rejects.toThrow('stale authority');
    expect(memory.values.has(SECURITY_STAMP_STORAGE_KEY)).toBe(false);
  });

  it('never reports an unpersisted baseline as initialized', async () => {
    const memory = memoryStore();
    const stamps = repository(memory);
    memory.set.mockImplementationOnce(async () => { throw new Error('storage write failed'); });

    await expect(compare(stamps, SCOPE_A, 'stamp-a')).rejects.toThrow('storage write failed');
    expect(memory.values.has(SECURITY_STAMP_STORAGE_KEY)).toBe(false);
  });

  it.each([
    null,
    {},
    { schemaVersion: 1, revision: 'r', baselines: [], extra: true },
    { schemaVersion: 1, revision: 'r', baselines: [] },
    { schemaVersion: 1, revision: 'r', baselines: [{ ...SCOPE_A, securityStamp: '' }] },
    {
      schemaVersion: 1,
      revision: 'r',
      baselines: [{ ...SCOPE_A, serverUrl: 'https://vault.example', securityStamp: 'a' }],
    },
    {
      schemaVersion: 1,
      revision: 'r',
      baselines: [
        { ...SCOPE_A, securityStamp: 'a' },
        { ...SCOPE_A, profileId: 'profile-b', securityStamp: 'b' },
      ],
    },
  ])('fails closed without replacing a corrupt envelope: %j', async (raw) => {
    const memory = memoryStore(raw);

    await expect(compare(repository(memory), SCOPE_A, 'stamp-a')).rejects.toMatchObject({
      code: 'corrupt_envelope',
    });
    expect(memory.values.get(SECURITY_STAMP_STORAGE_KEY)).toEqual(raw);
    expect(memory.set).not.toHaveBeenCalled();
  });

  it('rejects a non-canonical but equivalent caller server URL before reading storage', async () => {
    const memory = memoryStore();

    expect(() => compare(
      repository(memory),
      { ...SCOPE_A, serverUrl: 'HTTPS://VAULT.EXAMPLE/' },
      'stamp-a',
    )).toThrowError(expect.objectContaining({ code: 'invalid_scope' }));
    expect(memory.get).not.toHaveBeenCalled();
  });

  it('fails closed without replacing a future schema', async () => {
    const raw = { schemaVersion: 2, revision: 'future', baselines: [] };
    const memory = memoryStore(raw);

    await expect(compare(repository(memory), SCOPE_A, 'stamp-a')).rejects.toMatchObject({
      code: 'unsupported_schema',
    });
    expect(memory.values.get(SECURITY_STAMP_STORAGE_KEY)).toEqual(raw);
  });

  it('reconciles stale historical scopes before enforcing the durable capacity bound', async () => {
    const baselines = Array.from({ length: MAX_SECURITY_STAMP_BASELINES }, (_, index) => ({
      serverUrl: `https://vault-${index}.example/`,
      profileId: `profile-${index}`,
      credentialId: `credential-${index}`,
      securityStamp: `stamp-${index}`,
    }));
    const raw = { schemaVersion: 1, revision: 'full', baselines };
    const memory = memoryStore(raw);

    await expect(compare(repository(memory), SCOPE_A, 'stamp-a')).resolves.toEqual({
      status: 'initialized',
    });
    expect(memory.values.get(SECURITY_STAMP_STORAGE_KEY)).toMatchObject({
      baselines: [{ ...SCOPE_A, securityStamp: 'stamp-a' }],
    });
  });
});
