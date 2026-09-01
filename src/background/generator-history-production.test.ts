import { describe, expect, it } from 'vitest';
import type { GeneratorHistoryCrypto } from '../core/generator/history-crypto.js';
import type { SymmetricKey } from '../core/crypto/keys.js';
import type { KeyValueStore } from '../platform/store.js';
import {
  recoverPendingRotationOnStartup,
  RotationPendingStore,
} from '../core/session/rotation-pending-store.js';
import {
  createGeneratorHistoryAuthorityProvider,
  GENERATOR_HISTORY_SCOPE_INDEX_KEY,
  GeneratorHistoryProductionService,
  MAX_GENERATOR_HISTORY_SCOPE_INDEX_ENTRIES,
  type GeneratorHistoryAuthority,
} from './generator-history-production.js';

const SERVER_A = 'https://vault-a.example/tenant/';
const SERVER_B = 'https://vault-b.example/';
const EMAIL_A = 'alice@example.com';
const EMAIL_B = 'bob@example.com';
const EMAIL_C = 'carol@example.com';
const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '22222222-2222-4222-8222-222222222222';
const USER_C = '33333333-3333-4333-8333-333333333333';

interface InspectableStore extends KeyValueStore {
  readonly keys: () => string[];
  readonly raw: (key: string) => unknown;
  readonly serialized: () => string;
}

function createStore(): InspectableStore {
  const values = new Map<string, string>();
  return {
    async get<Value>(key: string): Promise<Value | undefined> {
      const value = values.get(key);
      return value === undefined ? undefined : JSON.parse(value) as Value;
    },
    async set(key, value) { values.set(key, JSON.stringify(value)); },
    async setMany(entries) {
      for (const [key, value] of Object.entries(entries)) values.set(key, JSON.stringify(value));
    },
    async remove(key) { values.delete(key); },
    async clear() { values.clear(); },
    keys: () => [...values.keys()].sort(),
    raw: (key) => {
      const value = values.get(key);
      return value === undefined ? undefined : JSON.parse(value) as unknown;
    },
    serialized: () => JSON.stringify([...values.entries()]),
  };
}

interface OpaqueCrypto extends GeneratorHistoryCrypto {
  onEncrypt: (() => void) | undefined;
}

function createOpaqueCrypto(): OpaqueCrypto {
  let sequence = 0;
  const records = new Map<string, { scope: string; bytes: Uint8Array }>();
  return {
    onEncrypt: undefined,
    async encrypt(scope, plaintext) {
      const token = `ciphertext-${++sequence}`;
      records.set(token, { scope, bytes: plaintext.slice() });
      this.onEncrypt?.();
      return token;
    },
    async decrypt(scope, ciphertext) {
      const record = records.get(ciphertext);
      if (!record || record.scope !== scope) throw new Error('bad ciphertext');
      return record.bytes.slice();
    },
  };
}

interface AuthorityState {
  readonly serverUrl: string;
  readonly accountIdentity: string;
  readonly userId: string;
  readonly policyRevision: number;
  readonly crypto: OpaqueCrypto;
}

function authorityState(overrides: Partial<AuthorityState> = {}): AuthorityState {
  return {
    serverUrl: SERVER_A,
    accountIdentity: EMAIL_A,
    userId: USER_A,
    policyRevision: 7,
    crypto: createOpaqueCrypto(),
    ...overrides,
  };
}

function createAuthorityHarness(initial: AuthorityState) {
  let current = initial;
  let generation = 0;
  return {
    withCurrentAuthority: async <Result>(
      operation: (authority: GeneratorHistoryAuthority) => Promise<Result>,
    ): Promise<Result> => {
      const captured = generation;
      const state = current;
      const assertCurrent = (): void => {
        if (captured !== generation || state !== current) throw new Error('authority changed');
      };
      return operation(Object.freeze({ ...state, assertCurrent }));
    },
    switchTo(next: AuthorityState): void {
      current = next;
      generation += 1;
    },
    bounce(first: AuthorityState, second: AuthorityState): void {
      current = first;
      generation += 1;
      current = second;
      generation += 1;
    },
    get current(): AuthorityState { return current; },
  };
}

function revisionFactory(): () => string {
  let sequence = 0;
  return () => `00000000-0000-4000-8000-${(++sequence).toString(16).padStart(12, '0')}`;
}

function createService(store: Pick<KeyValueStore, 'get' | 'set' | 'remove'>, harness: ReturnType<typeof createAuthorityHarness>) {
  return new GeneratorHistoryProductionService({
    store,
    withCurrentAuthority: harness.withCurrentAuthority,
    createIndexRevision: revisionFactory(),
  });
}

async function createSharedRollbackFailure() {
  const backing = createStore();
  const accountA = authorityState();
  const accountB = authorityState({ accountIdentity: EMAIL_B, userId: USER_B });
  const firstHarness = createAuthorityHarness(accountA);
  const secondHarness = createAuthorityHarness(accountA);
  let bounce = true;
  let failRollbackRemove = true;
  const store: Pick<KeyValueStore, 'get' | 'set' | 'remove'> = {
    get: (key) => backing.get(key),
    async set(key, value) {
      await backing.set(key, value);
      if (key.startsWith('generatorHistory.v1.') && bounce) {
        bounce = false;
        firstHarness.bounce(accountB, accountA);
      }
    },
    async remove(key) {
      if (key.startsWith('generatorHistory.v1.') && failRollbackRemove) {
        failRollbackRemove = false;
        throw new Error('history rollback remove failed');
      }
      await backing.remove(key);
    },
  };
  const revisions = revisionFactory();
  const first = new GeneratorHistoryProductionService({
    store, withCurrentAuthority: firstHarness.withCurrentAuthority, createIndexRevision: revisions,
  });
  const second = new GeneratorHistoryProductionService({
    store, withCurrentAuthority: secondHarness.withCurrentAuthority, createIndexRevision: revisions,
  });
  let failure: unknown;
  try {
    await first.track({ value: 'outcome-unknown', type: 'password', policyRevision: 7 });
  } catch (error) {
    failure = error;
  }
  return { backing, failure, second };
}

describe('generator history production authority and persistence', () => {
  it('fences authority awaits and clears both loaded and provider-owned UserKey copies', async () => {
    let generation = 1;
    const loaded = {
      encKey: new Uint8Array(32).fill(17),
      macKey: new Uint8Array(32).fill(29),
    };
    let retainedOwnedKey: SymmetricKey | undefined;
    const withCurrentAuthority = createGeneratorHistoryAuthorityProvider({
      captureSecurity: () => ({
        sessionLease: generation,
        accountLease: generation,
        policyLease: generation,
        serverUrl: SERVER_A,
        accountIdentity: EMAIL_A,
        policyRevision: 7,
      }),
      assertSecurity: (binding) => {
        if (binding.sessionLease !== generation
          || binding.accountLease !== generation
          || binding.policyLease !== generation) throw new Error('lease changed');
      },
      captureIdentity: async () => ({
        serverUrl: SERVER_A, accountIdentity: EMAIL_A, userId: USER_A,
      }),
      loadUserKey: async () => loaded,
      createCrypto: (owned) => {
        retainedOwnedKey = owned;
        return createOpaqueCrypto();
      },
    });

    await expect(withCurrentAuthority(async (authority) => {
      expect(authority).toMatchObject({
        serverUrl: SERVER_A,
        accountIdentity: EMAIL_A,
        userId: USER_A,
        policyRevision: 7,
      });
      generation += 1;
      await Promise.resolve();
      return 'unreachable';
    })).rejects.toThrow('lease changed');

    expect([...loaded.encKey, ...loaded.macKey].every((byte) => byte === 0)).toBe(true);
    expect(retainedOwnedKey).toBeDefined();
    expect([...retainedOwnedKey!.encKey, ...retainedOwnedKey!.macKey].every((byte) => byte === 0))
      .toBe(true);
  });

  it('binds listed plaintext to a final authority assertion without retaining crypto', async () => {
    const store = createStore();
    const first = authorityState();
    const harness = createAuthorityHarness(first);
    const service = createService(store, harness);
    await service.track({ value: 'release-secret', type: 'password', policyRevision: 7 });
    let finalAssert: (() => void) | undefined;

    await expect(service.list((assertCurrent) => { finalAssert = assertCurrent; }))
      .resolves.toMatchObject({ entries: [{ value: 'release-secret' }] });
    expect(finalAssert).toBeTypeOf('function');
    harness.switchTo(authorityState({ accountIdentity: EMAIL_B, userId: USER_B }));
    expect(() => finalAssert!()).toThrow('authority changed');
  });

  it('tracks and lists only public entry data while persisting no plaintext credential', async () => {
    const store = createStore();
    const harness = createAuthorityHarness(authorityState());
    const service = createService(store, harness);

    await expect(service.track({ value: 'top-secret-value', type: 'password', policyRevision: 7 }))
      .resolves.toEqual({ added: true });
    const listed = await service.list();

    expect(listed).toEqual({
      entries: [expect.objectContaining({ value: 'top-secret-value', type: 'password' })],
    });
    expect(JSON.stringify(listed)).not.toContain(SERVER_A);
    expect(JSON.stringify(listed)).not.toContain(EMAIL_A);
    expect(JSON.stringify(listed)).not.toContain(USER_A);
    expect(store.serialized()).not.toContain('top-secret-value');
    expect(store.raw(GENERATOR_HISTORY_SCOPE_INDEX_KEY)).toMatchObject({
      schemaVersion: 1,
      entries: [expect.objectContaining({
        serverUrl: SERVER_A,
        accountIdentity: EMAIL_A,
        userId: USER_A,
      })],
    });
  });

  it('rejects stale policy revisions before creating an index or history record', async () => {
    const store = createStore();
    const service = createService(store, createAuthorityHarness(authorityState()));

    await expect(service.track({ value: 'stale', type: 'password', policyRevision: 6 }))
      .rejects.toMatchObject({ code: 'stale_policy' });
    expect(store.keys()).toEqual([]);
  });

  it.each(['', 'line\nbreak', 'x'.repeat(32 * 1_024 + 1)])(
    'rejects an invalid track value before creating its scope index',
    async (value) => {
      const store = createStore();
      const service = createService(store, createAuthorityHarness(authorityState()));
      expect(() => service.track({ value, type: 'password', policyRevision: 7 }))
        .toThrow(expect.objectContaining({ code: 'invalid_request' }));
      expect(store.keys()).toEqual([]);
    },
  );

  it('keeps server and account histories isolated across A-B-A switches', async () => {
    const store = createStore();
    const accountA = authorityState();
    const accountB = authorityState({ accountIdentity: EMAIL_B, userId: USER_B });
    const otherServer = authorityState({ serverUrl: SERVER_B, crypto: createOpaqueCrypto() });
    const harness = createAuthorityHarness(accountA);
    const service = createService(store, harness);

    await service.track({ value: 'account-a', type: 'password', policyRevision: 7 });
    service.lockActiveScope();
    harness.switchTo(accountB);
    await service.track({ value: 'account-b', type: 'username', policyRevision: 7 });
    service.lockActiveScope();
    harness.switchTo(otherServer);
    await service.track({ value: 'server-b', type: 'pin', policyRevision: 7 });
    service.lockActiveScope();
    harness.switchTo(accountA);

    expect((await service.list()).entries.map((entry) => entry.value)).toEqual(['account-a']);
    expect((store.raw(GENERATOR_HISTORY_SCOPE_INDEX_KEY) as { entries: unknown[] }).entries).toHaveLength(3);
  });

  it('migrates an account identity change for the same profile UUID without aliasing its scope', async () => {
    const store = createStore();
    const beforeRename = authorityState();
    const afterRename = authorityState({
      accountIdentity: 'alice-renamed@example.com',
      crypto: beforeRename.crypto,
    });
    const harness = createAuthorityHarness(beforeRename);
    const service = createService(store, harness);
    await service.track({ value: 'survives-rename', type: 'password', policyRevision: 7 });
    service.lockActiveScope();
    harness.switchTo(afterRename);

    expect((await service.list()).entries.map((entry) => entry.value)).toEqual(['survives-rename']);
    expect((store.raw(GENERATOR_HISTORY_SCOPE_INDEX_KEY) as { entries: Array<{ accountIdentity: string }> }).entries)
      .toEqual([expect.objectContaining({ accountIdentity: 'alice-renamed@example.com' })]);
    await expect(service.removeExactAccount(SERVER_A, EMAIL_A)).resolves.toBe(false);
    expect((await service.list()).entries.map((entry) => entry.value)).toEqual(['survives-rename']);
  });

  it('rejects an A-B-A authority change after an index await without committing state', async () => {
    const backing = createStore();
    const accountA = authorityState();
    const accountB = authorityState({ accountIdentity: EMAIL_B, userId: USER_B });
    const harness = createAuthorityHarness(accountA);
    let bounce = true;
    const store: Pick<KeyValueStore, 'get' | 'set' | 'remove'> = {
      async get<Value>(key: string): Promise<Value | undefined> {
        const value = await backing.get<Value>(key);
        if (bounce) {
          bounce = false;
          harness.bounce(accountB, accountA);
        }
        return value;
      },
      set: (key, value) => backing.set(key, value),
      remove: (key) => backing.remove(key),
    };
    const service = createService(store, harness);

    await expect(service.track({ value: 'must-not-persist', type: 'password', policyRevision: 7 }))
      .rejects.toThrow('authority changed');
    expect(backing.keys()).toEqual([]);
  });

  it('rolls history back when authority changes during the repository write', async () => {
    const backing = createStore();
    const accountA = authorityState();
    const accountB = authorityState({ accountIdentity: EMAIL_B, userId: USER_B });
    const harness = createAuthorityHarness(accountA);
    let bounce = true;
    const store: Pick<KeyValueStore, 'get' | 'set' | 'remove'> = {
      get: (key) => backing.get(key),
      async set(key, value) {
        await backing.set(key, value);
        if (key.startsWith('generatorHistory.v1.') && bounce) {
          bounce = false;
          harness.bounce(accountB, accountA);
        }
      },
      remove: (key) => backing.remove(key),
    };
    const service = createService(store, harness);

    await expect(service.track({ value: 'stale-write', type: 'password', policyRevision: 7 }))
      .rejects.toThrow('authority changed');
    expect(backing.serialized()).not.toContain('stale-write');
    expect(backing.keys().filter((key) => key.startsWith('generatorHistory.v1.'))).toEqual([]);
  });

  it('shares one backing-store FIFO across service instances', async () => {
    const store = createStore();
    const firstHarness = createAuthorityHarness(authorityState());
    const secondHarness = createAuthorityHarness(authorityState({
      accountIdentity: EMAIL_B,
      userId: USER_B,
    }));
    const revisions = revisionFactory();
    const first = new GeneratorHistoryProductionService({
      store, withCurrentAuthority: firstHarness.withCurrentAuthority, createIndexRevision: revisions,
    });
    const second = new GeneratorHistoryProductionService({
      store, withCurrentAuthority: secondHarness.withCurrentAuthority, createIndexRevision: revisions,
    });

    await Promise.all([
      first.track({ value: 'first', type: 'password', policyRevision: 7 }),
      second.track({ value: 'second', type: 'passphrase', policyRevision: 7 }),
    ]);

    expect((store.raw(GENERATOR_HISTORY_SCOPE_INDEX_KEY) as { entries: unknown[] }).entries).toHaveLength(2);
    expect((await first.list()).entries.map((entry) => entry.value)).toEqual(['first']);
    expect((await second.list()).entries.map((entry) => entry.value)).toEqual(['second']);
  });

  it('uses the persistent index to recover the account scope in a fresh service instance', async () => {
    const store = createStore();
    const state = authorityState();
    const first = createService(store, createAuthorityHarness(state));
    await first.track({ value: 'before-restart', type: 'password', policyRevision: 7 });

    const restarted = createService(store, createAuthorityHarness(state));

    expect((await restarted.list()).entries.map((entry) => entry.value)).toEqual(['before-restart']);
  });

  it('projects injected repository entries to the three public DTO fields', async () => {
    const store = createStore();
    const harness = createAuthorityHarness(authorityState());
    const repository = {
      read: async () => [{
        generatedAt: 1,
        type: 'password' as const,
        value: 'visible',
        serverUrl: 'must-not-leak',
      } as never],
      track: async () => ({ added: false as const }),
      clear: async () => false,
      lock: () => {},
      unlock: () => {},
      remove: async () => false,
    };
    const service = new GeneratorHistoryProductionService({
      store,
      repository,
      withCurrentAuthority: harness.withCurrentAuthority,
      createIndexRevision: revisionFactory(),
    });

    const result = await service.list();
    expect(result).toEqual({ entries: [{ generatedAt: 1, type: 'password', value: 'visible' }] });
    expect(JSON.stringify(result)).not.toContain('must-not-leak');
  });

  it('clears history without removing the durable account-to-scope index', async () => {
    const store = createStore();
    const service = createService(store, createAuthorityHarness(authorityState()));
    await service.track({ value: 'clear-me', type: 'pin', policyRevision: 7 });
    const index = store.raw(GENERATOR_HISTORY_SCOPE_INDEX_KEY);

    await expect(service.clear()).resolves.toEqual({ cleared: true });
    expect(await service.list()).toEqual({ entries: [] });
    expect(store.raw(GENERATOR_HISTORY_SCOPE_INDEX_KEY)).toEqual(index);
  });
});

describe('generator history production index failures', () => {
  it.each([
    [{ schemaVersion: 2, future: true }, 'unsupported_index_schema'],
    [{ schemaVersion: 1, revision: 'bad', entries: [] }, 'corrupt_index'],
  ] as const)('retains an unsupported or corrupt index: %s', async (stored, code) => {
    const store = createStore();
    await store.set(GENERATOR_HISTORY_SCOPE_INDEX_KEY, stored);
    const service = createService(store, createAuthorityHarness(authorityState()));

    await expect(service.list()).rejects.toMatchObject({ code });
    await expect(service.track({ value: 'no-write', type: 'password', policyRevision: 7 }))
      .rejects.toMatchObject({ code });
    await expect(service.clear()).rejects.toMatchObject({ code });
    expect(store.raw(GENERATOR_HISTORY_SCOPE_INDEX_KEY)).toEqual(stored);
  });

  it('does not call the repository when the initial index write fails before commit', async () => {
    const backing = createStore();
    const store: Pick<KeyValueStore, 'get' | 'set' | 'remove'> = {
      get: (key) => backing.get(key),
      async set(key, value) {
        if (key === GENERATOR_HISTORY_SCOPE_INDEX_KEY) throw new Error('index write failed');
        await backing.set(key, value);
      },
      remove: (key) => backing.remove(key),
    };
    const service = createService(store, createAuthorityHarness(authorityState()));

    await expect(service.track({ value: 'must-not-orphan', type: 'password', policyRevision: 7 }))
      .rejects.toThrow('index write failed');
    expect(backing.keys()).toEqual([]);
  });

  it('rolls an outcome-unknown index commit back before repository tracking starts', async () => {
    const backing = createStore();
    let failOnce = true;
    const store: Pick<KeyValueStore, 'get' | 'set' | 'remove'> = {
      get: (key) => backing.get(key),
      async set(key, value) {
        await backing.set(key, value);
        if (key === GENERATOR_HISTORY_SCOPE_INDEX_KEY && failOnce) {
          failOnce = false;
          throw new Error('index write outcome unknown');
        }
      },
      remove: (key) => backing.remove(key),
    };
    const service = createService(store, createAuthorityHarness(authorityState()));

    await expect(service.track({ value: 'must-not-orphan', type: 'password', policyRevision: 7 }))
      .rejects.toThrow('index write outcome unknown');
    expect(backing.keys()).toEqual([]);
  });

  it('fails closed after an outcome-unknown index commit cannot be rolled back', async () => {
    const backing = createStore();
    let failCommit = true;
    const store: Pick<KeyValueStore, 'get' | 'set' | 'remove'> = {
      get: (key) => backing.get(key),
      async set(key, value) {
        await backing.set(key, value);
        if (key === GENERATOR_HISTORY_SCOPE_INDEX_KEY && failCommit) {
          failCommit = false;
          throw new Error('index write outcome unknown');
        }
      },
      async remove(key) {
        if (key === GENERATOR_HISTORY_SCOPE_INDEX_KEY) throw new Error('rollback failed');
        await backing.remove(key);
      },
    };
    const service = createService(store, createAuthorityHarness(authorityState()));

    await expect(service.track({ value: 'blocked', type: 'password', policyRevision: 7 }))
      .rejects.toMatchObject({ code: 'index_rollback_failed' });
    expect(() => service.list()).toThrow(expect.objectContaining({ code: 'index_unavailable' }));
  });

  it('enforces the strict 32-account index capacity without evicting discoverability metadata', async () => {
    const store = createStore();
    const states = Array.from({ length: MAX_GENERATOR_HISTORY_SCOPE_INDEX_ENTRIES + 1 }, (_, index) => authorityState({
      accountIdentity: `user-${index}@example.com`,
      userId: `${(index + 1).toString(16).padStart(8, '0')}-0000-4000-8000-${(index + 1).toString(16).padStart(12, '0')}`,
      crypto: createOpaqueCrypto(),
    }));
    const harness = createAuthorityHarness(states[0]!);
    const service = createService(store, harness);
    for (const [index, state] of states.slice(0, -1).entries()) {
      if (index > 0) {
        service.lockActiveScope();
        harness.switchTo(state);
      }
      await service.track({ value: `value-${index}`, type: 'password', policyRevision: 7 });
    }
    service.lockActiveScope();
    harness.switchTo(states.at(-1)!);

    await expect(service.track({ value: 'overflow', type: 'password', policyRevision: 7 }))
      .rejects.toMatchObject({ code: 'index_capacity' });
    expect((store.raw(GENERATOR_HISTORY_SCOPE_INDEX_KEY) as { entries: unknown[] }).entries)
      .toHaveLength(MAX_GENERATOR_HISTORY_SCOPE_INDEX_ENTRIES);
    expect(store.serialized()).not.toContain('overflow');
  });
});

describe('generator history production lifecycle', () => {
  it('shares outcome-unknown scope denial across services using the same store', async () => {
    const { failure, second } = await createSharedRollbackFailure();

    expect(failure).toMatchObject({ code: 'history_rollback_failed' });
    await expect(second.list()).rejects.toMatchObject({ code: 'history_rollback_failed' });
  });

  it('allows repo-first lifecycle removal to clear a shared unavailable-scope marker', async () => {
    const { backing, second } = await createSharedRollbackFailure();

    await expect(second.removeExactAccount(SERVER_A, EMAIL_A)).resolves.toBe(true);
    await expect(second.list()).resolves.toEqual({ entries: [] });
    expect(backing.serialized()).not.toContain('outcome-unknown');
  });

  it('locks an in-flight operation and rolls its repository write back', async () => {
    const store = createStore();
    const state = authorityState();
    const harness = createAuthorityHarness(state);
    const service = createService(store, harness);
    state.crypto.onEncrypt = () => service.lockActiveScope();

    await expect(service.track({ value: 'revoked', type: 'password', policyRevision: 7 }))
      .rejects.toMatchObject({ code: 'scope_locked' });
    state.crypto.onEncrypt = undefined;
    await service.unlockCurrent();
    expect(await service.list()).toEqual({ entries: [] });
    expect(store.serialized()).not.toContain('revoked');
  });

  it('removes an inactive account by its persistent index and preserves the active account', async () => {
    const store = createStore();
    const accountA = authorityState();
    const accountB = authorityState({ accountIdentity: EMAIL_B, userId: USER_B });
    const harness = createAuthorityHarness(accountA);
    const service = createService(store, harness);
    await service.track({ value: 'inactive-secret', type: 'password', policyRevision: 7 });
    service.lockActiveScope();
    harness.switchTo(accountB);
    await service.track({ value: 'active-secret', type: 'username', policyRevision: 7 });

    await expect(service.removeExactAccount(SERVER_A, EMAIL_A)).resolves.toBe(true);
    expect((await service.list()).entries.map((entry) => entry.value)).toEqual(['active-secret']);
    service.lockActiveScope();
    harness.switchTo(accountA);
    expect(await service.list()).toEqual({ entries: [] });
  });

  it('removes every account scope on the requested server and retains other servers', async () => {
    const store = createStore();
    const first = authorityState();
    const second = authorityState({ accountIdentity: EMAIL_B, userId: USER_B });
    const otherServer = authorityState({
      serverUrl: SERVER_B,
      accountIdentity: EMAIL_C,
      userId: USER_C,
      crypto: createOpaqueCrypto(),
    });
    const harness = createAuthorityHarness(first);
    const service = createService(store, harness);
    await service.track({ value: 'server-a-account-a', type: 'password', policyRevision: 7 });
    service.lockActiveScope();
    harness.switchTo(second);
    await service.track({ value: 'server-a-account-b', type: 'pin', policyRevision: 7 });
    service.lockActiveScope();
    harness.switchTo(otherServer);
    await service.track({ value: 'server-b-account-c', type: 'username', policyRevision: 7 });

    await expect(service.removeServerScopes(SERVER_A)).resolves.toBe(2);
    expect((await service.list()).entries.map((entry) => entry.value)).toEqual(['server-b-account-c']);
    service.lockActiveScope();
    harness.switchTo(first);
    expect(await service.list()).toEqual({ entries: [] });
  });

  it('uses a pending rotation server to clear all same-server scopes during startup recovery', async () => {
    const store = createStore();
    const accountA = authorityState();
    const accountB = authorityState({ accountIdentity: EMAIL_B, userId: USER_B });
    const otherServer = authorityState({
      serverUrl: SERVER_B,
      accountIdentity: EMAIL_C,
      userId: USER_C,
      crypto: createOpaqueCrypto(),
    });
    const harness = createAuthorityHarness(accountA);
    const service = createService(store, harness);
    await service.track({ value: 'rotation-a', type: 'password', policyRevision: 7 });
    service.lockActiveScope();
    harness.switchTo(accountB);
    await service.track({ value: 'rotation-b', type: 'pin', policyRevision: 7 });
    service.lockActiveScope();
    harness.switchTo(otherServer);
    await service.track({ value: 'other-server', type: 'username', policyRevision: 7 });
    const pending = new RotationPendingStore(store, { now: () => 10 });
    await pending.markBeforeRotation({ serverUrl: SERVER_A, accountId: EMAIL_A });

    await expect(recoverPendingRotationOnStartup(pending, {
      resetAllAccounts: async () => {},
      clearVaultCache: async () => {},
      clearGeneratorHistoryForServer: (serverUrl) => (
        service.removeServerScopes(serverUrl).then(() => undefined)
      ),
    })).resolves.toBe(true);

    expect((await service.list()).entries.map((entry) => entry.value)).toEqual(['other-server']);
    expect(await pending.inspectForStartup()).toEqual({ kind: 'none', requiresAccountReset: false });
    service.lockActiveScope();
    harness.switchTo(accountA);
    expect(await service.list()).toEqual({ entries: [] });
  });

  it('reconciles orphan scopes against the durable registered-account set on startup', async () => {
    const store = createStore();
    const accountA = authorityState();
    const accountB = authorityState({ accountIdentity: EMAIL_B, userId: USER_B });
    const harness = createAuthorityHarness(accountA);
    const service = createService(store, harness);
    await service.track({ value: 'orphaned', type: 'password', policyRevision: 7 });
    service.lockActiveScope();
    harness.switchTo(accountB);
    await service.track({ value: 'registered', type: 'pin', policyRevision: 7 });

    await expect(service.reconcileRegisteredAccounts([
      { serverUrl: SERVER_A, accountIdentity: EMAIL_B },
    ])).resolves.toBe(1);
    expect((await service.list()).entries.map((entry) => entry.value)).toEqual(['registered']);
    expect(store.serialized()).not.toContain('orphaned');
  });

  it('queues a same-worker re-login track after a late exact-account deletion', async () => {
    const backing = createStore();
    let blockHistoryRemoval = false;
    let markRemovalStarted!: () => void;
    const removalStarted = new Promise<void>((resolve) => { markRemovalStarted = resolve; });
    let releaseRemoval!: () => void;
    const removalGate = new Promise<void>((resolve) => { releaseRemoval = resolve; });
    const store: Pick<KeyValueStore, 'get' | 'set' | 'remove'> = {
      get: (key) => backing.get(key),
      set: (key, value) => backing.set(key, value),
      async remove(key) {
        if (blockHistoryRemoval && key.startsWith('generatorHistory.v1.')) {
          blockHistoryRemoval = false;
          markRemovalStarted();
          await removalGate;
        }
        await backing.remove(key);
      },
    };
    const harness = createAuthorityHarness(authorityState());
    const service = createService(store, harness);
    await service.track({ value: 'before-logout', type: 'password', policyRevision: 7 });
    blockHistoryRemoval = true;

    const removal = service.removeExactAccount(SERVER_A, EMAIL_A);
    await removalStarted;
    const afterRelogin = service.track({
      value: 'after-relogin', type: 'password', policyRevision: 7,
    });
    releaseRemoval();

    await expect(removal).resolves.toBe(true);
    await expect(afterRelogin).resolves.toEqual({ added: true });
    expect((await service.list()).entries.map((entry) => entry.value)).toEqual(['after-relogin']);
    expect(backing.serialized()).not.toContain('before-logout');
  });

  it('rejects non-canonical or duplicated registered accounts before touching storage', () => {
    const store = createStore();
    const service = createService(store, createAuthorityHarness(authorityState()));
    expect(() => service.reconcileRegisteredAccounts([
      { serverUrl: SERVER_A, accountIdentity: EMAIL_A },
      { serverUrl: SERVER_A, accountIdentity: EMAIL_A },
    ])).toThrow(expect.objectContaining({ code: 'invalid_request' }));
    expect(() => service.reconcileRegisteredAccounts([
      { serverUrl: SERVER_A, accountIdentity: ' Alice@example.com ' },
    ])).toThrow(expect.objectContaining({ code: 'invalid_request' }));
    expect(store.keys()).toEqual([]);
  });

  it('uses a one-shot pre-rotation receipt only after rotation succeeds', async () => {
    const store = createStore();
    const current = authorityState();
    const harness = createAuthorityHarness(current);
    const service = createService(store, harness);
    await service.track({ value: 'old-key-secret', type: 'passphrase', policyRevision: 7 });
    const failedRotationReceipt = await service.captureRotationRemoval();
    expect((await service.list()).entries.map((entry) => entry.value)).toEqual(['old-key-secret']);
    expect(failedRotationReceipt.kind).toBe('generatorHistoryRotationRemoval');

    const successfulRotationReceipt = await service.captureRotationRemoval();
    service.lockActiveScope();
    harness.switchTo(authorityState({ accountIdentity: EMAIL_B, userId: USER_B }));

    await expect(service.commitRotationRemoval(successfulRotationReceipt)).resolves.toBe(true);
    expect(() => service.commitRotationRemoval(successfulRotationReceipt))
      .toThrow(expect.objectContaining({ code: 'invalid_request' }));
    expect(store.serialized()).not.toContain('old-key-secret');
  });
});
