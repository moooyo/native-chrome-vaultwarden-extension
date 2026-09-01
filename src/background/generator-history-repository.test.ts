import { describe, expect, it, vi } from 'vitest';
import type { GeneratorHistoryCrypto } from '../core/generator/history-crypto.js';
import { createUserKeyGeneratorHistoryCrypto } from '../core/generator/history-crypto.js';
import { symmetricKeyFromBytes } from '../core/crypto/keys.js';
import type { KeyValueStore } from '../platform/store.js';
import {
  GENERATOR_HISTORY_SCHEMA_VERSION,
  GENERATOR_HISTORY_PADDING_FRAME_BYTES,
  GeneratorHistoryRepository,
  MAX_GENERATOR_HISTORY_ENTRIES,
  MAX_GENERATOR_HISTORY_VALUE_UTF8_BYTES,
  createGeneratorHistoryScope,
  type GeneratorHistoryScope,
} from './generator-history-repository.js';

const SERVER = 'https://vault.example/tenant/';
const ACCOUNT_A = '11111111-1111-4111-8111-111111111111';
const ACCOUNT_B = '22222222-2222-4222-8222-222222222222';

function createMemoryStore(): KeyValueStore {
  const values = new Map<string, string>();
  return {
    async get<Value>(key: string): Promise<Value | undefined> {
      const value = values.get(key);
      return value === undefined ? undefined : JSON.parse(value) as Value;
    },
    async set(key, value) {
      values.set(key, JSON.stringify(value));
    },
    async setMany(entries) {
      const serialized = Object.entries(entries).map(([key, value]) => [key, JSON.stringify(value)] as const);
      for (const [key, value] of serialized) values.set(key, value);
    },
    async remove(key) {
      values.delete(key);
    },
    async clear() {
      values.clear();
    },
  };
}

function userKey(seed = 1) {
  return symmetricKeyFromBytes(Uint8Array.from({ length: 64 }, (_, index) => (seed + index) & 0xff));
}

interface OpaqueCrypto extends GeneratorHistoryCrypto {
  seal(scopeDigest: string, text: string): Promise<string>;
}

function createOpaqueCrypto(): OpaqueCrypto {
  let sequence = 0;
  const records = new Map<string, { readonly scopeDigest: string; readonly bytes: Uint8Array }>();
  const encrypt = async (scopeDigest: string, plaintext: Uint8Array): Promise<string> => {
    const token = `opaque-${++sequence}`;
    records.set(token, { scopeDigest, bytes: plaintext.slice() });
    return token;
  };
  return {
    encrypt,
    async decrypt(scopeDigest, ciphertext) {
      const record = records.get(ciphertext);
      if (!record || record.scopeDigest !== scopeDigest) throw new Error('bad ciphertext');
      return record.bytes.slice();
    },
    async seal(scopeDigest, text) {
      const serialized = new TextEncoder().encode(text);
      const length = Math.ceil(
        (serialized.byteLength + 4) / GENERATOR_HISTORY_PADDING_FRAME_BYTES,
      ) * GENERATOR_HISTORY_PADDING_FRAME_BYTES;
      const bytes = new Uint8Array(length);
      new DataView(bytes.buffer).setUint32(0, serialized.byteLength, false);
      bytes.set(serialized, 4);
      try {
        return await encrypt(scopeDigest, bytes);
      } finally {
        serialized.fill(0);
        bytes.fill(0);
      }
    },
  };
}

async function scope(accountId = ACCOUNT_A, serverUrl = SERVER): Promise<GeneratorHistoryScope> {
  return createGeneratorHistoryScope(serverUrl, accountId);
}

describe('generator history scope', () => {
  it('canonicalizes the server and account id into a deterministic opaque domain-separated digest', async () => {
    const canonical = await scope();
    const equivalent = await createGeneratorHistoryScope(
      'https://VAULT.example/tenant',
      ACCOUNT_A.toUpperCase(),
    );
    const otherServer = await scope(ACCOUNT_A, 'https://vault.example/other');
    const otherAccount = await scope(ACCOUNT_B);

    expect(equivalent).toEqual(canonical);
    expect(canonical.digest).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(canonical.storageKey).toBe(`generatorHistory.v1.${canonical.digest}`);
    expect(otherServer.digest).not.toBe(canonical.digest);
    expect(otherAccount.digest).not.toBe(canonical.digest);
    expect(JSON.stringify(canonical)).not.toContain(SERVER);
    expect(JSON.stringify(canonical)).not.toContain(ACCOUNT_A);
  });

  it('rejects unsafe servers and non-stable account ids', async () => {
    await expect(createGeneratorHistoryScope('http://vault.example', ACCOUNT_A)).rejects.toThrow(/HTTPS/);
    await expect(createGeneratorHistoryScope(`${SERVER}?query=1`, ACCOUNT_A)).rejects.toThrow(/query/);
    await expect(createGeneratorHistoryScope(SERVER, 'email@example.com')).rejects.toThrow(/account id/);
  });
});

describe('generator history repository semantics', () => {
  it('stores unique credentials newest-first and matches official duplicate no-op semantics', async () => {
    let now = 100;
    const store = createMemoryStore();
    const history = new GeneratorHistoryRepository({ store, now: () => now });
    const account = await scope();
    const crypto = createOpaqueCrypto();

    expect(await history.track(account, crypto, { type: 'password', value: 'alpha' })).toMatchObject({
      added: true,
      entry: { generatedAt: 100, type: 'password', value: 'alpha' },
    });
    now = 200;
    await history.track(account, crypto, { type: 'username', value: 'bravo' });
    const beforeDuplicate = await store.get(account.storageKey);
    now = 300;
    expect(await history.track(account, crypto, {
      generatedAt: now,
      type: 'passphrase',
      value: 'alpha',
    })).toEqual({ added: false });
    expect(await store.get(account.storageKey)).toEqual(beforeDuplicate);

    expect(await history.read(account, crypto)).toEqual([
      { generatedAt: 200, type: 'username', value: 'bravo' },
      { generatedAt: 100, type: 'password', value: 'alpha' },
    ]);
  });

  it('shares the 200-entry capacity across all credential types and evicts only the oldest', async () => {
    let now = 0;
    const store = createMemoryStore();
    const history = new GeneratorHistoryRepository({ store, now: () => ++now });
    const account = await scope();
    const crypto = createOpaqueCrypto();

    for (let index = 0; index <= MAX_GENERATOR_HISTORY_ENTRIES; index += 1) {
      const type = (['password', 'passphrase', 'pin', 'username'] as const)[index % 4]!;
      await history.track(account, crypto, { type, value: `credential-${index}` });
    }

    const entries = await history.read(account, crypto);
    expect(entries).toHaveLength(MAX_GENERATOR_HISTORY_ENTRIES);
    expect(entries[0]?.value).toBe('credential-200');
    expect(entries.at(-1)?.value).toBe('credential-1');
    expect(entries.some((entry) => entry.value === 'credential-0')).toBe(false);
    expect(new Set(entries.map((entry) => entry.type))).toEqual(
      new Set(['password', 'passphrase', 'pin', 'username']),
    );
  });

  it('serializes concurrent updates from repository instances sharing the same store and scope', async () => {
    const store = createMemoryStore();
    const first = new GeneratorHistoryRepository({ store, now: () => 1 });
    const second = new GeneratorHistoryRepository({ store, now: () => 2 });
    const account = await scope();
    const crypto = createOpaqueCrypto();

    await Promise.all([
      first.track(account, crypto, { type: 'password', value: 'first' }),
      second.track(account, crypto, { type: 'username', value: 'second' }),
    ]);

    expect((await first.read(account, crypto)).map((entry) => entry.value)).toEqual(['second', 'first']);
  });

  it('enforces field and aggregate byte bounds while retaining the most recent values', async () => {
    const store = createMemoryStore();
    const history = new GeneratorHistoryRepository({ store });
    const account = await scope();
    const crypto = createOpaqueCrypto();

    expect(() => history.track(account, crypto, {
      type: 'password',
      value: 'x'.repeat(MAX_GENERATOR_HISTORY_VALUE_UTF8_BYTES + 1),
    })).toThrow(expect.objectContaining({ code: 'invalid_entry' }));

    const values: string[] = [];
    for (let index = 0; index < 17; index += 1) {
      const suffix = `-${index}`;
      const value = `${String.fromCharCode(97 + index).repeat(MAX_GENERATOR_HISTORY_VALUE_UTF8_BYTES - suffix.length)}${suffix}`;
      values.push(value);
      await history.track(account, crypto, { type: 'password', value });
    }
    const entries = await history.read(account, crypto);
    expect(entries.length).toBeLessThan(values.length);
    expect(entries[0]?.value).toBe(values.at(-1));
    expect(entries.some((entry) => entry.value === values[0])).toBe(false);
  });

  it.each([
    [{ type: 'email', value: 'value' }, 'type'],
    [{ type: 'password', value: '' }, 'value'],
    [{ type: 'password', value: 'line\nbreak' }, 'value'],
    [{ type: 'password', value: 'value', generatedAt: -1 }, 'time'],
    [{ type: 'password', value: 'value', extra: true }, 'shape'],
  ] as const)('rejects invalid generated credential %s (%s)', async (input, _label) => {
    const history = new GeneratorHistoryRepository({ store: createMemoryStore() });
    const account = await scope();
    expect(() => history.track(account, createOpaqueCrypto(), input as never))
      .toThrow(expect.objectContaining({ code: 'invalid_entry' }));
  });
});

describe('generator history encryption and lifecycle', () => {
  it('persists only strict ciphertext metadata without raw identity or credential fields', async () => {
    const store = createMemoryStore();
    const history = new GeneratorHistoryRepository({ store, now: () => 123 });
    const account = await scope();
    const crypto = createUserKeyGeneratorHistoryCrypto(userKey());
    await history.track(account, crypto, { type: 'password', value: 'top-secret-value' });

    const raw = await store.get<Record<string, unknown>>(account.storageKey);
    expect(Object.keys(raw ?? {}).sort()).toEqual(['payload', 'schemaVersion', 'scopeDigest']);
    expect(raw?.schemaVersion).toBe(GENERATOR_HISTORY_SCHEMA_VERSION);
    expect(raw?.scopeDigest).toBe(account.digest);
    const serialized = JSON.stringify({ key: account.storageKey, raw });
    expect(serialized).not.toContain('top-secret-value');
    expect(serialized).not.toContain('"generatedAt"');
    expect(serialized).not.toContain('"password"');
    expect(serialized).not.toContain(SERVER);
    expect(serialized).not.toContain(ACCOUNT_A);
    expect(await history.read(account, crypto)).toEqual([
      { generatedAt: 123, type: 'password', value: 'top-secret-value' },
    ]);
  });

  it('pads small histories to the same 2048-byte frame before UserKey encryption', async () => {
    const store = createMemoryStore();
    const history = new GeneratorHistoryRepository({ store });
    const first = await scope(ACCOUNT_A);
    const second = await scope(ACCOUNT_B);
    const crypto = createUserKeyGeneratorHistoryCrypto(userKey());
    await history.track(first, crypto, { type: 'password', value: 'short' });
    await history.track(second, crypto, { type: 'password', value: 'a somewhat longer generated password' });

    const firstEnvelope = await store.get<{ payload: string }>(first.storageKey);
    const secondEnvelope = await store.get<{ payload: string }>(second.storageKey);
    expect(firstEnvelope?.payload.length).toBe(secondEnvelope?.payload.length);
  });

  it('locks without deleting ciphertext and permits a fresh unlock to read it', async () => {
    const store = createMemoryStore();
    const history = new GeneratorHistoryRepository({ store });
    const account = await scope();
    const crypto = createOpaqueCrypto();
    await history.track(account, crypto, { type: 'password', value: 'retained' });
    const before = await store.get(account.storageKey);

    history.lock(account);
    expect(() => history.read(account, crypto))
      .toThrow(expect.objectContaining({ code: 'scope_locked' }));
    expect(() => history.clear(account, crypto))
      .toThrow(expect.objectContaining({ code: 'scope_locked' }));
    expect(await store.get(account.storageKey)).toEqual(before);

    history.unlock(account);
    expect(await history.read(account, crypto)).toEqual([
      expect.objectContaining({ value: 'retained' }),
    ]);
  });

  it('clears atomically inside the scope FIFO and leaves the unlocked scope reusable', async () => {
    const store = createMemoryStore();
    const history = new GeneratorHistoryRepository({ store });
    const account = await scope();
    const crypto = createOpaqueCrypto();
    await history.track(account, crypto, { type: 'password', value: 'before-clear' });

    const clearing = history.clear(account, crypto);
    const tracking = history.track(account, crypto, { type: 'pin', value: 'after-clear' });

    await expect(clearing).resolves.toBe(true);
    await expect(tracking).resolves.toMatchObject({
      added: true,
      entry: { type: 'pin', value: 'after-clear' },
    });
    expect(await history.read(account, crypto)).toEqual([
      expect.objectContaining({ type: 'pin', value: 'after-clear' }),
    ]);
    await expect(history.clear(account, crypto)).resolves.toBe(true);
    await expect(history.clear(account, crypto)).resolves.toBe(false);
    expect(await history.read(account, crypto)).toEqual([]);
  });

  it('restores the prior envelope when a shared lock revokes an in-flight clear', async () => {
    const backing = createMemoryStore();
    const hook: { onRemove?: () => void } = {};
    const store: Pick<KeyValueStore, 'get' | 'set' | 'remove'> = {
      get: (key) => backing.get(key),
      set: (key, value) => backing.set(key, value),
      async remove(key) {
        await backing.remove(key);
        hook.onRemove?.();
      },
    };
    const history = new GeneratorHistoryRepository({ store });
    const peer = new GeneratorHistoryRepository({ store });
    const account = await scope();
    const crypto = createOpaqueCrypto();
    await history.track(account, crypto, { type: 'passphrase', value: 'must-survive' });
    const before = await backing.get(account.storageKey);
    hook.onRemove = () => peer.lock(account);

    await expect(history.clear(account, crypto)).rejects.toMatchObject({ code: 'scope_locked' });
    expect(await backing.get(account.storageKey)).toEqual(before);
    history.unlock(account);
    expect(await history.read(account, crypto)).toEqual([
      expect.objectContaining({ type: 'passphrase', value: 'must-survive' }),
    ]);
  });

  it('marks a scope unavailable when an in-flight clear cannot restore its envelope', async () => {
    const backing = createMemoryStore();
    const account = await scope();
    let failWrites = false;
    const store: Pick<KeyValueStore, 'get' | 'set' | 'remove'> = {
      get: (key) => backing.get(key),
      async set(key, value) {
        if (failWrites) throw new Error('rollback write failed');
        await backing.set(key, value);
      },
      async remove(key) {
        await backing.remove(key);
        failWrites = true;
        peer.lock(account);
      },
    };
    const history = new GeneratorHistoryRepository({ store });
    const peer = new GeneratorHistoryRepository({ store });
    const crypto = createOpaqueCrypto();
    await history.track(account, crypto, { type: 'username', value: 'cannot-restore' });

    await expect(history.clear(account, crypto)).rejects.toMatchObject({ code: 'rollback_failed' });
    history.unlock(account);
    expect(() => history.clear(account, crypto))
      .toThrow(expect.objectContaining({ code: 'scope_unavailable' }));
  });

  it('rolls back a write that commits after a shared lock revokes its access', async () => {
    const backing = createMemoryStore();
    const hook: { onSet?: () => void } = {};
    const store: Pick<KeyValueStore, 'get' | 'set' | 'remove'> = {
      get: (key) => backing.get(key),
      remove: (key) => backing.remove(key),
      async set(key, value) {
        await backing.set(key, value);
        hook.onSet?.();
      },
    };
    const history = new GeneratorHistoryRepository({ store });
    const peer = new GeneratorHistoryRepository({ store });
    const account = await scope();
    let invoked = false;
    hook.onSet = () => {
      if (invoked) return;
      invoked = true;
      peer.lock(account);
    };

    await expect(history.track(account, createOpaqueCrypto(), {
      type: 'password', value: 'must-roll-back',
    })).rejects.toMatchObject({ code: 'scope_locked' });
    expect(await backing.get(account.storageKey)).toBeUndefined();
  });

  it('removes only the exact requested scope and leaves the repository locked for that account', async () => {
    const store = createMemoryStore();
    const history = new GeneratorHistoryRepository({ store });
    const first = await scope(ACCOUNT_A);
    const second = await scope(ACCOUNT_B);
    const crypto = createOpaqueCrypto();
    await history.track(first, crypto, { type: 'password', value: 'first-value' });
    await history.track(second, crypto, { type: 'password', value: 'second-value' });

    await expect(history.remove(first)).resolves.toBe(true);
    expect(await store.get(first.storageKey)).toBeUndefined();
    expect(await history.read(second, crypto)).toEqual([
      expect.objectContaining({ value: 'second-value' }),
    ]);
    expect(() => history.read(first, crypto))
      .toThrow(expect.objectContaining({ code: 'scope_locked' }));
  });
});

describe('generator history corrupt and future schema handling', () => {
  it('does not overwrite current-schema corruption until explicit recovery removes it', async () => {
    const store = createMemoryStore();
    const history = new GeneratorHistoryRepository({ store });
    const account = await scope();
    const corrupt = { schemaVersion: 1, scopeDigest: account.digest };
    await store.set(account.storageKey, corrupt);

    await expect(history.read(account, createOpaqueCrypto())).rejects.toMatchObject({ code: 'corrupt_storage' });
    await expect(history.track(account, createOpaqueCrypto(), {
      type: 'password', value: 'do-not-overwrite',
    })).rejects.toMatchObject({ code: 'corrupt_storage' });
    await expect(history.clear(account, createOpaqueCrypto()))
      .rejects.toMatchObject({ code: 'corrupt_storage' });
    expect(await store.get(account.storageKey)).toEqual(corrupt);
    await expect(history.recoverCorrupt(account, createOpaqueCrypto())).resolves.toBe(true);
    expect(await store.get(account.storageKey)).toBeUndefined();
  });

  it('explicitly recovers authenticated current-schema payload corruption but retains a valid record', async () => {
    const store = createMemoryStore();
    const history = new GeneratorHistoryRepository({ store });
    const account = await scope();
    const crypto = createOpaqueCrypto();
    const badPayload = await crypto.seal(account.digest, JSON.stringify({
      schemaVersion: 1,
      scopeDigest: account.digest,
      entries: [],
      extra: true,
    }));
    await store.set(account.storageKey, {
      schemaVersion: 1,
      scopeDigest: account.digest,
      payload: badPayload,
    });
    const beforeClear = await store.get(account.storageKey);

    await expect(history.clear(account, crypto)).rejects.toMatchObject({ code: 'corrupt_storage' });
    expect(await store.get(account.storageKey)).toEqual(beforeClear);
    await expect(history.recoverCorrupt(account, crypto)).resolves.toBe(true);
    await history.track(account, crypto, { type: 'username', value: 'valid' });
    await expect(history.recoverCorrupt(account, crypto)).resolves.toBe(false);
    expect(await history.read(account, crypto)).toEqual([expect.objectContaining({ value: 'valid' })]);
  });

  it('retains future outer and encrypted schemas and refuses reads, writes, and recovery', async () => {
    const store = createMemoryStore();
    const history = new GeneratorHistoryRepository({ store });
    const account = await scope();
    const crypto = createOpaqueCrypto();
    const futureOuter = { schemaVersion: 2, future: 'opaque' };
    await store.set(account.storageKey, futureOuter);

    await expect(history.read(account, crypto)).rejects.toMatchObject({ code: 'unsupported_schema' });
    await expect(history.track(account, crypto, {
      type: 'password', value: 'do-not-overwrite',
    })).rejects.toMatchObject({ code: 'unsupported_schema' });
    await expect(history.clear(account, crypto)).rejects.toMatchObject({ code: 'unsupported_schema' });
    await expect(history.recoverCorrupt(account, crypto)).rejects.toMatchObject({ code: 'unsupported_schema' });
    expect(await store.get(account.storageKey)).toEqual(futureOuter);

    const futurePayload = await crypto.seal(account.digest, JSON.stringify({
      schemaVersion: 2,
      scopeDigest: account.digest,
      entries: [],
    }));
    const futureInner = {
      schemaVersion: 1,
      scopeDigest: account.digest,
      payload: futurePayload,
    };
    await store.set(account.storageKey, futureInner);
    await expect(history.read(account, crypto)).rejects.toMatchObject({ code: 'unsupported_schema' });
    await expect(history.track(account, crypto, {
      type: 'password', value: 'still-do-not-overwrite',
    })).rejects.toMatchObject({ code: 'unsupported_schema' });
    await expect(history.clear(account, crypto)).rejects.toMatchObject({ code: 'unsupported_schema' });
    await expect(history.recoverCorrupt(account, crypto)).rejects.toMatchObject({ code: 'unsupported_schema' });
    expect(await store.get(account.storageKey)).toEqual(futureInner);
  });

  it('treats a bad MAC or wrong UserKey as current corruption without auto-deleting it', async () => {
    const store = createMemoryStore();
    const history = new GeneratorHistoryRepository({ store });
    const account = await scope();
    const correct = createUserKeyGeneratorHistoryCrypto(userKey(1));
    const wrong = createUserKeyGeneratorHistoryCrypto(userKey(9));
    await history.track(account, correct, { type: 'password', value: 'encrypted' });
    const before = await store.get(account.storageKey);

    await expect(history.read(account, wrong)).rejects.toMatchObject({ code: 'corrupt_storage' });
    expect(await store.get(account.storageKey)).toEqual(before);
    await expect(history.recoverCorrupt(account, wrong)).resolves.toBe(true);
    expect(await store.get(account.storageKey)).toBeUndefined();
  });

  it('rejects non-byte decrypt results and overlong ciphertext from injected boundaries', async () => {
    const store = createMemoryStore();
    const history = new GeneratorHistoryRepository({ store });
    const account = await scope();
    const crypto = createOpaqueCrypto();
    await history.track(account, crypto, { type: 'password', value: 'value' });
    await expect(history.read(account, {
      encrypt: crypto.encrypt,
      decrypt: vi.fn(async () => 'plaintext' as never),
    })).rejects.toMatchObject({ code: 'corrupt_storage' });

    await history.remove(account);
    history.unlock(account);
    await expect(history.track(account, {
      decrypt: crypto.decrypt,
      encrypt: vi.fn(async () => 'x'.repeat(1_048_577)),
    }, { type: 'password', value: 'value' })).rejects.toMatchObject({ code: 'storage_capacity' });
  });
});
