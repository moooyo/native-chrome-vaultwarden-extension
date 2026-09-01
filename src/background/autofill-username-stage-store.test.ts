import { describe, expect, it } from 'vitest';
import type { KeyValueStore } from '../platform/store.js';
import type { SymmetricKey } from '../core/crypto/keys.js';
import {
  AUTOFILL_USERNAME_STAGE_KEY,
  AUTOFILL_USERNAME_STAGE_ENVELOPE_MAX_UTF8_BYTES,
  AutofillUsernameStageStore,
  type AutofillUsernameStageInput,
} from './autofill-username-stage-store.js';

function createMemoryStore(): KeyValueStore {
  const values = new Map<string, unknown>();
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const value = values.get(key);
      return value === undefined ? undefined : structuredClone(value) as T;
    },
    async set(key: string, value: unknown): Promise<void> {
      values.set(key, structuredClone(value));
    },
    async remove(key: string): Promise<void> { values.delete(key); },
    async clear(): Promise<void> { values.clear(); },
  };
}

function ownedUserKey(): SymmetricKey {
  return {
    encKey: new Uint8Array(32).fill(17),
    macKey: new Uint8Array(32).fill(29),
  };
}

function createStages(
  store: KeyValueStore,
  options: Partial<Omit<ConstructorParameters<typeof AutofillUsernameStageStore>[0], 'store' | 'loadUserKey'>> = {},
): AutofillUsernameStageStore {
  return new AutofillUsernameStageStore({
    store,
    loadUserKey: async () => ownedUserKey(),
    ...options,
  });
}

const STAGE: AutofillUsernameStageInput = {
  tabId: 7,
  frameId: 0,
  origin: 'https://login.example.com',
  username: 'person@example.com',
  sessionGeneration: 3,
  sessionBindingId: 'session-binding',
  serverGeneration: 4,
  accountGeneration: 5,
  serverUrl: 'https://vault.example.com/',
  accountIdentity: 'person@example.com',
  policyGeneration: 6,
  enterprisePolicyGeneration: 7,
  enterprisePolicyRawGeneration: 'enterprise-raw-generation-A',
};

function context(overrides: Partial<AutofillUsernameStageInput> = {}) {
  const { username: _username, ...result } = { ...STAGE, ...overrides };
  return result;
}

describe('AutofillUsernameStageStore', () => {
  it('reserves at most 256 KiB of the shared storage.session quota', () => {
    expect(AUTOFILL_USERNAME_STAGE_ENVELOPE_MAX_UTF8_BYTES).toBe(256 * 1024);
  });
  it('survives a worker restart and consumes an exact match only once', async () => {
    const store = createMemoryStore();
    await createStages(store).stage(STAGE);
    await expect(store.get<{ schemaVersion: number }>(AUTOFILL_USERNAME_STAGE_KEY))
      .resolves.toMatchObject({ schemaVersion: 3 });
    const restarted = createStages(store);

    await expect(restarted.consume(context())).resolves.toBe(STAGE.username);
    await expect(restarted.consume(context())).resolves.toBeUndefined();
    await expect(store.get(AUTOFILL_USERNAME_STAGE_KEY)).resolves.toBeUndefined();
  });

  it.each([
    ['tab', { tabId: 8 }],
    ['frame', { frameId: 1 }],
    ['origin', { origin: 'https://other.example.com' }],
  ])('does not consume an entry from another %s', async (_label, overrides) => {
    const store = createMemoryStore();
    const stages = createStages(store);
    await stages.stage(STAGE);
    await expect(stages.consume(context(overrides))).resolves.toBeUndefined();
    await expect(stages.consume(context())).resolves.toBe(STAGE.username);
  });

  it.each([
    ['session generation', { sessionGeneration: 30 }],
    ['session binding', { sessionBindingId: 'new-session' }],
    ['server generation', { serverGeneration: 40 }],
    ['account generation', { accountGeneration: 50 }],
    ['server', { serverUrl: 'https://other-vault.example.com/' }],
    ['account', { accountIdentity: 'other@example.com' }],
    ['policy generation', { policyGeneration: 60 }],
    ['enterprise policy generation', { enterprisePolicyGeneration: 70 }],
    ['enterprise policy raw generation', { enterprisePolicyRawGeneration: 'enterprise-raw-generation-B' }],
  ])('consumes but rejects a stale %s binding', async (_label, overrides) => {
    const store = createMemoryStore();
    const stages = createStages(store);
    await stages.stage(STAGE);
    await expect(stages.consume(context(overrides))).resolves.toBeUndefined();
    await expect(stages.consume(context())).resolves.toBeUndefined();
  });

  it('rejects an enterprise policy ABA transition after the effective policy returns to A', async () => {
    const store = createMemoryStore();
    const stages = createStages(store);
    await stages.stage(STAGE);

    await expect(stages.consume(context({
      enterprisePolicyGeneration: STAGE.enterprisePolicyGeneration + 2,
      enterprisePolicyRawGeneration: 'enterprise-raw-generation-C',
    }))).resolves.toBeUndefined();
    await expect(stages.consume(context())).resolves.toBeUndefined();
  });

  it('expires entries and prunes malformed storage fail closed', async () => {
    let now = 1_000;
    const store = createMemoryStore();
    const stages = createStages(store, { now: () => now, ttlMs: 10 });
    await stages.stage(STAGE);
    now = 1_010;
    await expect(stages.consume(context())).resolves.toBeUndefined();
    await expect(store.get(AUTOFILL_USERNAME_STAGE_KEY)).resolves.toBeUndefined();

    await store.set(AUTOFILL_USERNAME_STAGE_KEY, { schemaVersion: 2, revision: 1, entries: [] });
    await expect(stages.consume(context())).resolves.toBeUndefined();
    await expect(store.get(AUTOFILL_USERNAME_STAGE_KEY)).resolves.toBeUndefined();
  });

  it('replaces a matching context and bounds capacity to the newest entries', async () => {
    const store = createMemoryStore();
    const stages = createStages(store, { maxEntries: 2 });
    await stages.stage(STAGE);
    await stages.stage({ ...STAGE, username: 'new@example.com' });
    await stages.stage({ ...STAGE, tabId: 8, username: 'eight@example.com' });
    await stages.stage({ ...STAGE, tabId: 9, username: 'nine@example.com' });

    await expect(stages.consume(context())).resolves.toBeUndefined();
    await expect(stages.consume(context({ tabId: 8 }))).resolves.toBe('eight@example.com');
    await expect(stages.consume(context({ tabId: 9 }))).resolves.toBe('nine@example.com');
  });

  it('serializes concurrent writes and can clear one tab without touching another', async () => {
    const store = createMemoryStore();
    const stages = createStages(store);
    await Promise.all([
      stages.stage(STAGE),
      stages.stage({ ...STAGE, tabId: 8, username: 'other@example.com' }),
    ]);
    await stages.clearTab(7);
    await expect(stages.consume(context())).resolves.toBeUndefined();
    await expect(stages.consume(context({ tabId: 8 }))).resolves.toBe('other@example.com');
  });

  it('rejects non-canonical or oversized inputs', async () => {
    const stages = createStages(createMemoryStore());
    await expect(stages.stage({ ...STAGE, origin: 'https://login.example.com/' })).rejects.toThrow('origin');
    await expect(stages.stage({ ...STAGE, serverUrl: 'https://vault.example.com' })).rejects.toThrow('canonical');
    await expect(stages.stage({ ...STAGE, enterprisePolicyRawGeneration: ' ' })).rejects.toThrow('enterprisePolicyRawGeneration');
    await expect(stages.stage({ ...STAGE, username: ' ' })).rejects.toThrow('username');
    await expect(stages.clearTab(-1)).rejects.toThrow('tabId');
  });

  it('never persists the username in plaintext and zeroes the owned UserKey', async () => {
    const store = createMemoryStore();
    const key = ownedUserKey();
    const staged = { ...STAGE, username: 'different-login-alias@example.net' };
    const stages = new AutofillUsernameStageStore({
      store,
      loadUserKey: async () => key,
    });

    await stages.stage(staged);

    const stored = await store.get<unknown>(AUTOFILL_USERNAME_STAGE_KEY);
    expect(JSON.stringify(stored)).not.toContain(staged.username);
    expect([...key.encKey, ...key.macKey].every((byte) => byte === 0)).toBe(true);
  });

  it('fails closed when ciphertext is tampered or the UserKey is unavailable', async () => {
    const store = createMemoryStore();
    const stages = createStages(store);
    await stages.stage(STAGE);
    const stored = await store.get<{ entries: Array<{ ciphertext: string }> }>(AUTOFILL_USERNAME_STAGE_KEY);
    expect(stored).toBeDefined();
    const ciphertext = stored!.entries[0]!.ciphertext;
    stored!.entries[0]!.ciphertext = `${ciphertext.startsWith('A') ? 'B' : 'A'}${ciphertext.slice(1)}`;
    await store.set(AUTOFILL_USERNAME_STAGE_KEY, stored);
    await expect(stages.consume(context())).resolves.toBeUndefined();

    await createStages(store).stage(STAGE);
    const unavailable = new AutofillUsernameStageStore({
      store,
      loadUserKey: async () => undefined,
    });
    await expect(unavailable.consume(context())).resolves.toBeUndefined();
    await expect(store.get(AUTOFILL_USERNAME_STAGE_KEY)).resolves.toBeUndefined();
  });
});
