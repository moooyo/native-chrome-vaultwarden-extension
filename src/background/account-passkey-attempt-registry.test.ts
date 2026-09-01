import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
      session: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
    },
  },
}));
import { createMemoryStore } from '../platform/store.js';
import { parseAccountPasskeyAssertionOptions } from '../core/api/account-passkey.js';
import {
  accountPasskeyConnectorUrl,
  parseAccountPasskeyConnectorContext,
} from '../core/session/account-passkey.js';
import {
  ACCOUNT_PASSKEY_ATTEMPT_STORAGE_KEY,
  AccountPasskeyAttemptRegistry,
} from './account-passkey-attempt-registry.js';

const SERVER = 'https://vault.example/base/';
const ATTEMPT_A = '11111111-1111-4111-8111-111111111111';
const ATTEMPT_B = '22222222-2222-4222-8222-222222222222';

function options() {
  return parseAccountPasskeyAssertionOptions({
    options: {
      challenge: '6CG3jqMCVASJVXySMi9KWw',
      timeout: 60_000,
      rpId: 'vault.example',
      allowCredentials: [],
      userVerification: 'required',
      status: 'ok',
      errorMessage: '',
    },
    token: 'server-signed-continuation',
    object: 'webAuthnLoginAssertionOptions',
  });
}

function connector(documentId = 'document-a') {
  return parseAccountPasskeyConnectorContext({
    tabId: 7,
    frameId: 0,
    documentId,
    url: accountPasskeyConnectorUrl(SERVER),
  }, SERVER);
}

describe('AccountPasskeyAttemptRegistry', () => {
  it('restores a waiting attempt across worker restart without exposing state outside background', async () => {
    const store = createMemoryStore();
    const first = new AccountPasskeyAttemptRegistry(store, { now: () => 1_000, workerId: 'worker-a' });
    const created = await first.create({
      attemptId: ATTEMPT_A,
      serverUrl: SERVER,
      connector: connector(),
      assertionOptions: options(),
      createdAt: 1_000,
      expiresAt: 61_000,
    });
    const restarted = new AccountPasskeyAttemptRegistry(store, {
      now: () => 2_000,
      workerId: 'worker-b',
    });

    await expect(restarted.read()).resolves.toEqual(created);
  });

  it('atomically claims once and rejects replay with the stale owner generation', async () => {
    const store = createMemoryStore();
    const registry = new AccountPasskeyAttemptRegistry(store, { now: () => 1_000, workerId: 'worker-a' });
    const waiting = await registry.create({
      attemptId: ATTEMPT_A,
      serverUrl: SERVER,
      connector: connector(),
      assertionOptions: options(),
      createdAt: 1_000,
      expiresAt: 61_000,
    });
    const [first, replay] = await Promise.all([
      registry.claim(waiting.owner),
      registry.claim(waiting.owner),
    ]);

    expect(first?.status).toBe('claimed');
    expect(first?.owner.generation).toBeGreaterThan(waiting.owner.generation);
    expect(replay).toBeUndefined();
  });

  it('turns a claimed attempt into a terminal state that contains no replayable token', async () => {
    const store = createMemoryStore();
    const registry = new AccountPasskeyAttemptRegistry(store, { now: () => 1_000, workerId: 'worker-a' });
    const waiting = await registry.create({
      attemptId: ATTEMPT_A,
      serverUrl: SERVER,
      connector: connector(),
      assertionOptions: options(),
      createdAt: 1_000,
      expiresAt: 61_000,
    });
    const claimed = (await registry.claim(waiting.owner))!;
    const unknown = await registry.markOutcomeUnknown(claimed.owner);

    expect(unknown?.status).toBe('outcome_unknown');
    const raw = JSON.stringify(await store.get(ACCOUNT_PASSKEY_ATTEMPT_STORAGE_KEY));
    expect(raw).not.toContain('server-signed-continuation');
    expect(raw).not.toContain('assertionOptions');
  });

  it('prevents ABA owners from claiming a later attempt with the same id', async () => {
    const store = createMemoryStore();
    const registry = new AccountPasskeyAttemptRegistry(store, { now: () => 1_000, workerId: 'worker-a' });
    const first = await registry.create({
      attemptId: ATTEMPT_A,
      serverUrl: SERVER,
      connector: connector(),
      assertionOptions: options(),
      createdAt: 1_000,
      expiresAt: 61_000,
    });
    expect(await registry.clear(first.owner)).toBe(true);
    const second = await registry.create({
      attemptId: ATTEMPT_A,
      serverUrl: SERVER,
      connector: connector('document-b'),
      assertionOptions: options(),
      createdAt: 1_000,
      expiresAt: 61_000,
    });

    expect(await registry.claim(first.owner)).toBeUndefined();
    expect((await registry.claim(second.owner))?.status).toBe('claimed');
  });

  it('purges expired and malformed persisted state', async () => {
    const store = createMemoryStore();
    const registry = new AccountPasskeyAttemptRegistry(store, { now: () => 1_000, workerId: 'worker-a' });
    await registry.create({
      attemptId: ATTEMPT_B,
      serverUrl: SERVER,
      connector: connector(),
      assertionOptions: options(),
      createdAt: 1_000,
      expiresAt: 2_000,
    });
    const later = new AccountPasskeyAttemptRegistry(store, { now: () => 2_000, workerId: 'worker-b' });
    await expect(later.read()).resolves.toBeUndefined();
    expect(await store.get(ACCOUNT_PASSKEY_ATTEMPT_STORAGE_KEY)).toBeUndefined();

    await store.set(ACCOUNT_PASSKEY_ATTEMPT_STORAGE_KEY, { schemaVersion: 1, generation: 9, status: 'waiting' });
    await expect(later.read()).resolves.toBeUndefined();
    expect(await store.get(ACCOUNT_PASSKEY_ATTEMPT_STORAGE_KEY)).toBeUndefined();
  });

  it('rejects an overlong TTL and connector binding changes', async () => {
    const registry = new AccountPasskeyAttemptRegistry(createMemoryStore(), {
      now: () => 1_000,
      workerId: 'worker-a',
    });
    await expect(registry.create({
      attemptId: ATTEMPT_A,
      serverUrl: SERVER,
      connector: connector(),
      assertionOptions: options(),
      createdAt: 1_000,
      expiresAt: 1_000 + 2 * 60 * 1000 + 1,
    })).rejects.toThrow(/lifetime/u);

    expect(() => parseAccountPasskeyConnectorContext({
      tabId: 7,
      frameId: 0,
      documentId: 'document-a',
      url: `${accountPasskeyConnectorUrl(SERVER)}?changed=1`,
    }, SERVER)).toThrow(/URL/u);
  });
});
