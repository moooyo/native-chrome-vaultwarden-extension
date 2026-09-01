import { describe, expect, it } from 'vitest';
import {
  ClientEventType,
  type CipherClientEventType,
  type ClientEvent,
} from '../core/events/client-event.js';
import type { AtomicKeyValueStore } from '../platform/store.js';
import {
  CLIENT_EVENT_CLAIM_TTL_MS,
  CLIENT_EVENT_MAX_AGE_MS,
  MAX_CLIENT_EVENT_QUEUE_EVENTS,
  MAX_CLIENT_EVENT_QUEUE_SCOPES,
  MAX_CLIENT_EVENT_QUEUE_UTF8_BYTES,
  CLIENT_EVENT_QUEUE_SCHEMA_VERSION,
  CLIENT_EVENT_QUEUE_STORAGE_KEY,
  ClientEventQueue,
  ClientEventQueueError,
  createClientEventQueueScope,
  parseRetryAfterHeader,
  type ClientEventClaim,
  type ClientEventClaimResult,
} from './client-event-queue.js';

const START = Date.parse('2026-08-31T10:20:30.123Z');
const DATE = new Date(START).toISOString();
const CIPHER_ID = '11111111-1111-4111-8111-111111111111';
const ORGANIZATION_ID = '22222222-2222-4222-8222-222222222222';
const SCOPE = createClientEventQueueScope('https://vault.example', 'account-user-a');
const OTHER_SCOPE = createClientEventQueueScope('https://other.example/base', 'account-user-a');
const RECREATED_ACCOUNT_SCOPE = createClientEventQueueScope('https://vault.example', 'account-user-b');

function cipherEvent(
  type: CipherClientEventType = ClientEventType.Cipher_ClientViewed,
): Extract<ClientEvent, { readonly cipherId: string }> {
  return { type, date: DATE, cipherId: CIPHER_ID, organizationId: ORGANIZATION_ID };
}

function idFactory(start = 1): () => string {
  let next = start;
  return () => `00000000-0000-4000-8000-${(next++).toString(16).padStart(12, '0')}`;
}

function memoryStore(values = new Map<string, string>()): AtomicKeyValueStore {
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const value = values.get(key);
      return value === undefined ? undefined : JSON.parse(value) as T;
    },
    async set(key: string, value: unknown): Promise<void> {
      values.set(key, JSON.stringify(value));
    },
    async setMany(next: Readonly<Record<string, unknown>>): Promise<void> {
      const serialized = Object.entries(next).map(([key, value]) => [key, JSON.stringify(value)] as const);
      for (const [key, value] of serialized) values.set(key, value);
    },
    async remove(key: string): Promise<void> { values.delete(key); },
    async clear(): Promise<void> { values.clear(); },
  };
}

function claimed(result: ClientEventClaimResult): ClientEventClaim {
  if (result.kind !== 'claimed') throw new Error(`Expected claim, got ${result.kind}`);
  return result.claim;
}

function harness(options: ConstructorParameters<typeof ClientEventQueue>[1] = {}) {
  let now = START;
  const store = memoryStore();
  const createId = idFactory();
  const queue = new ClientEventQueue(store, {
    now: () => now,
    random: () => 0,
    createId,
    ...options,
  });
  return {
    store,
    queue,
    setNow(value: number) { now = value; },
    advance(delta: number) { now += delta; },
    now: () => now,
    createId,
  };
}

describe('ClientEventQueue scopes and claims', () => {
  it('pins the hard retention and storage bounds', () => {
    expect(MAX_CLIENT_EVENT_QUEUE_EVENTS).toBe(2_048);
    expect(MAX_CLIENT_EVENT_QUEUE_UTF8_BYTES).toBe(1024 * 1024);
    expect(MAX_CLIENT_EVENT_QUEUE_SCOPES).toBe(32);
    expect(CLIENT_EVENT_MAX_AGE_MS).toBe(30 * 24 * 60 * 60 * 1000);
    expect(CLIENT_EVENT_CLAIM_TTL_MS).toBe(2 * 60 * 1000);
  });

  it('canonicalizes and isolates the stable account/server scope across a restart', async () => {
    const h = harness();
    expect(SCOPE).toEqual({ serverUrl: 'https://vault.example/', accountId: 'account-user-a' });

    await h.queue.enqueue(SCOPE, cipherEvent());
    await h.queue.enqueue(OTHER_SCOPE, { type: ClientEventType.User_ClientExportedVault, date: DATE });

    const restarted = new ClientEventQueue(h.store, {
      now: h.now,
      random: () => 0,
      createId: h.createId,
    });
    expect(await restarted.inspect(SCOPE)).toEqual({ queued: 1, claimed: 0, batchLimit: 50 });
    expect(await restarted.inspect(OTHER_SCOPE)).toEqual({ queued: 1, claimed: 0, batchLimit: 50 });

    const claim = claimed(await restarted.claim(SCOPE));
    expect(claim.scope).toEqual(SCOPE);
    expect(claim.entries.map((entry) => entry.event)).toEqual([cipherEvent()]);
    expect(await restarted.inspect(SCOPE)).toEqual({ queued: 1, claimed: 1, batchLimit: 50 });
    expect(await restarted.inspect(OTHER_SCOPE)).toEqual({ queued: 1, claimed: 0, batchLimit: 50 });
  });

  it('does not scope by email and hashes durable account/server ownership', async () => {
    expect(() => createClientEventQueueScope('https://vault.example', 'user@example.com'))
      .toThrow(TypeError);
    const h = harness();
    await h.queue.enqueue(SCOPE, cipherEvent());

    expect((await h.queue.inspect(RECREATED_ACCOUNT_SCOPE)).queued).toBe(0);
    expect((await h.queue.inspect(OTHER_SCOPE)).queued).toBe(0);
    await h.queue.enqueue(RECREATED_ACCOUNT_SCOPE, cipherEvent());
    await h.queue.enqueue(OTHER_SCOPE, cipherEvent());
    expect((await h.queue.inspect(SCOPE)).queued).toBe(1);
    expect((await h.queue.inspect(RECREATED_ACCOUNT_SCOPE)).queued).toBe(1);
    expect((await h.queue.inspect(OTHER_SCOPE)).queued).toBe(1);

    const raw = await h.store.get<Record<string, unknown>>(CLIENT_EVENT_QUEUE_STORAGE_KEY);
    const serialized = JSON.stringify(raw);
    expect(serialized).not.toContain('vault.example');
    expect(serialized).not.toContain('other.example');
    expect(serialized).not.toContain('account-user-a');
    expect(serialized).not.toContain('account-user-b');
    const scopes = raw?.scopes as Record<string, unknown>;
    expect(Object.keys(scopes)).toHaveLength(3);
    expect(Object.keys(scopes).every((key) => /^[0-9a-f]{64}$/u.test(key))).toBe(true);
  });

  it('acknowledges exact claimed IDs without deleting a concurrent enqueue', async () => {
    const h = harness();
    const first = await h.queue.enqueue(SCOPE, cipherEvent());
    const claim = claimed(await h.queue.claim(SCOPE));
    const second = await h.queue.enqueue(SCOPE, {
      ...cipherEvent(),
      type: ClientEventType.Cipher_ClientCopiedPassword,
    });

    expect(await h.queue.acknowledge(claim)).toBe(1);
    expect(await h.queue.inspect(SCOPE)).toEqual({ queued: 1, claimed: 0, batchLimit: 50 });
    const remaining = claimed(await h.queue.claim(SCOPE));
    expect(remaining.entries.map((entry) => entry.id)).toEqual([second.id]);
    expect(remaining.entries.map((entry) => entry.id)).not.toContain(first.id);
  });

  it('clears only the failed claim and preserves a concurrent enqueue', async () => {
    const h = harness();
    await h.queue.enqueue(SCOPE, cipherEvent());
    const claim = claimed(await h.queue.claim(SCOPE));
    await h.queue.enqueue(SCOPE, {
      ...cipherEvent(),
      type: ClientEventType.Cipher_ClientAutofilled,
    });

    const retry = await h.queue.release(claim, { kind: 'network' });
    expect(retry).toEqual({
      released: 1,
      failureCount: 1,
      retryAt: START + 2_500,
      batchLimit: 50,
    });
    expect(await h.queue.inspect(SCOPE)).toEqual({
      queued: 2,
      claimed: 0,
      retryAt: START + 2_500,
      batchLimit: 50,
    });
    expect(await h.queue.claim(SCOPE)).toEqual({ kind: 'deferred', retryAt: START + 2_500 });

    h.setNow(START + 2_500);
    expect(claimed(await h.queue.claim(SCOPE)).entries).toHaveLength(2);
  });

  it('reclaims a claim only after the two-minute stale deadline', async () => {
    const h = harness();
    const queued = await h.queue.enqueue(SCOPE, cipherEvent());
    const first = claimed(await h.queue.claim(SCOPE));

    h.advance(CLIENT_EVENT_CLAIM_TTL_MS - 1);
    expect(await h.queue.claim(SCOPE)).toEqual({
      kind: 'busy',
      retryAt: START + CLIENT_EVENT_CLAIM_TTL_MS,
    });

    h.advance(1);
    const reclaimed = claimed(await h.queue.claim(SCOPE));
    expect(reclaimed.token).not.toBe(first.token);
    expect(reclaimed.entries.map((entry) => entry.id)).toEqual([queued.id]);

    expect(await h.queue.acknowledge(first)).toBe(0);
    expect((await h.queue.inspect(SCOPE)).claimed).toBe(1);
    expect(await h.queue.acknowledge(reclaimed)).toBe(1);
  });

  it('allows only one active claim per scope and settles each claim once', async () => {
    const h = harness({ maxBatchEvents: 1 });
    await h.queue.enqueue(SCOPE, cipherEvent());
    await h.queue.enqueue(SCOPE, cipherEvent());
    const first = claimed(await h.queue.claim(SCOPE));

    expect(await h.queue.claim(SCOPE)).toEqual({
      kind: 'busy',
      retryAt: START + CLIENT_EVENT_CLAIM_TTL_MS,
    });
    const release = h.queue.release(first, { kind: 'network' });
    expect(() => h.queue.acknowledge(first)).toThrowError(ClientEventQueueError);
    await release;
    expect(() => h.queue.release(first, { kind: 'network' })).toThrowError(ClientEventQueueError);
  });

  it('requires current token ownership so an old success cannot hit a reused event ID', async () => {
    const firstIds = [
      '00000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-000000000002',
    ];
    const backing = new Map<string, string>();
    const first = new ClientEventQueue(memoryStore(backing), {
      now: () => START,
      createId: () => firstIds.shift()!,
    });
    const second = new ClientEventQueue(memoryStore(backing), {
      now: () => START,
      createId: () => '00000000-0000-4000-8000-000000000001',
    });
    const oldEvent = await first.enqueue(SCOPE, cipherEvent());
    const oldClaim = claimed(await first.claim(SCOPE));
    await second.discardScope(SCOPE);
    const newEvent = await second.enqueue(SCOPE, cipherEvent());

    expect(oldEvent.id).toBe('00000000-0000-4000-8000-000000000001');
    expect(newEvent.id).toBe('00000000-0000-4000-8000-000000000001');
    expect(await first.acknowledge(oldClaim)).toBe(0);
    expect((await second.inspect(SCOPE)).queued).toBe(1);
  });

  it('expires queued and claimed events at the 30-day retention boundary', async () => {
    const h = harness();
    await h.queue.enqueue(SCOPE, cipherEvent());
    await h.queue.claim(SCOPE);
    h.advance(CLIENT_EVENT_MAX_AGE_MS);

    expect(await h.queue.inspect(SCOPE)).toEqual({ queued: 0, claimed: 0, batchLimit: 50 });
    expect(await h.queue.claim(SCOPE)).toEqual({ kind: 'empty' });
  });
});

describe('ClientEventQueue retry policy', () => {
  it('honors bounded Retry-After values over exponential jitter', async () => {
    const h = harness();
    await h.queue.enqueue(SCOPE, cipherEvent());
    const first = claimed(await h.queue.claim(SCOPE));
    const firstRetry = await h.queue.release(first, {
      kind: 'http',
      status: 429,
      retryAfter: '120',
    });
    expect(firstRetry?.retryAt).toBe(START + 120_000);

    h.setNow(START + 120_000);
    const second = claimed(await h.queue.claim(SCOPE));
    const httpDate = new Date(h.now() + 10 * 60_000).toUTCString();
    const secondRetry = await h.queue.release(second, {
      kind: 'http',
      status: 503,
      retryAfter: httpDate,
    });
    expect(secondRetry).toMatchObject({
      failureCount: 2,
      retryAt: Date.parse(httpDate),
    });
  });

  it('halves a 413 batch and keeps the smaller batch limit after retry', async () => {
    const h = harness();
    for (let index = 0; index < 10; index += 1) {
      await h.queue.enqueue(SCOPE, cipherEvent());
    }
    const first = claimed(await h.queue.claim(SCOPE));
    expect(first.entries).toHaveLength(10);

    const retry = await h.queue.release(first, { kind: 'http', status: 413 });
    expect(retry?.batchLimit).toBe(5);
    h.setNow(retry!.retryAt);
    expect(claimed(await h.queue.claim(SCOPE)).entries).toHaveLength(5);
  });

  it('parses delta seconds and HTTP dates while rejecting or capping unsafe values', () => {
    expect(parseRetryAfterHeader('4', START)).toBe(4_000);
    expect(parseRetryAfterHeader(new Date(START + 5_000).toUTCString(), START)).toBe(4_877);
    expect(parseRetryAfterHeader('999999999999999999999', START)).toBe(24 * 60 * 60 * 1000);
    expect(parseRetryAfterHeader(' 4', START)).toBeUndefined();
    expect(parseRetryAfterHeader('not-a-date', START)).toBeUndefined();
  });
});

describe('ClientEventQueue bounds and corruption handling', () => {
  it('serializes different store wrappers over the same storage transaction domain', async () => {
    const backing = new Map<string, string>();
    const firstStore = memoryStore(backing);
    const secondStore = memoryStore(backing);
    const createId = idFactory();
    const first = new ClientEventQueue(firstStore, {
      now: () => START,
      random: () => 0,
      createId,
    });
    const second = new ClientEventQueue(secondStore, {
      now: () => START,
      random: () => 0,
      createId,
    });

    await Promise.all([
      first.enqueue(SCOPE, cipherEvent()),
      second.enqueue(SCOPE, { ...cipherEvent(), type: ClientEventType.Cipher_ClientAutofilled }),
    ]);
    expect(await first.inspect(SCOPE)).toEqual({ queued: 2, claimed: 0, batchLimit: 50 });
  });

  it('rejects event, scope, and byte capacity without replacing existing state', async () => {
    const eventBound = harness({ maxEvents: 2 });
    await eventBound.queue.enqueue(SCOPE, cipherEvent());
    await eventBound.queue.enqueue(SCOPE, cipherEvent());
    await expect(eventBound.queue.enqueue(SCOPE, cipherEvent()))
      .rejects.toMatchObject({ code: 'capacity' });
    expect((await eventBound.queue.inspect(SCOPE)).queued).toBe(2);

    const scopeBound = harness({ maxScopes: 1 });
    await scopeBound.queue.enqueue(SCOPE, cipherEvent());
    await expect(scopeBound.queue.enqueue(OTHER_SCOPE, cipherEvent()))
      .rejects.toMatchObject({ code: 'capacity' });

    const byteBound = harness({ maxStoredBytes: 128 });
    await expect(byteBound.queue.enqueue(SCOPE, cipherEvent()))
      .rejects.toMatchObject({ code: 'resource_limit' });
    expect(await byteBound.store.get(CLIENT_EVENT_QUEUE_STORAGE_KEY)).toBeUndefined();
  });

  it('bounds a claim by event count and serialized wire bytes', async () => {
    const countBound = harness({ maxBatchEvents: 3 });
    for (let index = 0; index < 5; index += 1) {
      await countBound.queue.enqueue(SCOPE, cipherEvent());
    }
    expect(claimed(await countBound.queue.claim(SCOPE)).entries).toHaveLength(3);

    const byteBound = harness({ maxBatchBytes: 1 });
    await byteBound.queue.enqueue(SCOPE, cipherEvent());
    await expect(byteBound.queue.claim(SCOPE)).rejects.toMatchObject({ code: 'resource_limit' });
  });

  it('fails closed on future and corrupt persisted schemas', async () => {
    const h = harness();
    const future = {
      schemaVersion: CLIENT_EVENT_QUEUE_SCHEMA_VERSION + 1,
      scopes: {},
      futureField: true,
    };
    await h.store.set(CLIENT_EVENT_QUEUE_STORAGE_KEY, future);
    await expect(h.queue.inspect(SCOPE)).rejects.toMatchObject({ code: 'unsupported_schema' });
    await expect(h.queue.recoverCorruptState()).rejects.toMatchObject({ code: 'unsupported_schema' });
    expect(await h.store.get(CLIENT_EVENT_QUEUE_STORAGE_KEY)).toEqual(future);

    await h.store.set(CLIENT_EVENT_QUEUE_STORAGE_KEY, {
      schemaVersion: CLIENT_EVENT_QUEUE_SCHEMA_VERSION,
      scopes: { unexpected: {} },
    });
    await expect(h.queue.inspect(SCOPE)).rejects.toBeInstanceOf(ClientEventQueueError);
    await expect(h.queue.inspect(SCOPE)).rejects.toMatchObject({ code: 'corrupt_state' });
    await expect(h.queue.recoverCorruptState()).resolves.toBe(true);
    await expect(h.queue.recoverCorruptState()).resolves.toBe(false);
    expect(await h.queue.inspect(SCOPE)).toEqual({ queued: 0, claimed: 0, batchLimit: 50 });
  });

  it('rejects a persisted scope with more than one active claim token', async () => {
    const h = harness({ maxBatchEvents: 1 });
    await h.queue.enqueue(SCOPE, cipherEvent());
    await h.queue.enqueue(SCOPE, cipherEvent());
    await h.queue.claim(SCOPE);
    const raw = await h.store.get<{
      scopes: Record<string, { events: Array<{ claimToken: string | null; claimedAt: number | null }> }>;
    }>(CLIENT_EVENT_QUEUE_STORAGE_KEY);
    const storedScope = Object.values(raw!.scopes)[0]!;
    storedScope.events[1]!.claimToken = '00000000-0000-4000-8000-999999999999';
    storedScope.events[1]!.claimedAt = START;
    await h.store.set(CLIENT_EVENT_QUEUE_STORAGE_KEY, raw);

    await expect(h.queue.inspect(SCOPE)).rejects.toMatchObject({ code: 'corrupt_state' });
  });

  it('discards one exact scope without affecting another', async () => {
    const h = harness();
    await h.queue.enqueue(SCOPE, cipherEvent());
    await h.queue.enqueue(OTHER_SCOPE, cipherEvent());

    expect(await h.queue.discardScope(SCOPE)).toBe(1);
    expect((await h.queue.inspect(SCOPE)).queued).toBe(0);
    expect((await h.queue.inspect(OTHER_SCOPE)).queued).toBe(1);
  });
});
