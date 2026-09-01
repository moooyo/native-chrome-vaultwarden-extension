import { describe, expect, it, vi } from 'vitest';
import { ClientEventType, type ClientEventWire } from '../core/events/client-event.js';
import type { KeyValueStore } from '../platform/store.js';
import {
  ClientEventQueue,
  createClientEventQueueScope,
  type ClientEventQueueScope,
} from './client-event-queue.js';
import { ClientEventUploader, type ClientEventTransport } from './client-event-uploader.js';

const NOW = Date.parse('2026-08-31T10:20:30.123Z');
const DATE = new Date(NOW).toISOString();
const CIPHER_ID = '11111111-1111-4111-8111-111111111111';
const ORGANIZATION_ID = '22222222-2222-4222-8222-222222222222';
const SCOPE = createClientEventQueueScope('https://vault.example', 'account-user-a');

function idFactory(): () => string {
  let next = 1;
  return () => `00000000-0000-4000-8000-${(next++).toString(16).padStart(12, '0')}`;
}

function memoryStore(): Pick<KeyValueStore, 'get' | 'set'> {
  const values = new Map<string, string>();
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const value = values.get(key);
      return value === undefined ? undefined : JSON.parse(value) as T;
    },
    async set(key: string, value: unknown): Promise<void> {
      values.set(key, JSON.stringify(value));
    },
  };
}

function queue(maxBatchEvents = 50): ClientEventQueue {
  return new ClientEventQueue(memoryStore(), {
    now: () => NOW,
    random: () => 0,
    createId: idFactory(),
    maxBatchEvents,
  });
}

async function addEvent(target: ClientEventQueue): Promise<void> {
  await target.enqueue(SCOPE, {
    type: ClientEventType.Cipher_ClientAutofilled,
    date: DATE,
    cipherId: CIPHER_ID,
    organizationId: ORGANIZATION_ID,
  });
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

describe('ClientEventUploader', () => {
  it('uploads only strict wire events and acknowledges the exact batch', async () => {
    const target = queue();
    await addEvent(target);
    const upload = vi.fn(async (
      _scope: ClientEventQueueScope,
      _events: readonly ClientEventWire[],
    ) => ({ ok: true as const }));
    const uploader = new ClientEventUploader(target, { upload });

    await expect(uploader.flush(SCOPE)).resolves.toEqual({ kind: 'uploaded', count: 1 });
    expect(upload).toHaveBeenCalledOnce();
    const [scope, events] = upload.mock.calls[0]!;
    expect(scope).toEqual(SCOPE);
    expect(events).toEqual([{
      type: 1114,
      date: DATE,
      cipherId: CIPHER_ID,
      organizationId: ORGANIZATION_ID,
    }]);
    expect(Object.keys(events[0]!)).toEqual(['type', 'date', 'cipherId', 'organizationId']);
    expect(await target.inspect(SCOPE)).toEqual({ queued: 0, claimed: 0, batchLimit: 50 });
    await expect(uploader.flush(SCOPE)).resolves.toEqual({ kind: 'idle' });
  });

  it('durably releases HTTP failures with status, Retry-After, and 413 reduction', async () => {
    const target = queue();
    await addEvent(target);
    const uploader = new ClientEventUploader(target, {
      upload: async () => ({ ok: false, status: 413, retryAfter: '60' }),
    });

    const result = await uploader.flush(SCOPE);
    expect(result).toEqual({
      kind: 'retry_scheduled',
      count: 1,
      status: 413,
      retry: {
        released: 1,
        failureCount: 1,
        retryAt: NOW + 60_000,
        batchLimit: 1,
      },
    });
    expect(await target.inspect(SCOPE)).toEqual({
      queued: 1,
      claimed: 0,
      retryAt: NOW + 60_000,
      batchLimit: 1,
    });
  });

  it('treats thrown and malformed transport outcomes as retryable network failures', async () => {
    for (const outcome of [
      () => Promise.reject(new Error('offline')),
      () => Promise.resolve({ ok: true, debug: 'must not be accepted' } as never),
    ]) {
      const target = queue();
      await addEvent(target);
      const onTransportError = vi.fn();
      const uploader = new ClientEventUploader(target, { upload: outcome }, { onTransportError });

      await expect(uploader.flush(SCOPE)).resolves.toMatchObject({
        kind: 'retry_scheduled',
        count: 1,
        retry: { released: 1, failureCount: 1, retryAt: NOW + 2_500 },
      });
      expect(onTransportError).toHaveBeenCalledOnce();
      expect(await target.inspect(SCOPE)).toMatchObject({ queued: 1, claimed: 0 });
    }
  });

  it('serializes uploads for one scope while allowing each batch to settle', async () => {
    const target = queue(1);
    await addEvent(target);
    await addEvent(target);
    const first = deferred<{ readonly ok: true }>();
    let call = 0;
    const transport: ClientEventTransport = {
      upload: vi.fn(() => (++call === 1 ? first.promise : Promise.resolve({ ok: true as const }))),
    };
    const uploader = new ClientEventUploader(target, transport);

    const firstFlush = uploader.flush(SCOPE);
    const secondFlush = uploader.flush(SCOPE);
    await vi.waitFor(() => expect(transport.upload).toHaveBeenCalledOnce());

    first.resolve({ ok: true });
    await expect(firstFlush).resolves.toEqual({ kind: 'uploaded', count: 1 });
    await expect(secondFlush).resolves.toEqual({ kind: 'uploaded', count: 1 });
    expect(transport.upload).toHaveBeenCalledTimes(2);
    expect((await target.inspect(SCOPE)).queued).toBe(0);
  });

  it('aggregates a transport error with a failed durable release', async () => {
    const claim = {
      scope: SCOPE,
      token: '00000000-0000-4000-8000-000000000001',
      claimedAt: NOW,
      entries: [{
        id: '00000000-0000-4000-8000-000000000002',
        enqueuedAt: NOW,
        event: { type: ClientEventType.User_ClientExportedVault, date: DATE },
      }],
    } as const;
    const releaseError = new Error('storage unavailable');
    const fakeQueue = {
      claim: async (_scope: ClientEventQueueScope) => ({ kind: 'claimed' as const, claim }),
      acknowledge: async () => 0,
      release: async () => { throw releaseError; },
    };
    const uploader = new ClientEventUploader(fakeQueue, {
      upload: async () => { throw new Error('offline'); },
    });

    await expect(uploader.flush(SCOPE)).rejects.toBeInstanceOf(AggregateError);
  });
});
