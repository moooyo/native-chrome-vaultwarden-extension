import { describe, expect, it, vi } from 'vitest';
import { ClientEventType, type ClientEvent } from '../core/events/client-event.js';
import type { ClientEventQueueScope } from './client-event-queue.js';
import type { ClientEventUploadResult } from './client-event-uploader.js';
import {
  CLIENT_EVENT_FLUSH_INTERVAL_MS,
  ClientEventService,
  type ClientEventAuthorityProjection,
  type ClientEventReceipt,
} from './client-event-service.js';

const NOW = Date.parse('2026-09-01T08:09:10.123Z');
const USER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const ORG_ENABLED = '11111111-1111-4111-8111-111111111111';
const ORG_DISABLED = '22222222-2222-4222-8222-222222222222';
const CIPHER_ENABLED = '33333333-3333-4333-8333-333333333333';
const CIPHER_DISABLED = '44444444-4444-4444-8444-444444444444';
const CIPHER_PERSONAL = '55555555-5555-4555-8555-555555555555';

function authority(
  overrides: Partial<ClientEventAuthorityProjection> = {},
): ClientEventAuthorityProjection {
  return {
    serverUrl: 'https://vault-a.example',
    userId: USER_A,
    organizations: [
      { id: ORG_ENABLED, useEvents: true },
      { id: ORG_DISABLED, useEvents: false },
    ],
    ciphers: [
      { id: CIPHER_ENABLED, organizationId: ORG_ENABLED },
      { id: CIPHER_DISABLED, organizationId: ORG_DISABLED },
      { id: CIPHER_PERSONAL, organizationId: null },
    ],
    ...overrides,
  };
}

function harness(initial: unknown = authority()) {
  let active = initial;
  const captureActive = vi.fn(() => active);
  const enqueue = vi.fn(async (_scope: ClientEventQueueScope, event: ClientEvent) => ({
    id: '00000000-0000-4000-8000-000000000001',
    event,
    enqueuedAt: NOW,
  }));
  const discardScope = vi.fn(async (_scope: ClientEventQueueScope) => 0);
  const flush = vi.fn(async (_scope: ClientEventQueueScope): Promise<ClientEventUploadResult> => ({ kind: 'idle' }));
  const schedule = vi.fn(async () => undefined);
  const cancel = vi.fn(async () => undefined);
  const onError = vi.fn();
  const service = new ClientEventService({
    authority: { captureActive },
    queue: { enqueue, discardScope },
    uploader: { flush },
    alarm: { schedule, cancel },
    now: () => NOW,
    onError,
  });
  return {
    service,
    captureActive,
    enqueue,
    discardScope,
    flush,
    schedule,
    cancel,
    onError,
    setActive(value: unknown) { active = value; },
  };
}

function receipt(value: ClientEventReceipt | undefined): ClientEventReceipt {
  if (!value) throw new Error('Expected a client event receipt');
  return value;
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

describe('ClientEventService prepare and commit', () => {
  it('writes nothing before commit and consumes a receipt exactly once', async () => {
    const h = harness();
    const prepared = receipt(await h.service.prepare({
      type: ClientEventType.Cipher_ClientAutofilled,
      cipherId: CIPHER_ENABLED,
    }));

    expect(h.enqueue).not.toHaveBeenCalled();
    const results = await Promise.all([
      h.service.commit(prepared),
      h.service.commit(prepared),
    ]);

    expect(results).toContainEqual({ kind: 'enqueued' });
    expect(results).toContainEqual({ kind: 'not_pending' });
    expect(h.enqueue).toHaveBeenCalledOnce();
    expect(h.enqueue).toHaveBeenCalledWith(
      { serverUrl: 'https://vault-a.example/', accountId: USER_A },
      {
        type: ClientEventType.Cipher_ClientAutofilled,
        date: new Date(NOW).toISOString(),
        cipherId: CIPHER_ENABLED,
        organizationId: ORG_ENABLED,
      },
    );
    expect(h.schedule).toHaveBeenCalledWith({
      scope: { serverUrl: 'https://vault-a.example/', accountId: USER_A },
      when: NOW + CLIENT_EVENT_FLUSH_INTERVAL_MS,
      reason: 'periodic',
    });
    await expect(h.service.commit({} as ClientEventReceipt)).resolves.toEqual({ kind: 'not_pending' });
  });

  it('derives cipher ownership from authority and rejects disabled or personal subjects', async () => {
    const h = harness();
    await expect(h.service.prepare({
      type: ClientEventType.Cipher_ClientViewed,
      cipherId: CIPHER_DISABLED,
    })).resolves.toBeUndefined();
    await expect(h.service.prepare({
      type: ClientEventType.Cipher_ClientViewed,
      cipherId: CIPHER_PERSONAL,
    })).resolves.toBeUndefined();
    await expect(h.service.prepare({
      type: ClientEventType.Cipher_ClientViewed,
      cipherId: '66666666-6666-4666-8666-666666666666',
    })).resolves.toBeUndefined();
    await expect(h.service.prepare({
      type: ClientEventType.Organization_ClientExportedVault,
      organizationId: ORG_DISABLED,
    })).resolves.toBeUndefined();
    expect(h.enqueue).not.toHaveBeenCalled();
  });

  it('allows user export only when at least one trusted organization uses events', async () => {
    const enabled = harness();
    expect(await enabled.service.prepare({
      type: ClientEventType.User_ClientExportedVault,
    })).toBeDefined();

    const disabled = harness(authority({
      organizations: [{ id: ORG_DISABLED, useEvents: false }],
    }));
    await expect(disabled.service.prepare({
      type: ClientEventType.User_ClientExportedVault,
    })).resolves.toBeUndefined();
  });

  it('records an organization decline only for an enabled direct membership', async () => {
    const h = harness();
    const prepared = receipt(await h.service.prepare({
      type: ClientEventType.Organization_ItemOrganization_Declined,
      organizationId: ORG_ENABLED,
    }));

    await expect(h.service.commit(prepared)).resolves.toEqual({ kind: 'enqueued' });
    expect(h.enqueue).toHaveBeenCalledWith(
      { serverUrl: 'https://vault-a.example/', accountId: USER_A },
      {
        type: ClientEventType.Organization_ItemOrganization_Declined,
        date: new Date(NOW).toISOString(),
        organizationId: ORG_ENABLED,
      },
    );
    await expect(h.service.prepare({
      type: ClientEventType.Organization_ItemOrganization_Declined,
      organizationId: ORG_DISABLED,
    })).resolves.toBeUndefined();
  });

  it('rejects unsupported types, wrong identifiers, extra ownership, and malformed authority', async () => {
    const h = harness();
    await expect(h.service.prepare({ type: 9999 } as never)).rejects.toBeInstanceOf(TypeError);
    await expect(h.service.prepare({
      type: ClientEventType.Cipher_ClientViewed,
      cipherId: 'not-a-uuid',
    })).rejects.toBeInstanceOf(TypeError);
    await expect(h.service.prepare({
      type: ClientEventType.Cipher_ClientViewed,
      cipherId: CIPHER_ENABLED,
      organizationId: ORG_ENABLED,
    } as never)).rejects.toBeInstanceOf(TypeError);

    h.setActive(authority({
      organizations: [
        { id: ORG_ENABLED, useEvents: true },
        { id: ORG_ENABLED, useEvents: true },
      ],
    }));
    await expect(h.service.prepare({
      type: ClientEventType.Cipher_ClientViewed,
      cipherId: CIPHER_ENABLED,
    })).resolves.toBeUndefined();
    expect(h.onError).toHaveBeenLastCalledWith('authority', expect.any(TypeError));
  });

  it('pins the old scope and ownership when the active account switches before commit', async () => {
    const h = harness();
    const prepared = receipt(await h.service.prepare({
      type: ClientEventType.Cipher_ClientCopiedPassword,
      cipherId: CIPHER_ENABLED,
    }));
    h.setActive(authority({
      serverUrl: 'https://vault-b.example/base',
      userId: USER_B,
      organizations: [{ id: ORG_DISABLED, useEvents: true }],
      ciphers: [{ id: CIPHER_ENABLED, organizationId: ORG_DISABLED }],
    }));

    await expect(h.service.commit(prepared)).resolves.toEqual({ kind: 'enqueued' });
    expect(h.captureActive).toHaveBeenCalledOnce();
    expect(h.enqueue.mock.calls[0]![0]).toEqual({
      serverUrl: 'https://vault-a.example/',
      accountId: USER_A,
    });
    expect(h.enqueue.mock.calls[0]![1]).toMatchObject({ organizationId: ORG_ENABLED });
  });
});

describe('ClientEventService failure isolation and scheduling', () => {
  it('consumes a failed enqueue and schedules recovery for commit-then-reject storage', async () => {
    const h = harness();
    const failure = new Error('storage unavailable');
    h.enqueue.mockRejectedValueOnce(failure);
    const prepared = receipt(await h.service.prepare({
      type: ClientEventType.Organization_ItemOrganization_Accepted,
      organizationId: ORG_ENABLED,
    }));

    await expect(h.service.commit(prepared)).resolves.toEqual({ kind: 'failed' });
    await expect(h.service.commit(prepared)).resolves.toEqual({ kind: 'not_pending' });
    expect(h.onError).toHaveBeenCalledWith('enqueue', failure);
    expect(h.schedule).toHaveBeenCalledWith({
      scope: { serverUrl: 'https://vault-a.example/', accountId: USER_A },
      when: NOW + CLIENT_EVENT_FLUSH_INTERVAL_MS,
      reason: 'periodic',
    });
  });

  it('keeps a successful enqueue successful when scheduling or diagnostics fail', async () => {
    const h = harness();
    const scheduleFailure = new Error('alarm unavailable');
    h.schedule.mockRejectedValueOnce(scheduleFailure);
    h.onError.mockImplementation(() => { throw new Error('diagnostics failed'); });
    const prepared = receipt(await h.service.prepare({
      type: ClientEventType.User_ClientExportedVault,
    }));

    await expect(h.service.commit(prepared)).resolves.toEqual({ kind: 'enqueued' });
    expect(h.enqueue).toHaveBeenCalledOnce();
    expect(h.onError).toHaveBeenCalledWith('schedule', scheduleFailure);
  });

  it.each([
    {
      result: { kind: 'deferred', retryAt: NOW + 10_000 } as ClientEventUploadResult,
      retryAt: NOW + 10_000,
    },
    {
      result: { kind: 'busy', retryAt: NOW + 20_000 } as ClientEventUploadResult,
      retryAt: NOW + 20_000,
    },
    {
      result: {
        kind: 'retry_scheduled',
        count: 1,
        retry: { released: 1, failureCount: 2, retryAt: NOW + 30_000, batchLimit: 25 },
      } as ClientEventUploadResult,
      retryAt: NOW + 30_000,
    },
  ])('schedules uploader retry state at its exact retryAt', async ({ result, retryAt }) => {
    const h = harness();
    h.flush.mockResolvedValueOnce(result);
    const scope = await h.service.captureActiveScope();

    await expect(h.service.flush(scope!)).resolves.toEqual(result);
    expect(h.schedule).toHaveBeenLastCalledWith({
      scope: { serverUrl: 'https://vault-a.example/', accountId: USER_A },
      when: retryAt,
      reason: 'retry',
    });
  });

  it('schedules another periodic batch after upload and cancels an idle scope', async () => {
    const h = harness();
    const scope = await h.service.captureActiveScope();
    h.flush.mockResolvedValueOnce({ kind: 'uploaded', count: 2 });
    await expect(h.service.flush(scope!)).resolves.toEqual({ kind: 'uploaded', count: 2 });
    expect(h.schedule).toHaveBeenLastCalledWith({
      scope: { serverUrl: 'https://vault-a.example/', accountId: USER_A },
      when: NOW + CLIENT_EVENT_FLUSH_INTERVAL_MS,
      reason: 'periodic',
    });

    h.flush.mockResolvedValueOnce({ kind: 'idle' });
    await expect(h.service.flush(scope!)).resolves.toEqual({ kind: 'idle' });
    expect(h.cancel).toHaveBeenCalledWith(scope);
  });

  it('serializes an idle cancellation before a concurrent enqueue schedule', async () => {
    const h = harness();
    const prepared = receipt(await h.service.prepare({
      type: ClientEventType.Cipher_ClientViewed,
      cipherId: CIPHER_ENABLED,
    }));
    const scope = await h.service.captureActiveScope();
    const upload = deferred<ClientEventUploadResult>();
    h.flush.mockReturnValueOnce(upload.promise);

    const flushing = h.service.flush(scope!);
    await vi.waitFor(() => expect(h.flush).toHaveBeenCalledOnce());
    const committing = h.service.commit(prepared);
    expect(h.enqueue).not.toHaveBeenCalled();
    upload.resolve({ kind: 'idle' });

    await expect(flushing).resolves.toEqual({ kind: 'idle' });
    await expect(committing).resolves.toEqual({ kind: 'enqueued' });
    expect(h.cancel.mock.invocationCallOrder[0]).toBeLessThan(h.schedule.mock.invocationCallOrder[0]!);
  });

  it('contains flush failure and leaves a periodic recovery wake-up', async () => {
    const h = harness();
    const failure = new Error('uploader failed');
    h.flush.mockRejectedValueOnce(failure);
    const scope = await h.service.captureActiveScope();

    await expect(h.service.flushBeforeLogout(scope!)).resolves.toEqual({ kind: 'failed' });
    expect(h.onError).toHaveBeenCalledWith('flush', failure);
    expect(h.schedule).toHaveBeenLastCalledWith({
      scope,
      when: NOW + CLIENT_EVENT_FLUSH_INTERVAL_MS,
      reason: 'periodic',
    });
  });
});

describe('ClientEventService account lifecycle', () => {
  it('discards logout plaintext without waiting for a hung upload scope lane', async () => {
    const h = harness();
    const scope = await h.service.captureActiveScope();
    const upload = deferred<ClientEventUploadResult>();
    h.flush.mockReturnValueOnce(upload.promise);
    h.discardScope.mockResolvedValueOnce(2);

    const flushing = h.service.flushBeforeLogout(scope!);
    await vi.waitFor(() => expect(h.flush).toHaveBeenCalledOnce());
    await expect(h.service.discardLoggedOutScope(scope!)).resolves.toEqual({
      kind: 'discarded', count: 2,
    });
    expect(h.discardScope).toHaveBeenCalledWith(scope);

    upload.resolve({ kind: 'idle' });
    await expect(flushing).resolves.toEqual({ kind: 'idle' });
  });

  it('revokes a pending receipt before discarding its removed-account scope', async () => {
    const h = harness();
    const prepared = receipt(await h.service.prepare({
      type: ClientEventType.Cipher_ClientViewed,
      cipherId: CIPHER_ENABLED,
    }));
    const scope = await h.service.captureActiveScope();

    const commit = h.service.commit(prepared);
    const discard = h.service.discardRemovedAccount(scope!);
    await expect(commit).resolves.toEqual({ kind: 'not_pending' });
    await expect(discard).resolves.toEqual({ kind: 'discarded', count: 0 });
    expect(h.enqueue).not.toHaveBeenCalled();
  });

  it('flushes and discards a captured scope after the active account changes', async () => {
    const h = harness();
    const oldScope = await h.service.captureActiveScope();
    h.setActive(authority({
      serverUrl: 'https://vault-b.example',
      userId: USER_B,
      organizations: [],
      ciphers: [],
    }));
    h.discardScope.mockResolvedValueOnce(3);

    await h.service.flushBeforeLogout(oldScope!);
    await expect(h.service.discardRemovedAccount(oldScope!)).resolves.toEqual({
      kind: 'discarded',
      count: 3,
    });
    expect(h.flush).toHaveBeenCalledWith(oldScope);
    expect(h.discardScope).toHaveBeenCalledWith(oldScope);
    expect(h.cancel).toHaveBeenCalledWith(oldScope);
  });

  it('returns no captured scope when the worker authority is unavailable', async () => {
    const h = harness(null);
    await expect(h.service.captureActiveScope()).resolves.toBeUndefined();
    expect(h.onError).toHaveBeenCalledWith('authority', expect.any(TypeError));
  });
});
