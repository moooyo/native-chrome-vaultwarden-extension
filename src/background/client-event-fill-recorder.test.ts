import { describe, expect, it, vi } from 'vitest';
import { ClientEventType } from '../core/events/client-event.js';
import { ClientEventFillRecorder } from './client-event-fill-recorder.js';

const CIPHER_ID = '22222222-2222-4222-8222-222222222222';

describe('ClientEventFillRecorder', () => {
  it('commits once only after the exact payload receives an exact filled response', async () => {
    const receipt = Object.freeze({}) as never;
    const prepare = vi.fn(async () => receipt);
    const commit = vi.fn(async () => ({ kind: 'enqueued' as const }));
    const recorder = new ClientEventFillRecorder({ prepare, commit });
    const payload = Object.freeze({ number: '4111111111111111' });

    await recorder.prepare(CIPHER_ID, payload);
    await recorder.settle(payload, { status: 'filled' });
    await recorder.settle(payload, { status: 'filled' });

    expect(prepare).toHaveBeenCalledWith({
      type: ClientEventType.Cipher_ClientAutofilled,
      cipherId: CIPHER_ID,
    });
    expect(commit).toHaveBeenCalledOnce();
    expect(commit).toHaveBeenCalledWith(receipt);
  });

  it.each([
    { status: 'target_changed' },
    { status: 'filled', extra: true },
    Object.assign(Object.create(null), { status: 'filled', extra: undefined }),
    ['filled'],
    null,
  ])('consumes without committing for a non-exact acknowledgement: %j', async (response) => {
    const receipt = Object.freeze({}) as never;
    const commit = vi.fn(async () => ({ kind: 'enqueued' as const }));
    const recorder = new ClientEventFillRecorder({
      prepare: vi.fn(async () => receipt),
      commit,
    });
    const payload = {};

    await recorder.prepare(CIPHER_ID, payload);
    await recorder.settle(payload, response);
    await recorder.settle(payload, { status: 'filled' });
    expect(commit).not.toHaveBeenCalled();
  });

  it('isolates preparation and commit failures from the fill path', async () => {
    const payload = {};
    const prepareFailure = new ClientEventFillRecorder({
      prepare: vi.fn(async () => { throw new Error('authority unavailable'); }),
      commit: vi.fn(async () => ({ kind: 'enqueued' as const })),
    });
    await expect(prepareFailure.prepare('invalid-test-id', payload)).resolves.toBeUndefined();
    await expect(prepareFailure.settle(payload, { status: 'filled' })).resolves.toBeUndefined();

    const commitFailure = new ClientEventFillRecorder({
      prepare: vi.fn(async () => Object.freeze({}) as never),
      commit: vi.fn(async () => { throw new Error('queue unavailable'); }),
    });
    await commitFailure.prepare(CIPHER_ID, payload);
    await expect(commitFailure.settle(payload, { status: 'filled' })).resolves.toBeUndefined();
  });

  it('does not transfer a receipt between concurrent payload objects', async () => {
    const firstReceipt = Object.freeze({ first: true }) as never;
    const secondReceipt = Object.freeze({ second: true }) as never;
    const prepare = vi.fn()
      .mockResolvedValueOnce(firstReceipt)
      .mockResolvedValueOnce(secondReceipt);
    const commit = vi.fn(async () => ({ kind: 'enqueued' as const }));
    const recorder = new ClientEventFillRecorder({ prepare, commit });
    const first = {};
    const second = {};

    await Promise.all([
      recorder.prepare(CIPHER_ID, first),
      recorder.prepare(CIPHER_ID, second),
    ]);
    await recorder.settle(second, { status: 'filled' });
    await recorder.settle(first, { status: 'target_changed' });

    expect(commit).toHaveBeenCalledOnce();
    expect(commit).toHaveBeenCalledWith(secondReceipt);
  });
});
