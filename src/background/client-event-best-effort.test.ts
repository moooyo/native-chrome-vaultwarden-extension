import { describe, expect, it, vi } from 'vitest';
import { bestEffortClientEvent } from './client-event-best-effort.js';

describe('bestEffortClientEvent', () => {
  it('returns settled values and contains synchronous or asynchronous failures', async () => {
    await expect(bestEffortClientEvent(() => Promise.resolve('ok'), 10)).resolves.toBe('ok');
    await expect(bestEffortClientEvent(() => { throw new Error('sync'); }, 10))
      .resolves.toBeUndefined();
    await expect(bestEffortClientEvent(() => Promise.reject(new Error('async')), 10))
      .resolves.toBeUndefined();
  });

  it('releases the caller at its deadline and observes a late rejection', async () => {
    vi.useFakeTimers();
    try {
      let reject!: (error: Error) => void;
      const pending = new Promise<never>((_resolve, rejectPromise) => { reject = rejectPromise; });
      const result = bestEffortClientEvent(() => pending, 25);

      await vi.advanceTimersByTimeAsync(25);
      await expect(result).resolves.toBeUndefined();
      reject(new Error('late failure'));
      await Promise.resolve();
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not invoke an invalid deadline operation twice', async () => {
    const operation = vi.fn(async () => 'never');
    await expect(bestEffortClientEvent(operation, -1)).rejects.toBeInstanceOf(RangeError);
    expect(operation).not.toHaveBeenCalled();
  });
});
