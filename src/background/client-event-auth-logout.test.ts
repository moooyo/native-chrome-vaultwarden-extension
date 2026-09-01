import { describe, expect, it, vi } from 'vitest';
import type { SessionTransitionEvent } from '../core/session/auth-service.js';
import { CLIENT_EVENT_BEST_EFFORT_WAIT_MS } from './client-event-best-effort.js';
import { ClientEventAuthLogoutLifecycle } from './client-event-auth-logout.js';

const START = Object.freeze({
  phase: 'start', transitionId: 7, reason: 'logout', identityChanged: true,
}) satisfies SessionTransitionEvent;

function settled(succeeded: boolean): SessionTransitionEvent {
  return Object.freeze({
    phase: 'settled', transitionId: 7, reason: 'logout', identityChanged: true,
    succeeded, state: succeeded ? 'loggedOut' : 'unlocked',
  }) as SessionTransitionEvent;
}

function harness() {
  const receipt = Object.freeze({}) as never;
  const confirmed = Object.freeze({}) as never;
  const runtime = {
    captureLogout: vi.fn(async () => receipt),
    flushBeforeLogout: vi.fn(async () => ({ kind: 'uploaded' as const, count: 1 })),
    confirmLogout: vi.fn(async () => confirmed),
    discardConfirmedLogout: vi.fn(async () => true),
    completeLogout: vi.fn(async () => true),
  };
  return { receipt, confirmed, runtime, lifecycle: new ClientEventAuthLogoutLifecycle(runtime) };
}

describe('ClientEventAuthLogoutLifecycle', () => {
  it('captures and flushes before transition action, then discards only after success', async () => {
    const { receipt, confirmed, runtime, lifecycle } = harness();

    await lifecycle.handle(START);
    expect(runtime.captureLogout).toHaveBeenCalledOnce();
    expect(runtime.flushBeforeLogout).toHaveBeenCalledWith(receipt);
    expect(runtime.completeLogout).not.toHaveBeenCalled();

    await lifecycle.handle(settled(true));
    expect(runtime.confirmLogout).toHaveBeenCalledWith(receipt);
    expect(runtime.discardConfirmedLogout).toHaveBeenCalledWith(confirmed);
    expect(runtime.completeLogout).not.toHaveBeenCalled();
  });

  it('preserves the queue when AuthService reports failed logout', async () => {
    const { receipt, runtime, lifecycle } = harness();

    await lifecycle.handle(START);
    await lifecycle.handle(settled(false));

    expect(runtime.completeLogout).toHaveBeenCalledWith(receipt, false);
  });

  it('bounds a hanging upload while still starting successful cleanup', async () => {
    vi.useFakeTimers();
    try {
      const { confirmed, runtime, lifecycle } = harness();
      runtime.flushBeforeLogout.mockImplementation(() => new Promise(() => {}));
      const start = lifecycle.handle(START);
      await vi.advanceTimersByTimeAsync(CLIENT_EVENT_BEST_EFFORT_WAIT_MS);
      await expect(start).resolves.toBeUndefined();

      await lifecycle.handle(settled(true));
      expect(runtime.discardConfirmedLogout).toHaveBeenCalledWith(confirmed);
    } finally {
      vi.useRealTimers();
    }
  });

  it('bounds a hanging discard after successful logout', async () => {
    vi.useFakeTimers();
    try {
      const { runtime, lifecycle } = harness();
      runtime.discardConfirmedLogout.mockImplementation(() => new Promise(() => {}));
      await lifecycle.handle(START);
      const completion = lifecycle.handle(settled(true));
      await vi.advanceTimersByTimeAsync(CLIENT_EVENT_BEST_EFFORT_WAIT_MS);

      await expect(completion).resolves.toBeUndefined();
      expect(runtime.confirmLogout).toHaveBeenCalledOnce();
      expect(runtime.discardConfirmedLogout).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not release successful settlement before a slow durable confirmation commits', async () => {
    vi.useFakeTimers();
    try {
      const { confirmed, runtime, lifecycle } = harness();
      let confirm!: (receipt: typeof confirmed) => void;
      const confirmation = new Promise<typeof confirmed>((resolve) => { confirm = resolve; });
      runtime.confirmLogout.mockImplementation(() => confirmation);
      await lifecycle.handle(START);
      let completed = false;
      const completion = lifecycle.handle(settled(true)).then(() => { completed = true; });

      await vi.advanceTimersByTimeAsync(CLIENT_EVENT_BEST_EFFORT_WAIT_MS * 2);
      expect(completed).toBe(false);
      expect(runtime.discardConfirmedLogout).not.toHaveBeenCalled();
      confirm(confirmed);
      await completion;
      expect(runtime.discardConfirmedLogout).toHaveBeenCalledWith(confirmed);
    } finally {
      vi.useRealTimers();
    }
  });

  it('fails successful settlement when durable confirmation cannot be written', async () => {
    const { runtime, lifecycle } = harness();
    runtime.confirmLogout.mockRejectedValue(new Error('confirmation storage failed'));
    await lifecycle.handle(START);

    await expect(lifecycle.handle(settled(true))).rejects.toThrow('confirmation storage failed');
    expect(runtime.discardConfirmedLogout).not.toHaveBeenCalled();
  });

  it('fails transition admission when durable capture fails', async () => {
    const { runtime, lifecycle } = harness();
    runtime.captureLogout.mockRejectedValue(new Error('capture failed'));
    await expect(lifecycle.handle(START)).rejects.toThrow(/cleanup intent/i);
    await expect(lifecycle.handle(settled(false))).resolves.toBeUndefined();
    expect(runtime.completeLogout).not.toHaveBeenCalled();
    await expect(lifecycle.handle(settled(false))).resolves.toBeUndefined();
    expect(runtime.completeLogout).not.toHaveBeenCalled();
  });

  it('fails transition admission when durable capture exceeds its local deadline', async () => {
    vi.useFakeTimers();
    try {
      const { runtime, lifecycle } = harness();
      runtime.captureLogout.mockImplementation(() => new Promise(() => {}));
      const start = expect(lifecycle.handle(START)).rejects.toThrow(/cleanup intent/i);
      await vi.advanceTimersByTimeAsync(CLIENT_EVENT_BEST_EFFORT_WAIT_MS);

      await start;
      expect(runtime.flushBeforeLogout).not.toHaveBeenCalled();
      const failure = lifecycle.handle(settled(false));
      await vi.advanceTimersByTimeAsync(CLIENT_EVENT_BEST_EFFORT_WAIT_MS);
      await expect(failure).resolves.toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });

  it('ignores unrelated AuthService transitions', async () => {
    const { runtime, lifecycle } = harness();
    await lifecycle.handle({
      phase: 'start', transitionId: 8, reason: 'lock', identityChanged: false,
    });
    expect(runtime.captureLogout).not.toHaveBeenCalled();
  });
});
