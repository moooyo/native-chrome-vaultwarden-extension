import { describe, it, expect, vi } from 'vitest';
import { createIdleLock, ensureIdleLockAlarm, IDLE_LOCK_ALARM, type IdleLockDeps, type IdleState } from './idle-lock.js';

function makeDeps(over: Partial<IdleLockDeps> = {}): IdleLockDeps {
  return {
    getConfig: async () => ({ idleSeconds: 900, lockOnSystemLock: true, action: 'lock' }),
    isUnlocked: async () => true,
    lock: vi.fn(async () => {}),
    logout: vi.fn(async () => {}),
    queryState: async () => 'active',
    setDetectionInterval: vi.fn(),
    ...over,
  };
}

describe('createIdleLock', () => {
  it('locks on idle and on locked when unlocked', async () => {
    const deps = makeDeps();
    const il = createIdleLock(deps);
    await il.onStateChanged('idle');
    await il.onStateChanged('locked');
    expect(deps.lock).toHaveBeenCalledTimes(1);
    expect(deps.logout).not.toHaveBeenCalled();
  });

  it('logs out when action is logout', async () => {
    const deps = makeDeps({ getConfig: async () => ({ idleSeconds: 60, lockOnSystemLock: true, action: 'logout' }) });
    await createIdleLock(deps).onStateChanged('locked');
    expect(deps.logout).toHaveBeenCalledTimes(1);
    expect(deps.lock).not.toHaveBeenCalled();
  });

  it('does nothing on active', async () => {
    const deps = makeDeps();
    await createIdleLock(deps).onStateChanged('active');
    expect(deps.lock).not.toHaveBeenCalled();
  });

  it('is a no-op when already locked (guards double-trigger, esp. logout)', async () => {
    const deps = makeDeps({
      isUnlocked: async () => false,
      getConfig: async () => ({ idleSeconds: 60, lockOnSystemLock: true, action: 'logout' }),
      queryState: async (): Promise<IdleState> => 'idle', // backstop reaches applyAction, then hits the guard
    });
    const il = createIdleLock(deps);
    await il.onStateChanged('idle');
    await il.onBackstopAlarm();
    expect(deps.logout).not.toHaveBeenCalled();
    expect(deps.lock).not.toHaveBeenCalled();
  });

  it('ignores idle and locked when disabled (idleSeconds null)', async () => {
    const deps = makeDeps({ getConfig: async () => ({ idleSeconds: null, lockOnSystemLock: false, action: 'lock' }), queryState: vi.fn(async (): Promise<IdleState> => 'active') });
    const il = createIdleLock(deps);
    await il.onStateChanged('idle');
    await il.onStateChanged('locked');
    await il.onBackstopAlarm();
    expect(deps.lock).not.toHaveBeenCalled();
    expect(deps.queryState).not.toHaveBeenCalled();
  });

  it('applyDetection uses idleSeconds (min 15) when enabled and a large sentinel when disabled', async () => {
    const enabled = makeDeps({ getConfig: async () => ({ idleSeconds: 5, lockOnSystemLock: true, action: 'lock' }) });
    await createIdleLock(enabled).applyDetection();
    expect(enabled.setDetectionInterval).toHaveBeenCalledWith(15); // clamped to API minimum
    const on = makeDeps({ getConfig: async () => ({ idleSeconds: 900, lockOnSystemLock: true, action: 'lock' }) });
    await createIdleLock(on).applyDetection();
    expect(on.setDetectionInterval).toHaveBeenCalledWith(15);
    const off = makeDeps({ getConfig: async () => ({ idleSeconds: null, lockOnSystemLock: false, action: 'lock' }) });
    await createIdleLock(off).applyDetection();
    expect(off.setDetectionInterval).toHaveBeenCalledWith(4 * 3600);
  });

  it('applies fail-closed immediate logout without waiting for an idle event', async () => {
    const deps = makeDeps({
      getConfig: async () => ({ idleSeconds: 0, lockOnSystemLock: true, action: 'logout' }),
      queryState: vi.fn(async (): Promise<IdleState> => 'active'),
    });
    const idle = createIdleLock(deps);

    await idle.applyDetection();
    expect(deps.logout).not.toHaveBeenCalled();
    expect(deps.setDetectionInterval).toHaveBeenCalledWith(15);
    await idle.onBackstopAlarm();
    expect(deps.logout).not.toHaveBeenCalled();
    expect(deps.queryState).toHaveBeenCalledWith(15);
  });

  it('treats a system-lock-only policy as an event trigger, not a fake idle timeout', async () => {
    const queryState = vi.fn()
      .mockResolvedValueOnce('idle' as IdleState)
      .mockResolvedValueOnce('locked' as IdleState);
    const deps = makeDeps({
      getConfig: async () => ({ idleSeconds: null, lockOnSystemLock: true, action: 'lock' }),
      queryState,
    });
    const idle = createIdleLock(deps);

    await idle.applyDetection();
    expect(deps.setDetectionInterval).toHaveBeenCalledWith(15);
    await idle.onStateChanged('idle');
    expect(deps.lock).not.toHaveBeenCalled();
    await idle.onStateChanged('locked');
    expect(deps.lock).toHaveBeenCalledTimes(1);
    await idle.onBackstopAlarm();
    expect(deps.lock).toHaveBeenCalledTimes(1);
    await idle.onBackstopAlarm();
    expect(deps.lock).toHaveBeenCalledTimes(2);
    expect(queryState).toHaveBeenNthCalledWith(1, 15);
  });

  it('backstop alarm acts only on system locked', async () => {
    const locked = makeDeps({ queryState: vi.fn(async (): Promise<IdleState> => 'locked') });
    await createIdleLock(locked).onBackstopAlarm();
    expect(locked.lock).toHaveBeenCalledTimes(1);
    const idle = makeDeps({ queryState: vi.fn(async (): Promise<IdleState> => 'idle') });
    await createIdleLock(idle).onBackstopAlarm();
    expect(idle.lock).not.toHaveBeenCalled();
    const active = makeDeps({ queryState: vi.fn(async (): Promise<IdleState> => 'active') });
    await createIdleLock(active).onBackstopAlarm();
    expect(active.lock).not.toHaveBeenCalled();
  });

  it('clamps the backstop queryState interval to the chrome.idle minimum', async () => {
    const queryState = vi.fn(async (): Promise<IdleState> => 'active');
    // A sub-minimum idleSeconds would make chrome.idle.queryState throw; clamp it like applyDetection.
    const deps = makeDeps({ getConfig: async () => ({ idleSeconds: 5, lockOnSystemLock: true, action: 'lock' }), queryState });
    await createIdleLock(deps).onBackstopAlarm();
    expect(queryState).toHaveBeenCalledWith(15);
  });
});

describe('ensureIdleLockAlarm', () => {
  it('creates the backstop alarm when it is missing', async () => {
    const create = vi.fn();
    await ensureIdleLockAlarm({ get: async () => undefined, create });
    expect(create).toHaveBeenCalledWith(IDLE_LOCK_ALARM, { periodInMinutes: 1 });
  });

  it('does not recreate an alarm that already exists', async () => {
    const create = vi.fn();
    await ensureIdleLockAlarm({ get: async () => ({ name: IDLE_LOCK_ALARM }), create });
    expect(create).not.toHaveBeenCalled();
  });
});
