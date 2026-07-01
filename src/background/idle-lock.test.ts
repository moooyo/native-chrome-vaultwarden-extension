import { describe, it, expect, vi } from 'vitest';
import { createIdleLock, type IdleLockDeps, type IdleState } from './idle-lock.js';

function makeDeps(over: Partial<IdleLockDeps> = {}): IdleLockDeps {
  return {
    getConfig: async () => ({ idleSeconds: 900, action: 'lock' }),
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
    expect(deps.lock).toHaveBeenCalledTimes(2);
    expect(deps.logout).not.toHaveBeenCalled();
  });

  it('logs out when action is logout', async () => {
    const deps = makeDeps({ getConfig: async () => ({ idleSeconds: 60, action: 'logout' }) });
    await createIdleLock(deps).onStateChanged('idle');
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
      getConfig: async () => ({ idleSeconds: 60, action: 'logout' }),
      queryState: async (_: number): Promise<IdleState> => 'idle', // backstop reaches applyAction, then hits the guard
    });
    const il = createIdleLock(deps);
    await il.onStateChanged('idle');
    await il.onBackstopAlarm();
    expect(deps.logout).not.toHaveBeenCalled();
    expect(deps.lock).not.toHaveBeenCalled();
  });

  it('ignores idle and locked when disabled (idleSeconds null)', async () => {
    const deps = makeDeps({ getConfig: async () => ({ idleSeconds: null, action: 'lock' }), queryState: vi.fn(async (_: number): Promise<IdleState> => 'active') });
    const il = createIdleLock(deps);
    await il.onStateChanged('idle');
    await il.onStateChanged('locked');
    await il.onBackstopAlarm();
    expect(deps.lock).not.toHaveBeenCalled();
    expect(deps.queryState).not.toHaveBeenCalled();
  });

  it('applyDetection uses idleSeconds (min 15) when enabled and a large sentinel when disabled', async () => {
    const enabled = makeDeps({ getConfig: async () => ({ idleSeconds: 5, action: 'lock' }) });
    await createIdleLock(enabled).applyDetection();
    expect(enabled.setDetectionInterval).toHaveBeenCalledWith(15); // clamped to API minimum
    const on = makeDeps({ getConfig: async () => ({ idleSeconds: 900, action: 'lock' }) });
    await createIdleLock(on).applyDetection();
    expect(on.setDetectionInterval).toHaveBeenCalledWith(900);
    const off = makeDeps({ getConfig: async () => ({ idleSeconds: null, action: 'lock' }) });
    await createIdleLock(off).applyDetection();
    expect(off.setDetectionInterval).toHaveBeenCalledWith(4 * 3600);
  });

  it('backstop alarm queries idle state and acts on idle/locked only', async () => {
    const idle = makeDeps({ queryState: vi.fn(async (_: number): Promise<IdleState> => 'idle') });
    await createIdleLock(idle).onBackstopAlarm();
    expect(idle.lock).toHaveBeenCalledTimes(1);
    const active = makeDeps({ queryState: vi.fn(async (_: number): Promise<IdleState> => 'active') });
    await createIdleLock(active).onBackstopAlarm();
    expect(active.lock).not.toHaveBeenCalled();
  });
});
