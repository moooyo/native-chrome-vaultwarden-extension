import { describe, it, expect, vi } from 'vitest';
import { createAlarmHandlers } from './alarms.js';

describe('background alarms', () => {
  it('touch stores last activity timestamp', async () => {
    let stored: number | undefined;
    const handlers = createAlarmHandlers({
      auth: { lock: vi.fn() },
      idleMs: 1000,
      now: () => 2000,
      getLastActivity: async () => stored,
      setLastActivity: async (n) => { stored = n; },
    });
    await handlers.touch();
    expect(stored).toBe(2000);
  });

  it('locks when idle alarm fires after idle window', async () => {
    const lock = vi.fn(async () => {});
    const handlers = createAlarmHandlers({
      auth: { lock },
      idleMs: 1000,
      now: () => 2501,
      getLastActivity: async () => 1000,
      setLastActivity: async () => {},
    });
    await handlers.handleAlarm('idle-lock');
    expect(lock).toHaveBeenCalledTimes(1);
  });

  it('does not lock for unrelated alarms', async () => {
    const lock = vi.fn(async () => {});
    const handlers = createAlarmHandlers({
      auth: { lock },
      idleMs: 1000,
      now: () => 2501,
      getLastActivity: async () => 1000,
      setLastActivity: async () => {},
    });
    await handlers.handleAlarm('other');
    expect(lock).not.toHaveBeenCalled();
  });
});
