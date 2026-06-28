import { describe, it, expect, vi } from 'vitest';
import { createAlarmHandlers } from './alarms.js';

describe('background alarms', () => {
  it('touch stores last activity timestamp', async () => {
    let stored: number | undefined;
    const handlers = createAlarmHandlers({
      auth: { lock: vi.fn() },
      getIdleMs: async () => 1000,
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
      getIdleMs: async () => 1000,
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
      getIdleMs: async () => 1000,
      now: () => 2501,
      getLastActivity: async () => 1000,
      setLastActivity: async () => {},
    });
    await handlers.handleAlarm('other');
    expect(lock).not.toHaveBeenCalled();
  });

  // Coverage-only branch tests: production guards already exist; RED evidence is N/A.

  it('does not lock when getLastActivity returns undefined', async () => {
    const lock = vi.fn(async () => {});
    const handlers = createAlarmHandlers({
      auth: { lock },
      getIdleMs: async () => 1000,
      now: () => 99999,
      getLastActivity: async () => undefined,
      setLastActivity: async () => {},
    });
    await handlers.handleAlarm('idle-lock');
    expect(lock).not.toHaveBeenCalled();
  });

  it('does not lock when elapsed equals idleMs (strict > boundary)', async () => {
    const lock = vi.fn(async () => {});
    const handlers = createAlarmHandlers({
      auth: { lock },
      getIdleMs: async () => 1000,
      now: () => 2000,       // elapsed = 2000 - 1000 = 1000, NOT > 1000
      getLastActivity: async () => 1000,
      setLastActivity: async () => {},
    });
    await handlers.handleAlarm('idle-lock');
    expect(lock).not.toHaveBeenCalled();
  });

  it('never idle-locks when getIdleMs returns null (Never / Only on close)', async () => {
    const lock = vi.fn(async () => {});
    const handlers = createAlarmHandlers({
      auth: { lock },
      getIdleMs: async () => null,
      now: () => 99999,
      getLastActivity: async () => 1000,
      setLastActivity: async () => {},
    });
    await handlers.handleAlarm('idle-lock');
    expect(lock).not.toHaveBeenCalled();
  });

  it('reads the configured timeout dynamically on each tick', async () => {
    const lock = vi.fn(async () => {});
    let configured = 30 * 60 * 1000; // 30 min
    const handlers = createAlarmHandlers({
      auth: { lock },
      getIdleMs: async () => configured,
      now: () => 1000 + 20 * 60 * 1000, // 20 min elapsed
      getLastActivity: async () => 1000,
      setLastActivity: async () => {},
    });
    await handlers.handleAlarm('idle-lock');
    expect(lock).not.toHaveBeenCalled(); // 20 min < 30 min
    configured = 5 * 60 * 1000; // user lowers it to 5 min; next tick must honor it
    await handlers.handleAlarm('idle-lock');
    expect(lock).toHaveBeenCalledTimes(1); // 20 min > 5 min
  });
});
