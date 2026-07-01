import { describe, it, expect, vi } from 'vitest';
import { createClipboard, CLIPBOARD_CLEAR_ALARM, type ClipboardDeps } from './clipboard.js';

function makeDeps(over: Partial<ClipboardDeps> = {}): ClipboardDeps {
  return {
    getClearSeconds: async () => 60,
    createAlarm: vi.fn(),
    clearAlarm: vi.fn(),
    ensureOffscreen: vi.fn(async () => {}),
    sendOffscreen: vi.fn(async () => ({ ok: true })),
    closeOffscreen: vi.fn(async () => {}),
    ...over,
  };
}

describe('createClipboard', () => {
  it('clears any pending alarm when set to never', async () => {
    const deps = makeDeps({ getClearSeconds: async () => null });
    await createClipboard(deps).scheduleClear();
    expect(deps.clearAlarm).toHaveBeenCalledWith(CLIPBOARD_CLEAR_ALARM);
    expect(deps.createAlarm).not.toHaveBeenCalled();
  });

  it('schedules an alarm at max(30, seconds)/60 minutes', async () => {
    const d60 = makeDeps({ getClearSeconds: async () => 60 });
    await createClipboard(d60).scheduleClear();
    expect(d60.createAlarm).toHaveBeenCalledWith(CLIPBOARD_CLEAR_ALARM, 1);
    const d30 = makeDeps({ getClearSeconds: async () => 30 });
    await createClipboard(d30).scheduleClear();
    expect(d30.createAlarm).toHaveBeenCalledWith(CLIPBOARD_CLEAR_ALARM, 0.5);
  });

  it('ensures offscreen, sends clear, then closes (close runs even if send throws)', async () => {
    const order: string[] = [];
    const deps = makeDeps({
      ensureOffscreen: vi.fn(async () => { order.push('ensure'); }),
      sendOffscreen: vi.fn(async () => { order.push('send'); return { ok: true }; }),
      closeOffscreen: vi.fn(async () => { order.push('close'); }),
    });
    await createClipboard(deps).handleClipboardAlarm();
    expect(order).toEqual(['ensure', 'send', 'close']);

    const throwing = makeDeps({ sendOffscreen: vi.fn(async () => { throw new Error('boom'); }) });
    await createClipboard(throwing).handleClipboardAlarm(); // must not reject
    expect(throwing.closeOffscreen).toHaveBeenCalledTimes(1);
  });
});
