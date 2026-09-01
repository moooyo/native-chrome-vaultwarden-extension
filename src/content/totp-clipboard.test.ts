import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { runtime: { id: 'test-extension', sendMessage: vi.fn() } },
}));

import {
  copyTotpCodeWithOwnedClear,
  TOTP_CLEAR_UNSCHEDULED_MESSAGE,
  TOTP_COPY_FAILED_MESSAGE,
  type TotpClipboardCopyDeps,
} from './totp-clipboard.js';

function deps(overrides: Partial<TotpClipboardCopyDeps> = {}): TotpClipboardCopyDeps {
  return {
    writeText: vi.fn(async () => {}),
    scheduleClear: vi.fn(async () => ({ ok: true })),
    ...overrides,
  };
}

describe('TOTP panel clipboard ownership', () => {
  it('waits for the clipboard write before claiming owned clear', async () => {
    let finishWrite: (() => void) | undefined;
    const writeText = vi.fn(() => new Promise<void>((resolve) => { finishWrite = resolve; }));
    const scheduleClear = vi.fn(async () => ({ ok: true }));
    const showStatus = vi.fn();

    const copying = copyTotpCodeWithOwnedClear('123456', showStatus, deps({ writeText, scheduleClear }));
    await Promise.resolve();
    expect(writeText).toHaveBeenCalledWith('123456');
    expect(scheduleClear).not.toHaveBeenCalled();

    finishWrite?.();
    await expect(copying).resolves.toBe('copied');
    expect(scheduleClear).toHaveBeenCalledWith('123456');
    expect(showStatus).not.toHaveBeenCalled();
  });

  it('does not claim ownership when the clipboard write fails', async () => {
    const scheduleClear = vi.fn(async () => ({ ok: true }));
    const showStatus = vi.fn();

    await expect(copyTotpCodeWithOwnedClear('123456', showStatus, deps({
      writeText: vi.fn(async () => { throw new Error('denied'); }),
      scheduleClear,
    }))).resolves.toBe('not_copied');

    expect(scheduleClear).not.toHaveBeenCalled();
    expect(showStatus).toHaveBeenCalledWith(TOTP_COPY_FAILED_MESSAGE);
  });

  it.each([
    ['a rejected response', vi.fn(async () => ({ ok: false }))],
    ['a transport failure', vi.fn(async () => { throw new Error('worker unavailable'); })],
  ])('reports copied-without-clear after %s', async (_label, scheduleClear) => {
    const showStatus = vi.fn();

    await expect(copyTotpCodeWithOwnedClear(
      '7W6CJ',
      showStatus,
      deps({ scheduleClear }),
    )).resolves.toBe('copied_without_clear');

    expect(showStatus).toHaveBeenCalledWith(TOTP_CLEAR_UNSCHEDULED_MESSAGE);
  });

  it('rejects a non-TOTP value before touching the clipboard', async () => {
    const writeText = vi.fn(async () => {});
    const scheduleClear = vi.fn(async () => ({ ok: true }));
    const showStatus = vi.fn();

    await expect(copyTotpCodeWithOwnedClear(
      'generic-secret',
      showStatus,
      deps({ writeText, scheduleClear }),
    )).resolves.toBe('not_copied');

    expect(writeText).not.toHaveBeenCalled();
    expect(scheduleClear).not.toHaveBeenCalled();
    expect(showStatus).toHaveBeenCalledWith(TOTP_COPY_FAILED_MESSAGE);
  });
});
