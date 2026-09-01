import { sendRequest } from '../messaging/protocol.js';
import { isContentTotpClipboardCode } from '../messaging/totp-clipboard-code.js';

export const TOTP_COPY_FAILED_MESSAGE = '无法复制验证码';
export const TOTP_CLEAR_UNSCHEDULED_MESSAGE = '验证码已复制，但未安排自动清理';

export type TotpClipboardCopyOutcome = 'copied' | 'copied_without_clear' | 'not_copied';

export interface TotpClipboardCopyDeps {
  writeText(value: string): Promise<void>;
  scheduleClear(value: string): Promise<{ readonly ok: boolean }>;
}

const DEFAULT_DEPS: TotpClipboardCopyDeps = {
  writeText: async (value) => {
    const clipboard = navigator.clipboard;
    if (!clipboard || typeof clipboard.writeText !== 'function') {
      throw new Error('Clipboard write is unavailable');
    }
    await clipboard.writeText(value);
  },
  scheduleClear: (value) => sendRequest({ type: 'clipboard.scheduleClear', value }),
};

/** Write one TOTP code, then claim owned-clear only after the browser confirms the write. */
export async function copyTotpCodeWithOwnedClear(
  code: string,
  showStatus: (message: string) => void,
  deps: TotpClipboardCopyDeps = DEFAULT_DEPS,
): Promise<TotpClipboardCopyOutcome> {
  if (!isContentTotpClipboardCode(code)) {
    reportStatus(showStatus, TOTP_COPY_FAILED_MESSAGE);
    return 'not_copied';
  }

  try {
    await deps.writeText(code);
  } catch {
    reportStatus(showStatus, TOTP_COPY_FAILED_MESSAGE);
    return 'not_copied';
  }

  try {
    const scheduled = await deps.scheduleClear(code);
    if (scheduled.ok) return 'copied';
  } catch {
    // The clipboard write already succeeded, so this is a clear-scheduling warning, not a copy failure.
  }

  reportStatus(showStatus, TOTP_CLEAR_UNSCHEDULED_MESSAGE);
  return 'copied_without_clear';
}

function reportStatus(showStatus: (message: string) => void, message: string): void {
  try {
    showStatus(message);
  } catch {
    // Copy settlement must not create an unhandled rejection if the page removed the surface.
  }
}
