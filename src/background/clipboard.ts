export const CLIPBOARD_CLEAR_ALARM = 'clipboard-clear';

export interface ClipboardDeps {
  getClearSeconds(): Promise<number | null>;
  createAlarm(name: string, delayInMinutes: number): void;
  clearAlarm(name: string): void;
  ensureOffscreen(): Promise<void>;
  sendOffscreen(msg: { type: 'offscreen.clearClipboard' }): Promise<unknown>;
  closeOffscreen(): Promise<void>;
}

export function createClipboard(deps: ClipboardDeps) {
  return {
    /** Schedule (or cancel) the background clipboard clear. A same-named alarm replaces the prior one,
     *  so back-to-back copies collapse to a single clear at the latest deadline. */
    async scheduleClear(): Promise<void> {
      const seconds = await deps.getClearSeconds();
      if (seconds === null) { deps.clearAlarm(CLIPBOARD_CLEAR_ALARM); return; }
      deps.createAlarm(CLIPBOARD_CLEAR_ALARM, Math.max(30, seconds) / 60);
    },
    /** Fired by the alarm: clear the clipboard via the offscreen document, then close it. Failures are swallowed. */
    async handleClipboardAlarm(): Promise<void> {
      try {
        await deps.ensureOffscreen();
        await deps.sendOffscreen({ type: 'offscreen.clearClipboard' });
      } catch {
        /* swallow — re-arming risks a wake loop; the secret exposure is best-effort */
      } finally {
        await deps.closeOffscreen().catch(() => {/* ignore */});
      }
    },
  };
}
