import type { FocusedFillCommand } from '../messaging/protocol.js';

export const FOCUSED_FILL_COMMAND = 'autofill-focused';

export interface CommandDeps {
  tabs: { sendMessage(tabId: number, message: FocusedFillCommand): Promise<unknown> };
}

/**
 * Relay a browser keyboard command to the active tab's content scripts. The message carries no vault
 * data; the focused leaf frame decides what (if anything) to fill.
 */
export async function handleFocusedFillCommand(
  command: string,
  tab: { id?: number } | undefined,
  deps: CommandDeps,
): Promise<void> {
  if (command !== FOCUSED_FILL_COMMAND) return;
  if (typeof tab?.id !== 'number') return;
  await deps.tabs.sendMessage(tab.id, { type: 'autofill.focusedFill' });
}
