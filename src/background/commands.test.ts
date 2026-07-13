import { describe, expect, it, vi } from 'vitest';
import { handleFocusedFillCommand, FOCUSED_FILL_COMMAND } from './commands.js';

function deps() {
  return { tabs: { sendMessage: vi.fn().mockResolvedValue(undefined) } };
}

describe('handleFocusedFillCommand', () => {
  it('relays the focused-fill command to the active tab', async () => {
    const d = deps();
    await handleFocusedFillCommand(FOCUSED_FILL_COMMAND, { id: 7 }, d);
    expect(d.tabs.sendMessage).toHaveBeenCalledWith(7, { type: 'autofill.focusedFill' });
  });

  it('ignores other command names', async () => {
    const d = deps();
    await handleFocusedFillCommand('something-else', { id: 7 }, d);
    expect(d.tabs.sendMessage).not.toHaveBeenCalled();
  });

  it('ignores calls without a valid tab id', async () => {
    const d = deps();
    await handleFocusedFillCommand(FOCUSED_FILL_COMMAND, undefined, d);
    await handleFocusedFillCommand(FOCUSED_FILL_COMMAND, {}, d);
    expect(d.tabs.sendMessage).not.toHaveBeenCalled();
  });
});
