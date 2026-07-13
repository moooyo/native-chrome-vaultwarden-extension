// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from 'vitest';
vi.mock('webextension-polyfill', () => ({ default: { runtime: { onMessage: { addListener: vi.fn() } } } }));
import { clearClipboard, handleOffscreenMessage } from './offscreen.js';

beforeEach(() => { vi.restoreAllMocks(); });

describe('offscreen clipboard clearer', () => {
  it('clears via navigator.clipboard.writeText("") when available', async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    const res = await clearClipboard();
    expect(writeText).toHaveBeenCalledWith('');
    expect(res).toEqual({ ok: true });
  });

  it('falls back to a textarea+execCommand overwrite when writeText throws', async () => {
    vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn(async () => { throw new Error('not focused'); }) } });
    const execCommand = vi.fn(() => true);
    // happy-dom lacks execCommand; stub it on document
    (document as unknown as { execCommand: unknown }).execCommand = execCommand;
    const res = await clearClipboard();
    expect(execCommand).toHaveBeenCalledWith('copy');
    expect(res).toEqual({ ok: true });
  });

  it('ignores non-clear messages', () => {
    expect(handleOffscreenMessage({ type: 'something.else' })).toBeUndefined();
    expect(handleOffscreenMessage({ type: 'offscreen.clearClipboard' })).toBeInstanceOf(Promise);
  });
});
