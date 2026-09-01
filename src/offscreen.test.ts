// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from 'vitest';
vi.mock('webextension-polyfill', () => ({ default: { runtime: {
  id: 'extension-id',
  getURL: (path: string) => `chrome-extension://extension-id/${path}`,
  onMessage: { addListener: vi.fn() },
} } }));
import {
  clearClipboardIfOwned,
  handleOffscreenMessage,
  writeClipboard,
  writeSecretClipboard,
} from './offscreen.js';

beforeEach(() => { vi.restoreAllMocks(); });

async function digest(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
}

const workerSender = Object.freeze({
  id: 'extension-id',
  url: 'chrome-extension://extension-id/background.js',
});

describe('offscreen clipboard clearer', () => {
  it('writes only a bounded TOTP value and reports browser failure truthfully', async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    await expect(writeClipboard('123456')).resolves.toEqual({ ok: true, written: true });
    expect(writeText).toHaveBeenCalledWith('123456');
    await expect(writeClipboard('B2CDX')).resolves.toEqual({ ok: true, written: true });
    expect(writeText).toHaveBeenCalledWith('B2CDX');
    await expect(writeClipboard('not-a-code')).resolves.toEqual({
      ok: false,
      error: 'Invalid clipboard value',
    });

    writeText.mockRejectedValueOnce(new Error('denied'));
    (document as unknown as { execCommand: unknown }).execCommand = vi.fn(() => false);
    await expect(writeClipboard('654321')).resolves.toEqual({
      ok: false,
      error: 'Clipboard write was rejected',
    });
  });

  it('accepts only the exact offscreen TOTP write message', async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    const operation = handleOffscreenMessage({
      type: 'offscreen.writeClipboard',
      value: '123456',
    }, workerSender);
    await expect(operation).resolves.toEqual({ ok: true, written: true });
    expect(handleOffscreenMessage({
      type: 'offscreen.writeClipboard',
      value: '123456',
      extra: true,
    }, workerSender)).toBeUndefined();
    expect(handleOffscreenMessage({
      type: 'offscreen.writeClipboard',
      value: '123456',
    }, { ...workerSender, tab: { id: 7 } as never })).toBeUndefined();
  });

  it('accepts bounded generic secrets only from the exact extension worker', async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    await expect(handleOffscreenMessage({
      type: 'offscreen.writeSecretClipboard',
      value: 'ordinary-password',
    }, workerSender)).resolves.toEqual({ ok: true, written: true });
    expect(writeText).toHaveBeenCalledWith('ordinary-password');
    expect(handleOffscreenMessage({
      type: 'offscreen.writeSecretClipboard',
      value: 'ordinary-password',
    }, { ...workerSender, tab: { id: 7 } as never })).toBeUndefined();
    expect(handleOffscreenMessage({
      type: 'offscreen.writeSecretClipboard',
      value: 'ordinary-password',
    }, { ...workerSender, url: 'chrome-extension://extension-id/ui/popup/popup.html' })).toBeUndefined();
    expect(handleOffscreenMessage({
      type: 'offscreen.writeSecretClipboard',
      value: 'ordinary-password',
    }, { ...workerSender, id: 'different-extension' })).toBeUndefined();
  });

  it('rejects oversized and malformed generic secret values', async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    await expect(writeSecretClipboard('x'.repeat(32 * 1_024 + 1))).resolves.toEqual({
      ok: false,
      error: 'Invalid clipboard value',
    });
    await expect(writeSecretClipboard('\ud800')).resolves.toEqual({
      ok: false,
      error: 'Invalid clipboard value',
    });
    expect(writeText).not.toHaveBeenCalled();
  });

  it('clears only when the current clipboard exactly matches the owned value', async () => {
    const readText = vi.fn(async () => 'owned-secret');
    const writeText = vi.fn(async () => {});
    vi.stubGlobal('navigator', { clipboard: { readText, writeText } });
    const expectedDigest = await digest('owned-secret');
    const res = await clearClipboardIfOwned(expectedDigest);
    expect(readText).toHaveBeenCalledOnce();
    expect(writeText).toHaveBeenCalledWith('');
    expect(res).toEqual({ ok: true, cleared: true });
    expect(expectedDigest.every((byte) => byte === 0)).toBe(true);
  });

  it('leaves a newer clipboard value untouched', async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal('navigator', { clipboard: { readText: vi.fn(async () => 'new-user-copy'), writeText } });
    await expect(clearClipboardIfOwned(await digest('old-secret'))).resolves.toEqual({ ok: true, cleared: false });
    expect(writeText).not.toHaveBeenCalled();
  });

  it('uses strict text equality rather than Unicode normalization', async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal('navigator', { clipboard: { readText: vi.fn(async () => 'e\u0301'), writeText } });
    await expect(clearClipboardIfOwned(await digest('\u00e9'))).resolves.toEqual({ ok: true, cleared: false });
    expect(writeText).not.toHaveBeenCalled();
  });

  it('fails closed when clipboard reading is unavailable', async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal('navigator', {
      clipboard: { readText: vi.fn(async () => { throw new Error('denied'); }), writeText },
    });
    await expect(clearClipboardIfOwned(await digest('owned-secret'))).resolves.toEqual({
      ok: false,
      error: 'Clipboard read was rejected',
    });
    expect(writeText).not.toHaveBeenCalled();
  });

  it('falls back to a textarea+execCommand overwrite after a successful ownership check', async () => {
    vi.stubGlobal('navigator', { clipboard: {
      readText: vi.fn(async () => 'owned-secret'),
      writeText: vi.fn(async () => { throw new Error('not focused'); }),
    } });
    const execCommand = vi.fn(() => true);
    // happy-dom lacks execCommand; stub it on document
    (document as unknown as { execCommand: unknown }).execCommand = execCommand;
    const res = await clearClipboardIfOwned(await digest('owned-secret'));
    expect(execCommand).toHaveBeenCalledWith('copy');
    expect(res).toEqual({ ok: true, cleared: true });
  });

  it('reports failure when the execCommand fallback rejects the overwrite', async () => {
    vi.stubGlobal('navigator', { clipboard: {
      readText: vi.fn(async () => 'owned-secret'),
      writeText: vi.fn(async () => { throw new Error('not focused'); }),
    } });
    (document as unknown as { execCommand: unknown }).execCommand = vi.fn(() => false);
    await expect(clearClipboardIfOwned(await digest('owned-secret'))).resolves.toEqual({ ok: false, error: 'Clipboard overwrite was rejected' });
    expect(document.querySelector('textarea')).toBeNull();
  });

  it('accepts only a conditional-clear message with an expected value', () => {
    expect(handleOffscreenMessage({ type: 'something.else' }, workerSender)).toBeUndefined();
    expect(handleOffscreenMessage({ type: 'offscreen.clearClipboard' }, workerSender)).toBeUndefined();
    expect(handleOffscreenMessage({ type: 'offscreen.clearClipboardIfOwned' }, workerSender)).toBeUndefined();
    expect(handleOffscreenMessage({
      type: 'offscreen.clearClipboardIfOwned', expectedDigest: [1, 2, 3],
    }, workerSender)).toBeUndefined();
  });

  it('copies and erases a valid wire digest before comparing it', async () => {
    vi.stubGlobal('navigator', { clipboard: {
      readText: vi.fn(async () => 'owned-secret'),
      writeText: vi.fn(async () => {}),
    } });
    const wireDigest = Array.from(await digest('owned-secret'));
    const result = handleOffscreenMessage({
      type: 'offscreen.clearClipboardIfOwned', expectedDigest: wireDigest,
    }, workerSender);
    expect(result).toBeInstanceOf(Promise);
    expect(wireDigest.every((byte) => byte === 0)).toBe(true);
    await expect(result).resolves.toEqual({ ok: true, cleared: true });
  });

  it('accepts conditional clear only from the exact extension worker', async () => {
    vi.stubGlobal('navigator', { clipboard: {
      readText: vi.fn(async () => 'owned-secret'),
      writeText: vi.fn(async () => {}),
    } });
    const expectedDigest = Array.from(await digest('owned-secret'));
    expect(handleOffscreenMessage({
      type: 'offscreen.clearClipboardIfOwned', expectedDigest: [...expectedDigest],
    })).toBeUndefined();
    expect(handleOffscreenMessage({
      type: 'offscreen.clearClipboardIfOwned', expectedDigest: [...expectedDigest],
    }, { ...workerSender, tab: { id: 7 } as never })).toBeUndefined();
    await expect(handleOffscreenMessage({
      type: 'offscreen.clearClipboardIfOwned', expectedDigest: [...expectedDigest],
    }, workerSender)).resolves.toEqual({ ok: true, cleared: true });
  });
});
