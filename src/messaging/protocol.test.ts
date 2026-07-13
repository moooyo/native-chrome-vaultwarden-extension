import { afterEach, describe, expect, it, vi } from 'vitest';
import type { RequestMessage } from './protocol.js';

// Controllable browser.runtime so we can simulate an orphaned content script (extension reloaded):
// `runtime` becomes undefined, or its `.id` goes away, or sendMessage rejects mid-flight.
const runtimeRef = vi.hoisted(() => ({
  current: undefined as undefined | { id?: string; sendMessage?: (m: unknown) => Promise<unknown> },
}));

vi.mock('webextension-polyfill', () => ({
  default: { get runtime() { return runtimeRef.current; } },
}));

import { sendRequest, isExtensionContextAlive } from './protocol.js';

const REQ = { type: 'vault.sync' } as unknown as RequestMessage;

afterEach(() => { runtimeRef.current = undefined; });

describe('sendRequest — orphaned-context resilience', () => {
  it('returns a typed error (no throw) when runtime is gone', async () => {
    runtimeRef.current = undefined;
    await expect(sendRequest(REQ)).resolves.toEqual({ ok: false, error: { code: 'error', message: 'Extension context invalidated' } });
  });

  it('returns a typed error and does not send when runtime.id is missing', async () => {
    const sendMessage = vi.fn();
    runtimeRef.current = { sendMessage };
    const res = await sendRequest(REQ);
    expect(res.ok).toBe(false);
    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('catches a rejected sendMessage (invalidated mid-flight)', async () => {
    runtimeRef.current = { id: 'abc', sendMessage: vi.fn().mockRejectedValue(new Error('Extension context invalidated')) };
    await expect(sendRequest(REQ)).resolves.toEqual({ ok: false, error: { code: 'error', message: 'Extension context invalidated' } });
  });

  it('passes the response through in a live context', async () => {
    const ok = { ok: true, data: null };
    const sendMessage = vi.fn().mockResolvedValue(ok);
    runtimeRef.current = { id: 'abc', sendMessage };
    await expect(sendRequest(REQ)).resolves.toEqual(ok);
    expect(sendMessage).toHaveBeenCalledWith(REQ);
  });
});

describe('isExtensionContextAlive', () => {
  it('is false with no runtime, true once runtime.id is present', () => {
    runtimeRef.current = undefined;
    expect(isExtensionContextAlive()).toBe(false);
    runtimeRef.current = { id: 'abc' };
    expect(isExtensionContextAlive()).toBe(true);
  });
});
