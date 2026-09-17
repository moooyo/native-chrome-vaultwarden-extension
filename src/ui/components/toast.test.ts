// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './toast.js';
import type { VwToast } from './toast.js';

async function mount(): Promise<VwToast> {
  const toast = document.createElement('vw-toast');
  toast.message = 'Password copied';
  document.body.append(toast);
  await toast.updateComplete;
  return toast;
}

describe('vw-toast', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    document.body.replaceChildren();
    vi.useRealTimers();
  });

  it('announces the complete receipt and dismisses after three seconds without another action', async () => {
    const toast = await mount();
    const dismissed = vi.fn();
    toast.addEventListener('vw-toast-dismiss', dismissed);
    expect(toast.shadowRoot!.querySelector('[role="status"]')?.textContent).toBe('Password copied');
    expect(toast.shadowRoot!.querySelector('button')).toBeNull();
    await vi.advanceTimersByTimeAsync(2999);
    expect(dismissed).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(dismissed).toHaveBeenCalledOnce();
  });

  it('gives a replacement receipt its own reading time', async () => {
    const toast = await mount();
    const dismissed = vi.fn();
    toast.addEventListener('vw-toast-dismiss', dismissed);
    await vi.advanceTimersByTimeAsync(2500);
    toast.message = 'Username copied';
    await toast.updateComplete;
    await vi.advanceTimersByTimeAsync(500);
    expect(dismissed).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(2500);
    expect(dismissed).toHaveBeenCalledOnce();
  });

  it('cancels stale dismissal when a receipt is cleared or detached', async () => {
    const toast = await mount();
    const dismissed = vi.fn();
    toast.addEventListener('vw-toast-dismiss', dismissed);
    toast.message = '';
    await toast.updateComplete;
    expect(toast.shadowRoot!.querySelector('[role="status"]')).toBeNull();
    await vi.advanceTimersByTimeAsync(3000);
    expect(dismissed).not.toHaveBeenCalled();
    toast.message = 'Saved';
    await toast.updateComplete;
    toast.remove();
    await vi.advanceTimersByTimeAsync(3000);
    expect(dismissed).not.toHaveBeenCalled();
  });
});
