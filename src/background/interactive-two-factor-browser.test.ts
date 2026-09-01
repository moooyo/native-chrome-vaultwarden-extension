import { describe, expect, it, vi } from 'vitest';
import {
  InteractiveTwoFactorBrowser,
  type InteractiveTwoFactorFrameDetails,
  type InteractiveTwoFactorNavigationDetails,
} from './interactive-two-factor-browser.js';

const URL = 'https://vault.example/webauthn-fallback-connector.html?data=abc&v=1';
const OLD_URL = 'https://vault.example/webauthn-fallback-connector.html?data=old&v=1';
const OLD_DOCUMENT = Object.freeze({ tabId: 8, documentId: 'old-doc', url: OLD_URL });
const DOCUMENT = Object.freeze({ tabId: 19, documentId: 'doc-a', url: URL });

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function harness(options: {
  readonly frame?: InteractiveTwoFactorFrameDetails | null | Promise<InteractiveTwoFactorFrameDetails | null>;
  readonly remove?: (tabId: number) => Promise<void>;
  readonly timeout?: number;
} = {}) {
  const listeners = new Set<(details: InteractiveTwoFactorNavigationDetails) => void>();
  const create = vi.fn(async () => ({ id: 19 }));
  const remove = vi.fn(options.remove ?? (async () => undefined));
  const getFrame = vi.fn(async () => await (options.frame ?? null));
  const browser = new InteractiveTwoFactorBrowser({
    tabs: { create, remove },
    webNavigation: {
      getFrame,
      onCommitted: {
        addListener: (listener) => { listeners.add(listener); },
        removeListener: (listener) => { listeners.delete(listener); },
      },
    },
    commitTimeoutMs: options.timeout ?? 100,
  });
  return {
    browser,
    create,
    remove,
    getFrame,
    listeners,
    commit(details: InteractiveTwoFactorNavigationDetails) {
      for (const listener of [...listeners]) listener(details);
    },
  };
}

describe('InteractiveTwoFactorBrowser', () => {
  it('returns only an exact browser-owned committed top-level document', async () => {
    const h = harness({ frame: { documentId: 'doc-a', url: URL } });

    await expect(h.browser.open(URL)).resolves.toEqual({
      tabId: 19,
      documentId: 'doc-a',
      url: URL,
    });
    expect(h.getFrame).toHaveBeenCalledWith({ tabId: 19, frameId: 0 });
    expect(h.listeners.size).toBe(0);
    expect(h.remove).not.toHaveBeenCalled();
  });

  it('closes a replaced tab first and waits for the exact committed event', async () => {
    const frame = deferred<null>();
    const h = harness();
    h.getFrame
      .mockResolvedValueOnce({ documentId: OLD_DOCUMENT.documentId, url: OLD_DOCUMENT.url })
      .mockReturnValueOnce(frame.promise);
    const opened = h.browser.open(URL, OLD_DOCUMENT);
    await vi.waitFor(() => expect(h.create).toHaveBeenCalledOnce());
    expect(h.remove).toHaveBeenCalledWith(8);

    h.commit({ tabId: 19, frameId: 1, documentId: 'child', url: URL });
    h.commit({ tabId: 20, frameId: 0, documentId: 'other-tab', url: URL });
    h.commit({ tabId: 19, frameId: 0, documentId: 'doc-b', url: URL });
    await expect(opened).resolves.toEqual({ tabId: 19, documentId: 'doc-b', url: URL });
    frame.resolve(null);
  });

  it('fails closed without deleting an unowned document on redirect, missing id, or timeout', async () => {
    const redirected = harness({ frame: null });
    const redirectOpen = redirected.browser.open(URL);
    await vi.waitFor(() => expect(redirected.listeners.size).toBe(1));
    redirected.commit({ tabId: 19, frameId: 0, documentId: 'doc', url: 'https://vault.example/login' });
    await expect(redirectOpen).rejects.toThrow(/unexpected URL/);
    expect(redirected.remove).not.toHaveBeenCalled();

    const missing = harness({ frame: { url: URL } });
    await expect(missing.browser.open(URL)).rejects.toThrow(/document id/);
    expect(missing.remove).not.toHaveBeenCalled();

    const timedOut = harness({ frame: null, timeout: 5 });
    await expect(timedOut.browser.open(URL)).rejects.toThrow(/deadline/);
    expect(timedOut.remove).not.toHaveBeenCalled();
  });

  it.each([' ', 'document\u0000id', 'd'.repeat(513)])(
    'fails closed without closing an unowned invalid document id %j',
    async (documentId) => {
      const h = harness({ frame: { documentId, url: URL } });

      await expect(h.browser.open(URL)).rejects.toThrow(/document id/);
      expect(h.remove).not.toHaveBeenCalled();
    },
  );

  it('never opens when an exact replacement document cannot be closed', async () => {
    const replacementFailure = harness({
      frame: { documentId: OLD_DOCUMENT.documentId, url: OLD_DOCUMENT.url },
      remove: async (tabId) => {
        if (tabId === 8) throw new Error('old tab close failed');
      },
    });
    await expect(replacementFailure.browser.open(URL, OLD_DOCUMENT)).rejects.toThrow(/old tab close failed/);
    expect(replacementFailure.create).not.toHaveBeenCalled();
  });

  it('retries settled cleanup once, treats a missing tab as clean, and reports persistent failure', async () => {
    let transientAttempts = 0;
    const transient = harness({
      frame: { documentId: DOCUMENT.documentId, url: DOCUMENT.url },
      remove: async () => {
        transientAttempts += 1;
        if (transientAttempts === 1) throw new Error('temporary close failure');
      },
    });
    await expect(transient.browser.closeAfterSettlement(DOCUMENT)).resolves.toBe(true);
    expect(transient.remove).toHaveBeenCalledTimes(2);

    const missing = harness({ frame: null });
    await expect(missing.browser.closeAfterSettlement(DOCUMENT)).resolves.toBe(true);
    expect(missing.remove).not.toHaveBeenCalled();

    const persistent = harness({
      frame: { documentId: DOCUMENT.documentId, url: DOCUMENT.url },
      remove: async () => { throw new Error('close failed'); },
    });
    await expect(persistent.browser.closeAfterSettlement(DOCUMENT)).rejects.toThrow(/close failed/);
    expect(persistent.remove).toHaveBeenCalledTimes(2);
  });

  it('never closes a tab that navigated away or reused the numeric tab id', async () => {
    const navigated = harness({ frame: { documentId: 'new-doc', url: 'https://example.com/' } });

    await expect(navigated.browser.close(DOCUMENT)).resolves.toBe(false);
    await expect(navigated.browser.closeAfterSettlement(DOCUMENT)).resolves.toBe(false);
    expect(navigated.remove).not.toHaveBeenCalled();
  });
});
