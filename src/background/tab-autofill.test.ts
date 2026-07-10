import { describe, it, expect, vi } from 'vitest';
import { createTabAutofillCoordinator, type TabAutofillDeps, type BrowserFrame } from './tab-autofill.js';
import type { AutofillCandidate, TabSuggestionTarget } from '../messaging/protocol.js';

function candidate(id: string, overrides: Partial<AutofillCandidate> = {}): AutofillCandidate {
  return { id, name: `Item ${id}`, matchedUri: 'https://example.com', matchType: 0, favorite: false, ...overrides };
}

function makeDeps(overrides: Partial<TabAutofillDeps> = {}): TabAutofillDeps {
  return {
    getTab: vi.fn(async () => ({ active: true, url: 'https://example.com/login' })),
    hasHostAccess: vi.fn(async () => true),
    getFrames: vi.fn(async (): Promise<BrowserFrame[]> => [{ frameId: 0, url: 'https://example.com/login' }]),
    getFrame: vi.fn(async (): Promise<BrowserFrame | undefined> => ({ frameId: 0, url: 'https://example.com/login' })),
    sendToFrame: vi.fn(async () => ({ frameUrl: 'https://example.com/login', forms: [] })),
    findCandidates: vi.fn(async () => []),
    getCredentials: vi.fn(async () => ({})),
    now: vi.fn(() => 1_000_000),
    ...overrides,
  };
}

describe('tab autofill coordinator', () => {
  describe('getSuggestions', () => {
    it('prefers focus newer than 30 seconds, then top frame, then document order', async () => {
      const now = 1_000_000;
      // Tier 1: a recently-focused iframe form outranks the (unfocused) top frame's form.
      const focusedDeps = makeDeps({
        now: () => now,
        getFrames: async () => [
          { frameId: 0, url: 'https://example.com/login' },
          { frameId: 1, url: 'https://example.com/login' },
        ],
        sendToFrame: vi.fn(async (_tabId, frameId) => (frameId === 0
          ? { frameUrl: 'https://example.com/login', forms: [{ formId: 'top-form', visible: true }] }
          : { frameUrl: 'https://example.com/login', forms: [{ formId: 'iframe-form', visible: true, focusedAt: now - 10_000 }] })),
        findCandidates: vi.fn(async () => [candidate('c1')]),
      });
      const focusedOutcome = await createTabAutofillCoordinator(focusedDeps).getSuggestions(7);
      expect(focusedOutcome.status).toBe('ready');
      expect(focusedOutcome.suggestions).toEqual([expect.objectContaining({ id: 'c1', target: { frameId: 1, formId: 'iframe-form' } })]);

      // Tier 2: with no recent focus anywhere, the top frame's form wins over the iframe's.
      const topFrameDeps = makeDeps({
        now: () => now,
        getFrames: async () => [
          { frameId: 0, url: 'https://example.com/login' },
          { frameId: 1, url: 'https://example.com/login' },
        ],
        sendToFrame: vi.fn(async (_tabId, frameId) => (frameId === 0
          ? { frameUrl: 'https://example.com/login', forms: [{ formId: 'top-form', visible: true }] }
          : { frameUrl: 'https://example.com/login', forms: [{ formId: 'iframe-form', visible: true }] })),
        findCandidates: vi.fn(async () => [candidate('c1')]),
      });
      const topFrameOutcome = await createTabAutofillCoordinator(topFrameDeps).getSuggestions(7);
      expect(topFrameOutcome.status).toBe('ready');
      expect(topFrameOutcome.suggestions).toEqual([expect.objectContaining({ id: 'c1', target: { frameId: 0, formId: 'top-form' } })]);

      // Tier 3: two non-top frames, neither focused — the first encountered (document order) wins.
      const orderDeps = makeDeps({
        now: () => now,
        getFrames: async () => [
          { frameId: 1, url: 'https://example.com/login' },
          { frameId: 2, url: 'https://example.com/login' },
        ],
        sendToFrame: vi.fn(async (_tabId, frameId) => (frameId === 1
          ? { frameUrl: 'https://example.com/login', forms: [{ formId: 'first-form', visible: true }] }
          : { frameUrl: 'https://example.com/login', forms: [{ formId: 'second-form', visible: true }] })),
        findCandidates: vi.fn(async () => [candidate('c1')]),
      });
      const orderOutcome = await createTabAutofillCoordinator(orderDeps).getSuggestions(7);
      expect(orderOutcome.status).toBe('ready');
      expect(orderOutcome.suggestions).toEqual([expect.objectContaining({ id: 'c1', target: { frameId: 1, formId: 'first-form' } })]);
    });

    it('deduplicates a cipher and keeps its best fill target', async () => {
      const deps = makeDeps({
        getFrames: async () => [
          { frameId: 0, url: 'https://example.com/login' },
          { frameId: 1, url: 'https://example.com/login' },
        ],
        sendToFrame: vi.fn(async (_tabId, frameId) => (frameId === 0
          ? { frameUrl: 'https://example.com/login', forms: [{ formId: 'top-form', visible: true }] }
          : { frameUrl: 'https://example.com/login', forms: [] })),
        findCandidates: vi.fn(async () => [candidate('c1')]),
      });
      const outcome = await createTabAutofillCoordinator(deps).getSuggestions(7);
      expect(outcome.status).toBe('ready');
      expect(outcome.suggestions).toHaveLength(1);
      expect(outcome.suggestions[0]).toEqual(expect.objectContaining({ id: 'c1', target: { frameId: 0, formId: 'top-form' } }));
    });

    it('keeps top-frame URI matches without a Fill target when no form exists', async () => {
      const deps = makeDeps({
        sendToFrame: vi.fn(async () => ({ frameUrl: 'https://example.com/login', forms: [] })),
        findCandidates: vi.fn(async () => [candidate('c1')]),
      });
      const outcome = await createTabAutofillCoordinator(deps).getSuggestions(7);
      expect(outcome.status).toBe('ready');
      expect(outcome.suggestions).toEqual([candidate('c1')]);
      expect(outcome.suggestions[0]).not.toHaveProperty('target');
    });

    it('returns no credentials in suggestion JSON', async () => {
      const getCredentials = vi.fn(async () => ({ username: 'me', password: 'hunter2', totp: '123456' }));
      const deps = makeDeps({
        findCandidates: vi.fn(async () => [candidate('c1', { username: 'me' })]),
        getCredentials,
      });
      const outcome = await createTabAutofillCoordinator(deps).getSuggestions(7);
      expect(outcome.status).toBe('ready');
      expect(JSON.stringify(outcome)).not.toMatch(/password|totp|credentials/i);
      expect(getCredentials).not.toHaveBeenCalled();
    });

    it('skips one unavailable content frame but reports unavailable when all frames fail', async () => {
      const frames = [
        { frameId: 0, url: 'https://example.com/login' },
        { frameId: 1, url: 'https://example.com/login' },
      ];

      // One frame throws; the other still answers, so the tab is usable.
      const partialFailureDeps = makeDeps({
        getFrames: async () => frames,
        sendToFrame: vi.fn(async (_tabId, frameId) => {
          if (frameId === 0) throw new Error('no receiving end');
          return { frameUrl: 'https://example.com/login', forms: [{ formId: 'form-1', visible: true }] };
        }),
        findCandidates: vi.fn(async () => [candidate('c1')]),
      });
      const partial = await createTabAutofillCoordinator(partialFailureDeps).getSuggestions(7);
      expect(partial.status).toBe('ready');
      expect(partial.suggestions).toEqual([expect.objectContaining({ id: 'c1' })]);

      // Every frame throws: the tab is reported unavailable with no suggestions.
      const totalFailureDeps = makeDeps({
        getFrames: async () => frames,
        sendToFrame: vi.fn(async () => { throw new Error('no receiving end'); }),
        findCandidates: vi.fn(async () => [candidate('c1')]),
      });
      const total = await createTabAutofillCoordinator(totalFailureDeps).getSuggestions(7);
      expect(total).toEqual({ status: 'content_script_unavailable', suggestions: [] });
    });

    it('reports no_eligible_tab when the tab is not the active one', async () => {
      const deps = makeDeps({ getTab: async () => ({ active: false, url: 'https://example.com/' }) });
      await expect(createTabAutofillCoordinator(deps).getSuggestions(7)).resolves.toEqual({ status: 'no_eligible_tab', suggestions: [] });
    });

    it('reports site_access_unavailable when the tab URL is not visible', async () => {
      const deps = makeDeps({ getTab: async () => ({ active: true }) });
      await expect(createTabAutofillCoordinator(deps).getSuggestions(7)).resolves.toEqual({ status: 'site_access_unavailable', suggestions: [] });
    });

    it('reports restricted_page for a browser-internal page', async () => {
      const deps = makeDeps({ getTab: async () => ({ active: true, url: 'chrome://extensions/' }) });
      await expect(createTabAutofillCoordinator(deps).getSuggestions(7)).resolves.toEqual({ status: 'restricted_page', suggestions: [] });
    });

    it('does not consult hasHostAccess for the top frame or same-origin frames', async () => {
      const hasHostAccess = vi.fn(async () => false);
      const deps = makeDeps({
        hasHostAccess,
        getFrames: async () => [{ frameId: 0, url: 'https://example.com/login' }],
      });
      const outcome = await createTabAutofillCoordinator(deps).getSuggestions(7);
      expect(outcome.status).toBe('ready');
      expect(hasHostAccess).not.toHaveBeenCalled();
    });

    it('skips a cross-origin iframe lacking permanent host access', async () => {
      const deps = makeDeps({
        hasHostAccess: vi.fn(async (url: string) => url !== 'https://other-origin.example/widget'),
        getFrames: async () => [
          { frameId: 0, url: 'https://example.com/login' },
          { frameId: 1, url: 'https://other-origin.example/widget' },
        ],
        sendToFrame: vi.fn(async () => ({ frameUrl: 'https://example.com/login', forms: [] })),
      });
      const outcome = await createTabAutofillCoordinator(deps).getSuggestions(7);
      expect(outcome.status).toBe('ready');
      expect(deps.sendToFrame).toHaveBeenCalledTimes(1);
      expect(deps.sendToFrame).toHaveBeenCalledWith(7, 0, { type: 'autofill.inspectFrame' });
    });

    it.each(['about:blank', 'about:srcdoc', 'data:text/html,<h1>hi</h1>', 'blob:https://other-origin.example/1234'])(
      'skips a %s frame before checking hasHostAccess, without aborting otherwise-valid suggestions',
      async (frameUrl) => {
        const hasHostAccess = vi.fn(async () => { throw new Error('Chrome would reject this as an invalid host pattern'); });
        const sendToFrame = vi.fn(async (_tabId: number, frameId: number) => (frameId === 0
          ? { frameUrl: 'https://example.com/login', forms: [{ formId: 'top-form', visible: true }] }
          : { frameUrl, forms: [] }));
        const deps = makeDeps({
          hasHostAccess,
          getFrames: async () => [
            { frameId: 0, url: 'https://example.com/login' },
            { frameId: 1, url: frameUrl },
          ],
          sendToFrame,
          findCandidates: vi.fn(async () => [candidate('c1')]),
        });

        const outcome = await createTabAutofillCoordinator(deps).getSuggestions(7);

        expect(outcome.status).toBe('ready');
        expect(outcome.suggestions).toEqual([expect.objectContaining({ id: 'c1' })]);
        expect(hasHostAccess).not.toHaveBeenCalled();
        expect(sendToFrame).not.toHaveBeenCalledWith(7, 1, expect.anything());
      },
    );

    it('rethrows an unexpected error from a frame instead of silently skipping it', async () => {
      const deps = makeDeps({
        getFrames: async () => [{ frameId: 0, url: 'https://example.com/login' }],
        sendToFrame: vi.fn(async () => { throw new TypeError('candidates is not a function'); }),
      });
      await expect(createTabAutofillCoordinator(deps).getSuggestions(7)).rejects.toThrow('candidates is not a function');
    });
  });

  describe('fill', () => {
    const target: TabSuggestionTarget = { frameId: 0, formId: 'form-1', documentId: 'doc-A' };

    it('re-reads the frame URL before decrypting credentials', async () => {
      const getCredentials = vi.fn(async () => ({ username: 'me', password: 'secret' }));
      const deps = makeDeps({
        getFrame: vi.fn(async () => ({ frameId: 0, url: 'https://fresh.example.com/login', documentId: 'doc-A' })),
        getCredentials,
        sendToFrame: vi.fn(async () => ({ status: 'filled' })),
      });
      await createTabAutofillCoordinator(deps).fill(7, 'c1', target);
      expect(deps.getFrame).toHaveBeenCalledWith(7, 0);
      expect(getCredentials).toHaveBeenCalledWith('c1', 'https://fresh.example.com/login');
      const frameOrder = (deps.getFrame as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0]!;
      const credentialsOrder = getCredentials.mock.invocationCallOrder[0]!;
      expect(frameOrder).toBeLessThan(credentialsOrder);
    });

    it('sends credentials only to the selected frame and returns its typed outcome', async () => {
      const credentials = { username: 'me', password: 'secret' };
      const deps = makeDeps({
        getFrame: vi.fn(async () => ({ frameId: 0, url: 'https://example.com/login', documentId: 'doc-A' })),
        getCredentials: vi.fn(async () => credentials),
        sendToFrame: vi.fn(async () => ({ status: 'filled' })),
      });
      const outcome = await createTabAutofillCoordinator(deps).fill(7, 'c1', target);
      expect(outcome).toEqual({ status: 'filled' });
      expect(deps.sendToFrame).toHaveBeenCalledTimes(1);
      expect(deps.sendToFrame).toHaveBeenCalledWith(7, 0, {
        type: 'autofill.commitLoginFill',
        formId: 'form-1',
        expectedFrameUrl: 'https://example.com/login',
        credentials,
      });
    });

    it('rejects a changed documentId before credential release', async () => {
      const getCredentials = vi.fn(async () => ({ username: 'me', password: 'secret' }));
      const sendToFrame = vi.fn(async () => ({ status: 'filled' }));
      const deps = makeDeps({
        getFrame: vi.fn(async () => ({ frameId: 0, url: 'https://example.com/login', documentId: 'doc-B' })),
        getCredentials,
        sendToFrame,
      });
      const outcome = await createTabAutofillCoordinator(deps).fill(7, 'c1', target);
      expect(outcome).toEqual({ status: 'target_changed' });
      expect(getCredentials).not.toHaveBeenCalled();
      expect(sendToFrame).not.toHaveBeenCalled();
    });

    it('reports no_fillable_target when credential release is denied', async () => {
      const { AppError } = await import('../core/errors.js');
      const deps = makeDeps({
        getFrame: vi.fn(async () => ({ frameId: 0, url: 'https://example.com/login', documentId: 'doc-A' })),
        getCredentials: vi.fn(async () => { throw new AppError('denied', 'Autofill item is not allowed for this page'); }),
      });
      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', target)).resolves.toEqual({ status: 'no_fillable_target' });
    });

    it('reports content_script_unavailable when the target frame no longer exists', async () => {
      const deps = makeDeps({ getFrame: vi.fn(async () => undefined) });
      await expect(createTabAutofillCoordinator(deps).fill(7, 'c1', target)).resolves.toEqual({ status: 'content_script_unavailable' });
    });

    it('denies fill and never releases credentials for a cross-origin iframe lacking host access', async () => {
      const crossOriginTarget: TabSuggestionTarget = { frameId: 1, formId: 'form-1', documentId: 'doc-A' };
      const hasHostAccess = vi.fn(async () => false);
      const getCredentials = vi.fn(async () => ({ username: 'me', password: 'secret' }));
      const sendToFrame = vi.fn(async () => ({ status: 'filled' }));
      const deps = makeDeps({
        getTab: vi.fn(async () => ({ active: true, url: 'https://example.com/login' })),
        getFrame: vi.fn(async () => ({ frameId: 1, url: 'https://other-origin.example/widget', documentId: 'doc-A' })),
        hasHostAccess,
        getCredentials,
        sendToFrame,
      });
      const outcome = await createTabAutofillCoordinator(deps).fill(7, 'c1', crossOriginTarget);
      expect(outcome).toEqual({ status: 'content_script_unavailable' });
      expect(hasHostAccess).toHaveBeenCalledWith('https://other-origin.example/widget');
      expect(getCredentials).not.toHaveBeenCalled();
      expect(sendToFrame).not.toHaveBeenCalled();
    });

    it('allows fill for a cross-origin iframe that does have permanent host access', async () => {
      const crossOriginTarget: TabSuggestionTarget = { frameId: 1, formId: 'form-1', documentId: 'doc-A' };
      const getCredentials = vi.fn(async () => ({ username: 'me', password: 'secret' }));
      const deps = makeDeps({
        getTab: vi.fn(async () => ({ active: true, url: 'https://example.com/login' })),
        getFrame: vi.fn(async () => ({ frameId: 1, url: 'https://other-origin.example/widget', documentId: 'doc-A' })),
        hasHostAccess: vi.fn(async () => true),
        getCredentials,
        sendToFrame: vi.fn(async () => ({ status: 'filled' })),
      });
      const outcome = await createTabAutofillCoordinator(deps).fill(7, 'c1', crossOriginTarget);
      expect(outcome).toEqual({ status: 'filled' });
      expect(getCredentials).toHaveBeenCalledWith('c1', 'https://other-origin.example/widget');
    });

    it.each(['about:blank', 'about:srcdoc', 'data:text/html,<h1>hi</h1>', 'blob:https://other-origin.example/1234'])(
      'denies fill for a %s frame before checking hasHostAccess',
      async (frameUrl) => {
        const skippableTarget: TabSuggestionTarget = { frameId: 1, formId: 'form-1', documentId: 'doc-A' };
        const hasHostAccess = vi.fn(async () => { throw new Error('Chrome would reject this as an invalid host pattern'); });
        const getCredentials = vi.fn(async () => ({ username: 'me', password: 'secret' }));
        const deps = makeDeps({
          getTab: vi.fn(async () => ({ active: true, url: 'https://example.com/login' })),
          getFrame: vi.fn(async () => ({ frameId: 1, url: frameUrl, documentId: 'doc-A' })),
          hasHostAccess,
          getCredentials,
        });
        const outcome = await createTabAutofillCoordinator(deps).fill(7, 'c1', skippableTarget);
        expect(outcome).toEqual({ status: 'content_script_unavailable' });
        expect(hasHostAccess).not.toHaveBeenCalled();
        expect(getCredentials).not.toHaveBeenCalled();
      },
    );

    it('reports no_eligible_tab, site_access_unavailable, and restricted_page before touching the frame', async () => {
      const inactive = makeDeps({ getTab: async () => ({ active: false, url: 'https://example.com/' }) });
      await expect(createTabAutofillCoordinator(inactive).fill(7, 'c1', target)).resolves.toEqual({ status: 'no_eligible_tab' });
      expect(inactive.getFrame).not.toHaveBeenCalled();

      const noAccess = makeDeps({ getTab: async () => ({ active: true }) });
      await expect(createTabAutofillCoordinator(noAccess).fill(7, 'c1', target)).resolves.toEqual({ status: 'site_access_unavailable' });
      expect(noAccess.getFrame).not.toHaveBeenCalled();

      const restricted = makeDeps({ getTab: async () => ({ active: true, url: 'chrome://extensions/' }) });
      await expect(createTabAutofillCoordinator(restricted).fill(7, 'c1', target)).resolves.toEqual({ status: 'restricted_page' });
      expect(restricted.getFrame).not.toHaveBeenCalled();
    });
  });
});
