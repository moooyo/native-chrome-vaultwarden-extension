// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './suggestions-view.js';
import type { VwSuggestionsView } from './suggestions-view.js';
import type { SuggestionsUnavailableReason, SuggestionsViewState, FillResult } from '../types.js';
import type { TabAutofillSuggestion, TabFillOutcome, TabSuggestionTarget } from '../../../messaging/protocol.js';

const target: TabSuggestionTarget = { frameId: 0, formId: 'f1' };

function suggestion(overrides: Partial<TabAutofillSuggestion> = {}): TabAutofillSuggestion {
  return {
    id: 's1',
    name: 'Example',
    username: 'alice',
    matchedUri: 'https://example.com',
    matchType: 0,
    favorite: false,
    ...overrides,
  };
}

async function mount(state: SuggestionsViewState, fill: FillResult = {}): Promise<VwSuggestionsView> {
  const el = document.createElement('vw-suggestions-view') as VwSuggestionsView;
  el.state = state;
  el.fill = fill;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

const ALL_UNAVAILABLE: SuggestionsUnavailableReason[] = [
  'no_eligible_tab',
  'site_access_unavailable',
  'restricted_page',
  'content_script_unavailable',
];

const ALL_FILL_OUTCOMES: TabFillOutcome['status'][] = [
  'filled',
  'no_eligible_tab',
  'site_access_unavailable',
  'no_fillable_target',
  'reprompt_required',
  'vault_locked',
  'sync_required',
  'no_longer_matched',
  'target_changed',
  'restricted_page',
  'content_script_unavailable',
];

describe('vw-suggestions-view', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('renders a candidate row with only non-secret data', async () => {
    const el = await mount({ status: 'ready', suggestions: [suggestion({ target })] });
    const text = el.shadowRoot?.textContent ?? '';
    expect(text).toContain('Example');
    expect(text).toContain('alice');
    expect(text).toContain('example.com');
    // The row carries no secret fields at all — assert nothing password/totp-shaped leaks.
    expect(text.toLowerCase()).not.toContain('password');
    expect(text.toLowerCase()).not.toContain('totp');
  });

  it('omits the Fill control when a suggestion has no target', async () => {
    const el = await mount({ status: 'ready', suggestions: [suggestion()] });
    expect(el.shadowRoot?.querySelector('[data-fill]')).toBeNull();
  });

  it('renders Fill and emits vw-suggestion-fill with only cipherId and target', async () => {
    const el = await mount({ status: 'ready', suggestions: [suggestion({ id: 'cip', target })] });
    const filled = vi.fn();
    el.addEventListener('vw-suggestion-fill', filled);
    const fillBtn = el.shadowRoot?.querySelector('[data-fill]');
    expect(fillBtn).not.toBeNull();
    (fillBtn as HTMLButtonElement).click();
    expect(filled).toHaveBeenCalledWith(expect.objectContaining({ detail: { cipherId: 'cip', target } }));
  });

  it('opens the item when the row body is activated', async () => {
    const el = await mount({ status: 'ready', suggestions: [suggestion({ id: 'cip', target })] });
    const opened = vi.fn();
    el.addEventListener('vw-item-open', opened);
    (el.shadowRoot?.querySelector('[data-open]') as HTMLElement).click();
    expect(opened).toHaveBeenCalledWith(expect.objectContaining({ detail: { cipherId: 'cip' } }));
  });

  it('marks the selected suggestion without reflecting its cipher id', async () => {
    const el = await mount({ status: 'ready', suggestions: [suggestion({ id: 'secret-id', target })] });
    el.selectedCipherId = 'secret-id';
    await el.updateComplete;
    const row = el.shadowRoot!.querySelector('[data-open]')!;
    expect(row.getAttribute('aria-selected')).toBe('true');
    expect(el.shadowRoot!.innerHTML).not.toContain('secret-id');
  });

  it.each(ALL_UNAVAILABLE)('maps the %s unavailable reason to neutral (non-danger) guidance', async (reason) => {
    const el = await mount({ status: 'unavailable', reason });
    const status = el.shadowRoot?.querySelector('vw-status-message');
    expect(status).not.toBeNull();
    expect((status?.getAttribute('message') ?? status?.textContent ?? '').length).toBeGreaterThan(0);
    expect(status?.getAttribute('tone')).not.toBe('danger');
  });

  it.each(ALL_FILL_OUTCOMES)('renders a message for the %s fill outcome', async (outcome) => {
    const el = await mount({ status: 'ready', suggestions: [suggestion({ target })] }, { outcome });
    const banners = Array.from(el.shadowRoot?.querySelectorAll('vw-status-message') ?? []);
    const messages = banners.map((b) => b.getAttribute('message') ?? b.textContent ?? '');
    expect(messages.some((m) => m.length > 0)).toBe(true);
  });

  it('renders the fill error message when the request failed', async () => {
    const el = await mount({ status: 'ready', suggestions: [suggestion({ target })] }, { error: 'nope' });
    const banners = Array.from(el.shadowRoot?.querySelectorAll('vw-status-message') ?? []);
    expect(banners.some((b) => (b.getAttribute('message') ?? '').includes('nope'))).toBe(true);
  });

  it('shows a loading status while suggestions resolve', async () => {
    const el = await mount({ status: 'loading' });
    expect(el.shadowRoot?.querySelector('vw-status-message')).not.toBeNull();
  });

  it('shows an error status with the message', async () => {
    const el = await mount({ status: 'error', message: 'boom' });
    const status = el.shadowRoot?.querySelector('vw-status-message');
    expect(status?.getAttribute('tone')).toBe('danger');
    expect(status?.getAttribute('message')).toContain('boom');
  });
});
