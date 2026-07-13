// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

// The component composes the MiYu i18n module, which imports webextension-polyfill; that throws
// outside an extension, so stub it (matching the project's test convention).
vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) },
      onChanged: { addListener: vi.fn() },
    },
  },
}));

import './vault-view.js';
import type { VwVaultView, CategoryId } from './vault-view.js';
import type { SuggestionsViewState } from '../types.js';
import type { CipherSummary } from '../../../core/vault/models.js';

function login(over: Partial<CipherSummary> = {}): CipherSummary {
  return {
    id: 'c1', name: 'Nebula', username: 'me@x.dev', uris: ['https://nebula.dev'], loginUris: [],
    type: 1, favorite: false, ...over,
  };
}

async function mount(over: Partial<VwVaultView> = {}): Promise<VwVaultView> {
  const el = document.createElement('vw-vault-view') as VwVaultView;
  el.items = [login()];
  el.suggestionsState = { status: 'ready', suggestions: [] } as SuggestionsViewState;
  el.query = '';
  el.category = 'all';
  el.selectedCipherId = null;
  Object.assign(el, over);
  document.body.append(el);
  await el.updateComplete;
  return el;
}

describe('vw-vault-view', () => {
  afterEach(() => document.body.replaceChildren());

  it('renders the search box and five category chips (2FA moved to its own view)', async () => {
    const el = await mount();
    expect(el.shadowRoot?.querySelector('input[type="search"]')).not.toBeNull();
    expect(el.shadowRoot?.querySelectorAll('.chip')).toHaveLength(5);
    expect(el.shadowRoot?.textContent).not.toContain('2FA');
  });

  it('emits vw-search-change on input', async () => {
    const el = await mount();
    const fired = vi.fn();
    el.addEventListener('vw-search-change', fired);
    const input = el.shadowRoot!.querySelector<HTMLInputElement>('input[type="search"]')!;
    input.value = 'neb';
    input.dispatchEvent(new Event('input'));
    expect(fired).toHaveBeenCalledWith(expect.objectContaining({ detail: { query: 'neb' } }));
  });

  it('emits vw-category-change when a chip is clicked', async () => {
    const el = await mount();
    const fired = vi.fn();
    el.addEventListener('vw-category-change', fired);
    el.shadowRoot!.querySelectorAll<HTMLButtonElement>('.chip')[1]!.click();
    const detail = fired.mock.calls[0]![0].detail as { category: CategoryId };
    expect(detail.category).toBe('login');
  });

  it('renders an item row and toggles it open on click', async () => {
    const el = await mount();
    const fired = vi.fn();
    el.addEventListener('vw-item-toggle', fired);
    const row = el.shadowRoot!.querySelector<HTMLElement>('.row')!;
    expect(row.textContent).toContain('Nebula');
    row.click();
    expect(fired).toHaveBeenCalledWith(expect.objectContaining({ detail: { cipherId: 'c1' } }));
  });

  it('shows the passkey marker only for items with a passkey', async () => {
    const withPk = await mount({ items: [login({ hasPasskey: true })] });
    expect(withPk.shadowRoot?.querySelector('.pk')).not.toBeNull();
    withPk.remove();
    const without = await mount({ items: [login()] });
    expect(without.shadowRoot?.querySelector('.pk')).toBeNull();
  });

  it('shows a Fill pill for current-site suggestions and emits vw-suggestion-fill', async () => {
    const el = await mount({
      suggestionsState: {
        status: 'ready',
        suggestions: [{ id: 'c1', name: 'Nebula', matchedUri: 'https://nebula.dev', matchType: 0, favorite: false, target: { frameId: 0, formId: 'f1' } }],
      },
    });
    const fired = vi.fn();
    el.addEventListener('vw-suggestion-fill', fired);
    const pill = el.shadowRoot!.querySelector<HTMLButtonElement>('.fill-pill')!;
    expect(pill).not.toBeNull();
    pill.click();
    expect(fired).toHaveBeenCalledWith(expect.objectContaining({ detail: { cipherId: 'c1', target: { frameId: 0, formId: 'f1' } } }));
  });
});
