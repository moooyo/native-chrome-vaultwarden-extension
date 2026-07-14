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

  it('caps the row stagger: high-index rows get no animation-delay', async () => {
    const items = Array.from({ length: 15 }, (_, i) => login({ id: `c${i}`, name: `Item ${i}` }));
    const el = await mount({ items });
    const rows = el.shadowRoot!.querySelectorAll<HTMLElement>('.row');
    expect(rows).toHaveLength(15);
    // Early rows still stagger in...
    expect(rows[0]!.getAttribute('style') ?? '').toContain('animation-delay');
    // ...but a row past the cap must not carry a (large) animation-delay that would leave it invisible.
    expect(rows[14]!.getAttribute('style') ?? '').not.toContain('animation-delay');
  });

  it('guards concurrent TOTP loads with an in-flight flag', async () => {
    let calls = 0;
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => { release = r; });
    const extras = {
      getField: async () => ({ ok: false }),
      getCustomField: async () => ({ ok: false }),
      getTotp: async () => { calls++; await gate; return { ok: true, totp: null }; },
      getPasswordHistory: async () => ({ ok: true, history: [] }),
    } as unknown as VwVaultView['extras'];
    const el = await mount({ extras });
    // Two overlapping loads: the second must early-return while the first is still awaiting.
    const first = (el as unknown as { loadTotp(): Promise<void> }).loadTotp();
    const second = (el as unknown as { loadTotp(): Promise<void> }).loadTotp();
    expect(calls).toBe(1);
    release();
    await Promise.all([first, second]);
  });

  it('surfaces a status banner when revealing a secret is refused (no silent failure)', async () => {
    const extras = {
      getField: async () => ({ ok: false }),
      getCustomField: async () => ({ ok: false }),
      getTotp: async () => ({ ok: true, totp: null }),
      getPasswordHistory: async () => ({ ok: true, history: [] }),
    } as unknown as VwVaultView['extras'];
    const el = await mount({ selectedCipherId: 'c1', extras });
    expect(el.shadowRoot!.querySelector('vw-status-message')).toBeNull();
    const eye = el.shadowRoot!.querySelector<HTMLButtonElement>('.icon-sm.eye')!;
    expect(eye).not.toBeNull();
    eye.click();
    // reveal() awaits getField, then sets the status and requests an update.
    await new Promise((r) => setTimeout(r));
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('vw-status-message')).not.toBeNull();
  });

  it('does not show an inline Fill/copy pill for a reprompt-protected suggestion', async () => {
    const el = await mount({
      items: [login({ id: 'c1', reprompt: true })],
      suggestionsState: {
        status: 'ready',
        suggestions: [{ id: 'c1', name: 'Nebula', matchedUri: 'https://nebula.dev', matchType: 0, favorite: false, reprompt: true, target: { frameId: 0, formId: 'f1' } }],
      },
    });
    // A reprompt item cannot be filled/copied inline (the worker refuses), so no such pill is rendered...
    expect(el.shadowRoot!.querySelector('.fill-pill')).toBeNull();
    expect(el.shadowRoot!.querySelector('.row-copy')).toBeNull();
    // ...the row still opens (chevron affordance present) so the user can reach the reprompt flow.
    expect(el.shadowRoot!.querySelector('.chev')).not.toBeNull();
  });
});
