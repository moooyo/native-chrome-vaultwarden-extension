// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './vault-item-row.js';
import type { VwVaultItemRow } from './vault-item-row.js';
import type { CipherSummary } from '../../../core/vault/models.js';

function summary(overrides: Partial<CipherSummary> = {}): CipherSummary {
  return {
    id: 'c1',
    name: 'GitHub',
    uris: ['https://github.com'],
    loginUris: [{ uri: 'https://github.com' }],
    type: 1,
    favorite: false,
    ...overrides,
  };
}

async function mount(item: CipherSummary): Promise<VwVaultItemRow> {
  const el = document.createElement('vw-vault-item-row') as VwVaultItemRow;
  el.item = item;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

describe('vw-vault-item-row', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('renders the item name and a non-secret subtitle', async () => {
    const el = await mount(summary({ username: 'octocat' }));
    const text = el.shadowRoot?.textContent ?? '';
    expect(text).toContain('GitHub');
    expect(text).toContain('octocat');
  });

  it('shows a favorite marker only for favorites', async () => {
    const plain = await mount(summary({ favorite: false }));
    expect(plain.shadowRoot?.querySelector('[data-favorite]')).toBeNull();
    plain.remove();
    const fav = await mount(summary({ favorite: true }));
    expect(fav.shadowRoot?.querySelector('[data-favorite]')).not.toBeNull();
  });

  it('renders a type label per cipher type', async () => {
    for (const [type, label] of [[1, 'Login'], [2, 'Secure note'], [3, 'Card'], [4, 'Identity']] as const) {
      const el = await mount(summary({ type }));
      expect(el.shadowRoot?.textContent).toContain(label);
      el.remove();
    }
  });

  it('emits vw-item-open with the cipher id when activated', async () => {
    const el = await mount(summary({ id: 'abc' }));
    const opened = vi.fn();
    el.addEventListener('vw-item-open', opened);
    el.shadowRoot!.querySelector('button')!.click();
    expect(opened).toHaveBeenCalledWith(expect.objectContaining({ detail: { cipherId: 'abc' } }));
  });

  it('never renders a raw user/vault id inside an HTML attribute', async () => {
    const el = await mount(summary({ id: 'secret-id', name: 'x' }));
    expect(el.shadowRoot?.innerHTML).not.toContain('secret-id');
  });
});
