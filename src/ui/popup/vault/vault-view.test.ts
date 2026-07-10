// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './vault-view.js';
import type { VwVaultView } from './vault-view.js';
import type { SuggestionsViewState } from '../types.js';

async function mount(scope: 'suggestions' | 'all', state: SuggestionsViewState): Promise<VwVaultView> {
  const el = document.createElement('vw-vault-view') as VwVaultView;
  el.scope = scope;
  el.suggestionsState = state;
  el.fill = {};
  el.items = [];
  el.folders = [];
  el.collections = [];
  el.orgPermissions = [];
  el.selectedFolderId = null;
  el.selectedCollectionId = null;
  el.query = '';
  el.showTrash = false;
  el.skippedOrgCount = 0;
  el.selectedCipherId = null;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

describe('vw-vault-view', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('defaults to the Suggestions sub-view', async () => {
    const el = await mount('suggestions', { status: 'ready', suggestions: [] });
    expect(el.shadowRoot?.querySelector('vw-suggestions-view')).not.toBeNull();
    expect(el.shadowRoot?.querySelector('vw-all-items-view')).toBeNull();
  });

  it('renders the All items sub-view for the all scope', async () => {
    const el = await mount('all', { status: 'ready', suggestions: [] });
    expect(el.shadowRoot?.querySelector('vw-all-items-view')).not.toBeNull();
    expect(el.shadowRoot?.querySelector('vw-suggestions-view')).toBeNull();
  });

  it('offers both tabs and keeps All items selectable when suggestions are unavailable', async () => {
    const el = await mount('suggestions', { status: 'unavailable', reason: 'restricted_page' });
    const tabs = el.shadowRoot?.querySelector('vw-tabs') as (Element & { tabs: { id: string }[] }) | null;
    expect(tabs).not.toBeNull();
    const ids = tabs!.tabs.map((t) => t.id);
    expect(ids).toContain('suggestions');
    expect(ids).toContain('all');
    // Suggestions still renders its neutral guidance, not a crash.
    expect(el.shadowRoot?.querySelector('vw-suggestions-view')).not.toBeNull();
    const changed = vi.fn();
    el.addEventListener('vw-tab-change', changed);
    tabs!.dispatchEvent(new CustomEvent('vw-tab-change', { detail: { id: 'all' }, bubbles: true, composed: true }));
    expect(changed).toHaveBeenCalled();
  });

  it('passes the suggestions state down to the Suggestions sub-view', async () => {
    const state: SuggestionsViewState = { status: 'loading' };
    const el = await mount('suggestions', state);
    const child = el.shadowRoot?.querySelector('vw-suggestions-view') as (Element & { state: SuggestionsViewState }) | null;
    expect(child?.state).toEqual(state);
  });

  it('passes selectedCipherId to the active sub-view', async () => {
    const el = await mount('suggestions', { status: 'ready', suggestions: [] });
    el.selectedCipherId = 'c1';
    await el.updateComplete;
    const child = el.shadowRoot!.querySelector('vw-suggestions-view') as Element & { selectedCipherId: string | null };
    expect(child.selectedCipherId).toBe('c1');
  });
});
