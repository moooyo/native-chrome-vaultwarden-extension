// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './all-items-view.js';
import type { VwAllItemsView } from './all-items-view.js';
import type { CipherSummary } from '../../../core/vault/models.js';

function summary(overrides: Partial<CipherSummary> = {}): CipherSummary {
  return { id: 'c1', name: 'GitHub', uris: ['https://github.com'], loginUris: [], type: 1, favorite: false, ...overrides };
}

interface Props {
  items?: CipherSummary[];
  query?: string;
  showTrash?: boolean;
  skippedOrgCount?: number;
  selectedFolderId?: string | null;
  selectedCollectionId?: string | null;
  selectedCipherId?: string | null;
}

async function mount(props: Props = {}): Promise<VwAllItemsView> {
  const el = document.createElement('vw-all-items-view') as VwAllItemsView;
  el.items = props.items ?? [];
  el.folders = [];
  el.collections = [];
  el.orgPermissions = [];
  el.query = props.query ?? '';
  el.showTrash = props.showTrash ?? false;
  el.skippedOrgCount = props.skippedOrgCount ?? 0;
  el.selectedFolderId = props.selectedFolderId ?? null;
  el.selectedCollectionId = props.selectedCollectionId ?? null;
  el.selectedCipherId = props.selectedCipherId ?? null;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function rows(el: VwAllItemsView): Element[] {
  return Array.from(el.shadowRoot?.querySelectorAll('vw-vault-item-row') ?? []);
}

describe('vw-all-items-view', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('renders one row per item using the shared core filter', async () => {
    const el = await mount({
      items: [summary({ id: 'a', name: 'GitHub', uris: [] }), summary({ id: 'b', name: 'GitLab', uris: [] })],
      query: 'hub',
    });
    expect(rows(el)).toHaveLength(1);
  });

  it('shows only trashed items when the trash scope is active', async () => {
    const el = await mount({
      items: [summary({ id: 'a' }), summary({ id: 'b', deletedDate: '2026-01-01' })],
      showTrash: true,
    });
    expect(rows(el)).toHaveLength(1);
  });

  it('excludes trashed items from the main scope', async () => {
    const el = await mount({
      items: [summary({ id: 'a' }), summary({ id: 'b', deletedDate: '2026-01-01' })],
      showTrash: false,
    });
    expect(rows(el)).toHaveLength(1);
  });

  it('emits vw-filter-change with the query on search input', async () => {
    const el = await mount();
    const changed = vi.fn();
    el.addEventListener('vw-filter-change', changed);
    const search = el.shadowRoot!.querySelector<HTMLInputElement>('[data-search]')!;
    search.value = 'git';
    search.dispatchEvent(new Event('input'));
    expect(changed).toHaveBeenCalledWith(expect.objectContaining({ detail: { query: 'git' } }));
  });

  it('toggles trash via vw-filter-change', async () => {
    const el = await mount({ showTrash: false });
    const changed = vi.fn();
    el.addEventListener('vw-filter-change', changed);
    el.shadowRoot!.querySelector<HTMLButtonElement>('[data-trash-toggle]')!.click();
    expect(changed).toHaveBeenCalledWith(expect.objectContaining({ detail: { trash: true } }));
  });

  it('shows the skipped-organization banner only when some org items were skipped', async () => {
    const none = await mount({ skippedOrgCount: 0 });
    expect(none.shadowRoot?.querySelector('[data-org-banner]')).toBeNull();
    none.remove();
    const some = await mount({ skippedOrgCount: 2 });
    const banner = some.shadowRoot?.querySelector('[data-org-banner]');
    expect(banner).not.toBeNull();
    expect(banner?.textContent).toContain('2');
  });

  it('renders the folder/collection filters', async () => {
    const el = await mount();
    expect(el.shadowRoot?.querySelector('vw-vault-filters')).not.toBeNull();
  });

  it('renders an empty state when nothing matches', async () => {
    const el = await mount({ items: [] });
    expect(rows(el)).toHaveLength(0);
    expect(el.shadowRoot?.textContent?.length).toBeGreaterThan(0);
  });

  it('passes selection to the matching row', async () => {
    const el = await mount({ items: [summary({ id: 'a' }), summary({ id: 'b' })], selectedCipherId: 'b' });
    expect((rows(el)[0] as Element & { selected: boolean }).selected).toBe(false);
    expect((rows(el)[1] as Element & { selected: boolean }).selected).toBe(true);
  });

  it('moves row focus with arrow keys without opening an item', async () => {
    const el = await mount({ items: [summary({ id: 'a' }), summary({ id: 'b' })] });
    const opened = vi.fn();
    el.addEventListener('vw-item-open', opened);
    const rowElements = rows(el) as (Element & { shadowRoot: ShadowRoot })[];
    await Promise.all(rowElements.map((row) => (row as unknown as { updateComplete: Promise<boolean> }).updateComplete));
    const first = rowElements[0]!.shadowRoot.querySelector<HTMLButtonElement>('button')!;
    const second = rowElements[1]!.shadowRoot.querySelector<HTMLButtonElement>('button')!;
    const focus = vi.spyOn(second, 'focus');
    first.focus();
    first.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, composed: true }));
    expect(focus).toHaveBeenCalled();
    expect(opened).not.toHaveBeenCalled();
  });
});
