// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './vault-filters.js';
import type { VwVaultFilters } from './vault-filters.js';
import type { CipherSummary, CollectionSummary, FolderSummary } from '../../../core/vault/models.js';
import type { OrgPermission } from '../../../core/vault/org-permissions.js';

function summary(overrides: Partial<CipherSummary> = {}): CipherSummary {
  return { id: 'c1', name: 'x', uris: [], loginUris: [], type: 1, favorite: false, ...overrides };
}

interface Props {
  folders?: FolderSummary[];
  collections?: CollectionSummary[];
  orgPermissions?: OrgPermission[];
  items?: CipherSummary[];
  selectedFolderId?: string | null;
  selectedCollectionId?: string | null;
}

async function mount(props: Props = {}): Promise<VwVaultFilters> {
  const el = document.createElement('vw-vault-filters') as VwVaultFilters;
  el.folders = props.folders ?? [];
  el.collections = props.collections ?? [];
  el.orgPermissions = props.orgPermissions ?? [];
  el.items = props.items ?? [];
  el.selectedFolderId = props.selectedFolderId ?? null;
  el.selectedCollectionId = props.selectedCollectionId ?? null;
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwVaultFilters, sel: string): T | null {
  return el.shadowRoot?.querySelector<T>(sel) ?? null;
}

describe('vw-vault-filters folders', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('emits vw-filter-change when the folder selection changes', async () => {
    const el = await mount({ folders: [{ id: 'f1', name: 'Work' }] });
    const changed = vi.fn();
    el.addEventListener('vw-filter-change', changed);
    const select = q<HTMLSelectElement>(el, '[data-folder-filter]')!;
    select.value = 'f1';
    select.dispatchEvent(new Event('change'));
    expect(changed).toHaveBeenCalledWith(expect.objectContaining({ detail: { folderId: 'f1' } }));
  });

  it('offers a No Folder option only when some item has no folder', async () => {
    const withNone = await mount({ folders: [{ id: 'f1', name: 'Work' }], items: [summary()] });
    expect(withNone.shadowRoot?.textContent).toContain('No Folder');
    withNone.remove();
    const allFoldered = await mount({ folders: [{ id: 'f1', name: 'Work' }], items: [summary({ folderId: 'f1' })] });
    expect(allFoldered.shadowRoot?.textContent).not.toContain('No Folder');
  });

  it('creates a folder via vw-folder-mutate', async () => {
    const el = await mount({ folders: [] });
    const mutated = vi.fn();
    el.addEventListener('vw-folder-mutate', mutated);
    q<HTMLButtonElement>(el, '[data-folder-new]')!.click();
    await el.updateComplete;
    const input = q<HTMLInputElement>(el, '[data-folder-name]')!;
    input.value = 'Personal';
    q<HTMLButtonElement>(el, '[data-folder-save]')!.click();
    expect(mutated).toHaveBeenCalledWith(expect.objectContaining({ detail: { op: 'create', name: 'Personal' } }));
  });

  it('exposes rename/delete only for a concrete selected folder', async () => {
    const none = await mount({ folders: [{ id: 'f1', name: 'Work' }], selectedFolderId: null });
    expect(q(none, '[data-folder-rename]')).toBeNull();
    expect(q(none, '[data-folder-delete]')).toBeNull();
    none.remove();
    const chosen = await mount({ folders: [{ id: 'f1', name: 'Work' }], selectedFolderId: 'f1' });
    expect(q(chosen, '[data-folder-rename]')).not.toBeNull();
    const mutated = vi.fn();
    chosen.addEventListener('vw-folder-mutate', mutated);
    q<HTMLButtonElement>(chosen, '[data-folder-delete]')!.click();
    await chosen.updateComplete;
    q<HTMLButtonElement>(chosen, '[data-folder-confirm]')!.click();
    expect(mutated).toHaveBeenCalledWith(expect.objectContaining({ detail: { op: 'delete', id: 'f1' } }));
  });
});

describe('vw-vault-filters collections', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  const manageable: OrgPermission = { id: 'o1', name: 'Acme', canManageCollections: true };
  const readonly: OrgPermission = { id: 'o2', name: 'ReadOnly', canManageCollections: false };

  it('hides the collection bar when there are no collections and no manageable orgs', async () => {
    const el = await mount({ collections: [], orgPermissions: [readonly] });
    expect(q(el, '[data-collection-bar]')).toBeNull();
  });

  it('hides the New collection control when no org is manageable', async () => {
    const el = await mount({
      collections: [{ id: 'col1', name: 'Shared', organizationId: 'o2' }],
      orgPermissions: [readonly],
    });
    expect(q(el, '[data-collection-new]')).toBeNull();
  });

  it('creates a collection in the sole manageable org', async () => {
    const el = await mount({ collections: [], orgPermissions: [manageable] });
    const mutated = vi.fn();
    el.addEventListener('vw-collection-mutate', mutated);
    q<HTMLButtonElement>(el, '[data-collection-new]')!.click();
    await el.updateComplete;
    q<HTMLInputElement>(el, '[data-collection-name]')!.value = 'Ops';
    q<HTMLButtonElement>(el, '[data-collection-save]')!.click();
    expect(mutated).toHaveBeenCalledWith(
      expect.objectContaining({ detail: { op: 'create', organizationId: 'o1', name: 'Ops' } }),
    );
  });

  it('offers an org picker when several orgs are manageable', async () => {
    const el = await mount({
      collections: [],
      orgPermissions: [manageable, { id: 'o3', name: 'Beta', canManageCollections: true }],
    });
    q<HTMLButtonElement>(el, '[data-collection-new]')!.click();
    await el.updateComplete;
    const orgSelect = q<HTMLSelectElement>(el, '[data-collection-org]');
    expect(orgSelect).not.toBeNull();
    const mutated = vi.fn();
    el.addEventListener('vw-collection-mutate', mutated);
    orgSelect!.value = 'o3';
    q<HTMLInputElement>(el, '[data-collection-name]')!.value = 'Team';
    q<HTMLButtonElement>(el, '[data-collection-save]')!.click();
    expect(mutated).toHaveBeenCalledWith(
      expect.objectContaining({ detail: { op: 'create', organizationId: 'o3', name: 'Team' } }),
    );
  });

  it('exposes rename/delete only for a manageable selected collection', async () => {
    const notManageable = await mount({
      collections: [{ id: 'col2', name: 'Shared', organizationId: 'o2' }],
      orgPermissions: [readonly],
      selectedCollectionId: 'col2',
    });
    expect(q(notManageable, '[data-collection-rename]')).toBeNull();
    notManageable.remove();

    const el = await mount({
      collections: [{ id: 'col1', name: 'Ops', organizationId: 'o1' }],
      orgPermissions: [manageable],
      selectedCollectionId: 'col1',
    });
    expect(q(el, '[data-collection-rename]')).not.toBeNull();
    const mutated = vi.fn();
    el.addEventListener('vw-collection-mutate', mutated);
    q<HTMLButtonElement>(el, '[data-collection-delete]')!.click();
    await el.updateComplete;
    q<HTMLButtonElement>(el, '[data-collection-confirm]')!.click();
    expect(mutated).toHaveBeenCalledWith(
      expect.objectContaining({ detail: { op: 'delete', organizationId: 'o1', id: 'col1' } }),
    );
  });

  it('emits vw-filter-change when the collection selection changes', async () => {
    const el = await mount({
      collections: [{ id: 'col1', name: 'Ops', organizationId: 'o1' }],
      orgPermissions: [manageable],
    });
    const changed = vi.fn();
    el.addEventListener('vw-filter-change', changed);
    const select = q<HTMLSelectElement>(el, '[data-collection-filter]')!;
    select.value = 'col1';
    select.dispatchEvent(new Event('change'));
    expect(changed).toHaveBeenCalledWith(expect.objectContaining({ detail: { collectionId: 'col1' } }));
  });
});
