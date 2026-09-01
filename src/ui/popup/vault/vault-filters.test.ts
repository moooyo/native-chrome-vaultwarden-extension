// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) },
      onChanged: { addListener: vi.fn() },
    },
  },
}));
import type { OrgPermission } from '../../../core/vault/org-permissions.js';
import type { CollectionSummary } from '../../../core/vault/models.js';
import { NO_FOLDER } from '../../../core/vault/search.js';
import './vault-filters.js';
import type { VwDialog } from '../../components/dialog.js';
import type { VwToggle } from '../../components/toggle.js';
import {
  PERSONAL_VAULT_FILTER_ID,
  type CollectionMutateDetail,
  type FilterChangeDetail,
  type FolderMutateDetail,
} from '../types.js';
import type { VwVaultFilters } from './vault-filters.js';
import { setLocale } from '../../i18n/index.js';

const folders = [
  { id: 'folder-work', name: 'Work' },
  { id: 'folder-home', name: 'Home' },
] as const;

const collections = [
  { id: 'collection-engineering', name: 'Engineering', organizationId: 'org-admin' },
  { id: 'collection-legal', name: 'Legal', organizationId: 'org-reader' },
] as const;

type CollectionPermissionGates = Pick<OrgPermission,
  'canCreateCollections' | 'canEditCollections' | 'canDeleteCollections'>;

function orgPermission(
  id: string,
  name: string,
  grants: Partial<CollectionPermissionGates> = {},
): OrgPermission {
  const gates: CollectionPermissionGates = {
    canCreateCollections: false,
    canEditCollections: false,
    canDeleteCollections: false,
    ...grants,
  };
  return {
    id,
    name,
    isMember: true,
    isProviderUser: false,
    ...gates,
    canManageCollections: gates.canCreateCollections
      || gates.canEditCollections
      || gates.canDeleteCollections,
  };
}

const orgPermissions = [
  orgPermission('org-admin', 'Acme', {
    canCreateCollections: true,
    canEditCollections: true,
    canDeleteCollections: true,
  }),
  orgPermission('org-reader', 'Read only'),
];

async function mount(overrides: Partial<VwVaultFilters> = {}): Promise<VwVaultFilters> {
  const element = document.createElement('vw-vault-filters') as VwVaultFilters;
  const configuredOrganizations = overrides.orgPermissions ?? orgPermissions;
  const configuredCollections: readonly CollectionSummary[] = overrides.collections ?? collections;
  element.folders = folders;
  element.orgPermissions = configuredOrganizations;
  element.collections = configuredCollections.map((collection): CollectionSummary => {
    const organization = configuredOrganizations.find((entry) => (
      entry.id === collection.organizationId
    ));
    return {
      ...collection,
      canRename: collection.canRename ?? organization?.canEditCollections === true,
      canDelete: collection.canDelete ?? organization?.canDeleteCollections === true,
    };
  });
  const {
    collections: _collections,
    orgPermissions: _orgPermissions,
    ...rest
  } = overrides;
  Object.assign(element, rest);
  document.body.append(element);
  await settle(element);
  return element;
}

async function settle(element: VwVaultFilters): Promise<void> {
  await element.updateComplete;
  const dialog = element.shadowRoot?.querySelector<VwDialog>('vw-dialog');
  await dialog?.updateComplete;
  await element.updateComplete;
}

function query<T extends Element = HTMLElement>(element: VwVaultFilters, selector: string): T {
  const match = element.shadowRoot?.querySelector<T>(selector);
  if (!match) throw new Error(`Missing ${selector}`);
  return match;
}

function listen<Detail>(
  element: VwVaultFilters,
  type: string,
  listener: (event: CustomEvent<Detail>) => void,
): void {
  const eventListener: EventListener = (event) => listener(event as CustomEvent<Detail>);
  element.addEventListener(type, eventListener);
}

async function openCollections(element: VwVaultFilters): Promise<void> {
  query<HTMLButtonElement>(element, '[data-tab="collections"]').click();
  await settle(element);
}

async function openOrganizations(element: VwVaultFilters): Promise<void> {
  query<HTMLButtonElement>(element, '[data-tab="organizations"]').click();
  await settle(element);
}

async function toggleManage(element: VwVaultFilters): Promise<void> {
  const toggle = query<VwToggle>(element, '[data-manage]');
  toggle.shadowRoot?.querySelector<HTMLButtonElement>('button')?.click();
  await settle(element);
}

async function setDialogName(element: VwVaultFilters, name: string): Promise<void> {
  const input = query<HTMLInputElement>(element, '[data-name]');
  input.value = name;
  input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
  await settle(element);
}

beforeEach(() => setLocale('en', false));
afterEach(() => {
  document.body.replaceChildren();
});

describe('vw-vault-filters selection', () => {
  it('accepts items and renders folder and collection membership counts', async () => {
    const element = await mount({
      items: [
        { id: 'a', name: 'A', uris: [], loginUris: [], type: 1, favorite: false, folderId: 'folder-work', collectionIds: ['collection-engineering'] },
        { id: 'b', name: 'B', uris: [], loginUris: [], type: 2, favorite: false },
      ],
    });
    expect(query(element, '[data-folder-id="folder-work"] .row-count').textContent).toBe('1');
    expect(query(element, `[data-folder-id="${NO_FOLDER}"] .row-count`).textContent).toBe('1');
    await openCollections(element);
    expect(query(element, '[data-collection-id="collection-engineering"] .row-count').textContent).toBe('1');
  });

  it('renders a full-width, uncarded tab surface with complete tab relationships', async () => {
    const element = await mount();
    const tabs = [...element.shadowRoot!.querySelectorAll<HTMLButtonElement>('[role="tab"]')];

    expect(tabs).toHaveLength(3);
    expect(tabs[0]?.getAttribute('aria-selected')).toBe('true');
    expect(tabs[0]?.getAttribute('aria-controls')).toBe('folders-panel');
    expect(tabs[0]?.tabIndex).toBe(0);
    expect(tabs[1]?.getAttribute('aria-controls')).toBe('collections-panel');
    expect(tabs[1]?.tabIndex).toBe(-1);
    expect(tabs[2]?.getAttribute('aria-controls')).toBe('organizations-panel');
    expect(tabs[2]?.tabIndex).toBe(-1);
    expect(query(element, '#folders-panel').getAttribute('aria-labelledby')).toBe('folders-tab');
    expect(query<HTMLElement>(element, '#folders-panel').hidden).toBe(false);
    expect(query<HTMLElement>(element, '#collections-panel').hidden).toBe(true);
    expect(query(element, '#organizations-panel').getAttribute('aria-labelledby')).toBe('organizations-tab');
    expect(query<HTMLElement>(element, '#organizations-panel').hidden).toBe(true);
    expect(element.shadowRoot?.querySelector('.card')).toBeNull();
  });

  it('selects No folder with a sparse patch that preserves other facets', async () => {
    const element = await mount({ selectedCollectionId: 'collection-engineering' });
    query<HTMLButtonElement>(element, '[data-tab="folders"]').click();
    await settle(element);
    const changed = vi.fn<(event: CustomEvent<FilterChangeDetail>) => void>();
    listen(element, 'vw-filter-change', changed);

    query<HTMLButtonElement>(element, `[data-folder-id="${NO_FOLDER}"]`).click();

    expect(changed).toHaveBeenCalledWith(expect.objectContaining({
      detail: { folderId: NO_FOLDER },
      bubbles: true,
      composed: true,
    }));
  });

  it('marks a selected folder active and clears it when clicked again', async () => {
    const element = await mount({ selectedFolderId: 'folder-work' });
    const row = query<HTMLButtonElement>(element, '[data-folder-id="folder-work"]');
    const changed = vi.fn<(event: CustomEvent<FilterChangeDetail>) => void>();
    listen(element, 'vw-filter-change', changed);

    expect(row.getAttribute('aria-pressed')).toBe('true');
    expect(row.closest('.filter-row')?.classList.contains('active')).toBe(true);
    row.click();

    expect(changed.mock.calls[0]?.[0].detail).toEqual({ folderId: null });
  });

  it('shows an externally selected collection and clears it when clicked again', async () => {
    const element = await mount({ selectedCollectionId: 'collection-engineering' });
    const row = query<HTMLButtonElement>(element, '[data-collection-id="collection-engineering"]');
    const changed = vi.fn<(event: CustomEvent<FilterChangeDetail>) => void>();
    listen(element, 'vw-filter-change', changed);

    expect(query(element, '[data-tab="collections"]').getAttribute('aria-selected')).toBe('true');
    expect(row.getAttribute('aria-pressed')).toBe('true');
    row.click();

    expect(changed.mock.calls[0]?.[0].detail).toEqual({ collectionId: null });
  });

  it('preserves active facets when switching tabs and supports roving keyboard focus', async () => {
    const element = await mount({ selectedFolderId: 'folder-work' });
    const changed = vi.fn<(event: CustomEvent<FilterChangeDetail>) => void>();
    listen(element, 'vw-filter-change', changed);
    const folderTab = query<HTMLButtonElement>(element, '[data-tab="folders"]');

    folderTab.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
    await settle(element);

    expect(changed).not.toHaveBeenCalled();
    expect(element.selectedFolderId).toBe('folder-work');
    expect(query(element, '[data-tab="collections"]').getAttribute('aria-selected')).toBe('true');
    expect(element.shadowRoot?.activeElement).toBe(query(element, '[data-tab="collections"]'));
  });
});

describe('vw-vault-filters organization selection', () => {
  it('shows personal and confirmed organization counts without surfacing unknown organization ids', async () => {
    const element = await mount({
      items: [
        { id: 'personal', name: 'Personal', uris: [], loginUris: [], type: 1, favorite: false },
        { id: 'admin', name: 'Admin', uris: [], loginUris: [], type: 1, favorite: false, organizationId: 'org-admin' },
        { id: 'reader', name: 'Reader', uris: [], loginUris: [], type: 2, favorite: false, organizationId: 'org-reader' },
        { id: 'unknown', name: 'Unknown', uris: [], loginUris: [], type: 3, favorite: false, organizationId: 'raw-unknown-org-id' },
      ],
    });
    await openOrganizations(element);

    expect(query(element, `[data-organization-id="${PERSONAL_VAULT_FILTER_ID}"] .row-count`).textContent).toBe('1');
    expect(query(element, '[data-organization-id="org-admin"] .row-count').textContent).toBe('1');
    expect(query(element, '[data-organization-id="org-reader"] .row-count').textContent).toBe('1');
    expect(element.shadowRoot?.textContent).toContain('Personal vault');
    expect(element.shadowRoot?.textContent).toContain('Acme');
    expect(element.shadowRoot?.textContent).toContain('Read only');
    expect(element.shadowRoot?.textContent).not.toContain('raw-unknown-org-id');
    expect(element.shadowRoot?.querySelector('[data-manage]')).toBeNull();
    expect(element.shadowRoot?.querySelector('[data-add-collection]')).toBeNull();
  });

  it('emits sparse typed patches for personal and organization filters', async () => {
    const personal = await mount({ selectedOrganizationId: PERSONAL_VAULT_FILTER_ID });
    await openOrganizations(personal);
    const personalChanged = vi.fn<(event: CustomEvent<FilterChangeDetail>) => void>();
    listen(personal, 'vw-filter-change', personalChanged);
    const personalRow = query<HTMLButtonElement>(personal, `[data-organization-id="${PERSONAL_VAULT_FILTER_ID}"]`);

    expect(personalRow.getAttribute('aria-pressed')).toBe('true');
    personalRow.click();
    expect(personalChanged.mock.calls[0]?.[0].detail).toEqual({ organizationId: null });

    personal.remove();
    const organization = await mount();
    await openOrganizations(organization);
    const organizationChanged = vi.fn<(event: CustomEvent<FilterChangeDetail>) => void>();
    listen(organization, 'vw-filter-change', organizationChanged);
    query<HTMLButtonElement>(organization, '[data-organization-id="org-admin"]').click();
    expect(organizationChanged.mock.calls[0]?.[0].detail).toEqual({ organizationId: 'org-admin' });
  });

  it('preserves folder and a same-organization collection when selecting its organization', async () => {
    const element = await mount({
      selectedFolderId: 'folder-work',
      selectedCollectionId: 'collection-engineering',
    });
    await openOrganizations(element);
    const changed = vi.fn<(event: CustomEvent<FilterChangeDetail>) => void>();
    listen(element, 'vw-filter-change', changed);

    query<HTMLButtonElement>(element, '[data-organization-id="org-admin"]').click();

    expect(changed.mock.calls[0]?.[0].detail).toEqual({ organizationId: 'org-admin' });
    expect(element.selectedFolderId).toBe('folder-work');
    expect(element.selectedCollectionId).toBe('collection-engineering');
  });

  it('clears only an incompatible collection when switching organizations', async () => {
    const element = await mount({
      selectedFolderId: 'folder-work',
      selectedOrganizationId: 'org-reader',
      selectedCollectionId: 'collection-legal',
    });
    const changed = vi.fn<(event: CustomEvent<FilterChangeDetail>) => void>();
    listen(element, 'vw-filter-change', changed);

    query<HTMLButtonElement>(element, '[data-organization-id="org-admin"]').click();

    expect(changed.mock.calls[0]?.[0].detail).toEqual({
      organizationId: 'org-admin',
      collectionId: null,
    });
    expect(element.selectedFolderId).toBe('folder-work');
  });

  it('clears collection but preserves folder when selecting Personal vault', async () => {
    const element = await mount({
      selectedFolderId: 'folder-work',
      selectedOrganizationId: 'org-reader',
      selectedCollectionId: 'collection-legal',
    });
    const changed = vi.fn<(event: CustomEvent<FilterChangeDetail>) => void>();
    listen(element, 'vw-filter-change', changed);

    query<HTMLButtonElement>(element, `[data-organization-id="${PERSONAL_VAULT_FILTER_ID}"]`).click();

    expect(changed.mock.calls[0]?.[0].detail).toEqual({
      organizationId: PERSONAL_VAULT_FILTER_ID,
      collectionId: null,
    });
    expect(element.selectedFolderId).toBe('folder-work');
  });

  it('scopes collection choices to the selected organization and shows none for Personal vault', async () => {
    const organization = await mount({ selectedOrganizationId: 'org-admin' });
    await openCollections(organization);
    expect(organization.shadowRoot?.querySelector('[data-collection-id="collection-engineering"]')).not.toBeNull();
    expect(organization.shadowRoot?.querySelector('[data-collection-id="collection-legal"]')).toBeNull();
    expect(query(organization, '#collections-panel').textContent).toContain('Acme');
    expect(query(organization, '#collections-panel').textContent).not.toContain('Read only');

    organization.remove();
    const personal = await mount({ selectedOrganizationId: PERSONAL_VAULT_FILTER_ID });
    await openCollections(personal);
    expect(personal.shadowRoot?.querySelector('[data-collection-id]')).toBeNull();
    expect(query(personal, '#collections-panel').textContent).toContain('No collections');
  });

  it('sets the collection organization while preserving an active folder facet', async () => {
    const element = await mount({ selectedFolderId: 'folder-work' });
    await openCollections(element);
    const changed = vi.fn<(event: CustomEvent<FilterChangeDetail>) => void>();
    listen(element, 'vw-filter-change', changed);

    query<HTMLButtonElement>(element, '[data-collection-id="collection-engineering"]').click();

    expect(changed.mock.calls[0]?.[0].detail).toEqual({
      collectionId: 'collection-engineering',
      organizationId: 'org-admin',
    });
    expect(element.selectedFolderId).toBe('folder-work');
  });

  it('omits unconfirmed and ambiguous organizations and preserves long accessible names', async () => {
    const longName = `Long organization ${'segment '.repeat(30)}`.trim();
    const element = await mount({
      orgPermissions: [
        orgPermission('org-long', longName),
        { ...orgPermission('org-pending', 'Pending'), isMember: false, isProviderUser: false },
        orgPermission('org-duplicate', 'First duplicate'),
        orgPermission('org-duplicate', 'Second duplicate'),
      ],
      collections: [],
      items: [{
        id: 'long-item', name: 'Long', uris: [], loginUris: [], type: 1, favorite: false,
        organizationId: 'org-long',
      }],
    });
    await openOrganizations(element);

    const row = query<HTMLButtonElement>(element, '[data-organization-id="org-long"]');
    const panelText = query(element, '#organizations-panel').textContent ?? '';
    expect(row.title).toBe(longName);
    expect(row.getAttribute('aria-label')).toBe(`${longName}, item count 1`);
    expect(panelText).not.toContain('Pending');
    expect(panelText).not.toContain('duplicate');

    const tab = query<HTMLButtonElement>(element, '[data-tab="organizations"]');
    tab.dispatchEvent(new KeyboardEvent('keydown', { key: 'Home', bubbles: true }));
    await settle(element);
    expect(element.shadowRoot?.activeElement).toBe(query(element, '[data-tab="folders"]'));
  });
});

describe('vw-vault-filters folder management', () => {
  it('keeps management separate from filtering and labels every icon control', async () => {
    const element = await mount();
    const internalToggle = vi.fn();
    element.addEventListener('vw-toggle-change', internalToggle);

    expect(element.shadowRoot?.querySelector('[data-add-folder]')).toBeNull();
    expect(element.shadowRoot?.querySelector('[data-rename-folder]')).toBeNull();
    await toggleManage(element);

    expect(internalToggle).not.toHaveBeenCalled();
    expect(query(element, '[data-add-folder]').getAttribute('aria-label')).toBe('New folder');
    expect(query(element, '[data-rename-folder="folder-work"]').getAttribute('aria-label')).toBe('Rename folder Work');
    expect(query(element, '[data-delete-folder="folder-work"]').getAttribute('aria-label')).toBe('Delete folder Work');
    const toggle = query<VwToggle>(element, '[data-manage]');
    expect(toggle.shadowRoot?.querySelector('button')?.getAttribute('aria-label')).toBe('Manage folders');

    const changed = vi.fn<(event: CustomEvent<FilterChangeDetail>) => void>();
    listen(element, 'vw-filter-change', changed);
    query<HTMLButtonElement>(element, '[data-folder-id="folder-work"]').click();
    expect(changed.mock.calls[0]?.[0].detail).toEqual({ folderId: 'folder-work' });
  });

  it('emits a trimmed, typed create request from the dialog', async () => {
    const element = await mount();
    const mutated = vi.fn<(event: CustomEvent<FolderMutateDetail>) => void>();
    listen(element, 'vw-folder-mutate', mutated);
    await toggleManage(element);

    query<HTMLButtonElement>(element, '[data-add-folder]').click();
    await settle(element);
    expect(query<VwDialog>(element, 'vw-dialog').heading).toBe('New folder');
    expect(query<HTMLInputElement>(element, '[data-name]').getAttribute('required')).not.toBeNull();
    await setDialogName(element, '  Projects  ');
    query<HTMLButtonElement>(element, '[data-dialog-confirm]').click();
    await settle(element);

    expect(mutated).toHaveBeenCalledTimes(1);
    expect(mutated).toHaveBeenCalledWith(expect.objectContaining({
      detail: { op: 'create', name: 'Projects' },
      bubbles: true,
      composed: true,
    }));
  });

  it('emits rename and delete requests without mutating the supplied folders', async () => {
    const renameElement = await mount();
    const renamed = vi.fn<(event: CustomEvent<FolderMutateDetail>) => void>();
    listen(renameElement, 'vw-folder-mutate', renamed);
    await toggleManage(renameElement);
    query<HTMLButtonElement>(renameElement, '[data-rename-folder="folder-work"]').click();
    await settle(renameElement);
    expect(query<HTMLInputElement>(renameElement, '[data-name]').value).toBe('Work');
    await setDialogName(renameElement, 'Office');
    query<HTMLButtonElement>(renameElement, '[data-dialog-confirm]').click();
    await settle(renameElement);

    expect(renamed.mock.calls[0]?.[0].detail).toEqual({ op: 'rename', id: 'folder-work', name: 'Office' });
    expect(folders[0].name).toBe('Work');

    renameElement.remove();
    const deleteElement = await mount();
    const deleted = vi.fn<(event: CustomEvent<FolderMutateDetail>) => void>();
    listen(deleteElement, 'vw-folder-mutate', deleted);
    await toggleManage(deleteElement);
    query<HTMLButtonElement>(deleteElement, '[data-delete-folder="folder-home"]').click();
    await settle(deleteElement);
    expect(query(deleteElement, '.dialog-copy').textContent).toContain('Home');
    query<HTMLButtonElement>(deleteElement, '[data-dialog-confirm]').click();
    await settle(deleteElement);

    expect(deleted.mock.calls[0]?.[0].detail).toEqual({ op: 'delete', id: 'folder-home' });
  });

  it('disables management controls and suppresses mutations while pending', async () => {
    const element = await mount();
    await toggleManage(element);
    element.pending = true;
    await settle(element);
    const mutated = vi.fn();
    element.addEventListener('vw-folder-mutate', mutated);

    expect(query<HTMLButtonElement>(element, '[data-add-folder]').disabled).toBe(true);
    expect(query<HTMLButtonElement>(element, '[data-rename-folder="folder-work"]').disabled).toBe(true);
    query<HTMLButtonElement>(element, '[data-add-folder]').click();
    await settle(element);
    expect(mutated).not.toHaveBeenCalled();
    expect(query<VwDialog>(element, 'vw-dialog').open).toBe(false);
  });
});

describe('vw-vault-filters collection management', () => {
  it.each([
    ['create-only', { canCreateCollections: true }, true, false, false],
    ['edit-only', { canEditCollections: true }, false, true, false],
    ['delete-only', { canDeleteCollections: true }, false, false, true],
    ['none', {}, false, false, false],
  ] as const)(
    'gates every collection action independently for %s permission',
    async (label, grants, canCreate, canEdit, canDelete) => {
      const organizationId = `org-${label}`;
      const collectionId = `collection-${label}`;
      const element = await mount({
        orgPermissions: [orgPermission(organizationId, label, grants)],
        collections: [{ id: collectionId, name: label, organizationId }],
      });
      await openCollections(element);

      const toggle = query<VwToggle>(element, '[data-manage]');
      expect(toggle.disabled).toBe(!canCreate && !canEdit && !canDelete);
      if (!toggle.disabled) await toggleManage(element);

      expect(element.shadowRoot?.querySelector(`[data-add-collection="${organizationId}"]`) !== null)
        .toBe(canCreate);
      expect(element.shadowRoot?.querySelector(`[data-rename-collection="${collectionId}"]`) !== null)
        .toBe(canEdit);
      expect(element.shadowRoot?.querySelector(`[data-delete-collection="${collectionId}"]`) !== null)
        .toBe(canDelete);
    },
  );

  it('gates add, rename, and delete controls per organization while retaining read-only filtering', async () => {
    const element = await mount();
    await openCollections(element);
    await toggleManage(element);

    expect(element.shadowRoot?.querySelectorAll('[data-add-collection]')).toHaveLength(1);
    expect(query(element, '[data-add-collection="org-admin"]').getAttribute('aria-label')).toBe('New collection in Acme');
    expect(element.shadowRoot?.querySelector('[data-add-collection="org-reader"]')).toBeNull();
    expect(element.shadowRoot?.querySelector('[data-rename-collection="collection-engineering"]')).not.toBeNull();
    expect(element.shadowRoot?.querySelector('[data-delete-collection="collection-engineering"]')).not.toBeNull();
    expect(element.shadowRoot?.querySelector('[data-rename-collection="collection-legal"]')).toBeNull();
    expect(element.shadowRoot?.querySelector('[data-delete-collection="collection-legal"]')).toBeNull();

    const changed = vi.fn<(event: CustomEvent<FilterChangeDetail>) => void>();
    listen(element, 'vw-filter-change', changed);
    query<HTMLButtonElement>(element, '[data-collection-id="collection-legal"]').click();
    expect(changed.mock.calls[0]?.[0].detail).toEqual({
      collectionId: 'collection-legal',
      organizationId: 'org-reader',
    });
  });

  it('emits an organization-scoped collection create request', async () => {
    const element = await mount();
    const mutated = vi.fn<(event: CustomEvent<CollectionMutateDetail>) => void>();
    listen(element, 'vw-collection-mutate', mutated);
    await openCollections(element);
    await toggleManage(element);

    query<HTMLButtonElement>(element, '[data-add-collection="org-admin"]').click();
    await settle(element);
    await setDialogName(element, '  Platform  ');
    query<HTMLButtonElement>(element, '[data-dialog-confirm]').click();
    await settle(element);

    expect(mutated).toHaveBeenCalledTimes(1);
    expect(mutated).toHaveBeenCalledWith(expect.objectContaining({
      detail: { op: 'create', organizationId: 'org-admin', name: 'Platform' },
      bubbles: true,
      composed: true,
    }));
  });

  it('emits organization-scoped rename and delete requests', async () => {
    const renameElement = await mount();
    const renamed = vi.fn<(event: CustomEvent<CollectionMutateDetail>) => void>();
    listen(renameElement, 'vw-collection-mutate', renamed);
    await openCollections(renameElement);
    await toggleManage(renameElement);
    query<HTMLButtonElement>(renameElement, '[data-rename-collection="collection-engineering"]').click();
    await settle(renameElement);
    await setDialogName(renameElement, 'Product engineering');
    query<HTMLButtonElement>(renameElement, '[data-dialog-confirm]').click();
    await settle(renameElement);

    expect(renamed.mock.calls[0]?.[0].detail).toEqual({
      op: 'rename',
      organizationId: 'org-admin',
      id: 'collection-engineering',
      name: 'Product engineering',
    });

    renameElement.remove();
    const deleteElement = await mount();
    const deleted = vi.fn<(event: CustomEvent<CollectionMutateDetail>) => void>();
    listen(deleteElement, 'vw-collection-mutate', deleted);
    await openCollections(deleteElement);
    await toggleManage(deleteElement);
    query<HTMLButtonElement>(deleteElement, '[data-delete-collection="collection-engineering"]').click();
    await settle(deleteElement);
    query<HTMLButtonElement>(deleteElement, '[data-dialog-confirm]').click();
    await settle(deleteElement);

    expect(deleted.mock.calls[0]?.[0].detail).toEqual({
      op: 'delete',
      organizationId: 'org-admin',
      id: 'collection-engineering',
    });
  });

  it('disables collection management when no organization grants permission', async () => {
    const element = await mount({
      orgPermissions: [orgPermission('org-reader', 'Read only')],
      collections: [{ id: 'collection-legal', name: 'Legal', organizationId: 'org-reader' }],
    });
    await openCollections(element);
    const toggle = query<VwToggle>(element, '[data-manage]');

    expect(toggle.disabled).toBe(true);
    expect(element.shadowRoot?.textContent).toContain('Not permitted');
    expect(element.shadowRoot?.querySelector('[data-add-collection]')).toBeNull();
    expect(element.shadowRoot?.querySelector('[data-rename-collection]')).toBeNull();
  });
});
