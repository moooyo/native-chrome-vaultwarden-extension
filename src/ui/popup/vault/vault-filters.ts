import { LitElement, css, html, nothing, type PropertyValues, type TemplateResult } from 'lit';
import type { CipherSummary, CollectionSummary, FolderSummary } from '../../../core/vault/models.js';
import type { OrgPermission } from '../../../core/vault/org-permissions.js';
import { NO_FOLDER } from '../../../core/vault/search.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { controlStyles } from '../../components/styles.js';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/dialog.js';
import '../../components/toggle.js';
import type { VwDialog } from '../../components/dialog.js';
import {
  PERSONAL_VAULT_FILTER_ID,
  type CollectionMutateDetail,
  type FilterChangeDetail,
  type FolderMutateDetail,
} from '../types.js';

type FilterTab = 'folders' | 'collections' | 'organizations';

const FILTER_TABS: readonly FilterTab[] = ['folders', 'collections', 'organizations'];

type DialogAction =
  | { kind: 'create-folder' }
  | { kind: 'rename-folder'; folder: FolderSummary }
  | { kind: 'delete-folder'; folder: FolderSummary }
  | { kind: 'create-collection'; organizationId: string; organizationName: string }
  | { kind: 'rename-collection'; collection: CollectionSummary }
  | { kind: 'delete-collection'; collection: CollectionSummary };

interface CollectionGroup {
  organizationId: string;
  organizationName: string;
  canCreate: boolean;
  collections: CollectionSummary[];
}

/**
 * Full-width folder, collection, and organization filter surface for the popup.
 *
 * This view owns only transient presentation state. Filter and mutation requests are emitted to the
 * popup root as typed details; the component never contacts the worker directly.
 */
export class VwVaultFilters extends LitElement {
  static override properties = {
    items: { attribute: false },
    folders: { attribute: false },
    collections: { attribute: false },
    orgPermissions: { attribute: false },
    selectedFolderId: { attribute: false },
    selectedCollectionId: { attribute: false },
    selectedOrganizationId: { attribute: false },
    pending: { type: Boolean },
    activeTab: { state: true },
    manage: { state: true },
    dialogAction: { state: true },
    draftName: { state: true },
  };

  declare items: readonly CipherSummary[];
  declare folders: readonly FolderSummary[];
  declare collections: readonly CollectionSummary[];
  declare orgPermissions: readonly OrgPermission[];
  declare selectedFolderId: string | null;
  declare selectedCollectionId: string | null;
  declare selectedOrganizationId: string | null;
  declare pending: boolean;

  declare activeTab: FilterTab;
  declare manage: boolean;
  declare dialogAction: DialogAction | null;
  declare draftName: string;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.items = [];
    this.folders = [];
    this.collections = [];
    this.orgPermissions = [];
    this.selectedFolderId = null;
    this.selectedCollectionId = null;
    this.selectedOrganizationId = null;
    this.pending = false;
    this.activeTab = 'folders';
    this.manage = false;
    this.dialogAction = null;
    this.draftName = '';
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: block;
        width: 100%;
        min-width: 0;
      }
      .surface {
        width: 100%;
        border-block: 1px solid var(--vw-line-1);
        background: var(--vw-panel);
      }
      .tabs {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        height: 34px;
        border-bottom: 1px solid var(--vw-line-1);
      }
      .tab {
        position: relative;
        min-width: 0;
        border: 0;
        background: transparent;
        color: var(--vw-muted);
        font: 500 12px/1 var(--vw-font-ui);
        cursor: pointer;
      }
      .tab[aria-selected='true'] {
        color: var(--vw-accent);
      }
      .tab[aria-selected='true']::after {
        position: absolute;
        right: 16px;
        bottom: -1px;
        left: 16px;
        height: 2px;
        background: var(--vw-accent);
        content: '';
      }
      .tab:focus-visible,
      .select-button:focus-visible,
      .group-add:focus-visible {
        position: relative;
        z-index: 1;
      }
      .manage-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        min-height: 34px;
        padding: 4px 10px 4px 12px;
        border-bottom: 1px solid var(--vw-line-1);
      }
      .manage-copy {
        min-width: 0;
        color: var(--vw-text-2);
        font-size: 11.5px;
        font-weight: 500;
      }
      .manage-controls {
        display: inline-flex;
        flex: none;
        align-items: center;
        gap: 5px;
      }
      .manage-unavailable {
        margin-left: 6px;
        color: var(--vw-muted);
        font-size: 10.5px;
        font-weight: 400;
      }
      vw-toggle {
        flex: none;
      }
      .panel {
        max-height: 210px;
        overflow-y: auto;
        scrollbar-color: var(--vw-scrollbar) transparent;
        scrollbar-width: thin;
      }
      .panel[hidden] {
        display: none;
      }
      .list {
        margin: 0;
        padding: 0;
        list-style: none;
      }
      .filter-row {
        display: flex;
        align-items: center;
        min-height: 34px;
        border-bottom: 1px solid var(--vw-line-1);
      }
      .filter-row:last-child {
        border-bottom: 0;
      }
      .filter-row.active {
        background: var(--pc);
      }
      .select-button {
        display: flex;
        flex: 1;
        align-items: center;
        gap: 8px;
        min-width: 0;
        min-height: 33px;
        padding: 0 12px;
        border: 0;
        background: transparent;
        color: var(--vw-text-2);
        font: 400 12px/1.2 var(--vw-font-ui);
        text-align: left;
        cursor: pointer;
      }
      .select-button:hover {
        background: var(--vw-row-hover);
      }
      .active .select-button {
        color: var(--onpc);
        font-weight: 500;
      }
      .row-icon {
        display: inline-flex;
        flex: none;
        width: 16px;
        height: 16px;
        color: var(--vw-muted);
      }
      .active .row-icon {
        color: currentColor;
      }
      .row-icon svg {
        width: 16px;
        height: 16px;
      }
      .row-name {
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .row-count {
        flex: none;
        color: var(--vw-muted);
        font-size: 10.5px;
        font-variant-numeric: tabular-nums;
      }
      .active .row-count { color: currentColor; }
      .row-actions {
        display: inline-flex;
        flex: none;
        align-items: center;
        gap: 1px;
        padding-right: 7px;
      }
      .active .row-actions .icon-btn {
        color: var(--onpc);
      }
      .icon-btn:disabled,
      .group-add:disabled {
        opacity: 0.45;
        cursor: default;
      }
      .org-group + .org-group {
        border-top: 1px solid var(--vw-line-2);
      }
      .group-heading {
        display: flex;
        align-items: center;
        justify-content: space-between;
        min-height: 30px;
        padding: 3px 8px 3px 12px;
        background: var(--vw-fill-2);
        color: var(--vw-muted);
        font-size: 10.5px;
        font-weight: 600;
      }
      .group-name {
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .group-add {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 24px;
        height: 24px;
        flex: none;
        border: 0;
        border-radius: var(--vw-radius-small);
        background: transparent;
        color: var(--vw-text-2);
        cursor: pointer;
      }
      .group-add:hover:not(:disabled) {
        background: var(--vw-icon-hover);
      }
      .group-add svg {
        width: 14px;
        height: 14px;
      }
      .empty {
        margin: 0;
        padding: 14px 12px;
        color: var(--vw-muted);
        font-size: 11.5px;
        text-align: center;
      }
      .dialog-form {
        display: grid;
        gap: 7px;
        min-width: min(72vw, 300px);
      }
      .dialog-form label {
        color: var(--vw-text-2);
        font-size: 12px;
        font-weight: 500;
      }
      .dialog-form .input {
        height: 40px;
      }
      .dialog-copy {
        max-width: 300px;
        margin: 0;
        color: var(--vw-text-2);
        font-size: 12.5px;
        overflow-wrap: anywhere;
      }
      vw-dialog > .btn {
        min-height: 34px;
        padding-inline: 14px;
        border-radius: 17px;
        font-size: 12px;
      }
      @media (prefers-reduced-motion: reduce) {
        * {
          scroll-behavior: auto;
        }
      }
    `,
  ];

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (changed.has('selectedOrganizationId') && this.selectedOrganizationId !== null) {
      this.activeTab = 'organizations';
    } else if (changed.has('selectedCollectionId') && this.selectedCollectionId !== null) {
      this.activeTab = 'collections';
    } else if (changed.has('selectedFolderId') && this.selectedFolderId !== null) {
      this.activeTab = 'folders';
    }
    if (this.activeTab === 'organizations'
      || (changed.has('orgPermissions') && this.activeTab === 'collections' && !this.canManageActiveTab)) {
      this.manage = false;
    }
  }

  protected override updated(): void {
    const toggle = this.renderRoot.querySelector('vw-toggle');
    if (!toggle || this.activeTab === 'organizations') return;
    const label = t(this.activeTab === 'folders' ? 'filter.manageFolders' : 'filter.manageCollections');
    toggle?.setAttribute('aria-label', label);
    void toggle?.updateComplete.then(() => {
      toggle.shadowRoot?.querySelector('button')?.setAttribute('aria-label', label);
    });
  }

  private get canManageActiveTab(): boolean {
    if (this.activeTab === 'folders') return true;
    if (this.activeTab === 'organizations') return false;
    return this.orgPermissions.some((org) => org.canCreateCollections)
      || this.collections.some((collection) => (
        collection.canRename === true || collection.canDelete === true
      ));
  }

  private canCreateCollection(organizationId: string): boolean {
    return this.orgPermissions.some((org) => org.id === organizationId && org.canCreateCollections);
  }

  private canEditCollection(collection: CollectionSummary): boolean {
    return collection.canRename === true;
  }

  private canDeleteCollection(collection: CollectionSummary): boolean {
    return collection.canDelete === true;
  }

  private collectionGroups(): CollectionGroup[] {
    const groups = new Map<string, CollectionGroup>();
    for (const org of this.orgPermissions) {
      groups.set(org.id, {
        organizationId: org.id,
        organizationName: org.name,
        canCreate: org.canCreateCollections,
        collections: [],
      });
    }
    for (const collection of this.collections) {
      let group = groups.get(collection.organizationId);
      if (!group) {
        group = {
          organizationId: collection.organizationId,
          organizationName: t('filter.organization'),
          canCreate: false,
          collections: [],
        };
        groups.set(collection.organizationId, group);
      }
      group.collections.push(collection);
    }
    return [...groups.values()];
  }

  private emitFilter(detail: FilterChangeDetail): void {
    emit<FilterChangeDetail>(this, 'vw-filter-change', detail);
  }

  private folderItemCount(folderId: string): number {
    return this.items.filter((item) => (
      folderId === NO_FOLDER ? !item.folderId : item.folderId === folderId
    )).length;
  }

  private collectionItemCount(collectionId: string): number {
    return this.items.filter((item) => item.collectionIds?.includes(collectionId)).length;
  }

  private organizationItemCount(organizationId: string): number {
    return organizationId === PERSONAL_VAULT_FILTER_ID
      ? this.items.filter((item) => !item.organizationId).length
      : this.items.filter((item) => item.organizationId === organizationId).length;
  }

  private selectFolder(folderId: string): void {
    const nextId = this.selectedFolderId === folderId ? null : folderId;
    this.emitFilter({ folderId: nextId } satisfies FilterChangeDetail);
  }

  private selectCollection(collection: CollectionSummary): void {
    if (this.selectedCollectionId === collection.id) {
      this.emitFilter({ collectionId: null } satisfies FilterChangeDetail);
      return;
    }
    this.emitFilter({
      collectionId: collection.id,
      organizationId: collection.organizationId,
    } satisfies FilterChangeDetail);
  }

  private selectOrganization(organizationId: string): void {
    const nextId = this.selectedOrganizationId === organizationId ? null : organizationId;
    const selectedCollections = this.selectedCollectionId === null
      ? []
      : this.collections.filter((collection) => collection.id === this.selectedCollectionId);
    const collectionCompatible = selectedCollections.length === 1
      && selectedCollections[0]!.organizationId === nextId;
    this.emitFilter({
      organizationId: nextId,
      ...(nextId === PERSONAL_VAULT_FILTER_ID
        || (nextId !== null && this.selectedCollectionId !== null && !collectionCompatible)
        ? { collectionId: null }
        : {}),
    } satisfies FilterChangeDetail);
  }

  private selectTab(tab: FilterTab): void {
    if (tab === this.activeTab) return;
    this.activeTab = tab;
    if (!this.canManageActiveTab) this.manage = false;
  }

  private handleTabKeydown(event: KeyboardEvent): void {
    let next: FilterTab | null = null;
    const currentIndex = FILTER_TABS.indexOf(this.activeTab);
    if (event.key === 'ArrowRight') {
      next = FILTER_TABS[(currentIndex + 1) % FILTER_TABS.length]!;
    } else if (event.key === 'ArrowLeft') {
      next = FILTER_TABS[(currentIndex - 1 + FILTER_TABS.length) % FILTER_TABS.length]!;
    } else if (event.key === 'Home') {
      next = FILTER_TABS[0]!;
    } else if (event.key === 'End') {
      next = FILTER_TABS[FILTER_TABS.length - 1]!;
    }
    if (next === null) return;
    event.preventDefault();
    this.selectTab(next);
    void this.updateComplete.then(() => {
      this.renderRoot.querySelector<HTMLButtonElement>(`[data-tab="${next}"]`)?.focus();
    });
  }

  private setManage(event: CustomEvent<{ checked: boolean }>): void {
    event.stopPropagation();
    if (this.pending || !this.canManageActiveTab) return;
    this.manage = event.detail.checked;
    if (!this.manage) this.dismissDialog();
  }

  private openDialog(action: DialogAction): void {
    if (this.pending || !this.manage) return;
    if (action.kind === 'create-collection' && !this.canCreateCollection(action.organizationId)) return;
    if (action.kind === 'rename-collection'
      && !this.canEditCollection(action.collection)) return;
    if (action.kind === 'delete-collection'
      && !this.canDeleteCollection(action.collection)) return;
    this.dialogAction = action;
    this.draftName = action.kind === 'rename-folder'
      ? action.folder.name
      : action.kind === 'rename-collection'
        ? action.collection.name
        : '';
  }

  private dismissDialog(): void {
    this.renderRoot.querySelector<VwDialog>('vw-dialog')?.requestClose('dismiss');
  }

  private handleDialogClose(event: CustomEvent<{ reason: string }>): void {
    event.stopPropagation();
    this.dialogAction = null;
    this.draftName = '';
  }

  private submitDialog(event?: Event): void {
    event?.preventDefault();
    const action = this.dialogAction;
    if (!action || this.pending) return;
    const name = this.draftName.trim();
    switch (action.kind) {
      case 'create-folder':
        if (!name) return;
        emit<FolderMutateDetail>(this, 'vw-folder-mutate', { op: 'create', name } satisfies FolderMutateDetail);
        break;
      case 'rename-folder':
        if (!name) return;
        emit<FolderMutateDetail>(this, 'vw-folder-mutate', {
          op: 'rename', id: action.folder.id, name,
        } satisfies FolderMutateDetail);
        break;
      case 'delete-folder':
        emit<FolderMutateDetail>(this, 'vw-folder-mutate', {
          op: 'delete', id: action.folder.id,
        } satisfies FolderMutateDetail);
        break;
      case 'create-collection':
        if (!name || !this.canCreateCollection(action.organizationId)) return;
        emit<CollectionMutateDetail>(this, 'vw-collection-mutate', {
          op: 'create', organizationId: action.organizationId, name,
        } satisfies CollectionMutateDetail);
        break;
      case 'rename-collection':
        if (!name || !this.canEditCollection(action.collection)) return;
        emit<CollectionMutateDetail>(this, 'vw-collection-mutate', {
          op: 'rename',
          organizationId: action.collection.organizationId,
          id: action.collection.id,
          name,
        } satisfies CollectionMutateDetail);
        break;
      case 'delete-collection':
        if (!this.canDeleteCollection(action.collection)) return;
        emit<CollectionMutateDetail>(this, 'vw-collection-mutate', {
          op: 'delete', organizationId: action.collection.organizationId, id: action.collection.id,
        } satisfies CollectionMutateDetail);
        break;
    }
    this.renderRoot.querySelector<VwDialog>('vw-dialog')?.requestClose('confirm');
  }

  private dialogHeading(): string {
    switch (this.dialogAction?.kind) {
      case 'create-folder': return t('filter.newFolder');
      case 'rename-folder': return t('filter.renameFolder');
      case 'delete-folder': return t('filter.deleteFolder');
      case 'create-collection': return t('filter.newCollection');
      case 'rename-collection': return t('filter.renameCollection');
      case 'delete-collection': return t('filter.deleteCollection');
      default: return '';
    }
  }

  private dialogEntityName(): string {
    const action = this.dialogAction;
    if (!action) return '';
    if ('folder' in action) return action.folder.name;
    if ('collection' in action) return action.collection.name;
    return '';
  }

  private renderDialogBody(): TemplateResult | typeof nothing {
    const action = this.dialogAction;
    if (!action) return nothing;
    const destructive = action.kind === 'delete-folder' || action.kind === 'delete-collection';
    if (destructive) {
      return html`
        <form id="vault-filter-mutation-form" class="dialog-form" @submit=${(event: Event) => this.submitDialog(event)}>
          <p class="dialog-copy">${t(
            action.kind === 'delete-folder' ? 'filter.deleteFolderConfirm' : 'filter.deleteCollectionConfirm',
            { name: this.dialogEntityName() },
          )}</p>
        </form>
      `;
    }
    const nameLabel = t(
      action.kind === 'create-folder' || action.kind === 'rename-folder'
        ? 'filter.folderName'
        : 'filter.collectionName',
    );
    return html`
      <form id="vault-filter-mutation-form" class="dialog-form" @submit=${(event: Event) => this.submitDialog(event)}>
        <label for="vault-filter-name">${nameLabel}</label>
        <input
          id="vault-filter-name"
          class="input"
          data-name
          name="name"
          type="text"
          autocomplete="off"
          required
          autofocus
          .value=${this.draftName}
          ?disabled=${this.pending}
          @input=${(event: Event) => { this.draftName = (event.currentTarget as HTMLInputElement).value; }}
        />
      </form>
    `;
  }

  private renderDialog(): TemplateResult {
    const destructive = this.dialogAction?.kind === 'delete-folder' || this.dialogAction?.kind === 'delete-collection';
    return html`
      <vw-dialog
        .open=${this.dialogAction !== null}
        .heading=${this.dialogHeading()}
        .cancelable=${!this.pending}
        @vw-dialog-close=${(event: CustomEvent<{ reason: string }>) => this.handleDialogClose(event)}
      >
        ${this.renderDialogBody()}
        <button
          type="button"
          slot="actions"
          class="btn ghost"
          data-dialog-cancel
          ?disabled=${this.pending}
          @click=${() => this.dismissDialog()}
        >${t('common.cancel')}</button>
        <button
          type="button"
          slot="actions"
          class=${destructive ? 'btn danger' : 'btn primary'}
          data-dialog-confirm
          ?disabled=${this.pending || (!destructive && !this.draftName.trim())}
          @click=${(event: Event) => this.submitDialog(event)}
        >${t(destructive ? 'common.delete' : 'common.save')}</button>
      </vw-dialog>
    `;
  }

  private renderFolderRow(folder: FolderSummary): TemplateResult {
    const active = this.selectedFolderId === folder.id;
    return html`
      <li class=${active ? 'filter-row active' : 'filter-row'}>
        <button
          type="button"
          class="select-button"
          data-folder-id=${folder.id}
          aria-pressed=${active ? 'true' : 'false'}
          title=${folder.name}
          @click=${() => this.selectFolder(folder.id)}
        >
          <span class="row-icon">${uiIcon('folder')}</span>
          <span class="row-name">${folder.name}</span>
          <span class="row-count">${this.folderItemCount(folder.id)}</span>
        </button>
        ${this.manage
          ? html`
              <span class="row-actions" aria-label=${t('filter.manageFolder', { name: folder.name })}>
                <button type="button" class="icon-btn xs" data-rename-folder=${folder.id} title=${t('filter.renameNamed', { name: folder.name })} aria-label=${t('filter.renameFolderNamed', { name: folder.name })} ?disabled=${this.pending} @click=${() => this.openDialog({ kind: 'rename-folder', folder })}>${uiIcon('edit')}</button>
                <button type="button" class="icon-btn xs" data-delete-folder=${folder.id} title=${t('filter.deleteNamed', { name: folder.name })} aria-label=${t('filter.deleteFolderNamed', { name: folder.name })} ?disabled=${this.pending} @click=${() => this.openDialog({ kind: 'delete-folder', folder })}>${uiIcon('trash')}</button>
              </span>
            `
          : nothing}
      </li>
    `;
  }

  private renderFolders(hidden: boolean): TemplateResult {
    const noFolderActive = this.selectedFolderId === NO_FOLDER;
    return html`
      <div id="folders-panel" class="panel" role="tabpanel" aria-labelledby="folders-tab" ?hidden=${hidden}>
        <ul class="list" aria-label=${t('filter.folders')}>
          <li class=${noFolderActive ? 'filter-row active' : 'filter-row'}>
            <button
              type="button"
              class="select-button"
              data-folder-id=${NO_FOLDER}
              aria-pressed=${noFolderActive ? 'true' : 'false'}
              @click=${() => this.selectFolder(NO_FOLDER)}
            >
              <span class="row-icon">${uiIcon('folder')}</span>
              <span class="row-name">${t('filter.noFolder')}</span>
              <span class="row-count">${this.folderItemCount(NO_FOLDER)}</span>
            </button>
          </li>
          ${this.folders.map((folder) => this.renderFolderRow(folder))}
        </ul>
      </div>
    `;
  }

  private renderCollectionRow(
    collection: CollectionSummary,
    canEdit: boolean,
    canDelete: boolean,
  ): TemplateResult {
    const active = this.selectedCollectionId === collection.id;
    return html`
      <li class=${active ? 'filter-row active' : 'filter-row'}>
        <button
          type="button"
          class="select-button"
          data-collection-id=${collection.id}
          aria-pressed=${active ? 'true' : 'false'}
          title=${collection.name}
          @click=${() => this.selectCollection(collection)}
        >
          <span class="row-icon">${uiIcon('folder')}</span>
          <span class="row-name">${collection.name}</span>
          <span class="row-count">${this.collectionItemCount(collection.id)}</span>
        </button>
        ${this.manage && (canEdit || canDelete)
          ? html`
              <span class="row-actions" aria-label=${t('filter.manageCollection', { name: collection.name })}>
                ${canEdit
                  ? html`<button type="button" class="icon-btn xs" data-rename-collection=${collection.id} title=${t('filter.renameNamed', { name: collection.name })} aria-label=${t('filter.renameCollectionNamed', { name: collection.name })} ?disabled=${this.pending} @click=${() => this.openDialog({ kind: 'rename-collection', collection })}>${uiIcon('edit')}</button>`
                  : nothing}
                ${canDelete
                  ? html`<button type="button" class="icon-btn xs" data-delete-collection=${collection.id} title=${t('filter.deleteNamed', { name: collection.name })} aria-label=${t('filter.deleteCollectionNamed', { name: collection.name })} ?disabled=${this.pending} @click=${() => this.openDialog({ kind: 'delete-collection', collection })}>${uiIcon('trash')}</button>`
                  : nothing}
              </span>
            `
          : nothing}
      </li>
    `;
  }

  private renderCollections(hidden: boolean): TemplateResult {
    const groups = this.selectedOrganizationId === PERSONAL_VAULT_FILTER_ID
      ? []
      : this.collectionGroups().filter((group) => (
          this.selectedOrganizationId === null
          || group.organizationId === this.selectedOrganizationId
        ));
    return html`
      <div id="collections-panel" class="panel" role="tabpanel" aria-labelledby="collections-tab" ?hidden=${hidden}>
        ${groups.length === 0
          ? html`<p class="empty">${t('filter.noCollections')}</p>`
          : groups.map((group, index) => html`
              <section class="org-group" aria-labelledby=${`collection-org-${index}`}>
                <div class="group-heading">
                  <span id=${`collection-org-${index}`} class="group-name" title=${group.organizationName}>${group.organizationName}</span>
                  ${this.manage && group.canCreate
                    ? html`
                        <button
                          type="button"
                          class="group-add"
                          data-add-collection=${group.organizationId}
                          title=${t('filter.newCollectionIn', { name: group.organizationName })}
                          aria-label=${t('filter.newCollectionIn', { name: group.organizationName })}
                          ?disabled=${this.pending}
                          @click=${() => this.openDialog({
                            kind: 'create-collection',
                            organizationId: group.organizationId,
                            organizationName: group.organizationName,
                          })}
                        >${uiIcon('plus')}</button>
                      `
                    : nothing}
                </div>
                ${group.collections.length === 0
                  ? html`<p class="empty">${t('filter.noCollections')}</p>`
                  : html`<ul class="list" aria-label=${t('filter.collectionsIn', { name: group.organizationName })}>
                      ${group.collections.map((collection) => this.renderCollectionRow(
                        collection,
                        collection.canRename === true,
                        collection.canDelete === true,
                      ))}
                    </ul>`}
              </section>
            `)}
      </div>
    `;
  }

  private organizationsForDisplay(): Array<{ id: string; name: string }> {
    const idCounts = new Map<string, number>();
    for (const organization of this.orgPermissions) {
      if (organization.id) idCounts.set(organization.id, (idCounts.get(organization.id) ?? 0) + 1);
    }
    return this.orgPermissions.flatMap((organization) => {
      const name = organization.name.trim();
      const confirmed = organization.isMember !== false || organization.isProviderUser === true;
      return confirmed
        && organization.id.length > 0
        && name.length > 0
        && idCounts.get(organization.id) === 1
        ? [{ id: organization.id, name }]
        : [];
    });
  }

  private renderOrganizationRow(organizationId: string, name: string, icon: 'user' | 'shield'): TemplateResult {
    const active = this.selectedOrganizationId === organizationId;
    const count = this.organizationItemCount(organizationId);
    return html`
      <li class=${active ? 'filter-row active' : 'filter-row'}>
        <button
          type="button"
          class="select-button"
          data-organization-id=${organizationId}
          aria-pressed=${active ? 'true' : 'false'}
          aria-label=${t('filter.organizationItemCount', { name, count })}
          title=${name}
          @click=${() => this.selectOrganization(organizationId)}
        >
          <span class="row-icon">${uiIcon(icon)}</span>
          <span class="row-name">${name}</span>
          <span class="row-count" aria-hidden="true">${count}</span>
        </button>
      </li>
    `;
  }

  private renderOrganizations(hidden: boolean): TemplateResult {
    const organizations = this.organizationsForDisplay();
    return html`
      <div id="organizations-panel" class="panel" role="tabpanel" aria-labelledby="organizations-tab" ?hidden=${hidden}>
        <ul class="list" aria-label=${t('filter.organizations')}>
          ${this.renderOrganizationRow(
            PERSONAL_VAULT_FILTER_ID,
            t('filter.personalVault'),
            'user',
          )}
          ${organizations.map((organization) => this.renderOrganizationRow(
            organization.id,
            organization.name,
            'shield',
          ))}
        </ul>
      </div>
    `;
  }

  protected override render(): TemplateResult {
    const manageLabel = t(this.activeTab === 'folders' ? 'filter.manageFolders' : 'filter.manageCollections');
    return html`
      <section class="surface" aria-label=${t('filter.surfaceLabel')}>
        <div class="tabs" role="tablist" aria-label=${t('filter.byFolderCollectionOrOrganization')}>
          <button
            id="folders-tab"
            type="button"
            class="tab"
            data-tab="folders"
            role="tab"
            aria-selected=${this.activeTab === 'folders' ? 'true' : 'false'}
            aria-controls="folders-panel"
            tabindex=${this.activeTab === 'folders' ? '0' : '-1'}
            @click=${() => this.selectTab('folders')}
            @keydown=${(event: KeyboardEvent) => this.handleTabKeydown(event)}
          >${t('filter.folders')}</button>
          <button
            id="collections-tab"
            type="button"
            class="tab"
            data-tab="collections"
            role="tab"
            aria-selected=${this.activeTab === 'collections' ? 'true' : 'false'}
            aria-controls="collections-panel"
            tabindex=${this.activeTab === 'collections' ? '0' : '-1'}
            @click=${() => this.selectTab('collections')}
            @keydown=${(event: KeyboardEvent) => this.handleTabKeydown(event)}
          >${t('filter.collections')}</button>
          <button
            id="organizations-tab"
            type="button"
            class="tab"
            data-tab="organizations"
            role="tab"
            aria-selected=${this.activeTab === 'organizations' ? 'true' : 'false'}
            aria-controls="organizations-panel"
            tabindex=${this.activeTab === 'organizations' ? '0' : '-1'}
            @click=${() => this.selectTab('organizations')}
            @keydown=${(event: KeyboardEvent) => this.handleTabKeydown(event)}
          >${t('filter.organizations')}</button>
        </div>
        ${this.activeTab === 'organizations'
          ? nothing
          : html`
              <div class="manage-bar">
                <span class="manage-copy">
                  ${manageLabel}
                  ${!this.canManageActiveTab ? html`<span class="manage-unavailable">${t('filter.notPermitted')}</span>` : nothing}
                </span>
                <span class="manage-controls">
                  ${this.manage && this.activeTab === 'folders'
                    ? html`
                        <button
                          type="button"
                          class="group-add"
                          data-add-folder
                          title=${t('filter.newFolder')}
                          aria-label=${t('filter.newFolder')}
                          ?disabled=${this.pending}
                          @click=${() => this.openDialog({ kind: 'create-folder' })}
                        >${uiIcon('plus')}</button>
                      `
                    : nothing}
                  <vw-toggle
                    data-manage
                    size="sm"
                    .checked=${this.manage}
                    .disabled=${this.pending || !this.canManageActiveTab}
                    aria-label=${manageLabel}
                    @vw-toggle-change=${(event: CustomEvent<{ checked: boolean }>) => this.setManage(event)}
                  ></vw-toggle>
                </span>
              </div>
            `}
        ${this.renderFolders(this.activeTab !== 'folders')}
        ${this.renderCollections(this.activeTab !== 'collections')}
        ${this.renderOrganizations(this.activeTab !== 'organizations')}
      </section>
      ${this.renderDialog()}
    `;
  }
}

customElements.define('vw-vault-filters', VwVaultFilters);

declare global {
  interface HTMLElementTagNameMap {
    'vw-vault-filters': VwVaultFilters;
  }
}
