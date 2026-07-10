import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import { NO_FOLDER } from '../../../core/vault/search.js';
import type { CollectionSummary, FolderSummary } from '../../../core/vault/models.js';
import type { OrgPermission } from '../../../core/vault/org-permissions.js';
import type { CollectionMutateDetail, FilterChangeDetail, FolderMutateDetail } from '../types.js';

type EditorState =
  | { kind: 'folder'; mode: 'create' }
  | { kind: 'folder'; mode: 'rename'; folder: FolderSummary }
  | { kind: 'folder'; mode: 'delete'; folder: FolderSummary }
  | { kind: 'collection'; mode: 'create' }
  | { kind: 'collection'; mode: 'rename'; collection: CollectionSummary }
  | { kind: 'collection'; mode: 'delete'; collection: CollectionSummary };

/**
 * Folder and collection selection + management. Selection changes emit `vw-filter-change` patches;
 * create/rename/delete emit `vw-folder-mutate`/`vw-collection-mutate` for the root to perform. The
 * component only reads the pre-computed `OrgPermission.canManageCollections` gate (fail-closed in the
 * worker) to decide which management affordances to show — it never re-derives permission logic.
 */
export class VwVaultFilters extends LitElement {
  static override properties = {
    folders: { attribute: false },
    collections: { attribute: false },
    orgPermissions: { attribute: false },
    items: { attribute: false },
    selectedFolderId: { attribute: false },
    selectedCollectionId: { attribute: false },
  };

  declare folders: FolderSummary[];
  declare collections: CollectionSummary[];
  declare orgPermissions: OrgPermission[];
  declare items: { folderId?: string }[];
  declare selectedFolderId: string | null;
  declare selectedCollectionId: string | null;
  private editor: EditorState | null = null;

  constructor() {
    super();
    this.folders = [];
    this.collections = [];
    this.orgPermissions = [];
    this.items = [];
    this.selectedFolderId = null;
    this.selectedCollectionId = null;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: block;
      }
      .bar {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 4px 0;
      }
      .select-wrap {
        display: flex;
        align-items: center;
        gap: 6px;
        flex: 1;
        min-width: 0;
      }
      .select-wrap .select {
        flex: 1;
        min-width: 0;
      }
      .glyph {
        color: var(--vw-muted);
        display: inline-flex;
      }
      .glyph svg {
        width: 16px;
        height: 16px;
      }
      .actions {
        display: flex;
        gap: 2px;
      }
      .edit-row {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 4px 0 8px;
      }
      .edit-row .input,
      .edit-row .select {
        flex: 1;
        min-width: 0;
      }
      .muted {
        color: var(--vw-muted);
        font-size: 12px;
      }
      .button.danger {
        border-color: var(--vw-danger);
        color: var(--vw-danger);
      }
    `,
  ];

  private get manageableOrgs(): OrgPermission[] {
    return this.orgPermissions.filter((o) => o.canManageCollections);
  }

  private isManageableCollection(collection: CollectionSummary): boolean {
    return this.manageableOrgs.some((o) => o.id === collection.organizationId);
  }

  private emitFilter(patch: FilterChangeDetail): void {
    this.dispatchEvent(new CustomEvent<FilterChangeDetail>('vw-filter-change', { detail: patch, bubbles: true, composed: true }));
  }

  private emitFolderMutate(detail: FolderMutateDetail): void {
    this.dispatchEvent(new CustomEvent<FolderMutateDetail>('vw-folder-mutate', { detail, bubbles: true, composed: true }));
  }

  private emitCollectionMutate(detail: CollectionMutateDetail): void {
    this.dispatchEvent(new CustomEvent<CollectionMutateDetail>('vw-collection-mutate', { detail, bubbles: true, composed: true }));
  }

  private closeEditor(): void {
    this.editor = null;
    this.requestUpdate();
  }

  private openEditor(editor: EditorState): void {
    this.editor = editor;
    this.requestUpdate();
  }

  private inputValue(selector: string): string {
    const el = this.shadowRoot?.querySelector(selector);
    return el instanceof HTMLInputElement ? el.value.trim() : '';
  }

  private selectValue(selector: string): string {
    const el = this.shadowRoot?.querySelector(selector);
    return el instanceof HTMLSelectElement ? el.value : '';
  }

  private submitFolder(mode: 'create' | 'rename', folder?: FolderSummary): void {
    const name = this.inputValue('[data-folder-name]');
    if (!name) return;
    if (mode === 'rename' && folder) this.emitFolderMutate({ op: 'rename', id: folder.id, name });
    else this.emitFolderMutate({ op: 'create', name });
    this.closeEditor();
  }

  private submitCollection(mode: 'create' | 'rename', collection?: CollectionSummary): void {
    const name = this.inputValue('[data-collection-name]');
    if (!name) return;
    if (mode === 'rename' && collection) {
      this.emitCollectionMutate({ op: 'rename', organizationId: collection.organizationId, id: collection.id, name });
    } else {
      const orgs = this.manageableOrgs;
      const organizationId = orgs.length === 1 ? orgs[0]!.id : this.selectValue('[data-collection-org]');
      if (!organizationId) return;
      this.emitCollectionMutate({ op: 'create', organizationId, name });
    }
    this.closeEditor();
  }

  private renderFolderBar() {
    const hasNoFolderItems = this.items.some((i) => !i.folderId);
    const showSelect = this.folders.length > 0 || hasNoFolderItems;
    const concrete = this.selectedFolderId !== null && this.selectedFolderId !== NO_FOLDER
      && this.folders.some((f) => f.id === this.selectedFolderId);
    const selectedFolder = this.folders.find((f) => f.id === this.selectedFolderId);
    return html`
      <div class="bar">
        ${showSelect
          ? html`
              <span class="select-wrap">
                <span class="glyph">${uiIcon('folder')}</span>
                <select
                  class="select"
                  data-folder-filter
                  aria-label="Filter by folder"
                  .value=${this.selectedFolderId ?? ''}
                  @change=${(e: Event) => {
                    const v = (e.target as HTMLSelectElement).value;
                    this.closeEditor();
                    this.emitFilter({ folderId: v === '' ? null : v });
                  }}
                >
                  <option value="">All folders</option>
                  ${this.folders.map((f) => html`<option value=${f.id} ?selected=${f.id === this.selectedFolderId}>${f.name}</option>`)}
                  ${hasNoFolderItems ? html`<option value=${NO_FOLDER} ?selected=${this.selectedFolderId === NO_FOLDER}>No Folder</option>` : nothing}
                </select>
              </span>`
          : html`<span class="muted glyph">${uiIcon('folder')} No folders</span>`}
        <span class="actions">
          <button type="button" class="icon-button" data-folder-new title="New folder" aria-label="New folder" @click=${() => this.openEditor({ kind: 'folder', mode: 'create' })}>${uiIcon('plus')}</button>
          ${concrete && selectedFolder
            ? html`
                <button type="button" class="icon-button" data-folder-rename title="Rename folder" aria-label="Rename folder" @click=${() => this.openEditor({ kind: 'folder', mode: 'rename', folder: selectedFolder })}>${uiIcon('edit')}</button>
                <button type="button" class="icon-button" data-folder-delete title="Delete folder" aria-label="Delete folder" @click=${() => this.openEditor({ kind: 'folder', mode: 'delete', folder: selectedFolder })}>${uiIcon('trash')}</button>`
            : nothing}
        </span>
      </div>
      ${this.renderFolderEditor()}
    `;
  }

  private renderFolderEditor() {
    const editor = this.editor;
    if (!editor || editor.kind !== 'folder') return nothing;
    if (editor.mode === 'delete') {
      return html`
        <div class="edit-row">
          <span class="muted">Delete “${editor.folder.name}”? Its items move to No Folder.</span>
          <button type="button" class="button danger" data-folder-confirm @click=${() => { this.emitFolderMutate({ op: 'delete', id: editor.folder.id }); this.closeEditor(); }}>Delete</button>
          <button type="button" class="button" @click=${() => this.closeEditor()}>Cancel</button>
        </div>`;
    }
    const initial = editor.mode === 'rename' ? editor.folder.name : '';
    const folder = editor.mode === 'rename' ? editor.folder : undefined;
    return html`
      <div class="edit-row">
        <input class="input" data-folder-name placeholder="Folder name" .value=${initial} @keydown=${(e: KeyboardEvent) => { if (e.key === 'Enter') { e.preventDefault(); this.submitFolder(editor.mode, folder); } if (e.key === 'Escape') this.closeEditor(); }} />
        <button type="button" class="button primary" data-folder-save @click=${() => this.submitFolder(editor.mode, folder)}>Save</button>
        <button type="button" class="button" @click=${() => this.closeEditor()}>Cancel</button>
      </div>`;
  }

  private renderCollectionBar() {
    const orgs = this.manageableOrgs;
    const canManageAny = orgs.length > 0;
    if (this.collections.length === 0 && !canManageAny) return nothing;
    const selected = this.collections.find((c) => c.id === this.selectedCollectionId);
    const canManageSelected = Boolean(selected && this.isManageableCollection(selected));
    return html`
      <div data-collection-bar>
        <div class="bar">
          ${this.collections.length > 0
            ? html`
                <span class="select-wrap">
                  <span class="glyph">${uiIcon('shield')}</span>
                  <select
                    class="select"
                    data-collection-filter
                    aria-label="Filter by collection"
                    .value=${this.selectedCollectionId ?? ''}
                    @change=${(e: Event) => {
                      const v = (e.target as HTMLSelectElement).value;
                      this.closeEditor();
                      this.emitFilter({ collectionId: v === '' ? null : v });
                    }}
                  >
                    <option value="">All collections</option>
                    ${this.collections.map((c) => html`<option value=${c.id} ?selected=${c.id === this.selectedCollectionId}>${c.name}</option>`)}
                  </select>
                </span>`
            : html`<span class="muted glyph">${uiIcon('shield')} No collections</span>`}
          <span class="actions">
            ${canManageAny
              ? html`<button type="button" class="icon-button" data-collection-new title="New collection" aria-label="New collection" @click=${() => this.openEditor({ kind: 'collection', mode: 'create' })}>${uiIcon('plus')}</button>`
              : nothing}
            ${canManageSelected && selected
              ? html`
                  <button type="button" class="icon-button" data-collection-rename title="Rename collection" aria-label="Rename collection" @click=${() => this.openEditor({ kind: 'collection', mode: 'rename', collection: selected })}>${uiIcon('edit')}</button>
                  <button type="button" class="icon-button" data-collection-delete title="Delete collection" aria-label="Delete collection" @click=${() => this.openEditor({ kind: 'collection', mode: 'delete', collection: selected })}>${uiIcon('trash')}</button>`
              : nothing}
          </span>
        </div>
        ${this.renderCollectionEditor()}
      </div>`;
  }

  private renderCollectionEditor() {
    const editor = this.editor;
    if (!editor || editor.kind !== 'collection') return nothing;
    if (editor.mode === 'delete') {
      return html`
        <div class="edit-row">
          <span class="muted">Delete “${editor.collection.name}”? Items keep their other collections.</span>
          <button type="button" class="button danger" data-collection-confirm @click=${() => { this.emitCollectionMutate({ op: 'delete', organizationId: editor.collection.organizationId, id: editor.collection.id }); this.closeEditor(); }}>Delete</button>
          <button type="button" class="button" @click=${() => this.closeEditor()}>Cancel</button>
        </div>`;
    }
    const orgs = this.manageableOrgs;
    const initial = editor.mode === 'rename' ? editor.collection.name : '';
    const collection = editor.mode === 'rename' ? editor.collection : undefined;
    const showOrgPicker = editor.mode === 'create' && orgs.length > 1;
    return html`
      <div class="edit-row">
        ${showOrgPicker
          ? html`<select class="select" data-collection-org>${orgs.map((o) => html`<option value=${o.id}>${o.name}</option>`)}</select>`
          : nothing}
        <input class="input" data-collection-name placeholder="Collection name" .value=${initial} @keydown=${(e: KeyboardEvent) => { if (e.key === 'Enter') { e.preventDefault(); this.submitCollection(editor.mode, collection); } if (e.key === 'Escape') this.closeEditor(); }} />
        <button type="button" class="button primary" data-collection-save @click=${() => this.submitCollection(editor.mode, collection)}>Save</button>
        <button type="button" class="button" @click=${() => this.closeEditor()}>Cancel</button>
      </div>`;
  }

  protected override render() {
    return html`${this.renderFolderBar()}${this.renderCollectionBar()}`;
  }
}

customElements.define('vw-vault-filters', VwVaultFilters);

declare global {
  interface HTMLElementTagNameMap {
    'vw-vault-filters': VwVaultFilters;
  }
}
