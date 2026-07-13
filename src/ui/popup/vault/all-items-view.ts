import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import { filterSummariesByFolderCollectionAndQuery } from '../../../core/vault/search.js';
import './vault-item-row.js';
import './vault-filters.js';
import type { CipherSummary, CollectionSummary, FolderSummary } from '../../../core/vault/models.js';
import type { OrgPermission } from '../../../core/vault/org-permissions.js';
import type { FilterChangeDetail } from '../types.js';

/**
 * The "All items" surface: search, folder/collection filters, trash toggle, the skipped-org banner,
 * and the filtered item list. It owns no filter state — every change is a `vw-filter-change` patch to
 * the root — and delegates the actual filtering to the shared `filterSummariesByFolderCollectionAndQuery`
 * core helper rather than re-implementing it.
 */
export class VwAllItemsView extends LitElement {
  static override properties = {
    items: { attribute: false },
    folders: { attribute: false },
    collections: { attribute: false },
    orgPermissions: { attribute: false },
    selectedFolderId: { attribute: false },
    selectedCollectionId: { attribute: false },
    query: { type: String },
    showTrash: { type: Boolean },
    skippedOrgCount: { type: Number },
    selectedCipherId: { attribute: false },
  };

  declare items: CipherSummary[];
  declare folders: FolderSummary[];
  declare collections: CollectionSummary[];
  declare orgPermissions: OrgPermission[];
  declare selectedFolderId: string | null;
  declare selectedCollectionId: string | null;
  declare query: string;
  declare showTrash: boolean;
  declare skippedOrgCount: number;
  declare selectedCipherId: string | null;

  constructor() {
    super();
    this.items = [];
    this.folders = [];
    this.collections = [];
    this.orgPermissions = [];
    this.selectedFolderId = null;
    this.selectedCollectionId = null;
    this.query = '';
    this.showTrash = false;
    this.skippedOrgCount = 0;
    this.selectedCipherId = null;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: block;
      }
      .toolbar {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 4px 0;
      }
      .search {
        display: flex;
        align-items: center;
        gap: 6px;
        flex: 1;
        min-width: 0;
        border: 1px solid var(--vw-line);
        border-radius: var(--vw-radius-control);
        padding: 0 8px;
        background: var(--vw-panel);
      }
      .search .glyph {
        color: var(--vw-muted);
        display: inline-flex;
      }
      .search input {
        flex: 1;
        min-width: 0;
        height: 30px;
        border: none;
        background: transparent;
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        font-size: 13px;
      }
      .search input:focus {
        outline: none;
      }
      .icon-button.active {
        background: var(--vw-blue-50);
        color: var(--vw-blue-600);
      }
      .banner {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 6px 10px;
        font-size: 12px;
        color: var(--vw-muted);
      }
      .banner .glyph {
        display: inline-flex;
      }
      .list {
        display: flex;
        flex-direction: column;
        gap: 2px;
        padding: 4px 0;
      }
      .empty {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 8px;
        padding: 24px 12px;
        color: var(--vw-muted);
        font-size: 13px;
        text-align: center;
      }
      .empty .glyph svg {
        width: 28px;
        height: 28px;
      }
    `,
  ];

  private emitFilter(patch: FilterChangeDetail): void {
    this.dispatchEvent(new CustomEvent<FilterChangeDetail>('vw-filter-change', { detail: patch, bubbles: true, composed: true }));
  }

  private get visibleItems(): CipherSummary[] {
    const scope = this.items.filter((item) => (this.showTrash ? Boolean(item.deletedDate) : !item.deletedDate));
    return filterSummariesByFolderCollectionAndQuery(scope, this.selectedFolderId, this.selectedCollectionId, this.query);
  }

  private renderEmpty() {
    const isSearch = this.query.trim().length > 0;
    const message = this.showTrash
      ? (isSearch ? 'No trashed items match your search.' : 'Trash is empty.')
      : (isSearch ? 'No items match your search.' : 'Your vault is empty. Sync to load items.');
    return html`
      <div class="empty">
        <span class="glyph">${uiIcon(isSearch ? 'search' : (this.showTrash ? 'trash' : 'shield'))}</span>
        <span>${message}</span>
      </div>`;
  }

  private moveFocus(event: KeyboardEvent): void {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    const path = event.composedPath();
    const current = path.find((node) => node instanceof HTMLElement && node.tagName === 'VW-VAULT-ITEM-ROW');
    if (!(current instanceof HTMLElement)) return;
    const rows = Array.from(this.renderRoot.querySelectorAll('vw-vault-item-row'));
    const currentIndex = rows.indexOf(current as typeof rows[number]);
    if (currentIndex < 0) return;
    event.preventDefault();
    const nextIndex = event.key === 'Home'
      ? 0
      : event.key === 'End'
        ? rows.length - 1
        : Math.max(0, Math.min(rows.length - 1, currentIndex + (event.key === 'ArrowDown' ? 1 : -1)));
    rows[nextIndex]?.shadowRoot?.querySelector<HTMLButtonElement>('button')?.focus();
  }

  protected override render() {
    const visible = this.visibleItems;
    return html`
      <div class="toolbar">
        <span class="search">
          <span class="glyph">${uiIcon('search')}</span>
          <input
            data-search
            type="search"
            placeholder="Search vault"
            autocomplete="off"
            .value=${this.query}
            @input=${(e: Event) => this.emitFilter({ query: (e.target as HTMLInputElement).value })}
          />
        </span>
        <button
          type="button"
          class=${`icon-button ${this.showTrash ? 'active' : ''}`}
          data-trash-toggle
          title=${this.showTrash ? 'Exit trash' : 'Trash'}
          aria-label=${this.showTrash ? 'Exit trash' : 'Trash'}
          aria-pressed=${this.showTrash ? 'true' : 'false'}
          @click=${() => this.emitFilter({ trash: !this.showTrash })}
        >
          ${uiIcon('trash')}
        </button>
      </div>
      <vw-vault-filters
        .folders=${this.folders}
        .collections=${this.collections}
        .orgPermissions=${this.orgPermissions}
        .items=${this.items}
        .selectedFolderId=${this.selectedFolderId}
        .selectedCollectionId=${this.selectedCollectionId}
      ></vw-vault-filters>
      ${this.skippedOrgCount > 0
        ? html`<div class="banner" data-org-banner><span class="glyph">${uiIcon('shield')}</span><span>${this.skippedOrgCount} organization item${this.skippedOrgCount === 1 ? '' : 's'} could not be decrypted</span></div>`
        : nothing}
      ${visible.length === 0
        ? this.renderEmpty()
        : html`<div class="list" role="listbox" @keydown=${(event: KeyboardEvent) => this.moveFocus(event)}>${visible.map((item) => html`
            <vw-vault-item-row .item=${item} .selected=${item.id === this.selectedCipherId}></vw-vault-item-row>
          `)}</div>`}
    `;
  }
}

customElements.define('vw-all-items-view', VwAllItemsView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-all-items-view': VwAllItemsView;
  }
}
