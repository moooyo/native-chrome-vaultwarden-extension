import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import '../../components/tabs.js';
import type { TabItem } from '../../components/tabs.js';
import './suggestions-view.js';
import './all-items-view.js';
import type { CipherSummary, CollectionSummary, FolderSummary } from '../../../core/vault/models.js';
import type { OrgPermission } from '../../../core/vault/org-permissions.js';
import type { FillResult, SuggestionsViewState } from '../types.js';

const VAULT_TABS: TabItem[] = [
  { id: 'suggestions', label: 'Suggestions' },
  { id: 'all', label: 'All items' },
];

/**
 * The unlocked vault shell: a Suggestions/All items tablist and whichever sub-view the current
 * `scope` selects. Both tabs are always present and selectable — the Suggestions sub-view renders
 * its own neutral guidance when unavailable, so All items is never blocked. It performs no requests
 * and forwards the typed events its children raise via bubbling.
 */
export class VwVaultView extends LitElement {
  static override properties = {
    scope: { type: String },
    suggestionsState: { attribute: false },
    fill: { attribute: false },
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

  declare scope: 'suggestions' | 'all';
  declare suggestionsState: SuggestionsViewState;
  declare fill: FillResult;
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
    this.scope = 'suggestions';
    this.suggestionsState = { status: 'loading' };
    this.fill = {};
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
      .content {
        padding-top: 4px;
      }
    `,
  ];

  private renderScope() {
    if (this.scope === 'all') {
      return html`
        <vw-all-items-view
          .items=${this.items}
          .folders=${this.folders}
          .collections=${this.collections}
          .orgPermissions=${this.orgPermissions}
          .selectedFolderId=${this.selectedFolderId}
          .selectedCollectionId=${this.selectedCollectionId}
          .query=${this.query}
          .showTrash=${this.showTrash}
          .skippedOrgCount=${this.skippedOrgCount}
          .selectedCipherId=${this.selectedCipherId}
        ></vw-all-items-view>`;
    }
    return html`<vw-suggestions-view
      .state=${this.suggestionsState}
      .fill=${this.fill}
      .selectedCipherId=${this.selectedCipherId}
    ></vw-suggestions-view>`;
  }

  protected override render() {
    return html`
      <vw-tabs .tabs=${VAULT_TABS} .selected=${this.scope}></vw-tabs>
      <div class="content">${this.renderScope()}</div>
    `;
  }
}

customElements.define('vw-vault-view', VwVaultView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-vault-view': VwVaultView;
  }
}
