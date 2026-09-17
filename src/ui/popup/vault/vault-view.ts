import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { tileColor, tileInitial } from '../../components/tile-color.js';
import { getLocale, LocalizeController, t } from '../../i18n/index.js';
import type { MessageKey } from '../../i18n/index.js';
import { isKnownCipherType } from '../../../core/vault/models.js';
import type { CipherSummary } from '../../../core/vault/models.js';
import { summaryAllowsCipherAccess } from '../../../core/vault/cipher-access.js';
import { filterSummaries, sortCipherSummaries } from '../../../core/vault/search.js';
import type {
  DetailExtras,
  DetailStatus,
  ItemLifecycleDetail,
  SuggestionsViewState,
  TotpSnapshot,
  VaultMode,
  VaultModeChangeDetail,
} from '../types.js';
import type { TabAutofillSuggestion } from '../../../messaging/protocol.js';
import '../../components/totp-meter.js';
import '../../components/status-message.js';

export type CategoryId = 'all' | 'favorite' | 'login' | 'card' | 'totp' | 'note' | 'identity' | 'ssh';

const CATEGORIES: ReadonlyArray<{ id: CategoryId; key: MessageKey }> = [
  { id: 'all', key: 'cat.all' },
  { id: 'favorite', key: 'cat.favorite' },
  { id: 'login', key: 'cat.login' },
  { id: 'card', key: 'cat.card' },
  { id: 'note', key: 'cat.note' },
  { id: 'identity', key: 'cat.identity' },
  { id: 'ssh', key: 'cat.ssh' },
];

const DOTS = '••••••••••••';

/** Which category an item belongs to. TOTP is a facet of logins that carry a TOTP secret. */
function matchesCategory(item: CipherSummary, category: CategoryId): boolean {
  switch (category) {
    case 'all': return true;
    case 'favorite': return item.favorite;
    case 'login': return item.type === 1;
    case 'card': return item.type === 3;
    case 'identity': return item.type === 4;
    case 'ssh': return item.type === 5;
    case 'note': return item.type === 2;
    case 'totp': return item.type === 1
      && Boolean(item.hasTotp)
      && summaryAllowsCipherAccess(item, 'viewTotp');
  }
}

function isUnsupported(item: CipherSummary): boolean {
  return item.unsupported === true || !isKnownCipherType(item.type);
}

function matchesVaultMode(item: CipherSummary, mode: VaultMode): boolean {
  if (mode === 'trash') return Boolean(item.deletedDate);
  if (mode === 'archive') return Boolean(item.archivedDate) && !item.deletedDate;
  return !item.deletedDate && !item.archivedDate;
}

function canOpenEditor(item: CipherSummary): boolean {
  if (!summaryAllowsCipherAccess(item, 'edit')) return false;
  if (item.hasTotp && !summaryAllowsCipherAccess(item, 'viewTotp')) return false;
  return (item.type !== 1 && item.type !== 5)
    || summaryAllowsCipherAccess(item, 'viewPassword');
}

function itemTitle(item: CipherSummary): string {
  return isUnsupported(item) ? t('detail.unsupportedItem') : item.name;
}

function typeLabel(item: CipherSummary): string {
  switch (item.type) {
    case 1: return t('cat.login');
    case 2: return t('cat.note');
    case 3: return t('cat.card');
    case 4: return t('cat.identity');
    case 5: return t('detail.sshKey');
    default: return t('detail.unsupportedType', { type: item.type });
  }
}

function suggestionTypeLabel(suggestion: TabAutofillSuggestion): string {
  switch (suggestion.kind) {
    case 'login': return t('cat.login');
    case 'card': return t('cat.card');
    case 'identity': return t('cat.identity');
  }
}

function suggestionSubtitle(suggestion: TabAutofillSuggestion): string {
  if (suggestion.kind === 'login') return suggestion.username ?? suggestion.matchedUri;
  return suggestion.subtitle ?? '';
}

/**
 * The MiYu vault view: the search box, category chips, the "current site" suggestions group with a
 * Fill pill, and the main list — each row expanding into an inline detail card (username / password /
 * one-time code / open-and-fill / edit). It owns the local reveal + TOTP-countdown state for the
 * expanded item and drives secrets only through the injected `extras` loaders, so plaintext never
 * flows through a prop. Consolidates the old vault-view / item-row / filters / suggestions views.
 */
export class VwVaultView extends LitElement {
  static override properties = {
    items: { attribute: false },
    suggestionsState: { attribute: false },
    query: { type: String },
    category: { type: String },
    mode: { type: String },
    pending: { type: Boolean },
    selectedCipherId: { attribute: false },
    extras: { attribute: false },
    status: { attribute: false },
    currentDomain: { type: String },
    compactDetails: { type: Boolean, attribute: 'compact-details' },
  };

  declare items: CipherSummary[];
  declare suggestionsState: SuggestionsViewState;
  declare query: string;
  declare category: CategoryId;
  declare mode: VaultMode;
  declare pending: boolean;
  declare selectedCipherId: string | null;
  declare extras: DetailExtras | undefined;
  declare status: DetailStatus | undefined;
  declare currentDomain: string;
  /** Popup rows may expand inline; a workspace opens the adjacent detail pane instead. */
  declare compactDetails: boolean;

  private i18n = new LocalizeController(this);
  private revealed = false;
  private password = '';
  private totp: TotpSnapshot | undefined;
  private totpTimer: number | undefined;
  private commandIndex = 0;
  /** Identifies the selection/extras pair that owns all on-demand detail state. */
  private detailGeneration = 0;
  /** Generation-scoped guard so an old request cannot block or clear the current TOTP load. */
  private totpLoadingGeneration: number | undefined;
  /** Local feedback for on-demand view operations; root-owned request feedback arrives via `status`. */
  private detailStatus: DetailStatus | undefined = undefined;
  private lifecycleSubmittedId: string | undefined;

  constructor() {
    super();
    this.items = [];
    this.suggestionsState = { status: 'loading' };
    this.query = '';
    this.category = 'all';
    this.mode = 'active';
    this.pending = false;
    this.selectedCipherId = null;
    this.extras = undefined;
    this.status = undefined;
    this.currentDomain = '';
    this.compactDetails = true;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display:flex; flex-direction:column; min-height:0; flex:1; background:var(--vw-panel); }
      .search {
        display:flex; align-items:center; gap:9px; height:40px; margin:10px 14px 0; padding:0 13px;
        border:1px solid var(--vw-line-3); border-radius:10px; background:var(--vw-card); flex:none; transition:box-shadow var(--vw-dur-fast);
      }
      .search:focus-within { box-shadow:var(--vw-focus); }
      .search svg { width:17px; height:17px; color:var(--vw-text-2); flex:none; }
      .search input { flex:1; min-width:0; border:0; outline:0; background:transparent; color:var(--vw-ink); font:400 13px/1 var(--vw-font-ui); }
      .search input::placeholder { color:var(--vw-placeholder); }
      .command-badge { height:24px; padding:0 9px; display:inline-flex; align-items:center; border-radius:12px; background:var(--pc); color:var(--onpc); font-size:11px; }
      .clear { display:grid; place-items:center; width:26px; height:26px; border:0; border-radius:13px; background:transparent; color:var(--vw-muted); cursor:pointer; }
      .clear:hover { background:var(--vw-icon-hover); }
      .clear svg { width:14px; height:14px; }

      .chips { display:flex; gap:6px; margin:10px 14px 8px; overflow-x:auto; scrollbar-width:none; flex:none; }
      .chips::-webkit-scrollbar { display:none; }
      .mode-bar {
        display:flex; align-items:center; gap:8px; min-height:40px; padding:5px 10px;
        border-bottom:1px solid var(--vw-line-1); flex:none;
      }
      .mode-back {
        width:30px; height:30px; display:grid; place-items:center; border:0; border-radius:8px;
        background:transparent; color:var(--vw-text-2); cursor:pointer;
      }
      .mode-back:hover { background:var(--vw-icon-hover); }
      .mode-back svg { width:17px; height:17px; }
      .mode-title { min-width:0; color:var(--vw-ink); font-size:13px; font-weight:600; }
      .mode-status { margin:8px 14px 0; }
      .chip {
        height:28px; padding:0 11px; display:inline-flex; align-items:center; gap:5px; flex:none;
        border:1px solid var(--vw-line-3); border-radius:8px; background:transparent; color:var(--vw-text-2);
        font:500 11.5px/1 var(--vw-font-ui); cursor:pointer; transition:background-color var(--vw-dur-fast), color var(--vw-dur-fast);
      }
      .chip:hover { background:var(--vw-row-hover); }
      .chip.on { background:var(--pc); color:var(--onpc); border-color:transparent; }

      .list { flex:1; min-height:0; overflow-y:auto; padding:0 8px 8px; scrollbar-width:thin; scrollbar-color:var(--vw-scrollbar) transparent; }
      .list::-webkit-scrollbar { width:6px; }
      .list::-webkit-scrollbar-thumb { background:var(--vw-scrollbar); border-radius:3px; }
      .group-label { font-size:11px; font-weight:500; color:var(--vw-muted); padding:8px 9px 4px; }
      .group-label.main { padding-top:9px; }

      .hero { margin:3px 4px 10px; padding:12px; border:1px solid var(--vw-line-1); border-radius:12px; background:var(--vw-fill); }
      .hero-head { display:flex; align-items:center; gap:9px; }
      .hero-site { width:34px; height:34px; display:grid; place-items:center; flex:none; border-radius:11px; background:var(--sf); color:var(--onpc); font-weight:500; }
      .hero-copy { min-width:0; flex:1; }
      .hero-domain { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--onpc); font-size:13px; font-weight:500; }
      .hero-meta { margin-top:1px; color:var(--vw-text-2); font-size:11px; }
      .hero-accounts { margin:9px 0 0; border-top:1px solid var(--vw-line-1); }
      .hero-account { display:flex; align-items:center; gap:4px; min-height:var(--vw-list-row-min, 46px); padding:2px; }
      .hero-account + .hero-account { border-top:1px solid var(--vw-line-1); }
      .hero-account-main {
        display:flex; align-items:center; gap:8px; min-width:0; min-height:40px; padding:3px 7px; flex:1;
        border:0; border-radius:8px; background:transparent; color:inherit; font:inherit; text-align:left; cursor:pointer;
      }
      .hero-account-main:hover { background:var(--vw-row-hover); }
      .hero-account .dot { width:9px; height:9px; border:2px solid var(--p); border-radius:50%; flex:none; }
      .hero-account:first-child .dot { background:var(--p); box-shadow:inset 0 0 0 2px var(--sf); }
      .hero-account .account-copy { min-width:0; flex:1; }
      .hero-account .account-user { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:12px; font-weight:500; }
      .hero-account .account-name { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--vw-muted); font-size:10.5px; }
      .hero-account .chev { margin-left:2px; }
      .hero-account .fill-pill { margin-right:5px; }
      .fill-pill { height:28px; padding:0 11px; border:0; border-radius:14px; background:var(--pc); color:var(--onpc); font:500 11.5px/1 var(--vw-font-ui); cursor:pointer; flex:none; }
      .fill-pill:hover { filter:brightness(.97); }
      .row { display:flex; align-items:center; width:100%; min-height:var(--vw-list-row-min, 52px); border-radius:8px; transition:background-color var(--vw-dur-fast); }
      .row:hover { background:var(--vw-row-hover); }
      .row.selected { background:var(--pc); box-shadow:inset 3px 0 0 var(--p); }
      .row-main {
        display:flex; align-items:center; gap:10px; flex:1; min-width:0; min-height:var(--vw-list-row-min, 46px); padding:var(--vw-list-row-padding-block, 5px) 8px;
        appearance:none; border:0; border-radius:8px; background:transparent; color:inherit; font:inherit; text-align:left; cursor:pointer;
      }
      .row-main[aria-disabled="true"] { cursor:default; }
      .tile { width:32px; height:32px; border-radius:10px; display:grid; place-items:center; color:#fff; font-size:13px; font-weight:500; flex:none; }
      .meta { flex:1; min-width:0; }
      .title-row { display:flex; align-items:center; gap:5px; min-width:0; }
      .title { flex:1; min-width:0; font-size:13px; font-weight:500; color:var(--vw-ink); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
      .favorite-marker { width:13px; height:13px; flex:none; display:inline-flex; color:var(--vw-sync-amber); }
      .favorite-marker svg { width:13px; height:13px; fill:currentColor; }
      .pk { width:13px; height:13px; color:var(--grn); flex:none; display:inline-flex; }
      .sub { display:block; font-size:11.5px; color:var(--vw-text-2); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
      .row-copy { width:28px; height:28px; margin-right:7px; border-radius:9px; display:grid; place-items:center; color:var(--vw-muted); background:transparent; border:0; cursor:pointer; opacity:.65; flex:none; }
      .row:hover .row-copy { opacity:1; }
      .row-copy:hover { background:var(--vw-icon-hover); }
      .row-copy svg { width:14px; height:14px; }
      .row-lifecycle {
        min-height:30px; margin-right:7px; padding:0 10px; border:0; border-radius:8px;
        display:inline-flex; align-items:center; gap:5px; flex:none; background:var(--pc);
        color:var(--onpc); font:500 11.5px/1 var(--vw-font-ui); cursor:pointer;
      }
      .row-lifecycle:hover:not(:disabled) { filter:brightness(.97); }
      .row-lifecycle:disabled { cursor:default; opacity:.55; }
      .row-lifecycle svg { width:14px; height:14px; }
      .chev { width:15px; height:15px; color:var(--vw-chevron); flex:none; display:inline-flex; transition:transform var(--vw-dur-fast); }
      .row.expanded .chev { transform:rotate(90deg); }

      .empty { padding:48px 20px; text-align:center; color:var(--vw-muted); font-size:12.5px; }
      .card { margin:1px 4px 8px; padding:11px 13px; display:flex; flex-direction:column; gap:9px; border:0; border-radius:0 0 12px 12px; background:var(--sfcl); animation:mvGrow .15s ease-out; transform-origin:top; }
      .field-label { margin-bottom:2px; color:var(--vw-muted); font-size:10.5px; font-weight:500; }
      .field-row { display:flex; align-items:center; gap:6px; }
      .field-val { flex:1; min-width:0; color:var(--vw-ink); font-size:12.5px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
      .field-val.mono { font-family:var(--vw-font-mono); font-size:12px; }
      .field-val.masked { color:var(--vw-muted); letter-spacing:.08em; user-select:none; }
      .icon-sm { width:28px; height:28px; border:0; border-radius:9px; display:grid; place-items:center; color:var(--vw-muted); background:var(--sfc); cursor:pointer; flex:none; }
      .icon-sm:hover { background:var(--sfch); }
      .icon-sm svg { width:14px; height:14px; }
      .actions { display:flex; gap:7px; margin-top:2px; }
      .btn-primary { flex:1; height:34px; border:0; border-radius:var(--vw-radius-control); background:var(--p); color:var(--onp); font:500 12px/1 var(--vw-font-ui); cursor:pointer; }
      .btn-primary:hover { background:var(--vw-primary-bg-hover); }
      .btn-outline { height:34px; padding:0 14px; border:1px solid var(--vw-line-3); border-radius:var(--vw-radius-control); background:var(--vw-card); color:var(--onpc); font:500 12px/1 var(--vw-font-ui); cursor:pointer; }
      .btn-outline:hover { filter:brightness(.97); }
      .btn-outline:only-child { flex:1; }

      .commands { flex:1; min-height:0; overflow:auto; padding:8px 8px 12px; }
      .command { width:100%; min-height:var(--vw-command-row-min, 46px); display:flex; align-items:center; gap:11px; padding:0 11px; border:0; border-radius:12px; background:transparent; color:var(--vw-ink); font:400 13px/1.3 var(--vw-font-ui); text-align:left; cursor:pointer; }
      .command:hover, .command.on { background:var(--sfch); }
      .command-icon { width:20px; color:var(--vw-text-2); display:inline-flex; }
      .command.on .command-icon { color:var(--p); }
      .command-icon svg { width:18px; height:18px; }
      .command-label { flex:1; }
      .command kbd { padding:2px 6px; border:1px solid var(--vw-line-3); border-radius:5px; color:var(--vw-muted); background:var(--sf); font:400 10px/1.4 var(--vw-font-mono); }
      button:focus-visible, input:focus-visible { outline:none; box-shadow:var(--vw-focus); }
    `,
  ];

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.detailGeneration++;
    this.resetDetailState();
  }

  protected override willUpdate(changed: Map<string, unknown>): void {
    if (changed.has('selectedCipherId') || changed.has('extras') || changed.has('mode') || changed.has('compactDetails')) {
      this.detailGeneration++;
      this.resetDetailState();
    }
    if (changed.has('mode') || changed.has('items')) this.lifecycleSubmittedId = undefined;
    if (changed.has('pending') && changed.get('pending') === true && !this.pending) {
      this.lifecycleSubmittedId = undefined;
    }
  }

  protected override updated(changed: Map<string, unknown>): void {
    if (changed.has('selectedCipherId') || changed.has('extras') || changed.has('mode') || changed.has('compactDetails')) {
      const item = this.selected();
      if (this.compactDetails && this.mode === 'active'
        && item?.hasTotp
        && summaryAllowsCipherAccess(item, 'viewTotp')
        && this.extras) {
        void this.loadTotp();
      }
    }
  }

  private resetDetailState(): void {
    this.revealed = false;
    this.password = '';
    this.detailStatus = undefined;
    this.clearTotp();
  }

  private selected(): CipherSummary | undefined {
    return this.selectedCipherId ? this.items.find((i) => i.id === this.selectedCipherId) : undefined;
  }

  private emit(type: string, detail?: unknown): void {
    emit(this, type, detail);
  }

  private onSearch(value: string): void {
    this.commandIndex = 0;
    this.emit('vw-search-change', { query: value });
  }

  private selectCategory(id: CategoryId): void {
    this.emit('vw-category-change', { category: id });
  }

  private toggleItem(id: string): void {
    this.emit('vw-item-toggle', { cipherId: this.selectedCipherId === id ? '' : id });
  }

  private async reveal(): Promise<void> {
    if (this.revealed) {
      this.revealed = false;
      this.password = '';
      this.requestUpdate();
      return;
    }
    const context = this.detailRequestContext();
    if (!context) return;
    const selected = this.selected();
    if (!selected || !summaryAllowsCipherAccess(selected, 'viewPassword')) return;
    const result = await context.extras.getField('password');
    if (!this.isCurrentDetailRequest(context)) return;
    if (result.ok) {
      const visiblePassword = result.value ?? '';
      this.password = visiblePassword;
      this.revealed = true;
      this.detailStatus = undefined;
      this.requestUpdate();
      await this.updateComplete;
      const renderedPassword = this.renderRoot.querySelector<HTMLElement>('.field-val.mono');
      if (!this.isCurrentDetailRequest(context)
          || !this.revealed
          || this.password !== visiblePassword
          || !renderedPassword
          || renderedPassword.classList.contains('masked')
          || renderedPassword.textContent !== visiblePassword) return;
      try {
        result.acknowledgeVisible?.();
      } catch {
        // Audit acknowledgement is best-effort after the secret is visibly rendered.
      }
      return;
    } else {
      // The worker refused to release the secret (reprompt-protected / locked / sync required). The
      // root has already recorded the detailed error on its own status, which this view never renders,
      // so give the user local feedback instead of a dead eye button.
      this.detailStatus = { message: t('detail.repromptTitle'), tone: 'danger' };
    }
    this.requestUpdate();
  }

  private async loadTotp(): Promise<void> {
    const context = this.detailRequestContext();
    if (!context) return;
    if (this.totpLoadingGeneration === context.generation) return;
    this.totpLoadingGeneration = context.generation;
    try {
      const result = await context.extras.getTotp();
      if (!this.isCurrentDetailRequest(context)) return;
      if (!result.ok || !result.totp) return;
      this.totp = result.totp;
      this.requestUpdate();
      this.startTotpTick();
    } finally {
      if (this.totpLoadingGeneration === context.generation) {
        this.totpLoadingGeneration = undefined;
      }
    }
  }

  private detailRequestContext(): { cipherId: string; extras: DetailExtras; generation: number } | undefined {
    const selected = this.selected();
    if (this.mode !== 'active'
      || !this.selectedCipherId
      || !this.extras
      || !selected
      || isUnsupported(selected)) return undefined;
    return {
      cipherId: this.selectedCipherId,
      extras: this.extras,
      generation: this.detailGeneration,
    };
  }

  private isCurrentDetailRequest(context: { cipherId: string; extras: DetailExtras; generation: number }): boolean {
    return (
      this.selectedCipherId === context.cipherId &&
      this.extras === context.extras &&
      this.detailGeneration === context.generation &&
      this.isConnected
    );
  }

  private startTotpTick(): void {
    this.stopTotpTimer();
    this.totpTimer = window.setInterval(() => {
      if (!this.totp) return;
      // A previous refresh is still deriving — skip this tick rather than stack concurrent derives.
      if (this.totpLoadingGeneration === this.detailGeneration) return;
      if (this.totp.remaining <= 1) {
        void this.loadTotp();
      } else {
        this.totp = { ...this.totp, remaining: this.totp.remaining - 1 };
        this.requestUpdate();
      }
    }, 1000);
  }

  private stopTotpTimer(): void {
    if (this.totpTimer !== undefined) {
      clearInterval(this.totpTimer);
      this.totpTimer = undefined;
    }
  }

  private clearTotp(): void {
    this.stopTotpTimer();
    this.totp = undefined;
    this.totpLoadingGeneration = undefined;
  }

  private copySecret(field: 'password', label: string): void {
    const selected = this.selected();
    if (this.mode !== 'active'
      || !selected
      || isUnsupported(selected)
      || !summaryAllowsCipherAccess(selected, 'viewPassword')) return;
    this.emit('vw-secret-request', { kind: 'field', field, label });
  }

  private copyValue(value: string, label: string): void {
    if (this.mode === 'active' && value) this.emit('vw-copy', { value, label });
  }

  protected override render() {
    const active = this.mode === 'active';
    return html`
      ${active ? nothing : this.renderModeHeader()}
      ${!active && this.status
        ? html`<vw-status-message
            class="mode-status"
            tone=${this.status.tone}
            .icon=${this.status.tone === 'success' ? 'checkCircle' : 'alert'}
            .message=${this.status.message}
          ></vw-status-message>`
        : nothing}
      ${this.renderSearch()}
      ${active && this.query.trim().startsWith('/')
        ? this.renderCommands()
        : html`${active ? this.renderChips() : nothing}<div class="list">${this.renderList()}</div>`}
    `;
  }

  private renderModeHeader() {
    const title = this.mode === 'archive' ? t('popup.archive') : t('popup.trash');
    return html`
      <div class="mode-bar">
        <button
          type="button"
          class="mode-back"
          title=${t('common.back')}
          aria-label=${t('common.back')}
          @click=${() => this.emit(
            'vw-vault-mode-change',
            { mode: 'active' } satisfies VaultModeChangeDetail,
          )}
        >${uiIcon('back')}</button>
        <span class="mode-title">${title}</span>
      </div>
    `;
  }

  private renderSearch() {
    return html`
      <label class="search">
        ${uiIcon('search')}
        <input
          type="search"
          aria-label=${t('popup.search')}
          placeholder=${t(this.mode === 'active' ? 'popup.searchCommand' : 'popup.search')}
          .value=${this.query}
          @input=${(e: Event) => this.onSearch((e.target as HTMLInputElement).value)}
          @keydown=${(e: KeyboardEvent) => { if (this.mode === 'active') this.onSearchKeydown(e); }}
        />
        ${this.mode === 'active' && this.query.trim().startsWith('/') ? html`<span class="command-badge">${t('popup.command')}</span>` : nothing}
        ${this.query ? html`<button type="button" class="clear" aria-label=${t('common.close')} @click=${() => this.onSearch('')}>${uiIcon('close')}</button>` : nothing}
      </label>
    `;
  }

  private commandItems() {
    const all = [
      { action: 'generator', label: t('popup.generator'), shortcut: '/gen', icon: 'wand' as const },
      { action: 'totp', label: t('popup.authenticator'), shortcut: '/2fa', icon: 'clock' as const },
      { action: 'lock', label: t('popup.lock'), shortcut: '/lock', icon: 'lock' as const },
      { action: 'new', label: t('popup.newItem'), shortcut: '/new', icon: 'plus' as const },
      { action: 'health', label: t('popup.health'), shortcut: '/health', icon: 'shield' as const },
      { action: 'settings', label: t('popup.settings'), shortcut: '/set', icon: 'sliders' as const },
    ];
    const needle = this.query.trim().slice(1).toLowerCase();
    return needle ? all.filter((item) => item.label.toLowerCase().includes(needle) || item.shortcut.includes(needle)) : all;
  }

  private renderCommands() {
    const commands = this.commandItems();
    return html`
      <div class="commands" role="listbox">
        ${commands.map((item, index) => html`
          <button type="button" class="command ${index === this.commandIndex ? 'on' : ''}" role="option" aria-selected=${index === this.commandIndex ? 'true' : 'false'} @click=${() => this.runCommand(item.action)}>
            <span class="command-icon">${uiIcon(item.icon)}</span>
            <span class="command-label">${item.label}</span>
            <kbd>${index === this.commandIndex ? '↵' : item.shortcut}</kbd>
          </button>
        `)}
      </div>
    `;
  }

  private onSearchKeydown(event: KeyboardEvent): void {
    if (!this.query.trim().startsWith('/')) return;
    const commands = this.commandItems();
    if (!commands.length) return;
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      const step = event.key === 'ArrowDown' ? 1 : -1;
      this.commandIndex = (this.commandIndex + step + commands.length) % commands.length;
      this.requestUpdate();
    } else if (event.key === 'Enter') {
      event.preventDefault();
      this.runCommand(commands[Math.min(this.commandIndex, commands.length - 1)]!.action);
    } else if (event.key === 'Escape') {
      event.preventDefault();
      this.onSearch('');
    }
  }

  private runCommand(action: string): void {
    this.emit('vw-command', { action });
  }

  private renderChips() {
    return html`
      <div class="chips" role="tablist">
        ${CATEGORIES.map(
          (cat) => html`
            <button
              type="button"
              role="tab"
              data-category=${cat.id}
              class="chip ${this.category === cat.id ? 'on' : ''}"
              aria-selected=${this.category === cat.id ? 'true' : 'false'}
              @click=${() => this.selectCategory(cat.id)}
            >
              ${t(cat.key)}
            </button>
          `,
        )}
      </div>
    `;
  }

  private filteredItems(): CipherSummary[] {
    const candidates = this.items.filter((item) => {
      if (!matchesVaultMode(item, this.mode)) return false;
      if (this.mode === 'active' && !matchesCategory(item, this.category)) return false;
      return true;
    });
    return sortCipherSummaries(filterSummaries(candidates, this.query), getLocale());
  }

  private suggestions(): TabAutofillSuggestion[] {
    return this.mode === 'active' && this.suggestionsState.status === 'ready'
      ? this.suggestionsState.suggestions
      : [];
  }

  private renderList() {
    const items = this.filteredItems();
    const showSuggestions = this.mode === 'active'
      && !this.query.trim()
      && this.category === 'all'
      && this.suggestions().length > 0;
    if (items.length === 0 && !showSuggestions) {
      const emptyKey = this.mode === 'archive'
        ? 'list.archiveEmpty'
        : this.mode === 'trash'
          ? 'list.trashEmpty'
          : 'list.empty';
      return html`<div class="empty">${this.query.trim() ? t('list.emptySearch') : t(emptyKey)}</div>`;
    }
    const mainLabel = this.mode === 'archive'
      ? t('popup.archive')
      : this.mode === 'trash'
        ? t('popup.trash')
      : this.query.trim()
      ? t('list.results', { count: items.length })
      : this.category === 'all'
        ? t('list.allItems')
        : t(CATEGORIES.find((c) => c.id === this.category)!.key);
    return html`
      ${showSuggestions ? this.renderSuggestionGroup() : nothing}
      <div class="group-label main">${mainLabel}</div>
      ${items.map((item) => this.renderItem(item, false))}
    `;
  }

  private renderSuggestionGroup() {
    const suggestions = this.suggestions();
    const byId = new Map(this.items.map((i) => [i.id, i] as const));
    const first = suggestions[0];
    const firstLogin = suggestions.find((suggestion) => suggestion.kind === 'login');
    const firstItem = first ? byId.get(first.id) : undefined;
    const rawDomain = this.currentDomain
      || firstLogin?.matchedUri
      || firstItem?.uris[0]
      || '';
    let domain = rawDomain || t('list.currentSiteBare');
    try { domain = new URL(rawDomain).hostname; } catch { /* Keep the display-safe fallback. */ }
    const hasPasskey = suggestions.some((suggestion) => suggestion.kind === 'login' && byId.get(suggestion.id)?.hasPasskey);
    return html`
      <section class="hero" aria-label=${t('list.currentSite', { domain })}>
        <div class="hero-head">
          <span class="hero-site">${domain.slice(0, 1).toUpperCase()}</span>
          <div class="hero-copy">
            <div class="hero-domain">${domain}</div>
            <div class="hero-meta">${t('content.matches', { count: suggestions.length })}${hasPasskey ? ` · ${t('list.passkeySupported')}` : ''}</div>
          </div>
          ${hasPasskey ? html`<span class="pk" title=${t('list.passkeySupported')}>${uiIcon('shield')}</span>` : nothing}
        </div>
        <div class="hero-accounts">
          ${suggestions.map((suggestion) => {
            const subtitle = suggestionSubtitle(suggestion);
            const canFill = Boolean(suggestion.target);
            return html`
              <div class="hero-account" data-kind=${suggestion.kind}>
                <button
                  type="button"
                  class="hero-account-main"
                  title=${t('detail.viewDetails')}
                  @click=${() => this.emit('vw-item-open', { cipherId: suggestion.id })}
                >
                  <span class="dot" aria-hidden="true"></span>
                  <span class="account-copy">
                    <span class="account-user">${suggestion.name}</span>
                    <span class="account-name">${subtitle ? `${subtitle} - ` : ''}${suggestionTypeLabel(suggestion)}</span>
                  </span>
                  <span class="chev">${uiIcon('chevron')}</span>
                </button>
                ${canFill
                  ? html`<button
                      type="button"
                      class="fill-pill"
                      aria-label=${`${t('list.fill')}: ${suggestion.name}`}
                      @click=${() => this.fillSuggestion(suggestion)}
                    >${t('list.fill')}</button>`
                  : nothing}
              </div>
            `;
          })}
        </div>
      </section>
    `;
  }

  private renderFavoriteMarker(item: CipherSummary) {
    return item.favorite
      ? html`<span
          class="favorite-marker"
          role="img"
          title=${t('list.favoriteItem')}
          aria-label=${t('list.favoriteItem')}
        >${uiIcon('star')}</span>`
      : nothing;
  }

  private renderItem(item: CipherSummary, isSuggestion: boolean, suggestion?: TabAutofillSuggestion) {
    if (isUnsupported(item)) return this.renderUnsupportedItem(item);

    const selected = this.selectedCipherId === item.id;
    const expanded = this.compactDetails && this.mode === 'active' && selected;
    // Row navigation still opens protected detail, while an explicit Fill button records a continuation
    // that resumes automatically after the worker issues a one-time reprompt proof.
    const needsReprompt = item.reprompt === true || suggestion?.reprompt === true;
    const needsFullDetail = !this.compactDetails || needsReprompt || item.type === 5;
    const title = itemTitle(item);
    return html`
      <div>
        <div class="row ${selected ? 'selected' : ''} ${expanded ? 'expanded' : ''}">
          <button
            type="button"
            class="row-main"
            aria-expanded=${needsFullDetail ? nothing : String(expanded)}
            aria-current=${!this.compactDetails && selected ? 'true' : nothing}
            @click=${() => {
              if (this.mode !== 'active' || needsFullDetail) this.emit('vw-item-open', { cipherId: item.id });
              else this.toggleItem(item.id);
            }}
          >
            <span class="tile" style=${`background:${tileColor(item.id)}`}>${tileInitial(title)}</span>
            <span class="meta">
              <span class="title-row">
                ${this.renderFavoriteMarker(item)}
                <span class="title">${title}</span>
                ${item.hasPasskey
                  ? html`<span class="pk" title=${t('list.passkeySupported')}>${uiIcon('passkey')}</span>`
                  : nothing}
              </span>
              <span class="sub">${item.username ?? item.subtitle ?? ''}</span>
            </span>
            ${needsFullDetail || !isSuggestion ? html`<span class="chev">${uiIcon('chevron')}</span>` : nothing}
          </button>
          ${this.mode === 'active' && item.type === 1
            ? html`<button
                type="button"
                class="fill-pill"
                @click=${() => suggestion?.target
                  ? this.fillSuggestion(suggestion)
                  : this.emit('vw-item-fill', { cipherId: item.id })}
              >${t('list.fill')}</button>`
            : nothing}
          ${this.mode === 'active' && !needsFullDetail && expanded && !isSuggestion && item.type === 1
            ? html`
                <button
                  type="button"
                  class="row-copy"
                  title=${t('list.copyPassword')}
                  aria-label=${t('list.copyPassword')}
                  @click=${() => this.copySecret('password', t('detail.password'))}
                >${uiIcon('copy')}</button>
              `
            : nothing}
          ${this.renderArchiveAction(item)}
        </div>
        ${expanded ? this.renderCard(item, suggestion) : nothing}
      </div>
    `;
  }

  private renderUnsupportedItem(item: CipherSummary) {
    const title = itemTitle(item);
    return html`
      <div>
        <div class="row">
          <div class="row-main" aria-disabled="true">
            <span class="tile" style=${`background:${tileColor(item.id)}`}>${tileInitial(title)}</span>
            <span class="meta">
              <span class="title-row">${this.renderFavoriteMarker(item)}<span class="title">${title}</span></span>
              <span class="sub">${typeLabel(item)}</span>
            </span>
          </div>
          ${this.renderArchiveAction(item)}
        </div>
      </div>
    `;
  }

  private renderArchiveAction(item: CipherSummary) {
    if (this.mode !== 'archive') return nothing;
    const busy = this.pending || this.lifecycleSubmittedId !== undefined;
    return html`
      <button
        type="button"
        class="row-lifecycle"
        data-unarchive
        title=${t('detail.unarchive')}
        aria-label=${`${t('detail.unarchive')}: ${itemTitle(item)}`}
        ?disabled=${busy}
        @click=${() => this.submitUnarchive(item)}
      >${uiIcon('refresh')}<span>${t('detail.unarchive')}</span></button>
    `;
  }

  private submitUnarchive(item: CipherSummary): void {
    if (
      this.mode !== 'archive'
      || this.pending
      || this.lifecycleSubmittedId !== undefined
      || !item.archivedDate
      || item.deletedDate
    ) return;
    this.lifecycleSubmittedId = item.id;
    this.requestUpdate();
    this.emit('vw-unarchive-item', {
      action: 'unarchive',
      cipherId: item.id,
      sourceMode: 'archive',
      targetMode: 'active',
    } satisfies ItemLifecycleDetail);
  }

  private fillSuggestion(suggestion: TabAutofillSuggestion): void {
    if (suggestion.target) this.emit('vw-suggestion-fill', { cipherId: suggestion.id, target: suggestion.target });
    else this.emit('vw-item-open', { cipherId: suggestion.id });
  }

  private renderCard(item: CipherSummary, suggestion?: TabAutofillSuggestion) {
    if (isUnsupported(item)) {
      return html`
        <div class="card">
          <div class="field-label">${typeLabel(item)}</div>
          <div class="field-val">${t('detail.unsupportedDescription')}</div>
        </div>
      `;
    }
    const isLogin = item.type === 1;
    const canOpenOrFill = isLogin && Boolean(suggestion?.target || item.uris[0]);
    const status = this.detailStatus ?? this.status;
    return html`
      <div class="card" @click=${(e: Event) => e.stopPropagation()}>
        ${status
          ? html`<vw-status-message
              tone=${status.tone}
              .icon=${'alert'}
              .message=${status.message}
            ></vw-status-message>`
          : nothing}
        ${item.username
          ? html`
              <div>
                <div class="field-label">${t('detail.username')}</div>
                <div class="field-row">
                  <span class="field-val">${item.username}</span>
                  <button class="icon-sm" title=${t('common.copy')} @click=${() => this.copyValue(item.username!, t('detail.username'))}>${uiIcon('copy')}</button>
                </div>
              </div>`
          : nothing}
        ${isLogin && summaryAllowsCipherAccess(item, 'viewPassword')
          ? html`
              <div>
                <div class="field-label">${t('detail.password')}</div>
                <div class="field-row">
                  <span class="field-val mono ${this.revealed ? '' : 'masked'}">${this.revealed ? this.password : DOTS}</span>
                  <button class="icon-sm eye" title=${t('detail.reveal')} @click=${() => void this.reveal()}>${uiIcon(this.revealed ? 'eyeOff' : 'eye')}</button>
                  <button class="icon-sm" title=${t('common.copy')} @click=${() => this.copySecret('password', t('detail.password'))}>${uiIcon('copy')}</button>
                </div>
              </div>`
          : nothing}
        ${item.hasTotp && summaryAllowsCipherAccess(item, 'viewTotp') && this.totp
          ? html`
              <div>
                <div class="field-label">${t('detail.totp')}</div>
                <div class="field-row">
                  <vw-totp-meter style="flex:1" .code=${this.totp.code} .period=${this.totp.period} .remaining=${this.totp.remaining}></vw-totp-meter>
                  <button class="icon-sm" title=${t('detail.copyCode')} @click=${() => this.copyValue(this.totp!.code, t('detail.totp'))}>${uiIcon('copy')}</button>
                </div>
              </div>`
          : nothing}
        ${!isLogin && item.subtitle
          ? html`<div><div class="field-label">${typeLabel(item)}</div><div class="field-val">${item.subtitle}</div></div>`
          : nothing}
        <div class="actions">
          ${canOpenOrFill
            ? html`<button class="btn-primary" @click=${() => this.openOrFill(item, suggestion)}>${t(
                suggestion?.target ? 'detail.fillCurrentPage' : 'detail.openWebsite',
              )}</button>`
            : nothing}
          ${canOpenEditor(item)
            ? html`<button class="btn-outline" @click=${() => this.emit('vw-edit-item', { cipherId: item.id })}>${t('common.edit')}</button>`
            : nothing}
          <button class="btn-outline" @click=${() => this.emit('vw-item-open', { cipherId: item.id })}>${t('detail.viewDetails')}</button>
        </div>
      </div>
    `;
  }

  private openOrFill(item: CipherSummary, suggestion?: TabAutofillSuggestion): void {
    if (isUnsupported(item)) return;
    if (suggestion?.target) this.emit('vw-suggestion-fill', { cipherId: item.id, target: suggestion.target });
    else this.emit('vw-item-fill', { cipherId: item.id });
  }
}

customElements.define('vw-vault-view', VwVaultView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-vault-view': VwVaultView;
  }
}
