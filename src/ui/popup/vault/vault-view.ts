import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { tileColor, tileInitial } from '../../components/tile-color.js';
import { LocalizeController, t } from '../../i18n/index.js';
import type { MessageKey } from '../../i18n/index.js';
import type { CipherSummary } from '../../../core/vault/models.js';
import type { DetailExtras, DetailStatus, SuggestionsViewState, TotpSnapshot } from '../types.js';
import type { TabAutofillSuggestion } from '../../../messaging/protocol.js';
import '../../components/totp-meter.js';
import '../../components/status-message.js';

export type CategoryId = 'all' | 'login' | 'card' | 'totp' | 'note' | 'identity';

const CATEGORIES: ReadonlyArray<{ id: CategoryId; key: MessageKey }> = [
  { id: 'all', key: 'cat.all' },
  { id: 'login', key: 'cat.login' },
  { id: 'card', key: 'cat.card' },
  { id: 'note', key: 'cat.note' },
  { id: 'identity', key: 'cat.identity' },
];

const DOTS = '••••••••••••';

/** How many leading rows carry the staggered entrance delay. Rows past this animate immediately, so
 *  a long list (each row starts at opacity:0) never leaves later rows invisible for seconds. */
const STAGGER_LIMIT = 12;

/** Which category an item belongs to. TOTP is a facet of logins that carry a TOTP secret. */
function matchesCategory(item: CipherSummary, category: CategoryId): boolean {
  switch (category) {
    case 'all': return true;
    case 'login': return item.type === 1;
    case 'card': return item.type === 3;
    case 'identity': return item.type === 4;
    case 'note': return item.type === 2;
    case 'totp': return item.type === 1 && Boolean(item.hasTotp);
  }
}

function typeLabelKey(item: CipherSummary): MessageKey {
  switch (item.type) {
    case 3: return 'cat.card';
    case 4: return 'cat.identity';
    case 2: return 'cat.note';
    default: return 'cat.login';
  }
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
    selectedCipherId: { attribute: false },
    extras: { attribute: false },
    currentDomain: { type: String },
  };

  declare items: CipherSummary[];
  declare suggestionsState: SuggestionsViewState;
  declare query: string;
  declare category: CategoryId;
  declare selectedCipherId: string | null;
  declare extras: DetailExtras | undefined;
  declare currentDomain: string;

  private i18n = new LocalizeController(this);
  private revealed = false;
  private password = '';
  private totp: TotpSnapshot | undefined;
  private totpTimer: number | undefined;
  private commandIndex = 0;
  /** In-flight guard so a slow `getTotp` (>1s) can't stack concurrent derives from the 1s tick. */
  private totpLoading = false;
  /** Local feedback for the open item when an on-demand secret release is refused (reprompt/locked).
   *  The root records its own detailed error, but that banner is not rendered in this view. */
  private detailStatus: DetailStatus | undefined = undefined;

  constructor() {
    super();
    this.items = [];
    this.suggestionsState = { status: 'loading' };
    this.query = '';
    this.category = 'all';
    this.selectedCipherId = null;
    this.extras = undefined;
    this.currentDomain = '';
  }

  static override styles = [
    themeTokens,
    css`
      :host { display:flex; flex-direction:column; min-height:0; flex:1; background:var(--vw-panel); }
      .search {
        display:flex; align-items:center; gap:9px; height:40px; margin:10px 14px 0; padding:0 13px;
        border-radius:20px; background:var(--vw-fill); flex:none; transition:box-shadow var(--vw-dur-fast);
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
      .chip {
        height:28px; padding:0 11px; display:inline-flex; align-items:center; gap:5px; flex:none;
        border:1px solid var(--vw-line-3); border-radius:8px; background:transparent; color:var(--vw-text-2);
        font:500 11.5px/1 var(--vw-font-ui); cursor:pointer; transition:background-color var(--vw-dur-fast), color var(--vw-dur-fast);
      }
      .chip:hover { background:var(--vw-row-hover); }
      .chip.on { background:var(--pc); color:var(--onpc); border-color:transparent; }
      .chip.on::before { content:'✓'; font-size:11px; }

      .list { flex:1; min-height:0; overflow-y:auto; padding:0 8px 8px; scrollbar-width:thin; scrollbar-color:var(--vw-scrollbar) transparent; }
      .list::-webkit-scrollbar { width:6px; }
      .list::-webkit-scrollbar-thumb { background:var(--vw-scrollbar); border-radius:3px; }
      .group-label { font-size:11px; font-weight:500; color:var(--vw-muted); padding:8px 9px 4px; }
      .group-label.main { padding-top:9px; }

      .hero { margin:3px 4px 6px; padding:12px; border-radius:16px; background:linear-gradient(135deg, var(--pc), var(--sfc) 90%); }
      .hero-head { display:flex; align-items:center; gap:9px; }
      .hero-site { width:34px; height:34px; display:grid; place-items:center; flex:none; border-radius:11px; background:var(--sf); color:var(--onpc); font-weight:500; }
      .hero-copy { min-width:0; flex:1; }
      .hero-domain { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--onpc); font-size:13px; font-weight:500; }
      .hero-meta { margin-top:1px; color:var(--vw-text-2); font-size:11px; }
      .hero-accounts { margin:9px 0 10px; border-radius:11px; background:color-mix(in srgb, var(--sf) 72%, transparent); overflow:hidden; }
      .hero-account { display:flex; align-items:center; gap:8px; min-height:40px; padding:5px 9px; }
      .hero-account + .hero-account { border-top:1px solid var(--vw-line-1); }
      .hero-account .dot { width:9px; height:9px; border:2px solid var(--p); border-radius:50%; flex:none; }
      .hero-account:first-child .dot { background:var(--p); box-shadow:inset 0 0 0 2px var(--sf); }
      .hero-account .account-copy { min-width:0; flex:1; }
      .hero-account .account-user { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:12px; font-weight:500; }
      .hero-account .account-name { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--vw-muted); font-size:10.5px; }
      .fill-pill { height:28px; padding:0 11px; border:0; border-radius:14px; background:var(--pc); color:var(--onpc); font:500 11.5px/1 var(--vw-font-ui); cursor:pointer; flex:none; }
      .fill-pill:hover { filter:brightness(.97); }
      .hero-fill { width:100%; height:42px; border-radius:21px; background:var(--p); color:var(--onp); font-size:12.5px; }
      .hero-fill:hover { background:var(--vw-primary-bg-hover); }

      .row { display:flex; align-items:center; gap:10px; min-height:46px; padding:5px 8px; border-radius:12px; cursor:pointer; animation:mvStag .24s ease-out both; }
      .row:hover, .row.selected { background:var(--vw-row-hover); }
      .tile { width:32px; height:32px; border-radius:10px; display:grid; place-items:center; color:#fff; font-size:13px; font-weight:500; flex:none; }
      .meta { flex:1; min-width:0; }
      .title-row { display:flex; align-items:center; gap:5px; min-width:0; }
      .title { font-size:13px; font-weight:500; color:var(--vw-ink); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
      .pk { width:13px; height:13px; color:var(--grn); flex:none; display:inline-flex; }
      .sub { font-size:11.5px; color:var(--vw-text-2); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
      .row-copy { width:28px; height:28px; border-radius:9px; display:grid; place-items:center; color:var(--vw-muted); background:transparent; border:0; cursor:pointer; opacity:.65; flex:none; }
      .row:hover .row-copy { opacity:1; }
      .row-copy:hover { background:var(--vw-icon-hover); }
      .row-copy svg { width:14px; height:14px; }
      .chev { width:15px; height:15px; color:var(--vw-chevron); flex:none; display:inline-flex; transition:transform var(--vw-dur-fast); }
      .row.selected .chev { transform:rotate(90deg); }

      .empty { padding:48px 20px; text-align:center; color:var(--vw-muted); font-size:12.5px; }
      .card { margin:1px 4px 8px; padding:11px 13px; display:flex; flex-direction:column; gap:9px; border:0; border-radius:0 0 12px 12px; background:var(--sfcl); animation:mvGrow .15s ease-out; transform-origin:top; }
      .field-label { margin-bottom:2px; color:var(--vw-muted); font-size:10.5px; font-weight:500; }
      .field-row { display:flex; align-items:center; gap:6px; }
      .field-val { flex:1; min-width:0; color:var(--vw-ink); font-size:12.5px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
      .field-val.mono { font-family:var(--vw-font-mono); font-size:12px; }
      .field-val.masked { filter:blur(4px); user-select:none; }
      .icon-sm { width:28px; height:28px; border:0; border-radius:9px; display:grid; place-items:center; color:var(--vw-muted); background:var(--sfc); cursor:pointer; flex:none; }
      .icon-sm:hover { background:var(--sfch); }
      .icon-sm svg { width:14px; height:14px; }
      .actions { display:flex; gap:7px; margin-top:2px; }
      .btn-primary { flex:1; height:34px; border:0; border-radius:17px; background:var(--p); color:var(--onp); font:500 12px/1 var(--vw-font-ui); cursor:pointer; }
      .btn-primary:hover { background:var(--vw-primary-bg-hover); }
      .btn-outline { height:34px; padding:0 14px; border:0; border-radius:17px; background:var(--pc); color:var(--onpc); font:500 12px/1 var(--vw-font-ui); cursor:pointer; }
      .btn-outline:hover { filter:brightness(.97); }

      .commands { flex:1; min-height:0; overflow:auto; padding:8px 8px 12px; }
      .command { width:100%; min-height:46px; display:flex; align-items:center; gap:11px; padding:0 11px; border:0; border-radius:12px; background:transparent; color:var(--vw-ink); font:400 13px/1.3 var(--vw-font-ui); text-align:left; cursor:pointer; }
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
    this.stopTotp();
  }

  protected override updated(changed: Map<string, unknown>): void {
    if (changed.has('selectedCipherId')) {
      this.revealed = false;
      this.password = '';
      this.detailStatus = undefined;
      this.stopTotp();
      const item = this.selected();
      if (item?.hasTotp && this.extras) void this.loadTotp();
    }
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
      this.requestUpdate();
      return;
    }
    if (!this.extras) return;
    const result = await this.extras.getField('password');
    if (result.ok) {
      this.password = result.value ?? '';
      this.revealed = true;
      this.detailStatus = undefined;
    } else {
      // The worker refused to release the secret (reprompt-protected / locked / sync required). The
      // root has already recorded the detailed error on its own status, which this view never renders,
      // so give the user local feedback instead of a dead eye button.
      this.detailStatus = { message: t('detail.repromptTitle'), tone: 'danger' };
    }
    this.requestUpdate();
  }

  private async loadTotp(): Promise<void> {
    if (!this.extras) return;
    if (this.totpLoading) return;
    this.totpLoading = true;
    try {
      const result = await this.extras.getTotp();
      if (!result.ok || !result.totp) return;
      this.totp = result.totp;
      this.requestUpdate();
      this.startTotpTick();
    } finally {
      this.totpLoading = false;
    }
  }

  private startTotpTick(): void {
    this.stopTotp();
    this.totpTimer = window.setInterval(() => {
      if (!this.totp) return;
      // A previous refresh is still deriving — skip this tick rather than stack concurrent derives.
      if (this.totpLoading) return;
      if (this.totp.remaining <= 1) {
        void this.loadTotp();
      } else {
        this.totp = { ...this.totp, remaining: this.totp.remaining - 1 };
        this.requestUpdate();
      }
    }, 1000);
  }

  private stopTotp(): void {
    if (this.totpTimer !== undefined) {
      clearInterval(this.totpTimer);
      this.totpTimer = undefined;
    }
    this.totp = undefined;
  }

  private copySecret(field: 'password', label: string): void {
    this.emit('vw-secret-request', { kind: 'field', field, label });
  }

  private copyValue(value: string, label: string): void {
    if (value) this.emit('vw-copy', { value, label });
  }

  protected override render() {
    return html`
      ${this.renderSearch()}
      ${this.query.trim().startsWith('/')
        ? this.renderCommands()
        : html`${this.renderChips()}<div class="list">${this.renderList()}</div>`}
    `;
  }

  private renderSearch() {
    return html`
      <label class="search">
        ${uiIcon('search')}
        <input
          type="search"
          aria-label=${t('popup.search')}
          placeholder=${t('popup.searchCommand')}
          .value=${this.query}
          @input=${(e: Event) => this.onSearch((e.target as HTMLInputElement).value)}
          @keydown=${(e: KeyboardEvent) => this.onSearchKeydown(e)}
        />
        ${this.query.trim().startsWith('/') ? html`<span class="command-badge">${t('popup.command')}</span>` : nothing}
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
    const q = this.query.trim().toLowerCase();
    return this.items.filter((item) => {
      if (item.deletedDate) return false;
      if (!matchesCategory(item, this.category)) return false;
      if (!q) return true;
      return (
        item.name.toLowerCase().includes(q) ||
        (item.username ?? '').toLowerCase().includes(q) ||
        item.uris.some((u) => u.toLowerCase().includes(q))
      );
    });
  }

  private suggestions(): TabAutofillSuggestion[] {
    return this.suggestionsState.status === 'ready' ? this.suggestionsState.suggestions : [];
  }

  private renderList() {
    const items = this.filteredItems();
    const showSuggestions = !this.query.trim() && this.category === 'all' && this.suggestions().length > 0;
    if (items.length === 0 && !showSuggestions) {
      return html`<div class="empty">${this.query.trim() ? t('list.emptySearch') : t('list.empty')}</div>`;
    }
    const mainLabel = this.query.trim()
      ? t('list.results', { count: items.length })
      : this.category === 'all'
        ? t('list.allItems')
        : t(CATEGORIES.find((c) => c.id === this.category)!.key);
    return html`
      ${showSuggestions ? this.renderSuggestionGroup() : nothing}
      <div class="group-label main">${mainLabel}</div>
      ${items.map((item, i) =>
        this.renderItem(item, false, undefined, i < STAGGER_LIMIT ? `calc(${i} * 40ms + 120ms)` : undefined),
      )}
    `;
  }

  private renderSuggestionGroup() {
    const suggestions = this.suggestions();
    const byId = new Map(this.items.map((i) => [i.id, i] as const));
    const first = suggestions[0];
    const firstItem = first ? byId.get(first.id) : undefined;
    const rawDomain = this.currentDomain || first?.matchedUri || firstItem?.uris[0] || '';
    let domain = rawDomain || t('list.currentSiteBare');
    try { domain = new URL(rawDomain).hostname; } catch { /* Keep the display-safe fallback. */ }
    const primary = first && firstItem && !firstItem.reprompt && !first.reprompt ? first : undefined;
    const hasPasskey = suggestions.some((suggestion) => byId.get(suggestion.id)?.hasPasskey);
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
            const item = byId.get(suggestion.id);
            return item ? html`
              <div class="hero-account">
                <span class="dot" aria-hidden="true"></span>
                <span class="account-copy">
                  <span class="account-user">${item.username || item.name}</span>
                  <span class="account-name">${item.name}</span>
                </span>
              </div>
            ` : nothing;
          })}
        </div>
        ${primary ? html`<button type="button" class="fill-pill hero-fill" @click=${() => this.fillSuggestion(primary)}>${t('list.fill')} · ${primary.name}</button>` : nothing}
      </section>
    `;
  }

  private renderItem(item: CipherSummary, isSuggestion: boolean, suggestion?: TabAutofillSuggestion, rowDelay?: string) {
    const expanded = this.selectedCipherId === item.id;
    // A reprompt-protected item cannot be released inline (the worker refuses with reprompt_required),
    // so an inline Fill/copy pill would fail silently. Route the row to open (toggle) instead, which
    // reaches the master-password reprompt flow — mirroring how the editor route gates protected items.
    const needsReprompt = item.reprompt === true || suggestion?.reprompt === true;
    return html`
      <div>
        <div class="row ${expanded ? 'selected' : ''}" style=${rowDelay ? `animation-delay:${rowDelay}` : nothing} @click=${() => this.toggleItem(item.id)}>
          <div class="tile" style=${`background:${tileColor(item.id)}`}>${tileInitial(item.name)}</div>
          <div class="meta">
            <div class="title-row">
              <span class="title">${item.name}</span>
              ${item.hasPasskey
                ? html`<span class="pk" title=${t('list.passkeySupported')}>${uiIcon('passkey')}</span>`
                : nothing}
            </div>
            <div class="sub">${item.username ?? item.subtitle ?? ''}</div>
          </div>
          ${needsReprompt
            ? html`<span class="chev">${uiIcon('chevron')}</span>`
            : isSuggestion && suggestion
              ? html`<button
                  type="button"
                  class="fill-pill"
                  @click=${(e: Event) => { e.stopPropagation(); this.fillSuggestion(suggestion); }}
                >${t('list.fill')}</button>`
              : html`
                  <button
                    type="button"
                    class="row-copy"
                    title=${t('list.copyPassword')}
                    aria-label=${t('list.copyPassword')}
                    @click=${(e: Event) => { e.stopPropagation(); this.copySecret('password', t('detail.password')); }}
                  >${uiIcon('copy')}</button>
                  <span class="chev">${uiIcon('chevron')}</span>
                `}
        </div>
        ${expanded ? this.renderCard(item, suggestion) : nothing}
      </div>
    `;
  }

  private fillSuggestion(suggestion: TabAutofillSuggestion): void {
    if (suggestion.target) this.emit('vw-suggestion-fill', { cipherId: suggestion.id, target: suggestion.target });
    else this.emit('vw-item-fill', { cipherId: suggestion.id });
  }

  private renderCard(item: CipherSummary, suggestion?: TabAutofillSuggestion) {
    const isLogin = item.type === 1;
    return html`
      <div class="card" @click=${(e: Event) => e.stopPropagation()}>
        ${this.detailStatus
          ? html`<vw-status-message
              tone=${this.detailStatus.tone}
              .icon=${'alert'}
              .message=${this.detailStatus.message}
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
        ${isLogin
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
        ${item.hasTotp && this.totp
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
          ? html`<div><div class="field-label">${t(typeLabelKey(item))}</div><div class="field-val">${item.subtitle}</div></div>`
          : nothing}
        <div class="actions">
          <button class="btn-primary" @click=${() => this.openAndFill(item, suggestion)}>${t('detail.openAndFill')}</button>
          <button class="btn-outline" @click=${() => this.emit('vw-edit-item', { cipherId: item.id })}>${t('common.edit')}</button>
        </div>
      </div>
    `;
  }

  private openAndFill(item: CipherSummary, suggestion?: TabAutofillSuggestion): void {
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
