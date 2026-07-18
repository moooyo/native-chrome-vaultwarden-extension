import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import { getPrefs, setPref, subscribePrefs } from '../../prefs.js';
import '../../components/setting-card.js';
import '../../components/toggle.js';
import '../../components/status-message.js';
import type { ConnectionSaveDetail, SectionStatus } from '../types.js';

/**
 * Account & sync (账户与同步) — the MiYu redesign of the connection section. It shows the signed-in
 * account, the self-hosted server URL (the sole control that leads to a host-permission prompt), the
 * vault sync status, and the auto-sync preference. Validation/normalization stays local and
 * synchronous: the server-URL Save parses with `new URL(...)` and emits an already-normalized value on
 * `vw-connection-save`, so the root can request host permission in the same user gesture. Sync is a
 * fire-and-forget `vw-sync-now`; the root performs the request and drives `syncing`/`lastSync`/status.
 */
export class VwConnectionSection extends LitElement {
  static override properties = {
    serverUrl: { type: String },
    accountEmail: { type: String },
    accountName: { type: String },
    lastSync: { type: Number },
    syncing: { type: Boolean },
    pending: { type: Boolean },
    status: { attribute: false },
    validationError: { state: true },
  };

  declare serverUrl: string;
  declare accountEmail: string;
  declare accountName: string;
  declare lastSync: number | undefined;
  declare syncing: boolean;
  declare pending: boolean;
  declare status: SectionStatus | undefined;
  declare validationError: string | undefined;

  private i18n = new LocalizeController(this);
  private unsubscribe: (() => void) | undefined = undefined;

  constructor() {
    super();
    this.serverUrl = '';
    this.accountEmail = '';
    this.accountName = '';
    this.lastSync = undefined;
    this.syncing = false;
    this.pending = false;
    this.status = undefined;
    this.validationError = undefined;
  }

  override connectedCallback(): void {
    super.connectedCallback();
    this.unsubscribe = subscribePrefs(() => this.requestUpdate());
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.unsubscribe?.();
    this.unsubscribe = undefined;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: flex; flex-direction: column; gap: 8px; }

      /* Account identity card */
      .account { display:flex; align-items:center; gap:14px; padding:14px 16px; background:var(--vw-card); border:1px solid var(--vw-line-1); border-radius:16px; }
      .avatar { width:40px; height:40px; border-radius:50%; background:#7c4dff; color:#fff; display:grid; place-items:center; font-size:17px; font-weight:500; flex:none; }
      .account-text { flex: 1; min-width: 0; }
      .account-name { font-size:14px; font-weight:500; color:var(--vw-ink); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
      .account-sub { margin-top: 2px; font-size: 11.5px; color: var(--vw-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

      /* Server URL control */
      .server-control { display: flex; gap: 8px; width: 100%; }
      .url-input { flex: 1; min-width: 0; height: 30px; padding: 0 11px; border: 1px solid var(--vw-line-3); border-radius: var(--vw-radius-input); background: var(--vw-card); color: var(--vw-ink); font-family: var(--vw-font-ui); font-size: 13px; }
      .url-input::placeholder { color: var(--vw-placeholder); }
      .url-input:focus { outline: none; border-color: var(--vw-accent); box-shadow: var(--vw-focus); }

      /* Buttons */
      .btn { display: inline-flex; align-items: center; justify-content: center; gap: 6px; height: 30px; padding: 0 14px; border: 1px solid transparent; border-radius: var(--vw-radius-input); font-family: var(--vw-font-ui); font-size: 12.5px; font-weight: 600; white-space: nowrap; cursor: pointer; transition: background-color var(--vw-dur-fast), border-color var(--vw-dur-fast); }
      .btn:disabled { opacity: 0.5; cursor: default; }
      .btn:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      .btn svg { width: 14px; height: 14px; }
      .btn.ink { background: var(--vw-primary-bg); color: var(--vw-primary-fg); }
      .btn.ink:hover:not(:disabled) { background: var(--vw-primary-bg-hover); }
      .btn.outline { border-color: var(--vw-line-3); background: var(--vw-card); color: var(--vw-text-4); }
      .btn.outline:hover:not(:disabled) { background: var(--vw-row-hover); }
      .btn.account-sync { height:34px; border:0; border-radius:17px; background:var(--pc); color:var(--onpc); }

      /* Sync button spinner */
      .ico { display: inline-flex; }
      .ico.spin svg { animation: vw-spin 0.8s linear infinite; }
      @keyframes vw-spin { to { transform: rotate(360deg); } }

      .status { margin-top: 6px; }
    `,
  ];

  private avatarInitial(): string {
    const source = this.accountName || this.accountEmail;
    const match = source.match(/[\p{L}\p{N}]/u);
    return match ? match[0]!.toUpperCase() : '?';
  }

  private accountSubtitle(displayName: string): string {
    const selfHosted = t('options.account.selfHosted');
    return this.accountEmail && this.accountEmail !== displayName
      ? `${this.accountEmail} · ${selfHosted}`
      : selfHosted;
  }

  private relativeTime(ts: number): string {
    const minutes = Math.floor((Date.now() - ts) / 60000);
    if (minutes < 1) return t('sync.justNow');
    if (minutes < 60) return t('sync.minutesAgo', { count: minutes });
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return t('sync.hoursAgo', { count: hours });
    return t('sync.daysAgo', { count: Math.floor(hours / 24) });
  }

  private syncDescription(): string {
    if (this.syncing) return t('options.account.syncing');
    if (this.lastSync) return t('options.account.lastSync', { time: this.relativeTime(this.lastSync) });
    return t('sync.never');
  }

  private saveServerUrl(): void {
    if (this.pending) return;
    this.validationError = undefined;
    const raw = this.renderRoot.querySelector<HTMLInputElement>('[data-server-url]')?.value ?? '';
    let normalized: string;
    try {
      normalized = new URL(raw).toString();
    } catch {
      this.validationError = t('auth.serverUrl');
      return;
    }
    emit<ConnectionSaveDetail>(this, 'vw-connection-save', { serverUrl: normalized });
  }

  private syncNow(): void {
    if (this.syncing) return;
    emit(this, 'vw-sync-now');
  }

  private renderStatus() {
    if (this.validationError) {
      return html`<vw-status-message class="status" tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>`;
    }
    if (this.status) {
      return html`<vw-status-message class="status" tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`;
    }
    return nothing;
  }

  protected override render() {
    const displayName = this.accountName || this.accountEmail || t('popup.account');
    const prefs = getPrefs();
    return html`
      <div class="account" data-account>
        <div class="avatar" aria-hidden="true">${this.avatarInitial()}</div>
        <div class="account-text">
          <div class="account-name">${displayName}</div>
          <div class="account-sub">${this.accountSubtitle(displayName)}</div>
        </div>
        <button type="button" class="btn account-sync" data-manage @click=${() => this.syncNow()}>${uiIcon('refresh')}<span>${t('options.account.syncNow')}</span></button>
      </div>

      <vw-setting-card stacked heading=${t('options.account.serverLabel')} description=${t('options.account.serverDesc')}>
        <div class="server-control">
          <input
            class="url-input"
            data-server-url
            type="text"
            inputmode="url"
            autocomplete="off"
            spellcheck="false"
            placeholder="https://vault.example.com"
            .value=${this.serverUrl}
          />
          <button type="button" class="btn ink" data-save ?disabled=${this.pending} @click=${() => this.saveServerUrl()}>
            ${uiIcon('check')}<span>${t('common.save')}</span>
          </button>
        </div>
      </vw-setting-card>

      <vw-setting-card heading=${t('options.account.syncTitle')} description=${this.syncDescription()}>
        <button type="button" class="btn outline" data-sync-now ?disabled=${this.syncing} @click=${() => this.syncNow()}>
          <span class="ico ${this.syncing ? 'spin' : ''}">${uiIcon('refresh')}</span>
          <span>${t('options.account.syncNow')}</span>
        </button>
      </vw-setting-card>

      <vw-setting-card heading=${t('options.account.encryption')} description=${t('options.account.encryptionDesc')}>
        <span style="color:var(--grn);font-size:12px;font-weight:500">${t('options.account.enabled')}</span>
      </vw-setting-card>

      <vw-setting-card heading=${t('options.account.autoSync')} description=${t('options.account.autoSyncDesc')}>
        <vw-toggle
          .checked=${prefs.autoSync}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => setPref('autoSync', e.detail.checked)}
        ></vw-toggle>
      </vw-setting-card>

      ${this.renderStatus()}
    `;
  }
}

customElements.define('vw-connection-section', VwConnectionSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-connection-section': VwConnectionSection;
  }
}
