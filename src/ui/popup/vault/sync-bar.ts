import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';

/** Fixed bottom action rail shared by every unlocked popup view. */
export class VwSyncBar extends LitElement {
  static override properties = {
    syncing: { type: Boolean },
    lastSuccessfulSyncAt: { type: Number },
    dirty: { attribute: false },
    generatorActive: { type: Boolean },
    totpActive: { type: Boolean },
    healthActive: { type: Boolean },
    disabled: { type: Boolean },
  };

  declare syncing: boolean;
  declare lastSuccessfulSyncAt: number | undefined;
  declare dirty: boolean | undefined;
  declare generatorActive: boolean;
  declare totpActive: boolean;
  declare healthActive: boolean;
  declare disabled: boolean;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.syncing = false;
    this.lastSuccessfulSyncAt = undefined;
    this.dirty = undefined;
    this.generatorActive = false;
    this.totpActive = false;
    this.healthActive = false;
    this.disabled = false;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display:block; flex:none; }
      .bar {
        display:flex;
        align-items:center;
        height:48px;
        padding:0 10px 0 14px;
        border-top:1px solid var(--vw-line-1);
        background:var(--vw-panel);
      }
      .hint {
        flex:1;
        min-width:0;
        color:var(--vw-muted);
        font-family:var(--vw-font-mono);
        font-size:9.5px;
        white-space:nowrap;
      }
      .actions { display:flex; align-items:center; gap:2px; }
      button {
        display:grid;
        place-items:center;
        width:34px;
        height:34px;
        border:0;
        border-radius:17px;
        background:transparent;
        color:var(--vw-text-2);
        cursor:pointer;
      }
      button:hover { background:var(--vw-icon-hover); }
      button:disabled { opacity:.5; cursor:default; }
      button.active { background:var(--pc); color:var(--onpc); }
      button.add { margin-left:3px; border-radius:12px; background:var(--p); color:var(--onp); }
      button.add:hover { background:var(--vw-primary-bg-hover); }
      button:focus-visible { outline:none; box-shadow:var(--vw-focus); }
      button svg { width:18px; height:18px; }
      button.add svg { width:20px; height:20px; }
    `,
  ];

  private fire(type: string): void {
    emit(this, type);
  }

  private syncHint(): string {
    if (this.syncing) return t('sync.syncing');
    if (this.dirty === undefined) return t('sync.unknown');
    if (this.dirty) return t('sync.pending');
    const last = this.lastSuccessfulSyncAt;
    if (last === undefined) return t('sync.never');
    const elapsed = Math.max(0, Date.now() - last);
    let relative: string;
    if (elapsed < 60_000) relative = t('sync.justNow');
    else if (elapsed < 3_600_000) relative = t('sync.minutesAgo', { count: Math.floor(elapsed / 60_000) });
    else if (elapsed < 86_400_000) relative = t('sync.hoursAgo', { count: Math.floor(elapsed / 3_600_000) });
    else relative = t('sync.daysAgo', { count: Math.floor(elapsed / 86_400_000) });
    return t('sync.synced', { time: relative });
  }

  protected override render() {
    const hint = this.syncHint();
    return html`
      <div class="bar">
        <span class="hint" title=${hint}>${hint}</span>
        <div class="actions">
          <button type="button" class=${this.generatorActive ? 'active' : ''} title=${t('popup.generator')} aria-label=${t('popup.generator')} aria-pressed=${this.generatorActive ? 'true' : 'false'} ?disabled=${this.disabled} @click=${() => this.fire('vw-generator-toggle')}>${uiIcon('wand')}</button>
          <button type="button" class=${this.totpActive ? 'active' : ''} title=${t('popup.authenticator')} aria-label=${t('popup.authenticator')} aria-pressed=${this.totpActive ? 'true' : 'false'} ?disabled=${this.disabled} @click=${() => this.fire('vw-open-totp')}>${uiIcon('clock')}</button>
          <button type="button" class=${this.healthActive ? 'active' : ''} title=${t('popup.health')} aria-label=${t('popup.health')} aria-pressed=${this.healthActive ? 'true' : 'false'} ?disabled=${this.disabled} @click=${() => this.fire('vw-open-health')}>${uiIcon('shield')}</button>
          <button type="button" title=${t('popup.settings')} aria-label=${t('popup.settings')} ?disabled=${this.disabled} @click=${() => this.fire('vw-open-settings')}>${uiIcon('sliders')}</button>
          <button type="button" class="add" title=${t('popup.newItem')} aria-label=${t('popup.newItem')} ?disabled=${this.disabled} @click=${() => this.fire('vw-add')}>${uiIcon('plus')}</button>
        </div>
      </div>
    `;
  }
}

customElements.define('vw-sync-bar', VwSyncBar);

declare global {
  interface HTMLElementTagNameMap {
    'vw-sync-bar': VwSyncBar;
  }
}
