import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';

/** Fixed bottom action rail shared by every unlocked popup view. */
export class VwSyncBar extends LitElement {
  static override properties = {
    syncing: { type: Boolean },
    lastSync: { type: Number },
    generatorActive: { type: Boolean },
    totpActive: { type: Boolean },
    healthActive: { type: Boolean },
    disabled: { type: Boolean },
  };

  declare syncing: boolean;
  declare lastSync: number | undefined;
  declare generatorActive: boolean;
  declare totpActive: boolean;
  declare healthActive: boolean;
  declare disabled: boolean;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.syncing = false;
    this.lastSync = undefined;
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

  protected override render() {
    return html`
      <div class="bar">
        <span class="hint" title=${this.syncing ? t('sync.syncing') : t('sync.now')}>↑↓ · ↵ · ⌘L</span>
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
