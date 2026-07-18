import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/logo.js';

/** Compact Chrome-style identity and security bar from the new popup handoff. */
export class VwPopupHeader extends LitElement {
  static override properties = {
    generatorActive: { type: Boolean },
    totpActive: { type: Boolean },
    syncing: { type: Boolean },
  };

  declare generatorActive: boolean;
  declare totpActive: boolean;
  declare syncing: boolean;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.generatorActive = false;
    this.totpActive = false;
    this.syncing = false;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display:block; flex:none; }
      .bar {
        display:flex;
        align-items:center;
        gap:9px;
        height:50px;
        padding:0 14px;
        border-bottom:1px solid var(--vw-line-1);
        background:var(--vw-panel);
      }
      .brand { font-size:14px; font-weight:500; color:var(--vw-ink); letter-spacing:.01em; }
      .spacer { flex:1; }
      button {
        display:inline-flex;
        align-items:center;
        justify-content:center;
        border:0;
        background:transparent;
        color:var(--vw-text-2);
        cursor:pointer;
        font:inherit;
      }
      button:hover { background:var(--vw-icon-hover); }
      button:focus-visible { outline:none; box-shadow:var(--vw-focus); }
      .score {
        gap:5px;
        height:32px;
        padding:0 7px;
        border-radius:16px;
        color:var(--grn);
        font-size:11px;
        font-weight:500;
      }
      .score-ring {
        position:relative;
        width:20px;
        height:20px;
        border-radius:50%;
        background:conic-gradient(var(--grn) 0 86%, var(--vw-track) 86% 100%);
      }
      .score-ring::after {
        content:'';
        position:absolute;
        inset:3px;
        border-radius:50%;
        background:var(--vw-panel);
      }
      .score.syncing .score-ring { animation:mvSpin .8s linear infinite; }
      .icon {
        width:32px;
        height:32px;
        border-radius:16px;
      }
      .icon svg { width:17px; height:17px; }
      .avatar {
        width:28px;
        height:28px;
        border-radius:50%;
        background:#7c4dff;
        color:#fff;
        font-size:12px;
        font-weight:500;
      }
    `,
  ];

  private fire(type: string): void {
    emit(this, type);
  }

  protected override render() {
    return html`
      <div class="bar">
        <vw-logo variant="header"></vw-logo>
        <span class="brand">${t('common.brand')}</span>
        <span class="spacer"></span>
        <button
          type="button"
          class="score ${this.syncing ? 'syncing' : ''}"
          title=${t('sync.now')}
          aria-label=${t('sync.now')}
          ?disabled=${this.syncing}
          @click=${() => this.fire('vw-sync-now')}
        >
          <span class="score-ring" aria-hidden="true"></span><span>86</span>
        </button>
        <button type="button" class="icon" title=${t('popup.lock')} aria-label=${t('popup.lock')} @click=${() => this.fire('vw-lock')}>
          ${uiIcon('lock')}
        </button>
        <button type="button" class="avatar" title=${t('popup.settings')} aria-label=${t('popup.settings')} @click=${() => this.fire('vw-open-settings')}>密</button>
      </div>
    `;
  }
}

customElements.define('vw-popup-header', VwPopupHeader);

declare global {
  interface HTMLElementTagNameMap {
    'vw-popup-header': VwPopupHeader;
  }
}
