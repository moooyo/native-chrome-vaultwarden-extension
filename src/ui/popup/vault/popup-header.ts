import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/logo.js';

/** Compact Chrome-style identity and security bar from the new popup handoff. */
export class VwPopupHeader extends LitElement {
  static override properties = {
    busy: { type: Boolean },
  };

  declare busy: boolean;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.busy = false;
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
      button:disabled { opacity:.5; cursor:default; }
      button:focus-visible { outline:none; box-shadow:var(--vw-focus); }
      .icon {
        width:32px;
        height:32px;
        border-radius:16px;
      }
      .icon svg { width:17px; height:17px; }
      .control-slot { display:inline-flex; align-items:center; }
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
        <span class="control-slot"><slot name="tools"></slot></span>
        <button type="button" class="icon" title=${t('popup.lock')} aria-label=${t('popup.lock')} ?disabled=${this.busy} @click=${() => this.fire('vw-lock')}>
          ${uiIcon('lock')}
        </button>
        <span class="control-slot"><slot name="account"></slot></span>
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
