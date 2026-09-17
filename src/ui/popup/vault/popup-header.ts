import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/logo.js';

/** Compact identity, workspace, and security actions for quick access. */
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
        height:52px;
        padding:0 16px;
        border-bottom:1px solid var(--vw-line-1);
        background:var(--vw-panel);
      }
      .brand { font-size:15px; font-weight:600; color:var(--vw-ink); }
      .spacer { flex:1; }
      button {
        appearance:none;
        display:inline-flex;
        align-items:center;
        justify-content:center;
        border:0;
        background:transparent;
        color:var(--vw-text-2);
        cursor:pointer;
        font:inherit;
        padding:0;
        flex-shrink:0;
        transition:background-color var(--vw-dur-fast),color var(--vw-dur-fast);
      }
      button:hover:not(:disabled) { background:var(--vw-icon-hover); }
      button:disabled { color:var(--vw-disabled-fg); cursor:default; }
      button:focus-visible { outline:2px solid var(--vw-accent); outline-offset:2px; }
      .icon {
        width:32px;
        height:32px;
        border-radius:var(--vw-radius-control);
      }
      .icon svg { width:17px; height:17px; }
      .control-slot { display:inline-flex; align-items:center; }
      @media(prefers-reduced-motion:reduce) { button { transition:none; } }
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
        <button type="button" class="icon" data-open-workspace title=${t('workspace.open')} aria-label=${t('workspace.open')} ?disabled=${this.busy} @click=${() => this.fire('vw-open-workspace')}>
          ${uiIcon('globe')}
        </button>
        <span class="control-slot"><slot name="tools"></slot></span>
        <button type="button" class="icon" data-lock title=${t('popup.lock')} aria-label=${t('popup.lock')} ?disabled=${this.busy} @click=${() => this.fire('vw-lock')}>
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
