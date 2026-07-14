import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/logo.js';

/**
 * The MiYu popup top bar: the logo + brand, then five 28px icon buttons — new item, authenticator
 * (2FA codes view), password generator (highlighted while the generator view is open), settings
 * (opens the options page), and lock. Emits `vw-add`, `vw-open-totp`, `vw-generator-toggle`,
 * `vw-open-settings`, `vw-lock`. Search lives in the vault body below, not here, matching the design.
 */
export class VwPopupHeader extends LitElement {
  static override properties = {
    generatorActive: { type: Boolean },
    totpActive: { type: Boolean },
  };

  declare generatorActive: boolean;
  declare totpActive: boolean;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.generatorActive = false;
    this.totpActive = false;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: block; flex: none; }
      .bar { display: flex; align-items: center; gap: 8px; padding: 12px 14px 9px; animation: mvIn 0.25s ease-out; }
      .brand { font-size: 14px; font-weight: 600; color: var(--vw-ink); letter-spacing: 0.01em; }
      .spacer { flex: 1; }
      button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 28px;
        height: 28px;
        border: none;
        border-radius: var(--vw-radius-chip);
        background: transparent;
        color: var(--vw-text-2);
        cursor: pointer;
        transition: background-color var(--vw-dur-fast), color var(--vw-dur-fast);
      }
      button:hover { background: var(--vw-icon-hover); }
      button:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      button svg { width: 15px; height: 15px; }
      button.active { color: var(--vw-teal-text); background: var(--vw-teal-10); }
    `,
  ];

  private emit(type: string): void {
    emit(this, type);
  }

  protected override render() {
    return html`
      <div class="bar">
        <vw-logo variant="header"></vw-logo>
        <span class="brand">${t('common.brand')}</span>
        <span class="spacer"></span>
        <button type="button" title=${t('popup.newItem')} aria-label=${t('popup.newItem')} @click=${() => this.emit('vw-add')}>
          ${uiIcon('plus')}
        </button>
        <button
          type="button"
          class=${this.totpActive ? 'active' : ''}
          title=${t('popup.authenticator')}
          aria-label=${t('popup.authenticator')}
          aria-pressed=${this.totpActive ? 'true' : 'false'}
          @click=${() => this.emit('vw-open-totp')}
        >
          ${uiIcon('clock')}
        </button>
        <button
          type="button"
          class=${this.generatorActive ? 'active' : ''}
          title=${t('popup.generator')}
          aria-label=${t('popup.generator')}
          aria-pressed=${this.generatorActive ? 'true' : 'false'}
          @click=${() => this.emit('vw-generator-toggle')}
        >
          ${uiIcon('wand')}
        </button>
        <button type="button" title=${t('popup.settings')} aria-label=${t('popup.settings')} @click=${() => this.emit('vw-open-settings')}>
          ${uiIcon('sliders')}
        </button>
        <button type="button" title=${t('popup.lock')} aria-label=${t('popup.lock')} @click=${() => this.emit('vw-lock')}>
          ${uiIcon('lock')}
        </button>
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
