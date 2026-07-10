import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../menus/account-menu.js';
import '../menus/tools-menu.js';
import type { AccountInfo } from '../types.js';

/**
 * The unlocked-vault header: the account menu, an Add and a Generator control, and the tools menu.
 * It performs no requests. Add/Generator raise `vw-add`/`vw-generator`; account and tool actions are
 * raised by the nested menus and bubble through unchanged.
 */
export class VwPopupHeader extends LitElement {
  static override properties = {
    accounts: { attribute: false },
    pinEnabled: { type: Boolean },
    deviceRemembered: { type: Boolean },
  };

  declare accounts: AccountInfo[];
  declare pinEnabled: boolean;
  declare deviceRemembered: boolean;

  constructor() {
    super();
    this.accounts = [];
    this.pinEnabled = false;
    this.deviceRemembered = false;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: block;
      }
      .header {
        display: flex;
        align-items: center;
        gap: 4px;
        padding: 4px 0;
      }
      .spacer {
        flex: 1;
      }
      .brand {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        color: var(--vw-blue-600);
        font-weight: 600;
        font-size: 14px;
      }
      .brand svg {
        width: 18px;
        height: 18px;
      }
    `,
  ];

  private emit(type: string): void {
    this.dispatchEvent(new CustomEvent(type, { bubbles: true, composed: true }));
  }

  protected override render() {
    return html`
      <div class="header">
        <span class="brand">${uiIcon('shield')}<span>Vaultwarden</span></span>
        <span class="spacer"></span>
        <button type="button" class="icon-button" data-add title="Add item" aria-label="Add item" @click=${() => this.emit('vw-add')}>
          ${uiIcon('plus')}
        </button>
        <button type="button" class="icon-button" data-generator title="Password generator" aria-label="Password generator" @click=${() => this.emit('vw-generator')}>
          ${uiIcon('key')}
        </button>
        <vw-tools-menu></vw-tools-menu>
        <vw-account-menu
          .accounts=${this.accounts}
          .pinEnabled=${this.pinEnabled}
          .deviceRemembered=${this.deviceRemembered}
        ></vw-account-menu>
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
