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
    query: { type: String },
  };

  declare accounts: AccountInfo[];
  declare pinEnabled: boolean;
  declare deviceRemembered: boolean;
  declare query: string;

  constructor() {
    super();
    this.accounts = [];
    this.pinEnabled = false;
    this.deviceRemembered = false;
    this.query = '';
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
        height: 100%;
        padding: 0 10px;
        box-sizing: border-box;
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
      .search {
        display: flex;
        align-items: center;
        gap: 6px;
        width: min(220px, 38vw);
        min-width: 120px;
        height: 34px;
        padding: 0 9px;
        border: 1px solid var(--vw-line);
        border-radius: var(--vw-radius-row);
        background: var(--vw-panel);
      }
      .search svg {
        width: 16px;
        height: 16px;
        color: var(--vw-muted);
      }
      .search input {
        flex: 1;
        min-width: 0;
        border: 0;
        outline: 0;
        background: transparent;
        color: var(--vw-ink);
        font: inherit;
      }
      .new-item {
        min-width: 92px;
      }
    `,
  ];

  private emit(type: string): void {
    this.dispatchEvent(new CustomEvent(type, { bubbles: true, composed: true }));
  }

  private emitSearch(query: string): void {
    this.dispatchEvent(new CustomEvent('vw-search-change', {
      detail: { query },
      bubbles: true,
      composed: true,
    }));
  }

  protected override render() {
    return html`
      <div class="header">
        <span class="brand">${uiIcon('shield')}<span>Vaultwarden</span></span>
        <span class="spacer"></span>
        <label class="search">
          ${uiIcon('search')}
          <input
            data-search
            type="search"
            aria-label="Search vault"
            placeholder="Search Vaultwarden"
            .value=${this.query}
            @input=${(event: Event) => this.emitSearch((event.target as HTMLInputElement).value)}
          />
        </label>
        <button type="button" class="button primary new-item" data-add @click=${() => this.emit('vw-add')}>
          ${uiIcon('plus')}<span>New item</span>
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
