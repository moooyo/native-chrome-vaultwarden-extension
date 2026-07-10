import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/menu.js';
import type { MenuItem, VwMenu } from '../../components/menu.js';
import type { AccountAction, AccountActionDetail, AccountInfo } from '../types.js';

/**
 * The account control: a trigger button and a keyboard `vw-menu` mapping every approved account
 * action to a typed `vw-account-action` event (closed `AccountAction` union, plus a target email for
 * switch/remove). It performs no requests. Menu ids are internal indices — never emails or vault ids
 * — and closing the menu restores focus to the trigger.
 */
export class VwAccountMenu extends LitElement {
  static override properties = {
    accounts: { attribute: false },
    pinEnabled: { type: Boolean },
    deviceRemembered: { type: Boolean },
    open: { type: Boolean },
  };

  declare accounts: AccountInfo[];
  declare pinEnabled: boolean;
  declare deviceRemembered: boolean;
  declare open: boolean;

  private actionById = new Map<string, AccountActionDetail>();

  constructor() {
    super();
    this.accounts = [];
    this.pinEnabled = false;
    this.deviceRemembered = false;
    this.open = false;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: inline-block;
        position: relative;
      }
      .anchor {
        position: absolute;
        top: 34px;
        right: 0;
        z-index: 20;
      }
    `,
  ];

  private buildItems(): MenuItem[] {
    const items: MenuItem[] = [];
    this.actionById = new Map();
    let n = 0;
    const add = (label: string, detail: AccountActionDetail, extra: Partial<MenuItem> = {}): void => {
      const id = `a${n}`;
      n += 1;
      items.push({ id, label, ...extra });
      this.actionById.set(id, detail);
    };

    for (const account of this.accounts) {
      if (!account.active) {
        add(`Switch to ${account.email}`, { action: 'switch-account', email: account.email }, { icon: 'user' });
      }
    }
    for (const account of this.accounts) {
      add(`Remove ${account.email}`, { action: 'remove-account', email: account.email }, { icon: 'trash' });
    }
    add('Add account', { action: 'add-account' }, { icon: 'plus' });
    add(this.pinEnabled ? 'Manage PIN' : 'Set up PIN', { action: 'pin' }, { icon: 'lock' });
    add('Account security', { action: 'account-security' }, { icon: 'key' });
    add('Options', { action: 'options' }, { icon: 'globe' });
    if (this.deviceRemembered) {
      add('Forget this device', { action: 'forget-device' }, { icon: 'alert' });
    }
    add('Lock', { action: 'lock' }, { icon: 'lock' });
    add('Log out', { action: 'logout' }, { icon: 'logout', tone: 'danger' });
    return items;
  }

  private emitAction(action: AccountAction, email?: string): void {
    const detail: AccountActionDetail = email !== undefined ? { action, email } : { action };
    this.dispatchEvent(new CustomEvent<AccountActionDetail>('vw-account-action', { detail, bubbles: true, composed: true }));
  }

  private handleSelect(event: Event): void {
    const { id } = (event as CustomEvent<{ id: string }>).detail;
    const detail = this.actionById.get(id);
    this.open = false;
    if (detail) this.emitAction(detail.action, detail.email);
  }

  private handleClose(): void {
    this.open = false;
    const trigger = this.shadowRoot?.querySelector<HTMLElement>('[data-trigger]');
    trigger?.focus();
  }

  /** Re-assert the menu's open state imperatively. `vw-menu` mutates its own `open` when it
   *  self-closes (select/Escape/outside click); without this, Lit's per-binding dirty check can
   *  skip re-opening it when this component's `open` returns to the same value it last committed. */
  protected override updated(): void {
    const menu = this.shadowRoot?.querySelector<VwMenu>('vw-menu');
    if (menu) menu.open = this.open;
  }

  protected override render() {
    const items = this.buildItems();
    return html`
      <button
        type="button"
        class="icon-button"
        data-trigger
        aria-haspopup="menu"
        aria-expanded=${this.open ? 'true' : 'false'}
        title="Account"
        aria-label="Account"
        @click=${() => { this.open = !this.open; }}
      >
        ${uiIcon('user')}
      </button>
      <div class="anchor">
        <vw-menu
          label="Account"
          .items=${items}
          .open=${this.open}
          @vw-menu-select=${(e: Event) => this.handleSelect(e)}
          @vw-menu-close=${() => this.handleClose()}
        ></vw-menu>
      </div>
    `;
  }
}

customElements.define('vw-account-menu', VwAccountMenu);

declare global {
  interface HTMLElementTagNameMap {
    'vw-account-menu': VwAccountMenu;
  }
}
