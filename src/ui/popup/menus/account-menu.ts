import { LitElement, css, html, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/menu.js';
import type { MenuItem, VwMenu } from '../../components/menu.js';
import type { AccountAction, AccountActionDetail, AccountInfo } from '../types.js';

/**
 * The account control: a trigger button and a keyboard `vw-menu` mapping every approved account
 * action to a typed `vw-account-action` event (closed `AccountAction` union, plus a target email for
 * account switching). It performs no requests. Destructive account removal stays hidden until a
 * confirmation flow exists. Menu ids are internal indices, and closing restores trigger focus.
 */
export class VwAccountMenu extends LitElement {
  static override properties = {
    accounts: { attribute: false },
    pinEnabled: { type: Boolean },
    deviceRemembered: { type: Boolean },
    open: { type: Boolean },
    disabled: { type: Boolean },
  };

  declare accounts: AccountInfo[];
  declare pinEnabled: boolean;
  declare deviceRemembered: boolean;
  declare open: boolean;
  declare disabled: boolean;

  private actionById = new Map<string, AccountActionDetail>();
  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.accounts = [];
    this.pinEnabled = false;
    this.deviceRemembered = false;
    this.open = false;
    this.disabled = false;
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
        top: 36px;
        right: 0;
        z-index: 20;
      }
      .trigger {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 30px;
        height: 30px;
        padding: 0;
        border: 0;
        border-radius: 50%;
        background: #7c4dff;
        color: #fff;
        cursor: pointer;
      }
      .trigger:hover { filter: brightness(.96); }
      .trigger:disabled { opacity:.5; cursor:default; }
      .trigger:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      .trigger svg { width: 16px; height: 16px; }
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
        add(`${t('auth.switchAccount')} · ${account.email}`, { action: 'switch-account', email: account.email }, { icon: 'user' });
      }
    }
    add(t('auth.addAccount'), { action: 'add-account' }, { icon: 'plus' });
    add(this.pinEnabled ? t('auth.managePin') : t('auth.setPin'), { action: 'pin' }, { icon: 'lock' });
    add(t('popup.accountSecurity'), { action: 'account-security' }, { icon: 'key' });
    add(t('popup.settings'), { action: 'options' }, { icon: 'globe' });
    if (this.deviceRemembered) {
      add(t('auth.forgetDevice'), { action: 'forget-device' }, { icon: 'alert' });
    }
    add(t('popup.lock'), { action: 'lock' }, { icon: 'lock' });
    add(t('auth.logout'), { action: 'logout' }, { icon: 'logout', tone: 'danger' });
    return items;
  }

  private emitAction(action: AccountAction, email?: string): void {
    const detail: AccountActionDetail = email !== undefined ? { action, email } : { action };
    emit<AccountActionDetail>(this, 'vw-account-action', detail);
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
  protected override willUpdate(changed: PropertyValues<this>): void {
    if (changed.has('disabled') && this.disabled) this.open = false;
  }

  protected override updated(): void {
    const menu = this.shadowRoot?.querySelector<VwMenu>('vw-menu');
    if (menu) menu.open = this.open;
  }

  protected override render() {
    const items = this.buildItems().map((item) => ({ ...item, disabled: this.disabled || item.disabled === true }));
    const label = t('popup.account');
    return html`
      <button
        type="button"
        class="trigger"
        data-trigger
        aria-haspopup="menu"
        aria-expanded=${this.open ? 'true' : 'false'}
        ?disabled=${this.disabled}
        title=${label}
        aria-label=${label}
        @click=${() => { this.open = !this.open; }}
      >
        ${uiIcon('user')}
      </button>
      <div class="anchor">
        <vw-menu
          .label=${label}
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
