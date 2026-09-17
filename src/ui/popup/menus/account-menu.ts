import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
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
    pinAllowed: { type: Boolean },
    deviceRemembered: { type: Boolean },
    deviceLoginApprovalCount: { type: Number },
    constrained: { type: Boolean },
    open: { type: Boolean },
    disabled: { type: Boolean },
  };

  declare accounts: AccountInfo[];
  declare pinEnabled: boolean;
  declare pinAllowed: boolean;
  declare deviceRemembered: boolean;
  declare deviceLoginApprovalCount: number;
  declare constrained: boolean;
  declare open: boolean;
  declare disabled: boolean;

  private actionById = new Map<string, AccountActionDetail>();
  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.accounts = [];
    this.pinEnabled = false;
    this.pinAllowed = true;
    this.deviceRemembered = false;
    this.deviceLoginApprovalCount = 0;
    this.constrained = false;
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
        top: 39px;
        right: 0;
        z-index: 20;
        width: min(280px, calc(100vw - 32px));
        border: 1px solid var(--vw-line-2);
        border-radius: var(--vw-radius-panel);
        background: var(--vw-panel);
        box-shadow: var(--vw-panel-shadow);
        overflow: hidden;
      }
      .anchor[hidden] { display: none; }
      .account-context { padding: 13px 15px; border-bottom: 1px solid var(--vw-line-1); }
      .account-context span { display: block; font-size: 11px; color: var(--vw-text-3); margin-bottom: 4px; }
      .account-context strong { display: block; font-size: 13px; font-weight: 500; overflow-wrap: anywhere; }
      vw-menu { display: block; }
      vw-menu::part(menu) { min-width: 0; max-width: none; max-height:min(420px,calc(100dvh - 148px)); border: 0; border-radius: 0; box-shadow: none; }
      .trigger {
        appearance: none;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 30px;
        height: 30px;
        padding: 0;
        border: 0;
        border-radius: 50%;
        background: var(--pc);
        color: var(--onpc);
        font: 600 13px/1 var(--vw-font-ui);
        cursor: pointer;
        transition: background-color var(--vw-dur-fast), color var(--vw-dur-fast);
      }
      .trigger:hover:not(:disabled) { background: var(--vw-teal-18); }
      .trigger:disabled { color:var(--vw-disabled-fg); background:var(--vw-disabled-bg); cursor:default; }
      .trigger:focus-visible { outline: 2px solid var(--vw-accent); outline-offset: 2px; }
      .trigger svg { width: 16px; height: 16px; }
      @media(prefers-reduced-motion:reduce) { .trigger { transition:none; } }
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
    if (this.constrained) {
      add(t('popup.lock'), { action: 'lock' }, { icon: 'lock' });
      add(t('auth.logout'), { action: 'logout' }, { icon: 'logout', tone: 'danger' });
      return items;
    }
    add(t('auth.addAccount'), { action: 'add-account' }, { icon: 'plus' });
    if (this.pinAllowed) {
      add(this.pinEnabled ? t('auth.managePin') : t('auth.setPin'), { action: 'pin' }, { icon: 'lock' });
    } else {
      add(t('auth.pinManaged'), { action: 'pin' }, { icon: 'lock', disabled: true });
    }
    add(t('popup.accountSecurity'), { action: 'account-security' }, { icon: 'key' });
    const approvalCount = Number.isSafeInteger(this.deviceLoginApprovalCount)
      ? Math.max(0, this.deviceLoginApprovalCount)
      : 0;
    add(
      t('auth.deviceLogin.approvalsMenu', { count: approvalCount }),
      { action: 'device-login-approvals' },
      { icon: 'idcard' },
    );
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
    const activeAccount = this.accounts.find((account) => account.active);
    return html`
      <button
        type="button"
        class="trigger"
        data-trigger
        aria-haspopup="menu"
        aria-expanded=${this.open ? 'true' : 'false'}
        ?disabled=${this.disabled}
        title=${activeAccount ? `${label} · ${activeAccount.email}` : label}
        aria-label=${activeAccount ? `${label} · ${activeAccount.email}` : label}
        @click=${() => { this.open = !this.open; }}
      >
        ${activeAccount?.email.trim().charAt(0).toUpperCase() || uiIcon('user')}
      </button>
      <div class="anchor" ?hidden=${!this.open}>
        ${activeAccount ? html`<div class="account-context"><span>${label}</span><strong>${activeAccount.email}</strong></div>` : nothing}
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
