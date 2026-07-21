import { LitElement, css, html, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t, type MessageKey } from '../../i18n/index.js';
import '../../components/menu.js';
import type { MenuItem, VwMenu } from '../../components/menu.js';
import type { ToolAction, ToolActionDetail } from '../types.js';

const TOOL_ITEMS: { id: string; key: MessageKey; icon: NonNullable<MenuItem['icon']>; action: ToolAction }[] = [
  { id: 'generator', key: 'popup.generator', icon: 'wand', action: 'generator' },
  { id: 'health', key: 'popup.health', icon: 'checkCircle', action: 'health' },
  { id: 'sends', key: 'popup.sends', icon: 'mail', action: 'sends' },
  { id: 'sync', key: 'popup.sync', icon: 'refresh', action: 'sync' },
];

/**
 * The tools control: a trigger button and a keyboard `vw-menu` for the fully wired generator,
 * health, Send, and sync actions. Incomplete destructive tools stay out of the visible menu. It
 * performs no requests; every selection is a typed action, and closing restores trigger focus.
 */
export class VwToolsMenu extends LitElement {
  static override properties = {
    open: { type: Boolean },
    syncing: { type: Boolean },
    disabled: { type: Boolean },
  };

  declare open: boolean;
  declare syncing: boolean;
  declare disabled: boolean;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.open = false;
    this.syncing = false;
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
        width: 32px;
        height: 32px;
        padding: 0;
        border: 0;
        border-radius: 50%;
        background: transparent;
        color: var(--vw-text-2);
        cursor: pointer;
      }
      .trigger:hover { background: var(--vw-icon-hover); }
      .trigger:disabled { opacity:.5; cursor:default; }
      .trigger:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      .trigger svg { width: 17px; height: 17px; }
    `,
  ];

  private emitAction(action: ToolAction): void {
    emit<ToolActionDetail>(this, 'vw-tool-action', { action });
  }

  private handleSelect(event: Event): void {
    const { id } = (event as CustomEvent<{ id: string }>).detail;
    const match = TOOL_ITEMS.find((item) => item.id === id);
    this.open = false;
    if (match) this.emitAction(match.action);
  }

  private handleClose(): void {
    this.open = false;
    const trigger = this.shadowRoot?.querySelector<HTMLElement>('[data-trigger]');
    trigger?.focus();
  }

  /** Re-assert the menu's open state imperatively; see the note in `VwAccountMenu.updated`. */
  protected override willUpdate(changed: PropertyValues<this>): void {
    if (changed.has('disabled') && this.disabled) this.open = false;
  }

  protected override updated(): void {
    const menu = this.shadowRoot?.querySelector<VwMenu>('vw-menu');
    if (menu) menu.open = this.open;
  }

  protected override render() {
    const label = t('popup.tools');
    const items: MenuItem[] = TOOL_ITEMS.map((item) => ({
      id: item.id,
      label: item.action === 'sync' && this.syncing ? t('sync.syncing') : t(item.key),
      icon: item.icon,
      disabled: this.disabled || (item.action === 'sync' && this.syncing),
    }));
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
        ${uiIcon('sliders')}
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

customElements.define('vw-tools-menu', VwToolsMenu);

declare global {
  interface HTMLElementTagNameMap {
    'vw-tools-menu': VwToolsMenu;
  }
}
