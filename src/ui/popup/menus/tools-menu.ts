import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/menu.js';
import type { MenuItem, VwMenu } from '../../components/menu.js';
import type { ToolAction, ToolActionDetail } from '../types.js';

const TOOL_ITEMS: { item: MenuItem; action: ToolAction }[] = [
  { item: { id: 'generator', label: 'Password generator', icon: 'key' }, action: 'generator' },
  { item: { id: 'health', label: 'Password health', icon: 'checkCircle' }, action: 'health' },
  { item: { id: 'sends', label: 'Sends', icon: 'mail' }, action: 'sends' },
  { item: { id: 'trash', label: 'Trash', icon: 'trash' }, action: 'trash' },
  { item: { id: 'sync', label: 'Sync vault', icon: 'refresh' }, action: 'sync' },
];

/**
 * The tools control: a trigger button and a keyboard `vw-menu` for health, Sends, trash, and sync.
 * It performs no requests — every selection is a typed `vw-tool-action` (closed `ToolAction` union) —
 * and closing the menu restores focus to the trigger.
 */
export class VwToolsMenu extends LitElement {
  static override properties = {
    open: { type: Boolean },
  };

  declare open: boolean;

  constructor() {
    super();
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

  private emitAction(action: ToolAction): void {
    emit<ToolActionDetail>(this, 'vw-tool-action', { action });
  }

  private handleSelect(event: Event): void {
    const { id } = (event as CustomEvent<{ id: string }>).detail;
    const match = TOOL_ITEMS.find((t) => t.item.id === id);
    this.open = false;
    if (match) this.emitAction(match.action);
  }

  private handleClose(): void {
    this.open = false;
    const trigger = this.shadowRoot?.querySelector<HTMLElement>('[data-trigger]');
    trigger?.focus();
  }

  /** Re-assert the menu's open state imperatively; see the note in `VwAccountMenu.updated`. */
  protected override updated(): void {
    const menu = this.shadowRoot?.querySelector<VwMenu>('vw-menu');
    if (menu) menu.open = this.open;
  }

  protected override render() {
    return html`
      <button
        type="button"
        class="icon-button"
        data-trigger
        aria-haspopup="menu"
        aria-expanded=${this.open ? 'true' : 'false'}
        title="Tools"
        aria-label="Tools"
        @click=${() => { this.open = !this.open; }}
      >
        ${uiIcon('refresh')}
      </button>
      <div class="anchor">
        <vw-menu
          label="Tools"
          .items=${TOOL_ITEMS.map((t) => t.item)}
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
