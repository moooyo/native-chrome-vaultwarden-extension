import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from './tokens.js';
import { controlStyles } from './styles.js';
import { uiIcon, type IconName } from './icon.js';

export interface MenuItem {
  id: string;
  label: string;
  icon?: IconName;
  tone?: 'normal' | 'danger';
  disabled?: boolean;
}

/**
 * A dormant popup menu built from native <button role="menuitem"> controls.
 * Keyboard support: ArrowUp/ArrowDown/Home/End move the active item, Enter
 * and Space select it, Escape closes it. A document-level pointerdown
 * listener closes the menu on outside clicks while it is open, and is always
 * removed in disconnectedCallback.
 */
export class VwMenu extends LitElement {
  static override properties = {
    items: { attribute: false },
    open: { type: Boolean },
    label: { type: String },
  };

  declare items: MenuItem[];
  declare open: boolean;
  declare label: string;

  private activeIndex = -1;

  constructor() {
    super();
    this.items = [];
    this.open = false;
    this.label = 'Menu';
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: inline-block;
      }
      [role='menu'] {
        display: flex;
        flex-direction: column;
        min-width: 180px;
        padding: 4px;
        gap: 2px;
        border: 1px solid var(--vw-line);
        border-radius: var(--vw-radius-group);
        background: var(--vw-panel);
      }
      button[role='menuitem'] {
        display: flex;
        align-items: center;
        gap: 8px;
        height: 32px;
        padding: 0 10px;
        border: none;
        border-radius: var(--vw-radius-control);
        background: transparent;
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        font-size: 13px;
        text-align: left;
        cursor: pointer;
      }
      button[role='menuitem'].active {
        background: var(--vw-blue-50);
      }
      button[role='menuitem'].tone-danger {
        color: var(--vw-danger);
      }
      button[role='menuitem'][disabled] {
        color: var(--vw-muted);
        cursor: not-allowed;
      }
    `,
  ];

  private readonly handleDocumentPointerDown = (event: PointerEvent): void => {
    if (!event.composedPath().includes(this)) {
      this.closeMenu();
    }
  };

  override connectedCallback(): void {
    super.connectedCallback();
    this.addEventListener('keydown', this.handleKeydown);
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.removeEventListener('keydown', this.handleKeydown);
    document.removeEventListener('pointerdown', this.handleDocumentPointerDown);
  }

  protected override updated(changed: PropertyValues<this>): void {
    if (!changed.has('open')) {
      return;
    }
    if (this.open) {
      this.activeIndex = this.enabledIndexFrom(0, 1);
      document.addEventListener('pointerdown', this.handleDocumentPointerDown);
    } else {
      this.activeIndex = -1;
      document.removeEventListener('pointerdown', this.handleDocumentPointerDown);
    }
  }

  private enabledIndexFrom(start: number, direction: 1 | -1): number {
    const count = this.items.length;
    for (let step = 0; step < count; step += 1) {
      const index = (((start + step * direction) % count) + count) % count;
      if (!this.items[index]?.disabled) {
        return index;
      }
    }
    return -1;
  }

  private moveActive(direction: 1 | -1): void {
    const from = this.activeIndex === -1 ? 0 : this.activeIndex + direction;
    this.activeIndex = this.enabledIndexFrom(from, direction);
    this.requestUpdate();
  }

  private selectActive(): void {
    const item = this.items[this.activeIndex];
    if (!item || item.disabled) {
      return;
    }
    this.dispatchEvent(new CustomEvent('vw-menu-select', {
      detail: { id: item.id },
      bubbles: true,
      composed: true,
    }));
    this.closeMenu();
  }

  private closeMenu(): void {
    if (!this.open) {
      return;
    }
    this.open = false;
    this.dispatchEvent(new CustomEvent('vw-menu-close', { bubbles: true, composed: true }));
  }

  private readonly handleKeydown = (event: KeyboardEvent): void => {
    if (!this.open) {
      return;
    }
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault();
        this.moveActive(1);
        break;
      case 'ArrowUp':
        event.preventDefault();
        this.moveActive(-1);
        break;
      case 'Home':
        event.preventDefault();
        this.activeIndex = this.enabledIndexFrom(0, 1);
        this.requestUpdate();
        break;
      case 'End':
        event.preventDefault();
        this.activeIndex = this.enabledIndexFrom(this.items.length - 1, -1);
        this.requestUpdate();
        break;
      case 'Enter':
      case ' ':
        event.preventDefault();
        this.selectActive();
        break;
      case 'Escape':
        event.preventDefault();
        this.closeMenu();
        break;
      default:
        break;
    }
  };

  protected override render() {
    if (!this.open) {
      return nothing;
    }
    return html`
      <div role="menu" aria-label=${this.label}>
        ${this.items.map((item, index) => html`
          <button
            type="button"
            role="menuitem"
            class=${`${index === this.activeIndex ? 'active' : ''} ${item.tone === 'danger' ? 'tone-danger' : ''}`}
            ?disabled=${item.disabled}
            aria-disabled=${item.disabled ? 'true' : 'false'}
            @click=${() => {
              this.activeIndex = index;
              this.selectActive();
            }}
          >
            ${item.icon ? uiIcon(item.icon) : nothing}
            <span>${item.label}</span>
          </button>
        `)}
      </div>
    `;
  }
}

customElements.define('vw-menu', VwMenu);

declare global {
  interface HTMLElementTagNameMap {
    'vw-menu': VwMenu;
  }
}
