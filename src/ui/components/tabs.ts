import { LitElement, css, html } from 'lit';
import { themeTokens } from './tokens.js';
import { controlStyles } from './styles.js';
import { emit } from './emit.js';

export interface TabItem {
  id: string;
  label: string;
  count?: number;
}

/**
 * A dormant tablist built from native <button role="tab"> controls with a
 * roving tabindex. ArrowLeft/ArrowRight move (and activate) the adjacent
 * tab, wrapping at the edges; Home/End jump to the first/last tab. Real DOM
 * focus always follows the newly selected tab's button.
 */
export class VwTabs extends LitElement {
  static override properties = {
    tabs: { attribute: false },
    selected: { type: String },
  };

  declare tabs: TabItem[];
  declare selected: string;

  constructor() {
    super();
    this.tabs = [];
    this.selected = '';
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      [role='tablist'] {
        display: flex;
        gap: 4px;
        border-bottom: 1px solid var(--vw-line);
      }
      button[role='tab'] {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        height: 32px;
        padding: 0 10px;
        border: none;
        border-bottom: 2px solid transparent;
        background: transparent;
        color: var(--vw-muted);
        font-family: var(--vw-font-ui);
        font-size: 13px;
        cursor: pointer;
      }
      button[role='tab'][aria-selected='true'] {
        color: var(--vw-blue-600);
        border-bottom-color: var(--vw-blue-600);
      }
      .count {
        color: inherit;
        opacity: 0.7;
      }
    `,
  ];

  override connectedCallback(): void {
    super.connectedCallback();
    this.addEventListener('keydown', this.handleKeydown);
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.removeEventListener('keydown', this.handleKeydown);
  }

  private currentIndex(): number {
    const index = this.tabs.findIndex((tab) => tab.id === this.selected);
    return index === -1 ? 0 : index;
  }

  private selectByIndex(index: number): void {
    const tab = this.tabs[index];
    if (!tab || tab.id === this.selected) {
      return;
    }
    this.selected = tab.id;
    emit(this, 'vw-tab-change', { id: tab.id });
  }

  private readonly handleKeydown = (event: KeyboardEvent): void => {
    const count = this.tabs.length;
    if (count === 0) {
      return;
    }
    const current = this.currentIndex();
    let target: number;
    switch (event.key) {
      case 'ArrowRight':
        event.preventDefault();
        target = (current + 1) % count;
        break;
      case 'ArrowLeft':
        event.preventDefault();
        target = (current - 1 + count) % count;
        break;
      case 'Home':
        event.preventDefault();
        target = 0;
        break;
      case 'End':
        event.preventDefault();
        target = count - 1;
        break;
      default:
        return;
    }
    this.selectByIndex(target);
    this.focusTabAt(target);
  };

  private focusTabAt(index: number): void {
    void this.updateComplete.then(() => {
      const buttons = this.shadowRoot?.querySelectorAll('button[role="tab"]');
      const button = buttons?.[index];
      if (button instanceof HTMLElement) {
        button.focus();
      }
    });
  }

  protected override render() {
    return html`
      <div role="tablist">
        ${this.tabs.map((tab, index) => {
          const isSelected = tab.id === this.selected;
          return html`
            <button
              type="button"
              role="tab"
              aria-selected=${isSelected ? 'true' : 'false'}
              tabindex=${isSelected ? '0' : '-1'}
              @click=${() => this.selectByIndex(index)}
            >
              <span>${tab.label}</span>
              ${typeof tab.count === 'number' ? html`<span class="count">(${tab.count})</span>` : ''}
            </button>
          `;
        })}
      </div>
    `;
  }
}

customElements.define('vw-tabs', VwTabs);

declare global {
  interface HTMLElementTagNameMap {
    'vw-tabs': VwTabs;
  }
}
