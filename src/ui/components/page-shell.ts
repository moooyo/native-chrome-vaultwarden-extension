import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from './tokens.js';
import { controlStyles } from './styles.js';
import { uiIcon, type IconName } from './icon.js';

export interface SettingsRailItem {
  id: string;
  label: string;
  icon: IconName;
}

/**
 * A dormant page frame for settings-style surfaces: a vertical navigation
 * rail of native buttons in the default (wide) layout, or a single native
 * <select> "top selector" when `narrow` is set for constrained viewports.
 * Selecting a section (either way) reuses the `vw-tab-change` event, since
 * both are "which section is active" changes.
 */
export class VwPageShell extends LitElement {
  static override properties = {
    items: { attribute: false },
    selected: { type: String },
    narrow: { type: Boolean, reflect: true },
  };

  declare items: SettingsRailItem[];
  declare selected: string;
  declare narrow: boolean;

  constructor() {
    super();
    this.items = [];
    this.selected = '';
    this.narrow = false;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: block;
      }
      .shell {
        display: flex;
        gap: 16px;
      }
      :host([narrow]) .shell {
        flex-direction: column;
      }
      nav {
        display: flex;
        flex-direction: column;
        gap: 2px;
        min-width: 160px;
      }
      nav button {
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
      nav button[aria-current='page'] {
        background: var(--vw-blue-50);
        color: var(--vw-blue-600);
      }
      main {
        flex: 1;
        min-width: 0;
      }
    `,
  ];

  private select(id: string): void {
    if (id === this.selected) {
      return;
    }
    this.selected = id;
    this.dispatchEvent(new CustomEvent('vw-tab-change', {
      detail: { id },
      bubbles: true,
      composed: true,
    }));
  }

  private renderRail() {
    return html`
      <nav aria-label="Sections">
        ${this.items.map((item) => html`
          <button
            type="button"
            aria-current=${item.id === this.selected ? 'page' : nothing}
            @click=${() => this.select(item.id)}
          >
            ${uiIcon(item.icon)}
            <span>${item.label}</span>
          </button>
        `)}
      </nav>
    `;
  }

  private renderSelector() {
    return html`
      <label class="field">
        <span>Section</span>
        <select
          class="select"
          .value=${this.selected}
          @change=${(event: Event) => this.select((event.target as HTMLSelectElement).value)}
        >
          ${this.items.map((item) => html`<option value=${item.id}>${item.label}</option>`)}
        </select>
      </label>
    `;
  }

  protected override render() {
    return html`
      <div class="shell">
        ${this.narrow ? this.renderSelector() : this.renderRail()}
        <main><slot></slot></main>
      </div>
    `;
  }
}

customElements.define('vw-page-shell', VwPageShell);

declare global {
  interface HTMLElementTagNameMap {
    'vw-page-shell': VwPageShell;
  }
}
