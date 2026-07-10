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
        display: grid;
        grid-template-columns: 206px minmax(0, 1fr);
        min-height: min(680px, calc(100vh - 32px));
        overflow: hidden;
        border: 1px solid var(--vw-line);
        border-radius: var(--vw-radius-large);
        background: var(--vw-panel);
      }
      :host([narrow]) .shell {
        display: flex;
        flex-direction: column;
        min-height: 0;
        padding: 16px;
      }
      nav {
        display: flex;
        flex-direction: column;
        gap: 2px;
        padding: 18px 10px;
        border-right: 1px solid var(--vw-line);
      }
      nav button {
        display: flex;
        align-items: center;
        gap: 8px;
        height: 39px;
        padding: 0 10px;
        border: none;
        border-radius: var(--vw-radius-control);
        background: transparent;
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        font-size: var(--vw-font-size-body);
        font-weight: 600;
        text-align: left;
        cursor: pointer;
      }
      nav button[aria-current='page'] {
        background: var(--vw-blue);
        color: #fff;
      }
      nav svg {
        width: 18px;
        height: 18px;
        flex: none;
      }
      main {
        min-width: 0;
        padding: 28px 32px;
        overflow: auto;
        background: var(--vw-canvas);
      }
      :host([narrow]) main {
        padding: 20px 0 0;
        overflow: visible;
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
      <nav data-settings-rail aria-label="Sections">
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
      <div class="shell" data-page-shell>
        ${this.narrow ? this.renderSelector() : this.renderRail()}
        <main data-settings-content><slot></slot></main>
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
