import { LitElement, css, html } from 'lit';
import { themeTokens } from './tokens.js';
import { uiIcon } from './icon.js';
import { emit } from './emit.js';

export interface SelectOption {
  value: string;
  label: string;
}

/**
 * `vw-select` — the MiYu dropdown. The design's prototype used a click-to-cycle control but the
 * handoff says to ship a real dropdown; we wrap a styled native `<select>` so keyboard, screen-reader
 * semantics, and the platform popup come for free. Emits `vw-select-change` with `{ value }`.
 */
export class VwSelect extends LitElement {
  static override properties = {
    options: { attribute: false },
    value: { type: String },
    label: { type: String },
  };

  declare options: SelectOption[];
  declare value: string;
  declare label: string;

  constructor() {
    super();
    this.options = [];
    this.value = '';
    this.label = '';
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: inline-block; }
      .wrap { position: relative; display: inline-flex; align-items: center; }
      select {
        appearance: none;
        -webkit-appearance: none;
        height: 30px;
        min-width: 92px;
        padding: 0 30px 0 11px;
        border: 1px solid var(--vw-line-3);
        border-radius: var(--vw-radius-input);
        background: var(--vw-card);
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        font-size: 12px;
        cursor: pointer;
      }
      select:hover { background: var(--vw-fill-2); }
      select:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      .chev {
        position: absolute;
        right: 10px;
        display: inline-flex;
        pointer-events: none;
        color: var(--vw-muted);
      }
      .chev svg { width: 12px; height: 12px; }
    `,
  ];

  private onChange(event: Event): void {
    const value = (event.target as HTMLSelectElement).value;
    this.value = value;
    emit(this, 'vw-select-change', { value });
  }

  protected override render() {
    return html`
      <div class="wrap">
        <select aria-label=${this.label || 'select'} .value=${this.value} @change=${this.onChange}>
          ${this.options.map(
            (opt) => html`<option value=${opt.value} ?selected=${opt.value === this.value}>${opt.label}</option>`,
          )}
        </select>
        <span class="chev">${uiIcon('chevronDown')}</span>
      </div>
    `;
  }
}

customElements.define('vw-select', VwSelect);

declare global {
  interface HTMLElementTagNameMap {
    'vw-select': VwSelect;
  }
}
