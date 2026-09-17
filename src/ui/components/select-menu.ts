import { LitElement, css, html, nothing } from 'lit';
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
      :host { display: inline-block; max-width: 100%; min-width: 0; }
      .wrap { position: relative; display: inline-flex; align-items: center; max-width: 100%; }
      select {
        appearance: none;
        -webkit-appearance: none;
        height: 40px;
        min-width: 92px;
        max-width: 100%;
        padding: 0 34px 0 11px;
        border: 1px solid var(--vw-line-3);
        border-radius:var(--vw-radius-control);
        background:var(--vw-card);
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        font-size: 13px;
        cursor: pointer;
      }
      select:hover { background: var(--vw-fill-2); }
      select:focus-visible { outline: 2px solid var(--vw-accent); outline-offset: 2px; border-color: var(--vw-accent); }
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
        <select aria-label=${this.label || nothing} .value=${this.value} @change=${this.onChange}>
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
