import { LitElement, css, html } from 'lit';
import { themeTokens } from './tokens.js';
import { emit } from './emit.js';

export interface SegmentedOption {
  id: string;
  label: string;
}

/**
 * `vw-segmented` — the MiYu segmented control (generator mode 随机/易记/PIN, Send type 文本/文件,
 * theme 浅色/深色/跟随系统). Container is a filled pill; the active tab is a raised white chip.
 * Emits `vw-segmented-change` with `{ id }`.
 */
export class VwSegmented extends LitElement {
  static override properties = {
    options: { attribute: false },
    value: { type: String },
    height: { type: Number },
  };

  declare options: SegmentedOption[];
  declare value: string;
  declare height: number;

  constructor() {
    super();
    this.options = [];
    this.value = '';
    this.height = 27;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: block; }
      .track {
        display: flex;
        gap: 2px;
        padding:2px;
        border-radius:18px;
        background:var(--vw-fill);
      }
      button {
        flex: 1;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border: none;
        border-radius:16px;
        background: transparent;
        color: var(--vw-text-3);
        font-family: var(--vw-font-ui);
        font-size: 11.5px;
        font-weight: 500;
        cursor: pointer;
        transition: background-color var(--vw-dur-fast), color var(--vw-dur-fast);
      }
      button[aria-selected='true'] {
        background:var(--pc);
        color:var(--onpc);
        font-weight:500;
        box-shadow:none;
      }
      button:focus-visible { outline: none; box-shadow: var(--vw-focus); }
    `,
  ];

  private select(id: string): void {
    if (id === this.value) return;
    this.value = id;
    emit(this, 'vw-segmented-change', { id });
  }

  protected override render() {
    return html`
      <div class="track" role="tablist">
        ${this.options.map(
          (opt) => html`
            <button
              type="button"
              role="tab"
              style=${`height:${this.height}px`}
              aria-selected=${opt.id === this.value ? 'true' : 'false'}
              @click=${() => this.select(opt.id)}
            >
              ${opt.label}
            </button>
          `,
        )}
      </div>
    `;
  }
}

customElements.define('vw-segmented', VwSegmented);

declare global {
  interface HTMLElementTagNameMap {
    'vw-segmented': VwSegmented;
  }
}
