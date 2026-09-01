import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from './tokens.js';
import { emit } from './emit.js';

export interface SegmentedOption {
  id: string;
  label: string;
  disabled?: boolean;
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
    label: { type: String },
    disabled: { type: Boolean, reflect: true },
  };

  declare options: SegmentedOption[];
  declare value: string;
  declare height: number;
  declare label: string;
  declare disabled: boolean;

  constructor() {
    super();
    this.options = [];
    this.value = '';
    this.height = 27;
    this.label = '';
    this.disabled = false;
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
      button:disabled { cursor: default; opacity: 0.5; }
      button:focus-visible { outline: none; box-shadow: var(--vw-focus); }
    `,
  ];

  private select(id: string): void {
    const option = this.options.find((candidate) => candidate.id === id);
    if (this.disabled || !option || option.disabled) return;
    if (id === this.value) return;
    this.value = id;
    emit(this, 'vw-segmented-change', { id });
  }

  private onKeyDown(event: KeyboardEvent, option: SegmentedOption): void {
    if (this.disabled || option.disabled) return;
    const enabled = this.options.filter((candidate) => !candidate.disabled);
    const currentIndex = enabled.indexOf(option);
    if (currentIndex < 0 || enabled.length === 0) return;

    let targetIndex: number | undefined;
    switch (event.key) {
      case 'ArrowRight':
        targetIndex = (currentIndex + 1) % enabled.length;
        break;
      case 'ArrowLeft':
        targetIndex = (currentIndex - 1 + enabled.length) % enabled.length;
        break;
      case 'Home':
        targetIndex = 0;
        break;
      case 'End':
        targetIndex = enabled.length - 1;
        break;
      default:
        return;
    }

    event.preventDefault();
    const target = enabled[targetIndex];
    if (!target) return;
    const optionIndex = this.options.indexOf(target);
    this.renderRoot.querySelectorAll<HTMLButtonElement>('[role="tab"]')[optionIndex]?.focus();
    this.select(target.id);
  }

  protected override render() {
    const focusableId = this.options.find(
      (option) => option.id === this.value && !option.disabled,
    )?.id ?? this.options.find((option) => !option.disabled)?.id;
    return html`
      <div
        class="track"
        role="tablist"
        aria-label=${this.label || nothing}
        aria-orientation="horizontal"
        aria-disabled=${this.disabled ? 'true' : 'false'}
      >
        ${this.options.map(
          (opt) => html`
            <button
              type="button"
              role="tab"
              style=${`height:${this.height}px`}
              aria-selected=${opt.id === this.value ? 'true' : 'false'}
              tabindex=${!this.disabled && opt.id === focusableId ? 0 : -1}
              ?disabled=${this.disabled || opt.disabled}
              @click=${() => this.select(opt.id)}
              @keydown=${(event: KeyboardEvent) => this.onKeyDown(event, opt)}
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
