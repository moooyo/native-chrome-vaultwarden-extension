import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from './tokens.js';
import { emit } from './emit.js';

/**
 * `vw-toggle` is a 40×22 switch, with a 36×20 compact variant.
 * Emits `vw-toggle-change` with `{ checked }` on user toggle. Accessible: `role="switch"`, keyboard
 * operable via Space/Enter.
 */
export class VwToggle extends LitElement {
  static override properties = {
    checked: { type: Boolean, reflect: true },
    disabled: { type: Boolean, reflect: true },
    size: { type: String },
    label: { type: String },
  };

  declare checked: boolean;
  declare disabled: boolean;
  declare size: 'md' | 'sm';
  declare label: string;

  constructor() {
    super();
    this.checked = false;
    this.disabled = false;
    this.size = 'md';
    this.label = '';
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: inline-flex; }
      button {
        appearance: none;
        position: relative;
        width: 40px;
        height: 22px;
        padding: 0;
        border: 1px solid transparent;
        border-radius: 11px;
        background: var(--vw-toggle-off);
        cursor: pointer;
        transition: background-color var(--vw-dur-fast);
      }
      button.sm { width:36px; height:20px; }
      button[aria-checked='true'] { border-color:transparent; background:var(--vw-toggle-on); }
      button:disabled { opacity: 0.6; cursor: default; }
      .knob {
        position: absolute;
        top: 2px;
        left: 2px;
        width: 16px;
        height: 16px;
        border-radius: 50%;
        background: #fff;
        box-shadow: var(--vw-knob-shadow);
        transition: transform var(--vw-dur-fast) var(--vw-ease);
      }
      button.sm .knob { width:14px; height:14px; }
      button[aria-checked='true'] .knob { transform:translateX(18px); }
      button.sm[aria-checked='true'] .knob { transform:translateX(16px); }
      button:focus-visible { outline: 2px solid var(--vw-accent); outline-offset: 3px; }
      @media (prefers-reduced-motion: reduce) { button, .knob { transition: none; } }
    `,
  ];

  private toggle(event: Event): void {
    event.preventDefault();
    if (this.disabled) return;
    this.checked = !this.checked;
    emit(this, 'vw-toggle-change', { checked: this.checked });
  }

  protected override render() {
    return html`
      <button
        type="button"
        role="switch"
        class=${this.size === 'sm' ? 'sm' : ''}
        aria-checked=${this.checked ? 'true' : 'false'}
        aria-label=${this.label || this.getAttribute('aria-label') || nothing}
        ?disabled=${this.disabled}
        @click=${this.toggle}
      >
        <span class="knob"></span>
      </button>
    `;
  }
}

customElements.define('vw-toggle', VwToggle);

declare global {
  interface HTMLElementTagNameMap {
    'vw-toggle': VwToggle;
  }
}
