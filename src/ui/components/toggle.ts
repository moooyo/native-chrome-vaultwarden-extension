import { LitElement, css, html } from 'lit';
import { themeTokens } from './tokens.js';

/**
 * `vw-toggle` — the MiYu switch. 40×20 by default, 36×19 in the `sm` variant (Send access-password).
 * Emits `vw-toggle-change` with `{ checked }` on user toggle. Accessible: `role="switch"`, keyboard
 * operable via Space/Enter.
 */
export class VwToggle extends LitElement {
  static override properties = {
    checked: { type: Boolean, reflect: true },
    disabled: { type: Boolean, reflect: true },
    size: { type: String },
  };

  declare checked: boolean;
  declare disabled: boolean;
  declare size: 'md' | 'sm';

  constructor() {
    super();
    this.checked = false;
    this.disabled = false;
    this.size = 'md';
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: inline-flex; }
      button {
        position: relative;
        width: 40px;
        height: 20px;
        padding: 0;
        border: none;
        border-radius: 10px;
        background: var(--vw-toggle-off);
        cursor: pointer;
        transition: background-color var(--vw-dur-fast);
      }
      button.sm { width: 36px; height: 19px; }
      button[aria-checked='true'] { background: var(--vw-toggle-on); }
      button:disabled { opacity: 0.5; cursor: default; }
      .knob {
        position: absolute;
        top: 3px;
        left: 3px;
        width: 14px;
        height: 14px;
        border-radius: 50%;
        background: #fff;
        box-shadow: var(--vw-knob-shadow);
        transition: left var(--vw-dur-fast);
      }
      button.sm .knob { width: 13px; height: 13px; }
      button[aria-checked='true'] .knob { left: 23px; }
      button:focus-visible { outline: none; box-shadow: var(--vw-focus); }
    `,
  ];

  private toggle(event: Event): void {
    event.preventDefault();
    if (this.disabled) return;
    this.checked = !this.checked;
    this.dispatchEvent(
      new CustomEvent('vw-toggle-change', { detail: { checked: this.checked }, bubbles: true, composed: true }),
    );
  }

  protected override render() {
    return html`
      <button
        type="button"
        role="switch"
        class=${this.size === 'sm' ? 'sm' : ''}
        aria-checked=${this.checked ? 'true' : 'false'}
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
