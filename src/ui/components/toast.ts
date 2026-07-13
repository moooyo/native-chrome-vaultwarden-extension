import { LitElement, css, html } from 'lit';
import { themeTokens } from './tokens.js';

const TOAST_MS = 1900;

/**
 * `vw-toast` — the copy confirmation pill. The parent renders it with a `message` and listens for
 * `vw-toast-dismiss` to clear its state; the toast schedules its own auto-dismiss after 1.9s and
 * plays the `mvUp` entrance. `offset` sets the distance from the bottom of the positioned parent
 * (42 in the popup — above the sync bar, 18 elsewhere).
 */
export class VwToast extends LitElement {
  static override properties = {
    message: { type: String },
    offset: { type: Number },
  };

  declare message: string;
  declare offset: number;

  private timer: ReturnType<typeof setTimeout> | undefined = undefined;

  constructor() {
    super();
    this.message = '';
    this.offset = 18;
  }

  static override styles = [
    themeTokens,
    css`
      :host {
        position: absolute;
        left: 50%;
        transform: translateX(-50%);
        z-index: 40;
        pointer-events: none;
      }
      .toast {
        display: inline-block;
        max-width: 320px;
        padding: 6px 13px;
        border-radius: var(--vw-radius-dialog);
        background: rgba(22, 24, 29, 0.92);
        color: #fff;
        font-size: 11.5px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        animation: mvUp 0.18s ease-out;
      }
      @media (prefers-color-scheme: dark) {
        :host([data-dark]) .toast { background: rgba(242, 243, 245, 0.95); color: #16181d; }
      }
      @keyframes mvUp {
        from { opacity: 0; transform: translateY(8px); }
        to { opacity: 1; transform: translateY(0); }
      }
      @media (prefers-reduced-motion: reduce) { .toast { animation: none; } }
    `,
  ];

  protected override updated(changed: Map<string, unknown>): void {
    if (changed.has('message') && this.message) {
      this.style.bottom = `${this.offset}px`;
      if (this.timer) clearTimeout(this.timer);
      this.timer = setTimeout(() => {
        this.dispatchEvent(new CustomEvent('vw-toast-dismiss', { bubbles: true, composed: true }));
      }, TOAST_MS);
    }
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    if (this.timer) clearTimeout(this.timer);
  }

  protected override render() {
    return html`<div class="toast" role="status">${this.message}</div>`;
  }
}

customElements.define('vw-toast', VwToast);

declare global {
  interface HTMLElementTagNameMap {
    'vw-toast': VwToast;
  }
}
