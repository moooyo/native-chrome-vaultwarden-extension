import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from './tokens.js';
import { emit } from './emit.js';

const TOAST_MS = 3000;

/**
 * `vw-toast` is a compact operation receipt. The parent renders a `message` and listens for
 * `vw-toast-dismiss` to clear its state; the toast schedules its own auto-dismiss after 3s and
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
        width: max-content;
        max-width: calc(100% - 32px);
        z-index: 40;
        pointer-events: none;
      }
      .toast {
        display: inline-block;
        max-width: 100%;
        padding: 10px 14px;
        border-radius: var(--vw-radius-control);
        background: var(--inv);
        color: var(--oninv);
        font-size: 12px;
        line-height: 1.6;
        overflow-wrap: anywhere;
        box-shadow: var(--vw-popup-shadow);
        animation: mvUp var(--vw-dur) var(--vw-ease);
      }
      @keyframes mvUp {
        from { opacity: 0; transform: translateY(5px); }
        to { opacity: 1; transform: translateY(0); }
      }
      @media (prefers-reduced-motion: reduce) { .toast { animation: none; } }
    `,
  ];

  protected override updated(changed: Map<string, unknown>): void {
    if (changed.has('offset') || changed.has('message')) {
      this.style.bottom = `${this.offset}px`;
    }
    if (changed.has('message')) {
      if (this.timer) clearTimeout(this.timer);
      this.timer = undefined;
      if (!this.message) return;
      this.timer = setTimeout(() => {
        this.timer = undefined;
        emit(this, 'vw-toast-dismiss');
      }, TOAST_MS);
    }
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    if (this.timer) clearTimeout(this.timer);
  }

  protected override render() {
    return this.message ? html`<div class="toast" role="status" aria-live="polite" aria-atomic="true">${this.message}</div>` : nothing;
  }
}

customElements.define('vw-toast', VwToast);

declare global {
  interface HTMLElementTagNameMap {
    'vw-toast': VwToast;
  }
}
