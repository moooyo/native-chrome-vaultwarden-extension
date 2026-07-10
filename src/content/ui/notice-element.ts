import { LitElement, css, html } from 'lit';
import { mountClosedSurface } from './closed-surface.js';

/** How long a notice stays on screen before it self-dismisses. */
export const NOTICE_TIMEOUT_MS = 4000;

/**
 * Dormant Lit surface backing the self-dismissing notice bar. Mounted inside a closed root so nothing
 * is exposed to the page. The `message` is bound with `${}` so it renders inert, and long words wrap
 * instead of overflowing.
 */
export class VwNotice extends LitElement {
  static override properties = {
    message: { type: String },
  };

  declare message: string;

  constructor() {
    super();
    this.message = '';
  }

  static override styles = css`
    :host { all: initial; }
    .bar {
      position: fixed; right: 16px; bottom: 16px; z-index: 2147483647;
      max-width: 320px; padding: 10px 14px;
      font: 14px/1.4 "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif;
      color: #fff; background: #1a1a1a; border-radius: 8px;
      box-shadow: 0 12px 32px rgba(0,0,0,.35);
      overflow-wrap: anywhere; word-break: break-word;
    }
    @media (prefers-reduced-motion: reduce) { .bar { animation: none; } }
  `;

  protected override render() {
    return html`<div class="bar">${this.message}</div>`;
  }
}

customElements.define('vw-notice', VwNotice);

export interface NoticeHandle {
  remove(): void;
}

/**
 * Mounts a notice inside a closed shadow root and schedules it to auto-dismiss after
 * NOTICE_TIMEOUT_MS. Returns a handle so callers can remove it early.
 */
export function presentNotice(message: string): NoticeHandle {
  const surface = mountClosedSurface<VwNotice>('vw-notice', (element) => {
    element.message = message;
  });
  surface.host.dataset.vwNotice = '';
  const view = surface.host.ownerDocument.defaultView;
  const timer = view?.setTimeout(() => surface.remove(), NOTICE_TIMEOUT_MS);
  return {
    remove: () => {
      if (view && timer !== undefined) {
        view.clearTimeout(timer);
      }
      surface.remove();
    },
  };
}

declare global {
  interface HTMLElementTagNameMap {
    'vw-notice': VwNotice;
  }
}
