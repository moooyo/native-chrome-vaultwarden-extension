import { defineContentElement } from './define.js';
import { LitElement, css, html } from 'lit';
import { mountClosedSurface } from './closed-surface.js';

/** How long a notice stays on screen before it self-dismisses. */
export const NOTICE_TIMEOUT_MS = 4000;

/**
 * Dormant Lit surface backing the self-dismissing notice bar. Mounted inside a closed root so nothing
 * is exposed to the page. The `message` is bound with `${}` so it renders inert, and long words wrap
 * instead of overflowing.
 *
 * Styled as a compact 密屿/MiYu toast pill (bottom-center). As a closed-shadow surface on arbitrary
 * host pages it cannot use the extension's `--vw-*` tokens, so its colors are hardcoded locally with
 * a `prefers-color-scheme: dark` override (the pill inverts to a light fill with ink text in dark).
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
      position: fixed; left: 50%; bottom: 18px; transform: translateX(-50%); z-index: 2147483647;
      max-width: min(360px, calc(100vw - 32px)); padding: 8px 14px;
      font: 500 11.5px/1.5 "Instrument Sans", "Segoe UI", system-ui, sans-serif;
      color: #fff; background: rgba(22,24,29,.92); border-radius: 16px;
      box-shadow: 0 8px 22px rgba(20,24,32,.18);
      overflow-wrap: anywhere; word-break: break-word;
      animation: mvUp .18s ease-out;
    }
    @keyframes mvUp { from { opacity: 0; transform: translate(-50%, 8px); } to { opacity: 1; transform: translate(-50%, 0); } }
    @media (prefers-color-scheme: dark) {
      .bar { color: #16181D; background: rgba(242,243,245,.95); box-shadow: 0 8px 22px rgba(0,0,0,.4); }
    }
    @media (prefers-reduced-motion: reduce) { .bar { animation: none; } }
  `;

  protected override render() {
    return html`<div class="bar">${this.message}</div>`;
  }
}

defineContentElement('vw-notice', VwNotice);

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
