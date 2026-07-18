import { html, type TemplateResult } from 'lit';
import { mountRenderSurface } from './render-surface.js';

/** How long a notice stays on screen before it self-dismisses. */
export const NOTICE_TIMEOUT_MS = 4000;

/** The render state of the notice bar — just the (page-inert) message text. */
export interface NoticeState {
  message: string;
}

/**
 * Styles for the self-dismissing notice bar. Because the surface lives in a closed shadow root on
 * arbitrary host pages it cannot use the extension's `--vw-*` tokens, so its colors are hardcoded
 * locally with a `prefers-color-scheme: dark` override (the pill inverts to a light fill with ink
 * text in dark). Styled as a compact 密屿/MiYu toast pill (bottom-center).
 */
export const NOTICE_STYLES = `
    :host { all: initial; }
    .bar {
      position: fixed; left: 50%; bottom: 18px; transform: translateX(-50%); z-index: 2147483647;
      max-width: min(360px, calc(100vw - 32px)); padding: 8px 14px;
      font:500 11.5px/1.5 "Roboto", "Segoe UI", system-ui, sans-serif;
      color:#f5eff7; background:#322f35; border-radius:10px;
      box-shadow:0 8px 22px rgba(20,24,32,.18);
      overflow-wrap: anywhere; word-break: break-word;
      animation: mvUp .18s ease-out;
    }
    @keyframes mvUp { from { opacity: 0; transform: translate(-50%, 8px); } to { opacity: 1; transform: translate(-50%, 0); } }
    @media (prefers-color-scheme: dark) {
      .bar { color:#1f1f1f; background:#e3e3e3; box-shadow:0 8px 22px rgba(0,0,0,.4); }
    }
    @media (prefers-reduced-motion: reduce) { .bar { animation: none; } }
  `;

/**
 * Render the notice bar. The `message` is bound with `${}` so it renders inert, and long words wrap
 * instead of overflowing.
 */
export function renderNotice(state: NoticeState): TemplateResult {
  return html`<div class="bar">${state.message}</div>`;
}

export interface NoticeHandle {
  remove(): void;
}

/**
 * Mounts a notice inside a closed shadow root and schedules it to auto-dismiss after
 * NOTICE_TIMEOUT_MS. Returns a handle so callers can remove it early.
 */
export function presentNotice(message: string): NoticeHandle {
  const surface = mountRenderSurface(NOTICE_STYLES);
  surface.render(renderNotice({ message }));
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
