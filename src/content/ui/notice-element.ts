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
 * locally with a `prefers-color-scheme: dark` override. The compact MiYu notice uses a quiet
 * white surface and blue accent at the bottom center, without assuming success or failure.
 */
export const NOTICE_STYLES = `
    :host { all: initial; }
    * { box-sizing: border-box; }
    .bar {
      position: fixed; left: 50%; bottom: max(20px, env(safe-area-inset-bottom)); transform: translateX(-50%); z-index: 2147483647;
      width: max-content; max-width: min(400px, calc(100vw - 32px)); padding: 12px 16px;
      font:500 12px/1.6 "Segoe UI Variable Text", "Segoe UI", "Microsoft YaHei UI", system-ui, sans-serif;
      color:#253650; background:#ffffff; border:1px solid #dce6f4; border-left:3px solid #155ed7; border-radius:10px;
      box-shadow:0 8px 26px rgba(30,53,89,.12), 0 2px 6px rgba(30,53,89,.05);
      overflow-wrap: anywhere; word-break: break-word;
      -webkit-font-smoothing: antialiased;
      animation: mvUp .18s cubic-bezier(.2,.8,.2,1);
    }
    @keyframes mvUp { from { opacity: 0; transform: translate(-50%, 8px); } to { opacity: 1; transform: translate(-50%, 0); } }
    @media (prefers-color-scheme: dark) {
      .bar { color:#edf3ff; background:#172238; border-color:#33445f; border-left-color:#8eb9ff; box-shadow:0 8px 26px rgba(0,0,0,.3); }
    }
    @media (prefers-reduced-motion: reduce) { .bar { animation: none; } }
  `;

/**
 * Render the notice bar. The `message` is bound with `${}` so it renders inert, and long words wrap
 * instead of overflowing.
 */
export function renderNotice(state: NoticeState): TemplateResult {
  return html`<div class="bar" role="status" aria-live="polite" aria-atomic="true">${state.message}</div>`;
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
