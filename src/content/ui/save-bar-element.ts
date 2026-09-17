import { html, nothing, type TemplateResult } from 'lit';
import { uiIcon } from '../../ui/components/icon.js';
import { INLINE_SURFACE_CSS } from './surface-theme.js';

/**
 * Render-based surface backing the save/update bar. Content scripts run in an isolated world with no
 * custom-element registry (Chromium 41118431), so this is a plain lit-html template rendered into a
 * closed shadow root by the factory (see save-bar.ts) rather than a LitElement. Mounted inside a closed
 * root so the page cannot read it or forge its actions; only trusted clicks act. The site-controlled
 * `message` is bound with `${}` so it always renders inert.
 *
 * Styled for MiYu: a top-right prompt with a blue primary action and a quiet dismiss action.
 * As a closed-shadow surface on arbitrary host pages it cannot use the extension's `--vw-*` tokens,
 * so the MiYu palette is defined locally on `:host` with a `prefers-color-scheme: dark` override
 * (the primary button uses a light blue fill in dark mode).
 */

/** The render state of the save bar. Held by the factory and passed to `renderSaveBar` on each change. */
export interface SaveBarState {
  view: 'prompt' | 'saving' | 'uncertain' | 'saved';
  /** Plain-text message (no HTML); bound with `${}` so site data can't inject markup. */
  message: string;
  actionLabel: string;
  statusMessage: string;
}

/** Privileged callbacks. Every click that reaches them is gated on `Event.isTrusted` in the template,
 *  so a page script cannot synthesize a click to save or dismiss. */
export interface SaveBarHandlers {
  onAction?: () => void;
  onDismiss?: () => void;
}

export const SAVE_BAR_STYLES = INLINE_SURFACE_CSS + `
  .bar { position:fixed; top:16px; right:16px; width:340px; max-width:calc(100vw - 32px);
    font:400 13px/1.5 "Segoe UI", "Microsoft YaHei", system-ui, sans-serif;
    color:var(--mi-ink); background:var(--mi-panel); border:1px solid var(--mi-line);
    border-radius:12px; box-shadow:var(--mi-shadow); z-index:2147483647;
    animation:mi-surface-enter 180ms var(--mi-ease); overflow:hidden; }
  .msg { display:block; min-width:0; margin:0; padding:16px; overflow-wrap:anywhere; font-size:14px; font-weight:500; line-height:1.65; }
  .msg[role="alert"] { color:var(--mi-red); }
  .actions { display:flex; align-items:center; justify-content:flex-end; gap:10px; padding:0 16px 16px; }
  .act, .dismiss { min-height:38px; padding:8px 14px; border-radius:8px; border:1px solid transparent; font-weight:500; }
  .act { background:var(--mi-ink-btn); color:var(--mi-ink-btn-fg); }
  .act:hover { background:var(--mi-ink-hover); }
  .dismiss { background:transparent; color:var(--mi-text-2); }
  .dismiss:hover { background:var(--mi-row-hover); color:var(--mi-ink); }
  .receipt-note { margin:0; padding:0 16px 16px; }
  .bar[data-view="saved"] .msg { display:flex; align-items:flex-start; gap:9px; padding-bottom:5px; }
  .msg svg { margin-top:3px; color:var(--mi-success); }
`;
/** Render the save bar for the given state. The page cannot forge the privileged clicks: each handler
 *  bails unless `event.isTrusted`. */
export function renderSaveBar(state: SaveBarState, handlers: SaveBarHandlers): TemplateResult {
  // TODO i18n: content-script surfaces are isolated from the extension i18n module, so the dismiss
  // label / aria strings are hardcoded in Chinese here (message + actionLabel come from the caller).
  return html`
    <div class="bar" data-view=${state.view} role=${state.view === 'saved' ? 'status' : 'dialog'} aria-label="保存到密屿" aria-live=${state.view === 'saved' ? 'polite' : nothing} aria-busy=${state.view === 'saving' ? 'true' : 'false'}
      @keydown=${(event: KeyboardEvent) => {
        if (event.isTrusted && event.key === 'Escape') {
          event.preventDefault();
          event.stopPropagation();
          handlers.onDismiss?.();
        }
      }}>
      <div class="head"><span class="logo"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7.5 15.5a5.5 5.5 0 1 1 4.9-8H22v4h-2v2h-3v2h-4.6a5.5 5.5 0 0 1-4.9 3Zm0-3.5a2 2 0 1 0 0 4 2 2 0 0 0 0-4Z"/></svg></span><span class="brand">密屿</span></div>
      <span class="msg" role=${state.view === 'uncertain' ? 'alert' : nothing}>${state.view === 'saved' ? uiIcon('check') : nothing}${state.view === 'prompt' ? state.message : state.statusMessage}</span>
      ${state.view !== 'saved' ? html`<div class="actions">
        <button type="button" class="dismiss" id="vw-save-dismiss" aria-label="关闭"
          @click=${(event: MouseEvent) => { if (event.isTrusted) handlers.onDismiss?.(); }}>${state.view === 'prompt' ? '暂不' : '关闭'}</button>
      ${state.view === 'prompt' || state.view === 'saving' ? html`
        <button type="button" class="act" id="vw-save-act" ?disabled=${state.view === 'saving'}
          @click=${(event: MouseEvent) => { if (event.isTrusted && state.view === 'prompt') handlers.onAction?.(); }}>${state.view === 'saving' ? '正在保存…' : state.actionLabel}</button>
      ` : nothing}
      </div>` : html`<p class="receipt-note">此提示将在 3 秒后自动关闭</p>`}
    </div>
  `;
}
