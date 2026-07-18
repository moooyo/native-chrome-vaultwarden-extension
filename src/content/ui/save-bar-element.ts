import { html, type TemplateResult } from 'lit';

/**
 * Render-based surface backing the save/update bar. Content scripts run in an isolated world with no
 * custom-element registry (Chromium 41118431), so this is a plain lit-html template rendered into a
 * closed shadow root by the factory (see save-bar.ts) rather than a LitElement. Mounted inside a closed
 * root so the page cannot read it or forge its actions; only trusted clicks act. The site-controlled
 * `message` is bound with `${}` so it always renders inert.
 *
 * Styled for the 密屿/MiYu design: a top-center card with an ink primary action and a ghost dismiss.
 * As a closed-shadow surface on arbitrary host pages it cannot use the extension's `--vw-*` tokens,
 * so the MiYu palette is defined locally on `:host` with a `prefers-color-scheme: dark` override
 * (the primary button inverts to a light fill with ink text in dark mode).
 */

/** The render state of the save bar. Held by the factory and passed to `renderSaveBar` on each change. */
export interface SaveBarState {
  /** Plain-text message (no HTML); bound with `${}` so site data can't inject markup. */
  message: string;
  actionLabel: string;
}

/** Privileged callbacks. Every click that reaches them is gated on `Event.isTrusted` in the template,
 *  so a page script cannot synthesize a click to save or dismiss. */
export interface SaveBarHandlers {
  onAction?: () => void;
  onDismiss?: () => void;
}

export const SAVE_BAR_STYLES = `
    :host { all: initial; }
    :host {
      --mi-panel: #fff;
      --mi-ink:#1f1f1f;
      --mi-ink-hover:#0842a0;
      --mi-on-ink: #fff;
      --mi-text-2:#474747;
      --mi-teal:#0b57d0;
      --mi-line:#c4c7c5;
      --mi-row-hover:rgba(31,31,31,.07);
      --mi-shadow:0 10px 32px rgba(0,0,0,.24);
    }
    * { box-sizing: border-box; }
    .bar {
      position:fixed; top:14px; right:14px;
      display:grid; grid-template-columns:22px 1fr; align-items:center; gap:8px 9px;
      width:252px; max-width:calc(100vw - 28px);
      font:400 14px/1.4 "Roboto", "Segoe UI", system-ui, sans-serif;
      color: var(--mi-ink); background: var(--mi-panel);
      border: 1px solid var(--mi-line); border-radius: 14px;
      box-shadow: var(--mi-shadow);
      padding: 10px 12px; z-index: 2147483647;
      animation:mvSheet .25s cubic-bezier(.2,.9,.3,1);
    }
    @keyframes mvSheet { from { opacity:0; transform:translateY(-10px); } to { opacity:1; transform:none; } }

    /* Concentric-circle mini logo on a moss-green block (identical in light + dark). */
    .logo { display:grid; place-items:center; width:22px; height:22px; border-radius:7px; background:#0b57d0; flex:none; }
    .logo svg { width:14px; height:14px; fill:#fff; stroke:none; }
    .glyph { position: relative; width: 11px; height: 11px; }
    .ring { position: absolute; inset: 0; border: 2px solid #fff; border-radius: 50%; }
    .dot { position: absolute; left: 4px; top: 4px; width: 3px; height: 3px; border-radius: 50%; background: #fff; }

    .msg { min-width:0; overflow-wrap:anywhere; font-size:12.5px; color:var(--mi-ink); }
    button { font:inherit; font-size:12px; font-weight:500; border-radius:17px; padding:9px 14px; cursor:pointer; border:1px solid transparent; }
    .act { grid-column:1 / 3; background:#0b57d0; color:#fff; }
    .act:hover { background: var(--mi-ink-hover); }
    .dismiss { grid-column:1 / 3; background:transparent; color:var(--mi-text-2); padding:5px 10px; }
    .dismiss:hover { color: var(--mi-ink); background: var(--mi-row-hover); }
    button:focus-visible { outline: none; box-shadow: 0 0 0 2px var(--mi-teal); }

    @media (prefers-color-scheme: dark) {
      :host {
        --mi-panel:#1f1f1f;
        --mi-ink:#e3e3e3;
        --mi-ink-hover:#d3e3fd;
        --mi-on-ink:#062e6f;
        --mi-text-2:#c4c7c5;
        --mi-line:#47494c;
        --mi-row-hover:rgba(227,227,227,.09);
        --mi-shadow:0 10px 32px rgba(0,0,0,.5);
      }
      .act { background:#a8c7fa; color:#062e6f; }
    }
    @media (prefers-reduced-motion: reduce) { .bar { animation: none; } }
  `;

/** Render the save bar for the given state. The page cannot forge the privileged clicks: each handler
 *  bails unless `event.isTrusted`. */
export function renderSaveBar(state: SaveBarState, handlers: SaveBarHandlers): TemplateResult {
  // TODO i18n: content-script surfaces are isolated from the extension i18n module, so the dismiss
  // label / aria strings are hardcoded in Chinese here (message + actionLabel come from the caller).
  return html`
    <div class="bar" role="dialog" aria-label="保存到密屿">
      <span class="logo"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7.5 15.5a5.5 5.5 0 1 1 4.9-8H22v4h-2v2h-3v2h-4.6a5.5 5.5 0 0 1-4.9 3Zm0-3.5a2 2 0 1 0 0 4 2 2 0 0 0 0-4Z"/></svg></span>
      <span class="msg">${state.message}</span>
      <button type="button" class="act" id="vw-save-act" @click=${(event: MouseEvent) => { if (event.isTrusted) handlers.onAction?.(); }}>${state.actionLabel}</button>
      <button type="button" class="dismiss" id="vw-save-dismiss" aria-label="关闭" @click=${(event: MouseEvent) => { if (event.isTrusted) handlers.onDismiss?.(); }}>暂不</button>
    </div>
  `;
}
