import { defineContentElement } from './define.js';
import { LitElement, css, html } from 'lit';

/**
 * Dormant Lit surface backing the save/update bar. Mounted inside a closed root so the page cannot
 * read it or forge its actions; only trusted clicks act. The site-controlled `message` is bound with
 * `${}` so it always renders inert. Callbacks are non-reflected properties.
 *
 * Styled for the 密屿/MiYu design: a top-center card with an ink primary action and a ghost dismiss.
 * As a closed-shadow surface on arbitrary host pages it cannot use the extension's `--vw-*` tokens,
 * so the MiYu palette is defined locally on `:host` with a `prefers-color-scheme: dark` override
 * (the primary button inverts to a light fill with ink text in dark mode).
 */
export class VwSaveBar extends LitElement {
  static override properties = {
    message: { type: String },
    actionLabel: { type: String },
    onAction: { attribute: false },
    onDismiss: { attribute: false },
  };

  declare message: string;
  declare actionLabel: string;
  declare onAction: (() => void) | undefined;
  declare onDismiss: (() => void) | undefined;

  constructor() {
    super();
    this.message = '';
    this.actionLabel = '';
    this.onAction = undefined;
    this.onDismiss = undefined;
  }

  static override styles = css`
    :host { all: initial; }
    :host {
      --mi-panel: #fff;
      --mi-ink: #16181D;
      --mi-ink-hover: #2A2D34;
      --mi-on-ink: #fff;
      --mi-text-2: #565B66;
      --mi-teal: #0E8A72;
      --mi-line: rgba(22,24,29,.09);
      --mi-row-hover: #F2F2EF;
      --mi-shadow: 0 16px 40px rgba(20,24,32,.16);
    }
    * { box-sizing: border-box; }
    .bar {
      position: fixed; top: 12px; left: 50%; transform: translateX(-50%);
      display: flex; align-items: center; gap: 12px;
      max-width: min(560px, calc(100vw - 24px));
      font: 400 14px/1.4 "Instrument Sans", "Segoe UI", system-ui, sans-serif;
      color: var(--mi-ink); background: var(--mi-panel);
      border: 1px solid var(--mi-line); border-radius: 14px;
      box-shadow: var(--mi-shadow);
      padding: 10px 12px; z-index: 2147483647;
      animation: mvIn .18s ease-out;
    }
    @keyframes mvIn { from { opacity: 0; transform: translate(-50%, -8px); } to { opacity: 1; transform: translate(-50%, 0); } }

    /* Concentric-circle mini logo on a moss-green block (identical in light + dark). */
    .logo { display: grid; place-items: center; width: 22px; height: 22px; border-radius: 6px; background: #0E8A72; flex: none; }
    .glyph { position: relative; width: 11px; height: 11px; }
    .ring { position: absolute; inset: 0; border: 2px solid #fff; border-radius: 50%; }
    .dot { position: absolute; left: 4px; top: 4px; width: 3px; height: 3px; border-radius: 50%; background: #fff; }

    .msg { flex: 1; min-width: 0; overflow-wrap: anywhere; font-size: 12.5px; color: var(--mi-ink); }
    button { font: inherit; font-size: 12.5px; font-weight: 600; border-radius: 9px; padding: 7px 14px; cursor: pointer; border: 1px solid transparent; flex: none; }
    .act { background: var(--mi-ink); color: var(--mi-on-ink); }
    .act:hover { background: var(--mi-ink-hover); }
    .dismiss { background: transparent; color: var(--mi-text-2); padding: 7px 10px; }
    .dismiss:hover { color: var(--mi-ink); background: var(--mi-row-hover); }
    button:focus-visible { outline: none; box-shadow: 0 0 0 2px var(--mi-teal); }

    @media (prefers-color-scheme: dark) {
      :host {
        --mi-panel: #1F2229;
        --mi-ink: #F2F3F5;
        --mi-ink-hover: #fff;
        --mi-on-ink: #16181D;
        --mi-text-2: #9AA0AC;
        --mi-line: rgba(255,255,255,.09);
        --mi-row-hover: rgba(255,255,255,.05);
        --mi-shadow: 0 18px 48px rgba(0,0,0,.5);
      }
    }
    @media (prefers-reduced-motion: reduce) { .bar { animation: none; } }
  `;

  private handleAction(event: MouseEvent): void {
    if (event.isTrusted) {
      this.onAction?.();
    }
  }

  private handleDismiss(event: MouseEvent): void {
    if (event.isTrusted) {
      this.onDismiss?.();
    }
  }

  protected override render() {
    // TODO i18n: content-script surfaces are isolated from the extension i18n module, so the dismiss
    // label / aria strings are hardcoded in Chinese here (message + actionLabel come from the caller).
    return html`
      <div class="bar" role="dialog" aria-label="保存到密屿">
        <span class="logo"><span class="glyph"><span class="ring"></span><span class="dot"></span></span></span>
        <span class="msg">${this.message}</span>
        <button type="button" class="act" id="vw-save-act" @click=${this.handleAction}>${this.actionLabel}</button>
        <button type="button" class="dismiss" id="vw-save-dismiss" aria-label="关闭" @click=${this.handleDismiss}>暂不</button>
      </div>
    `;
  }
}

defineContentElement('vw-save-bar', VwSaveBar);

declare global {
  interface HTMLElementTagNameMap {
    'vw-save-bar': VwSaveBar;
  }
}
