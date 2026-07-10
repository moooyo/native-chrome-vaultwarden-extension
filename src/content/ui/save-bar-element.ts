import { LitElement, css, html } from 'lit';
import { uiIcon } from '../../ui/components/icon.js';

/**
 * Dormant Lit surface backing the save/update bar. Mounted inside a closed root so the page cannot
 * read it or forge its actions; only trusted clicks act. The site-controlled `message` is bound with
 * `${}` so it always renders inert. Callbacks are non-reflected properties.
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
    * { box-sizing: border-box; }
    .bar {
      position: fixed; top: 12px; left: 50%; transform: translateX(-50%);
      display: flex; align-items: center; gap: 12px;
      max-width: min(560px, calc(100vw - 24px));
      font: 14px/1.4 "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif;
      color: rgb(0 0 0 / 82%); background: #ffffff;
      border: 1px solid rgb(0 0 0 / 13%); border-radius: 8px;
      box-shadow: 0 18px 48px rgba(20,27,45,.22), 0 4px 12px rgba(20,27,45,.12);
      padding: 10px 12px; z-index: 2147483647;
      animation: drop 160ms cubic-bezier(.2,.7,.2,1);
    }
    @keyframes drop { from { opacity: 0; transform: translate(-50%, -8px); } to { opacity: 1; transform: translate(-50%, 0); } }
    .mark { display: grid; place-items: center; width: 22px; height: 22px; border-radius: 4px; background: hsl(212 96% 47%); color: #fff; flex: none; }
    .mark svg { width: 14px; height: 14px; }
    .msg { flex: 1; min-width: 0; overflow-wrap: anywhere; }
    button { font: inherit; border-radius: 8px; padding: 7px 12px; cursor: pointer; border: 1px solid transparent; font-weight: 620; flex: none; }
    .act { background: hsl(212 96% 47%); color: #fff; }
    .act:hover { background: hsl(216 100% 39%); }
    .dismiss { background: transparent; color: #5b647a; padding: 7px 8px; }
    .dismiss:hover { color: #181d2b; }
    button:focus-visible { outline: none; box-shadow: 0 0 0 2px hsl(215 63% 53%); }
    svg { stroke-width: 1.8; }
    @media (prefers-color-scheme: dark) {
      .bar { color: #e9edf7; background: #151a26; border-color: #283041; box-shadow: 0 18px 48px rgba(0,0,0,.6); }
      .dismiss { color: #9aa4b8; } .dismiss:hover { color: #e9edf7; }
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
    return html`
      <div class="bar" role="dialog" aria-label="Save login">
        <span class="mark">${uiIcon('shield')}</span>
        <span class="msg">${this.message}</span>
        <button type="button" class="act" id="vw-save-act" @click=${this.handleAction}>${this.actionLabel}</button>
        <button type="button" class="dismiss" id="vw-save-dismiss" aria-label="Dismiss" @click=${this.handleDismiss}>Not now</button>
      </div>
    `;
  }
}

customElements.define('vw-save-bar', VwSaveBar);

declare global {
  interface HTMLElementTagNameMap {
    'vw-save-bar': VwSaveBar;
  }
}
