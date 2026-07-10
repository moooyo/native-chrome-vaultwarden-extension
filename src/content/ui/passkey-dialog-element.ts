import { LitElement, css, html, nothing } from 'lit';
import { uiIcon } from '../../ui/components/icon.js';

const dialogStyles = css`
  :host { all: initial; }
  * { box-sizing: border-box; }
  .overlay {
    position: fixed; inset: 0; display: grid; place-items: center;
    background: rgba(12,16,26,.45); z-index: 2147483647;
    font: 14px/1.5 -apple-system, "Segoe UI", system-ui, Roboto, sans-serif;
  }
  .card {
    width: min(360px, calc(100vw - 32px));
    background: #ffffff; color: #181d2b;
    border: 1px solid #dee3ef; border-radius: 14px;
    box-shadow: 0 24px 64px rgba(20,27,45,.32);
    padding: 18px; animation: pop 140ms cubic-bezier(.2,.7,.2,1);
  }
  @keyframes pop { from { opacity: 0; transform: translateY(-6px) scale(.98); } to { opacity: 1; transform: none; } }
  .head { display: flex; align-items: center; gap: 9px; margin-bottom: 10px; }
  .mark { display: grid; place-items: center; width: 26px; height: 26px; border-radius: 7px; background: linear-gradient(150deg, #4f46e5, #4338ca); color: #fff; flex: none; }
  .mark svg { width: 16px; height: 16px; }
  h1 { font-size: 14px; font-weight: 680; margin: 0; }
  p { margin: 0 0 14px; color: #5b647a; }
  .rp { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; color: #181d2b; word-break: break-all; }
  .row { display: flex; gap: 8px; }
  .col { display: flex; flex-direction: column; gap: 8px; margin-bottom: 10px; }
  .targets { display: flex; flex-direction: column; gap: 8px; }
  .targets.scrollable { max-height: 232px; overflow-y: auto; }
  .target { text-align: left; }
  button { font: inherit; flex: 1; padding: 9px 12px; border-radius: 9px; cursor: pointer; border: 1px solid transparent; font-weight: 620; }
  .confirm { background: #4f46e5; color: #fff; }
  .confirm:hover { background: #4338ca; }
  .cancel { background: #f3f5fb; color: #181d2b; border-color: #e7ebf5; }
  .cancel:hover { background: #e9edf7; }
  button:focus-visible { outline: none; box-shadow: 0 0 0 3px rgba(79,70,229,.35); }
  svg { stroke-width: 1.8; }
  @media (prefers-color-scheme: dark) {
    .card { background: #151a26; color: #e9edf7; border-color: #283041; box-shadow: 0 24px 64px rgba(0,0,0,.65); }
    p { color: #9aa4b8; } .rp { color: #e9edf7; }
    .cancel { background: #1b2230; color: #e9edf7; border-color: #283041; }
    .cancel:hover { background: #232c3d; }
  }
  @media (prefers-reduced-motion: reduce) { .card { animation: none; } }
`;

/** Above this many rows the target list scrolls locally instead of growing without bound. */
const SCROLL_THRESHOLD = 6;

/**
 * Dormant consent dialog: shown before a vault-stored passkey signs a WebAuthn assertion. Lives in a
 * closed root the page cannot reach. `onResult` fires exactly once; confirm requires a trusted click,
 * while cancel / outside-click / Escape resolve false.
 */
export class VwPasskeyConsent extends LitElement {
  static override properties = {
    rpId: { type: String },
    onResult: { attribute: false },
  };

  declare rpId: string;
  declare onResult: ((confirmed: boolean) => void) | undefined;

  private settled = false;

  constructor() {
    super();
    this.rpId = '';
    this.onResult = undefined;
  }

  static override styles = dialogStyles;

  private readonly handleKeydown = (event: KeyboardEvent): void => {
    if (event.key === 'Escape') {
      event.preventDefault();
      this.finish(false);
    }
  };

  override connectedCallback(): void {
    super.connectedCallback();
    window.addEventListener('keydown', this.handleKeydown, true);
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    window.removeEventListener('keydown', this.handleKeydown, true);
  }

  private finish(confirmed: boolean): void {
    if (this.settled) {
      return;
    }
    this.settled = true;
    window.removeEventListener('keydown', this.handleKeydown, true);
    this.onResult?.(confirmed);
  }

  private handleConfirm(event: MouseEvent): void {
    if (event.isTrusted) {
      this.finish(true);
    }
  }

  private handleCancel(event: MouseEvent): void {
    if (event.isTrusted) {
      this.finish(false);
    }
  }

  private handleOverlay(event: MouseEvent): void {
    if (event.isTrusted && event.target === event.currentTarget) {
      this.finish(false);
    }
  }

  protected override render() {
    return html`
      <div class="overlay" @click=${this.handleOverlay}>
        <div class="card" role="dialog" aria-modal="true" aria-label="Use passkey">
          <div class="head"><span class="mark">${uiIcon('shield')}</span><h1>Use a saved passkey?</h1></div>
          <p>Vaultwarden will sign in to <span class="rp">${this.rpId}</span> with a passkey from your vault.</p>
          <div class="row">
            <button type="button" class="cancel" id="vw-pk-cancel" @click=${this.handleCancel}>Cancel</button>
            <button type="button" class="confirm" id="vw-pk-confirm" @click=${this.handleConfirm}>Use passkey</button>
          </div>
        </div>
      </div>
    `;
  }
}

export interface PasskeyRegisterTarget {
  id: string;
  name: string;
  username?: string;
}

export type PasskeyRegisterResult = { cancelled: true } | { targetCipherId?: string };

/**
 * Dormant registration picker: choose where to store a new passkey (a new item, or an existing
 * same-domain item). Lives in a closed root. `onResult` fires exactly once. Target identities stay in
 * the in-memory `targets` array and are selected by rendered index — their ids never reach the DOM.
 */
export class VwPasskeyRegister extends LitElement {
  static override properties = {
    rpId: { type: String },
    targets: { attribute: false },
    onResult: { attribute: false },
  };

  declare rpId: string;
  declare targets: PasskeyRegisterTarget[];
  declare onResult: ((result: PasskeyRegisterResult) => void) | undefined;

  private settled = false;

  constructor() {
    super();
    this.rpId = '';
    this.targets = [];
    this.onResult = undefined;
  }

  static override styles = dialogStyles;

  private readonly handleKeydown = (event: KeyboardEvent): void => {
    if (event.key === 'Escape') {
      event.preventDefault();
      this.finish({ cancelled: true });
    }
  };

  override connectedCallback(): void {
    super.connectedCallback();
    window.addEventListener('keydown', this.handleKeydown, true);
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    window.removeEventListener('keydown', this.handleKeydown, true);
  }

  private finish(result: PasskeyRegisterResult): void {
    if (this.settled) {
      return;
    }
    this.settled = true;
    window.removeEventListener('keydown', this.handleKeydown, true);
    this.onResult?.(result);
  }

  private handleNew(event: MouseEvent): void {
    if (event.isTrusted) {
      this.finish({});
    }
  }

  private handleCancel(event: MouseEvent): void {
    if (event.isTrusted) {
      this.finish({ cancelled: true });
    }
  }

  private handleTarget(event: MouseEvent, index: number): void {
    if (!event.isTrusted) {
      return;
    }
    const target = this.targets[index];
    if (target) {
      this.finish({ targetCipherId: target.id });
    }
  }

  private handleOverlay(event: MouseEvent): void {
    if (event.isTrusted && event.target === event.currentTarget) {
      this.finish({ cancelled: true });
    }
  }

  protected override render() {
    const scrollable = this.targets.length > SCROLL_THRESHOLD;
    return html`
      <div class="overlay" @click=${this.handleOverlay}>
        <div class="card" role="dialog" aria-modal="true" aria-label="Save passkey">
          <div class="head"><span class="mark">${uiIcon('shield')}</span><h1>Save a passkey for <span class="rp">${this.rpId}</span>?</h1></div>
          <p>Choose where to store this passkey in your vault.</p>
          <div class="col">
            <button type="button" class="confirm" id="vw-pk-new" @click=${this.handleNew}>New login item</button>
            <div class="targets ${scrollable ? 'scrollable' : ''}">
              ${this.targets.map((target, index) => this.renderTarget(target, index))}
            </div>
          </div>
          <div class="row"><button type="button" class="cancel" id="vw-pk-cancel" @click=${this.handleCancel}>Cancel</button></div>
        </div>
      </div>
    `;
  }

  private renderTarget(target: PasskeyRegisterTarget, index: number) {
    return html`
      <button type="button" class="cancel target" @click=${(event: MouseEvent) => this.handleTarget(event, index)}>
        ${target.name}${target.username ? html` <span class="rp">${target.username}</span>` : nothing}
      </button>
    `;
  }
}

customElements.define('vw-passkey-consent', VwPasskeyConsent);
customElements.define('vw-passkey-register', VwPasskeyRegister);

declare global {
  interface HTMLElementTagNameMap {
    'vw-passkey-consent': VwPasskeyConsent;
    'vw-passkey-register': VwPasskeyRegister;
  }
}
