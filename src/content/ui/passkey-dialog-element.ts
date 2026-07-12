import { defineContentElement } from './define.js';
import { LitElement, css, html, nothing } from 'lit';
import { uiIcon } from '../../ui/components/icon.js';

// NOTE: These dialogs render inside a CLOSED shadow root on arbitrary host pages, so they cannot
// rely on the extension's `--vw-*` design tokens (those only exist inside the extension's own page
// roots). The MiYu palette is therefore redeclared LOCALLY on `:host` as `--mv-*` custom properties,
// with a `@media (prefers-color-scheme: dark)` block. `:host{all:initial}` isolates us from the
// host page's cascade (it does not reset custom properties). Values mirror `paletteTokens` in
// `src/ui/components/tokens.ts`; the moss logo block (`--mv-teal`) is identical in both themes.
const dialogStyles = css`
  :host {
    all: initial;
    --mv-overlay: rgba(18, 22, 30, 0.28);
    --mv-panel: #fcfcfb;
    --mv-ink: #16181d;
    --mv-teal: #0e8a72;
    --mv-teal-text: #0b7a65;
    --mv-teal-10: rgba(14, 138, 114, 0.1);
    --mv-muted: #8a8f99;
    --mv-faint: #9aa0aa;
    --mv-text-2: #565b66;
    --mv-line: rgba(22, 24, 29, 0.09);
    --mv-row-hover: #f2f2ef;
    --mv-chevron: #c4c7cc;
    --mv-primary-bg: #16181d;
    --mv-primary-bg-hover: #2a2d34;
    --mv-primary-fg: #ffffff;
    --mv-dialog-shadow: 0 24px 56px rgba(20, 24, 32, 0.28);
    --mv-font-ui: 'Instrument Sans', 'Segoe UI', system-ui, sans-serif;
    --mv-font-mono: 'JetBrains Mono', ui-monospace, monospace;
  }
  @media (prefers-color-scheme: dark) {
    :host {
      --mv-panel: #1f2229;
      --mv-ink: #f2f3f5;
      --mv-teal-text: #45d6b5;
      --mv-teal-10: rgba(69, 214, 181, 0.14);
      --mv-muted: #9aa0ac;
      --mv-faint: #7b818b;
      --mv-text-2: #9aa0ac;
      --mv-line: rgba(255, 255, 255, 0.09);
      --mv-row-hover: rgba(255, 255, 255, 0.05);
      --mv-chevron: #565b66;
      --mv-primary-bg: #f2f3f5;
      --mv-primary-bg-hover: #ffffff;
      --mv-primary-fg: #16181d;
      --mv-dialog-shadow: 0 24px 56px rgba(0, 0, 0, 0.5);
    }
  }
  * { box-sizing: border-box; }

  .overlay {
    position: fixed;
    inset: 0;
    display: grid;
    place-items: center;
    background: var(--mv-overlay);
    z-index: 2147483647;
    font-family: var(--mv-font-ui);
    font-size: 13px;
    line-height: 1.45;
    -webkit-font-smoothing: antialiased;
  }
  .card {
    width: 302px;
    max-width: calc(100vw - 32px);
    background: var(--mv-panel);
    color: var(--mv-ink);
    border: 1px solid var(--mv-line);
    border-radius: 16px;
    box-shadow: var(--mv-dialog-shadow);
    overflow: hidden;
    animation: mvIn 0.18s ease-out;
  }
  @keyframes mvIn {
    from { opacity: 0; transform: translateY(-5px); }
    to { opacity: 1; transform: none; }
  }

  /* Header: mini-logo + brand + domain -------------------------------------------------- */
  .header { display: flex; align-items: center; gap: 7px; padding: 12px 14px 10px; }
  .logo {
    width: 16px;
    height: 16px;
    border-radius: 5px;
    background: var(--mv-teal);
    display: grid;
    place-items: center;
    flex: none;
  }
  .logo-glyph { position: relative; width: 8px; height: 8px; }
  .logo-ring { position: absolute; inset: 0; border: 1.5px solid #fff; border-radius: 50%; }
  .logo-dot { position: absolute; left: 3px; top: 3px; width: 2px; height: 2px; border-radius: 50%; background: #fff; }
  .brand { font-size: 11.5px; font-weight: 600; color: var(--mv-teal-text); letter-spacing: 0.01em; }
  .domain {
    margin-left: auto;
    font-size: 10.5px;
    color: var(--mv-faint);
    max-width: 160px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  /* Body -------------------------------------------------------------------------------- */
  .body { padding: 4px 16px 16px; display: flex; flex-direction: column; align-items: center; text-align: center; }
  .icon-circle {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    background: var(--mv-teal-10);
    color: var(--mv-teal-text);
    display: grid;
    place-items: center;
    margin-bottom: 12px;
  }
  .icon-circle svg { width: 20px; height: 20px; }
  .title { margin: 0; font-size: 14px; font-weight: 600; color: var(--mv-ink); }
  .sub { margin: 4px 0 0; font-size: 11.5px; color: var(--mv-muted); line-height: 1.5; }

  .primary {
    margin-top: 16px;
    width: 100%;
    height: 40px;
    border: none;
    border-radius: 10px;
    background: var(--mv-primary-bg);
    color: var(--mv-primary-fg);
    font-family: inherit;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: background-color 0.15s;
  }
  .primary:hover { background: var(--mv-primary-bg-hover); }

  /* Account list ------------------------------------------------------------------------ */
  .list { margin-top: 12px; width: 100%; display: flex; flex-direction: column; gap: 2px; }
  .list.scrollable { max-height: 216px; overflow-y: auto; }
  .row {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    text-align: left;
    padding: 9px 8px;
    border: none;
    background: transparent;
    border-radius: 10px;
    color: var(--mv-ink);
    font-family: inherit;
    cursor: pointer;
  }
  .row:hover { background: var(--mv-row-hover); }
  .tile {
    width: 30px;
    height: 30px;
    border-radius: 9px;
    flex: none;
    display: grid;
    place-items: center;
    background: var(--mv-teal-10);
    color: var(--mv-teal-text);
    font-size: 13px;
    font-weight: 700;
  }
  .row-text { display: flex; flex-direction: column; min-width: 0; flex: 1; }
  .row-name { font-size: 12.5px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .row-user { font-size: 11px; color: var(--mv-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .row-chev { color: var(--mv-chevron); display: grid; place-items: center; flex: none; }
  .row-chev svg { width: 16px; height: 16px; }

  /* Footer ------------------------------------------------------------------------------ */
  .footer {
    width: 100%;
    height: 40px;
    border: none;
    border-top: 1px solid var(--mv-line);
    background: transparent;
    color: var(--mv-text-2);
    font-family: inherit;
    font-size: 12px;
    cursor: pointer;
    transition: background-color 0.15s;
  }
  .footer:hover { background: var(--mv-row-hover); }

  button:focus-visible { outline: none; box-shadow: 0 0 0 2px rgba(14, 138, 114, 0.55); }
  @media (prefers-reduced-motion: reduce) { .card { animation: none; } }
`;

/** Above this many rows the target list scrolls locally instead of growing without bound. */
const SCROLL_THRESHOLD = 6;

/** First visible character of a label, uppercased, for the account tile. Falls back to a dot. */
function tileInitial(name: string): string {
  const first = [...name.trim()][0];
  return first ? first.toUpperCase() : '•';
}

/** Shared dialog header: the 16px moss mini-logo, the 密屿 wordmark, and the requesting domain.
 *  `// TODO i18n` — content surfaces don't import the extension i18n module, so strings are inline. */
function renderHeader(rpId: string) {
  return html`
    <div class="header">
      <span class="logo" aria-hidden="true">
        <span class="logo-glyph"><span class="logo-ring"></span><span class="logo-dot"></span></span>
      </span>
      <span class="brand">密屿</span>
      <span class="domain">${rpId}</span>
    </div>
  `;
}

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
    // Hardcoded Chinese — content surfaces don't import the i18n module. // TODO i18n
    return html`
      <div class="overlay" @click=${this.handleOverlay}>
        <div class="card" role="dialog" aria-modal="true" aria-label="使用通行密钥">
          ${renderHeader(this.rpId)}
          <div class="body">
            <div class="icon-circle">${uiIcon('key')}</div>
            <h1 class="title">使用通行密钥登录</h1>
            <p class="sub">此网站请求使用通行密钥验证身份</p>
            <button type="button" class="primary" id="vw-pk-confirm" @click=${this.handleConfirm}>使用通行密钥</button>
          </div>
          <button type="button" class="footer" id="vw-pk-cancel" @click=${this.handleCancel}>改用密码登录</button>
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
    // Hardcoded Chinese — content surfaces don't import the i18n module. // TODO i18n
    return html`
      <div class="overlay" @click=${this.handleOverlay}>
        <div class="card" role="dialog" aria-modal="true" aria-label="保存通行密钥">
          ${renderHeader(this.rpId)}
          <div class="body">
            <div class="icon-circle">${uiIcon('key')}</div>
            <h1 class="title">保存通行密钥</h1>
            <p class="sub">选择要保存的登录项，或新建一个</p>
            <button type="button" class="primary" id="vw-pk-new" @click=${this.handleNew}>创建通行密钥</button>
            ${this.targets.length
              ? html`
                  <div class="list ${scrollable ? 'scrollable' : ''}">
                    ${this.targets.map((target, index) => this.renderTarget(target, index))}
                  </div>
                `
              : nothing}
          </div>
          <button type="button" class="footer" id="vw-pk-cancel" @click=${this.handleCancel}>取消</button>
        </div>
      </div>
    `;
  }

  private renderTarget(target: PasskeyRegisterTarget, index: number) {
    return html`
      <button type="button" class="row target" @click=${(event: MouseEvent) => this.handleTarget(event, index)}>
        <span class="tile" aria-hidden="true">${tileInitial(target.name)}</span>
        <span class="row-text">
          <span class="row-name">${target.name}</span>
          ${target.username ? html`<span class="row-user">${target.username}</span>` : nothing}
        </span>
        <span class="row-chev" aria-hidden="true">${uiIcon('chevron')}</span>
      </button>
    `;
  }
}

defineContentElement('vw-passkey-consent', VwPasskeyConsent);
defineContentElement('vw-passkey-register', VwPasskeyRegister);

declare global {
  interface HTMLElementTagNameMap {
    'vw-passkey-consent': VwPasskeyConsent;
    'vw-passkey-register': VwPasskeyRegister;
  }
}
