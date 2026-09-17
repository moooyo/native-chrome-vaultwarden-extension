import { html, nothing, type TemplateResult } from 'lit';
import { uiIcon } from '../../ui/components/icon.js';

// NOTE: These dialogs render inside a CLOSED shadow root on arbitrary host pages, so they cannot
// rely on the extension's `--vw-*` design tokens (those only exist inside the extension's own page
// roots). The MiYu palette is therefore redeclared LOCALLY on `:host` as `--mv-*` custom properties,
// with a `@media (prefers-color-scheme: dark)` block. `:host{all:initial}` isolates us from the
// host page's cascade (it does not reset custom properties). Values mirror `paletteTokens` in
// `src/ui/components/tokens.ts`; the brand block follows the approved blue-and-white design.
//
// Content scripts run in an isolated world with no custom-element registry (`customElements` is null;
// Chromium 41118431), so these surfaces render via lit-html `render()` into a closed shadow root
// rather than as custom elements. The styles are exported as a plain string applied once by
// `mountRenderSurface`; the render functions below are pure `(state, handlers) => TemplateResult`.
export const DIALOG_STYLES = `
  :host {
    all: initial;
    --mv-overlay: rgba(15, 23, 42, 0.24);
    --mv-panel:#ffffff;
    --mv-ink:#192d48;
    --mv-teal:#155ed7;
    --mv-teal-text:#155ed7;
    --mv-teal-10:#edf4ff;
    --mv-muted:#62718a;
    --mv-faint:#62718a;
    --mv-text-2:#42526c;
    --mv-line:#e1e8f2;
    --mv-row-hover:#f3f7fd;
    --mv-chevron:#71819a;
    --mv-primary-bg:#155ed7;
    --mv-primary-bg-hover:#0d4faf;
    --mv-primary-fg: #ffffff;
    --mv-dialog-shadow:0 18px 56px rgba(27, 48, 82, .16), 0 2px 8px rgba(27, 48, 82, .06);
    --mv-font-ui:'Segoe UI Variable Text','Segoe UI','Microsoft YaHei UI',system-ui,sans-serif;
    --mv-font-mono:'Cascadia Code',ui-monospace,monospace;
  }
  @media (prefers-color-scheme: dark) {
    :host {
      --mv-panel:#172238;
      --mv-ink:#edf3ff;
      --mv-teal:#8eb9ff;
      --mv-teal-text:#a8c9ff;
      --mv-teal-10:#213756;
      --mv-muted:#a8b7d0;
      --mv-faint:#a8b7d0;
      --mv-text-2:#c8d5ea;
      --mv-line:#33445f;
      --mv-row-hover:#213149;
      --mv-chevron:#a8b7d0;
      --mv-primary-bg:#8eb9ff;
      --mv-primary-bg-hover:#b4d0ff;
      --mv-primary-fg:#132c55;
      --mv-dialog-shadow:0 8px 28px rgba(0,0,0,.5);
    }
  }
  * { box-sizing: border-box; }

  .overlay {
    position: fixed;
    inset: 0;
    padding: 16px;
    display: grid;
    place-items: center;
    background: var(--mv-overlay);
    z-index: 2147483647;
    font-family: var(--mv-font-ui);
    font-size: 13px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }
  .card {
    display: flex;
    flex-direction: column;
    width: 360px;
    max-width: calc(100vw - 32px);
    max-height: calc(100vh - 32px);
    max-height: calc(100dvh - 32px);
    background: var(--mv-panel);
    color: var(--mv-ink);
    border: 1px solid var(--mv-line);
    border-radius:16px;
    box-shadow: var(--mv-dialog-shadow);
    overflow: hidden;
    animation:mvIn .18s cubic-bezier(.2,.8,.2,1);
  }
  @keyframes mvIn {
    from { opacity: 0; transform: translateY(6px); }
    to { opacity: 1; transform: none; }
  }

  /* Keep the entire requesting domain visible before any credential action. */
  .header { padding: 18px 20px 16px; border-bottom: 1px solid var(--mv-line); flex: none; }
  .brand-line { display: flex; align-items: center; gap: 8px; }
  .logo {
    width: 24px;
    height: 24px;
    border-radius: 7px;
    background: var(--mv-teal);
    display: grid;
    place-items: center;
    flex: none;
  }
  .logo svg { width:16px; height:16px; fill:var(--mv-panel); stroke:none; }
  .brand { font-size: 14px; font-weight: 650; color: var(--mv-ink); letter-spacing: 0.02em; }
  .product-kind { margin-left: auto; font-size: 11px; color: var(--mv-muted); }
  .request-label { display: block; margin-top: 16px; font-size: 11px; color: var(--mv-muted); }
  .domain {
    display: block;
    margin-top: 3px;
    font-size: 14px;
    font-weight: 600;
    color: var(--mv-ink);
    overflow-wrap: anywhere;
    unicode-bidi: plaintext;
    direction: ltr;
  }

  /* Body -------------------------------------------------------------------------------- */
  .body { padding: 20px; display: flex; flex-direction: column; align-items: flex-start; text-align: left; min-height: 0; overflow-y: auto; overscroll-behavior: contain; scrollbar-width: thin; }
  .icon-circle {
    width: 36px;
    height: 36px;
    border-radius: 10px;
    flex: none;
    background: var(--mv-teal-10);
    color: var(--mv-teal-text);
    display: grid;
    place-items: center;
    margin-bottom: 12px;
  }
  .icon-circle svg { width: 20px; height: 20px; }
  .title { margin: 0; font-size: 19px; line-height: 1.35; font-weight: 650; letter-spacing: -.02em; color: var(--mv-ink); }
  .sub { margin: 7px 0 0; font-size: 12px; color: var(--mv-muted); line-height: 1.65; }
  .list-label { margin-top: 20px; font-size: 11px; font-weight: 600; color: var(--mv-muted); }

  .primary {
    margin-top: 20px;
    width: 100%;
    min-height: 42px;
    flex: none;
    padding: 10px 14px;
    appearance: none;
    border: none;
    border-radius:10px;
    background: var(--mv-primary-bg);
    color: var(--mv-primary-fg);
    font-family: inherit;
    font-size: 13px;
    font-weight:600;
    cursor: pointer;
    transition: background-color .14s ease, transform .14s ease;
  }
  .primary:hover { background: var(--mv-primary-bg-hover); }
  .primary:active { transform: translateY(1px); }

  /* Account list ------------------------------------------------------------------------ */
  .list { margin-top: 10px; width: 100%; display: flex; flex-direction: column; flex: none; gap: 2px; }
  .list.scrollable { max-height: 264px; overflow-y: auto; overscroll-behavior: contain; scrollbar-width: thin; }
  .row {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    text-align: left;
    padding: 11px 10px;
    min-height: 58px;
    flex: none;
    appearance: none;
    border: none;
    background: transparent;
    border-radius: 10px;
    color: var(--mv-ink);
    font-family: inherit;
    cursor: pointer;
    transition: background-color .14s ease;
  }
  .row:hover { background: var(--mv-row-hover); }
  .tile {
    width: 34px;
    height: 34px;
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
  .row-name { font-size: 13px; font-weight: 600; overflow-wrap: anywhere; }
  .row-user { margin-top: 2px; font-size: 11px; color: var(--mv-muted); overflow-wrap: anywhere; }
  .row-chev { color: var(--mv-chevron); display: grid; place-items: center; flex: none; }
  .row-chev svg { width: 16px; height: 16px; }

  /* Footer ------------------------------------------------------------------------------ */
  .footer {
    width: 100%;
    min-height: 44px;
    flex: none;
    padding: 12px 16px;
    appearance: none;
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

  button:focus-visible { outline: 2px solid var(--mv-teal); outline-offset: -3px; }
  .primary:focus-visible { outline-color: var(--mv-primary-fg); outline-offset: -5px; }
  @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; transition: none !important; } }
`;

/** Above this many rows the target list scrolls locally instead of growing without bound. */
const SCROLL_THRESHOLD = 6;

export interface PasskeyRegisterTarget {
  id: string;
  name: string;
  username?: string;
}

export type PasskeyRegisterResult = { cancelled: true } | { targetCipherId?: string };

/** The render state of the consent dialog. Held by the factory (see passkey-consent.ts). */
export interface PasskeyConsentState {
  rpId: string;
}

/** Privileged callbacks for the consent dialog. Every click that reaches them is gated on
 *  `Event.isTrusted` in the template, so a page script cannot synthesize a click to confirm/cancel. */
export interface PasskeyConsentHandlers {
  onConfirm?: () => void;
  onCancel?: () => void;
  /** Fired when the user clicks the backdrop outside the card (a trusted click on the overlay itself). */
  onOverlay?: () => void;
}

/** The render state of the registration picker. Target identities stay in this in-memory array and are
 *  selected by rendered index — their ids never reach the DOM. */
export interface PasskeyRegisterState {
  rpId: string;
  targets: PasskeyRegisterTarget[];
}

/** Privileged callbacks for the registration picker. Gated on `Event.isTrusted` in the template. */
export interface PasskeyRegisterHandlers {
  onNew?: () => void;
  onCancel?: () => void;
  /** Select an existing target by its rendered index (its cipher id never enters the DOM). */
  onSelectTarget?: (index: number) => void;
  /** Fired when the user clicks the backdrop outside the card (a trusted click on the overlay itself). */
  onOverlay?: () => void;
}

/** First visible character of a label, uppercased, for the account tile. Falls back to a dot. */
function tileInitial(name: string): string {
  const first = [...name.trim()][0];
  return first ? first.toUpperCase() : '•';
}

/** Shared dialog header: the blue mini-logo, the MiYu wordmark, and the full requesting domain.
 *  `// TODO i18n` — content surfaces don't import the extension i18n module, so strings are inline. */
function renderHeader(rpId: string): TemplateResult {
  return html`
    <div class="header">
      <div class="brand-line">
        <span class="logo" aria-hidden="true">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7.5 15.5a5.5 5.5 0 1 1 4.9-8H22v4h-2v2h-3v2h-4.6a5.5 5.5 0 0 1-4.9 3Zm0-3.5a2 2 0 1 0 0 4 2 2 0 0 0 0-4Z"/></svg>
        </span>
        <span class="brand">密屿</span>
        <span class="product-kind">通行密钥</span>
      </div>
      <span class="request-label">请求网站</span>
      <span class="domain" id="vw-pk-domain">${rpId}</span>
    </div>
  `;
}

/** Only a trusted click on the overlay itself (not bubbling from the card) counts as an outside click. */
function overlayHandler(handlers: { onOverlay?: () => void }) {
  return (event: MouseEvent): void => {
    if (event.isTrusted && event.target === event.currentTarget) {
      handlers.onOverlay?.();
    }
  };
}

/**
 * Consent dialog: shown before a vault-stored passkey signs a WebAuthn assertion. Confirm requires a
 * trusted click; cancel / outside-click resolve false (Escape is handled by the factory's key listener).
 */
export function renderPasskeyConsent(
  state: PasskeyConsentState,
  handlers: PasskeyConsentHandlers,
): TemplateResult {
  // Hardcoded Chinese — content surfaces don't import the i18n module. // TODO i18n
  return html`
    <div class="overlay" @click=${overlayHandler(handlers)}>
      <div class="card" role="dialog" aria-modal="true" aria-labelledby="vw-pk-title" aria-describedby="vw-pk-domain vw-pk-description">
        ${renderHeader(state.rpId)}
        <div class="body">
          <div class="icon-circle" aria-hidden="true">${uiIcon('key')}</div>
          <h1 class="title" id="vw-pk-title">使用通行密钥登录</h1>
          <p class="sub" id="vw-pk-description">使用已保存的通行密钥，验证你在此网站的身份。</p>
          <button
            type="button"
            class="primary"
            id="vw-pk-confirm"
            @click=${(event: MouseEvent) => { if (event.isTrusted) handlers.onConfirm?.(); }}
          >
            使用通行密钥
          </button>
        </div>
        <button
          type="button"
          class="footer"
          id="vw-pk-cancel"
          @click=${(event: MouseEvent) => { if (event.isTrusted) handlers.onCancel?.(); }}
        >
          取消网站请求
        </button>
      </div>
    </div>
  `;
}

/**
 * Registration picker: choose where to store a new passkey (a new item, or an existing same-domain
 * item). Confirm / target selection require a trusted click; cancel / outside-click resolve cancelled
 * (Escape is handled by the factory's key listener).
 */
export function renderPasskeyRegister(
  state: PasskeyRegisterState,
  handlers: PasskeyRegisterHandlers,
): TemplateResult {
  const scrollable = state.targets.length > SCROLL_THRESHOLD;
  // Hardcoded Chinese — content surfaces don't import the i18n module. // TODO i18n
  return html`
    <div class="overlay" @click=${overlayHandler(handlers)}>
      <div class="card" role="dialog" aria-modal="true" aria-labelledby="vw-pk-title" aria-describedby="vw-pk-domain vw-pk-description">
        ${renderHeader(state.rpId)}
        <div class="body">
          <div class="icon-circle" aria-hidden="true">${uiIcon('key')}</div>
          <h1 class="title" id="vw-pk-title">保存通行密钥</h1>
          <p class="sub" id="vw-pk-description">保存到已有登录项，或为此网站新建一个登录项。</p>
          <button
            type="button"
            class="primary"
            id="vw-pk-new"
            @click=${(event: MouseEvent) => { if (event.isTrusted) handlers.onNew?.(); }}
          >
            新建登录项并保存
          </button>
          ${state.targets.length
            ? html`
                <span class="list-label" id="vw-pk-list-label">保存到已有登录项</span>
                <div class="list ${scrollable ? 'scrollable' : ''}" role="group" aria-labelledby="vw-pk-list-label">
                  ${state.targets.map((target, index) => renderTarget(target, index, handlers))}
                </div>
              `
            : nothing}
        </div>
        <button
          type="button"
          class="footer"
          id="vw-pk-cancel"
          @click=${(event: MouseEvent) => { if (event.isTrusted) handlers.onCancel?.(); }}
        >
          取消保存
        </button>
      </div>
    </div>
  `;
}

function renderTarget(
  target: PasskeyRegisterTarget,
  index: number,
  handlers: PasskeyRegisterHandlers,
): TemplateResult {
  return html`
    <button
      type="button"
      class="row target"
      @click=${(event: MouseEvent) => { if (event.isTrusted) handlers.onSelectTarget?.(index); }}
    >
      <span class="tile" aria-hidden="true">${tileInitial(target.name)}</span>
      <span class="row-text">
        <span class="row-name">${target.name}</span>
        ${target.username ? html`<span class="row-user">${target.username}</span>` : nothing}
      </span>
      <span class="row-chev" aria-hidden="true">${uiIcon('chevron')}</span>
    </button>
  `;
}

/** A single account shown in the login picker. The credentialId stays out of the render state — the
 *  factory (passkey-consent.ts) maps the selected index back to a credential in its own memory. */
export interface PasskeyLoginAccount {
  name: string;
  username?: string;
}

/** The render state of the login (assertion) account picker. */
export interface PasskeyLoginPickerState {
  rpId: string;
  accounts: PasskeyLoginAccount[];
}

/** Privileged callbacks for the login picker. Gated on `Event.isTrusted` in the template. */
export interface PasskeyLoginPickerHandlers {
  onCancel?: () => void;
  /** Select an account by its rendered index (its credentialId never enters the DOM). */
  onSelect?: (index: number) => void;
  /** Fired when the user clicks the backdrop outside the card (a trusted click on the overlay itself). */
  onOverlay?: () => void;
}

/**
 * Login picker: shown before signing an assertion when the site has MORE THAN ONE stored passkey, so
 * the user chooses which account to sign in with. Selection requires a trusted click; cancel /
 * outside-click resolve cancelled (Escape is handled by the factory's key listener). A single passkey
 * uses the simpler `renderPasskeyConsent` instead — no picker.
 */
export function renderPasskeyLoginPicker(
  state: PasskeyLoginPickerState,
  handlers: PasskeyLoginPickerHandlers,
): TemplateResult {
  const scrollable = state.accounts.length > SCROLL_THRESHOLD;
  // Hardcoded Chinese — content surfaces don't import the i18n module. // TODO i18n
  return html`
    <div class="overlay" @click=${overlayHandler(handlers)}>
      <div class="card" role="dialog" aria-modal="true" aria-labelledby="vw-pk-title" aria-describedby="vw-pk-domain vw-pk-description">
        ${renderHeader(state.rpId)}
        <div class="body">
          <div class="icon-circle" aria-hidden="true">${uiIcon('key')}</div>
          <h1 class="title" id="vw-pk-title">选择通行密钥</h1>
          <p class="sub" id="vw-pk-description">选择要登录的账户。仅为上方网站完成通行密钥验证。</p>
          <div class="list ${scrollable ? 'scrollable' : ''}" role="group" aria-label="可用账户">
            ${state.accounts.map((account, index) => html`
              <button
                type="button"
                class="row target"
                @click=${(event: MouseEvent) => { if (event.isTrusted) handlers.onSelect?.(index); }}
              >
                <span class="tile" aria-hidden="true">${tileInitial(account.name)}</span>
                <span class="row-text">
                  <span class="row-name">${account.name}</span>
                  ${account.username ? html`<span class="row-user">${account.username}</span>` : nothing}
                </span>
                <span class="row-chev" aria-hidden="true">${uiIcon('chevron')}</span>
              </button>
            `)}
          </div>
        </div>
        <button
          type="button"
          class="footer"
          id="vw-pk-cancel"
          @click=${(event: MouseEvent) => { if (event.isTrusted) handlers.onCancel?.(); }}
        >
          取消网站请求
        </button>
      </div>
    </div>
  `;
}
