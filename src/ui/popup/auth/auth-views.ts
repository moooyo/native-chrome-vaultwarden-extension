import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon, type IconName } from '../../components/icon.js';
import '../../components/status-message.js';

export type AuthViewMode = 'login' | 'register' | 'twoFactor' | 'unlock';

export interface LoginSubmitDetail {
  email: string;
  masterPassword: string;
}

export interface RegisterSubmitDetail {
  email: string;
  name?: string;
  masterPassword: string;
  confirm: string;
}

export interface TwoFactorSubmitDetail {
  provider: number;
  code: string;
  remember: boolean;
}

export interface UnlockSubmitDetail {
  masterPassword: string;
}

export interface PinUnlockSubmitDetail {
  pin: string;
}

export interface EmailChangeDetail {
  email: string;
}

/** Friendly names for Bitwarden two-factor provider ids (unchanged from the live popup). */
const TWO_FACTOR_NAMES: Record<number, string> = {
  0: 'Authenticator app',
  1: 'Email',
  2: 'Duo',
  3: 'YubiKey OTP',
  6: 'Duo (organization)',
  7: 'Security key (FIDO2)',
};

/** Providers whose token is a code/OTP string the user can type (unchanged from the live popup). */
const CODE_BASED_PROVIDERS = [0, 1, 2, 3, 6];

/** Per-provider input hint for the code field (unchanged from the live popup). */
function twoFactorHint(provider: number): string {
  if (provider === 1) return 'Enter the code emailed to you.';
  if (provider === 3) return 'Touch your YubiKey to emit its one-time code.';
  if (provider === 2 || provider === 6) return 'Enter a passcode from the Duo Mobile app.';
  return 'Enter the 6-digit code from your authenticator app.';
}

/**
 * Renders the four auth screens (login, register, two-factor, unlock) from props only. It never
 * calls `sendRequest` or otherwise touches the worker — `VwPopupApp` owns every request and
 * transition and reacts to the typed submit/action events this component dispatches.
 */
export class VwAuthViews extends LitElement {
  static override properties = {
    mode: { type: String },
    error: { type: String },
    pending: { type: Boolean },
    providers: { attribute: false },
    pinEnabled: { type: Boolean },
    deviceRemembered: { type: Boolean },
    deviceForgotten: { type: Boolean },
  };

  declare mode: AuthViewMode;
  declare error: string | undefined;
  declare pending: boolean;
  declare providers: number[];
  declare pinEnabled: boolean;
  declare deviceRemembered: boolean;
  declare deviceForgotten: boolean;

  /** Locally-tracked provider selection for the two-factor dropdown; presentation-only, never
   *  read by the root (it always resolves the provider from the submit event's detail). */
  private selectedProvider: number | undefined;

  constructor() {
    super();
    this.mode = 'login';
    this.error = undefined;
    this.pending = false;
    this.providers = [];
    this.pinEnabled = false;
    this.deviceRemembered = false;
    this.deviceForgotten = false;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: block;
      }
      .auth {
        display: flex;
        flex-direction: column;
        gap: 12px;
        padding: 8px 4px;
      }
      .auth-head {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 4px;
        text-align: center;
      }
      .auth-head .brand-mark {
        color: var(--vw-blue-600);
      }
      .auth-head h1 {
        margin: 0;
        font-size: 16px;
      }
      .auth-head p {
        margin: 0;
        font-size: 13px;
        color: var(--vw-muted);
      }
      form {
        display: flex;
        flex-direction: column;
        gap: 10px;
      }
      .field-label {
        font-size: 12px;
        color: var(--vw-muted);
      }
      .hint {
        margin: 0;
        font-size: 12px;
        color: var(--vw-muted);
      }
      .full {
        width: 100%;
      }
      .button.danger {
        border-color: var(--vw-danger);
        color: var(--vw-danger);
      }
      .button.danger:hover {
        background: var(--vw-danger);
        border-color: var(--vw-danger);
        color: #fff;
      }
      .link-button {
        border: none;
        background: none;
        padding: 0;
        color: var(--vw-blue-600);
        font-size: 12px;
        text-decoration: underline;
        cursor: pointer;
        font-family: var(--vw-font-ui);
      }
      .remember-row {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 13px;
      }
      .pin-unlock {
        display: flex;
        flex-direction: column;
        gap: 8px;
        padding-top: 8px;
        border-top: 1px solid var(--vw-line);
      }
    `,
  ];

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (changed.has('providers') || changed.has('mode')) {
      const usable = this.usableProviders;
      if (this.selectedProvider === undefined || !usable.includes(this.selectedProvider)) {
        this.selectedProvider = usable[0];
      }
    }
  }

  private get usableProviders(): number[] {
    return this.providers.filter((provider) => CODE_BASED_PROVIDERS.includes(provider));
  }

  private inputValue(id: string): string {
    const el = this.shadowRoot?.getElementById(id);
    return el instanceof HTMLInputElement ? el.value : '';
  }

  private emit(type: string, detail: unknown = null): void {
    this.dispatchEvent(new CustomEvent(type, { detail, bubbles: true, composed: true }));
  }

  private renderHead(iconName: IconName, title: string, subtitle: string) {
    return html`
      <div class="auth-head">
        <span class="brand-mark">${uiIcon(iconName)}</span>
        <h1>${title}</h1>
        <p>${subtitle}</p>
      </div>
    `;
  }

  private renderError() {
    return this.error
      ? html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.error}></vw-status-message>`
      : nothing;
  }

  private submitLogin(): void {
    this.emit('vw-auth-login-submit', {
      email: this.inputValue('email'),
      masterPassword: this.inputValue('password'),
    } satisfies LoginSubmitDetail);
  }

  private renderRememberForgetSlot() {
    if (this.deviceForgotten) {
      return html`<p class="hint">This device is no longer remembered.</p>`;
    }
    if (this.deviceRemembered) {
      return html`
        <button type="button" class="link-button" @click=${() => this.emit('vw-auth-forget-device')}>
          This device is remembered for 2-step login — Forget
        </button>
      `;
    }
    return nothing;
  }

  private renderLogin() {
    return html`
      <div class="auth">
        ${this.renderHead('shield', 'Vaultwarden', 'Sign in to your self-hosted vault')}
        <form @submit=${(event: Event) => { event.preventDefault(); this.submitLogin(); }}>
          <label class="field">
            <span class="field-label">Email</span>
            <input
              id="email"
              class="input"
              type="email"
              autocomplete="username"
              required
              ?disabled=${this.pending}
              @change=${() => this.emit('vw-auth-email-change', { email: this.inputValue('email').trim() } satisfies EmailChangeDetail)}
            />
          </label>
          <label class="field">
            <span class="field-label">Master password</span>
            <input id="password" class="input" type="password" autocomplete="current-password" required ?disabled=${this.pending} />
          </label>
          <button type="submit" class="button primary full" ?disabled=${this.pending}>${uiIcon('unlock')}<span>Log in</span></button>
          <button type="button" class="button full" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-go-register')}>
            ${uiIcon('user')}<span>Create account</span>
          </button>
          ${this.renderError()}
        </form>
        ${this.renderRememberForgetSlot()}
      </div>
    `;
  }

  private submitRegister(): void {
    const email = this.inputValue('regEmail').trim();
    const name = this.inputValue('regName').trim();
    const masterPassword = this.inputValue('regPassword');
    const confirm = this.inputValue('regConfirm');
    const detail: RegisterSubmitDetail = name ? { email, name, masterPassword, confirm } : { email, masterPassword, confirm };
    this.emit('vw-auth-register-submit', detail);
  }

  private renderRegister() {
    return html`
      <div class="auth">
        ${this.renderHead('shield', 'Create account', 'Set up a new vault on your self-hosted server')}
        <form @submit=${(event: Event) => { event.preventDefault(); this.submitRegister(); }}>
          <label class="field">
            <span class="field-label">Email</span>
            <input id="regEmail" class="input" type="email" autocomplete="username" required ?disabled=${this.pending} />
          </label>
          <label class="field">
            <span class="field-label">Name (optional)</span>
            <input id="regName" class="input" type="text" autocomplete="name" ?disabled=${this.pending} />
          </label>
          <label class="field">
            <span class="field-label">Master password</span>
            <input id="regPassword" class="input" type="password" autocomplete="new-password" required ?disabled=${this.pending} />
          </label>
          <label class="field">
            <span class="field-label">Confirm master password</span>
            <input id="regConfirm" class="input" type="password" autocomplete="new-password" required ?disabled=${this.pending} />
          </label>
          <p class="hint">Your master password can't be recovered. It never leaves this device.</p>
          <button type="submit" class="button primary full" ?disabled=${this.pending}>${uiIcon('shield')}<span>Create account</span></button>
          <button type="button" class="button full" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-back-to-login')}>
            ${uiIcon('back')}<span>Back to sign in</span>
          </button>
          ${this.renderError()}
        </form>
      </div>
    `;
  }

  private submitTwoFactor(): void {
    const provider = this.selectedProvider ?? this.usableProviders[0];
    if (provider === undefined) return;
    const remember = this.shadowRoot?.getElementById('tfRemember');
    this.emit('vw-auth-two-factor-submit', {
      provider,
      code: this.inputValue('code'),
      remember: remember instanceof HTMLInputElement ? remember.checked : false,
    } satisfies TwoFactorSubmitDetail);
  }

  private renderTwoFactor() {
    const usable = this.usableProviders;
    if (usable.length === 0) {
      const names = this.providers.map((provider) => TWO_FACTOR_NAMES[provider] ?? `Method ${provider}`).join(', ');
      return html`
        <div class="auth">
          ${this.renderHead('shield', 'Two-step login', 'This method is not supported here yet')}
          <vw-status-message
            tone="danger"
            .icon=${'alert'}
            message=${`Your account requires: ${names || 'an unsupported method'}. Use a Bitwarden client that supports it, or add an authenticator/email method.`}
          ></vw-status-message>
          <button type="button" class="button full" @click=${() => this.emit('vw-auth-back-to-login')}>
            ${uiIcon('back')}<span>Back to login</span>
          </button>
          ${this.renderError()}
        </div>
      `;
    }
    const selected = this.selectedProvider ?? usable[0]!;
    return html`
      <div class="auth">
        ${this.renderHead('shield', 'Two-step login', 'Enter your verification code to continue')}
        <form @submit=${(event: Event) => { event.preventDefault(); this.submitTwoFactor(); }}>
          <label class="field">
            <span class="field-label">Provider</span>
            <select
              id="provider"
              class="select"
              ?disabled=${this.pending}
              @change=${(event: Event) => {
                this.selectedProvider = Number((event.target as HTMLSelectElement).value);
                this.requestUpdate();
              }}
            >
              ${usable.map((provider) => html`
                <option value=${provider} ?selected=${provider === selected}>${TWO_FACTOR_NAMES[provider] ?? `Method ${provider}`}</option>
              `)}
            </select>
          </label>
          <label class="field">
            <span class="field-label">Code</span>
            <input id="code" class="input mono" autocomplete="one-time-code" required ?disabled=${this.pending} />
            <span class="hint">${twoFactorHint(selected)}</span>
          </label>
          <label class="remember-row">
            <input id="tfRemember" type="checkbox" ?disabled=${this.pending} />
            <span>Remember this device</span>
          </label>
          <button type="submit" class="button primary full" ?disabled=${this.pending}>${uiIcon('key')}<span>Continue</span></button>
          ${usable.includes(1)
            ? html`
                <button type="button" class="button full" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-send-email-code')}>
                  ${uiIcon('mail')}<span>Send email code</span>
                </button>
              `
            : nothing}
          ${this.renderError()}
        </form>
      </div>
    `;
  }

  private submitPinUnlock(): void {
    const pin = this.inputValue('pinUnlockInput').trim();
    if (!pin) return;
    this.emit('vw-auth-pin-unlock-submit', { pin } satisfies PinUnlockSubmitDetail);
  }

  private renderPinUnlock() {
    return html`
      <div class="pin-unlock">
        <input
          id="pinUnlockInput"
          class="input"
          inputmode="numeric"
          autocomplete="off"
          placeholder="PIN"
          ?disabled=${this.pending}
          @keydown=${(event: KeyboardEvent) => {
            if (event.key === 'Enter') {
              event.preventDefault();
              this.submitPinUnlock();
            }
          }}
        />
        <button type="button" class="button full" ?disabled=${this.pending} @click=${() => this.submitPinUnlock()}>
          ${uiIcon('unlock')}<span>Unlock with PIN</span>
        </button>
      </div>
    `;
  }

  private renderUnlock() {
    return html`
      <div class="auth">
        ${this.renderHead('shield', 'Vault locked', 'Enter your master password to unlock')}
        <form @submit=${(event: Event) => { event.preventDefault(); this.emit('vw-auth-unlock-submit', { masterPassword: this.inputValue('unlockPassword') } satisfies UnlockSubmitDetail); }}>
          <label class="field">
            <span class="field-label">Master password</span>
            <input id="unlockPassword" class="input" type="password" autocomplete="current-password" required ?disabled=${this.pending} />
          </label>
          <button type="submit" class="button primary full" ?disabled=${this.pending}>${uiIcon('unlock')}<span>Unlock</span></button>
          ${this.pinEnabled ? this.renderPinUnlock() : nothing}
          <button type="button" class="button danger full" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-logout')}>
            ${uiIcon('logout')}<span>Log out</span>
          </button>
          ${this.renderError()}
        </form>
      </div>
    `;
  }

  protected override render() {
    switch (this.mode) {
      case 'login':
        return this.renderLogin();
      case 'register':
        return this.renderRegister();
      case 'twoFactor':
        return this.renderTwoFactor();
      case 'unlock':
        return this.renderUnlock();
      default:
        return nothing;
    }
  }
}

customElements.define('vw-auth-views', VwAuthViews);

declare global {
  interface HTMLElementTagNameMap {
    'vw-auth-views': VwAuthViews;
  }
}
