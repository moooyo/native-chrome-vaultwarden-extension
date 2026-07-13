import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/logo.js';
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

/** Friendly names for Bitwarden two-factor provider ids (unchanged behaviour from the live popup). */
const TWO_FACTOR_NAMES: Record<number, string> = {
  0: '验证器应用', // TODO i18n
  1: '邮箱验证码', // TODO i18n
  2: 'Duo',
  3: 'YubiKey OTP',
  6: 'Duo（组织）', // TODO i18n
  7: '安全密钥 (FIDO2)', // TODO i18n
};

/** Providers whose token is a code/OTP string the user can type (unchanged from the live popup). */
const CODE_BASED_PROVIDERS = [0, 1, 2, 3, 6];

/** Per-provider input hint for the code field (unchanged behaviour from the live popup). */
function twoFactorHint(provider: number): string {
  if (provider === 1) return '输入发送到你邮箱的验证码'; // TODO i18n
  if (provider === 3) return '轻触 YubiKey 以生成一次性验证码'; // TODO i18n
  if (provider === 2 || provider === 6) return '输入 Duo Mobile 应用中的验证码'; // TODO i18n
  return '输入验证器应用中的 6 位验证码'; // TODO i18n
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

  private i18n = new LocalizeController(this);

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
        display: flex;
        flex-direction: column;
        height: 100%;
        min-height: 0;
        overflow: hidden;
      }

      /* Shared column for login / register / two-factor ------------------------------------ */
      .auth {
        flex: 1;
        min-height: 0;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 14px;
        padding: 26px 28px;
        box-sizing: border-box;
      }
      .head {
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
      .brand {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .brand-spacer {
        flex: 1;
      }
      .head-icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 28px;
        height: 28px;
        border: none;
        border-radius: var(--vw-radius-chip);
        background: transparent;
        color: var(--vw-text-2);
        cursor: pointer;
        transition: background-color var(--vw-dur-fast), color var(--vw-dur-fast);
      }
      .head-icon:hover {
        background: var(--vw-icon-hover);
      }
      .head-icon:focus-visible {
        outline: none;
        box-shadow: var(--vw-focus);
      }
      .head-icon:disabled {
        opacity: 0.5;
        cursor: default;
      }
      .head-icon svg {
        width: 16px;
        height: 16px;
      }
      .brand-name {
        font-size: 14px;
        font-weight: 600;
        letter-spacing: 0.01em;
        color: var(--vw-ink);
      }
      .title {
        margin: 0;
        font-size: 16px;
        font-weight: 600;
        color: var(--vw-ink);
      }
      .subtitle {
        margin: 0;
        font-size: 12px;
        color: var(--vw-muted);
      }

      form {
        display: flex;
        flex-direction: column;
        gap: 12px;
      }
      .field {
        display: flex;
        flex-direction: column;
        gap: 6px;
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

      .select {
        width: 100%;
        height: 36px;
        padding: 0 10px;
        border: 1px solid transparent;
        border-radius: var(--vw-radius-control);
        background: var(--vw-fill);
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        font-size: 13px;
      }
      .select:focus {
        outline: none;
        border-color: var(--vw-accent);
      }

      .remember-row {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 12.5px;
        color: var(--vw-text-2);
      }
      .remember-row input {
        accent-color: var(--vw-accent);
      }

      .link {
        align-self: center;
        border: none;
        background: none;
        padding: 2px 4px;
        color: var(--vw-teal-text);
        font-family: var(--vw-font-ui);
        font-size: 12px;
        cursor: pointer;
      }
      .link:hover {
        text-decoration: underline;
      }
      .link:disabled {
        opacity: 0.5;
        cursor: default;
        text-decoration: none;
      }

      /* Locked (unlock) screen — the primary, pixel-specced surface ------------------------- */
      .locked {
        flex: 1;
        min-height: 0;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 10px;
        padding: 24px;
        box-sizing: border-box;
        text-align: center;
        animation: mvIn 0.22s ease-out;
      }
      .locked-title {
        margin: 0;
        font-size: 15.5px;
        font-weight: 600;
        color: var(--vw-ink);
      }
      .locked-sub {
        margin: -6px 0 0;
        font-size: 12px;
        color: var(--vw-muted);
      }
      .locked-form {
        display: flex;
        flex-direction: column;
        gap: 10px;
        width: 236px;
      }
      .locked-input {
        width: 100%;
        height: 36px;
        padding: 0 12px;
        border: 1px solid transparent;
        border-radius: var(--vw-radius-control);
        background: var(--vw-fill);
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        font-size: 13px;
      }
      .locked-input::placeholder {
        color: var(--vw-placeholder);
      }
      .locked-input:focus {
        outline: none;
        border-color: var(--vw-accent);
      }
      .locked-btn {
        width: 100%;
        height: 36px;
        border: none;
        border-radius: var(--vw-radius-control);
        background: var(--vw-primary-bg);
        color: var(--vw-primary-fg);
        font-family: var(--vw-font-ui);
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        transition: background-color var(--vw-dur-fast);
      }
      .locked-btn:hover:not(:disabled) {
        background: var(--vw-primary-bg-hover);
      }
      .locked-btn:disabled {
        opacity: 0.5;
        cursor: default;
      }

      .pin-row {
        display: flex;
        gap: 8px;
        width: 236px;
        margin-top: 4px;
      }
      .pin-input {
        flex: 1;
      }
      .pin-btn {
        flex: none;
        width: 36px;
        height: 36px;
        border-radius: 50%;
        border: 1px solid var(--vw-line-3);
        background: transparent;
        color: var(--vw-teal-text);
        cursor: pointer;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        transition: background-color var(--vw-dur-fast);
      }
      .pin-btn:hover:not(:disabled) {
        background: var(--vw-teal-10);
      }
      .pin-btn:disabled {
        opacity: 0.5;
        cursor: default;
      }
      .pin-btn svg {
        width: 18px;
        height: 18px;
      }

      .locked-logout {
        margin-top: 2px;
        border: none;
        background: none;
        padding: 2px 4px;
        color: var(--vw-muted);
        font-family: var(--vw-font-ui);
        font-size: 12px;
        cursor: pointer;
      }
      .locked-logout:hover {
        color: var(--vw-danger);
      }
      .locked-logout:disabled {
        opacity: 0.5;
        cursor: default;
        color: var(--vw-muted);
      }

      .status {
        width: 236px;
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

  private renderBrandHead(title: string, subtitle: string, action: unknown = nothing) {
    return html`
      <div class="head">
        <div class="brand">
          <vw-logo variant="header"></vw-logo>
          <span class="brand-name">${t('common.brand')}</span>
          ${action !== nothing ? html`<span class="brand-spacer"></span>${action}` : nothing}
        </div>
        <h1 class="title">${title}</h1>
        ${subtitle ? html`<p class="subtitle">${subtitle}</p>` : nothing}
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
      return html`<p class="hint">此设备已不再被记住。<!-- TODO i18n --></p>`;
    }
    if (this.deviceRemembered) {
      return html`
        <button type="button" class="link" @click=${() => this.emit('vw-auth-forget-device')}>
          ${t('auth.forgetDevice')}
        </button>
      `;
    }
    return nothing;
  }

  private renderLogin() {
    const settingsGear = html`
      <button
        type="button"
        class="head-icon"
        data-open-settings
        title=${t('popup.settings')}
        aria-label=${t('popup.settings')}
        ?disabled=${this.pending}
        @click=${() => this.emit('vw-auth-open-settings')}
      >
        ${uiIcon('sliders')}
      </button>
    `;
    return html`
      <div class="auth">
        ${this.renderBrandHead(t('auth.loginTitle'), '登录到你的密钥库', settingsGear)/* TODO i18n subtitle */}
        <form @submit=${(event: Event) => { event.preventDefault(); this.submitLogin(); }}>
          <label class="field">
            <span class="field-label">${t('auth.email')}</span>
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
            <span class="field-label">${t('auth.masterPassword')}</span>
            <input id="password" class="input" type="password" autocomplete="current-password" required ?disabled=${this.pending} />
          </label>
          <button type="submit" class="btn primary full" ?disabled=${this.pending}>${t('auth.login')}</button>
          ${this.renderError()}
        </form>
        <button type="button" class="link" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-go-register')}>
          ${t('auth.goRegister')}
        </button>
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
        ${this.renderBrandHead(t('auth.registerTitle'), '在你的服务器上创建一个新密钥库')/* TODO i18n subtitle */}
        <form @submit=${(event: Event) => { event.preventDefault(); this.submitRegister(); }}>
          <label class="field">
            <span class="field-label">${t('auth.email')}</span>
            <input id="regEmail" class="input" type="email" autocomplete="username" required ?disabled=${this.pending} />
          </label>
          <label class="field">
            <span class="field-label">${t('auth.name')}（可选）<!-- TODO i18n optional marker --></span>
            <input id="regName" class="input" type="text" autocomplete="name" ?disabled=${this.pending} />
          </label>
          <label class="field">
            <span class="field-label">${t('auth.masterPassword')}</span>
            <input id="regPassword" class="input" type="password" autocomplete="new-password" required ?disabled=${this.pending} />
          </label>
          <label class="field">
            <span class="field-label">确认主密码<!-- TODO i18n --></span>
            <input id="regConfirm" class="input" type="password" autocomplete="new-password" required ?disabled=${this.pending} />
          </label>
          <p class="hint">主密码无法找回，且永不离开此设备。<!-- TODO i18n --></p>
          <button type="submit" class="btn primary full" ?disabled=${this.pending}>${t('auth.createAccount')}</button>
          ${this.renderError()}
        </form>
        <button type="button" class="link" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-back-to-login')}>
          ${t('auth.goLogin')}
        </button>
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
      const names = this.providers.map((provider) => TWO_FACTOR_NAMES[provider] ?? `方式 ${provider}`).join('、');
      return html`
        <div class="auth">
          ${this.renderBrandHead(t('auth.twoFactorTitle'), '此验证方式暂不支持')/* TODO i18n subtitle */}
          <vw-status-message
            tone="danger"
            .icon=${'alert'}
            message=${`你的账户需要：${names || '暂不支持的验证方式'}。请使用支持该方式的 Bitwarden 客户端，或改用验证器/邮箱验证。`/* TODO i18n */}
          ></vw-status-message>
          <button type="button" class="btn outline full" @click=${() => this.emit('vw-auth-back-to-login')}>
            ${t('common.back')}
          </button>
          ${this.renderError()}
        </div>
      `;
    }
    const selected = this.selectedProvider ?? usable[0]!;
    return html`
      <div class="auth">
        ${this.renderBrandHead(t('auth.twoFactorTitle'), '输入验证码以继续登录')/* TODO i18n subtitle */}
        <form @submit=${(event: Event) => { event.preventDefault(); this.submitTwoFactor(); }}>
          <label class="field">
            <span class="field-label">验证方式<!-- TODO i18n --></span>
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
                <option value=${provider} ?selected=${provider === selected}>${TWO_FACTOR_NAMES[provider] ?? `方式 ${provider}`}</option>
              `)}
            </select>
          </label>
          <label class="field">
            <span class="field-label">${t('auth.twoFactorCode')}</span>
            <input id="code" class="input mono" autocomplete="one-time-code" required ?disabled=${this.pending} />
            <span class="hint">${twoFactorHint(selected)}</span>
          </label>
          <label class="remember-row">
            <input id="tfRemember" type="checkbox" ?disabled=${this.pending} />
            <span>${t('auth.rememberDevice')}</span>
          </label>
          <button type="submit" class="btn primary full" ?disabled=${this.pending}>继续<!-- TODO i18n --></button>
          ${usable.includes(1)
            ? html`
                <button type="button" class="btn outline full" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-send-email-code')}>
                  ${t('auth.sendEmailCode')}
                </button>
              `
            : nothing}
          ${this.renderError()}
        </form>
        <button type="button" class="link" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-back-to-login')}>
          ${t('common.back')}
        </button>
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
      <div class="pin-row">
        <input
          id="pinUnlockInput"
          class="locked-input pin-input"
          inputmode="numeric"
          autocomplete="off"
          placeholder=${t('auth.pin')}
          ?disabled=${this.pending}
          @keydown=${(event: KeyboardEvent) => {
            if (event.key === 'Enter') {
              event.preventDefault();
              this.submitPinUnlock();
            }
          }}
        />
        <button
          type="button"
          class="pin-btn"
          aria-label=${t('auth.usePin')}
          title=${t('auth.usePin')}
          ?disabled=${this.pending}
          @click=${() => this.submitPinUnlock()}
        >
          ${uiIcon('fingerprint')}
        </button>
      </div>
    `;
  }

  private renderUnlock() {
    return html`
      <div class="locked">
        <vw-logo variant="hero"></vw-logo>
        <h1 class="locked-title">${t('auth.lockedTitle')}</h1>
        <p class="locked-sub">${t('auth.unlockSubtitle')}</p>
        <form
          class="locked-form"
          @submit=${(event: Event) => {
            event.preventDefault();
            this.emit('vw-auth-unlock-submit', { masterPassword: this.inputValue('unlockPassword') } satisfies UnlockSubmitDetail);
          }}
        >
          <input
            id="unlockPassword"
            class="locked-input"
            type="password"
            autocomplete="current-password"
            placeholder=${t('auth.masterPassword')}
            required
            ?disabled=${this.pending}
          />
          <button type="submit" class="locked-btn" ?disabled=${this.pending}>${t('auth.unlock')}</button>
        </form>
        ${this.pinEnabled ? this.renderPinUnlock() : nothing}
        ${this.error ? html`<div class="status">${this.renderError()}</div>` : nothing}
        <button type="button" class="locked-logout" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-logout')}>
          ${t('auth.logout')}
        </button>
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
