import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import {
  MAX_PIN_UTF16_CODE_UNITS,
  isValidPinInput,
} from '../../../core/session/pin-constraints.js';
import type { Fido2TwoFactorChallenge } from '../../../core/session/auth-service.js';
import type {
  PasswordHintEmailDetail,
  PasswordHintStatus,
} from './password-hint-view.js';
import { authIdentityStyles, renderAuthIdentity, type AuthIdentityDisplay } from './auth-identity.js';
import {
  DEFAULT_MASTER_PASSWORD_MIN_LENGTH,
  MASTER_PASSWORD_HINT_MAX_LENGTH,
  newMasterPasswordMinimumLength,
  type PasswordChangeRequirement,
} from '../../../core/policy/master-password-policy.js';
import '../../components/logo.js';
import '../../components/status-message.js';
import './password-hint-view.js';

export type AuthViewMode =
  | 'login'
  | 'passwordHint'
  | 'register'
  | 'registrationFinish'
  | 'registrationCheckEmail'
  | 'newDeviceVerification'
  | 'twoFactor'
  | 'sso'
  | 'accountPasskey'
  | 'restricted'
  | 'unlock';

export type AccountPasskeyViewStatus =
  | 'waiting'
  | 'outcome_unknown'
  | 'unavailable'
  | 'cancelled'
  | 'expired'
  | 'failed'
  | 'two_factor_unsupported';

export interface LoginSubmitDetail {
  email: string;
  masterPassword: string;
}

export interface DeviceLoginStartDetail {
  readonly email: string;
}

export interface SsoLoginStartDetail {
  readonly email: string;
  readonly organizationIdentifier?: string;
}

export type SsoViewStatus = 'waiting' | 'processing' | 'outcome_unknown' | 'error';

export interface RegisterSubmitDetail {
  email: string;
  name?: string;
}

export interface RegisterFinishSubmitDetail {
  masterPassword: string;
  confirm: string;
  masterPasswordHint: string;
}

export interface TwoFactorSubmitDetail {
  provider: number;
  code: string;
  remember: boolean;
}

export interface TwoFactorProviderChangeDetail {
  readonly provider: number;
  readonly attemptKey: string;
}

export interface EmailTwoFactorCodeRequestDetail {
  readonly provider: 1;
  readonly attemptKey: string;
  readonly automatic: boolean;
}

export interface NewDeviceVerificationSubmitDetail {
  readonly code: string;
}

export interface Fido2TwoFactorStartDetail {
  readonly owner: Fido2TwoFactorChallenge['owner'];
}

export interface DuoTwoFactorStartDetail {
  readonly provider: 2 | 6;
  readonly remember: boolean;
}

export interface UnlockSubmitDetail {
  masterPassword: string;
}

export interface PinUnlockSubmitDetail {
  pin: string;
}

export interface ForcedPasswordChangeSubmitDetail {
  readonly currentPassword: string;
  readonly newPassword: string;
}

export interface EmailChangeDetail {
  email: string;
}

/** Providers whose token is a code/OTP string the user can type directly. */
const CODE_BASED_PROVIDERS = [0, 1, 3];

/** Official Bitwarden preference order, expressed as unique priorities. */
const TWO_FACTOR_PRIORITIES: Readonly<Record<number, number>> = Object.freeze({
  0: 1,
  1: 0,
  2: 2,
  3: 3,
  6: 10,
  7: 4,
});

export function usableTwoFactorProviders(
  providers: readonly number[],
  fido2Available: boolean,
): number[] {
  return providers.filter((provider) => CODE_BASED_PROVIDERS.includes(provider)
    || provider === 2 || provider === 6
    || (provider === 7 && fido2Available));
}

export function preferredTwoFactorProvider(providers: readonly number[]): number | undefined {
  let selected: number | undefined;
  let priority = Number.NEGATIVE_INFINITY;
  for (const provider of providers) {
    const candidate = TWO_FACTOR_PRIORITIES[provider];
    if (candidate !== undefined && candidate > priority) {
      selected = provider;
      priority = candidate;
    }
  }
  return selected;
}

function twoFactorName(provider: number): string {
  switch (provider) {
    case 0: return t('auth.twoFactor.provider.authenticator');
    case 1: return t('auth.twoFactor.provider.email');
    case 2: return t('auth.twoFactor.provider.duo');
    case 3: return t('auth.twoFactor.provider.yubikey');
    case 6: return t('auth.twoFactor.provider.organizationDuo');
    case 7: return t('auth.twoFactor.provider.fido2');
    default: return t('auth.twoFactor.provider.unknown', { provider });
  }
}

/** Per-provider input guidance for code-based methods. */
function twoFactorHint(provider: number): string {
  if (provider === 1) return t('auth.twoFactor.hint.email');
  if (provider === 3) return t('auth.twoFactor.hint.yubikey');
  return t('auth.twoFactor.hint.authenticator');
}

/**
 * Renders authentication screens from props only. It never
 * calls `sendRequest` or otherwise touches the worker — `VwPopupApp` owns every request and
 * transition and reacts to the typed submit/action events this component dispatches.
 */
export class VwAuthViews extends LitElement {
  static override properties = {
    mode: { type: String },
    error: { type: String },
    notice: { type: String },
    pending: { type: Boolean },
    providers: { attribute: false },
    selectedProvider: { attribute: false },
    twoFactorAttemptKey: { type: String },
    fido2: { attribute: false },
    pinEnabled: { type: Boolean },
    deviceRemembered: { type: Boolean },
    deviceForgotten: { type: Boolean },
    accountPasskeyStatus: { type: String },
    ssoStatus: { type: String },
    ssoRequired: { type: Boolean },
    newDeviceVerificationExpiresAt: { type: Number },
    passwordChangeRequirement: { attribute: false },
    registrationEmail: { type: String },
    passwordHintEmail: { attribute: false },
    passwordHintStatus: { attribute: false },
    passwordHintMessage: { attribute: false },
    identity: { attribute: false },
  };

  declare mode: AuthViewMode;
  declare error: string | undefined;
  declare notice: string | undefined;
  declare pending: boolean;
  declare providers: number[];
  declare selectedProvider: number | undefined;
  declare twoFactorAttemptKey: string;
  declare fido2: Fido2TwoFactorChallenge | undefined;
  declare pinEnabled: boolean;
  declare deviceRemembered: boolean;
  declare deviceForgotten: boolean;
  declare accountPasskeyStatus: AccountPasskeyViewStatus | undefined;
  declare ssoStatus: SsoViewStatus | undefined;
  declare ssoRequired: boolean;
  declare newDeviceVerificationExpiresAt: number | undefined;
  declare passwordChangeRequirement: PasswordChangeRequirement | undefined;
  declare registrationEmail: string | undefined;
  declare passwordHintEmail: string;
  declare passwordHintStatus: PasswordHintStatus | undefined;
  declare passwordHintMessage: string | undefined;
  declare identity: AuthIdentityDisplay | undefined;

  private i18n = new LocalizeController(this);

  private rememberSelection = false;
  private selectionAttemptKey = '';
  private lastAutomaticEmailAttemptKey = '';

  constructor() {
    super();
    this.mode = 'login';
    this.error = undefined;
    this.notice = undefined;
    this.pending = false;
    this.providers = [];
    this.selectedProvider = undefined;
    this.twoFactorAttemptKey = '';
    this.fido2 = undefined;
    this.pinEnabled = false;
    this.deviceRemembered = false;
    this.deviceForgotten = false;
    this.accountPasskeyStatus = undefined;
    this.ssoStatus = undefined;
    this.ssoRequired = false;
    this.newDeviceVerificationExpiresAt = undefined;
    this.passwordChangeRequirement = undefined;
    this.registrationEmail = undefined;
    this.passwordHintEmail = '';
    this.passwordHintStatus = undefined;
    this.passwordHintMessage = undefined;
    this.identity = undefined;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    authIdentityStyles,
    css`
      :host {
        display: flex;
        flex-direction: column;
        height: 100%;
        min-height: 0;
        overflow: hidden;
        background: var(--vw-panel);
      }

      /* Shared column for login / register / two-factor ------------------------------------ */
      .auth {
        flex: 1;
        min-height: 0;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 20px;
        padding: 24px 28px;
        overflow-x: hidden;
        box-sizing: border-box;
        animation: auth-enter 160ms ease-out;
      }
      .head {
        display: flex;
        flex-direction: column;
        gap: 8px;
      }
      .brand {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 16px;
      }
      .brand-spacer {
        flex: 1;
      }
      .head-icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 32px;
        height: 32px;
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
        font-size: 22px;
        font-weight: 600;
        line-height: 1.35;
        letter-spacing: -0.025em;
        color: var(--vw-ink);
      }
      .subtitle {
        margin: 0;
        font-size: 13px;
        line-height: 1.55;
        color: var(--vw-muted);
      }

      form {
        display: flex;
        flex-direction: column;
        gap: 16px;
        min-width: 0;
      }
      .field {
        display: flex;
        flex-direction: column;
        gap: 7px;
        min-width: 0;
      }
      .field-label {
        font-size: 12px;
        font-weight: 500;
        color: var(--vw-text-2);
      }
      .hint {
        margin: 0;
        font-size: 12px;
        line-height: 1.55;
        color: var(--vw-muted);
      }
      .full {
        width: 100%;
      }

      .select {
        width: 100%;
        height: 40px;
        padding: 0 12px;
        border: 1px solid var(--vw-line-3);
        border-radius: var(--vw-radius-control);
        background: var(--vw-panel);
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        font-size: 13px;
      }
      .select:focus {
        outline: none;
        border-color: var(--vw-accent);
        box-shadow: var(--vw-focus);
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
        padding: 6px 4px;
        color: var(--vw-teal-text);
        font-family: var(--vw-font-ui);
        font-size: 12px;
        cursor: pointer;
      }
      .link:hover {
        text-decoration: underline;
      }
      .link:focus-visible, .locked-logout:focus-visible, .pin-btn:focus-visible {
        outline: none;
        border-radius: var(--vw-radius-control);
        box-shadow: var(--vw-focus);
      }
      .link:disabled {
        opacity: 0.5;
        cursor: default;
        text-decoration: none;
      }
      .alternate-methods {
        border-top: 1px solid var(--vw-line-1);
        padding-top: 14px;
      }
      .alternate-methods summary {
        display: flex;
        align-items: center;
        justify-content: space-between;
        min-height: 32px;
        color: var(--vw-text-2);
        font-size: 12px;
        font-weight: 500;
        cursor: pointer;
        list-style: none;
      }
      .alternate-methods summary::-webkit-details-marker { display: none; }
      .alternate-methods summary::after { content: '+'; font-size: 18px; font-weight: 400; }
      .alternate-methods[open] summary::after { content: '−'; }
      .alternate-methods summary:focus-visible {
        outline: none;
        border-radius: var(--vw-radius-control);
        box-shadow: var(--vw-focus);
      }
      .alternate-actions { display: grid; gap: 8px; padding-top: 10px; }

      /* The locked view shows identity context without suggesting that secret data is loaded. */
      .locked {
        flex: 1;
        min-height: 0;
        overflow-y: auto;
        overflow-x: hidden;
        background: var(--vw-panel);
      }
      .locked-inner {
        min-height: 100%;
        display: flex;
        flex-direction: column;
        align-items: stretch;
        justify-content: safe center;
        gap: 20px;
        padding: 32px 28px;
        box-sizing: border-box;
        animation: auth-enter 160ms ease-out;
      }
      .locked-head {
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        gap: 10px;
      }
      .locked-head vw-logo { margin-bottom: 8px; }
      .locked .auth-identity { width: 100%; box-sizing: border-box; }
      .locked-title {
        margin: 0;
        font-size: 24px;
        font-weight: 600;
        line-height: 1.3;
        letter-spacing: -0.025em;
        color: var(--vw-ink);
      }
      .locked-sub {
        margin: 0;
        font-size: 13px;
        line-height: 1.6;
        color: var(--vw-muted);
      }
      .locked-form {
        display: flex;
        flex-direction: column;
        gap: 14px;
        width: 100%;
      }
      .locked-input {
        width: 100%;
        min-width: 0;
        height: 42px;
        padding: 0 12px;
        box-sizing: border-box;
        border: 1px solid var(--vw-line-3);
        border-radius: var(--vw-radius-control);
        background: var(--vw-panel);
        color: var(--vw-ink);
        font: 400 13px/1 var(--vw-font-ui);
      }
      .locked-input::placeholder {
        color: var(--vw-placeholder);
      }
      .locked-input:focus {
        outline: none;
        border-color: var(--vw-accent);
        box-shadow: var(--vw-focus);
      }
      .locked-btn {
        width: 100%;
        min-height: 42px;
      }
      .pin-row {
        display: flex;
        align-items: flex-end;
        gap: 8px;
        width: 100%;
        padding-top: 18px;
        border-top: 1px solid var(--vw-line-1);
      }
      .pin-row .field {
        flex: 1;
      }
      .pin-input {
        flex: 1;
      }
      .pin-btn {
        flex: none;
        min-height: 42px;
      }

      .locked-logout {
        align-self: center;
        margin-top: 0;
        border: none;
        background: none;
        padding: 6px 4px;
        color:var(--vw-text-2);
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
        width: 100%;
        min-width: 0;
      }
      @keyframes auth-enter {
        from { opacity: 0; transform: translateY(4px); }
        to { opacity: 1; transform: translateY(0); }
      }
      @media (prefers-reduced-motion: reduce) {
        .auth, .locked-inner { animation: none; }
        .head-icon { transition: none; }
      }
      @media (max-width: 340px) {
        .auth, .locked-inner { padding-right: 18px; padding-left: 18px; }
        .pin-row { flex-direction: column; align-items: stretch; }
      }
    `,
  ];

  protected override willUpdate(changed: PropertyValues<this>): void {
    const attemptChanged = this.mode === 'twoFactor'
      && this.twoFactorAttemptKey !== this.selectionAttemptKey;
    if (attemptChanged) {
      this.selectionAttemptKey = this.twoFactorAttemptKey;
      this.rememberSelection = false;
    }
    if (changed.has('providers') || changed.has('mode') || changed.has('fido2')
        || changed.has('selectedProvider') || attemptChanged) {
      const usable = this.usableProviders;
      if (this.selectedProvider === undefined || !usable.includes(this.selectedProvider)) {
        this.selectedProvider = preferredTwoFactorProvider(usable);
      }
    }
  }

  protected override updated(): void {
    const providerSelect = this.shadowRoot?.getElementById('provider');
    if (providerSelect instanceof HTMLSelectElement && this.selectedProvider !== undefined) {
      providerSelect.value = String(this.selectedProvider);
    }
    if (this.mode !== 'twoFactor' || this.pending || this.selectedProvider !== 1
        || !this.twoFactorAttemptKey
        || this.lastAutomaticEmailAttemptKey === this.twoFactorAttemptKey) return;
    this.lastAutomaticEmailAttemptKey = this.twoFactorAttemptKey;
    this.requestEmailCode(true);
  }

  private get usableProviders(): number[] {
    return usableTwoFactorProviders(this.providers, this.fido2 !== undefined);
  }

  private inputValue(id: string): string {
    const el = this.shadowRoot?.getElementById(id);
    return el instanceof HTMLInputElement ? el.value : '';
  }

  private emit(type: string, detail: unknown = null): void {
    emit(this, type, detail);
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
      ${renderAuthIdentity(this.identity)}
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

  private startDeviceLogin(): void {
    if (this.pending) return;
    const emailInput = this.shadowRoot?.getElementById('email');
    if (!(emailInput instanceof HTMLInputElement)) return;
    const email = emailInput.value.trim();
    emailInput.value = email;
    if (!emailInput.reportValidity()) return;
    this.emit('vw-auth-device-login-start', { email } satisfies DeviceLoginStartDetail);
  }

  private startSsoLogin(): void {
    if (this.pending) return;
    const emailInput = this.shadowRoot?.getElementById('email');
    if (!(emailInput instanceof HTMLInputElement)) return;
    const email = emailInput.value.trim();
    emailInput.value = email;
    if (!emailInput.reportValidity()) return;
    this.emit('vw-auth-sso-start', { email } satisfies SsoLoginStartDetail);
  }

  private renderRememberForgetSlot() {
    if (this.deviceForgotten) {
      return html`<p class="hint">${t('auth.deviceForgotten')}</p>`;
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
        ${this.renderBrandHead(t('auth.loginTitle'), t('auth.loginSubtitle'), settingsGear)}
        <form @submit=${(event: Event) => {
          event.preventDefault();
          if (this.ssoRequired) this.startSsoLogin();
          else this.submitLogin();
        }}>
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
          ${this.ssoRequired
            ? html`<vw-status-message
                tone="info"
                .icon=${'shield'}
                .message=${t('auth.sso.required')}
              ></vw-status-message>`
            : html`
                <label class="field">
                  <span class="field-label">${t('auth.masterPassword')}</span>
                  <input id="password" class="input" type="password" autocomplete="current-password" required ?disabled=${this.pending} />
                </label>
                <button type="submit" class="btn primary full" ?disabled=${this.pending}>${t('auth.login')}</button>
              `}
          ${this.ssoRequired ? html`
            <button
              type="button"
              class="btn primary full"
              data-sso-login
              ?disabled=${this.pending}
              @click=${() => this.startSsoLogin()}
            >${uiIcon('globe')}<span>${t('auth.sso.start')}</span></button>
          ` : html`
            <details class="alternate-methods">
              <summary>${t('auth.otherLoginMethods')}</summary>
              <div class="alternate-actions">
                <button
                  type="button"
                  class="btn outline full"
                  data-account-passkey
                  ?disabled=${this.pending}
                  @click=${() => this.emit('vw-auth-account-passkey-start')}
                >${uiIcon('passkey')}<span>${t('auth.accountPasskey.start')}</span></button>
                <button
                  type="button"
                  class="btn outline full"
                  data-sso-login
                  ?disabled=${this.pending}
                  @click=${() => this.startSsoLogin()}
                >${uiIcon('globe')}<span>${t('auth.sso.start')}</span></button>
                <button
                  type="button"
                  class="btn outline full"
                  data-device-login
                  ?disabled=${this.pending}
                  @click=${() => this.startDeviceLogin()}
                >${uiIcon('idcard')}<span>${t('auth.deviceLogin.start')}</span></button>
              </div>
            </details>
          `}
          ${this.renderError()}
        </form>
        ${this.notice
          ? html`<vw-status-message tone="success" .icon=${'check'} .message=${this.notice}></vw-status-message>`
          : nothing}
        <button
          type="button"
          class="link"
          data-password-hint
          ?disabled=${this.pending}
          @click=${() => this.emit('vw-auth-password-hint-start', {
            email: this.inputValue('email'),
          } satisfies PasswordHintEmailDetail)}
        >${t('auth.passwordHint.title')}</button>
        ${this.ssoRequired ? nothing : html`
          <button type="button" class="link" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-go-register')}>
            ${t('auth.goRegister')}
          </button>
          ${this.renderRememberForgetSlot()}
        `}
      </div>
    `;
  }

  private submitRegister(): void {
    const email = this.inputValue('regEmail').trim();
    const name = this.inputValue('regName').trim();
    const detail: RegisterSubmitDetail = name ? { email, name } : { email };
    this.emit('vw-auth-register-submit', detail);
  }

  private renderRegister() {
    return html`
      <div class="auth">
        ${this.renderBrandHead(t('auth.registerTitle'), t('auth.registrationStartSubtitle'))}
        <form @submit=${(event: Event) => { event.preventDefault(); this.submitRegister(); }}>
          <label class="field">
            <span class="field-label">${t('auth.email')}</span>
            <input id="regEmail" class="input" type="email" autocomplete="username" required ?disabled=${this.pending} />
          </label>
          <label class="field">
            <span class="field-label">${t('auth.name')} ${t('auth.optional')}</span>
            <input id="regName" class="input" type="text" autocomplete="name" ?disabled=${this.pending} />
          </label>
          <button type="submit" class="btn primary full" ?disabled=${this.pending}>${t('auth.continue')}</button>
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

  private startDuo(provider: 2 | 6): void {
    const remember = this.shadowRoot?.getElementById('tfRemember');
    this.emit('vw-auth-duo-start', {
      provider,
      remember: remember instanceof HTMLInputElement && remember.checked,
    } satisfies DuoTwoFactorStartDetail);
  }

  private selectTwoFactorProvider(event: Event): void {
    const provider = Number((event.target as HTMLSelectElement).value);
    if (!this.usableProviders.includes(provider)) return;
    if (provider === this.selectedProvider) return;
    this.selectedProvider = provider;
    this.emit('vw-auth-two-factor-provider-change', {
      provider,
      attemptKey: this.twoFactorAttemptKey,
    } satisfies TwoFactorProviderChangeDetail);
  }

  private requestEmailCode(automatic: boolean): void {
    if (this.pending || this.selectedProvider !== 1 || !this.twoFactorAttemptKey) return;
    this.emit('vw-auth-send-email-code', {
      provider: 1,
      attemptKey: this.twoFactorAttemptKey,
      automatic,
    } satisfies EmailTwoFactorCodeRequestDetail);
  }

  private renderFido2Connector() {
    const challenge = this.fido2;
    if (!challenge) {
      return html`<vw-status-message tone="danger" .icon=${'alert'} .message=${t('auth.fido2.invalidConnector')}></vw-status-message>`;
    }
    if (this.pending) {
      return html`<vw-status-message tone="info" .icon=${'refresh'} .message=${t('auth.fido2.verifying')}></vw-status-message>`;
    }
    return html`
      <button
        type="button"
        class="btn primary full"
        data-fido2-start
        @click=${() => this.emit('vw-auth-fido2-start', {
          owner: challenge.owner,
        } satisfies Fido2TwoFactorStartDetail)}
      >${uiIcon('key')}<span>${t('auth.fido2.read')}</span></button>
    `;
  }

  private renderTwoFactorRecovery() {
    return html`
      <button
        type="button"
        class="btn outline full"
        data-two-factor-recovery
        ?disabled=${this.pending}
        @click=${() => this.emit('vw-auth-two-factor-recovery')}
      >${t('auth.twoFactorRecovery')}</button>
    `;
  }

  private submitRegistrationFinish(): void {
    this.emit('vw-auth-register-finish-submit', {
      masterPassword: this.inputValue('regPassword'),
      confirm: this.inputValue('regConfirm'),
      masterPasswordHint: this.inputValue('regPasswordHint'),
    } satisfies RegisterFinishSubmitDetail);
  }

  private renderRegistrationFinish() {
    return html`
      <div class="auth">
        ${this.renderBrandHead(t('auth.registrationFinishTitle'), t('auth.registrationFinishSubtitle'))}
        <p class="hint">${this.registrationEmail ?? ''}</p>
        <form @submit=${(event: Event) => {
          event.preventDefault();
          this.submitRegistrationFinish();
        }}>
          <label class="field">
            <span class="field-label">${t('auth.masterPassword')}</span>
            <input id="regPassword" class="input" type="password" autocomplete="new-password" minlength=${DEFAULT_MASTER_PASSWORD_MIN_LENGTH} maxlength="1024" required ?disabled=${this.pending} />
          </label>
          <label class="field">
            <span class="field-label">${t('auth.confirmMasterPassword')}</span>
            <input id="regConfirm" class="input" type="password" autocomplete="new-password" minlength=${DEFAULT_MASTER_PASSWORD_MIN_LENGTH} maxlength="1024" required ?disabled=${this.pending} />
          </label>
          <label class="field">
            <span class="field-label">${t('security.masterPasswordHint')}</span>
            <input id="regPasswordHint" class="input" type="text" autocomplete="off" maxlength=${MASTER_PASSWORD_HINT_MAX_LENGTH} ?disabled=${this.pending} />
          </label>
          <p class="hint">${t('auth.masterPasswordWarning')}</p>
          <button type="submit" class="btn primary full" ?disabled=${this.pending}>${t('auth.createAccount')}</button>
          ${this.renderError()}
        </form>
        <button type="button" class="link" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-registration-cancel')}>
          ${t('auth.startOver')}
        </button>
      </div>
    `;
  }

  private renderRegistrationCheckEmail() {
    return html`
      <div class="auth">
        ${this.renderBrandHead(t('auth.registrationCheckEmailTitle'), t('auth.registrationCheckEmailSubtitle'))}
        <p class="hint">${this.registrationEmail ?? ''}</p>
        <button type="button" class="link" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-registration-cancel')}>
          ${t('auth.startOver')}
        </button>
        <button type="button" class="link" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-back-to-login')}>
          ${t('auth.goLogin')}
        </button>
      </div>
    `;
  }

  private accountPasskeyMessage(status: AccountPasskeyViewStatus): string {
    switch (status) {
      case 'waiting': return t('auth.accountPasskey.waiting');
      case 'outcome_unknown': return t('auth.accountPasskey.outcomeUnknown');
      case 'unavailable': return t('auth.accountPasskey.unavailable');
      case 'cancelled': return t('auth.accountPasskey.cancelled');
      case 'expired': return t('auth.accountPasskey.expired');
      case 'failed': return t('auth.accountPasskey.failed');
      case 'two_factor_unsupported': return t('auth.accountPasskey.twoFactorUnsupported');
    }
  }

  private renderAccountPasskey() {
    const status = this.accountPasskeyStatus ?? 'failed';
    const active = status === 'waiting' || status === 'outcome_unknown';
    return html`
      <div class="auth">
        ${this.renderBrandHead(t('auth.accountPasskey.title'), '')}
        <vw-status-message
          tone=${active ? 'info' : 'danger'}
          .icon=${status === 'waiting' ? 'passkey' : 'alert'}
          .message=${this.accountPasskeyMessage(status)}
        ></vw-status-message>
        ${status === 'waiting'
          ? html`<button
              type="button"
              class="btn outline full"
              ?disabled=${this.pending}
              @click=${() => this.emit('vw-auth-account-passkey-cancel')}
            >${t('common.cancel')}</button>`
          : status === 'outcome_unknown'
              ? html`<button
                  type="button"
                  class="btn primary full"
                  data-account-passkey-check
                  ?disabled=${this.pending}
                  @click=${() => this.emit('vw-auth-account-passkey-check')}
              >${t('auth.accountPasskey.checkState')}</button>`
            : nothing}
        <button
          type="button"
          class="link"
          ?disabled=${this.pending}
          @click=${() => this.emit('vw-auth-account-passkey-back')}
        >${t('auth.accountPasskey.back')}</button>
      </div>
    `;
  }

  private renderSso() {
    const status = this.ssoStatus ?? 'error';
    const message = status === 'waiting'
      ? t('auth.sso.waiting')
      : status === 'processing'
        ? t('auth.sso.processing')
        : status === 'outcome_unknown'
          ? t('auth.sso.outcomeUnknown')
          : this.error ?? t('auth.sso.failed');
    return html`
      <div class="auth">
        ${this.renderBrandHead(t('auth.sso.title'), '')}
        <vw-status-message
          tone=${status === 'error' || status === 'outcome_unknown' ? 'danger' : 'info'}
          .icon=${status === 'error' || status === 'outcome_unknown' ? 'alert' : 'globe'}
          .message=${message}
        ></vw-status-message>
        ${status === 'waiting'
          ? html`<button
              type="button"
              class="btn outline full"
              ?disabled=${this.pending}
              @click=${() => this.emit('vw-auth-sso-cancel')}
            >${t('common.cancel')}</button>`
          : nothing}
        <button
          type="button"
          class="link"
          ?disabled=${this.pending}
          @click=${() => this.emit('vw-auth-back-to-login')}
        >${t('auth.accountPasskey.back')}</button>
      </div>
    `;
  }

  private renderNewDeviceVerification() {
    const expiresAt = this.newDeviceVerificationExpiresAt;
    const expired = !Number.isSafeInteger(expiresAt) || expiresAt! <= Date.now();
    const remainingMinutes = expired ? 0 : Math.max(1, Math.ceil((expiresAt! - Date.now()) / 60_000));
    return html`
      <div class="auth">
        ${this.renderBrandHead(t('auth.newDeviceVerification.title'), '')}
        <vw-status-message
          tone=${expired ? 'danger' : 'info'}
          .icon=${expired ? 'alert' : 'mail'}
          .message=${expired
            ? t('auth.newDeviceVerification.expired')
            : t('auth.newDeviceVerification.description', { minutes: remainingMinutes })}
        ></vw-status-message>
        ${expired
          ? nothing
          : html`
              <form @submit=${(event: Event) => {
                event.preventDefault();
                this.emit('vw-auth-new-device-verification-submit', {
                  code: this.inputValue('newDeviceVerificationCode'),
                } satisfies NewDeviceVerificationSubmitDetail);
              }}>
                <label class="field">
                  <span class="field-label">${t('auth.twoFactorCode')}</span>
                  <input
                    id="newDeviceVerificationCode"
                    class="input mono"
                    autocomplete="one-time-code"
                    maxlength="256"
                    required
                    ?disabled=${this.pending}
                  />
                </label>
                <button type="submit" class="btn primary full" ?disabled=${this.pending}>
                  ${t('auth.newDeviceVerification.continue')}
                </button>
                <button
                  type="button"
                  class="btn outline full"
                  ?disabled=${this.pending}
                  @click=${() => this.emit('vw-auth-new-device-verification-send-otp')}
                >${t('auth.newDeviceVerification.sendCode')}</button>
              </form>
            `}
        ${this.notice
          ? html`<vw-status-message tone="success" .icon=${'check'} .message=${this.notice}></vw-status-message>`
          : nothing}
        ${this.renderError()}
        <button
          type="button"
          class="link"
          ?disabled=${this.pending}
          @click=${() => this.emit('vw-auth-new-device-verification-cancel')}
        >${expired ? t('common.back') : t('common.cancel')}</button>
      </div>
    `;
  }

  private renderTwoFactor() {
    const usable = this.usableProviders;
    if (usable.length === 0) {
      const names = this.providers.map(twoFactorName).join(', ');
      return html`
        <div class="auth">
          ${this.renderBrandHead(t('auth.twoFactorTitle'), t('auth.twoFactor.unsupportedSubtitle'))}
          <vw-status-message
            tone="danger"
            .icon=${'alert'}
            .message=${t('auth.twoFactor.unsupported', {
              providers: names || t('auth.twoFactor.provider.unsupported'),
            })}
          ></vw-status-message>
          ${this.renderTwoFactorRecovery()}
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
        ${this.renderBrandHead(
          t('auth.twoFactorTitle'),
          selected === 7 ? t('auth.fido2.subtitle') : t('auth.twoFactor.enterCodeSubtitle'),
        )}
        <label class="field">
          <span class="field-label">${t('auth.twoFactor.method')}</span>
          <select id="provider" class="select" .value=${String(selected)} ?disabled=${this.pending} @change=${this.selectTwoFactorProvider}>
            ${usable.map((provider) => html`
              <option value=${provider}>${twoFactorName(provider)}</option>
            `)}
          </select>
        </label>
        ${selected === 7
          ? nothing
          : html`
              <label class="remember-row">
                <input
                  id="tfRemember"
                  type="checkbox"
                  .checked=${this.rememberSelection}
                  ?disabled=${this.pending}
                  @change=${(event: Event) => { this.rememberSelection = (event.target as HTMLInputElement).checked; }}
                />
                <span>${t('auth.rememberDevice')}</span>
              </label>
            `}
        ${selected === 7
          ? this.renderFido2Connector()
          : selected === 2 || selected === 6
            ? html`
                <button
                  type="button"
                  class="btn primary full"
                  data-duo-start
                  ?disabled=${this.pending}
                  @click=${() => this.startDuo(selected)}
                >${t('auth.twoFactor.continueDuo')}</button>
              `
          : html`
              <form @submit=${(event: Event) => { event.preventDefault(); this.submitTwoFactor(); }}>
                <label class="field">
                  <span class="field-label">${t('auth.twoFactorCode')}</span>
                  <input id="code" class="input mono" autocomplete="one-time-code" required ?disabled=${this.pending} />
                  <span class="hint">${twoFactorHint(selected)}</span>
                </label>
                <button type="submit" class="btn primary full" ?disabled=${this.pending}>${t('auth.twoFactor.continue')}</button>
                ${selected === 1
                  ? html`
                      <button type="button" class="btn outline full" ?disabled=${this.pending} @click=${() => this.requestEmailCode(false)}>
                        ${t('auth.twoFactor.resendEmailCode')}
                      </button>
                    `
                  : nothing}
              </form>
            `}
        ${this.renderTwoFactorRecovery()}
        ${this.notice
          ? html`<vw-status-message tone="success" .icon=${'check'} .message=${this.notice}></vw-status-message>`
          : nothing}
        ${this.renderError()}
        <button type="button" class="link" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-back-to-login')}>
          ${t('common.back')}
        </button>
      </div>
    `;
  }

  private submitPinUnlock(): void {
    const pin = this.inputValue('pinUnlockInput');
    if (!isValidPinInput(pin)) return;
    this.emit('vw-auth-pin-unlock-submit', { pin } satisfies PinUnlockSubmitDetail);
  }

  private renderPinUnlock() {
    return html`
      <div class="pin-row">
        <label class="field" for="pinUnlockInput">
          <span class="field-label">${t('auth.pin')}</span>
          <input
            id="pinUnlockInput"
            class="locked-input pin-input"
            type="password"
            autocomplete="off"
            maxlength=${MAX_PIN_UTF16_CODE_UNITS}
            ?disabled=${this.pending}
            @keydown=${(event: KeyboardEvent) => {
              if (event.key === 'Enter') {
                event.preventDefault();
                this.submitPinUnlock();
              }
            }}
          />
        </label>
        <button
          type="button"
          class="btn outline pin-btn"
          aria-label=${t('auth.usePin')}
          title=${t('auth.usePin')}
          ?disabled=${this.pending}
          @click=${() => this.submitPinUnlock()}
        >
          ${t('auth.usePin')}
        </button>
      </div>
    `;
  }

  private renderUnlock() {
    return html`
      <div class="locked" aria-busy=${this.pending ? 'true' : 'false'}>
        <div class="locked-inner">
          <div class="locked-head">
            <vw-logo variant="hero"></vw-logo>
            <h1 class="locked-title">${t('auth.welcomeBack')}</h1>
            <p class="locked-sub">${t('auth.lockedPrivacy')}</p>
          </div>
          ${renderAuthIdentity(this.identity)}
          <form
            class="locked-form"
            aria-label=${t('auth.masterPasswordUnlock')}
            @submit=${(event: Event) => {
              event.preventDefault();
              this.emit('vw-auth-unlock-submit', { masterPassword: this.inputValue('unlockPassword') } satisfies UnlockSubmitDetail);
            }}
          >
            <label class="field" for="unlockPassword">
              <span class="field-label">${t('auth.masterPassword')}</span>
              <input
                id="unlockPassword"
                class="locked-input"
                type="password"
                autocomplete="current-password"
                required
                ?disabled=${this.pending}
              />
            </label>
            <button type="submit" class="btn primary locked-btn" title=${t('auth.unlock')} aria-label=${t('auth.unlock')} ?disabled=${this.pending}>${t('auth.unlock')}</button>
          </form>
          ${this.error ? html`<div class="status">${this.renderError()}</div>` : nothing}
          ${this.notice
            ? html`<div class="status"><vw-status-message tone="info" .icon=${'passkey'} .message=${this.notice}></vw-status-message></div>`
            : nothing}
          ${this.pinEnabled ? this.renderPinUnlock() : nothing}
          <button type="button" class="locked-logout" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-logout')}>
            ${t('auth.logout')}
          </button>
        </div>
      </div>
    `;
  }

  private submitForcedPasswordChange(): void {
    const currentPassword = this.inputValue('restrictedCurrentPassword');
    const newPassword = this.inputValue('restrictedNewPassword');
    const newPasswordInput = this.shadowRoot?.getElementById('restrictedNewPassword');
    const confirmation = this.shadowRoot?.getElementById('restrictedConfirmPassword');
    if (!(newPasswordInput instanceof HTMLInputElement)
        || !(confirmation instanceof HTMLInputElement)) return;
    const minimumLength = newMasterPasswordMinimumLength(this.passwordChangeRequirement?.policy);
    newPasswordInput.setCustomValidity(
      newPassword.length >= minimumLength ? '' : t('auth.passwordMin', { min: minimumLength }),
    );
    if (!newPasswordInput.reportValidity()) return;
    confirmation.setCustomValidity(
      confirmation.value === newPassword ? '' : t('auth.passwordMismatch'),
    );
    if (!confirmation.reportValidity()) return;
    this.emit('vw-auth-forced-password-change', {
      currentPassword,
      newPassword,
    } satisfies ForcedPasswordChangeSubmitDetail);
  }

  private renderRestricted() {
    const requirement = this.passwordChangeRequirement;
    if (!requirement) return this.renderError();
    const minimumLength = newMasterPasswordMinimumLength(requirement.policy);
    return html`
      <div class="auth">
        ${this.renderBrandHead(t('auth.passwordChangeRequired.title'), '')}
        <vw-status-message
          tone="warning"
          .icon=${'lock'}
          .message=${requirement.reason === 'adminForcePasswordReset'
            ? t('auth.passwordChangeRequired.admin')
            : t('auth.passwordChangeRequired.weak')}
        ></vw-status-message>
        <form @submit=${(event: Event) => {
          event.preventDefault();
          this.submitForcedPasswordChange();
        }}>
          <label class="field">
            <span class="field-label">${t('security.currentPassword')}</span>
            <input id="restrictedCurrentPassword" class="input" type="password" autocomplete="current-password" required ?disabled=${this.pending} />
          </label>
          <label class="field">
            <span class="field-label">${t('security.newPassword')}</span>
            <input id="restrictedNewPassword" class="input" type="password" autocomplete="new-password" minlength=${minimumLength} maxlength="1024" required ?disabled=${this.pending} />
          </label>
          <label class="field">
            <span class="field-label">${t('security.confirmPassword')}</span>
            <input id="restrictedConfirmPassword" class="input" type="password" autocomplete="new-password" minlength=${minimumLength} maxlength="1024" required ?disabled=${this.pending} />
          </label>
          <button type="submit" class="btn primary full" ?disabled=${this.pending}>
            ${t('security.changePassword.title')}
          </button>
          ${this.renderError()}
        </form>
        <button type="button" class="link" ?disabled=${this.pending} @click=${() => this.emit('vw-auth-logout')}>
          ${t('auth.logout')}
        </button>
      </div>
    `;
  }

  protected override render() {
    switch (this.mode) {
      case 'login':
        return this.renderLogin();
      case 'passwordHint':
        return html`
          <vw-password-hint-view
            .identity=${this.identity}
            .email=${this.passwordHintEmail}
            .pending=${this.pending}
            .error=${this.error}
            .status=${this.passwordHintStatus}
            .message=${this.passwordHintMessage}
          ></vw-password-hint-view>
        `;
      case 'register':
        return this.renderRegister();
      case 'registrationFinish':
        return this.renderRegistrationFinish();
      case 'registrationCheckEmail':
        return this.renderRegistrationCheckEmail();
      case 'newDeviceVerification':
        return this.renderNewDeviceVerification();
      case 'twoFactor':
        return this.renderTwoFactor();
      case 'sso':
        return this.renderSso();
      case 'accountPasskey':
        return this.renderAccountPasskey();
      case 'restricted':
        return this.renderRestricted();
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
