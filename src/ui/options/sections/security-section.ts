import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/setting-card.js';
import '../../components/select-menu.js';
import '../../components/status-message.js';
import type { SelectOption } from '../../components/select-menu.js';
import {
  LOCK_TIMEOUT_VALUES,
  MAX_LOCK_TIMEOUT_MINUTES,
  CLIPBOARD_CLEAR_VALUES,
  isCanonicalLockTimeoutMinutes,
  isSelectableLockTimeoutSetting,
  isOnIdleAction,
  isClipboardClearSetting,
  type LockTimeoutSetting,
  type OnIdleAction,
  type ClipboardClearSetting,
} from '../../../background/settings.js';
import type {
  ChangePasswordDetail,
  LockTimeoutSaveDetail,
  SecuritySaveDetail,
  SectionStatus,
} from '../types.js';
import type { EffectiveVaultTimeoutMode } from '../../../background/vault-timeout-policy.js';
import {
  MASTER_PASSWORD_HINT_MAX_LENGTH,
  masterPasswordHintValidationError,
} from '../../../core/policy/master-password-policy.js';

const CUSTOM_TIMEOUT_OPTION = 'custom';
type BuiltInLockTimeout = (typeof LOCK_TIMEOUT_VALUES)[number];
type LockTimeoutOption = BuiltInLockTimeout | typeof CUSTOM_TIMEOUT_OPTION;

/** Localised lock-timeout labels. Legacy `never` renders as the truthful close-only behavior. */
function lockTimeoutLabel(value: LockTimeoutSetting): string {
  switch (value) {
    case 'immediate': return t('options.lock.immediately');
    case '1': return t('options.lock.1m');
    case '5': return t('options.lock.5m');
    case '15': return t('options.lock.15m');
    case '30': return t('options.lock.30m');
    case 'onLocked': return t('options.lock.systemLock');
    case 'onClose':
    case 'never': return t('options.lock.onClose');
    default:
      return isCanonicalLockTimeoutMinutes(value)
        ? t('options.lock.minutes', { minutes: value })
        : t('options.lock.onClose');
  }
}

function isBuiltInLockTimeout(value: string): value is BuiltInLockTimeout {
  return (LOCK_TIMEOUT_VALUES as readonly string[]).includes(value);
}

function timeoutOption(value: LockTimeoutSetting): LockTimeoutOption {
  if (value === 'never') return 'onClose';
  return isBuiltInLockTimeout(value) ? value : CUSTOM_TIMEOUT_OPTION;
}

/** Localised clipboard-clear labels. */
function clipboardLabel(value: ClipboardClearSetting): string {
  switch (value) {
    case 'never': return t('options.clipboard.never');
    case '30': return t('options.clipboard.30s');
    case '60': return t('options.clipboard.60s');
    case '120': return t('options.clipboard.120s');
    case '300': return t('options.clipboard.300s');
  }
}

/**
 * Security (安全) — the MiYu redesign. Automatic lock and the on-idle action live in one card
 * (`vw-lock-timeout-save` for the timeout, `vw-security-save` for the idle action), clipboard
 * auto-clear saves on change (`vw-security-save`), and the master password can be changed inline
 * (`vw-change-password`). Every control emits an already-typed value;
 * the root performs the requests and drives the section-local status banner.
 */
export class VwSecuritySection extends LitElement {
  static override properties = {
    lockTimeout: { attribute: false },
    onIdleAction: { attribute: false },
    clipboardClearSeconds: { attribute: false },
    timeoutManaged: { type: Boolean },
    timeoutMode: { type: String },
    pinUnlockAllowed: { type: Boolean },
    locked: { type: Boolean },
    pending: { type: Boolean },
    status: { attribute: false },
    passwordError: { state: true },
    passwordErrorField: { state: true },
    timeoutSelection: { state: true },
    customMinutes: { state: true },
    customTimeoutError: { state: true },
    customSaveLocked: { state: true },
  };

  declare lockTimeout: LockTimeoutSetting;
  declare onIdleAction: OnIdleAction;
  declare clipboardClearSeconds: ClipboardClearSetting;
  declare timeoutManaged: boolean;
  declare timeoutMode: EffectiveVaultTimeoutMode;
  declare pinUnlockAllowed: boolean;
  declare locked: boolean;
  declare pending: boolean;
  declare status: SectionStatus | undefined;
  declare passwordError: string | undefined;
  private declare passwordErrorField: 'newPassword' | 'confirmPassword' | 'hint' | undefined;
  private declare timeoutSelection: LockTimeoutOption;
  private declare customMinutes: string;
  private declare customTimeoutError: string | undefined;
  private declare customSaveLocked: boolean;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.lockTimeout = '15';
    this.onIdleAction = 'lock';
    this.clipboardClearSeconds = '60';
    this.timeoutManaged = false;
    this.timeoutMode = 'local';
    this.pinUnlockAllowed = true;
    this.locked = true;
    this.pending = false;
    this.status = undefined;
    this.passwordError = undefined;
    this.passwordErrorField = undefined;
    this.timeoutSelection = '15';
    this.customMinutes = '15';
    this.customTimeoutError = undefined;
    this.customSaveLocked = false;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: flex; flex-direction: column; gap: 8px; }
      .selects { display: inline-flex; flex-wrap: wrap; gap: 8px; }
      .custom-timeout { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 6px 8px; width: min(100%, 340px); }
      .custom-timeout label { grid-column: 1 / 3; color: var(--vw-muted); font-size: 12px; }
      .custom-input { min-width: 0; height: 40px; padding: 0 11px; border: 1px solid var(--vw-line-3); border-radius: var(--vw-radius-input); background: var(--vw-card); color: var(--vw-ink); font-family: var(--vw-font-ui); font-size: 13px; }
      .custom-input:focus { outline: none; border-color: var(--vw-accent); box-shadow: var(--vw-focus); }
      .custom-input[aria-invalid='true'] { border-color: var(--vw-danger-border); }
      .custom-help, .custom-error { grid-column: 1 / 3; margin: 0; font-size: 11.5px; line-height: 1.35; }
      .custom-help { color: var(--vw-muted); }
      .custom-error { color: var(--vw-danger); overflow-wrap: anywhere; }

      /* Inline change-password form */
      .pw-form { display: flex; flex-direction: column; gap: 8px; width: 100%; }
      .pw-input { width: 100%; height: 32px; padding: 0 11px; border: 1px solid var(--vw-line-3); border-radius: var(--vw-radius-input); background: var(--vw-card); color: var(--vw-ink); font-family: var(--vw-font-ui); font-size: 13px; }
      .pw-input::placeholder { color: var(--vw-placeholder); }
      .pw-input:focus { outline: none; border-color: var(--vw-accent); box-shadow: var(--vw-focus); }
      .pw-input[aria-invalid='true'] { border-color: var(--vw-danger-border); }

      .btn { display: inline-flex; align-items: center; justify-content: center; gap: 6px; height: 30px; padding: 0 14px; border: 1px solid transparent; border-radius: var(--vw-radius-input); font-family: var(--vw-font-ui); font-size: 12.5px; font-weight: 600; white-space: nowrap; cursor: pointer; transition: background-color var(--vw-dur-fast); align-self: flex-start; }
      .btn:disabled { opacity: 0.5; cursor: default; }
      .btn:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      .btn.ink { background: var(--vw-primary-bg); color: var(--vw-primary-fg); }
      .btn.ink:hover:not(:disabled) { background: var(--vw-primary-bg-hover); }

      .pw-error { margin: 0; font-size: 11.5px; color: var(--vw-danger); }
      .status { margin-top: 6px; }
      .managed-value { font-size: 12.5px; color: var(--vw-ink); }
    `,
  ];

  private lockOptions(): SelectOption[] {
    return [
      ...LOCK_TIMEOUT_VALUES.map((value) => ({ value, label: lockTimeoutLabel(value) })),
      { value: CUSTOM_TIMEOUT_OPTION, label: t('options.lock.custom') },
    ];
  }

  private clipboardOptions(): SelectOption[] {
    return CLIPBOARD_CLEAR_VALUES.map((value) => ({ value, label: clipboardLabel(value) }));
  }

  private idleOptions(): SelectOption[] {
    return [
      { value: 'lock', label: t('popup.lock') },
      { value: 'logout', label: t('auth.logout') },
    ];
  }

  private onLockTimeoutChange(value: string): void {
    if (this.timeoutManaged) return;
    if (value === CUSTOM_TIMEOUT_OPTION) {
      this.timeoutSelection = CUSTOM_TIMEOUT_OPTION;
      if (isCanonicalLockTimeoutMinutes(this.lockTimeout)) this.customMinutes = this.lockTimeout;
      this.customTimeoutError = undefined;
      return;
    }
    if (!isBuiltInLockTimeout(value) || !isSelectableLockTimeoutSetting(value)) return;
    this.timeoutSelection = value;
    this.customTimeoutError = undefined;
    this.lockTimeout = value;
    emit<LockTimeoutSaveDetail>(this, 'vw-lock-timeout-save', { lockTimeout: value });
  }

  private onCustomMinutesInput(event: Event): void {
    const target = event.target;
    if (!(target instanceof HTMLInputElement) || this.timeoutManaged) return;
    this.customMinutes = target.value;
    this.customTimeoutError = undefined;
  }

  private saveCustomTimeout(): void {
    if (this.timeoutManaged || this.pending || this.customSaveLocked) return;
    if (!isCanonicalLockTimeoutMinutes(this.customMinutes)) {
      this.customTimeoutError = t('options.lock.customInvalid', { max: MAX_LOCK_TIMEOUT_MINUTES });
      return;
    }
    this.customTimeoutError = undefined;
    this.customSaveLocked = true;
    emit<LockTimeoutSaveDetail>(this, 'vw-lock-timeout-save', { lockTimeout: this.customMinutes });
  }

  private onIdleChange(value: string): void {
    if (this.timeoutManaged) return;
    if (!isOnIdleAction(value)) return;
    this.onIdleAction = value;
    this.emitSecurity();
  }

  private onClipboardChange(value: string): void {
    if (!isClipboardClearSetting(value)) return;
    this.clipboardClearSeconds = value;
    this.emitSecurity();
  }

  private emitSecurity(): void {
    emit<SecuritySaveDetail>(this, 'vw-security-save', { onIdleAction: this.onIdleAction, clipboardClearSeconds: this.clipboardClearSeconds });
  }

  private changePassword(): void {
    if (this.locked || this.pending) return;
    this.passwordError = undefined;
    this.passwordErrorField = undefined;
    const currentPassword = this.renderRoot.querySelector<HTMLInputElement>('[data-current-password]')?.value ?? '';
    const newPassword = this.renderRoot.querySelector<HTMLInputElement>('[data-new-password]')?.value ?? '';
    const confirmPassword = this.renderRoot.querySelector<HTMLInputElement>('[data-confirm-password]')?.value ?? '';
    const masterPasswordHint = this.renderRoot.querySelector<HTMLInputElement>('[data-master-password-hint]')?.value ?? '';
    if (!newPassword || !confirmPassword || newPassword !== confirmPassword) {
      this.passwordError = t('security.confirmPassword');
      this.passwordErrorField = !newPassword ? 'newPassword' : 'confirmPassword';
      return;
    }
    const hintError = masterPasswordHintValidationError(masterPasswordHint, newPassword);
    if (hintError === 'tooLong') {
      this.passwordError = t('security.masterPasswordHintTooLong', {
        max: MASTER_PASSWORD_HINT_MAX_LENGTH,
      });
      this.passwordErrorField = 'hint';
      return;
    }
    if (hintError === 'matchesPassword') {
      this.passwordError = t('security.masterPasswordHintMatches');
      this.passwordErrorField = 'hint';
      return;
    }
    emit<ChangePasswordDetail>(this, 'vw-change-password', {
      currentPassword,
      newPassword,
      masterPasswordHint,
    });
  }

  private managedTimeoutLabel(): string {
    if (this.timeoutMode === 'systemLock') return t('options.lock.systemLock');
    if (this.timeoutMode === 'immediate') return t('options.lock.immediately');
    return lockTimeoutLabel(this.lockTimeout);
  }

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (changed.has('lockTimeout')) {
      this.timeoutSelection = timeoutOption(this.lockTimeout);
      if (isCanonicalLockTimeoutMinutes(this.lockTimeout)) this.customMinutes = this.lockTimeout;
      this.customTimeoutError = undefined;
      this.customSaveLocked = false;
    }
    if ((changed.has('pending') && !this.pending) || changed.has('status')) {
      this.customSaveLocked = false;
    }
  }

  protected override updated(changed: PropertyValues<this>): void {
    if (!changed.has('locked') || !this.locked) return;
    for (const input of this.renderRoot.querySelectorAll<HTMLInputElement>('.pw-input')) input.value = '';
    if (this.passwordError !== undefined) this.passwordError = undefined;
    this.passwordErrorField = undefined;
  }

  private renderStatus() {
    return this.status
      ? html`<vw-status-message class="status" tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`
      : nothing;
  }

  protected override render() {
    return html`
      <vw-setting-card heading=${t('options.security.autoLock')} description=${t('options.security.autoLockDesc')}>
        ${this.timeoutManaged
          ? html`
              <div class="managed-value" data-timeout-value>${this.managedTimeoutLabel()} · ${this.onIdleAction === 'logout' ? t('auth.logout') : t('popup.lock')}</div>
              <vw-status-message data-timeout-managed tone="info" .message=${t('options.security.managedTimeout')}></vw-status-message>
            `
          : html`
              <div class="selects">
                <vw-select
                  data-lock-select
                  .options=${this.lockOptions()}
                  .value=${this.timeoutSelection}
                  .label=${t('options.security.autoLock')}
                  @vw-select-change=${(e: CustomEvent<{ value: string }>) => this.onLockTimeoutChange(e.detail.value)}
                ></vw-select>
                <vw-select
                  data-idle-select
                  .options=${this.idleOptions()}
                  .value=${this.onIdleAction}
                  .label=${t('options.security.autoLock')}
                  @vw-select-change=${(e: CustomEvent<{ value: string }>) => this.onIdleChange(e.detail.value)}
                ></vw-select>
              </div>
              ${this.timeoutSelection === CUSTOM_TIMEOUT_OPTION
                ? html`
                    <div class="custom-timeout">
                      <label for="custom-lock-minutes">${t('options.lock.customMinutes')}</label>
                      <input
                        id="custom-lock-minutes"
                        class="custom-input"
                        data-custom-lock-minutes
                        type="number"
                        inputmode="numeric"
                        min="1"
                        max=${MAX_LOCK_TIMEOUT_MINUTES}
                        step="1"
                        .value=${this.customMinutes}
                        aria-invalid=${this.customTimeoutError ? 'true' : 'false'}
                        aria-describedby="custom-lock-help custom-lock-error"
                        ?disabled=${this.pending || this.customSaveLocked}
                        @input=${(event: Event) => this.onCustomMinutesInput(event)}
                        @keydown=${(event: KeyboardEvent) => {
                          if (event.key !== 'Enter') return;
                          event.preventDefault();
                          this.saveCustomTimeout();
                        }}
                      />
                      <button type="button" class="btn ink" data-save-custom-lock ?disabled=${this.pending || this.customSaveLocked} @click=${() => this.saveCustomTimeout()}>${t('options.lock.customSave')}</button>
                      <p id="custom-lock-help" class="custom-help">${t('options.lock.customRange', { max: MAX_LOCK_TIMEOUT_MINUTES })}</p>
                      ${this.customTimeoutError
                        ? html`<p id="custom-lock-error" class="custom-error" role="alert">${this.customTimeoutError}</p>`
                        : html`<span id="custom-lock-error" hidden></span>`}
                    </div>
                  `
                : nothing}
            `}
      </vw-setting-card>

      ${this.pinUnlockAllowed
        ? nothing
        : html`<vw-status-message data-pin-managed tone="info" .message=${t('options.security.pinManaged')}></vw-status-message>`}

      <vw-setting-card heading=${t('options.security.clipboard')} description=${t('options.security.clipboardDesc')}>
        <vw-select
          data-clip-select
          .options=${this.clipboardOptions()}
          .value=${this.clipboardClearSeconds}
          .label=${t('options.security.clipboard')}
          @vw-select-change=${(e: CustomEvent<{ value: string }>) => this.onClipboardChange(e.detail.value)}
        ></vw-select>
      </vw-setting-card>

      <vw-setting-card emphasized heading=${t('options.security.lockNow')} description=${t('options.security.lockNowDesc')}>
        <button type="button" class="btn ink" data-lock-now ?disabled=${this.locked || this.pending} @click=${() => emit(this, 'vw-lock-now')}>${t('popup.lock')}</button>
      </vw-setting-card>

      <vw-setting-card stacked heading=${t('options.security.masterPassword')} description=${t('options.security.masterPasswordDesc')}>
        <div class="pw-form">
          <input
            class="pw-input"
            data-current-password
            type="password"
            autocomplete="current-password"
            placeholder=${t('security.currentPassword')}
            aria-label=${t('security.currentPassword')}
            ?disabled=${this.locked || this.pending}
          />
          <input
            class="pw-input"
            data-new-password
            type="password"
            autocomplete="new-password"
            placeholder=${t('security.newPassword')}
            aria-label=${t('security.newPassword')}
            aria-invalid=${this.passwordErrorField === 'newPassword' ? 'true' : 'false'}
            aria-describedby=${this.passwordErrorField === 'newPassword' ? 'password-change-error' : nothing}
            ?disabled=${this.locked || this.pending}
          />
          <input
            class="pw-input"
            data-confirm-password
            type="password"
            autocomplete="new-password"
            placeholder=${t('security.confirmPassword')}
            aria-label=${t('security.confirmPassword')}
            aria-invalid=${this.passwordErrorField === 'confirmPassword' ? 'true' : 'false'}
            aria-describedby=${this.passwordErrorField === 'confirmPassword' ? 'password-change-error' : nothing}
            ?disabled=${this.locked || this.pending}
          />
          <input
            class="pw-input"
            data-master-password-hint
            type="text"
            autocomplete="off"
            maxlength=${MASTER_PASSWORD_HINT_MAX_LENGTH}
            placeholder=${t('security.masterPasswordHint')}
            aria-label=${t('security.masterPasswordHint')}
            aria-invalid=${this.passwordErrorField === 'hint' ? 'true' : 'false'}
            aria-describedby=${this.passwordErrorField === 'hint' ? 'password-change-error' : nothing}
            ?disabled=${this.locked || this.pending}
          />
          ${this.passwordError ? html`<p id="password-change-error" class="pw-error" role="alert">${this.passwordError}</p>` : nothing}
          <button type="button" class="btn ink" data-change-password ?disabled=${this.locked || this.pending} @click=${() => this.changePassword()}>
            ${t('options.security.changePassword')}
          </button>
        </div>
      </vw-setting-card>

      ${this.renderStatus()}
    `;
  }
}

customElements.define('vw-security-section', VwSecuritySection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-security-section': VwSecuritySection;
  }
}
