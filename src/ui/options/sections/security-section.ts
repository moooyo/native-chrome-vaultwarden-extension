import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { LocalizeController, t } from '../../i18n/index.js';
import { getPrefs, setPref, subscribePrefs } from '../../prefs.js';
import '../../components/setting-card.js';
import '../../components/select-menu.js';
import '../../components/toggle.js';
import '../../components/status-message.js';
import type { SelectOption } from '../../components/select-menu.js';
import {
  LOCK_TIMEOUT_VALUES,
  CLIPBOARD_CLEAR_VALUES,
  isLockTimeoutSetting,
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

/** Localised lock-timeout labels. `onClose` has no i18n key (the catalog covers 1h instead), so it
 *  carries a literal — matching this section's established pattern of local label maps. */
function lockTimeoutLabel(value: LockTimeoutSetting): string {
  switch (value) {
    case '1': return t('options.lock.1m');
    case '5': return t('options.lock.5m');
    case '15': return t('options.lock.15m');
    case '30': return t('options.lock.30m');
    case 'onClose': return t('common.close');
    case 'never': return t('options.lock.never');
  }
}

/** Localised clipboard-clear labels. 120s/300s have no i18n key, so they carry a composed literal. */
function clipboardLabel(value: ClipboardClearSetting): string {
  switch (value) {
    case 'never': return t('options.clipboard.never');
    case '30': return t('options.clipboard.30s');
    case '60': return t('options.clipboard.60s');
    case '120': return '2 分钟';
    case '300': return '5 分钟';
  }
}

/**
 * Security (安全) — the MiYu redesign. Automatic lock and the on-idle action live in one card
 * (`vw-lock-timeout-save` for the timeout, `vw-security-save` for the idle action), clipboard
 * auto-clear saves on change (`vw-security-save`), biometric unlock is a UI-local pref, and the master
 * password can be changed inline (`vw-change-password`). Every control emits an already-typed value;
 * the root performs the requests and drives the section-local status banner.
 */
export class VwSecuritySection extends LitElement {
  static override properties = {
    lockTimeout: { attribute: false },
    onIdleAction: { attribute: false },
    clipboardClearSeconds: { attribute: false },
    pending: { type: Boolean },
    status: { attribute: false },
    passwordError: { state: true },
  };

  declare lockTimeout: LockTimeoutSetting;
  declare onIdleAction: OnIdleAction;
  declare clipboardClearSeconds: ClipboardClearSetting;
  declare pending: boolean;
  declare status: SectionStatus | undefined;
  declare passwordError: string | undefined;

  private i18n = new LocalizeController(this);
  private unsubscribe: (() => void) | undefined = undefined;

  constructor() {
    super();
    this.lockTimeout = '15';
    this.onIdleAction = 'lock';
    this.clipboardClearSeconds = '60';
    this.pending = false;
    this.status = undefined;
    this.passwordError = undefined;
  }

  override connectedCallback(): void {
    super.connectedCallback();
    this.unsubscribe = subscribePrefs(() => this.requestUpdate());
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.unsubscribe?.();
    this.unsubscribe = undefined;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: flex; flex-direction: column; gap: 8px; }
      .selects { display: inline-flex; gap: 8px; }

      /* Inline change-password form */
      .pw-form { display: flex; flex-direction: column; gap: 8px; width: 100%; }
      .pw-input { width: 100%; height: 32px; padding: 0 11px; border: 1px solid var(--vw-line-3); border-radius: var(--vw-radius-input); background: var(--vw-card); color: var(--vw-ink); font-family: var(--vw-font-ui); font-size: 13px; }
      .pw-input::placeholder { color: var(--vw-placeholder); }
      .pw-input:focus { outline: none; border-color: var(--vw-accent); box-shadow: var(--vw-focus); }

      .btn { display: inline-flex; align-items: center; justify-content: center; gap: 6px; height: 30px; padding: 0 14px; border: 1px solid transparent; border-radius: var(--vw-radius-input); font-family: var(--vw-font-ui); font-size: 12.5px; font-weight: 600; white-space: nowrap; cursor: pointer; transition: background-color var(--vw-dur-fast); align-self: flex-start; }
      .btn:disabled { opacity: 0.5; cursor: default; }
      .btn:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      .btn.ink { background: var(--vw-primary-bg); color: var(--vw-primary-fg); }
      .btn.ink:hover:not(:disabled) { background: var(--vw-primary-bg-hover); }

      .pw-error { margin: 0; font-size: 11.5px; color: var(--vw-danger); }
      .status { margin-top: 6px; }
    `,
  ];

  private lockOptions(): SelectOption[] {
    return LOCK_TIMEOUT_VALUES.map((value) => ({ value, label: lockTimeoutLabel(value) }));
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
    if (this.pending || !isLockTimeoutSetting(value)) return;
    this.lockTimeout = value;
    emit<LockTimeoutSaveDetail>(this, 'vw-lock-timeout-save', { lockTimeout: value });
  }

  private onIdleChange(value: string): void {
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
    if (this.pending) return;
    this.passwordError = undefined;
    const currentPassword = this.renderRoot.querySelector<HTMLInputElement>('[data-current-password]')?.value ?? '';
    const newPassword = this.renderRoot.querySelector<HTMLInputElement>('[data-new-password]')?.value ?? '';
    const confirmPassword = this.renderRoot.querySelector<HTMLInputElement>('[data-confirm-password]')?.value ?? '';
    if (!newPassword || !confirmPassword || newPassword !== confirmPassword) {
      this.passwordError = t('security.confirmPassword');
      return;
    }
    emit<ChangePasswordDetail>(this, 'vw-change-password', { currentPassword, newPassword });
  }

  private renderStatus() {
    return this.status
      ? html`<vw-status-message class="status" tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`
      : nothing;
  }

  protected override render() {
    const prefs = getPrefs();
    return html`
      <vw-setting-card heading=${t('options.security.biometric')} description=${t('options.security.biometricDesc')}>
        <vw-toggle
          .checked=${prefs.biometric}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => setPref('biometric', e.detail.checked)}
        ></vw-toggle>
      </vw-setting-card>

      <vw-setting-card heading=${t('options.security.autoLock')} description=${t('options.security.autoLockDesc')}>
        <div class="selects">
          <vw-select
            data-lock-select
            .options=${this.lockOptions()}
            .value=${this.lockTimeout}
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
      </vw-setting-card>

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
        <button type="button" class="btn ink" data-lock-now @click=${() => emit(this, 'vw-lock-now')}>${t('popup.lock')}</button>
      </vw-setting-card>

      <vw-setting-card stacked heading=${t('options.security.masterPassword')} description=${t('options.security.masterPasswordDesc')}>
        <div class="pw-form">
          <input class="pw-input" data-current-password type="password" autocomplete="current-password" placeholder=${t('security.currentPassword')} />
          <input class="pw-input" data-new-password type="password" autocomplete="new-password" placeholder=${t('security.newPassword')} />
          <input class="pw-input" data-confirm-password type="password" autocomplete="new-password" placeholder=${t('security.confirmPassword')} />
          ${this.passwordError ? html`<p class="pw-error" role="alert">${this.passwordError}</p>` : nothing}
          <button type="button" class="btn ink" data-change-password ?disabled=${this.pending} @click=${() => this.changePassword()}>
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
