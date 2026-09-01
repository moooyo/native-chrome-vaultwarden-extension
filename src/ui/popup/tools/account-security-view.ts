import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/status-message.js';
import '../../components/setting-card.js';
import '../../components/segmented.js';
import { LocalizeController, t } from '../../i18n/index.js';
import {
  DEFAULT_MASTER_PASSWORD_MIN_LENGTH,
  MASTER_PASSWORD_HINT_MAX_LENGTH,
  masterPasswordHintValidationError,
} from '../../../core/policy/master-password-policy.js';
import type { ChangeKdfDetail, ChangePasswordDetail, DetailStatus, RotateKeyDetail } from '../types.js';

const MIN_KDF_ITERATIONS = 600_000;
// Upper guard: a mistyped count (e.g. 100_000_000) would make every later unlock run PBKDF2 for
// seconds-to-minutes, effectively locking the user out. Reject anything above a generous ceiling.
const MAX_KDF_ITERATIONS = 2_000_000;
const MIN_ARGON2_ITERATIONS = 2;
const MAX_ARGON2_ITERATIONS = 10;
const MIN_ARGON2_MEMORY_MIB = 16;
const MAX_ARGON2_MEMORY_MIB = 1_024;
const MIN_ARGON2_PARALLELISM = 1;
const MAX_ARGON2_PARALLELISM = 16;

type ValidationField =
  | 'current-password'
  | 'new-password'
  | 'confirm-password'
  | 'password-hint'
  | 'kdf-current-password'
  | 'pbkdf2-iterations'
  | 'argon2-iterations'
  | 'argon2-memory'
  | 'argon2-parallelism'
  | 'rotate-current-password';

/**
 * Account security (MiYu design): change the master password, change PBKDF2/Argon2id settings, or
 * rotate the account encryption key (a deliberate two-step warning + confirm). All validation is
 * local and synchronous; the view only emits typed, already-validated commands and the root performs
 * the `auth.changePassword` / `auth.changeKdf` / `auth.rotateAccountKey` requests. No secret is held
 * beyond the inputs, and no request is issued here.
 */
export class VwAccountSecurityView extends LitElement {
  static override properties = {
    pending: { type: Boolean },
    status: { attribute: false },
    view: { state: true },
    validationError: { state: true },
    validationField: { state: true },
    kdfType: { state: true },
  };

  declare pending: boolean;
  declare status: DetailStatus | undefined;
  declare view: 'main' | 'rotate';
  declare validationError: string | undefined;
  declare validationField: ValidationField | undefined;
  declare kdfType: 0 | 1;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.pending = false;
    this.status = undefined;
    this.view = 'main';
    this.validationError = undefined;
    this.validationField = undefined;
    this.kdfType = 0;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: flex;
        flex-direction: column;
        min-height: 0;
        flex: 1;
      }
      .head {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 10px 14px;
        flex: none;
      }
      .head h1 {
        margin: 0;
        font-size: 14px;
        font-weight: 600;
        color: var(--vw-ink);
      }
      .content {
        flex: 1;
        min-height: 0;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 10px;
        padding: 2px 14px 14px;
        scrollbar-width: thin;
        scrollbar-color: var(--vw-scrollbar) transparent;
      }
      .content::-webkit-scrollbar {
        width: 8px;
      }
      .content::-webkit-scrollbar-thumb {
        background: var(--vw-scrollbar);
        border-radius: 4px;
        border: 2px solid transparent;
        background-clip: content-box;
      }

      .form {
        display: flex;
        flex-direction: column;
        gap: 8px;
      }
      .input.bordered {
        background: var(--vw-fill-2);
        border-color: var(--vw-line-1);
      }
      .input[aria-invalid='true'] {
        border-color: var(--vw-danger-border);
      }
      .btn.wide {
        width: 100%;
      }
      .btn svg {
        width: 16px;
        height: 16px;
      }

      .warning {
        display: flex;
        gap: 10px;
        padding: 12px;
        border: 1px solid var(--vw-danger-border);
        border-radius: var(--vw-radius-card);
        background: var(--vw-danger-10);
        color: var(--vw-danger);
        font-size: 12.5px;
        line-height: 1.5;
      }
      .warning svg {
        width: 18px;
        height: 18px;
        flex: none;
        margin-top: 1px;
      }
      .rotate-form {
        display: flex;
        flex-direction: column;
        gap: 10px;
      }
      .row {
        display: flex;
        gap: 8px;
      }
      .row .btn {
        flex: 1;
      }
      .kdf-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 6px;
      }
      .kdf-field {
        display: flex;
        min-width: 0;
        flex-direction: column;
        gap: 4px;
      }
      .field-label {
        color: var(--vw-text-3);
        font-size: 10.5px;
      }
      .sr-only {
        position: absolute;
        width: 1px;
        height: 1px;
        padding: 0;
        margin: -1px;
        overflow: hidden;
        clip-path: inset(50%);
        white-space: nowrap;
        border: 0;
      }
    `,
  ];

  private read(sel: string): string {
    return this.renderRoot.querySelector<HTMLInputElement>(sel)?.value ?? '';
  }

  private back(): void {
    emit(this, 'vw-item-back');
  }

  private toMain(): void {
    this.view = 'main';
    this.clearValidationError();
  }

  private clearValidationError(): void {
    this.validationError = undefined;
    this.validationField = undefined;
  }

  private reject(field: ValidationField, message: string): void {
    this.validationError = message;
    this.validationField = field;
  }

  private fieldInvalid(field: ValidationField): boolean {
    return this.validationError !== undefined && this.validationField === field;
  }

  private changePassword(): void {
    if (this.pending) return;
    this.clearValidationError();
    const currentPassword = this.read('[data-current]');
    const newPassword = this.read('[data-new]');
    const confirm = this.read('[data-confirm]');
    const masterPasswordHint = this.read('[data-hint]');
    if (!currentPassword) { this.reject('current-password', '请输入当前主密码和新主密码'); return; } // TODO i18n
    if (!newPassword) { this.reject('new-password', '请输入当前主密码和新主密码'); return; } // TODO i18n
    if (newPassword.length < DEFAULT_MASTER_PASSWORD_MIN_LENGTH) {
      this.reject('new-password', t('auth.passwordMin', { min: DEFAULT_MASTER_PASSWORD_MIN_LENGTH }));
      return;
    }
    if (newPassword !== confirm) { this.reject('confirm-password', '两次输入的新主密码不一致'); return; } // TODO i18n
    const hintError = masterPasswordHintValidationError(masterPasswordHint, newPassword);
    if (hintError === 'tooLong') {
      this.reject('password-hint', t('security.masterPasswordHintTooLong', {
        max: MASTER_PASSWORD_HINT_MAX_LENGTH,
      }));
      return;
    }
    if (hintError === 'matchesPassword') {
      this.reject('password-hint', t('security.masterPasswordHintMatches'));
      return;
    }
    emit<ChangePasswordDetail>(this, 'vw-change-password', {
      currentPassword,
      newPassword,
      masterPasswordHint,
    });
  }

  private changeKdf(): void {
    if (this.pending) return;
    this.clearValidationError();
    const currentPassword = this.read('[data-kdf-current]');
    if (!currentPassword) { this.reject('kdf-current-password', '请输入当前主密码'); return; } // TODO i18n
    if (this.kdfType === 0) {
      const iterations = Number(this.read('[data-iterations]'));
      if (!Number.isInteger(iterations) || iterations < MIN_KDF_ITERATIONS) { this.reject('pbkdf2-iterations', '迭代次数至少为 600000'); return; } // TODO i18n
      if (iterations > MAX_KDF_ITERATIONS) { this.reject('pbkdf2-iterations', '迭代次数不能超过 2000000'); return; } // TODO i18n
      emit<ChangeKdfDetail>(this, 'vw-change-kdf', {
        currentPassword,
        kdf: { kdf: 0, kdfIterations: iterations },
      });
      return;
    }

    const iterations = Number(this.read('[data-argon-iterations]'));
    const memory = Number(this.read('[data-argon-memory]'));
    const parallelism = Number(this.read('[data-argon-parallelism]'));
    if (!Number.isInteger(iterations) || iterations < MIN_ARGON2_ITERATIONS || iterations > MAX_ARGON2_ITERATIONS) {
      this.reject('argon2-iterations', 'Argon2 迭代次数必须在 2 到 10 之间'); return; // TODO i18n
    }
    if (!Number.isInteger(memory) || memory < MIN_ARGON2_MEMORY_MIB || memory > MAX_ARGON2_MEMORY_MIB) {
      this.reject('argon2-memory', 'Argon2 内存必须在 16 到 1024 MiB 之间'); return; // TODO i18n
    }
    if (!Number.isInteger(parallelism) || parallelism < MIN_ARGON2_PARALLELISM || parallelism > MAX_ARGON2_PARALLELISM) {
      this.reject('argon2-parallelism', 'Argon2 并行度必须在 1 到 16 之间'); return; // TODO i18n
    }
    emit<ChangeKdfDetail>(this, 'vw-change-kdf', {
      currentPassword,
      kdf: { kdf: 1, kdfIterations: iterations, kdfMemory: memory, kdfParallelism: parallelism },
    });
  }

  private setKdfType(id: string): void {
    this.kdfType = id === 'argon2id' ? 1 : 0;
    this.clearValidationError();
  }

  private confirmRotate(): void {
    if (this.pending) return;
    this.clearValidationError();
    const masterPassword = this.read('[data-rotate-current]');
    if (!masterPassword) { this.reject('rotate-current-password', '请输入当前主密码'); return; } // TODO i18n
    emit<RotateKeyDetail>(this, 'vw-rotate-key', { masterPassword });
  }

  private renderStatus() {
    if (this.validationError) return html`
      <span id="account-security-validation-error" class="sr-only">${this.validationError}</span>
      <vw-status-message tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>
    `;
    if (this.status) return html`<vw-status-message tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`;
    return nothing;
  }

  private renderRotate() {
    return html`
      <div class="head">
        <button type="button" class="icon-btn" data-back title=${t('common.back')} aria-label=${t('common.back')} @click=${() => this.toMain()}>
          ${uiIcon('back')}
        </button>
        <h1>${t('security.rotateKey')}</h1>
      </div>
      <div class="content">
        <div class="warning">
          ${uiIcon('alert')}
          <span>${t('security.rotateKeyWarn')}。所有已登录设备需要重新登录，且此操作无法撤销。</span>
          <!-- TODO i18n: second sentence -->
        </div>
        <input
          class="input bordered"
          data-rotate-current
          type="password"
          autocomplete="current-password"
          placeholder=${t('auth.masterPassword')}
          aria-label=${t('security.currentPassword')}
          aria-invalid=${this.fieldInvalid('rotate-current-password') ? 'true' : 'false'}
          aria-describedby=${this.fieldInvalid('rotate-current-password') ? 'account-security-validation-error' : nothing}
        />
        <div class="row">
          <button type="button" class="btn danger" data-rotate-confirm ?disabled=${this.pending} @click=${() => this.confirmRotate()}>
            ${uiIcon('key')}<span>${t('security.rotateKey')}</span>
          </button>
          <button type="button" class="btn outline" data-rotate-cancel @click=${() => this.toMain()}>${t('common.cancel')}</button>
        </div>
        ${this.renderStatus()}
      </div>
    `;
  }

  private renderMain() {
    return html`
      <div class="head">
        <button type="button" class="icon-btn" data-back title=${t('common.back')} aria-label=${t('common.back')} @click=${() => this.back()}>
          ${uiIcon('back')}
        </button>
        <h1>${t('popup.accountSecurity')}</h1>
      </div>
      <div class="content">
        <vw-setting-card stacked emphasized heading=${t('security.changePassword.title')}>
          <div class="form">
            <input
              class="input bordered"
              data-current
              type="password"
              autocomplete="current-password"
              placeholder=${t('security.currentPassword')}
              aria-label=${t('security.currentPassword')}
              aria-invalid=${this.fieldInvalid('current-password') ? 'true' : 'false'}
              aria-describedby=${this.fieldInvalid('current-password') ? 'account-security-validation-error' : nothing}
            />
            <input
              class="input bordered"
              data-new
              type="password"
              autocomplete="new-password"
              minlength=${DEFAULT_MASTER_PASSWORD_MIN_LENGTH}
              maxlength="1024"
              placeholder=${t('security.newPassword')}
              aria-label=${t('security.newPassword')}
              aria-invalid=${this.fieldInvalid('new-password') ? 'true' : 'false'}
              aria-describedby=${this.fieldInvalid('new-password') ? 'account-security-validation-error' : nothing}
            />
            <input
              class="input bordered"
              data-confirm
              type="password"
              autocomplete="new-password"
              minlength=${DEFAULT_MASTER_PASSWORD_MIN_LENGTH}
              maxlength="1024"
              placeholder=${t('security.confirmPassword')}
              aria-label=${t('security.confirmPassword')}
              aria-invalid=${this.fieldInvalid('confirm-password') ? 'true' : 'false'}
              aria-describedby=${this.fieldInvalid('confirm-password') ? 'account-security-validation-error' : nothing}
            />
            <input
              class="input bordered"
              data-hint
              type="text"
              autocomplete="off"
              maxlength=${MASTER_PASSWORD_HINT_MAX_LENGTH}
              placeholder=${t('security.masterPasswordHint')}
              aria-label=${t('security.masterPasswordHint')}
              aria-invalid=${this.fieldInvalid('password-hint') ? 'true' : 'false'}
              aria-describedby=${this.fieldInvalid('password-hint') ? 'account-security-validation-error' : nothing}
            />
            <button type="button" class="btn primary wide" data-change-password ?disabled=${this.pending} @click=${() => this.changePassword()}>
              ${uiIcon('check')}<span>${t('security.changePassword.title')}</span>
            </button>
          </div>
        </vw-setting-card>

        <vw-setting-card stacked emphasized heading=${t('security.changeKdf')} description=${this.kdfType === 0 ? 'PBKDF2' : 'Argon2id'}>
          <div class="form">
            <input
              class="input bordered"
              data-kdf-current
              type="password"
              autocomplete="current-password"
              placeholder=${t('security.currentPassword')}
              aria-label=${t('security.currentPassword')}
              aria-invalid=${this.fieldInvalid('kdf-current-password') ? 'true' : 'false'}
              aria-describedby=${this.fieldInvalid('kdf-current-password') ? 'account-security-validation-error' : nothing}
            />
            <vw-segmented
              .options=${[{ id: 'pbkdf2', label: 'PBKDF2' }, { id: 'argon2id', label: 'Argon2id' }]}
              .value=${this.kdfType === 0 ? 'pbkdf2' : 'argon2id'}
              .label=${t('security.kdfType')}
              @vw-segmented-change=${(event: CustomEvent<{ id: string }>) => this.setKdfType(event.detail.id)}
            ></vw-segmented>
            ${this.kdfType === 0
              ? html`
                  <input
                    class="input bordered"
                    data-iterations
                    type="number"
                    min="600000"
                    max="2000000"
                    step="100000"
                    value="600000"
                    placeholder=${t('security.pbkdf2Iterations')}
                    aria-label=${t('security.pbkdf2Iterations')}
                    aria-invalid=${this.fieldInvalid('pbkdf2-iterations') ? 'true' : 'false'}
                    aria-describedby=${this.fieldInvalid('pbkdf2-iterations') ? 'account-security-validation-error' : nothing}
                  />
                `
              : html`
                  <div class="kdf-grid">
                    <label class="kdf-field">
                      <span class="field-label">${t('security.argon2Iterations')}</span>
                      <input
                        class="input bordered"
                        data-argon-iterations
                        type="number"
                        min="2"
                        max="10"
                        step="1"
                        value="6"
                        aria-invalid=${this.fieldInvalid('argon2-iterations') ? 'true' : 'false'}
                        aria-describedby=${this.fieldInvalid('argon2-iterations') ? 'account-security-validation-error' : nothing}
                      />
                    </label>
                    <label class="kdf-field">
                      <span class="field-label">${t('security.argon2Memory')}</span>
                      <input
                        class="input bordered"
                        data-argon-memory
                        type="number"
                        min="16"
                        max="1024"
                        step="1"
                        value="32"
                        aria-invalid=${this.fieldInvalid('argon2-memory') ? 'true' : 'false'}
                        aria-describedby=${this.fieldInvalid('argon2-memory') ? 'account-security-validation-error' : nothing}
                      />
                    </label>
                    <label class="kdf-field">
                      <span class="field-label">${t('security.argon2Parallelism')}</span>
                      <input
                        class="input bordered"
                        data-argon-parallelism
                        type="number"
                        min="1"
                        max="16"
                        step="1"
                        value="4"
                        aria-invalid=${this.fieldInvalid('argon2-parallelism') ? 'true' : 'false'}
                        aria-describedby=${this.fieldInvalid('argon2-parallelism') ? 'account-security-validation-error' : nothing}
                      />
                    </label>
                  </div>
                `}
            <button type="button" class="btn primary wide" data-change-kdf ?disabled=${this.pending} @click=${() => this.changeKdf()}>
              ${uiIcon('refresh')}<span>${t('common.save')}</span>
            </button>
          </div>
          <!-- TODO i18n: KDF field labels and validation messages -->
        </vw-setting-card>

        <vw-setting-card stacked danger heading=${t('security.rotateKey')} description=${t('security.rotateKeyWarn')}>
          <button type="button" class="btn danger wide" data-rotate ?disabled=${this.pending} @click=${() => { this.view = 'rotate'; this.clearValidationError(); }}>
            ${uiIcon('key')}<span>${t('security.rotateKey')}</span>
          </button>
        </vw-setting-card>

        ${this.renderStatus()}
      </div>
    `;
  }

  protected override render() {
    return this.view === 'rotate' ? this.renderRotate() : this.renderMain();
  }
}

customElements.define('vw-account-security-view', VwAccountSecurityView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-account-security-view': VwAccountSecurityView;
  }
}
