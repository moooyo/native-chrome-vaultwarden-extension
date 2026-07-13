import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/status-message.js';
import '../../components/setting-card.js';
import { LocalizeController, t } from '../../i18n/index.js';
import type { ChangeKdfDetail, ChangePasswordDetail, DetailStatus, RotateKeyDetail } from '../types.js';

const MIN_KDF_ITERATIONS = 600_000;

/**
 * Account security (MiYu design): change the master password, change the PBKDF2 iteration count, or
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
  };

  declare pending: boolean;
  declare status: DetailStatus | undefined;
  declare view: 'main' | 'rotate';
  declare validationError: string | undefined;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.pending = false;
    this.status = undefined;
    this.view = 'main';
    this.validationError = undefined;
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
    `,
  ];

  private read(sel: string): string {
    return this.renderRoot.querySelector<HTMLInputElement>(sel)?.value ?? '';
  }

  private back(): void {
    this.dispatchEvent(new CustomEvent('vw-item-back', { bubbles: true, composed: true }));
  }

  private toMain(): void {
    this.view = 'main';
    this.validationError = undefined;
  }

  private changePassword(): void {
    if (this.pending) return;
    this.validationError = undefined;
    const currentPassword = this.read('[data-current]');
    const newPassword = this.read('[data-new]');
    const confirm = this.read('[data-confirm]');
    if (!currentPassword || !newPassword) { this.validationError = '请输入当前主密码和新主密码'; return; } // TODO i18n
    if (newPassword.length < 8) { this.validationError = '新主密码至少需要 8 个字符'; return; } // TODO i18n
    if (newPassword !== confirm) { this.validationError = '两次输入的新主密码不一致'; return; } // TODO i18n
    this.dispatchEvent(new CustomEvent<ChangePasswordDetail>('vw-change-password', { detail: { currentPassword, newPassword }, bubbles: true, composed: true }));
  }

  private changeKdf(): void {
    if (this.pending) return;
    this.validationError = undefined;
    const currentPassword = this.read('[data-kdf-current]');
    const iterations = Number(this.read('[data-iterations]'));
    if (!currentPassword) { this.validationError = '请输入当前主密码'; return; } // TODO i18n
    if (!Number.isFinite(iterations) || iterations < MIN_KDF_ITERATIONS) { this.validationError = '迭代次数至少为 600000'; return; } // TODO i18n
    this.dispatchEvent(new CustomEvent<ChangeKdfDetail>('vw-change-kdf', { detail: { currentPassword, iterations }, bubbles: true, composed: true }));
  }

  private confirmRotate(): void {
    if (this.pending) return;
    this.validationError = undefined;
    const masterPassword = this.read('[data-rotate-current]');
    if (!masterPassword) { this.validationError = '请输入当前主密码'; return; } // TODO i18n
    this.dispatchEvent(new CustomEvent<RotateKeyDetail>('vw-rotate-key', { detail: { masterPassword }, bubbles: true, composed: true }));
  }

  private renderStatus() {
    if (this.validationError) return html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>`;
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
        <input class="input bordered" data-rotate-current type="password" autocomplete="current-password" placeholder=${t('auth.masterPassword')} />
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
            <input class="input bordered" data-current type="password" autocomplete="current-password" placeholder=${t('security.currentPassword')} />
            <input class="input bordered" data-new type="password" autocomplete="new-password" placeholder=${t('security.newPassword')} />
            <input class="input bordered" data-confirm type="password" autocomplete="new-password" placeholder=${t('security.confirmPassword')} />
            <button type="button" class="btn primary wide" data-change-password ?disabled=${this.pending} @click=${() => this.changePassword()}>
              ${uiIcon('check')}<span>${t('security.changePassword.title')}</span>
            </button>
          </div>
        </vw-setting-card>

        <vw-setting-card stacked emphasized heading=${t('security.changeKdf')} description="PBKDF2 · 至少 600000 次迭代">
          <div class="form">
            <input class="input bordered" data-kdf-current type="password" autocomplete="current-password" placeholder=${t('security.currentPassword')} />
            <input class="input bordered" data-iterations type="number" min="600000" step="100000" placeholder="迭代次数（至少 600000）" />
            <button type="button" class="btn primary wide" data-change-kdf ?disabled=${this.pending} @click=${() => this.changeKdf()}>
              ${uiIcon('refresh')}<span>${t('common.save')}</span>
            </button>
          </div>
          <!-- TODO i18n: description + iterations placeholder -->
        </vw-setting-card>

        <vw-setting-card stacked danger heading=${t('security.rotateKey')} description=${t('security.rotateKeyWarn')}>
          <button type="button" class="btn danger wide" data-rotate ?disabled=${this.pending} @click=${() => { this.view = 'rotate'; this.validationError = undefined; }}>
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
