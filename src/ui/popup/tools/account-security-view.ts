import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/status-message.js';
import type { ChangeKdfDetail, ChangePasswordDetail, DetailStatus, RotateKeyDetail } from '../types.js';

const MIN_KDF_ITERATIONS = 600_000;

/**
 * Account security: change the master password, change the PBKDF2 iteration count, or rotate the
 * account encryption key (a deliberate two-step warning + confirm). All validation is local and
 * synchronous; the view only emits typed, already-validated commands and the root performs the
 * `auth.changePassword` / `auth.changeKdf` / `auth.rotateAccountKey` requests. No secret is held
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
        display: block;
      }
      .head {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 6px 0 12px;
      }
      .head h1 {
        margin: 0;
        font-size: 15px;
      }
      .card {
        border: 1px solid var(--vw-line);
        border-radius: var(--vw-radius-control);
        padding: 12px;
        margin-bottom: 12px;
        display: flex;
        flex-direction: column;
        gap: 8px;
      }
      .card.danger {
        border-color: var(--vw-danger);
      }
      .section-label {
        font-size: 12px;
        color: var(--vw-muted);
      }
      .input {
        width: 100%;
        box-sizing: border-box;
      }
      .block {
        width: 100%;
      }
      .warning {
        display: flex;
        gap: 8px;
        font-size: 13px;
        color: var(--vw-danger);
      }
      .row {
        display: flex;
        gap: 8px;
      }
      .row .button {
        flex: 1;
      }
      .status {
        margin-top: 10px;
      }
      svg {
        width: 16px;
        height: 16px;
      }
    `,
  ];

  private read(sel: string): string {
    return this.renderRoot.querySelector<HTMLInputElement>(sel)?.value ?? '';
  }

  private back(): void {
    this.dispatchEvent(new CustomEvent('vw-item-back', { bubbles: true, composed: true }));
  }

  private changePassword(): void {
    if (this.pending) return;
    this.validationError = undefined;
    const currentPassword = this.read('[data-current]');
    const newPassword = this.read('[data-new]');
    const confirm = this.read('[data-confirm]');
    if (!currentPassword || !newPassword) { this.validationError = 'Enter your current and new password'; return; }
    if (newPassword.length < 8) { this.validationError = 'New master password must be at least 8 characters'; return; }
    if (newPassword !== confirm) { this.validationError = 'New passwords do not match'; return; }
    this.dispatchEvent(new CustomEvent<ChangePasswordDetail>('vw-change-password', { detail: { currentPassword, newPassword }, bubbles: true, composed: true }));
  }

  private changeKdf(): void {
    if (this.pending) return;
    this.validationError = undefined;
    const currentPassword = this.read('[data-kdf-current]');
    const iterations = Number(this.read('[data-iterations]'));
    if (!currentPassword) { this.validationError = 'Enter your current master password'; return; }
    if (!Number.isFinite(iterations) || iterations < MIN_KDF_ITERATIONS) { this.validationError = 'Use at least 600000 iterations'; return; }
    this.dispatchEvent(new CustomEvent<ChangeKdfDetail>('vw-change-kdf', { detail: { currentPassword, iterations }, bubbles: true, composed: true }));
  }

  private confirmRotate(): void {
    if (this.pending) return;
    this.validationError = undefined;
    const masterPassword = this.read('[data-rotate-current]');
    if (!masterPassword) { this.validationError = 'Enter your current master password'; return; }
    this.dispatchEvent(new CustomEvent<RotateKeyDetail>('vw-rotate-key', { detail: { masterPassword }, bubbles: true, composed: true }));
  }

  private renderStatus() {
    if (this.validationError) return html`<vw-status-message class="status" tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>`;
    if (this.status) return html`<vw-status-message class="status" tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`;
    return nothing;
  }

  private renderRotate() {
    return html`
      <div class="head">
        <button type="button" class="icon-button" data-back title="Back" aria-label="Back" @click=${() => { this.view = 'main'; this.validationError = undefined; }}>${uiIcon('back')}</button>
        <h1>Rotate encryption key</h1>
      </div>
      <div class="card danger">
        <p class="warning">${uiIcon('alert')}<span>This generates a new encryption key and re-encrypts your entire vault. You and all other signed-in devices will need to sign in again. This can't be undone.</span></p>
        <input class="input" data-rotate-current type="password" autocomplete="current-password" placeholder="Current master password" />
        <div class="row">
          <button type="button" class="button primary" data-rotate-confirm ?disabled=${this.pending} @click=${() => this.confirmRotate()}>${uiIcon('key')}<span>Rotate encryption key</span></button>
          <button type="button" class="button" data-rotate-cancel @click=${() => { this.view = 'main'; this.validationError = undefined; }}>Cancel</button>
        </div>
      </div>
      ${this.renderStatus()}
    `;
  }

  private renderMain() {
    return html`
      <div class="head">
        <button type="button" class="icon-button" data-back title="Back" aria-label="Back" @click=${() => this.back()}>${uiIcon('back')}</button>
        <h1>Account security</h1>
      </div>
      <div class="card">
        <span class="section-label">Change master password</span>
        <input class="input" data-current type="password" autocomplete="current-password" placeholder="Current master password" />
        <input class="input" data-new type="password" autocomplete="new-password" placeholder="New master password" />
        <input class="input" data-confirm type="password" autocomplete="new-password" placeholder="Confirm new password" />
        <button type="button" class="button primary block" data-change-password ?disabled=${this.pending} @click=${() => this.changePassword()}>${uiIcon('check')}<span>Change password</span></button>
      </div>
      <div class="card">
        <span class="section-label">Change KDF iterations (PBKDF2)</span>
        <input class="input" data-kdf-current type="password" autocomplete="current-password" placeholder="Current master password" />
        <input class="input" data-iterations type="number" min="600000" step="100000" placeholder="KDF iterations (e.g. 600000)" />
        <button type="button" class="button block" data-change-kdf ?disabled=${this.pending} @click=${() => this.changeKdf()}>${uiIcon('refresh')}<span>Change KDF iterations</span></button>
      </div>
      <div class="card danger">
        <span class="section-label">Danger zone</span>
        <button type="button" class="button block" data-rotate ?disabled=${this.pending} @click=${() => { this.view = 'rotate'; this.validationError = undefined; }}>${uiIcon('key')}<span>Rotate encryption key</span></button>
      </div>
      ${this.renderStatus()}
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
