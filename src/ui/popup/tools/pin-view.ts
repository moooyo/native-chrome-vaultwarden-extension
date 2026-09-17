import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import { authIdentityStyles, renderAuthIdentity, type AuthIdentityDisplay } from '../auth/auth-identity.js';
import {
  MAX_PIN_UTF16_CODE_UNITS,
  pinConstraintViolation,
} from '../../../core/session/pin-constraints.js';
import '../../components/status-message.js';
import type { DetailStatus, PinSetDetail } from '../types.js';

/**
 * PIN unlock management. The root loads the current PIN status (`auth.pinStatus`) and passes it as
 * `enabled`; this view shows either a remove control or a set-PIN form. It validates the minimum
 * length locally and emits `vw-pin-set` / `vw-pin-remove` — the root performs `auth.setPin` /
 * `auth.disablePin`. No secret is retained beyond the input.
 *
 * The settings surface keeps the active vault identity and the device-scoped PIN rules together.
 */
export class VwPinView extends LitElement {
  static override properties = {
    enabled: { type: Boolean },
    allowed: { type: Boolean },
    requireMasterPasswordOnRestart: { type: Boolean },
    pending: { type: Boolean },
    status: { attribute: false },
    identity: { attribute: false },
    validationError: { state: true },
  };

  declare enabled: boolean;
  declare allowed: boolean;
  declare requireMasterPasswordOnRestart: boolean;
  declare pending: boolean;
  declare status: DetailStatus | undefined;
  declare identity: AuthIdentityDisplay | undefined;
  declare validationError: string | undefined;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.enabled = false;
    this.allowed = true;
    this.requireMasterPasswordOnRestart = true;
    this.pending = false;
    this.status = undefined;
    this.identity = undefined;
    this.validationError = undefined;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    authIdentityStyles,
    css`
      :host {
        display: block;
        min-width: 0;
        color: var(--vw-ink);
        background: var(--vw-panel);
      }
      .head {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 6px 0 16px;
      }
      .head h1 {
        margin: 0;
        font-size: 18px;
        font-weight: 600;
        line-height: 1.4;
        letter-spacing: -0.015em;
        color: var(--vw-ink);
      }
      .card {
        padding: 16px 0;
        border: 0;
        border-radius: 0;
        background: transparent;
        display: flex;
        flex-direction: column;
        gap: 16px;
      }
      .row {
        display: flex;
        align-items: center;
        gap: 10px;
      }
      .badge {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex: none;
        width: 32px;
        height: 32px;
        border-radius: var(--vw-radius-control);
        background: var(--vw-teal-12);
        color: var(--vw-teal-text);
      }
      .badge svg {
        width: 17px;
        height: 17px;
      }
      .row-text {
        display: flex;
        flex-direction: column;
        gap: 4px;
        min-width: 0;
      }
      .row-title {
        font-size: 13px;
        font-weight: 600;
        color: var(--vw-ink);
      }
      .section-label {
        font-size: 12.5px;
        line-height: 1.5;
        color: var(--vw-muted);
      }
      .hint {
        font-size: 12px;
        line-height: 1.5;
        color: var(--vw-muted);
      }
      .field {
        display: flex;
        min-width: 0;
        flex-direction: column;
        gap: 7px;
      }
      .field-label {
        color: var(--vw-text-2);
        font-size: 12px;
        font-weight: 500;
      }
      .input[aria-invalid='true'] { border-color: var(--vw-danger-border); }
      .check-row {
        display: flex;
        align-items: flex-start;
        gap: 8px;
        font-size: 12px;
        line-height: 1.4;
        color: var(--vw-muted);
        cursor: pointer;
      }
      .check-row input {
        margin: 2px 0 0;
        flex: none;
      }
      .block {
        width: 100%;
      }
      .btn svg {
        width: 16px;
        height: 16px;
      }
      .status {
        margin-top: 10px;
      }
    `,
  ];

  private back(): void {
    emit(this, 'vw-item-back');
  }

  private emitRemove(): void {
    if (this.pending || !this.allowed) return;
    emit(this, 'vw-pin-remove');
  }

  private setPin(): void {
    if (this.pending || !this.allowed) return;
    this.validationError = undefined;
    const pin = this.renderRoot.querySelector<HTMLInputElement>('[data-pin]')?.value ?? '';
    const violation = pinConstraintViolation(pin);
    if (violation) {
      this.validationError = t(violation === 'too_long' ? 'auth.pinMaximum' : 'auth.pinMinimum');
      return;
    }
    emit<PinSetDetail>(this, 'vw-pin-set', {
      pin,
      requireMasterPasswordOnRestart: this.requireMasterPasswordOnRestart,
    });
  }

  private onKeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter') {
      event.preventDefault();
      this.setPin();
    }
  }

  private renderStatus() {
    if (this.validationError) {
      return html`<vw-status-message class="status" tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>`;
    }
    if (this.status) {
      return html`<vw-status-message class="status" tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`;
    }
    return nothing;
  }

  private renderEnabled() {
    return html`
      <div class="card">
        <div class="row">
          <span class="badge">${uiIcon('lock')}</span>
          <div class="row-text">
            <span class="row-title">${t('auth.pinEnabledTitle')}</span>
            <span class="section-label">
              ${this.requireMasterPasswordOnRestart
                ? t('auth.pinRestartRequiredDesc')
                : t('auth.pinRestartPersistentDesc')}
            </span>
          </div>
        </div>
        <button
          type="button"
          class="btn danger block"
          data-remove
          ?disabled=${this.pending}
          @click=${() => this.emitRemove()}
        >
          ${uiIcon('trash')}<span>${t('auth.removePin')}</span>
        </button>
      </div>
    `;
  }

  private renderSetForm() {
    return html`
      <div class="card">
        <span class="section-label">${t('auth.pinEnabledDesc')}</span>
        <label class="field">
          <span class="field-label">${t('auth.pin')}</span>
          <input
            class="input"
            data-pin
            type="password"
            autocomplete="off"
            maxlength=${MAX_PIN_UTF16_CODE_UNITS}
            aria-invalid=${this.validationError ? 'true' : 'false'}
            aria-describedby="pin-hint"
            ?disabled=${this.pending || !this.allowed}
            @input=${() => { this.validationError = undefined; }}
            @keydown=${(e: KeyboardEvent) => this.onKeydown(e)}
          />
          <span id="pin-hint" class="hint">${t('auth.pinRange')}</span>
        </label>
        <label class="check-row">
          <input
            data-require-restart
            type="checkbox"
            .checked=${this.requireMasterPasswordOnRestart}
            ?disabled=${this.pending || !this.allowed}
            @change=${(event: Event) => {
              this.requireMasterPasswordOnRestart = (event.target as HTMLInputElement).checked;
            }}
          />
          <span>${t('auth.pinRequireMasterPasswordOnRestart')}</span>
        </label>
        <button
          type="button"
          class="btn primary block"
          data-set
          ?disabled=${this.pending || !this.allowed}
          @click=${() => this.setPin()}
        >
          ${uiIcon('lock')}<span>${t('auth.setPin')}</span>
        </button>
      </div>
    `;
  }

  private renderManaged() {
    return html`
      <div class="card" data-managed role="status">
        <div class="row">
          <span class="badge">${uiIcon('lock')}</span>
          <div class="row-text">
            <span class="row-title">${t('auth.pinManaged')}</span>
            <span class="section-label">${t('auth.pinManagedDesc')}</span>
          </div>
        </div>
      </div>
    `;
  }

  protected override render() {
    return html`
      <div class="head">
        <button
          type="button"
          class="icon-btn"
          data-back
          title=${t('common.back')}
          aria-label=${t('common.back')}
          @click=${() => this.back()}
        >
          ${uiIcon('back')}
        </button>
        <h1>${t('auth.usePin')}</h1>
      </div>
      ${renderAuthIdentity(this.identity)}
      ${!this.allowed ? this.renderManaged() : this.enabled ? this.renderEnabled() : this.renderSetForm()}
      ${this.renderStatus()}
    `;
  }
}

customElements.define('vw-pin-view', VwPinView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-pin-view': VwPinView;
  }
}
