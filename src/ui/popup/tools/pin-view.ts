import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/status-message.js';
import type { DetailStatus, PinSetDetail } from '../types.js';

const MIN_PIN_LENGTH = 4;

/**
 * PIN unlock management. The root loads the current PIN status (`auth.pinStatus`) and passes it as
 * `enabled`; this view shows either a remove control or a set-PIN form. It validates the minimum
 * length locally and emits `vw-pin-set` / `vw-pin-remove` — the root performs `auth.setPin` /
 * `auth.disablePin`. No secret is retained beyond the input.
 *
 * Visually it is a MiYu settings panel: a header with a back control, a card, MiYu inputs, an ink
 * primary set button, and a danger remove action when a PIN is already configured.
 */
export class VwPinView extends LitElement {
  static override properties = {
    enabled: { type: Boolean },
    pending: { type: Boolean },
    status: { attribute: false },
    validationError: { state: true },
  };

  declare enabled: boolean;
  declare pending: boolean;
  declare status: DetailStatus | undefined;
  declare validationError: string | undefined;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.enabled = false;
    this.pending = false;
    this.status = undefined;
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
        font-weight: 600;
        color: var(--vw-ink);
      }
      .card {
        padding: 14px;
        display: flex;
        flex-direction: column;
        gap: 10px;
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
        gap: 1px;
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
        font-size: 11.5px;
        color: var(--vw-faint);
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
    if (this.pending) return;
    emit(this, 'vw-pin-remove');
  }

  private setPin(): void {
    if (this.pending) return;
    this.validationError = undefined;
    const pin = (this.renderRoot.querySelector<HTMLInputElement>('[data-pin]')?.value ?? '').trim();
    if (pin.length < MIN_PIN_LENGTH) {
      this.validationError = 'PIN 码至少需要 4 位数字'; // TODO i18n
      return;
    }
    emit<PinSetDetail>(this, 'vw-pin-set', { pin });
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
            <span class="row-title">PIN 解锁已开启<!-- TODO i18n --></span>
            <span class="section-label">在此设备上使用 PIN 快速解锁。<!-- TODO i18n --></span>
          </div>
        </div>
        <button
          type="button"
          class="btn danger block"
          data-remove
          ?disabled=${this.pending}
          @click=${() => this.emitRemove()}
        >
          ${uiIcon('trash')}<span>移除 PIN<!-- TODO i18n --></span>
        </button>
      </div>
    `;
  }

  private renderSetForm() {
    return html`
      <div class="card">
        <span class="section-label">设置一个 PIN，即可在此设备上快速解锁，无需输入完整主密码。<!-- TODO i18n --></span>
        <input
          class="input"
          data-pin
          inputmode="numeric"
          autocomplete="off"
          placeholder=${t('auth.pin')}
          ?disabled=${this.pending}
          @keydown=${(e: KeyboardEvent) => this.onKeydown(e)}
        />
        <span class="hint">至少 4 位数字。<!-- TODO i18n --></span>
        <button
          type="button"
          class="btn primary block"
          data-set
          ?disabled=${this.pending}
          @click=${() => this.setPin()}
        >
          ${uiIcon('lock')}<span>${t('auth.setPin')}</span>
        </button>
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
      ${this.enabled ? this.renderEnabled() : this.renderSetForm()}
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
