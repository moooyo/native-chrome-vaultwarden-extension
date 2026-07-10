import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/status-message.js';
import type { DetailStatus, PinSetDetail } from '../types.js';

const MIN_PIN_LENGTH = 4;

/**
 * PIN unlock management. The root loads the current PIN status (`auth.pinStatus`) and passes it as
 * `enabled`; this view shows either a remove control or a set-PIN form. It validates the minimum
 * length locally and emits `vw-pin-set` / `vw-pin-remove` — the root performs `auth.setPin` /
 * `auth.disablePin`. No secret is retained beyond the input.
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
      }
      .card {
        border: 1px solid var(--vw-line);
        border-radius: var(--vw-radius-control);
        padding: 12px;
        display: flex;
        flex-direction: column;
        gap: 8px;
      }
      .section-label {
        font-size: 13px;
        color: var(--vw-muted);
      }
      .input {
        width: 100%;
        box-sizing: border-box;
      }
      .block {
        width: 100%;
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

  private back(): void {
    this.dispatchEvent(new CustomEvent('vw-item-back', { bubbles: true, composed: true }));
  }

  private emitRemove(): void {
    if (this.pending) return;
    this.dispatchEvent(new CustomEvent('vw-pin-remove', { bubbles: true, composed: true }));
  }

  private setPin(): void {
    if (this.pending) return;
    this.validationError = undefined;
    const pin = (this.renderRoot.querySelector<HTMLInputElement>('[data-pin]')?.value ?? '').trim();
    if (pin.length < MIN_PIN_LENGTH) { this.validationError = 'PIN must be at least 4 digits'; return; }
    this.dispatchEvent(new CustomEvent<PinSetDetail>('vw-pin-set', { detail: { pin }, bubbles: true, composed: true }));
  }

  private onKeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter') {
      event.preventDefault();
      this.setPin();
    }
  }

  private renderStatus() {
    if (this.validationError) return html`<vw-status-message class="status" tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>`;
    if (this.status) return html`<vw-status-message class="status" tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`;
    return nothing;
  }

  protected override render() {
    return html`
      <div class="head">
        <button type="button" class="icon-button" data-back title="Back" aria-label="Back" @click=${() => this.back()}>${uiIcon('back')}</button>
        <h1>PIN unlock</h1>
      </div>
      <div class="card">
        ${this.enabled
          ? html`
              <span class="section-label">PIN unlock is on.</span>
              <button type="button" class="button block" data-remove ?disabled=${this.pending} @click=${() => this.emitRemove()}>${uiIcon('trash')}<span>Remove PIN</span></button>`
          : html`
              <span class="section-label">Set a PIN to unlock without your full master password on this device.</span>
              <input class="input" data-pin inputmode="numeric" autocomplete="off" placeholder="New PIN (4+ digits)" @keydown=${(e: KeyboardEvent) => this.onKeydown(e)} />
              <button type="button" class="button primary block" data-set ?disabled=${this.pending} @click=${() => this.setPin()}>${uiIcon('lock')}<span>Set PIN</span></button>`}
      </div>
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
