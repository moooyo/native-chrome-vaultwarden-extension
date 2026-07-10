import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/status-message.js';
import type { RepromptSubmitDetail } from '../types.js';

/**
 * The master-password reprompt gate for a protected item. It is purely presentational: the root
 * owns the verified credential and the verification request. The gate only collects the password
 * and emits `vw-reprompt-submit`; it never retains the value beyond its own input, and never
 * requests or reveals any secret. The worker enforces reprompt at the boundary — this is the UX.
 */
export class VwRepromptGate extends LitElement {
  static override properties = {
    name: { type: String },
    pending: { type: Boolean },
    error: { attribute: false },
  };

  declare name: string;
  declare pending: boolean;
  declare error: string | undefined;

  constructor() {
    super();
    this.name = '';
    this.pending = false;
    this.error = undefined;
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
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .readout {
        display: flex;
        align-items: center;
        gap: 8px;
        color: var(--vw-muted);
        font-size: 13px;
        padding-bottom: 10px;
      }
      .readout svg {
        width: 16px;
        height: 16px;
      }
      label {
        display: flex;
        flex-direction: column;
        gap: 4px;
        font-size: 12px;
        color: var(--vw-muted);
      }
      .actions {
        margin-top: 12px;
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

  private get input(): HTMLInputElement | null {
    return this.renderRoot.querySelector('input[type="password"]');
  }

  private submit(): void {
    if (this.pending) return;
    const password = this.input?.value ?? '';
    if (!password) return;
    this.dispatchEvent(
      new CustomEvent<RepromptSubmitDetail>('vw-reprompt-submit', {
        detail: { password },
        bubbles: true,
        composed: true,
      }),
    );
  }

  private back(): void {
    this.dispatchEvent(new CustomEvent('vw-item-back', { bubbles: true, composed: true }));
  }

  private onKeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter') {
      event.preventDefault();
      this.submit();
    }
  }

  protected override render() {
    return html`
      <div class="head">
        <button type="button" class="icon-button" data-back title="Back" aria-label="Back" @click=${() => this.back()}>
          ${uiIcon('back')}
        </button>
        <h1>${this.name}</h1>
      </div>
      <div class="readout">${uiIcon('lock')}<span>Re-enter your master password to view this item.</span></div>
      <label>
        <span>Master password</span>
        <input class="input" type="password" autocomplete="off" ?disabled=${this.pending} @keydown=${(e: KeyboardEvent) => this.onKeydown(e)} />
      </label>
      <div class="actions">
        <button type="button" class="button primary block" data-unlock ?disabled=${this.pending} @click=${() => this.submit()}>
          ${uiIcon('unlock')}<span>Unlock item</span>
        </button>
      </div>
      ${this.error
        ? html`<vw-status-message class="status" tone="danger" .icon=${'alert'} .message=${this.error}></vw-status-message>`
        : nothing}
    `;
  }
}

customElements.define('vw-reprompt-gate', VwRepromptGate);

declare global {
  interface HTMLElementTagNameMap {
    'vw-reprompt-gate': VwRepromptGate;
  }
}
