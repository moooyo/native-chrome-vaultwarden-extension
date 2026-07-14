import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/logo.js';
import '../../components/status-message.js';
import type { RepromptSubmitDetail } from '../types.js';

/**
 * The master-password reprompt gate for a protected item. It is purely presentational: the root
 * owns the verified credential and the verification request. The gate only collects the password
 * and emits `vw-reprompt-submit`; it never retains the value beyond its own input, and never
 * requests or reveals any secret. The worker enforces reprompt at the boundary — this is the UX.
 *
 * Visually it is the MiYu lock screen: a centered column with the hero mark, the reprompt title and
 * hint, the protected item's name, a single master-password input, an ink primary unlock button, and
 * a back link. Enter submits; a blank password is guarded.
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

  private i18n = new LocalizeController(this);

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
        height: 100%;
      }
      .gate {
        min-height: 100%;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 10px;
        padding: 28px 24px;
        box-sizing: border-box;
        text-align: center;
      }
      .title {
        margin: 2px 0 0;
        font-size: 15.5px;
        font-weight: 600;
        color: var(--vw-ink);
      }
      .hint {
        margin: -4px 0 0;
        max-width: 236px;
        font-size: 12px;
        color: var(--vw-muted);
      }
      .item {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        max-width: 236px;
        margin-top: 2px;
        padding: 4px 12px;
        border-radius: var(--vw-radius-pill);
        background: var(--vw-fill);
        color: var(--vw-ink);
        font-size: 12.5px;
        font-weight: 600;
      }
      .item svg {
        flex: none;
        width: 14px;
        height: 14px;
        color: var(--vw-muted);
      }
      .item span {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .form {
        display: flex;
        flex-direction: column;
        gap: 10px;
        width: 236px;
        margin-top: 6px;
      }
      .block {
        width: 100%;
      }
      .btn svg {
        width: 16px;
        height: 16px;
      }
      .status {
        width: 236px;
        margin-top: 2px;
      }
      .back-link {
        margin-top: 2px;
        border: none;
        background: none;
        padding: 2px 6px;
        color: var(--vw-muted);
        font-family: var(--vw-font-ui);
        font-size: 12px;
        cursor: pointer;
        transition: color var(--vw-dur-fast);
      }
      .back-link:hover:not(:disabled) {
        color: var(--vw-teal-text);
      }
      .back-link:disabled {
        opacity: 0.5;
        cursor: default;
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
    emit<RepromptSubmitDetail>(this, 'vw-reprompt-submit', { password });
  }

  private back(): void {
    emit(this, 'vw-item-back');
  }

  private onKeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter') {
      event.preventDefault();
      this.submit();
    }
  }

  protected override render() {
    return html`
      <div class="gate">
        <vw-logo variant="hero"></vw-logo>
        <h1 class="title">${t('detail.repromptTitle')}</h1>
        <p class="hint">${t('detail.repromptHint')}</p>
        ${this.name
          ? html`<span class="item">${uiIcon('lock')}<span>${this.name}</span></span>`
          : nothing}
        <div class="form">
          <input
            class="input"
            type="password"
            autocomplete="off"
            placeholder=${t('auth.masterPassword')}
            ?disabled=${this.pending}
            @keydown=${(e: KeyboardEvent) => this.onKeydown(e)}
          />
          <button
            type="button"
            class="btn primary block"
            data-unlock
            ?disabled=${this.pending}
            @click=${() => this.submit()}
          >
            ${uiIcon('lock')}<span>${t('auth.unlock')}</span>
          </button>
        </div>
        ${this.error
          ? html`<vw-status-message class="status" tone="danger" .icon=${'alert'} .message=${this.error}></vw-status-message>`
          : nothing}
        <button
          type="button"
          class="back-link"
          data-back
          ?disabled=${this.pending}
          @click=${() => this.back()}
        >
          ${t('common.back')}
        </button>
      </div>
    `;
  }
}

customElements.define('vw-reprompt-gate', VwRepromptGate);

declare global {
  interface HTMLElementTagNameMap {
    'vw-reprompt-gate': VwRepromptGate;
  }
}
