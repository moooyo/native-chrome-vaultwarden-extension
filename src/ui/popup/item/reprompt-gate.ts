import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/logo.js';
import '../../components/status-message.js';
import type { RepromptSubmitDetail } from '../types.js';
import { authIdentityStyles, renderAuthIdentity, type AuthIdentityDisplay } from '../auth/auth-identity.js';

/**
 * The master-password reprompt gate for a protected item. It is purely presentational: the root
 * owns the verified credential and the verification request. The gate only collects the password
 * and emits `vw-reprompt-submit`; it never retains the value beyond its own input, and never
 * requests or reveals any secret. The worker enforces reprompt at the boundary — this is the UX.
 *
 * The item, requested operation, and vault identity remain visible throughout the decision.
 * Secret input stays in the DOM only and is cleared when the protected context changes.
 */
export class VwRepromptGate extends LitElement {
  static override properties = {
    name: { type: String },
    pending: { type: Boolean },
    error: { attribute: false },
    identity: { attribute: false },
    contextKey: { attribute: false },
    fieldLabel: { type: String },
    actionLabel: { type: String },
    hasPassword: { state: true },
  };

  declare name: string;
  declare pending: boolean;
  declare error: string | undefined;
  declare identity: AuthIdentityDisplay | undefined;
  /** Opaque request context, retained only in memory to distinguish equally named items. */
  declare contextKey: string;
  declare fieldLabel: string;
  declare actionLabel: string;
  private declare hasPassword: boolean;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.name = '';
    this.pending = false;
    this.error = undefined;
    this.identity = undefined;
    this.contextKey = '';
    this.fieldLabel = '';
    this.actionLabel = '';
    this.hasPassword = false;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    authIdentityStyles,
    css`
      :host {
        display: flex;
        flex: 1;
        min-height: 0;
        background: var(--vw-panel);
      }
      .gate {
        flex: 1;
        min-width: 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: safe center;
        gap: 14px;
        padding: 28px 24px;
        box-sizing: border-box;
        text-align: center;
        overflow-y: auto;
      }
      .title {
        margin: 2px 0 0;
        font-size: 20px;
        font-weight: 600;
        color: var(--vw-ink);
      }
      .hint {
        margin: -4px 0 0;
        max-width: 320px;
        font-size: 12px;
        color: var(--vw-muted);
      }
      .item {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        max-width: 320px;
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
        width: 100%;
        max-width: 320px;
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
        width: 100%;
        max-width: 320px;
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
      .auth-identity { max-width: 320px; }
      .operation { width: 100%; max-width: 320px; margin: 0; display: grid; gap: 4px; text-align: left; }
      .operation dt, .field-label { color: var(--vw-muted); font-size: 11px; }
      .operation dd { margin: 0; color: var(--vw-ink); font-size: 13px; font-weight: 600; overflow-wrap: anywhere; }
      .field { display: grid; gap: 6px; text-align: left; }
      .field .input { width: 100%; box-sizing: border-box; }
      .back-link:focus-visible { outline: none; box-shadow: var(--vw-focus); border-radius: 4px; }
    `,
  ];

  private get input(): HTMLInputElement | null {
    return this.renderRoot.querySelector('input[type="password"]');
  }

  protected override willUpdate(changed: PropertyValues<this>): void {
    const previousIdentity = changed.get('identity') as AuthIdentityDisplay | undefined;
    const identityChanged = changed.has('identity') && (
      previousIdentity?.email !== this.identity?.email
      || previousIdentity?.server !== this.identity?.server
      || previousIdentity?.owner !== this.identity?.owner
    );
    if (changed.has('contextKey') || changed.has('name') || changed.has('fieldLabel') || changed.has('actionLabel') || identityChanged) {
      this.clearPassword();
    }
  }

  override disconnectedCallback(): void {
    this.clearPassword();
    super.disconnectedCallback();
  }

  private clearPassword(): void {
    if (this.input) this.input.value = '';
    this.hasPassword = false;
  }

  private submit(): void {
    if (this.pending) return;
    const password = this.input?.value ?? '';
    if (!password) return;
    this.clearPassword();
    emit<RepromptSubmitDetail>(this, 'vw-reprompt-submit', { password });
  }

  private back(): void {
    if (this.pending) return;
    this.clearPassword();
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
      <section class="gate" aria-labelledby="reprompt-title" aria-busy=${this.pending ? 'true' : 'false'}>
        <vw-logo variant="header"></vw-logo>
        <h1 id="reprompt-title" class="title">${t('detail.repromptTitle')}</h1>
        <p id="reprompt-hint" class="hint">${t('detail.repromptHint')}</p>
        ${this.name
          ? html`<span class="item">${uiIcon('lock')}<span>${this.name}</span></span>`
          : nothing}
        ${this.actionLabel || this.fieldLabel ? html`<dl class="operation"><dt>${t('detail.repromptOperation')}</dt><dd>${this.actionLabel}${this.actionLabel && this.fieldLabel ? ' · ' : ''}${this.fieldLabel}</dd></dl>` : nothing}
        ${renderAuthIdentity(this.identity)}
        <div class="form">
          <label class="field">
            <span class="field-label">${t('auth.masterPassword')}</span>
          <input
            class="input"
            type="password"
            autocomplete="current-password"
            aria-invalid=${this.error ? 'true' : 'false'}
            aria-describedby=${this.error ? 'reprompt-hint reprompt-error' : 'reprompt-hint'}
            required
            ?disabled=${this.pending}
            @input=${() => { this.hasPassword = Boolean(this.input?.value); }}
            @keydown=${(e: KeyboardEvent) => this.onKeydown(e)}
          />
          </label>
          <button
            type="button"
            class="btn primary block"
            data-unlock
            ?disabled=${this.pending || !this.hasPassword}
            @click=${() => this.submit()}
          >
            ${uiIcon('lock')}<span>${this.actionLabel ? t('detail.verifyAction', { action: this.actionLabel }) : t('detail.verify')}</span>
          </button>
        </div>
        ${this.error
          ? html`<vw-status-message id="reprompt-error" class="status" tone="danger" .icon=${'alert'} .message=${this.error}></vw-status-message>`
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
      </section>
    `;
  }
}

customElements.define('vw-reprompt-gate', VwRepromptGate);

declare global {
  interface HTMLElementTagNameMap {
    'vw-reprompt-gate': VwRepromptGate;
  }
}
