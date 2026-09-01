import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/logo.js';
import '../../components/status-message.js';

const MAX_EMAIL_LENGTH = 254;

export type PasswordHintStatus = 'sent' | 'hint' | 'no_hint' | 'unavailable';

/** Canonical email carried by both view-to-host events. */
export interface PasswordHintEmailDetail {
  readonly email: string;
}

/**
 * Account-recovery presentation only. The host owns transport and supplies server errors; this view
 * keeps the success state deliberately generic so it cannot disclose whether an account exists.
 */
export class VwPasswordHintView extends LitElement {
  static override properties = {
    email: { attribute: false },
    pending: { type: Boolean },
    error: { attribute: false },
    status: { attribute: false },
    message: { attribute: false },
    draftEmail: { state: true },
    localError: { state: true },
  };

  declare email: string;
  declare pending: boolean;
  declare error: string | undefined;
  declare status: PasswordHintStatus | undefined;
  declare message: string | undefined;
  private declare draftEmail: string;
  private declare localError: string | undefined;

  private i18n = new LocalizeController(this);
  private actionLocked = false;

  constructor() {
    super();
    this.email = '';
    this.pending = false;
    this.error = undefined;
    this.status = undefined;
    this.message = undefined;
    this.draftEmail = '';
    this.localError = undefined;
  }

  static override styles = [themeTokens, controlStyles, css`
    :host {
      display: flex;
      flex: 1;
      width: 100%;
      height: 100%;
      min-width: 0;
      min-height: 0;
      overflow: hidden;
      background: var(--vw-panel);
    }
    .surface {
      display: flex;
      flex: 1;
      min-width: 0;
      min-height: 0;
      flex-direction: column;
      gap: 18px;
      padding: 26px 28px;
      overflow-x: hidden;
      overflow-y: auto;
      color: var(--vw-ink);
      box-sizing: border-box;
    }
    .head {
      display: grid;
      grid-template-columns: auto minmax(0, 1fr);
      align-items: center;
      gap: 10px;
    }
    .head-copy { min-width: 0; }
    h1, p { margin: 0; }
    h1 {
      overflow-wrap: anywhere;
      font-size: 16px;
      font-weight: 600;
      letter-spacing: 0;
      line-height: 1.3;
    }
    .description {
      margin-top: 4px;
      color: var(--vw-muted);
      font-size: 12px;
      line-height: 1.45;
      overflow-wrap: anywhere;
    }
    form {
      display: flex;
      flex-direction: column;
      gap: 12px;
      min-width: 0;
    }
    .field {
      display: flex;
      min-width: 0;
      flex-direction: column;
      gap: 6px;
    }
    .field-label {
      color: var(--vw-muted);
      font-size: 12px;
    }
    .input[aria-invalid='true'] { border-color: var(--vw-danger-border); }
    .actions {
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 8px;
    }
    .feedback {
      min-width: 0;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    vw-status-message {
      display: block;
      width: 100%;
      min-width: 0;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    @media (max-width: 340px) {
      .surface { padding-right: 16px; padding-left: 16px; }
    }
  `];

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (changed.has('email')) {
      this.draftEmail = typeof this.email === 'string' ? this.email : '';
      this.localError = undefined;
      this.actionLocked = false;
    }
    if ((changed.has('pending') && !this.pending) || changed.has('error') || changed.has('status')) {
      this.actionLocked = false;
    }
  }

  override disconnectedCallback(): void {
    this.actionLocked = true;
    super.disconnectedCallback();
  }

  private updateDraft(event: Event): void {
    const target = event.target;
    if (!(target instanceof HTMLInputElement)) return;
    this.draftEmail = target.value;
    this.localError = undefined;
  }

  private submit(): void {
    if (this.pending || this.actionLocked) return;
    const normalized = validEmail(this.draftEmail);
    if (!normalized) {
      this.localError = t('auth.passwordHint.invalidEmail');
      return;
    }
    this.draftEmail = normalized;
    this.localError = undefined;
    this.actionLocked = true;
    this.requestUpdate();
    emit<PasswordHintEmailDetail>(this, 'vw-password-hint-submit', { email: normalized });
  }

  private back(): void {
    if (this.pending || this.actionLocked) return;
    this.actionLocked = true;
    this.requestUpdate();
    emit<PasswordHintEmailDetail>(this, 'vw-password-hint-back', {
      email: canonicalEmail(this.draftEmail),
    });
  }

  private keydown(event: KeyboardEvent): void {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    this.submit();
  }

  private feedback() {
    const error = this.localError ?? this.error;
    if (error) {
      return html`<div id="password-hint-feedback" class="feedback"><vw-status-message tone="danger" .icon=${'alert'} .message=${error}></vw-status-message></div>`;
    }
    if (this.status === 'sent') {
      return html`<div id="password-hint-feedback" class="feedback"><vw-status-message tone="success" .icon=${'check'} .message=${t('auth.passwordHint.success')}></vw-status-message></div>`;
    }
    if (this.status === 'hint' && this.message) {
      return html`<div id="password-hint-feedback" class="feedback"><vw-status-message tone="info" .icon=${'key'} .message=${this.message}></vw-status-message></div>`;
    }
    if (this.status === 'no_hint') {
      return html`<div id="password-hint-feedback" class="feedback"><vw-status-message tone="info" .message=${t('auth.passwordHint.noHint')}></vw-status-message></div>`;
    }
    if (this.status === 'unavailable') {
      return html`<div id="password-hint-feedback" class="feedback"><vw-status-message tone="danger" .icon=${'alert'} .message=${t('auth.passwordHint.unavailable')}></vw-status-message></div>`;
    }
    if (this.pending) {
      return html`<div id="password-hint-feedback" class="feedback"><vw-status-message tone="info" .message=${t('auth.passwordHint.pending')}></vw-status-message></div>`;
    }
    return nothing;
  }

  protected override render() {
    const completed = this.status !== undefined && !this.error && !this.localError;
    const submitDisabled = this.pending || this.actionLocked || completed;
    const backDisabled = this.pending || this.actionLocked;
    const describedBy = `password-hint-description${this.localError || this.error || this.status || this.pending ? ' password-hint-feedback' : ''}`;
    return html`
      <section class="surface" aria-labelledby="password-hint-title" aria-busy=${this.pending ? 'true' : 'false'}>
        <div class="head">
          <vw-logo variant="header"></vw-logo>
          <div class="head-copy">
            <h1 id="password-hint-title">${t('auth.passwordHint.title')}</h1>
            <p id="password-hint-description" class="description">${t('auth.passwordHint.description')}</p>
          </div>
        </div>
        <form novalidate @submit=${(event: SubmitEvent) => { event.preventDefault(); this.submit(); }}>
          <label class="field" for="password-hint-email">
            <span class="field-label">${t('auth.passwordHint.email')}</span>
            <input
              id="password-hint-email"
              class="input"
              type="email"
              inputmode="email"
              autocomplete="email"
              maxlength=${MAX_EMAIL_LENGTH}
              required
              .value=${this.draftEmail}
              aria-invalid=${this.localError ? 'true' : 'false'}
              aria-describedby=${describedBy}
              ?disabled=${submitDisabled}
              @input=${(event: Event) => this.updateDraft(event)}
              @keydown=${(event: KeyboardEvent) => this.keydown(event)}
            />
          </label>
          ${this.feedback()}
          <div class="actions">
            <button type="submit" class="btn primary" ?disabled=${submitDisabled}>${t('auth.passwordHint.submit')}</button>
            <button type="button" class="btn outline" ?disabled=${backDisabled} @click=${() => this.back()}>${t('auth.passwordHint.back')}</button>
          </div>
        </form>
      </section>
    `;
  }
}

function canonicalEmail(input: string): string {
  return input.trim().toLowerCase();
}

function validEmail(input: string): string | undefined {
  if (containsControl(input)) return undefined;
  const email = canonicalEmail(input);
  if (email.length < 3 || email.length > MAX_EMAIL_LENGTH || !/^[^@\s]+@[^@\s]+$/u.test(email)) {
    return undefined;
  }
  return email;
}

function containsControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

customElements.define('vw-password-hint-view', VwPasswordHintView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-password-hint-view': VwPasswordHintView;
  }
}
