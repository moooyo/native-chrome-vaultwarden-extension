import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import {
  generatePassword,
  DEFAULT_PASSWORD_OPTIONS,
  type PasswordGenOptions,
} from '../../../core/generator/password.js';
import {
  generatePassphrase,
  DEFAULT_PASSPHRASE_OPTIONS,
  type PassphraseGenOptions,
} from '../../../core/generator/passphrase.js';
import {
  generatePlusAddressedEmail,
  generateCatchAllEmail,
  generateRandomWordUsername,
  DEFAULT_USERNAME_OPTIONS,
  type UsernameGenOptions,
  type UsernameType,
} from '../../../core/generator/username.js';
import type { CopyDetail, GeneratorHistoryAddDetail } from '../types.js';

type GenMode = 'password' | 'passphrase' | 'username';

function clampInt(value: string, min: number, max: number, fallback: number): number {
  const n = Number(value);
  return Number.isFinite(n) ? Math.min(Math.max(Math.trunc(n), min), max) : fallback;
}

/**
 * The standalone password/passphrase/username generator. Every value is produced locally by the
 * core generator functions — no worker request, no vault secret, no network. The root owns the
 * in-memory history (rendered from the `history` prop and mutated only via `vw-history-add` /
 * `vw-history-clear`) and performs the clipboard copy in response to `vw-copy`. The base email for
 * plus-addressed usernames is prefilled from the injected `accountEmail` when the user has not
 * typed one.
 */
export class VwGeneratorView extends LitElement {
  static override properties = {
    history: { attribute: false },
    accountEmail: { attribute: false },
    mode: { state: true },
    usernameType: { state: true },
    current: { state: true },
    lengthInput: { state: true },
    wordsInput: { state: true },
    separatorInput: { state: true },
    baseEmail: { state: true },
    domain: { state: true },
    unLenInput: { state: true },
    lowercase: { state: true },
    uppercase: { state: true },
    numbers: { state: true },
    special: { state: true },
    avoidAmbiguous: { state: true },
    passphraseCapitalize: { state: true },
    passphraseNumber: { state: true },
    usernameCapitalize: { state: true },
    usernameNumber: { state: true },
  };

  declare history: readonly string[];
  declare accountEmail: string | undefined;
  declare mode: GenMode;
  declare usernameType: UsernameType;
  declare current: string;
  declare lengthInput: string;
  declare wordsInput: string;
  declare separatorInput: string;
  declare baseEmail: string;
  declare domain: string;
  declare unLenInput: string;
  declare lowercase: boolean;
  declare uppercase: boolean;
  declare numbers: boolean;
  declare special: boolean;
  declare avoidAmbiguous: boolean;
  declare passphraseCapitalize: boolean;
  declare passphraseNumber: boolean;
  declare usernameCapitalize: boolean;
  declare usernameNumber: boolean;

  private prefilled = false;

  constructor() {
    super();
    this.history = [];
    this.accountEmail = undefined;
    this.mode = 'password';
    this.usernameType = 'plusAddressed';
    this.current = '';
    this.lengthInput = String(DEFAULT_PASSWORD_OPTIONS.length);
    this.wordsInput = String(DEFAULT_PASSPHRASE_OPTIONS.numWords);
    this.separatorInput = DEFAULT_PASSPHRASE_OPTIONS.separator;
    this.baseEmail = '';
    this.domain = '';
    this.unLenInput = String(DEFAULT_USERNAME_OPTIONS.randomLength);
    this.lowercase = DEFAULT_PASSWORD_OPTIONS.lowercase;
    this.uppercase = DEFAULT_PASSWORD_OPTIONS.uppercase;
    this.numbers = DEFAULT_PASSWORD_OPTIONS.numbers;
    this.special = DEFAULT_PASSWORD_OPTIONS.special;
    this.avoidAmbiguous = DEFAULT_PASSWORD_OPTIONS.avoidAmbiguous;
    this.passphraseCapitalize = DEFAULT_PASSPHRASE_OPTIONS.capitalize;
    this.passphraseNumber = DEFAULT_PASSPHRASE_OPTIONS.includeNumber;
    this.usernameCapitalize = DEFAULT_USERNAME_OPTIONS.capitalize;
    this.usernameNumber = DEFAULT_USERNAME_OPTIONS.includeNumber;
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
      .seg {
        display: flex;
        gap: 4px;
        margin-bottom: 12px;
      }
      .seg-btn {
        flex: 1;
        height: 30px;
        border: 1px solid var(--vw-line);
        border-radius: var(--vw-radius-control);
        background: var(--vw-panel);
        color: var(--vw-muted);
        font-family: var(--vw-font-ui);
        font-size: 13px;
        cursor: pointer;
      }
      .seg-btn.is-active {
        border-color: var(--vw-blue-600);
        color: var(--vw-blue-600);
      }
      .readout {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 10px;
        border: 1px solid var(--vw-line);
        border-radius: var(--vw-radius-control);
        margin-bottom: 12px;
      }
      .out {
        flex: 1;
        min-width: 0;
        word-break: break-all;
        font-family: var(--vw-font-mono);
        font-size: 13px;
      }
      .options {
        display: flex;
        flex-direction: column;
        gap: 8px;
        margin-bottom: 12px;
      }
      .row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        font-size: 13px;
      }
      .row .input {
        width: 90px;
      }
      .check {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 13px;
      }
      .field {
        display: flex;
        flex-direction: column;
        gap: 4px;
        font-size: 12px;
        color: var(--vw-muted);
      }
      .block {
        width: 100%;
      }
      .history {
        margin-top: 12px;
        border-top: 1px solid var(--vw-line);
        padding-top: 8px;
      }
      .history-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        font-size: 12px;
        color: var(--vw-muted);
        margin-bottom: 6px;
      }
      .hist-row {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .hist-val {
        flex: 1;
        min-width: 0;
        word-break: break-all;
        font-family: var(--vw-font-mono);
        font-size: 12px;
      }
      .link {
        border: none;
        background: transparent;
        color: var(--vw-blue-600);
        font-size: 12px;
        cursor: pointer;
      }
      svg {
        width: 16px;
        height: 16px;
      }
    `,
  ];

  override connectedCallback(): void {
    super.connectedCallback();
    // compute() reads only reactive fields (never the DOM), so seeding the initial value here —
    // before the first render — avoids scheduling a second update from firstUpdated.
    if (!this.current) this.regenerate();
  }

  protected override willUpdate(): void {
    // Prefill the plus-addressed base email from the injected account email once the user reaches
    // that mode without having typed one. Done in willUpdate so the value is part of this render.
    if (this.mode === 'username' && this.usernameType === 'plusAddressed' && !this.baseEmail && this.accountEmail && !this.prefilled) {
      this.prefilled = true;
      this.baseEmail = this.accountEmail;
      this.regenerate();
    }
  }

  private label(): string {
    return this.mode === 'username' ? 'Username' : this.mode === 'passphrase' ? 'Passphrase' : 'Password';
  }

  private compute(): string {
    if (this.mode === 'username') {
      const options: UsernameGenOptions = {
        randomLength: clampInt(this.unLenInput, 4, 32, DEFAULT_USERNAME_OPTIONS.randomLength),
        capitalize: this.usernameCapitalize,
        includeNumber: this.usernameNumber,
      };
      if (this.usernameType === 'plusAddressed') return this.baseEmail.trim() ? generatePlusAddressedEmail(this.baseEmail, options) : '';
      if (this.usernameType === 'catchAll') return this.domain.trim() ? generateCatchAllEmail(this.domain, options) : '';
      return generateRandomWordUsername(options);
    }
    if (this.mode === 'passphrase') {
      const options: PassphraseGenOptions = {
        numWords: clampInt(this.wordsInput, 3, 20, DEFAULT_PASSPHRASE_OPTIONS.numWords),
        separator: this.separatorInput || '-',
        capitalize: this.passphraseCapitalize,
        includeNumber: this.passphraseNumber,
      };
      return generatePassphrase(options);
    }
    const options: PasswordGenOptions = {
      ...DEFAULT_PASSWORD_OPTIONS,
      length: clampInt(this.lengthInput, 4, 128, DEFAULT_PASSWORD_OPTIONS.length),
      lowercase: this.lowercase,
      uppercase: this.uppercase,
      numbers: this.numbers,
      special: this.special,
      avoidAmbiguous: this.avoidAmbiguous,
    };
    return generatePassword(options);
  }

  /** Recompute the shown value from the current options without recording history. */
  private regenerate(): void {
    this.current = this.compute();
  }

  private emitHistoryAdd(value: string): void {
    this.dispatchEvent(new CustomEvent<GeneratorHistoryAddDetail>('vw-history-add', { detail: { value }, bubbles: true, composed: true }));
  }

  /** Explicit Regenerate: record the value being replaced, then produce a fresh one. */
  private regenerateAndRecord(): void {
    if (this.current) this.emitHistoryAdd(this.current);
    this.regenerate();
  }

  private copy(): void {
    if (!this.current) return;
    this.emitHistoryAdd(this.current);
    this.dispatchEvent(new CustomEvent<CopyDetail>('vw-copy', { detail: { value: this.current, label: this.label() }, bubbles: true, composed: true }));
  }

  private copyHistory(value: string): void {
    this.dispatchEvent(new CustomEvent<CopyDetail>('vw-copy', { detail: { value, label: 'Password' }, bubbles: true, composed: true }));
  }

  private clearHistory(): void {
    this.dispatchEvent(new CustomEvent('vw-history-clear', { bubbles: true, composed: true }));
  }

  private back(): void {
    this.dispatchEvent(new CustomEvent('vw-item-back', { bubbles: true, composed: true }));
  }

  private setMode(mode: GenMode): void {
    if (this.mode === mode) return;
    this.mode = mode;
    this.regenerate();
  }

  private renderCheck(label: string, checked: boolean, marker: string, set: (value: boolean) => void) {
    return html`
      <label class="check">
        <input type="checkbox" data-check=${marker} .checked=${checked}
          @change=${(e: Event) => { set((e.target as HTMLInputElement).checked); this.regenerate(); }} />
        <span>${label}</span>
      </label>
    `;
  }

  private renderPasswordOptions() {
    return html`
      <div class="options">
        <label class="row"><span>Length</span>
          <input class="input" data-length type="number" min="4" max="128" .value=${this.lengthInput}
            @input=${(e: Event) => { this.lengthInput = (e.target as HTMLInputElement).value; this.regenerate(); }} />
        </label>
        ${this.renderCheck('Lowercase (a-z)', this.lowercase, 'lower', (v) => { this.lowercase = v; })}
        ${this.renderCheck('Uppercase (A-Z)', this.uppercase, 'upper', (v) => { this.uppercase = v; })}
        ${this.renderCheck('Numbers (0-9)', this.numbers, 'numbers', (v) => { this.numbers = v; })}
        ${this.renderCheck('Special (!@#$%^&*)', this.special, 'special', (v) => { this.special = v; })}
        ${this.renderCheck('Avoid ambiguous (Il1O0)', this.avoidAmbiguous, 'ambiguous', (v) => { this.avoidAmbiguous = v; })}
      </div>
    `;
  }

  private renderPassphraseOptions() {
    return html`
      <div class="options">
        <label class="row"><span>Words</span>
          <input class="input" data-words type="number" min="3" max="20" .value=${this.wordsInput}
            @input=${(e: Event) => { this.wordsInput = (e.target as HTMLInputElement).value; this.regenerate(); }} />
        </label>
        <label class="row"><span>Separator</span>
          <input class="input" data-separator maxlength="3" .value=${this.separatorInput}
            @input=${(e: Event) => { this.separatorInput = (e.target as HTMLInputElement).value; this.regenerate(); }} />
        </label>
        ${this.renderCheck('Capitalize', this.passphraseCapitalize, 'cap', (v) => { this.passphraseCapitalize = v; })}
        ${this.renderCheck('Include number', this.passphraseNumber, 'num', (v) => { this.passphraseNumber = v; })}
      </div>
    `;
  }

  private renderUsernameOptions() {
    return html`
      <div class="seg" role="tablist">
        <button type="button" class="seg-btn ${this.usernameType === 'plusAddressed' ? 'is-active' : ''}" data-ut-plus role="tab"
          aria-selected=${this.usernameType === 'plusAddressed' ? 'true' : 'false'}
          @click=${() => { this.usernameType = 'plusAddressed'; this.regenerate(); }}>Plus</button>
        <button type="button" class="seg-btn ${this.usernameType === 'catchAll' ? 'is-active' : ''}" data-ut-catch role="tab"
          aria-selected=${this.usernameType === 'catchAll' ? 'true' : 'false'}
          @click=${() => { this.usernameType = 'catchAll'; this.regenerate(); }}>Catch-all</button>
        <button type="button" class="seg-btn ${this.usernameType === 'randomWord' ? 'is-active' : ''}" data-ut-word role="tab"
          aria-selected=${this.usernameType === 'randomWord' ? 'true' : 'false'}
          @click=${() => { this.usernameType = 'randomWord'; this.regenerate(); }}>Random word</button>
      </div>
      <div class="options">
        ${this.usernameType === 'plusAddressed'
          ? html`<label class="field"><span>Base email</span>
              <input class="input" data-base type="email" placeholder="you@example.com" .value=${this.baseEmail}
                @input=${(e: Event) => { this.baseEmail = (e.target as HTMLInputElement).value; this.regenerate(); }} /></label>`
          : nothing}
        ${this.usernameType === 'catchAll'
          ? html`<label class="field"><span>Catch-all domain</span>
              <input class="input" data-domain type="text" placeholder="example.com" .value=${this.domain}
                @input=${(e: Event) => { this.domain = (e.target as HTMLInputElement).value; this.regenerate(); }} /></label>`
          : nothing}
        ${this.usernameType === 'randomWord'
          ? html`
              ${this.renderCheck('Capitalize', this.usernameCapitalize, 'un-cap', (v) => { this.usernameCapitalize = v; })}
              ${this.renderCheck('Include number', this.usernameNumber, 'un-num', (v) => { this.usernameNumber = v; })}`
          : nothing}
        ${this.usernameType !== 'randomWord'
          ? html`<label class="field"><span>Random length</span>
              <input class="input" data-un-len type="number" min="4" max="32" .value=${this.unLenInput}
                @input=${(e: Event) => { this.unLenInput = (e.target as HTMLInputElement).value; this.regenerate(); }} /></label>`
          : nothing}
      </div>
    `;
  }

  private renderHistory() {
    if (this.history.length === 0) return nothing;
    return html`
      <div class="history">
        <div class="history-head">
          <span>${uiIcon('refresh')} History</span>
          <button type="button" class="link" data-clear @click=${() => this.clearHistory()}>Clear</button>
        </div>
        ${this.history.map((value) => html`
          <div class="hist-row">
            <code class="hist-val">${value}</code>
            <button type="button" class="icon-button" data-copy-hist title="Copy" aria-label="Copy password" @click=${() => this.copyHistory(value)}>${uiIcon('copy')}</button>
          </div>
        `)}
      </div>
    `;
  }

  protected override render() {
    const placeholder = this.mode === 'username' ? 'Enter a base email / domain' : 'Enable at least one character set';
    return html`
      <div class="head">
        <button type="button" class="icon-button" data-back title="Back" aria-label="Back" @click=${() => this.back()}>${uiIcon('back')}</button>
        <h1>Generator</h1>
      </div>
      <div class="seg" role="tablist">
        <button type="button" class="seg-btn ${this.mode === 'password' ? 'is-active' : ''}" data-mode-password role="tab"
          aria-selected=${this.mode === 'password' ? 'true' : 'false'} @click=${() => this.setMode('password')}>Password</button>
        <button type="button" class="seg-btn ${this.mode === 'passphrase' ? 'is-active' : ''}" data-mode-passphrase role="tab"
          aria-selected=${this.mode === 'passphrase' ? 'true' : 'false'} @click=${() => this.setMode('passphrase')}>Passphrase</button>
        <button type="button" class="seg-btn ${this.mode === 'username' ? 'is-active' : ''}" data-mode-username role="tab"
          aria-selected=${this.mode === 'username' ? 'true' : 'false'} @click=${() => this.setMode('username')}>Username</button>
      </div>
      <div class="readout">
        <code class="out" data-output>${this.current || placeholder}</code>
        <button type="button" class="icon-button" data-regenerate title="Regenerate" aria-label="Regenerate" @click=${() => this.regenerateAndRecord()}>${uiIcon('refresh')}</button>
      </div>
      ${this.mode === 'username' ? this.renderUsernameOptions() : this.mode === 'passphrase' ? this.renderPassphraseOptions() : this.renderPasswordOptions()}
      <button type="button" class="button primary block" data-copy @click=${() => this.copy()}>${uiIcon('copy')}<span>Copy</span></button>
      ${this.renderHistory()}
    `;
  }
}

customElements.define('vw-generator-view', VwGeneratorView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-generator-view': VwGeneratorView;
  }
}
