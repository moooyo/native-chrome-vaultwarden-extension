import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/toggle.js';
import '../../components/segmented.js';
import { LocalizeController, t } from '../../i18n/index.js';
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
import type { CopyDetail, GeneratorHistoryAddDetail } from '../types.js';

/** The three generation styles the reskinned generator exposes. */
type GenMode = 'random' | 'memorable' | 'pin';

const LENGTH_MIN = 8;
const LENGTH_MAX = 40;

function clampInt(value: string, min: number, max: number, fallback: number): number {
  const n = Number(value);
  return Number.isFinite(n) ? Math.min(Math.max(Math.trunc(n), min), max) : fallback;
}

/** Classifies one output character for the digit/symbol coloring in the result box. */
function charKind(ch: string): 'digit' | 'symbol' | 'letter' {
  if (ch >= '0' && ch <= '9') return 'digit';
  if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) return 'letter';
  return 'symbol';
}

/**
 * The standalone password generator (MiYu design). Every value is produced locally by the core
 * generator functions — no worker request, no vault secret, no network. The popup root owns the
 * in-memory generator history (fed by `vw-history-add`) and performs the clipboard copy in response
 * to `vw-copy`. Three modes map onto the existing core generators: 随机 → random password,
 * 易记 → passphrase (words), PIN → numeric PIN. `history`/`accountEmail` remain part of the public
 * contract the root binds, even though this design surfaces neither a history list nor an email field.
 */
export class VwGeneratorView extends LitElement {
  static override properties = {
    history: { attribute: false },
    accountEmail: { attribute: false },
    mode: { state: true },
    current: { state: true },
    length: { state: true },
    uppercase: { state: true },
    numbers: { state: true },
    symbols: { state: true },
  };

  declare history: readonly string[];
  declare accountEmail: string | undefined;
  declare mode: GenMode;
  declare current: string;
  declare length: number;
  declare uppercase: boolean;
  declare numbers: boolean;
  declare symbols: boolean;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.history = [];
    this.accountEmail = undefined;
    this.mode = 'random';
    this.current = '';
    this.length = Math.min(Math.max(DEFAULT_PASSWORD_OPTIONS.length, LENGTH_MIN), LENGTH_MAX);
    this.uppercase = DEFAULT_PASSWORD_OPTIONS.uppercase;
    this.numbers = DEFAULT_PASSWORD_OPTIONS.numbers;
    this.symbols = DEFAULT_PASSWORD_OPTIONS.special;
  }

  static override styles = [
    themeTokens,
    css`
      :host {
        display: block;
      }
      .wrap {
        display: flex;
        flex-direction: column;
        gap: 12px;
        padding: 12px 14px;
        animation: mvIn 0.2s ease-out;
      }
      .head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
      }
      .head h1 {
        margin: 0;
        font-size: 13px;
        font-weight: 600;
        color: var(--vw-ink);
      }
      .close {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 26px;
        height: 26px;
        padding: 0;
        border: none;
        border-radius: var(--vw-radius-small);
        background: transparent;
        color: var(--vw-text-2);
        cursor: pointer;
        transition: background-color var(--vw-dur-fast);
      }
      .close:hover {
        background: var(--vw-icon-hover);
      }
      .close:focus-visible {
        outline: none;
        box-shadow: var(--vw-focus);
      }
      .close svg {
        width: 15px;
        height: 15px;
      }
      .result {
        background: var(--vw-fill-2);
        border: 1px solid var(--vw-line-1);
        border-radius: var(--vw-radius-card);
        padding: 12px;
      }
      .password {
        font-family: var(--vw-font-mono);
        font-size: 13.5px;
        line-height: 1.6;
        word-break: break-all;
        min-height: 44px;
        color: var(--vw-ink);
      }
      .password .digit {
        color: var(--vw-gen-digit);
      }
      .password .symbol {
        color: var(--vw-gen-symbol);
      }
      .strength {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-top: 10px;
      }
      .track {
        flex: 1;
        height: 4px;
        border-radius: 2px;
        background: var(--vw-track);
        overflow: hidden;
      }
      .fill {
        height: 100%;
        border-radius: 2px;
        transition: width var(--vw-dur), background-color var(--vw-dur);
      }
      .strength-label {
        font-size: 11.5px;
        font-weight: 600;
        white-space: nowrap;
      }
      .length-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
      }
      .length-label {
        font-size: 13px;
        color: var(--vw-text-4);
      }
      .length-pill {
        font-size: 11.5px;
        font-weight: 600;
        color: var(--vw-teal-text);
        background: var(--vw-teal-10);
        border-radius: 6px;
        padding: 2px 8px;
      }
      input[type='range'] {
        width: 100%;
        margin: 0;
        accent-color: var(--vw-accent);
        cursor: pointer;
      }
      .toggles {
        display: flex;
        flex-direction: column;
        gap: 10px;
      }
      .toggle-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
      }
      .toggle-row span {
        font-size: 13px;
        color: var(--vw-text-4);
      }
      .actions {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .copy {
        flex: 1;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 7px;
        height: 34px;
        border: none;
        border-radius: var(--vw-radius-control);
        background: var(--vw-primary-bg);
        color: var(--vw-primary-fg);
        font-family: var(--vw-font-ui);
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        transition: background-color var(--vw-dur-fast);
      }
      .copy:hover {
        background: var(--vw-primary-bg-hover);
      }
      .regen {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 34px;
        height: 34px;
        padding: 0;
        border: 1px solid var(--vw-line-3);
        border-radius: var(--vw-radius-control);
        background: transparent;
        color: var(--vw-text-4);
        cursor: pointer;
        transition: background-color var(--vw-dur-fast);
      }
      .regen:hover {
        background: var(--vw-row-hover);
      }
      .copy:focus-visible,
      .regen:focus-visible {
        outline: none;
        box-shadow: var(--vw-focus);
      }
      .copy svg,
      .regen svg {
        width: 16px;
        height: 16px;
      }
    `,
  ];

  override connectedCallback(): void {
    super.connectedCallback();
    // compute() reads only reactive fields (never the DOM), so seeding the initial value here —
    // before the first render — avoids scheduling a second update.
    if (!this.current) this.regenerate();
  }

  /** Runs the core generator matching the current mode/options. Never touches the DOM. */
  private compute(): string {
    if (this.mode === 'memorable') {
      const options: PassphraseGenOptions = {
        ...DEFAULT_PASSPHRASE_OPTIONS,
        numWords: Math.min(Math.max(this.length, 3), 20),
        capitalize: this.uppercase,
        includeNumber: this.numbers,
      };
      return generatePassphrase(options);
    }
    if (this.mode === 'pin') {
      const options: PasswordGenOptions = {
        ...DEFAULT_PASSWORD_OPTIONS,
        length: this.length,
        lowercase: false,
        uppercase: false,
        numbers: true,
        special: false,
        minNumbers: 0,
        minSpecial: 0,
        avoidAmbiguous: false,
      };
      return generatePassword(options);
    }
    const options: PasswordGenOptions = {
      ...DEFAULT_PASSWORD_OPTIONS,
      length: this.length,
      lowercase: true,
      uppercase: this.uppercase,
      numbers: this.numbers,
      special: this.symbols,
    };
    return generatePassword(options);
  }

  /** Recompute the shown value from the current options without recording history. */
  private regenerate(): void {
    this.current = this.compute();
  }

  private emitHistoryAdd(value: string): void {
    emit<GeneratorHistoryAddDetail>(this, 'vw-history-add', { value });
  }

  /** Explicit Regenerate: record the value being replaced, then produce a fresh one. */
  private regenerateAndRecord(): void {
    if (this.current) this.emitHistoryAdd(this.current);
    this.regenerate();
  }

  private copyLabel(): string {
    return this.mode === 'pin' ? t('gen.modePin') : t('detail.password');
  }

  private copy(): void {
    if (!this.current) return;
    this.emitHistoryAdd(this.current);
    emit<CopyDetail>(this, 'vw-copy', { value: this.current, label: this.copyLabel() });
  }

  private back(): void {
    emit(this, 'vw-item-back');
  }

  private setMode(mode: GenMode): void {
    if (this.mode === mode) return;
    this.mode = mode;
    this.regenerate();
  }

  private setLength(value: string): void {
    this.length = clampInt(value, LENGTH_MIN, LENGTH_MAX, this.length);
    this.regenerate();
  }

  private setToggle(key: 'uppercase' | 'numbers' | 'symbols', checked: boolean): void {
    this[key] = checked;
    this.regenerate();
  }

  /** Length-based strength: matches the design's tiers plus a proportional bar width. */
  private strength(): { label: string; color: string; width: number } {
    const len = this.current.length;
    const width = Math.max(0, Math.min(100, Math.round((len / 20) * 100)));
    if (len >= 16) return { label: t('gen.strengthStrong'), color: 'var(--vw-strength-strong)', width };
    if (len >= 12) return { label: t('gen.strengthGood'), color: 'var(--vw-strength-good)', width };
    if (len >= 10) return { label: t('gen.strengthMid'), color: 'var(--vw-strength-mid)', width };
    return { label: t('gen.strengthWeak'), color: 'var(--vw-strength-weak)', width };
  }

  private renderPassword() {
    return [...this.current].map((ch) => {
      const kind = charKind(ch);
      return kind === 'letter' ? html`<span>${ch}</span>` : html`<span class=${kind}>${ch}</span>`;
    });
  }

  private renderToggleRow(label: string, key: 'uppercase' | 'numbers' | 'symbols', marker: string) {
    return html`
      <div class="toggle-row">
        <span>${label}</span>
        <vw-toggle
          data-toggle=${marker}
          .checked=${this[key]}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => this.setToggle(key, e.detail.checked)}
        ></vw-toggle>
      </div>
    `;
  }

  protected override render() {
    const strength = this.strength();
    const modes = [
      { id: 'random', label: t('gen.modeRandom') },
      { id: 'memorable', label: t('gen.modeWords') },
      { id: 'pin', label: t('gen.modePin') },
    ];
    return html`
      <div class="wrap">
        <div class="head">
          <h1>${t('gen.title')}</h1>
          <button type="button" class="close" data-close title=${t('common.close')} aria-label=${t('common.close')} @click=${() => this.back()}>
            ${uiIcon('close')}
          </button>
        </div>

        <div class="result">
          <div class="password" data-output>${this.renderPassword()}</div>
          <div class="strength">
            <div class="track"><div class="fill" data-strength-fill style=${`width:${strength.width}%;background:${strength.color}`}></div></div>
            <span class="strength-label" data-strength style=${`color:${strength.color}`}>${strength.label}</span>
          </div>
        </div>

        <div class="length-row">
          <span class="length-label">${t('gen.length')}</span>
          <span class="length-pill" data-length-value>${this.length}</span>
        </div>
        <input
          type="range"
          data-length
          min=${LENGTH_MIN}
          max=${LENGTH_MAX}
          .value=${String(this.length)}
          @input=${(e: Event) => this.setLength((e.target as HTMLInputElement).value)}
        />

        <div class="toggles">
          ${this.renderToggleRow(t('gen.upper'), 'uppercase', 'upper')}
          ${this.renderToggleRow(t('gen.number'), 'numbers', 'number')}
          ${this.renderToggleRow(t('gen.symbol'), 'symbols', 'symbol')}
        </div>

        <vw-segmented
          data-mode
          .options=${modes}
          .value=${this.mode}
          @vw-segmented-change=${(e: CustomEvent<{ id: string }>) => this.setMode(e.detail.id as GenMode)}
        ></vw-segmented>

        <div class="actions">
          <button type="button" class="copy" data-copy @click=${() => this.copy()}>${uiIcon('copy')}<span>${t('gen.copy')}</span></button>
          <button type="button" class="regen" data-regenerate title=${t('gen.regenerate')} aria-label=${t('gen.regenerate')} @click=${() => this.regenerateAndRecord()}>
            ${uiIcon('refresh')}
          </button>
        </div>
      </div>
    `;
  }
}

customElements.define('vw-generator-view', VwGeneratorView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-generator-view': VwGeneratorView;
  }
}
