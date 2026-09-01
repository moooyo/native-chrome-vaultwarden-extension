import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
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
} from '../../../core/generator/passphrase.js';
import {
  generateCatchAllEmail,
  generatePlusAddressedEmail,
  generateRandomWordUsername,
  type UsernameGenOptions,
  type UsernameType,
} from '../../../core/generator/username.js';
import { PASSPHRASE_WORDLIST } from '../../../core/generator/wordlist.js';
import {
  applyGeneratorPolicySnapshot,
  parseGeneratorPolicySnapshot,
  UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
  type GeneratorPolicySnapshot,
  type PasswordGeneratorOptions,
} from '../../../core/generator/enterprise-password-policy.js';
import {
  getPrefs,
  setPref,
  setPrefs,
  subscribePrefs,
  type GeneratorPreferenceMode,
  type MiyuPrefs,
} from '../../prefs.js';
import type { GeneratorHistoryEntry, GeneratorHistoryEntryType } from '../../../core/generator/history.js';
import type { CopyDetail, GeneratorHistoryAddDetail, GeneratorSelectionDetail } from '../types.js';
import '../../components/status-message.js';

/** Password, passphrase, PIN, and username generation surfaces. */
type GenMode = GeneratorPreferenceMode;

const PASSWORD_LENGTH_MIN = 5;
const PASSWORD_LENGTH_MAX = 128;
const PIN_LENGTH_MIN = 8;
const PIN_LENGTH_MAX = 40;
const MINIMUM_COUNT_MIN = 1;
const MINIMUM_COUNT_MAX = 9;

// Memorable (passphrase) word count is a distinct control from the character-length slider: a
// passphrase is measured in words, not characters, so 8–40 characters would be meaningless here.
const WORDS_MIN = 3;
const WORDS_MAX = 20;

const USERNAME_LENGTH_MIN = 4;
const USERNAME_LENGTH_MAX = 32;

// Entropy tiers (bits). A digit-only PIN or a short passphrase is rated on real entropy, not raw
// character count, so a 16-digit PIN (~53 bits) reads "fair", never "very strong".
const BITS_VERY_STRONG = 128;
const BITS_STRONG = 80;
const BITS_FAIR = 50;
const BITS_FULL_BAR = 128;

/** Bits of entropy contributed by each independently-chosen passphrase word. */
const BITS_PER_WORD = Math.log2(PASSPHRASE_WORDLIST.length);

function clampInt(value: string, min: number, max: number, fallback: number): number {
  const n = Number(value);
  return Number.isFinite(n) ? Math.min(Math.max(Math.trunc(n), min), max) : fallback;
}

function normalizeAccountEmail(value: string | undefined): string | undefined {
  const email = value?.trim();
  if (!email || email.length > 254 || !/^[^@\s]+@[^@\s]+$/u.test(email)) return undefined;
  const at = email.indexOf('@');
  const local = email.slice(0, at);
  if (
    !local
    || local.length > 64
    || local.startsWith('.')
    || local.endsWith('.')
    || local.includes('..')
    || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/i.test(local)
  ) return undefined;
  const domain = normalizeCatchAllDomain(email.slice(at + 1), local.length);
  if (!domain) return undefined;
  return `${local}@${domain}`;
}

function normalizePlusAddressBase(value: string | undefined, randomLength: number): string | undefined {
  const email = normalizeAccountEmail(value);
  if (!email) return undefined;
  const at = email.indexOf('@');
  const separatorLength = email.slice(0, at).includes('+') ? 0 : 1;
  const generatedLocalLength = at + separatorLength + randomLength;
  if (generatedLocalLength > 64 || email.length + separatorLength + randomLength > 254) return undefined;
  return email;
}

function normalizeCatchAllDomain(value: string, localLength = 0): string | undefined {
  const domain = value.trim().replace(/^@+/, '');
  if (!domain || domain.length > 253 || /[\s/@\\:?#]/u.test(domain)) return undefined;
  try {
    const hostname = new URL(`https://${domain}`).hostname.toLowerCase();
    if (!hostname || hostname.endsWith('.')) return undefined;
    const labels = hostname.split('.');
    if (labels.some((label) => (
      !label
      || label.length > 63
      || !/^[a-z0-9-]+$/i.test(label)
      || label.startsWith('-')
      || label.endsWith('-')
    ))) return undefined;
    if (localLength > 0 && localLength + 1 + hostname.length > 254) return undefined;
    return hostname;
  } catch {
    return undefined;
  }
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
 * generator history through structured events and performs clipboard copy in response to `vw-copy`.
 * Four modes map onto the existing core generators: password, passphrase, numeric PIN, and username.
 */
export class VwGeneratorView extends LitElement {
  static override properties = {
    history: { attribute: false },
    accountEmail: { attribute: false },
    defaultLength: { type: Number },
    defaultUppercase: { type: Boolean },
    defaultNumbers: { type: Boolean },
    defaultSymbols: { type: Boolean },
    generatorPolicy: { attribute: false },
    selectionTarget: { attribute: false },
    websiteUri: { attribute: false },
    mode: { state: true },
    current: { state: true },
    length: { state: true },
    pinLength: { state: true },
    words: { state: true },
    lowercase: { state: true },
    uppercase: { state: true },
    numbers: { state: true },
    symbols: { state: true },
    minNumbers: { state: true },
    minSpecial: { state: true },
    avoidAmbiguous: { state: true },
    passphraseCapitalize: { state: true },
    passphraseNumber: { state: true },
    usernameType: { state: true },
    usernameLength: { state: true },
    usernameCapitalize: { state: true },
    usernameNumber: { state: true },
    plusAddressEmail: { state: true },
    catchAllDomain: { state: true },
    validationMessage: { state: true },
  };

  declare history: readonly GeneratorHistoryEntry[];
  declare accountEmail: string | undefined;
  declare defaultLength: number;
  declare defaultUppercase: boolean;
  declare defaultNumbers: boolean;
  declare defaultSymbols: boolean;
  declare generatorPolicy: GeneratorPolicySnapshot;
  declare selectionTarget: GeneratorSelectionDetail['target'] | null;
  declare websiteUri: string | undefined;
  declare mode: GenMode;
  declare current: string;
  declare length: number;
  declare pinLength: number;
  declare words: number;
  declare lowercase: boolean;
  declare uppercase: boolean;
  declare numbers: boolean;
  declare symbols: boolean;
  declare minNumbers: number;
  declare minSpecial: number;
  declare avoidAmbiguous: boolean;
  declare passphraseCapitalize: boolean;
  declare passphraseNumber: boolean;
  declare usernameType: UsernameType;
  declare usernameLength: number;
  declare usernameCapitalize: boolean;
  declare usernameNumber: boolean;
  declare plusAddressEmail: string;
  declare catchAllDomain: string;
  declare validationMessage: string;

  private i18n = new LocalizeController(this);
  private unsubscribePrefs: (() => void) | undefined;

  constructor() {
    super();
    const prefs = getPrefs();
    this.history = [];
    this.accountEmail = undefined;
    this.defaultLength = prefs.genLength;
    this.defaultUppercase = prefs.genUppercase;
    this.defaultNumbers = prefs.genNumbers;
    this.defaultSymbols = prefs.genSymbols;
    this.generatorPolicy = UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT;
    this.selectionTarget = null;
    this.websiteUri = undefined;
    this.mode = prefs.genMode;
    this.current = '';
    this.length = prefs.genLength;
    this.pinLength = prefs.genPinLength;
    this.words = prefs.genPassphraseWords;
    this.lowercase = prefs.genLowercase;
    this.uppercase = prefs.genUppercase;
    this.numbers = prefs.genNumbers;
    this.symbols = prefs.genSymbols;
    this.minNumbers = prefs.genMinNumbers;
    this.minSpecial = prefs.genMinSpecial;
    this.avoidAmbiguous = prefs.genAvoidAmbiguous;
    this.passphraseCapitalize = prefs.genPassphraseCapitalize;
    this.passphraseNumber = prefs.genPassphraseNumber;
    this.usernameType = prefs.genUsernameType;
    this.usernameLength = prefs.genUsernameLength;
    this.usernameCapitalize = prefs.genUsernameCapitalize;
    this.usernameNumber = prefs.genUsernameNumber;
    this.plusAddressEmail = '';
    this.catchAllDomain = '';
    this.validationMessage = '';
  }

  override connectedCallback(): void {
    super.connectedCallback();
    this.unsubscribePrefs = subscribePrefs(() => this.applyStoredPrefs(getPrefs()));
    if (this.hasUpdated) this.applyStoredPrefs(getPrefs());
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.unsubscribePrefs?.();
    this.unsubscribePrefs = undefined;
  }

  static override styles = [
    themeTokens,
    css`
      :host {
        display: block;
        height: 100%;
        min-height: 0;
      }
      .wrap {
        box-sizing: border-box;
        display: flex;
        flex-direction: column;
        gap: 12px;
        height: 100%;
        overflow-y: auto;
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
      .username-context {
        display: flex;
        flex-direction: column;
        gap: 5px;
      }
      .field-label {
        font-size: 12px;
        font-weight: 600;
        color: var(--vw-text-3);
      }
      .text-input {
        width: 100%;
        box-sizing: border-box;
        height: 34px;
        padding: 0 10px;
        border: 1px solid var(--vw-line-3);
        border-radius: var(--vw-radius-control);
        background: var(--vw-card);
        color: var(--vw-ink);
        font: 13px/1 var(--vw-font-ui);
      }
      .text-input:focus-visible {
        outline: none;
        box-shadow: var(--vw-focus);
      }
      .text-input[aria-invalid='true'] {
        border-color: var(--vw-danger-border);
      }
      .hint,
      .validation {
        font-size: 11.5px;
        line-height: 1.45;
      }
      .hint {
        color: var(--vw-text-2);
      }
      .validation {
        color: var(--vw-danger);
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
      .minimums {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 10px;
      }
      .minimum-control {
        display: flex;
        min-width: 0;
        flex-direction: column;
        gap: 5px;
        color: var(--vw-text-4);
        font-size: 12px;
      }
      .minimum-control input {
        box-sizing: border-box;
        width: 100%;
        height: 34px;
        padding: 0 9px;
        border: 1px solid var(--vw-line-3);
        border-radius: var(--vw-radius-control);
        background: var(--vw-card);
        color: var(--vw-ink);
        font: 12px/1 var(--vw-font-mono);
      }
      .minimum-control input:focus-visible {
        outline: none;
        box-shadow: var(--vw-focus);
      }
      .minimum-control input:disabled {
        opacity: 0.55;
      }
      .username-checkbox {
        width: 18px;
        height: 18px;
        margin: 0;
        accent-color: var(--vw-accent);
        cursor: pointer;
      }
      .username-size {
        display: flex;
        flex-direction: column;
        gap: 8px;
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
      .copy:not(:disabled):hover {
        background: var(--vw-primary-bg-hover);
      }
      .history { border-top:1px solid var(--vw-line-1); padding-top:10px; }
      .history-head { display:flex; align-items:center; justify-content:space-between; gap:8px; }
      .history-head h2 { margin:0; font-size:12px; font-weight:600; color:var(--vw-text-3); }
      .history-clear { border:0; background:transparent; color:var(--vw-danger); font:500 11px/1 var(--vw-font-ui); cursor:pointer; }
      .history-list { display:flex; flex-direction:column; gap:6px; margin-top:8px; max-height:180px; overflow:auto; }
      .history-item { display:grid; grid-template-columns:minmax(0,1fr) 28px; gap:8px; align-items:center; padding:7px 8px; border-radius:6px; background:var(--vw-fill-2); }
      .history-value { font:12px/1.45 var(--vw-font-mono); color:var(--vw-ink); overflow-wrap:anywhere; white-space:normal; }
      .history-meta { margin-top:2px; font-size:10px; color:var(--vw-text-2); }
      .history-copy { width:28px; height:28px; padding:0; border:0; border-radius:6px; display:grid; place-items:center; background:transparent; color:var(--vw-text-3); cursor:pointer; }
      .history-copy:hover { background:var(--vw-row-hover); }
      .history-copy svg { width:14px; height:14px; }
      .history-empty { margin:8px 0 0; font-size:11px; color:var(--vw-text-2); }
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
      .regen:not(:disabled):hover {
        background: var(--vw-row-hover);
      }
      .copy:disabled,
      .regen:disabled {
        cursor: default;
        opacity: 0.5;
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

  protected override willUpdate(changed: PropertyValues<this>): void {
    const accountEmailChanged = changed.has('accountEmail');
    if (accountEmailChanged) this.plusAddressEmail = this.accountEmail?.trim() ?? '';
    const policyChanged = changed.has('generatorPolicy');
    const selectionChanged = changed.has('selectionTarget');
    if (policyChanged) {
      this.restoreStoredPreferenceState(getPrefs());
      const policy = this.policySnapshot();
      if (this.mode !== 'username') {
        if (policy.forcedMode === 'password') this.mode = 'random';
        else if (policy.forcedMode === 'passphrase') this.mode = 'memorable';
        else if (this.mode === 'pin' && policy.policyInEffect) {
          this.mode = policy.password.allowed ? 'random' : 'memorable';
        } else if (this.mode === 'random' && !policy.password.allowed && policy.passphrase.allowed) {
          this.mode = 'memorable';
        } else if (this.mode === 'memorable' && !policy.passphrase.allowed && policy.password.allowed) {
          this.mode = 'random';
        }
      }
    }
    if (policyChanged || selectionChanged) {
      this.applySelectionMode();
      this.regenerate();
    } else if (accountEmailChanged && this.mode === 'username' && this.usernameType === 'plusAddressed') {
      this.regenerate();
    } else if (!this.current) {
      this.regenerate();
    }
  }

  private applyStoredPrefs(prefs: Readonly<MiyuPrefs>): void {
    this.restoreStoredPreferenceState(prefs);
    this.applySelectionMode();
    this.regenerate();
  }

  private applySelectionMode(): void {
    if (this.selectionTarget === 'username') {
      this.mode = 'username';
      return;
    }
    if (this.selectionTarget === 'password' && (this.mode === 'username' || this.mode === 'pin')) {
      const policy = this.policySnapshot();
      this.mode = policy.password.allowed ? 'random' : 'memorable';
    }
  }

  private restoreStoredPreferenceState(prefs: Readonly<MiyuPrefs>): void {
    this.defaultLength = prefs.genLength;
    this.defaultUppercase = prefs.genUppercase;
    this.defaultNumbers = prefs.genNumbers;
    this.defaultSymbols = prefs.genSymbols;
    this.mode = prefs.genMode;
    this.length = prefs.genLength;
    this.pinLength = prefs.genPinLength;
    this.words = prefs.genPassphraseWords;
    this.lowercase = prefs.genLowercase;
    this.uppercase = prefs.genUppercase;
    this.numbers = prefs.genNumbers;
    this.symbols = prefs.genSymbols;
    this.minNumbers = prefs.genMinNumbers;
    this.minSpecial = prefs.genMinSpecial;
    this.avoidAmbiguous = prefs.genAvoidAmbiguous;
    this.passphraseCapitalize = prefs.genPassphraseCapitalize;
    this.passphraseNumber = prefs.genPassphraseNumber;
    this.usernameType = prefs.genUsernameType;
    this.usernameLength = prefs.genUsernameLength;
    this.usernameCapitalize = prefs.genUsernameCapitalize;
    this.usernameNumber = prefs.genUsernameNumber;
  }

  private usernameOptions(): UsernameGenOptions {
    return {
      randomLength: this.usernameLength,
      capitalize: this.usernameCapitalize,
      includeNumber: this.usernameNumber,
    };
  }

  private computeUsername(): string {
    const options = this.usernameOptions();
    if (this.usernameType === 'plusAddressed') {
      const email = normalizePlusAddressBase(this.plusAddressEmail, this.usernameLength);
      return email ? generatePlusAddressedEmail(email, options) : '';
    }
    if (this.usernameType === 'catchAll') {
      const domain = normalizeCatchAllDomain(this.catchAllDomain, this.usernameLength);
      return domain ? generateCatchAllEmail(domain, options) : '';
    }
    return generateRandomWordUsername(options);
  }

  private policySnapshot(): GeneratorPolicySnapshot {
    return parseGeneratorPolicySnapshot(this.generatorPolicy)
      ?? UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT;
  }

  private credentialOptions(): PasswordGeneratorOptions {
    return {
      mode: this.mode === 'memorable' ? 'passphrase' : 'password',
      password: {
        ...DEFAULT_PASSWORD_OPTIONS,
        length: this.length,
        lowercase: this.lowercase,
        uppercase: this.uppercase,
        numbers: this.numbers,
        special: this.symbols,
        minNumbers: this.numbers ? this.minNumbers : 0,
        minSpecial: this.symbols ? this.minSpecial : 0,
        avoidAmbiguous: this.avoidAmbiguous,
      },
      passphrase: {
        ...DEFAULT_PASSPHRASE_OPTIONS,
        numWords: this.words,
        capitalize: this.passphraseCapitalize,
        includeNumber: this.passphraseNumber,
      },
    };
  }

  private policyAllowsMode(mode: GenMode): boolean {
    if (this.selectionTarget === 'username' && mode !== 'username') return false;
    if (this.selectionTarget === 'password' && (mode === 'username' || mode === 'pin')) return false;
    if (mode === 'username') return true;
    const policy = this.policySnapshot();
    if (mode === 'pin') return !policy.malformed && !policy.policyInEffect;
    return mode === 'random' ? policy.password.allowed : policy.passphrase.allowed;
  }

  private canConfigurePassword(): boolean {
    const policy = this.policySnapshot();
    return !policy.malformed && policy.password.allowed;
  }

  private canConfigurePassphrase(): boolean {
    const policy = this.policySnapshot();
    return !policy.malformed && policy.passphrase.allowed;
  }

  private passwordLengthMinimum(): number {
    return Math.max(PASSWORD_LENGTH_MIN, this.policySnapshot().password.minLength);
  }

  private passphraseWordsMinimum(): number {
    return Math.max(WORDS_MIN, this.policySnapshot().passphrase.minWords);
  }

  private passwordToggleRequired(key: 'lowercase' | 'uppercase' | 'numbers' | 'symbols'): boolean {
    const password = this.policySnapshot().password;
    if (key === 'symbols') return password.special;
    return password[key];
  }

  private passphraseToggleRequired(key: 'passphraseCapitalize' | 'passphraseNumber'): boolean {
    const passphrase = this.policySnapshot().passphrase;
    return key === 'passphraseCapitalize' ? passphrase.capitalize : passphrase.includeNumber;
  }

  private applyPolicyFloors(policy: GeneratorPolicySnapshot): void {
    if (policy.malformed) return;
    if (policy.password.allowed) {
      this.length = Math.max(this.length, policy.password.minLength);
      this.lowercase ||= policy.password.lowercase;
      this.uppercase ||= policy.password.uppercase;
      this.numbers ||= policy.password.numbers;
      this.symbols ||= policy.password.special;
      this.minNumbers = this.numbers ? Math.max(this.minNumbers, policy.password.minNumbers, 1) : 0;
      this.minSpecial = this.symbols ? Math.max(this.minSpecial, policy.password.minSpecial, 1) : 0;
    }
    if (policy.passphrase.allowed) {
      this.words = Math.max(this.words, policy.passphrase.minWords);
      this.passphraseCapitalize ||= policy.passphrase.capitalize;
      this.passphraseNumber ||= policy.passphrase.includeNumber;
    }
  }

  private passwordConfigurationMessage(): string {
    const enabledCount = Number(this.lowercase)
      + Number(this.uppercase)
      + Number(this.numbers)
      + Number(this.symbols);
    if (enabledCount === 0) return t('gen.characterTypeRequired');
    const requiredLength = Number(this.lowercase)
      + Number(this.uppercase)
      + (this.numbers ? Math.max(this.minNumbers, 1) : 0)
      + (this.symbols ? Math.max(this.minSpecial, 1) : 0);
    return this.length < requiredLength
      ? t('gen.minimumsExceedLength', { minimum: requiredLength, length: this.length })
      : '';
  }

  /** Runs the core generator matching the current mode/options. Never touches the DOM. */
  private compute(): string {
    if (this.mode === 'username') return this.computeUsername();
    if (this.mode === 'pin') {
      if (!this.policyAllowsMode('pin')) return '';
      const options: PasswordGenOptions = {
        ...DEFAULT_PASSWORD_OPTIONS,
        length: this.pinLength,
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
    const evaluation = applyGeneratorPolicySnapshot(this.credentialOptions(), this.policySnapshot());
    if (!evaluation.allowed) return '';
    const options = evaluation.options;
    this.mode = options.mode === 'password' ? 'random' : 'memorable';
    this.length = options.password.length;
    this.lowercase = options.password.lowercase;
    this.uppercase = options.password.uppercase;
    this.numbers = options.password.numbers;
    this.symbols = options.password.special;
    this.minNumbers = options.password.minNumbers;
    this.minSpecial = options.password.minSpecial;
    this.avoidAmbiguous = options.password.avoidAmbiguous;
    this.words = options.passphrase.numWords;
    this.passphraseCapitalize = options.passphrase.capitalize;
    this.passphraseNumber = options.passphrase.includeNumber;
    return options.mode === 'password'
      ? generatePassword(options.password)
      : generatePassphrase(options.passphrase);
  }

  /** Recompute and announce one newly generated non-empty value. */
  private regenerate(): void {
    const policy = parseGeneratorPolicySnapshot(this.generatorPolicy);
    if (policy === null || this.generatorPolicy === UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT) {
      this.current = '';
      this.validationMessage = '';
      return;
    }
    this.applyPolicyFloors(policy);
    this.validationMessage = this.mode === 'random' ? this.passwordConfigurationMessage() : '';
    if (this.validationMessage) {
      this.current = '';
      return;
    }
    this.current = this.compute();
    if (this.current && this.isConnected) {
      emit<GeneratorHistoryAddDetail>(this, 'vw-history-add', {
        value: this.current,
        type: this.historyType(),
        policyRevision: policy.revision,
      });
    }
  }

  /** Explicit regenerate produces a new value; the replaced value was tracked when generated. */
  private regenerateAndRecord(): void {
    this.regenerate();
  }

  private historyType(): GeneratorHistoryEntryType {
    if (this.mode === 'memorable') return 'passphrase';
    if (this.mode === 'pin') return 'pin';
    return this.mode === 'username' ? 'username' : 'password';
  }

  private copyLabel(): string {
    if (this.mode === 'username') return t('detail.username');
    return this.mode === 'pin' ? t('gen.modePin') : t('detail.password');
  }

  private copy(): void {
    if (!this.current) return;
    emit<CopyDetail>(this, 'vw-copy', { value: this.current, label: this.copyLabel() });
  }

  private selectValue(): void {
    if (!this.current || !this.selectionTarget) return;
    emit<GeneratorSelectionDetail>(this, 'vw-generator-select', {
      target: this.selectionTarget,
      value: this.current,
    });
  }

  private copyHistoryEntry(entry: GeneratorHistoryEntry): void {
    emit<CopyDetail>(this, 'vw-copy', { value: entry.value, label: this.historyLabel(entry.type) });
  }

  private historyLabel(type: GeneratorHistoryEntryType): string {
    if (type === 'pin') return t('gen.modePin');
    if (type === 'username') return t('detail.username');
    return type === 'passphrase' ? t('gen.modeWords') : t('detail.password');
  }

  private clearHistory(): void {
    if (this.history.length > 0 && window.confirm(t('gen.historyClearConfirm'))) emit(this, 'vw-history-clear');
  }

  private renderHistory() {
    return html`
      <section class="history" aria-label=${t('gen.history')}>
        <div class="history-head">
          <h2>${t('gen.history')}</h2>
          ${this.history.length > 0
            ? html`<button type="button" class="history-clear" data-history-clear @click=${() => this.clearHistory()}>${t('gen.historyClear')}</button>`
            : nothing}
        </div>
        ${this.history.length > 0
          ? html`<div class="history-list">${this.history.map((entry) => html`
              <div class="history-item">
                <div>
                  <div class="history-value">${entry.value}</div>
                  <div class="history-meta">${this.historyLabel(entry.type)} · ${new Date(entry.generatedAt).toLocaleString()}</div>
                </div>
                <button type="button" class="history-copy" aria-label=${t('gen.historyCopy')} @click=${() => this.copyHistoryEntry(entry)}>${uiIcon('copy')}</button>
              </div>`)}
            </div>`
          : html`<p class="history-empty">${t('gen.historyEmpty')}</p>`}
      </section>`;
  }

  private back(): void {
    emit(this, 'vw-item-back');
  }

  private setMode(mode: GenMode): void {
    if (this.mode === mode || !this.policyAllowsMode(mode)) return;
    setPref('genMode', mode);
  }

  private setUsernameType(type: UsernameType): void {
    if (this.usernameType === type) return;
    setPref('genUsernameType', type);
  }

  private setUsernameLength(value: string): void {
    setPref(
      'genUsernameLength',
      clampInt(value, USERNAME_LENGTH_MIN, USERNAME_LENGTH_MAX, this.usernameLength),
    );
  }

  private setUsernameToggle(key: 'usernameCapitalize' | 'usernameNumber', checked: boolean): void {
    setPref(key === 'usernameCapitalize' ? 'genUsernameCapitalize' : 'genUsernameNumber', checked);
  }

  private setCatchAllDomain(value: string): void {
    this.catchAllDomain = value;
    this.regenerate();
  }

  private setPlusAddressEmail(value: string): void {
    this.plusAddressEmail = value;
    this.regenerate();
  }

  private setLength(value: string): void {
    if (this.mode === 'pin') {
      if (!this.policyAllowsMode('pin')) return;
      setPref('genPinLength', clampInt(value, PIN_LENGTH_MIN, PIN_LENGTH_MAX, this.pinLength));
      return;
    }
    if (this.mode !== 'random' || !this.canConfigurePassword()) return;
    setPref(
      'genLength',
      clampInt(value, this.passwordLengthMinimum(), PASSWORD_LENGTH_MAX, this.length),
    );
  }

  private setWords(value: string): void {
    if (!this.canConfigurePassphrase()) return;
    setPref(
      'genPassphraseWords',
      clampInt(value, this.passphraseWordsMinimum(), WORDS_MAX, this.words),
    );
  }

  private setPasswordToggle(
    key: 'lowercase' | 'uppercase' | 'numbers' | 'symbols' | 'avoidAmbiguous',
    checked: boolean,
  ): void {
    if (!this.canConfigurePassword()) return;
    if (key !== 'avoidAmbiguous' && this.passwordToggleRequired(key)) return;
    if (key === 'numbers') {
      setPrefs({ genNumbers: checked, genMinNumbers: checked ? Math.max(this.minNumbers, 1) : 0 });
      return;
    }
    if (key === 'symbols') {
      setPrefs({ genSymbols: checked, genMinSpecial: checked ? Math.max(this.minSpecial, 1) : 0 });
      return;
    }
    const prefKey = key === 'lowercase'
      ? 'genLowercase'
      : key === 'uppercase' ? 'genUppercase' : 'genAvoidAmbiguous';
    setPref(prefKey, checked);
  }

  private setMinimum(key: 'numbers' | 'special', value: string): void {
    if (!this.canConfigurePassword()) return;
    const policy = this.policySnapshot().password;
    if (key === 'numbers') {
      if (!this.numbers || policy.minNumbers > MINIMUM_COUNT_MAX) return;
      const minimum = Math.max(MINIMUM_COUNT_MIN, policy.minNumbers);
      setPrefs({
        genNumbers: true,
        genMinNumbers: clampInt(value, minimum, MINIMUM_COUNT_MAX, this.minNumbers),
      });
      return;
    }
    if (!this.symbols || policy.minSpecial > MINIMUM_COUNT_MAX) return;
    const minimum = Math.max(MINIMUM_COUNT_MIN, policy.minSpecial);
    setPrefs({
      genSymbols: true,
      genMinSpecial: clampInt(value, minimum, MINIMUM_COUNT_MAX, this.minSpecial),
    });
  }

  private setPassphraseToggle(key: 'passphraseCapitalize' | 'passphraseNumber', checked: boolean): void {
    if (!this.canConfigurePassphrase() || this.passphraseToggleRequired(key)) return;
    setPref(
      key === 'passphraseCapitalize' ? 'genPassphraseCapitalize' : 'genPassphraseNumber',
      checked,
    );
  }

  /** Estimated entropy (bits) of the current value. Passphrases are measured per independently-chosen
   *  word; everything else is `length × log2(alphabetSize)` over the active character classes, so a
   *  digit-only PIN is scored on its true (small) alphabet rather than raw length. */
  private entropyBits(): number {
    if (this.mode === 'memorable') return this.words * BITS_PER_WORD;
    const alphabet =
      this.mode === 'pin'
        ? 10
        : (this.lowercase ? (this.avoidAmbiguous ? 25 : 26) : 0) +
          (this.uppercase ? (this.avoidAmbiguous ? 24 : 26) : 0) +
          (this.numbers ? (this.avoidAmbiguous ? 8 : 10) : 0) +
          (this.symbols ? 8 : 0);
    return this.current.length * Math.log2(Math.max(alphabet, 2));
  }

  /** Entropy-based strength: tiers on estimated bits (not raw length) plus a proportional bar width. */
  private strength(): { label: string; color: string; width: number } {
    const bits = this.entropyBits();
    const width = Math.max(0, Math.min(100, Math.round((bits / BITS_FULL_BAR) * 100)));
    if (bits >= BITS_VERY_STRONG) return { label: t('gen.strengthStrong'), color: 'var(--vw-strength-strong)', width };
    if (bits >= BITS_STRONG) return { label: t('gen.strengthGood'), color: 'var(--vw-strength-good)', width };
    if (bits >= BITS_FAIR) return { label: t('gen.strengthMid'), color: 'var(--vw-strength-mid)', width };
    return { label: t('gen.strengthWeak'), color: 'var(--vw-strength-weak)', width };
  }

  private renderPassword() {
    return [...this.current].map((ch) => {
      const kind = charKind(ch);
      return kind === 'letter' ? html`<span>${ch}</span>` : html`<span class=${kind}>${ch}</span>`;
    });
  }

  private renderPasswordToggleRow(
    label: string,
    key: 'lowercase' | 'uppercase' | 'numbers' | 'symbols' | 'avoidAmbiguous',
    marker: string,
  ) {
    const required = key !== 'avoidAmbiguous' && this.passwordToggleRequired(key);
    const disabled = !this.canConfigurePassword() || required;
    return html`
      <div class="toggle-row">
        <span>${label}</span>
        <vw-toggle
          data-toggle=${marker}
          .checked=${this[key]}
          .disabled=${disabled}
          title=${required ? t('gen.policyRequired') : nothing}
          aria-describedby=${required ? 'generator-policy-status' : nothing}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => this.setPasswordToggle(key, e.detail.checked)}
        ></vw-toggle>
      </div>
    `;
  }

  private renderUsernameToggleRow(
    label: string,
    key: 'usernameCapitalize' | 'usernameNumber',
    marker: string,
  ) {
    return html`
      <label class="toggle-row">
        <span>${label}</span>
        <input
          class="username-checkbox"
          data-username-toggle=${marker}
          type="checkbox"
          aria-label=${label}
          .checked=${this[key]}
          @change=${(e: Event) => this.setUsernameToggle(key, (e.target as HTMLInputElement).checked)}
        />
      </label>
    `;
  }

  private renderPassphraseToggleRow(
    label: string,
    key: 'passphraseCapitalize' | 'passphraseNumber',
    marker: string,
  ) {
    const required = this.passphraseToggleRequired(key);
    return html`
      <div class="toggle-row">
        <span>${label}</span>
        <vw-toggle
          data-toggle=${marker}
          .checked=${this[key]}
          .disabled=${!this.canConfigurePassphrase() || required}
          title=${required ? t('gen.policyRequired') : nothing}
          aria-describedby=${required ? 'generator-policy-status' : nothing}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => this.setPassphraseToggle(key, e.detail.checked)}
        ></vw-toggle>
      </div>
    `;
  }

  private renderUsernameContext() {
    const types = [
      { id: 'randomWord', label: t('gen.usernameRandomWord') },
      { id: 'plusAddressed', label: t('gen.usernamePlusAddressed') },
      { id: 'catchAll', label: t('gen.usernameCatchAll') },
    ];
    const accountEmail = normalizeAccountEmail(this.plusAddressEmail);
    const email = normalizePlusAddressBase(this.plusAddressEmail, this.usernameLength);
    const parsedDomain = normalizeCatchAllDomain(this.catchAllDomain);
    const domain = normalizeCatchAllDomain(this.catchAllDomain, this.usernameLength);
    const plusError = !accountEmail
      ? t('gen.plusAddressUnavailable')
      : !email
        ? t('gen.plusAddressTooLong')
        : undefined;
    return html`
      <vw-segmented
        data-username-type
        .options=${types}
        .value=${this.usernameType}
        @vw-segmented-change=${(e: CustomEvent<{ id: string }>) => this.setUsernameType(e.detail.id as UsernameType)}
      ></vw-segmented>
      ${this.usernameType === 'plusAddressed'
        ? html`
          <label class="username-context">
            <span class="field-label">${t('gen.plusAddressEmail')}</span>
            <input
              class="text-input"
              data-plus-address-email
              type="email"
              autocomplete="email"
              spellcheck="false"
              .value=${this.plusAddressEmail}
              aria-invalid=${plusError ? 'true' : 'false'}
              aria-describedby="plus-address-guidance"
              @input=${(e: Event) => this.setPlusAddressEmail((e.target as HTMLInputElement).value)}
            />
            <span
              id="plus-address-guidance"
              class=${plusError ? 'validation' : 'hint'}
              ?data-username-error=${Boolean(plusError)}
              role=${plusError ? 'status' : nothing}
            >${plusError ?? t('gen.plusAddressHint')}</span>
          </label>
        `
        : this.usernameType === 'catchAll'
          ? html`
            <label class="username-context">
              <span class="field-label">${t('gen.catchAllDomain')}</span>
              <input
                class="text-input"
                data-catch-all-domain
                type="text"
                autocomplete="off"
                spellcheck="false"
                placeholder=${t('gen.catchAllDomainPlaceholder')}
                .value=${this.catchAllDomain}
                aria-invalid=${this.catchAllDomain && !domain ? 'true' : 'false'}
                aria-describedby="catch-all-guidance"
                @input=${(e: Event) => this.setCatchAllDomain((e.target as HTMLInputElement).value)}
              />
              <span
                id="catch-all-guidance"
                class=${this.catchAllDomain && !domain ? 'validation' : 'hint'}
                ?data-username-error=${Boolean(this.catchAllDomain && !domain)}
              >${this.catchAllDomain && !domain
                ? parsedDomain ? t('gen.catchAllAddressTooLong') : t('gen.catchAllDomainInvalid')
                : t('gen.catchAllHint')}</span>
            </label>
          `
          : nothing}
    `;
  }

  /** The size control: a character-length slider for random/PIN, or a dedicated word-count slider for
   *  a memorable passphrase (words, not characters). */
  private renderSizeControl() {
    if (this.mode === 'username') {
      if (this.usernameType === 'randomWord') return nothing;
      return html`
        <label class="username-size">
          <span class="length-row">
            <span class="length-label">${t('gen.usernameRandomLength')}</span>
            <span class="length-pill" data-username-length-value>${this.usernameLength}</span>
          </span>
          <input
            type="range"
            data-username-length
            aria-label=${t('gen.usernameRandomLength')}
            min=${USERNAME_LENGTH_MIN}
            max=${USERNAME_LENGTH_MAX}
            .value=${String(this.usernameLength)}
            @input=${(e: Event) => this.setUsernameLength((e.target as HTMLInputElement).value)}
          />
        </label>
      `;
    }
    if (this.mode === 'memorable') {
      return html`
        <div class="length-row">
          <span class="length-label">${t('gen.words')}</span>
          <span class="length-pill" data-words-value>${this.words}</span>
        </div>
        <input
          type="range"
          data-words
          min=${this.passphraseWordsMinimum()}
          max=${WORDS_MAX}
          .value=${String(this.words)}
          ?disabled=${!this.canConfigurePassphrase()}
          @input=${(e: Event) => this.setWords((e.target as HTMLInputElement).value)}
        />
      `;
    }
    const characterLength = this.mode === 'pin' ? this.pinLength : this.length;
    const minimum = this.mode === 'pin' ? PIN_LENGTH_MIN : this.passwordLengthMinimum();
    const maximum = this.mode === 'pin' ? PIN_LENGTH_MAX : PASSWORD_LENGTH_MAX;
    const disabled = this.mode === 'pin'
      ? !this.policyAllowsMode('pin')
      : !this.canConfigurePassword();
    return html`
      <div class="length-row">
        <span class="length-label">${t('gen.length')}</span>
        <span class="length-pill" data-length-value>${characterLength}</span>
      </div>
      <input
        type="range"
        data-length
        min=${minimum}
        max=${maximum}
        .value=${String(characterLength)}
        ?disabled=${disabled}
        aria-describedby=${this.validationMessage ? 'generator-validation-status' : nothing}
        @input=${(e: Event) => this.setLength((e.target as HTMLInputElement).value)}
      />
    `;
  }

  /** Only the class toggles that affect the active mode: all three for random, uppercase + number for
   *  a memorable passphrase (symbols do not apply), none for a digit-only PIN. */
  private renderToggles() {
    if (this.mode === 'username') {
      if (this.usernameType !== 'randomWord') return html`<div class="toggles"></div>`;
      return html`
        <div class="toggles">
          ${this.renderUsernameToggleRow(t('gen.usernameCapitalize'), 'usernameCapitalize', 'capitalize')}
          ${this.renderUsernameToggleRow(t('gen.usernameIncludeNumber'), 'usernameNumber', 'number')}
        </div>
      `;
    }
    if (this.mode === 'pin') return html`<div class="toggles"></div>`;
    if (this.mode === 'memorable') {
      return html`
        <div class="toggles">
          ${this.renderPassphraseToggleRow(t('gen.upper'), 'passphraseCapitalize', 'upper')}
          ${this.renderPassphraseToggleRow(t('gen.number'), 'passphraseNumber', 'number')}
        </div>
      `;
    }
    return html`
      <div class="toggles">
        ${this.renderPasswordToggleRow(t('gen.lower'), 'lowercase', 'lower')}
        ${this.renderPasswordToggleRow(t('gen.upper'), 'uppercase', 'upper')}
        ${this.renderPasswordToggleRow(t('gen.number'), 'numbers', 'number')}
        ${this.renderPasswordToggleRow(t('gen.symbol'), 'symbols', 'symbol')}
        ${this.renderPasswordToggleRow(t('gen.avoidAmbiguous'), 'avoidAmbiguous', 'ambiguous')}
      </div>
    `;
  }

  private renderPasswordMinimums() {
    if (this.mode !== 'random') return nothing;
    const policy = this.policySnapshot().password;
    const numberMinimum = Math.max(MINIMUM_COUNT_MIN, policy.minNumbers);
    const specialMinimum = Math.max(MINIMUM_COUNT_MIN, policy.minSpecial);
    return html`
      <div class="minimums">
        <label class="minimum-control">
          <span>${t('gen.minNumbers')}</span>
          <input
            type="number"
            inputmode="numeric"
            data-min-numbers
            min=${numberMinimum}
            max=${Math.max(MINIMUM_COUNT_MAX, numberMinimum)}
            .value=${String(this.numbers ? this.minNumbers : 0)}
            ?disabled=${!this.numbers || !this.canConfigurePassword() || policy.minNumbers > MINIMUM_COUNT_MAX}
            title=${policy.minNumbers > MINIMUM_COUNT_MAX ? t('gen.policyRequired') : nothing}
            aria-describedby=${this.validationMessage ? 'generator-validation-status' : nothing}
            @change=${(event: Event) => this.setMinimum('numbers', (event.target as HTMLInputElement).value)}
          />
        </label>
        <label class="minimum-control">
          <span>${t('gen.minSpecial')}</span>
          <input
            type="number"
            inputmode="numeric"
            data-min-special
            min=${specialMinimum}
            max=${Math.max(MINIMUM_COUNT_MAX, specialMinimum)}
            .value=${String(this.symbols ? this.minSpecial : 0)}
            ?disabled=${!this.symbols || !this.canConfigurePassword() || policy.minSpecial > MINIMUM_COUNT_MAX}
            title=${policy.minSpecial > MINIMUM_COUNT_MAX ? t('gen.policyRequired') : nothing}
            aria-describedby=${this.validationMessage ? 'generator-validation-status' : nothing}
            @change=${(event: Event) => this.setMinimum('special', (event.target as HTMLInputElement).value)}
          />
        </label>
      </div>
    `;
  }

  protected override render() {
    const strength = this.mode === 'username' ? undefined : this.strength();
    const modes = [
      { id: 'random', label: t('gen.modePassword') },
      { id: 'memorable', label: t('gen.modeWords') },
      { id: 'pin', label: t('gen.modePin') },
      { id: 'username', label: t('gen.modeUsername') },
    ].filter((option) => this.policyAllowsMode(option.id as GenMode));
    const policy = this.policySnapshot();
    const credentialPolicyVisible = this.mode !== 'username'
      && (policy.policyInEffect || policy.malformed);
    const policyUnavailable = policy.malformed
      || (this.mode === 'random' && !policy.password.allowed)
      || (this.mode === 'memorable' && !policy.passphrase.allowed)
      || (this.mode === 'pin' && policy.policyInEffect);
    const disabledDescription = this.validationMessage
      ? 'generator-validation-status'
      : policyUnavailable ? 'generator-policy-status' : nothing;
    return html`
      <div class="wrap">
        <div class="head">
          <h1>${this.mode === 'username' ? t('gen.usernameTitle') : t('gen.title')}</h1>
          <button type="button" class="close" data-close title=${t('common.close')} aria-label=${t('common.close')} @click=${() => this.back()}>
            ${uiIcon('close')}
          </button>
        </div>

        <vw-segmented
          data-mode
          .options=${modes}
          .value=${this.mode}
          @vw-segmented-change=${(e: CustomEvent<{ id: string }>) => this.setMode(e.detail.id as GenMode)}
        ></vw-segmented>

        ${credentialPolicyVisible
          ? html`<vw-status-message
              id="generator-policy-status"
              data-generator-policy
              tone=${policyUnavailable ? 'danger' : 'info'}
              .message=${policyUnavailable
                ? t(policy.malformed ? 'gen.policyMalformed' : 'gen.policyUnsatisfiable')
                : t('gen.policyManaged')}
            ></vw-status-message>`
          : nothing}

        ${this.validationMessage
          ? html`<vw-status-message
              id="generator-validation-status"
              data-generator-configuration
              tone="danger"
              .message=${this.validationMessage}
            ></vw-status-message>`
          : nothing}

        ${this.mode === 'username' ? this.renderUsernameContext() : nothing}

        <div class="result">
          <div class="password" data-output>${this.renderPassword()}</div>
          ${strength
            ? html`
              <div class="strength">
                <div class="track"><div class="fill" data-strength-fill style=${`width:${strength.width}%;background:${strength.color}`}></div></div>
                <span class="strength-label" data-strength style=${`color:${strength.color}`}>${strength.label}</span>
              </div>
            `
            : nothing}
        </div>

        ${this.renderSizeControl()}

        ${this.renderToggles()}

        ${this.renderPasswordMinimums()}

        <div class="actions">
          <button
            type="button"
            class="copy"
            data-copy
            data-select-generated=${this.selectionTarget ? '' : nothing}
            ?disabled=${!this.current}
            aria-describedby=${disabledDescription}
            @click=${() => this.selectionTarget ? this.selectValue() : this.copy()}
          >
            ${uiIcon(this.selectionTarget ? 'check' : 'copy')}<span>${this.selectionTarget
              ? t(this.selectionTarget === 'password' ? 'gen.usePassword' : 'gen.useUsername')
              : t(this.mode === 'username' ? 'gen.copyUsername' : 'gen.copy')}</span>
          </button>
          <button type="button" class="regen" data-regenerate ?disabled=${!this.current} aria-describedby=${disabledDescription} title=${t('gen.regenerate')} aria-label=${t('gen.regenerate')} @click=${() => this.regenerateAndRecord()}>
            ${uiIcon('refresh')}
          </button>
        </div>
        ${this.selectionTarget ? nothing : this.renderHistory()}
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
