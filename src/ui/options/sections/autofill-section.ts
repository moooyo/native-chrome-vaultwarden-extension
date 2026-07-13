import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';
import { getPrefs, setPref, subscribePrefs } from '../../prefs.js';
import '../../components/setting-card.js';
import '../../components/toggle.js';
import '../../components/select-menu.js';
import '../../components/status-message.js';
import type { SelectOption } from '../../components/select-menu.js';
import { UriMatchStrategy, isUriMatchStrategySetting, type UriMatchStrategySetting } from '../../../core/vault/uri-match.js';
import type { AutofillSaveDetail, SectionStatus } from '../types.js';

/** Human labels for each URI-match strategy, in display order. The enum values are the contract;
 *  the labels are section-local (there are no per-strategy i18n keys). */
const STRATEGY_OPTIONS: SelectOption[] = [
  { value: String(UriMatchStrategy.Domain), label: 'Base domain' },
  { value: String(UriMatchStrategy.Host), label: 'Host' },
  { value: String(UriMatchStrategy.StartsWith), label: 'Starts with' },
  { value: String(UriMatchStrategy.Exact), label: 'Exact' },
  { value: String(UriMatchStrategy.RegularExpression), label: 'Regular expression' },
  { value: String(UriMatchStrategy.Never), label: 'Never' },
];

/**
 * Autofill settings, MiYu styling: the default URI match strategy (a real dropdown that saves on
 * change) plus the inline-suggestion and auto-submit UI-local toggles and the fill shortcut. The
 * strategy persists through the root's `settings.save`; this section only emits the typed strategy
 * (`vw-autofill-save`). The toggles are UI-local prefs written straight to the prefs module.
 */
export class VwAutofillSection extends LitElement {
  static override properties = {
    defaultUriMatchStrategy: { attribute: false },
    pending: { type: Boolean },
    status: { attribute: false },
  };

  declare defaultUriMatchStrategy: UriMatchStrategySetting;
  declare pending: boolean;
  declare status: SectionStatus | undefined;

  private i18n = new LocalizeController(this);
  private unsubscribe: (() => void) | undefined = undefined;

  constructor() {
    super();
    this.defaultUriMatchStrategy = UriMatchStrategy.Domain;
    this.pending = false;
    this.status = undefined;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: flex; flex-direction: column; gap: 8px; }
      .shortcut { display: inline-flex; align-items: center; gap: 10px; }
      .keychip {
        font-family: var(--vw-font-mono);
        font-size: 12px;
        color: var(--vw-ink);
        background: var(--vw-icon-hover);
        border: 1px solid var(--vw-line-3);
        border-radius: 6px;
        padding: 3px 8px;
      }
      .btn-outline {
        height: 30px;
        padding: 0 13px;
        border: 1px solid var(--vw-line-3);
        border-radius: var(--vw-radius-input);
        background: var(--vw-card);
        color: var(--vw-text-4);
        font-family: inherit;
        font-size: 12.5px;
        cursor: pointer;
      }
      .btn-outline:hover:not(:disabled) { background: var(--vw-row-hover); }
      .btn-outline:disabled { opacity: 0.5; cursor: default; }
      button:focus-visible { outline: none; box-shadow: var(--vw-focus); }
    `,
  ];

  override connectedCallback(): void {
    super.connectedCallback();
    this.unsubscribe = subscribePrefs(() => this.requestUpdate());
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.unsubscribe?.();
    this.unsubscribe = undefined;
  }

  private onStrategyChange(value: string): void {
    const raw = Number(value);
    if (!isUriMatchStrategySetting(raw)) return;
    this.dispatchEvent(new CustomEvent<AutofillSaveDetail>('vw-autofill-save', {
      detail: { defaultUriMatchStrategy: raw },
      bubbles: true,
      composed: true,
    }));
  }

  protected override render() {
    const prefs = getPrefs();
    return html`
      <vw-setting-card heading=${t('options.autofill.matchTitle')} description=${t('options.autofill.matchDesc')}>
        <vw-select
          data-strategy
          .options=${STRATEGY_OPTIONS}
          .value=${String(this.defaultUriMatchStrategy)}
          .label=${t('options.autofill.matchTitle')}
          @vw-select-change=${(e: CustomEvent<{ value: string }>) => this.onStrategyChange(e.detail.value)}
        ></vw-select>
      </vw-setting-card>

      <vw-setting-card heading=${t('options.autofill.inline')} description=${t('options.autofill.inlineDesc')}>
        <vw-toggle
          data-inline
          .checked=${prefs.inlineSuggestions}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => setPref('inlineSuggestions', e.detail.checked)}
        ></vw-toggle>
      </vw-setting-card>

      <vw-setting-card heading=${t('options.autofill.autoSubmit')} description=${t('options.autofill.autoSubmitDesc')}>
        <vw-toggle
          data-auto-submit
          .checked=${prefs.autoSubmit}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => setPref('autoSubmit', e.detail.checked)}
        ></vw-toggle>
      </vw-setting-card>

      <vw-setting-card heading=${t('options.autofill.shortcut')} description=${t('options.autofill.shortcutDesc')}>
        <div class="shortcut">
          <span class="keychip" data-shortcut>⌘⇧Space</span>
          <button type="button" class="btn-outline" data-shortcut-change @click=${() => {}}>
            ${t('options.autofill.change')}
          </button>
        </div>
      </vw-setting-card>

      ${this.status
        ? html`<vw-status-message data-status .tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`
        : nothing}
    `;
  }
}

customElements.define('vw-autofill-section', VwAutofillSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-autofill-section': VwAutofillSection;
  }
}
