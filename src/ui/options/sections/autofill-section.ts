import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/status-message.js';
import { UriMatchStrategy, isUriMatchStrategySetting, type UriMatchStrategySetting } from '../../../core/vault/uri-match.js';
import type { AutofillSaveDetail, SectionStatus } from '../types.js';

const STRATEGY_LABELS: Record<UriMatchStrategySetting, string> = {
  [UriMatchStrategy.Domain]: 'Base domain',
  [UriMatchStrategy.Host]: 'Host',
  [UriMatchStrategy.StartsWith]: 'Starts with',
  [UriMatchStrategy.Exact]: 'Exact',
  [UriMatchStrategy.RegularExpression]: 'Regular expression',
  [UriMatchStrategy.Never]: 'Never',
};

/** Plain-language description of each match strategy, shown beneath the select. */
const STRATEGY_HELP: Record<UriMatchStrategySetting, string> = {
  [UriMatchStrategy.Domain]: 'Fills when the registrable domain matches — example.com matches app.example.com. The safe default for most sites.',
  [UriMatchStrategy.Host]: 'Fills only when the host and port match exactly, so app.example.com and example.com are treated separately.',
  [UriMatchStrategy.StartsWith]: 'Fills when the page address starts with the saved URI. Useful for path-scoped logins.',
  [UriMatchStrategy.Exact]: 'Fills only when the full address matches the saved URI character for character.',
  [UriMatchStrategy.RegularExpression]: 'Fills when the page address matches the saved URI as a regular expression. For advanced setups.',
  [UriMatchStrategy.Never]: 'Never offers to fill automatically for these items.',
};

const STRATEGY_ORDER: UriMatchStrategySetting[] = [
  UriMatchStrategy.Domain,
  UriMatchStrategy.Host,
  UriMatchStrategy.StartsWith,
  UriMatchStrategy.Exact,
  UriMatchStrategy.RegularExpression,
  UriMatchStrategy.Never,
];

/**
 * Autofill settings: the default URI match strategy with plain-language help that follows the
 * selection. The root persists the choice through `settings.save`, reusing the already-loaded
 * server URL (no host-permission prompt); this section only emits the typed strategy.
 */
export class VwAutofillSection extends LitElement {
  static override properties = {
    defaultUriMatchStrategy: { attribute: false },
    pending: { type: Boolean },
    status: { attribute: false },
    selected: { state: true },
  };

  declare defaultUriMatchStrategy: UriMatchStrategySetting;
  declare pending: boolean;
  declare status: SectionStatus | undefined;
  declare selected: UriMatchStrategySetting;

  constructor() {
    super();
    this.defaultUriMatchStrategy = UriMatchStrategy.Domain;
    this.pending = false;
    this.status = undefined;
    this.selected = UriMatchStrategy.Domain;
  }

  override willUpdate(changed: Map<PropertyKey, unknown>): void {
    if (changed.has('defaultUriMatchStrategy')) {
      this.selected = this.defaultUriMatchStrategy;
    }
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host { display: block; }
      h1 { margin: 0 0 4px; font-size: 16px; }
      p.lede { margin: 0 0 16px; color: var(--vw-muted); font-size: 13px; }
      form { display: flex; flex-direction: column; gap: 10px; max-width: 420px; }
      .select { width: 100%; box-sizing: border-box; }
      .help { margin: 0; font-size: 12px; color: var(--vw-muted); }
      .status { margin-top: 12px; }
    `,
  ];

  private onChange(event: Event): void {
    const value = Number((event.target as HTMLSelectElement).value);
    if (isUriMatchStrategySetting(value)) this.selected = value;
  }

  // Set the native <select> value after its <option>s render, so the loaded strategy shows.
  protected override updated(): void {
    const select = this.renderRoot.querySelector<HTMLSelectElement>('[data-strategy]');
    if (select) select.value = String(this.selected);
  }

  private save(event: Event): void {
    event.preventDefault();
    if (this.pending) return;
    const raw = Number(this.renderRoot.querySelector<HTMLSelectElement>('[data-strategy]')?.value ?? '');
    if (!isUriMatchStrategySetting(raw)) return;
    this.dispatchEvent(new CustomEvent<AutofillSaveDetail>('vw-autofill-save', {
      detail: { defaultUriMatchStrategy: raw },
      bubbles: true,
      composed: true,
    }));
  }

  private renderStatus() {
    return this.status
      ? html`<vw-status-message class="status" tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`
      : nothing;
  }

  protected override render() {
    return html`
      <h1>Autofill</h1>
      <p class="lede">How saved logins are matched to the page you're on.</p>
      <form @submit=${(e: Event) => this.save(e)}>
        <label class="field">
          <span>Default URI match detection</span>
          <select class="select" data-strategy @change=${(e: Event) => this.onChange(e)}>
            ${STRATEGY_ORDER.map((s) => html`<option value=${s}>${STRATEGY_LABELS[s]}</option>`)}
          </select>
        </label>
        <p class="help" data-strategy-help>${STRATEGY_HELP[this.selected]}</p>
        <button type="submit" class="button primary" data-strategy-save ?disabled=${this.pending}>${uiIcon('check')}<span>Save autofill</span></button>
      </form>
      ${this.renderStatus()}
    `;
  }
}

customElements.define('vw-autofill-section', VwAutofillSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-autofill-section': VwAutofillSection;
  }
}
