import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';
import { getPrefs, setPref, subscribePrefs } from '../../prefs.js';
import '../../components/setting-card.js';
import '../../components/toggle.js';

/**
 * Generator-defaults section: the default length + include-numbers / include-symbols the popup
 * generator seeds from. UI-local prefs managed directly via the prefs module.
 */
export class VwGeneratorSection extends LitElement {
  private i18n = new LocalizeController(this);
  private unsubscribe: (() => void) | undefined = undefined;

  static override styles = [
    themeTokens,
    css`
      :host { display: flex; flex-direction: column; gap: 8px; }
      .len { display: flex; align-items: center; gap: 12px; }
      input[type='range'] { width: 180px; accent-color: var(--vw-accent); }
      .pill {
        font-size: 12px; font-weight: 600; color: var(--vw-teal-text); background: var(--vw-teal-10);
        border-radius: 6px; padding: 2px 8px; min-width: 24px; text-align: center;
      }
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

  protected override render() {
    const prefs = getPrefs();
    return html`
      <vw-setting-card heading=${t('options.generator.defaultLength')}>
        <div class="len">
          <input
            type="range"
            min="8"
            max="40"
            .value=${String(prefs.genLength)}
            @input=${(e: Event) => setPref('genLength', Number((e.target as HTMLInputElement).value))}
          />
          <span class="pill">${prefs.genLength}</span>
        </div>
      </vw-setting-card>

      <vw-setting-card heading=${t('options.generator.includeNumbers')}>
        <vw-toggle
          .checked=${prefs.genNumbers}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => setPref('genNumbers', e.detail.checked)}
        ></vw-toggle>
      </vw-setting-card>

      <vw-setting-card heading=${t('options.generator.includeSymbols')}>
        <vw-toggle
          .checked=${prefs.genSymbols}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => setPref('genSymbols', e.detail.checked)}
        ></vw-toggle>
      </vw-setting-card>
    `;
  }
}

customElements.define('vw-generator-section', VwGeneratorSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-generator-section': VwGeneratorSection;
  }
}
