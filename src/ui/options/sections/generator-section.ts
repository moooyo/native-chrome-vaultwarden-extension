import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';
import { getPrefs, setPref, subscribePrefs } from '../../prefs.js';
import '../../components/setting-card.js';
import '../../components/toggle.js';

/**
 * Generator-defaults section: the random-password defaults injected into the popup generator.
 * UI-local prefs are managed directly via the prefs module.
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
      input[type='number'] {
        box-sizing: border-box; width: 84px; height: 34px; padding: 0 9px;
        border: 1px solid var(--vw-line-3); border-radius: var(--vw-radius-control);
        background: var(--vw-card); color: var(--vw-ink); font: 12px/1 var(--vw-font-mono);
      }
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
            min="5"
            max="128"
            aria-label=${t('options.generator.defaultLength')}
            .value=${String(prefs.genLength)}
            @input=${(e: Event) => setPref('genLength', Number((e.target as HTMLInputElement).value))}
          />
          <span class="pill">${prefs.genLength}</span>
        </div>
      </vw-setting-card>

      <vw-setting-card heading=${t('options.generator.includeLowercase')}>
        <vw-toggle
          data-lowercase
          .checked=${prefs.genLowercase}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => setPref('genLowercase', e.detail.checked)}
        ></vw-toggle>
      </vw-setting-card>

      <vw-setting-card heading=${t('options.generator.includeUppercase')}>
        <vw-toggle
          data-uppercase
          .checked=${prefs.genUppercase}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => setPref('genUppercase', e.detail.checked)}
        ></vw-toggle>
      </vw-setting-card>

      <vw-setting-card heading=${t('options.generator.includeNumbers')}>
        <vw-toggle
          data-numbers
          .checked=${prefs.genNumbers}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => setPref('genNumbers', e.detail.checked)}
        ></vw-toggle>
      </vw-setting-card>

      <vw-setting-card heading=${t('options.generator.includeSymbols')}>
        <vw-toggle
          data-symbols
          .checked=${prefs.genSymbols}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => setPref('genSymbols', e.detail.checked)}
        ></vw-toggle>
      </vw-setting-card>

      <vw-setting-card heading=${t('options.generator.minNumbers')}>
        <input
          type="number"
          inputmode="numeric"
          data-min-numbers
          min="1"
          max="9"
          aria-label=${t('options.generator.minNumbers')}
          .value=${String(prefs.genNumbers ? prefs.genMinNumbers : 0)}
          ?disabled=${!prefs.genNumbers}
          @change=${(event: Event) => setPref('genMinNumbers', Number((event.target as HTMLInputElement).value))}
        />
      </vw-setting-card>

      <vw-setting-card heading=${t('options.generator.minSpecial')}>
        <input
          type="number"
          inputmode="numeric"
          data-min-special
          min="1"
          max="9"
          aria-label=${t('options.generator.minSpecial')}
          .value=${String(prefs.genSymbols ? prefs.genMinSpecial : 0)}
          ?disabled=${!prefs.genSymbols}
          @change=${(event: Event) => setPref('genMinSpecial', Number((event.target as HTMLInputElement).value))}
        />
      </vw-setting-card>

      <vw-setting-card heading=${t('options.generator.avoidAmbiguous')}>
        <vw-toggle
          data-avoid-ambiguous
          .checked=${prefs.genAvoidAmbiguous}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => setPref('genAvoidAmbiguous', e.detail.checked)}
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
