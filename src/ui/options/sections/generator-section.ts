import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';
import { getPrefs, setPref, subscribePrefs, type MiyuPrefs } from '../../prefs.js';
import '../../components/setting-card.js';
import '../../components/toggle.js';

/**
 * Generator-defaults section: the random-password defaults injected into the popup generator.
 * UI-local prefs are managed directly via the prefs module.
 */
export class VwGeneratorSection extends LitElement {
  private i18n = new LocalizeController(this);
  private unsubscribe: (() => void) | undefined = undefined;
  private invalidFields = new Set<string>();

  static override styles = [
    themeTokens,
    css`
      :host { display: block; }
      .sheet { min-width: 0; border: 1px solid var(--vw-line-1); border-radius: 12px; background: var(--vw-card); }
      .intro { padding: 22px 24px 0; }
      .intro p { margin: 0; font-size: 12px; line-height: 1.6; color: var(--vw-muted); }
      vw-setting-card::part(card) { border: 0; border-radius: 0; background: transparent; padding: 20px 24px; }
      .len { display: flex; align-items: center; gap: 14px; }
      .length-control { display: grid; gap: 6px; }
      .hint { margin: 5px 0 0; color: var(--vw-muted); font-size: 12px; line-height: 1.6; }
      input[type='range'] { min-width: 100px; width: 180px; accent-color: var(--vw-accent); }
      input[type='number'] {
        box-sizing: border-box; width: 84px; height: 40px; padding: 0 11px;
        border: 1px solid var(--vw-line-3); border-radius: var(--vw-radius-control);
        background: var(--vw-card); color: var(--vw-ink); font: 14px/1 var(--vw-font-mono);
      }
      input:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      input:disabled { opacity: .5; cursor: not-allowed; background: var(--vw-fill-2); }
      input[aria-invalid='true'] { border-color: var(--vw-danger); }
      .character-group { border-top: 1px solid var(--vw-line-1); padding: 22px 24px; }
      h2 { margin: 0; font-size: 14px; line-height: 1.5; font-weight: 600; }
      .character-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 28px; margin-top: 14px; }
      .character-option { display: flex; align-items: center; gap: 16px; padding: 13px 0; min-height: 52px; }
      .character-option span { flex: 1; font-size: 13px; }
      .minimums { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-top: 18px; }
      .minimum-field { display: flex; flex-direction: column; align-items: flex-start; gap: 9px; font-size: 13px; }
      .minimum-field input { width: 100%; }
      .error { color: var(--vw-danger); font-size: 12px; line-height: 1.6; margin: 0; }
      .configuration-error { margin-top: 18px; padding: 10px 12px; border-left: 2px solid var(--vw-danger); background: var(--vw-danger-10); }
      .last-row { border-top: 1px solid var(--vw-line-1); }
      @media (max-width: 620px) {
        .character-grid, .minimums { grid-template-columns: 1fr; gap: 0; }
        .minimums { gap: 18px; }
        .character-option + .character-option { border-top: 1px solid var(--vw-line-1); }
        .len { width: 100%; }
        input[type='range'] { flex: 1; width: 100%; }
        vw-setting-card::part(card) { flex-wrap: wrap; }
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

  private onNumericChange(key: 'genLength' | 'genMinNumbers' | 'genMinSpecial', event: Event, min: number, max: number): void {
    const input = event.target as HTMLInputElement;
    const value = input.valueAsNumber;
    if (!Number.isSafeInteger(value) || value < min || value > max) {
      this.invalidFields.add(key);
    } else {
      this.invalidFields.delete(key);
      setPref(key, value);
    }
    this.requestUpdate();
  }

  private onLengthInput(event: Event): void {
    const value = Number((event.target as HTMLInputElement).value);
    this.invalidFields.delete('genLength');
    setPref('genLength', value);
    const exactInput = this.renderRoot.querySelector<HTMLInputElement>('[data-length]');
    if (exactInput) exactInput.value = String(value);
    this.requestUpdate();
  }

  private onCountedCharacterChange(key: 'genNumbers' | 'genSymbols', checked: boolean): void {
    this.invalidFields.delete(key === 'genNumbers' ? 'genMinNumbers' : 'genMinSpecial');
    setPref(key, checked);
    this.requestUpdate();
  }

  private configurationMessage(prefs: Readonly<MiyuPrefs>): string {
    const requiredLength = Number(prefs.genLowercase) + Number(prefs.genUppercase)
      + (prefs.genNumbers ? prefs.genMinNumbers : 0) + (prefs.genSymbols ? prefs.genMinSpecial : 0);
    if (requiredLength === 0) return t('gen.characterTypeRequired');
    return prefs.genLength < requiredLength
      ? t('gen.minimumsExceedLength', { minimum: requiredLength, length: prefs.genLength })
      : '';
  }

  protected override render() {
    const prefs = getPrefs();
    const configurationMessage = this.configurationMessage(prefs);
    return html`
      <div class="sheet">
      <div class="intro"><p>${t('options.generator.defaultsDesc')}</p></div>
      <vw-setting-card heading=${t('options.generator.defaultLength')}>
        <div class="length-control">
        <div class="len">
          <input
            type="range"
            min="5"
            max="128"
            aria-label=${t('options.generator.defaultLength')}
            .value=${String(prefs.genLength)}
            @input=${this.onLengthInput}
          />
          <input type="number" inputmode="numeric" min="5" max="128" step="1" data-length
            aria-label=${t('options.generator.defaultLength')}
            aria-invalid=${this.invalidFields.has('genLength') ? 'true' : 'false'}
            aria-describedby="length-hint length-error"
            .value=${String(prefs.genLength)}
            @change=${(event: Event) => this.onNumericChange('genLength', event, 5, 128)} />
        </div>
        <p class="hint" id="length-hint">${t('options.generator.lengthRange')}</p>
        <p class="error" id="length-error" role="status">${this.invalidFields.has('genLength') ? t('options.generator.lengthInvalid') : ''}</p>
        </div>
      </vw-setting-card>

      <section class="character-group" aria-labelledby="character-heading">
      <h2 id="character-heading">${t('options.generator.characterTypes')}</h2>
      <p class="hint">${t('options.generator.characterRules')}</p>
      <div class="character-grid">
      <div class="character-option"><span>${t('options.generator.includeLowercase')}</span>
        <vw-toggle
          data-lowercase
          .label=${t('options.generator.includeLowercase')}
          .checked=${prefs.genLowercase}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => setPref('genLowercase', e.detail.checked)}
        ></vw-toggle>
      </div>

      <div class="character-option"><span>${t('options.generator.includeUppercase')}</span>
        <vw-toggle
          data-uppercase
          .label=${t('options.generator.includeUppercase')}
          .checked=${prefs.genUppercase}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => setPref('genUppercase', e.detail.checked)}
        ></vw-toggle>
      </div>

      <div class="character-option"><span>${t('options.generator.includeNumbers')}</span>
        <vw-toggle
          data-numbers
          .label=${t('options.generator.includeNumbers')}
          .checked=${prefs.genNumbers}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => this.onCountedCharacterChange('genNumbers', e.detail.checked)}
        ></vw-toggle>
      </div>

      <div class="character-option"><span>${t('options.generator.includeSymbols')}</span>
        <vw-toggle
          data-symbols
          .label=${t('options.generator.includeSymbols')}
          .checked=${prefs.genSymbols}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => this.onCountedCharacterChange('genSymbols', e.detail.checked)}
        ></vw-toggle>
      </div>
      </div>

      <div class="minimums">
      <label class="minimum-field"><span>${t('options.generator.minNumbers')}</span>
        <input
          type="number"
          inputmode="numeric"
          data-min-numbers
          min="1"
          max="9"
          step="1"
          aria-label=${t('options.generator.minNumbers')}
          aria-invalid=${prefs.genNumbers && this.invalidFields.has('genMinNumbers') ? 'true' : 'false'}
          aria-describedby="minimum-hint numbers-error"
          .value=${String(prefs.genNumbers ? prefs.genMinNumbers : 0)}
          ?disabled=${!prefs.genNumbers}
          @change=${(event: Event) => this.onNumericChange('genMinNumbers', event, 1, 9)}
        />
        <span class="error" id="numbers-error" role="status">${prefs.genNumbers && this.invalidFields.has('genMinNumbers') ? t('options.generator.minimumInvalid') : ''}</span>
      </label>

      <label class="minimum-field"><span>${t('options.generator.minSpecial')}</span>
        <input
          type="number"
          inputmode="numeric"
          data-min-special
          min="1"
          max="9"
          step="1"
          aria-label=${t('options.generator.minSpecial')}
          aria-invalid=${prefs.genSymbols && this.invalidFields.has('genMinSpecial') ? 'true' : 'false'}
          aria-describedby="minimum-hint symbols-error"
          .value=${String(prefs.genSymbols ? prefs.genMinSpecial : 0)}
          ?disabled=${!prefs.genSymbols}
          @change=${(event: Event) => this.onNumericChange('genMinSpecial', event, 1, 9)}
        />
        <span class="error" id="symbols-error" role="status">${prefs.genSymbols && this.invalidFields.has('genMinSpecial') ? t('options.generator.minimumInvalid') : ''}</span>
      </label>
      </div>
      <p class="hint" id="minimum-hint">${t('options.generator.minimumRange')}</p>
      ${configurationMessage ? html`<p class="error configuration-error" role="status" data-configuration-error>${configurationMessage}</p>` : nothing}
      </section>

      <vw-setting-card class="last-row" heading=${t('options.generator.avoidAmbiguous')} description=${t('options.generator.ambiguousExample')}>
        <vw-toggle
          data-avoid-ambiguous
          .label=${t('options.generator.avoidAmbiguous')}
          .checked=${prefs.genAvoidAmbiguous}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => setPref('genAvoidAmbiguous', e.detail.checked)}
        ></vw-toggle>
      </vw-setting-card>
      </div>
    `;
  }
}

customElements.define('vw-generator-section', VwGeneratorSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-generator-section': VwGeneratorSection;
  }
}
