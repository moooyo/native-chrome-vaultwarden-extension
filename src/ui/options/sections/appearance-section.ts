import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t, getLocale, setLocale, type Locale } from '../../i18n/index.js';
import {
  AppearanceController,
  getTheme,
  setTheme,
  getDensity,
  setDensity,
  type ThemeSetting,
  type DensitySetting,
} from '../../theme.js';
import '../../components/setting-card.js';
import '../../components/select-menu.js';
import '../../components/toggle.js';

/**
 * Appearance section: theme (light/dark/system), language (zh-CN/en), and compact density. All three
 * are UI-local preferences managed directly via the appearance + i18n modules — no root handler,
 * no worker request. Changing them re-themes / re-localizes every open surface live.
 */
export class VwAppearanceSection extends LitElement {
  private i18n = new LocalizeController(this);
  private appearance = new AppearanceController(this);

  static override styles = [
    themeTokens,
    css`
      :host { display: block; }
      .layout { display: grid; grid-template-columns: minmax(0, 1fr) 220px; gap: 28px; align-items: start; }
      .sheet { min-width: 0; border: 1px solid var(--vw-line-1); border-radius: 12px; background: var(--vw-card); }
      .theme-group { padding: 22px 24px; }
      h2 { margin: 0; font-size: 14px; line-height: 1.5; font-weight: 600; }
      .description { margin: 4px 0 18px; color: var(--vw-muted); font-size: 12px; line-height: 1.6; }
      .theme-options { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
      .theme-option { display: block; min-width: 0; cursor: pointer; font-size: 12px; }
      .theme-option input { position: absolute; width: 1px; height: 1px; opacity: 0; }
      .swatch { display: flex; gap: 7px; height: 72px; padding: 10px; margin-bottom: 9px; border: 1px solid #dce4ef; border-radius: 8px; background: #f4f7fb; }
      .swatch::before { content: ''; width: 23%; border-radius: 3px; background: #e2eaf5; }
      .swatch::after { content: ''; flex: 1; border-radius: 3px; background: #fff; box-shadow: 0 12px 0 -8px #cbd7e7 inset; }
      .swatch.dark { background: #172433; border-color: #637b94; }
      .swatch.dark::before { background: #23384e; }
      .swatch.dark::after { background: #2b3e52; box-shadow: 0 12px 0 -8px #637b94 inset; }
      .swatch.system { background: linear-gradient(90deg, #f4f7fb 50%, #172433 50%); }
      .theme-option input:checked + .swatch { border-color: var(--vw-accent); box-shadow: 0 0 0 1px var(--vw-accent); }
      .theme-option input:focus-visible + .swatch { outline: 3px solid var(--vw-accent); outline-offset: 4px; }
      .theme-label { display: flex; align-items: center; justify-content: space-between; gap: 6px; }
      .theme-label svg { width: 14px; height: 14px; color: var(--vw-accent); }
      vw-setting-card { border-top: 1px solid var(--vw-line-1); }
      vw-setting-card::part(card) { border: 0; border-radius: 0; background: transparent; padding: 20px 24px; }
      .preview { padding-top: 2px; }
      .preview h2 { font-size: 12px; color: var(--vw-muted); margin-bottom: 12px; }
      .preview-list { border: 1px solid var(--vw-line-1); border-radius: 8px; background: var(--vw-card); }
      .preview-row { display: flex; align-items: center; gap: 10px; min-height: var(--vw-list-row-min); padding: var(--vw-list-row-padding-block) 12px; font-size: 12px; }
      .preview-row + .preview-row { border-top: 1px solid var(--vw-line-1); }
      .preview-row svg { flex: none; width: 16px; height: 16px; color: var(--vw-muted); }
      .preview .description { margin: 10px 0 0; }
      @media (max-width: 1000px) { .layout { grid-template-columns: minmax(0, 1fr); gap: 24px; } .preview { max-width: 320px; } }
      @media (max-width: 520px) { .theme-group { padding: 20px; } vw-setting-card::part(card) { padding: 20px; } .theme-options { gap: 10px; } }
    `,
  ];

  private onTheme(id: string): void {
    setTheme(id as ThemeSetting);
    this.requestUpdate();
  }

  private onLanguage(value: string): void {
    setLocale(value as Locale);
    this.requestUpdate();
  }

  private onDensity(checked: boolean): void {
    setDensity(checked ? 'compact' : ('comfortable' as DensitySetting));
    this.requestUpdate();
  }

  protected override render() {
    const themeOptions = [
      { id: 'system', label: t('options.appearance.themeSystem') },
      { id: 'light', label: t('options.appearance.themeLight') },
      { id: 'dark', label: t('options.appearance.themeDark') },
    ];
    const langOptions = [
      { value: 'zh-CN', label: t('options.appearance.langZh') },
      { value: 'en', label: t('options.appearance.langEn') },
    ];
    return html`
      <div class="layout">
      <div class="sheet">
        <section class="theme-group" aria-labelledby="theme-heading">
          <h2 id="theme-heading">${t('options.appearance.theme')}</h2>
          <p class="description">${t('options.appearance.themeDesc')}</p>
          <div class="theme-options" role="radiogroup" aria-labelledby="theme-heading">
            ${themeOptions.map((option) => html`
              <label class="theme-option">
                <input type="radio" name="theme" .value=${option.id} .checked=${getTheme() === option.id}
                  @change=${() => this.onTheme(option.id)} />
                <span class="swatch ${option.id}" aria-hidden="true"></span>
                <span class="theme-label">${option.label}${getTheme() === option.id ? uiIcon('check') : ''}</span>
              </label>
            `)}
          </div>
        </section>

      <vw-setting-card heading=${t('options.appearance.language')} description=${t('options.appearance.languageDesc')}>
        <vw-select
          .options=${langOptions}
          .value=${getLocale()}
          .label=${t('options.appearance.language')}
          @vw-select-change=${(e: CustomEvent<{ value: string }>) => this.onLanguage(e.detail.value)}
        ></vw-select>
      </vw-setting-card>
      <vw-setting-card heading=${t('options.appearance.density')} description=${t('options.appearance.densityDesc')}>
        <vw-toggle
          .label=${t('options.appearance.density')}
          .checked=${getDensity() === 'compact'}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => this.onDensity(e.detail.checked)}
        ></vw-toggle>
      </vw-setting-card>
      </div>
      <aside class="preview" aria-labelledby="preview-heading">
        <h2 id="preview-heading">${t('options.appearance.preview')}</h2>
        <div class="preview-list" aria-hidden="true">
          <div class="preview-row">${uiIcon('key')}<span>${t('cat.login')}</span></div>
          <div class="preview-row">${uiIcon('card')}<span>${t('cat.card')}</span></div>
          <div class="preview-row">${uiIcon('note')}<span>${t('cat.note')}</span></div>
        </div>
        <p class="description">${t('options.appearance.previewDesc')}</p>
      </aside>
      </div>

    `;
  }
}

customElements.define('vw-appearance-section', VwAppearanceSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-appearance-section': VwAppearanceSection;
  }
}
