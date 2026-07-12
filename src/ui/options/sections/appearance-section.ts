import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
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
import '../../components/segmented.js';
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
      :host { display: flex; flex-direction: column; gap: 8px; }
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
      { id: 'light', label: t('options.appearance.themeLight') },
      { id: 'dark', label: t('options.appearance.themeDark') },
      { id: 'system', label: t('options.appearance.themeSystem') },
    ];
    const langOptions = [
      { value: 'zh-CN', label: t('options.appearance.langZh') },
      { value: 'en', label: t('options.appearance.langEn') },
    ];
    return html`
      <vw-setting-card heading=${t('options.appearance.theme')} description=${t('options.appearance.themeDesc')}>
        <vw-segmented
          style="width:230px"
          .options=${themeOptions}
          .value=${getTheme()}
          .height=${26}
          @vw-segmented-change=${(e: CustomEvent<{ id: string }>) => this.onTheme(e.detail.id)}
        ></vw-segmented>
      </vw-setting-card>

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
          .checked=${getDensity() === 'compact'}
          @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => this.onDensity(e.detail.checked)}
        ></vw-toggle>
      </vw-setting-card>
    `;
  }
}

customElements.define('vw-appearance-section', VwAppearanceSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-appearance-section': VwAppearanceSection;
  }
}
