import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/logo.js';

/**
 * About, MiYu styling: a centered hero card with the logo, brand name, extension version, and an
 * accurate product relationship note. It does not present unavailable documents as links.
 */
export class VwAboutSection extends LitElement {
  static override properties = {
    version: { type: String },
  };

  declare version: string;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.version = '';
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: block; }
      .card {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 14px;
        max-width: 360px;
        margin: 8px auto 0;
        padding: 32px 28px;
        text-align: center;
        background: var(--vw-card);
        border: 1px solid var(--vw-line-1);
        border-radius: var(--vw-radius-card);
      }
      .name { font-size: 15px; font-weight: 600; color: var(--vw-ink); }
      .version { font-family: var(--vw-font-mono); font-size: 12px; color: var(--vw-muted); }
      .description { margin-top: 16px; text-align: center; font-size: 11px; color: var(--vw-faint); }
    `,
  ];

  protected override render() {
    return html`
      <div class="card">
        <vw-logo variant="hero"></vw-logo>
        <div class="name">${t('common.appName')}</div>
        <div class="version" data-version>${t('options.about.version', { version: this.version })}</div>
      </div>
      <div class="description" data-description>${t('options.about.description')}</div>
    `;
  }
}

customElements.define('vw-about-section', VwAboutSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-about-section': VwAboutSection;
  }
}
