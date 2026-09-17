import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/logo.js';

/**
 * About presents the client identity and its real extension version in a quiet information sheet.
 * It does not present unavailable documents as links or claim an official project relationship.
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
        max-width: 720px;
        background: var(--vw-card);
        border: 1px solid var(--vw-line-1);
        border-radius: 12px;
      }
      .identity { display: flex; align-items: center; gap: 18px; padding: 28px 24px; }
      .name { margin: 0; font-size: 20px; font-weight: 600; color: var(--vw-ink); line-height: 1.4; letter-spacing: -.3px; }
      .description { margin: 7px 0 0; font-size: 13px; line-height: 1.6; color: var(--vw-muted); }
      .facts { margin: 0; padding: 20px 24px; border-top: 1px solid var(--vw-line-1); }
      .fact { display: grid; grid-template-columns: minmax(100px, 150px) minmax(0, 1fr); align-items: baseline; gap: 18px; }
      dt { color: var(--vw-muted); font-size: 12px; }
      .version { margin: 0; font-family: var(--vw-font-mono); font-size: 13px; color: var(--vw-ink); overflow-wrap: anywhere; }
      @media (max-width: 520px) { .identity { align-items: flex-start; gap: 14px; padding: 24px 20px; } .facts { padding: 20px; } }
    `,
  ];

  protected override render() {
    return html`
      <div class="card">
        <div class="identity">
          <vw-logo variant="hero"></vw-logo>
          <div>
            <h2 class="name">${t('common.appName')}</h2>
            <p class="description" data-description>${t('options.about.description')}</p>
          </div>
        </div>
        <dl class="facts"><div class="fact">
          <dt>${t('options.about.versionLabel')}</dt>
          <dd class="version" data-version>${this.version || '—'}</dd>
        </div></dl>
      </div>
    `;
  }
}

customElements.define('vw-about-section', VwAboutSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-about-section': VwAboutSection;
  }
}
