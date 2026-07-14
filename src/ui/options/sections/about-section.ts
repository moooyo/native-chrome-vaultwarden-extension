import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/logo.js';
import '../../components/status-message.js';
import type { SectionStatus } from '../types.js';

/**
 * About, MiYu styling: a centered hero card with the logo, the brand name, the extension version,
 * and a "check for updates" action (emits `vw-check-update`; the root performs the check and drives
 * `status`). A footer line links the legal/security pages. Presentational apart from the one event.
 */
export class VwAboutSection extends LitElement {
  static override properties = {
    version: { type: String },
    status: { attribute: false },
  };

  declare version: string;
  declare status: SectionStatus | undefined;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.version = '';
    this.status = undefined;
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
      .check {
        display: inline-flex; align-items: center; justify-content: center; height: 34px; padding: 0 18px;
        border: none; border-radius: var(--vw-radius-control);
        background: var(--vw-primary-bg); color: var(--vw-primary-fg);
        font-family: inherit; font-size: 12.5px; font-weight: 600; cursor: pointer;
      }
      .check:hover { background: var(--vw-primary-bg-hover); }
      .check:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      .footer { margin-top: 16px; text-align: center; font-size: 11px; color: var(--vw-faint); }
    `,
  ];

  protected override render() {
    return html`
      <div class="card">
        <vw-logo variant="hero"></vw-logo>
        <div class="name">${t('common.appName')}</div>
        <div class="version" data-version>${t('options.about.version', { version: this.version })}</div>
        <button type="button" class="check" data-check-update @click=${() => emit(this, 'vw-check-update')}>
          ${t('options.about.checkUpdate')}
        </button>
        ${this.status
          ? html`<vw-status-message data-status .tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`
          : nothing}
      </div>
      <div class="footer">${t('options.about.links')}</div>
    `;
  }
}

customElements.define('vw-about-section', VwAboutSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-about-section': VwAboutSection;
  }
}
