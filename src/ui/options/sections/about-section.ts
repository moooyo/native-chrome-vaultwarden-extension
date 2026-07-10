import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';

/**
 * About: the extension version and a plain statement that vault secrets are derived and stored
 * locally on this device and never leave it in plaintext. Purely presentational — no state, no
 * requests, no events.
 */
export class VwAboutSection extends LitElement {
  static override properties = {
    version: { type: String },
  };

  declare version: string;

  constructor() {
    super();
    this.version = '';
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host { display: block; max-width: 760px; }
      h1 { margin: 0 0 24px; font-size: 28px; color:var(--vw-ink-strong); }
      dl { display: grid; grid-template-columns: auto 1fr; gap: 6px 16px; margin: 0 0 16px; font-size: 13px; }
      dt { color: var(--vw-muted); }
      dd { margin: 0; }
      .note { display: flex; gap: 8px; max-width: 620px; font-size: 13px; color: var(--vw-ink); border: 1px solid var(--vw-line); border-radius: var(--vw-radius-row); padding: 16px 12px; background:var(--vw-panel); }
      .note svg { width: 18px; height: 18px; flex: none; color: var(--vw-muted); }
    `,
  ];

  protected override render() {
    return html`
      <h1>About</h1>
      <dl>
        <dt>Version</dt>
        <dd data-version>${this.version}</dd>
      </dl>
      <p class="note">${uiIcon('shield')}<span>Your master password and vault keys are derived and kept only on this local device. Secrets never leave the device in plaintext.</span></p>
    `;
  }
}

customElements.define('vw-about-section', VwAboutSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-about-section': VwAboutSection;
  }
}
