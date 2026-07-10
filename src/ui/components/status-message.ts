import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from './tokens.js';
import { controlStyles } from './styles.js';
import { uiIcon, type IconName } from './icon.js';

export type StatusTone = 'info' | 'success' | 'warning' | 'danger';

/**
 * A dormant, reusable live-region message. Danger-toned messages use
 * role="alert" (assertive) so they interrupt; every other tone uses
 * role="status" (polite) so it announces without stealing focus.
 */
export class VwStatusMessage extends LitElement {
  static override properties = {
    tone: { type: String },
    message: { type: String },
    icon: { attribute: false },
  };

  declare tone: StatusTone;
  declare message: string;
  declare icon: IconName | undefined;

  constructor() {
    super();
    this.tone = 'info';
    this.message = '';
    this.icon = undefined;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      .status {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px 12px;
        border-radius: var(--vw-radius-control);
        border: 1px solid var(--vw-line);
        background: var(--vw-blue-50);
        color: var(--vw-ink);
        font-size: 13px;
      }
      .status.tone-success {
        border-color: var(--vw-ok);
      }
      .status.tone-warning {
        border-color: var(--vw-blue-600);
      }
      .status.tone-danger {
        border-color: var(--vw-danger);
        background: transparent;
      }
    `,
  ];

  protected override render() {
    if (!this.message) {
      return nothing;
    }
    const isDanger = this.tone === 'danger';
    return html`
      <div
        class="status tone-${this.tone}"
        role=${isDanger ? 'alert' : 'status'}
        aria-live=${isDanger ? 'assertive' : 'polite'}
      >
        ${this.icon ? uiIcon(this.icon) : nothing}
        <span>${this.message}</span>
      </div>
    `;
  }
}

customElements.define('vw-status-message', VwStatusMessage);

declare global {
  interface HTMLElementTagNameMap {
    'vw-status-message': VwStatusMessage;
  }
}
