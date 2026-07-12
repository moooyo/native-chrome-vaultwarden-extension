import { LitElement, css, html } from 'lit';
import { themeTokens } from './tokens.js';

/**
 * `vw-totp-meter` — display-only one-time-code readout: the mono code (grouped "XXX XXX"), the
 * seconds remaining, and a progress bar that drains over the period. Used in the popup inline detail
 * (16px) and the 2FA autofill panel (18px). The parent owns the countdown state and copy button.
 */
export class VwTotpMeter extends LitElement {
  static override properties = {
    code: { type: String },
    period: { type: Number },
    remaining: { type: Number },
    codeSize: { type: Number },
  };

  declare code: string;
  declare period: number;
  declare remaining: number;
  declare codeSize: number;

  constructor() {
    super();
    this.code = '';
    this.period = 30;
    this.remaining = 30;
    this.codeSize = 16;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: block; }
      .row { display: flex; align-items: center; gap: 8px; }
      .code {
        font-family: var(--vw-font-mono);
        font-weight: 600;
        color: var(--vw-teal-text);
        letter-spacing: 0.08em;
      }
      .secs { font-size: 10.5px; color: var(--vw-faint); flex: none; }
      .track {
        flex: 1;
        height: 3px;
        border-radius: 2px;
        background: var(--vw-track);
        overflow: hidden;
      }
      .fill {
        height: 100%;
        background: var(--vw-accent);
        transition: width 1s linear;
      }
    `,
  ];

  private grouped(): string {
    const c = this.code ?? '';
    if (c.length === 6) return `${c.slice(0, 3)} ${c.slice(3)}`;
    if (c.length === 8) return `${c.slice(0, 4)} ${c.slice(4)}`;
    return c;
  }

  protected override render() {
    const period = this.period || 30;
    const pct = Math.max(0, Math.min(100, Math.round((this.remaining / period) * 100)));
    return html`
      <div class="row">
        <span class="code" style=${`font-size:${this.codeSize}px`}>${this.grouped()}</span>
        <span class="secs">${this.remaining}s</span>
        <span class="track"><span class="fill" style=${`width:${pct}%`}></span></span>
      </div>
    `;
  }
}

customElements.define('vw-totp-meter', VwTotpMeter);

declare global {
  interface HTMLElementTagNameMap {
    'vw-totp-meter': VwTotpMeter;
  }
}
