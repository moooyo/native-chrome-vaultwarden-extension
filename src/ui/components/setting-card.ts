import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from './tokens.js';

/**
 * `vw-setting-card` — the recurring options-page row: a white card with a title (+ optional
 * description) on the left and a control slotted on the right. `danger` renders the destructive
 * variant (red border/title). The right-hand control goes in the default slot.
 */
export class VwSettingCard extends LitElement {
  static override properties = {
    heading: { type: String },
    description: { type: String },
    emphasized: { type: Boolean },
    danger: { type: Boolean },
    stacked: { type: Boolean },
  };

  declare heading: string;
  declare description: string;
  declare emphasized: boolean;
  declare danger: boolean;
  declare stacked: boolean;

  constructor() {
    super();
    this.heading = '';
    this.description = '';
    this.emphasized = false;
    this.danger = false;
    this.stacked = false;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: block; }
      .card {
        display: flex;
        align-items: center;
        gap: 14px;
        padding: 13px 16px;
        background: var(--vw-card);
        border: 1px solid var(--vw-line-1);
        border-radius: var(--vw-radius-card);
      }
      .card.stacked { flex-direction: column; align-items: stretch; gap: 12px; }
      .card.danger { border-color: var(--vw-danger-border); }
      .text { flex: 1; min-width: 0; }
      .title { font-size: 13.5px; color: var(--vw-ink); }
      .title.strong { font-weight: 600; }
      .title.danger { color: var(--vw-danger); font-weight: 600; }
      .desc { margin-top: 2px; font-size: 11.5px; color: var(--vw-muted); line-height: 1.5; }
      .control { flex: none; display: inline-flex; align-items: center; gap: 8px; }
      .card.stacked .control { flex: 1; }
    `,
  ];

  protected override render() {
    return html`
      <div class="card ${this.danger ? 'danger' : ''} ${this.stacked ? 'stacked' : ''}">
        <div class="text">
          <div class="title ${this.emphasized ? 'strong' : ''} ${this.danger ? 'danger' : ''}">${this.heading}</div>
          ${this.description ? html`<div class="desc">${this.description}</div>` : nothing}
        </div>
        <div class="control"><slot></slot></div>
      </div>
    `;
  }
}

customElements.define('vw-setting-card', VwSettingCard);

declare global {
  interface HTMLElementTagNameMap {
    'vw-setting-card': VwSettingCard;
  }
}
