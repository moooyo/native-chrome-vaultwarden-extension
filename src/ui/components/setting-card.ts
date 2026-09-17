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
        flex-wrap: wrap;
        align-items: center;
        gap: 12px 20px;
        min-height:var(--vw-setting-row-min, 68px);
        padding:var(--vw-setting-row-padding-block, 13px) 16px;
        background: var(--vw-card);
        border:1px solid var(--vw-line-1);
        border-radius:var(--vw-radius-card);
      }
      .card.stacked { flex-direction: column; align-items: stretch; gap: var(--vw-setting-stack-gap, 12px); }
      .card.danger { border-color: var(--vw-danger-border); }
      .text { flex: 1 1 180px; min-width: 0; }
      .card.stacked .text { flex-basis: auto; }
      .title { font-size:13px; font-weight:500; color:var(--vw-ink); line-height:1.5; }
      .title.strong { font-weight:600; }
      .title.danger { color: var(--vw-danger); font-weight: 600; }
      .desc { margin-top:4px; font-size:12px; color:var(--vw-text-2); line-height:1.7; overflow-wrap:anywhere; }
      .control { flex: 0 1 auto; min-width: 0; max-width: 100%; display: inline-flex; align-items: center; gap: 8px; }
      .card.stacked .control { flex: 1; }
    `,
  ];

  protected override render() {
    return html`
      <div class="card ${this.danger ? 'danger' : ''} ${this.stacked ? 'stacked' : ''}" part="card">
        <div class="text">
          <div class="title ${this.emphasized ? 'strong' : ''} ${this.danger ? 'danger' : ''}" part="title">${this.heading}</div>
          ${this.description ? html`<div class="desc" part="description">${this.description}</div>` : nothing}
        </div>
        <div class="control" part="control"><slot></slot></div>
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
