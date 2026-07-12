import { LitElement, css, html } from 'lit';
import { themeTokens } from '../components/tokens.js';

/**
 * The MiYu popup shell — a single 372×560 column filling the popup window. The panel background,
 * fonts, and clipping live here; the app root fills the default slot with the top bar, the swappable
 * body, and the sync bar. (The design's floating rounded card + shadow are inherent to a browser
 * popup window, which is a rectangle, so the panel fills edge-to-edge rather than faking window
 * rounding.)
 */
export class VwPopupFrame extends LitElement {
  static override styles = [
    themeTokens,
    css`
      :host {
        display: block;
        width: 100%;
        height: 100%;
      }
      .panel {
        position: relative;
        display: flex;
        flex-direction: column;
        width: 100%;
        height: 100%;
        min-height: 0;
        overflow: hidden;
        background: var(--vw-panel);
        color: var(--vw-ink);
      }
    `,
  ];

  protected override render() {
    return html`<div class="panel"><slot></slot></div>`;
  }
}

customElements.define('vw-popup-frame', VwPopupFrame);

declare global {
  interface HTMLElementTagNameMap {
    'vw-popup-frame': VwPopupFrame;
  }
}
