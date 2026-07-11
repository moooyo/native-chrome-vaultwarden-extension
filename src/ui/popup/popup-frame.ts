import { LitElement, css, html } from 'lit';
import { themeTokens } from '../components/tokens.js';
import type { PopupLayoutMode } from './types.js';

export type { PopupLayoutMode } from './types.js';

/** Geometry-only popup frame. Feature roots own all navigation, data, and privileged actions. */
export class VwPopupFrame extends LitElement {
  static override properties = {
    mode: { type: String, reflect: true },
  };

  declare mode: PopupLayoutMode;

  constructor() {
    super();
    this.mode = 'double';
  }

  static override styles = [
    themeTokens,
    css`
      :host {
        display: block;
        width: var(--vw-popup-double-width);
        height: var(--vw-popup-height);
        overflow: hidden;
        background: var(--vw-panel);
      }
      :host([mode='single']),
      :host([mode='auth']) {
        width: var(--vw-popup-single-width);
      }
      [data-popup-frame] {
        width: 100%;
        height: 100%;
        min-width: 0;
        min-height: 0;
        box-sizing: border-box;
        overflow: hidden;
        background: var(--vw-panel);
        color: var(--vw-ink);
      }
      .frame {
        display: grid;
        grid-template-rows: 52px minmax(0, 1fr);
      }
      header {
        min-width: 0;
        border-bottom: 1px solid var(--vw-line);
      }
      .workspace {
        display: grid;
        grid-template-columns: var(--vw-pane-list-width) minmax(0, var(--vw-pane-detail-width));
        min-width: 0;
        min-height: 0;
      }
      [data-list-pane],
      [data-detail-pane],
      [data-single-pane] {
        box-sizing: border-box;
        min-width: 0;
        min-height: 0;
        overflow: auto;
        scrollbar-gutter: stable;
      }
      [data-list-pane] {
        border-right: 1px solid var(--vw-line);
      }
    `,
  ];

  protected override render() {
    if (this.mode !== 'double') {
      return html`<section data-popup-frame data-single-pane><slot></slot></section>`;
    }
    return html`
      <section data-popup-frame class="frame">
        <header><slot name="toolbar"></slot></header>
        <div class="workspace">
          <aside data-list-pane><slot name="list"></slot></aside>
          <main data-detail-pane><slot name="detail"></slot></main>
        </div>
      </section>
    `;
  }
}

customElements.define('vw-popup-frame', VwPopupFrame);

declare global {
  interface HTMLElementTagNameMap {
    'vw-popup-frame': VwPopupFrame;
  }
}
