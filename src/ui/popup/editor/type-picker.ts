import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon, type IconName } from '../../components/icon.js';
import type { EditorTypeDetail } from './editor-types.js';

const TYPES: ReadonlyArray<readonly [1 | 2 | 3 | 4, string, IconName]> = [
  [1, 'Login', 'key'],
  [2, 'Secure note', 'note'],
  [3, 'Card', 'card'],
  [4, 'Identity', 'idcard'],
];

/**
 * Step one of "add item": pick a cipher type. Purely presentational — it emits the chosen type via
 * `vw-editor-type` and a back request via `vw-item-back`; the root navigates to the concrete editor.
 */
export class VwTypePicker extends LitElement {
  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: block;
      }
      .head {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 6px 0 12px;
      }
      .head h1 {
        margin: 0;
        font-size: 15px;
      }
      .grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 8px;
      }
      .type {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 8px;
        height: 84px;
        border: 1px solid var(--vw-line);
        border-radius: var(--vw-radius-control);
        background: var(--vw-panel);
        color: var(--vw-ink);
        font-size: 13px;
        cursor: pointer;
      }
      .type:hover {
        border-color: var(--vw-blue-200);
        background: var(--vw-blue-50);
      }
      .type svg {
        width: 22px;
        height: 22px;
      }
      .head svg {
        width: 16px;
        height: 16px;
      }
    `,
  ];

  private pick(type: 1 | 2 | 3 | 4): void {
    this.dispatchEvent(new CustomEvent<EditorTypeDetail>('vw-editor-type', { detail: { type }, bubbles: true, composed: true }));
  }

  private back(): void {
    this.dispatchEvent(new CustomEvent('vw-item-back', { bubbles: true, composed: true }));
  }

  protected override render() {
    return html`
      <div class="head">
        <button type="button" class="icon-button" data-back title="Back" aria-label="Back" @click=${() => this.back()}>${uiIcon('back')}</button>
        <h1>Add item</h1>
      </div>
      <div class="grid">
        ${TYPES.map(
          ([type, label, ic]) => html`
            <button type="button" class="type" data-type=${type} @click=${() => this.pick(type)}>
              ${uiIcon(ic)}<span>${label}</span>
            </button>
          `,
        )}
      </div>
    `;
  }
}

customElements.define('vw-type-picker', VwTypePicker);

declare global {
  interface HTMLElementTagNameMap {
    'vw-type-picker': VwTypePicker;
  }
}
