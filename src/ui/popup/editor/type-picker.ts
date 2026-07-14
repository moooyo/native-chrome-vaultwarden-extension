import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon, type IconName } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import type { EditorTypeDetail } from './editor-types.js';

/** The four creatable cipher types, in the design's order (登录/银行卡/身份/笔记), each with its tile icon. */
const TYPES: ReadonlyArray<readonly [1 | 2 | 3 | 4, () => string, IconName]> = [
  [1, () => t('editor.typeLogin'), 'key'],
  [3, () => t('editor.typeCard'), 'card'],
  [4, () => t('editor.typeIdentity'), 'idcard'],
  [2, () => t('editor.typeNote'), 'note'],
];

/**
 * Step one of "add item": pick a cipher type. Purely presentational — it emits the chosen type via
 * `vw-editor-type` and a back request via `vw-item-back`; the root navigates to the concrete editor.
 * Reskinned to the MiYu system: a compact header (back + title) over a list of rows, each an icon
 * tile + label + chevron.
 */
export class VwTypePicker extends LitElement {
  private i18n = new LocalizeController(this);

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: flex;
        flex-direction: column;
        height: 100%;
        min-height: 0;
      }
      .head {
        display: flex;
        align-items: center;
        gap: 8px;
        flex: none;
        padding: 12px 14px 10px;
      }
      .head h1 {
        margin: 0;
        flex: 1;
        min-width: 0;
        font-size: 15.5px;
        font-weight: 600;
        color: var(--vw-ink);
      }
      .list {
        display: flex;
        flex-direction: column;
        gap: 8px;
        padding: 4px 14px 16px;
        overflow-y: auto;
        min-height: 0;
      }
      .type-row {
        display: flex;
        align-items: center;
        gap: 12px;
        width: 100%;
        padding: 10px 12px;
        border: 1px solid var(--vw-line-1);
        border-radius: var(--vw-radius-card);
        background: var(--vw-card);
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        text-align: left;
        cursor: pointer;
        transition: background-color var(--vw-dur-fast), border-color var(--vw-dur-fast);
      }
      .type-row:hover {
        background: var(--vw-row-hover);
        border-color: var(--vw-line-3);
      }
      .type-row:focus-visible {
        outline: none;
        box-shadow: var(--vw-focus);
      }
      .tile {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex: none;
        width: 34px;
        height: 34px;
        border-radius: var(--vw-radius-control);
        background: var(--vw-teal-10);
        color: var(--vw-teal-text);
      }
      .tile svg {
        width: 18px;
        height: 18px;
      }
      .name {
        flex: 1;
        min-width: 0;
        font-size: 13.5px;
        font-weight: 600;
      }
      .chev {
        display: inline-flex;
        color: var(--vw-chevron);
      }
      .chev svg {
        width: 16px;
        height: 16px;
      }
    `,
  ];

  private pick(type: 1 | 2 | 3 | 4): void {
    emit<EditorTypeDetail>(this, 'vw-editor-type', { type });
  }

  private back(): void {
    emit(this, 'vw-item-back');
  }

  protected override render() {
    return html`
      <div class="head">
        <button type="button" class="icon-btn" data-back title=${t('common.back')} aria-label=${t('common.back')} @click=${() => this.back()}>
          ${uiIcon('back')}
        </button>
        <h1>${t('editor.chooseType')}</h1>
      </div>
      <div class="list">
        ${TYPES.map(
          ([type, label, ic]) => html`
            <button type="button" class="type-row" data-type=${type} @click=${() => this.pick(type)}>
              <span class="tile">${uiIcon(ic)}</span>
              <span class="name">${label()}</span>
              <span class="chev">${uiIcon('chevron')}</span>
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
