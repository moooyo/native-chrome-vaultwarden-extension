import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon, type IconName } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import type { EditorTypeDetail } from './editor-types.js';

/** The baseline creatable cipher types, in the design's order, each with its tile icon. */
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
  static override properties = {
    sshAvailability: { type: String },
  };

  declare sshAvailability: 'loading' | 'available' | 'unavailable';

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.sshAvailability = 'loading';
  }

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
        flex-direction: row;
        gap: 6px;
        padding: 4px 14px 16px;
        overflow-y: auto;
        min-height: 0;
      }
      .type-row {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 6px;
        flex: 1;
        min-width: 0;
        height: 82px;
        padding: 8px 4px;
        border: 1px solid var(--vw-line-3);
        border-radius: 16px;
        background: transparent;
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        text-align: left;
        cursor: pointer;
        transition: background-color var(--vw-dur-fast), border-color var(--vw-dur-fast);
      }
      .type-row:hover {
        background: var(--pc);
        border-color: transparent;
      }
      .type-row:focus-visible {
        outline: none;
        box-shadow: var(--vw-focus);
      }
      .type-row:disabled {
        cursor: progress;
        opacity: 0.55;
      }
      .type-row:disabled:hover {
        background: transparent;
        border-color: var(--vw-line-3);
      }
      .checking svg { animation: mvSpin .8s linear infinite; }
      @media (prefers-reduced-motion: reduce) { .checking svg { animation: none; } }
      .tile {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex: none;
        width: 30px;
        height: 30px;
        border-radius: 15px;
        background: var(--vw-fill);
        color: var(--p);
      }
      .tile svg {
        width: 18px;
        height: 18px;
      }
      .name {
        flex: 1;
        min-width: 0;
        font-size: 11.5px;
        font-weight: 500;
        text-align: center;
      }
      .chev {
        display: none;
      }
      .chev svg {
        width: 16px;
        height: 16px;
      }
    `,
  ];

  private pick(type: 1 | 2 | 3 | 4 | 5): void {
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
        ${this.sshAvailability === 'available'
          ? html`
              <button type="button" class="type-row" data-type="5" @click=${() => this.pick(5)}>
                <span class="tile">${uiIcon('key')}</span>
                <span class="name">${t('editor.typeSshKey')}</span>
                <span class="chev">${uiIcon('chevron')}</span>
              </button>
            `
          : this.sshAvailability === 'loading'
            ? html`
                <button type="button" class="type-row" data-ssh-checking disabled>
                  <span class="tile checking">${uiIcon('refresh')}</span>
                  <span class="name">${t('ssh.checkingAvailability')}</span>
                  <span class="chev">${uiIcon('chevron')}</span>
                </button>
              `
            : nothing}
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
