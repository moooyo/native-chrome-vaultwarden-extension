import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon, type IconName } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import type { EditorTypeDetail } from './editor-types.js';

/** Supported cipher types follow the purpose-led order used in the final design. */
const TYPES: ReadonlyArray<readonly [1 | 2 | 3 | 4, () => string, () => string, IconName]> = [
  [1, () => t('editor.typeLogin'), () => t('editor.typeLoginHint'), 'key'],
  [3, () => t('editor.typeCard'), () => t('editor.typeCardHint'), 'card'],
  [4, () => t('editor.typeIdentity'), () => t('editor.typeIdentityHint'), 'idcard'],
  [2, () => t('editor.typeNote'), () => t('editor.typeNoteHint'), 'note'],
];

/**
 * Step one of "add item": pick a cipher type. Purely presentational — it emits the chosen type via
 * `vw-editor-type` and a back request via `vw-item-back`; the root navigates to the concrete editor.
 * Each full-width row identifies its purpose before navigating to the dedicated editor.
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
        background: var(--vw-panel);
      }
      .head {
        display: flex;
        align-items: center;
        gap: 8px;
        flex: none;
        min-height: 52px;
        padding: 8px 14px;
        border-bottom: 1px solid var(--vw-line-1);
      }
      .head h1 {
        margin: 0;
        flex: 1;
        min-width: 0;
        font-size: 16px;
        font-weight: 600;
        color: var(--vw-ink);
      }
      .list {
        display: flex;
        flex-direction: column;
        padding: 8px 14px 20px;
        overflow-y: auto;
        min-height: 0;
      }
      .type-row {
        display: flex;
        appearance: none;
        align-items: center;
        gap: 12px;
        flex: none;
        width: 100%;
        min-width: 0;
        min-height: 76px;
        padding: 14px 10px;
        border: 0;
        border-bottom: 1px solid var(--vw-line-1);
        border-radius: 0;
        background: transparent;
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        text-align: left;
        cursor: pointer;
        transition: background-color var(--vw-dur-fast);
      }
      .type-row:hover {
        background: var(--vw-fill-2);
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
      }
      .type-row:last-child { border-bottom: 0; }
      .checking svg { animation: mvSpin .8s linear infinite; }
      @media (prefers-reduced-motion: reduce) { .checking svg { animation: none; } }
      .tile {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex: none;
        width: 36px;
        height: 36px;
        border-radius: var(--vw-radius-small);
        background: var(--vw-teal-10);
        color: var(--vw-accent);
      }
      .tile svg {
        width: 18px;
        height: 18px;
      }
      .copy {
        flex: 1;
        min-width: 0;
      }
      .name {
        display: block;
        font-size: 14px;
        font-weight: 600;
        line-height: 1.4;
      }
      .description {
        display: block;
        margin-top: 3px;
        color: var(--vw-text-3);
        font-size: 12px;
        font-weight: 400;
        line-height: 1.5;
      }
      .chev {
        display: inline-flex;
        flex: none;
        color: var(--vw-chevron);
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
          ([type, label, description, ic]) => html`
            <button type="button" class="type-row" data-type=${type} @click=${() => this.pick(type)}>
              <span class="tile">${uiIcon(ic)}</span>
              <span class="copy"><span class="name">${label()}</span><span class="description">${description()}</span></span>
              <span class="chev">${uiIcon('chevron')}</span>
            </button>
          `,
        )}
        ${this.sshAvailability === 'available'
          ? html`
              <button type="button" class="type-row" data-type="5" @click=${() => this.pick(5)}>
                <span class="tile">${uiIcon('key')}</span>
                <span class="copy"><span class="name">${t('editor.typeSshKey')}</span><span class="description">${t('editor.typeSshKeyHint')}</span></span>
                <span class="chev">${uiIcon('chevron')}</span>
              </button>
            `
          : this.sshAvailability === 'loading'
            ? html`
                <button type="button" class="type-row" data-ssh-checking disabled>
                  <span class="tile checking">${uiIcon('refresh')}</span>
                  <span class="copy"><span class="name">${t('ssh.checkingAvailability')}</span></span>
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
