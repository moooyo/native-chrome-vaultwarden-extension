import { LitElement, css, html } from 'lit';
import type { ManualAutofillAction, ManualAutofillWarningData } from '../../../messaging/protocol.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';

export interface ManualAutofillActionDetail {
  readonly action: ManualAutofillAction;
}

export class VwManualAutofillConfirmation extends LitElement {
  static override properties = {
    name: { type: String },
    warning: { attribute: false },
    pending: { type: Boolean },
  };

  declare name: string;
  declare warning: ManualAutofillWarningData;
  declare pending: boolean;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.name = '';
    this.warning = { risk: 'no_match', site: '', canSave: false, requiresReprompt: false };
    this.pending = false;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display:flex; flex:1; min-height:0; background:var(--vw-panel); }
      .view { width:100%; padding:22px 18px 18px; display:flex; flex-direction:column; gap:16px; }
      .icon {
        width:42px; height:42px; display:grid; place-items:center; border-radius:8px;
        background:var(--vw-danger-soft); color:var(--vw-danger);
      }
      .icon svg { width:22px; height:22px; }
      h1 { margin:0; color:var(--vw-ink); font:600 18px/1.25 var(--vw-font-ui); letter-spacing:0; }
      .name { margin-top:-9px; color:var(--vw-text-2); font-size:13px; overflow-wrap:anywhere; }
      .warning { margin:0; color:var(--vw-ink); font-size:13px; line-height:1.5; }
      .site { color:var(--vw-text-2); font-size:12px; overflow-wrap:anywhere; }
      .actions { margin-top:auto; display:grid; gap:8px; }
      button {
        min-height:38px; padding:8px 12px; border:0; border-radius:8px;
        font:500 12.5px/1.3 var(--vw-font-ui); cursor:pointer;
      }
      button:disabled { cursor:default; opacity:.55; }
      .primary { background:var(--p); color:var(--onp); }
      .secondary { background:var(--pc); color:var(--onpc); }
      .cancel { background:transparent; color:var(--vw-text-2); }
      button:focus-visible { outline:none; box-shadow:var(--vw-focus); }
    `,
  ];

  private warningText(): string {
    switch (this.warning.risk) {
      case 'never': return t('fill.manual.never');
      case 'https_downgrade': return t('fill.manual.httpsDowngrade');
      case 'no_match': return t('fill.manual.noMatch');
    }
  }

  private choose(action: ManualAutofillAction): void {
    if (!this.pending) emit<ManualAutofillActionDetail>(this, 'vw-manual-autofill-action', { action });
  }

  protected override render() {
    return html`
      <section class="view" aria-labelledby="manual-autofill-title">
        <span class="icon" aria-hidden="true">${uiIcon('alert')}</span>
        <h1 id="manual-autofill-title">${t('fill.manual.title')}</h1>
        <div class="name">${this.name}</div>
        <p class="warning">${this.warningText()}</p>
        <div class="site">${t('fill.manual.site', { site: this.warning.site })}</div>
        ${this.warning.recipientSite
          ? html`<div class="site">${t('fill.manual.recipientSite', { site: this.warning.recipientSite })}</div>`
          : ''}
        <div class="actions">
          <button
            type="button"
            class="primary"
            ?disabled=${this.pending}
            @click=${() => this.choose('fill_only')}
          >${t('fill.manual.fillOnly')}</button>
          ${this.warning.canSave
            ? html`<button
                type="button"
                class="secondary"
                ?disabled=${this.pending}
                @click=${() => this.choose('fill_and_save')}
              >${t('fill.manual.fillAndSave')}</button>`
            : ''}
          <button
            type="button"
            class="cancel"
            ?disabled=${this.pending}
            @click=${() => emit(this, 'vw-manual-autofill-cancel')}
          >${t('fill.manual.cancel')}</button>
        </div>
      </section>
    `;
  }
}

customElements.define('vw-manual-autofill-confirmation', VwManualAutofillConfirmation);

declare global {
  interface HTMLElementTagNameMap {
    'vw-manual-autofill-confirmation': VwManualAutofillConfirmation;
  }
}
