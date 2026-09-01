import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { controlStyles } from '../../components/styles.js';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/status-message.js';

export interface DataOwnershipMigrationModel {
  readonly organizationId: string;
  readonly collectionId?: string;
  readonly migrateAuthorizationId?: string;
  readonly leaveAuthorizationId: string;
  readonly personalItemCount: number;
  readonly organizationName: string;
  readonly collectionName?: string;
  readonly migrationAvailable: boolean;
}

export interface DataOwnershipMigrationSubmitDetail {
  readonly masterPassword: string;
  readonly organizationId: string;
  readonly collectionId: string;
  readonly authorizationId: string;
}

export interface DataOwnershipLeaveDetail {
  readonly organizationId: string;
  readonly authorizationId: string;
}

export interface DataOwnershipReconciliationModel {
  readonly operation: 'migrate' | 'leave';
  readonly reason: 'outcome_unknown' | 'committed_unsynced';
}

export class VwDataOwnershipView extends LitElement {
  static override properties = {
    model: { attribute: false },
    pending: { type: Boolean },
    error: { type: String },
    reconciliation: { attribute: false },
    confirmingLeave: { state: true },
  };

  declare model: DataOwnershipMigrationModel | undefined;
  declare pending: boolean;
  declare error: string | undefined;
  declare reconciliation: DataOwnershipReconciliationModel | undefined;
  private declare confirmingLeave: boolean;
  private leaveTarget: {
    readonly organizationId: string;
    readonly organizationName: string;
    readonly authorizationId: string;
  } | undefined;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.model = undefined;
    this.pending = false;
    this.error = undefined;
    this.reconciliation = undefined;
    this.confirmingLeave = false;
    this.leaveTarget = undefined;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host { display:flex; flex:1; min-height:0; background:var(--vw-panel); }
      .view { display:flex; flex:1; min-height:0; flex-direction:column; }
      .head { display:flex; align-items:center; gap:9px; min-height:48px; padding:8px 14px; border-bottom:1px solid var(--vw-line-1); }
      .head svg { width:17px; height:17px; color:var(--vw-teal-text); }
      h1 { margin:0; font-size:14px; font-weight:600; letter-spacing:0; }
      .body { display:flex; flex:1; min-height:0; flex-direction:column; gap:13px; padding:16px; overflow-y:auto; }
      p { margin:0; color:var(--vw-text-2); font-size:12.5px; line-height:1.55; }
      dl { display:grid; grid-template-columns:max-content minmax(0,1fr); gap:7px 12px; margin:0; padding:11px 12px; border-top:1px solid var(--vw-line-1); border-bottom:1px solid var(--vw-line-1); }
      dt { color:var(--vw-muted); font-size:11px; }
      dd { min-width:0; margin:0; overflow-wrap:anywhere; color:var(--vw-ink); font-size:12px; font-weight:600; }
      form { display:flex; flex-direction:column; gap:11px; }
      .field { display:flex; flex-direction:column; gap:5px; }
      .label { color:var(--vw-muted); font-size:11px; }
      .input { min-height:34px; padding:0 10px; border:1px solid var(--vw-line-2); border-radius:var(--vw-radius-input); background:var(--vw-fill-2); color:var(--vw-ink); font:12px var(--vw-font-ui); }
      .input:focus { outline:none; border-color:var(--vw-accent); box-shadow:var(--vw-focus); }
      .actions { display:flex; gap:8px; }
      .actions .btn { flex:1; min-width:0; }
      vw-status-message { width:100%; }
    `,
  ];

  override disconnectedCallback(): void {
    this.scrubPassword();
    super.disconnectedCallback();
  }

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (!changed.has('model')) return;
    const previous = changed.get('model') as DataOwnershipMigrationModel | undefined;
    if (previous?.organizationId !== this.model?.organizationId
        || previous?.collectionId !== this.model?.collectionId
        || previous?.migrateAuthorizationId !== this.model?.migrateAuthorizationId
        || previous?.leaveAuthorizationId !== this.model?.leaveAuthorizationId) {
      this.scrubPassword();
      this.confirmingLeave = false;
      this.leaveTarget = undefined;
    }
  }

  private scrubPassword(): void {
    const password = this.renderRoot.querySelector<HTMLInputElement>('[data-master-password]');
    if (password) password.value = '';
  }

  private submit(): void {
    if (this.pending || !this.model?.migrationAvailable || !this.model.collectionId
        || !this.model.migrateAuthorizationId) return;
    const password = this.renderRoot.querySelector<HTMLInputElement>('[data-master-password]');
    if (!password?.value) return;
    const masterPassword = password.value;
    password.value = '';
    emit<DataOwnershipMigrationSubmitDetail>(this, 'vw-data-ownership-migrate', {
      masterPassword,
      organizationId: this.model.organizationId,
      collectionId: this.model.collectionId,
      authorizationId: this.model.migrateAuthorizationId,
    });
  }

  private requestLeave(): void {
    if (this.pending || !this.model) return;
    this.leaveTarget = {
      organizationId: this.model.organizationId,
      organizationName: this.model.organizationName,
      authorizationId: this.model.leaveAuthorizationId,
    };
    this.confirmingLeave = true;
  }

  private cancelLeave(): void {
    if (this.pending) return;
    this.confirmingLeave = false;
    this.leaveTarget = undefined;
  }

  protected override render() {
    const model = this.model;
    return html`
      <section class="view">
        <header class="head">${uiIcon('shield')}<h1>${t('dataOwnership.title')}</h1></header>
        <main class="body">
          ${model
            ? html`
                <p>${model.migrationAvailable
                  ? t('dataOwnership.description', { count: model.personalItemCount })
                  : t('dataOwnership.blockedDescription', { count: model.personalItemCount })}</p>
                <dl>
                  <dt>${t('dataOwnership.organization')}</dt><dd>${model.organizationName}</dd>
                  ${model.collectionName
                    ? html`<dt>${t('dataOwnership.collection')}</dt><dd>${model.collectionName}</dd>`
                    : nothing}
                </dl>
                ${this.error
                  ? html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.error}></vw-status-message>`
                  : nothing}
                ${this.confirmingLeave && this.leaveTarget
                  ? html`
                      <vw-status-message tone="danger" .icon=${'alert'} .message=${t('dataOwnership.leaveWarning', { organization: this.leaveTarget.organizationName })}></vw-status-message>
                      <div class="actions">
                        <button type="button" class="btn outline" ?disabled=${this.pending} @click=${this.cancelLeave}>${t('common.back')}</button>
                        <button type="button" class="btn danger" ?disabled=${this.pending} @click=${() => emit<DataOwnershipLeaveDetail>(this, 'vw-data-ownership-leave', { organizationId: this.leaveTarget!.organizationId, authorizationId: this.leaveTarget!.authorizationId })}>${t('dataOwnership.confirmLeave')}</button>
                      </div>
                    `
                  : model.migrationAvailable
                    ? html`<form @submit=${(event: Event) => { event.preventDefault(); this.submit(); }}>
                        <label class="field">
                          <span class="label">${t('auth.masterPassword')}</span>
                          <input class="input" data-master-password type="password" autocomplete="current-password" required ?disabled=${this.pending} />
                        </label>
                        <div class="actions">
                          <button type="button" class="btn danger" ?disabled=${this.pending} @click=${this.requestLeave}>${t('dataOwnership.leave')}</button>
                          <button type="submit" class="btn primary" ?disabled=${this.pending}>${t('dataOwnership.migrate')}</button>
                        </div>
                      </form>`
                    : html`
                        <vw-status-message tone="warning" .icon=${'alert'} .message=${t('dataOwnership.unavailable')}></vw-status-message>
                        <div class="actions">
                          <button type="button" class="btn danger" ?disabled=${this.pending} @click=${this.requestLeave}>${t('dataOwnership.leave')}</button>
                        </div>
                      `}
              `
            : html`
                <vw-status-message tone="warning" .icon=${'alert'} .message=${this.reconciliation
                  ? t('dataOwnership.reconciliationRequired')
                  : t('dataOwnership.unavailable')}></vw-status-message>
                ${this.error
                  ? html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.error}></vw-status-message>`
                  : nothing}
                <div class="actions">
                  <button type="button" class="btn outline" data-full-sync ?disabled=${this.pending} @click=${() => emit(this, 'vw-data-ownership-retry')}>${this.reconciliation
                    ? t('dataOwnership.fullSync')
                    : t('common.retry')}</button>
                </div>
              `}
        </main>
      </section>
    `;
  }
}

customElements.define('vw-data-ownership-view', VwDataOwnershipView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-data-ownership-view': VwDataOwnershipView;
  }
}
