import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { controlStyles } from '../../components/styles.js';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';
import { authIdentityStyles, renderAuthIdentity, type AuthIdentityDisplay } from '../auth/auth-identity.js';
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
    identity: { attribute: false },
    confirmingLeave: { state: true },
    actionLocked: { state: true },
  };

  declare model: DataOwnershipMigrationModel | undefined;
  declare pending: boolean;
  declare error: string | undefined;
  declare reconciliation: DataOwnershipReconciliationModel | undefined;
  declare identity: AuthIdentityDisplay | undefined;
  private declare confirmingLeave: boolean;
  private declare actionLocked: boolean;
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
    this.identity = undefined;
    this.confirmingLeave = false;
    this.actionLocked = false;
    this.leaveTarget = undefined;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    authIdentityStyles,
    css`
      :host { display:flex; flex:1; min-width:0; min-height:0; background:var(--vw-panel); color:var(--vw-ink); }
      .view { display:flex; flex:1; min-width:0; min-height:0; flex-direction:column; }
      .head { display:flex; align-items:center; gap:10px; min-height:52px; padding:10px 18px; border-bottom:1px solid var(--vw-line-1); }
      .head svg { width:17px; height:17px; color:var(--vw-teal-text); }
      h1 { margin:0; font-size:18px; font-weight:600; line-height:1.4; letter-spacing:-0.015em; }
      .body { display:flex; flex:1; min-width:0; min-height:0; flex-direction:column; gap:16px; padding:18px; overflow-y:auto; }
      p { margin:0; color:var(--vw-text-2); font-size:12.5px; line-height:1.55; }
      .destination { display:grid; grid-template-columns:max-content minmax(0,1fr); gap:9px 12px; margin:0; padding:14px 0; border-top:1px solid var(--vw-line-1); border-bottom:1px solid var(--vw-line-1); }
      .destination dt { color:var(--vw-muted); font-size:12px; }
      .destination dd { min-width:0; margin:0; overflow-wrap:anywhere; color:var(--vw-ink); font-size:12px; font-weight:600; }
      form { display:flex; flex-direction:column; gap:16px; min-width:0; }
      .field { display:flex; flex-direction:column; gap:7px; min-width:0; }
      .label { color:var(--vw-text-2); font-size:12px; font-weight:500; }
      .input { min-height:40px; padding:0 12px; border:1px solid var(--vw-line-2); border-radius:var(--vw-radius-input); background:var(--vw-panel); color:var(--vw-ink); font:13px var(--vw-font-ui); }
      .input:focus { outline:none; border-color:var(--vw-accent); box-shadow:var(--vw-focus); }
      .actions { display:flex; gap:8px; }
      .actions .btn { flex:1; min-width:0; }
      vw-status-message { width:100%; }
      @media (max-width:340px) { .actions { flex-direction:column; } }
    `,
  ];

  override disconnectedCallback(): void {
    this.scrubPassword();
    super.disconnectedCallback();
  }

  protected override willUpdate(changed: PropertyValues<this>): void {
    if ((changed.has('pending') && !this.pending) || changed.has('error')
        || changed.has('model') || changed.has('reconciliation')) {
      this.actionLocked = false;
    }
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
    if (this.pending || this.actionLocked || !this.model?.migrationAvailable || !this.model.collectionId
        || !this.model.migrateAuthorizationId) return;
    const password = this.renderRoot.querySelector<HTMLInputElement>('[data-master-password]');
    if (!password?.value) return;
    const masterPassword = password.value;
    password.value = '';
    this.actionLocked = true;
    emit<DataOwnershipMigrationSubmitDetail>(this, 'vw-data-ownership-migrate', {
      masterPassword,
      organizationId: this.model.organizationId,
      collectionId: this.model.collectionId,
      authorizationId: this.model.migrateAuthorizationId,
    });
  }

  private requestLeave(): void {
    if (this.pending || this.actionLocked || !this.model) return;
    this.scrubPassword();
    this.leaveTarget = {
      organizationId: this.model.organizationId,
      organizationName: this.model.organizationName,
      authorizationId: this.model.leaveAuthorizationId,
    };
    this.confirmingLeave = true;
  }

  private cancelLeave(): void {
    if (this.pending || this.actionLocked) return;
    this.confirmingLeave = false;
    this.leaveTarget = undefined;
  }

  private confirmLeave(): void {
    const target = this.leaveTarget;
    const model = this.model;
    if (this.pending || this.actionLocked || !this.confirmingLeave || !target || !model
        || target.organizationId !== model.organizationId
        || target.authorizationId !== model.leaveAuthorizationId) return;
    this.actionLocked = true;
    emit<DataOwnershipLeaveDetail>(this, 'vw-data-ownership-leave', {
      organizationId: target.organizationId,
      authorizationId: target.authorizationId,
    });
  }

  private retry(): void {
    if (this.pending || this.actionLocked) return;
    this.actionLocked = true;
    emit(this, 'vw-data-ownership-retry');
  }

  protected override render() {
    const model = this.model;
    const leaveTarget = this.confirmingLeave ? this.leaveTarget : undefined;
    const disabled = this.pending || this.actionLocked;
    return html`
      <section class="view" aria-busy=${disabled ? 'true' : 'false'}>
        <header class="head">${uiIcon('shield')}<h1>${t('dataOwnership.title')}</h1></header>
        <main class="body">
          ${renderAuthIdentity(this.identity)}
          ${model
            ? html`
                ${leaveTarget ? nothing : html`<p>${model.migrationAvailable
                  ? t('dataOwnership.description', { count: model.personalItemCount })
                  : t('dataOwnership.blockedDescription', { count: model.personalItemCount })}</p>`}
                <dl class="destination">
                  <dt>${t('dataOwnership.organization')}</dt><dd>${leaveTarget?.organizationName ?? model.organizationName}</dd>
                  ${!leaveTarget && model.collectionName
                    ? html`<dt>${t('dataOwnership.collection')}</dt><dd>${model.collectionName}</dd>`
                    : nothing}
                </dl>
                ${this.error
                  ? html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.error}></vw-status-message>`
                  : nothing}
                ${leaveTarget
                  ? html`
                      <vw-status-message tone="danger" .icon=${'alert'} .message=${t('dataOwnership.leaveWarning', { organization: leaveTarget.organizationName })}></vw-status-message>
                      <div class="actions">
                        <button type="button" class="btn outline" ?disabled=${disabled} @click=${this.cancelLeave}>${t('common.back')}</button>
                        <button type="button" class="btn danger" data-confirm-leave ?disabled=${disabled} @click=${this.confirmLeave}>${t('dataOwnership.confirmLeave')}</button>
                      </div>
                    `
                  : model.migrationAvailable
                    ? html`<form @submit=${(event: Event) => { event.preventDefault(); this.submit(); }}>
                        <label class="field">
                          <span class="label">${t('auth.masterPassword')}</span>
                          <input class="input" data-master-password type="password" autocomplete="current-password" required ?disabled=${disabled} />
                        </label>
                        <div class="actions">
                          <button type="button" class="btn danger" ?disabled=${disabled} @click=${this.requestLeave}>${t('dataOwnership.leave')}</button>
                          <button type="submit" class="btn primary" ?disabled=${disabled}>${t('dataOwnership.migrate')}</button>
                        </div>
                      </form>`
                    : html`
                        <vw-status-message tone="warning" .icon=${'alert'} .message=${t('dataOwnership.unavailable')}></vw-status-message>
                        <div class="actions">
                          <button type="button" class="btn danger" ?disabled=${disabled} @click=${this.requestLeave}>${t('dataOwnership.leave')}</button>
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
                  <button type="button" class="btn outline" data-full-sync ?disabled=${disabled} @click=${this.retry}>${this.reconciliation
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
