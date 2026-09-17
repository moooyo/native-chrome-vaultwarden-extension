import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';
import type { AsyncState } from '../../components/async-state.js';
import {
  SEND_DATE_PRESET_HOURS,
  type SendInput,
  type SendSummary,
} from '../../../core/vault/sends.js';
import {
  normalizeSendDraft,
  sendDraftHasEdits,
  type SendDraftSnapshot,
} from '../../send-form-draft.js';
import '../../components/segmented.js';
import '../../components/select-menu.js';
import '../../components/toggle.js';
import '../../components/status-message.js';
import type { SectionStatus } from '../types.js';

const MAX_FILE_BYTES = 100 * 1024 * 1024;
const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;

/**
 * Send creation and grouped active/ended links. Content, access protection, and retention are
 * distinct form sections. Emits `vw-send-create`, confirmed `vw-send-delete`, and `vw-copy`;
 * the options root owns protocol requests and clipboard writes.
 */
export class VwSendSection extends LitElement {
  static override properties = {
    sends: { attribute: false },
    locked: { type: Boolean },
    pending: { type: Boolean },
    status: { attribute: false },
    validationError: { state: true },
    confirmingDeleteId: { state: true },
  };

  declare sends: AsyncState<SendSummary[]>;
  declare locked: boolean;
  declare pending: boolean;
  declare status: SectionStatus | undefined;
  declare validationError: string | undefined;
  declare confirmingDeleteId: string | null;

  private i18n = new LocalizeController(this);
  private formOpen = false;
  private kind: 'text' | 'file' = 'text';
  private passwordOn = false;
  private file: File | undefined;
  private draftBaseline: SendDraftSnapshot | undefined;
  private draftRevision = 0;
  private submittedRevision: number | undefined;
  private wasPending = false;

  constructor() {
    super();
    this.sends = { status: 'idle' };
    this.locked = false;
    this.pending = false;
    this.status = undefined;
    this.validationError = undefined;
    this.confirmingDeleteId = null;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: flex; flex-direction: column; gap: 18px; }
      .card { background: var(--vw-card); border: 1px solid var(--vw-line-1); border-radius: var(--vw-radius-card); padding: 22px; }
      * { box-sizing: border-box; }
      .intro { display: flex; align-items: center; gap: 14px; }
      .intro.card { padding: 0 0 18px; border: 0; border-bottom: 1px solid var(--vw-line-1); border-radius: 0; background: transparent; }
      .intro .text { flex: 1; }
      .intro .title { font-size: 18px; font-weight: 650; letter-spacing: -.3px; }
      .intro .desc { font-size: 13px; line-height: 1.6; color: var(--vw-muted); margin-top: 5px; }
      .btn-primary { display: inline-flex; align-items: center; justify-content: center; gap: 6px; min-height: 40px; padding: 8px 16px; border: none; border-radius: var(--vw-radius-input); background: var(--vw-primary-bg); color: var(--vw-primary-fg); font-family: inherit; font-size: 13px; font-weight: 600; cursor: pointer; }
      .btn-primary:hover { background: var(--vw-primary-bg-hover); }
      .btn-primary svg { width: 13px; height: 13px; }
      .btn-outline { min-height: 40px; padding: 8px 14px; border: 1px solid var(--vw-line-3); border-radius: var(--vw-radius-input); background: var(--vw-card); color: var(--vw-text-4); font-family: inherit; font-size: 13px; cursor: pointer; }
      .form { display: flex; flex-direction: column; gap: 22px; animation: sendEnter .18s ease-out; }
      .form-head { display: flex; align-items: center; }
      .form-head .t { font-size: 16px; font-weight: 650; flex: 1; }
      .form-section { display: flex; flex-direction: column; gap: 14px; padding: 0; margin: 0; border: 0; min-width: 0; }
      .form-section + .form-section { border-top: 1px solid var(--vw-line-1); padding-top: 20px; }
      .section-title { margin: 0; font-size: 13px; font-weight: 650; color: var(--vw-ink); }
      .field { display: flex; flex-direction: column; gap: 7px; min-width: 0; }
      .field label { font-size: 12px; color: var(--vw-text-3); }
      .hint { margin: 0; font-size: 12px; line-height: 1.6; color: var(--vw-muted); }
      .field input, .field textarea {
        width: 100%; box-sizing: border-box; min-height: 40px; padding: 9px 11px; border: 1px solid var(--vw-line-3);
        border-radius: var(--vw-radius-input); background: var(--vw-card); color: var(--vw-ink); font-family: inherit; font-size: 13px;
      }
      .field textarea { min-height: 132px; resize: vertical; line-height: 1.6; }
      .field input:focus, .field textarea:focus { outline: none; border-color: var(--vw-accent); }
      .controls { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; align-items: start; }
      .controls .field { gap: 6px; }
      .row-toggle { display: flex; align-items: center; justify-content: space-between; gap: 16px; font-size: 13px; color: var(--vw-text-3); }
      .actions { display: flex; justify-content: flex-end; gap: 8px; border-top: 1px solid var(--vw-line-1); padding-top: 18px; }
      .group-label { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 650; color: var(--vw-ink); padding: 0 0 10px; }
      .count { font-size: 11px; font-weight: 500; color: var(--vw-muted); }
      .send-list { overflow: hidden; border: 1px solid var(--vw-line-1); border-radius: var(--vw-radius-card); background: var(--vw-card); }
      .send { display: flex; flex-wrap: wrap; align-items: center; gap: 13px; padding: 16px; }
      .send + .send { border-top: 1px solid var(--vw-line-1); }
      .send.dead .tile { background: var(--vw-fill); color: var(--vw-muted); }
      .tile { width: 34px; height: 34px; border-radius: var(--vw-radius-control); background: var(--vw-teal-10); color: var(--vw-teal-text); display: grid; place-items: center; flex: none; }
      .tile svg { width: 17px; height: 17px; }
      .send .meta { flex: 1; min-width: 0; }
      .send .name { font-size: 13px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .send .sub { font-size: 11.5px; color: var(--vw-muted); }
      .send .sub { margin-top: 5px; line-height: 1.5; }
      .send .sub, .delete-confirm .copy { overflow-wrap: anywhere; }
      .send-actions { display: flex; gap: 4px; }
      .delete-confirm { flex-basis: 100%; display: flex; flex-wrap: wrap; align-items: center; gap: 10px; padding: 14px; border-radius: var(--vw-radius-input); background: var(--vw-danger-10); }
      .delete-confirm .copy { flex: 1; min-width: 160px; font-size: 13px; }
      .delete-confirm .hint { margin-top: 4px; }
      .btn-danger { color: var(--vw-danger); border-color: var(--vw-danger); }
      .icon-btn { width: 36px; height: 36px; border: none; border-radius: var(--vw-radius-input); background: transparent; color: var(--vw-text-2); cursor: pointer; display: grid; place-items: center; }
      .icon-btn:hover { background: var(--vw-icon-hover); }
      .icon-btn.danger { color: var(--vw-danger); }
      .icon-btn.danger:hover { background: var(--vw-danger-10); }
      .icon-btn svg { width: 15px; height: 15px; }
      .footer { font-size: 11px; color: var(--vw-faint); padding: 4px 2px; }
      .empty { padding: 24px; text-align: center; color: var(--vw-muted); font-size: 12.5px; }
      button:focus-visible, input:focus-visible, textarea:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      button:disabled { opacity: .5; cursor: default; }
      @keyframes sendEnter { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }
      @media (prefers-reduced-motion: reduce) { .form { animation: none; } }
      @media (max-width: 600px) { .controls { grid-template-columns: 1fr; } .intro { align-items: flex-start; } .card { padding: 18px; } }
    `,
  ];

  private emit(type: string, detail?: unknown): void {
    emit(this, type, detail);
  }

  private q<T extends HTMLElement>(sel: string): T | null {
    return this.renderRoot.querySelector<T>(sel);
  }

  override disconnectedCallback(): void {
    this.draftRevision += 1;
    this.submittedRevision = undefined;
    super.disconnectedCallback();
  }

  private selectValue(sel: string): string {
    return this.q<HTMLElement & { value: string }>(sel)?.value ?? '';
  }

  private toggleChecked(sel: string): boolean {
    return this.q<HTMLElement & { checked: boolean }>(sel)?.checked ?? false;
  }

  private createBaseline(): SendDraftSnapshot {
    return normalizeSendDraft({
      owner: 'create',
      type: 'text',
      passwordMode: 'none',
      expirationHours: SEND_DATE_PRESET_HOURS.sevenDays,
      deletionHours: SEND_DATE_PRESET_HOURS.fourteenDays,
      maxAccessCount: null,
    });
  }

  private currentDraft(): SendDraftSnapshot | undefined {
    if (!this.formOpen) return undefined;
    const password = this.passwordOn ? (this.q<HTMLInputElement>('[data-pass]')?.value ?? '') : '';
    const expiry = this.selectValue('[data-expiry]');
    return normalizeSendDraft({
      owner: 'create',
      type: this.kind,
      name: this.q<HTMLInputElement>('[data-name]')?.value ?? '',
      text: this.q<HTMLTextAreaElement>('[data-content]')?.value ?? '',
      ...(this.file ? { file: this.file } : {}),
      hideEmail: this.toggleChecked('[data-hide-email]'),
      passwordMode: password ? 'set' : 'none',
      password,
      expirationHours: expiry,
      deletionHours: this.selectValue('[data-deletion]'),
      maxAccessCount: this.selectValue('[data-max]'),
    });
  }

  /** Used by the options root before switching to another section. */
  sendFormHasEdits(): boolean {
    return sendDraftHasEdits(this.draftBaseline, this.currentDraft());
  }

  promptForUnsavedEdits(): boolean {
    if (this.formOpen && this.pending) return false;
    if (!this.sendFormHasEdits()) return true;
    return typeof window === 'undefined' || window.confirm(t('send.unsavedChanges'));
  }

  private changeKind(event: CustomEvent<{ id: string }>): void {
    const control = event.currentTarget as HTMLElement & { value: string };
    const next = event.detail.id as 'text' | 'file';
    if (this.pending || next === this.kind) {
      control.value = this.kind;
      return;
    }
    const variantHasValue = this.kind === 'text'
      ? (this.q<HTMLTextAreaElement>('[data-content]')?.value ?? '') !== ''
      : this.file !== undefined;
    if (variantHasValue && typeof window !== 'undefined' && !window.confirm(t('send.unsavedChanges'))) {
      control.value = this.kind;
      return;
    }
    if (this.kind === 'file') this.file = undefined;
    this.kind = next;
    this.validationError = undefined;
    this.requestUpdate();
  }

  private changePasswordEnabled(event: CustomEvent<{ checked: boolean }>): void {
    const control = event.currentTarget as HTMLElement & { checked: boolean };
    if (this.pending) {
      control.checked = this.passwordOn;
      return;
    }
    if (!event.detail.checked && this.passwordOn) {
      const password = this.q<HTMLInputElement>('[data-pass]')?.value ?? '';
      if (password && typeof window !== 'undefined' && !window.confirm(t('send.unsavedChanges'))) {
        control.checked = true;
        return;
      }
    }
    this.passwordOn = event.detail.checked;
    this.requestUpdate();
  }

  private openForm(): void {
    if (this.locked || this.pending) return;
    this.draftRevision += 1;
    this.formOpen = true;
    this.draftBaseline = this.createBaseline();
    this.requestUpdate();
  }
  private resetFormState(): void {
    this.draftRevision += 1;
    this.formOpen = false;
    this.file = undefined;
    this.passwordOn = false;
    this.kind = 'text';
    this.draftBaseline = undefined;
    this.validationError = undefined;
    this.submittedRevision = undefined;
    this.wasPending = false;
  }

  private closeForm(): void {
    if (this.pending || !this.promptForUnsavedEdits()) return;
    this.resetFormState();
    this.requestUpdate();
  }

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (changed.has('locked') && this.locked) {
      this.confirmingDeleteId = null;
      this.resetFormState();
      return;
    }
    if ((changed.has('pending') || changed.has('status')) && !this.pending
      && this.submittedRevision !== undefined && (this.wasPending || changed.has('status'))) {
      const revision = this.submittedRevision;
      this.submittedRevision = undefined;
      if (revision === this.draftRevision
        && (this.status?.tone === 'success' || this.status?.tone === 'warning')) {
        this.resetFormState();
        return;
      }
    }
    if (changed.has('pending')) this.wasPending = this.pending;
  }

  private create(): void {
    if (this.locked || this.pending || !this.isConnected) return;
    this.validationError = undefined;
    const rawName = (this.q<HTMLInputElement>('[data-name]')?.value ?? '').trim();
    const name = rawName || t('send.defaultName');
    const expirationHours = Number(this.selectValue('[data-expiry]')) || SEND_DATE_PRESET_HOURS.sevenDays;
    const deletionHours = Number(this.selectValue('[data-deletion]')) || SEND_DATE_PRESET_HOURS.fourteenDays;
    if (expirationHours > deletionHours) {
      this.validationError = t('send.dateOrderError');
      this.q<HTMLElement>('[data-expiry]')?.shadowRoot?.querySelector('select')?.focus();
      return;
    }
    const maxRaw = this.q<HTMLSelectElement>('[data-max]')?.value ?? '';
    const password = this.passwordOn ? (this.q<HTMLInputElement>('[data-pass]')?.value ?? '') : '';
    const base: SendInput = {
      name,
      deletionHours,
      expirationHours,
      hideEmail: this.toggleChecked('[data-hide-email]'),
    };
    if (maxRaw) base.maxAccessCount = Number(maxRaw);
    if (password) base.password = password;
    if (this.kind === 'file') {
      const file = this.file;
      if (!file) { this.validationError = t('send.error.fileRequired'); return; }
      if (file.size > MAX_FILE_BYTES) { this.validationError = t('send.error.fileTooLarge', { max: '100 MB' }); return; }
      this.submittedRevision = this.draftRevision;
      this.emit('vw-send-create', { kind: 'file', input: { ...base, name: rawName || file.name }, file, fileName: file.name });
    } else {
      const text = this.q<HTMLTextAreaElement>('[data-content]')?.value ?? '';
      if (!text.trim()) { this.validationError = t('send.error.textRequired'); return; }
      this.submittedRevision = this.draftRevision;
      this.emit('vw-send-create', { kind: 'text', input: { ...base, text } });
    }
  }

  private meta(send: SendSummary): string {
    const parts: string[] = [];
    const now = Date.now();
    const deadline = this.effectiveDeadline(send);
    const dead = this.hasEnded(send);
    if (send.disabled) parts.push(t('send.disabledBadge'));
    else if (deadline <= now) parts.push(t('options.send.expired'));
    else if (dead) parts.push(t('send.limitReached'));
    else {
      const remaining = deadline - now;
      if (remaining < DAY_MS) {
        const hours = Math.max(1, Math.ceil(remaining / HOUR_MS));
        parts.push(hours === 1
          ? t('options.send.expiresInOneHour')
          : t('options.send.expiresInHours', { count: hours }));
      } else {
        parts.push(t('options.send.expiresInDays', { count: Math.ceil(remaining / DAY_MS) }));
      }
    }
    if (send.maxAccessCount != null) parts.push(t('options.send.accessed', { used: send.accessCount, max: send.maxAccessCount }));
    else parts.push(t('send.viewCount', { count: send.accessCount }));
    return parts.join(' · ');
  }

  private hasEnded(send: SendSummary): boolean {
    return send.disabled || this.effectiveDeadline(send) <= Date.now()
      || (send.maxAccessCount != null && send.accessCount >= send.maxAccessCount);
  }

  private async promptDelete(send: SendSummary): Promise<void> {
    if (this.locked || this.pending) return;
    this.confirmingDeleteId = send.id;
    await this.updateComplete;
    this.q<HTMLButtonElement>('[data-delete-cancel]')?.focus();
  }

  private async cancelDelete(): Promise<void> {
    const id = this.confirmingDeleteId;
    this.confirmingDeleteId = null;
    await this.updateComplete;
    Array.from(this.renderRoot.querySelectorAll<HTMLButtonElement>('[data-delete]'))
      .find((button) => button.dataset.delete === id)?.focus();
  }

  private deleteSend(send: SendSummary): void {
    if (this.locked || this.pending || this.confirmingDeleteId !== send.id) return;
    this.confirmingDeleteId = null;
    this.emit('vw-send-delete', { id: send.id });
  }

  private effectiveDeadline(send: SendSummary): number {
    const deletionTime = Date.parse(send.deletionDate);
    const expirationTime = send.expirationDate ? Date.parse(send.expirationDate) : Number.POSITIVE_INFINITY;
    return Number.isFinite(expirationTime)
      ? Math.min(deletionTime, expirationTime)
      : deletionTime;
  }

  protected override render() {
    return html`
      ${this.renderIntro()}
      ${this.formOpen ? this.renderForm() : nothing}
      ${this.status ? html`<vw-status-message .tone=${this.status.tone} message=${this.status.message}></vw-status-message>` : nothing}
      ${this.renderList()}
      <div class="footer">${t('options.send.footer')}</div>
    `;
  }

  private renderIntro() {
    return html`
      <div class="card intro">
        <div class="text">
          <div class="title">${t('options.send.introTitle')}</div>
          <div class="desc">${t('options.send.introDesc')}</div>
        </div>
        <button type="button" class="btn-primary" ?disabled=${this.locked || this.pending} @click=${() => this.openForm()}>
          ${uiIcon('plus')}${t('options.send.new')}
        </button>
      </div>
    `;
  }

  private renderForm() {
    const expiryOptions = [
      { value: String(SEND_DATE_PRESET_HOURS.oneHour), label: t('options.send.expiry.1h') },
      { value: String(SEND_DATE_PRESET_HOURS.oneDay), label: t('options.send.expiry.1d') },
      { value: String(SEND_DATE_PRESET_HOURS.twoDays), label: t('options.send.expiry.2d') },
      { value: String(SEND_DATE_PRESET_HOURS.threeDays), label: t('options.send.expiry.3d') },
      { value: String(SEND_DATE_PRESET_HOURS.sevenDays), label: t('options.send.expiry.7d') },
      { value: String(SEND_DATE_PRESET_HOURS.fourteenDays), label: t('options.send.expiry.14d') },
      { value: String(SEND_DATE_PRESET_HOURS.thirtyDays), label: t('options.send.expiry.30d') },
    ];
    const maxOptions = [
      { value: '1', label: t('options.send.access.1') },
      { value: '5', label: t('options.send.access.5') },
      { value: '10', label: t('options.send.access.10') },
      { value: '', label: t('options.send.access.unlimited') },
    ];
    return html`
      <div class="card form" ?inert=${this.pending}>
        <div class="form-head">
          <span class="t">${t('options.send.formTitle')}</span>
          <vw-segmented
            style="width:172px"
            .label=${t('send.formContent')}
            .disabled=${this.pending}
            .options=${[{ id: 'text', label: t('options.send.typeText') }, { id: 'file', label: t('options.send.typeFile') }]}
            .value=${this.kind}
            .height=${34}
            @vw-segmented-change=${(e: CustomEvent<{ id: string }>) => this.changeKind(e)}
          ></vw-segmented>
        </div>
        <section class="form-section" aria-labelledby="send-content-title">
        <h3 class="section-title" id="send-content-title">${t('send.formContent')}</h3>
        <div class="field">
          <label for="send-name">${t('options.send.name')}</label>
          <input id="send-name" data-name type="text" placeholder=${t('options.send.namePlaceholder')} ?disabled=${this.pending} />
        </div>
        <div class="field">
          <label for="send-content">${this.kind === 'text' ? t('options.send.textContent') : t('options.send.fileContent')}</label>
          ${this.kind === 'text'
            ? html`<textarea id="send-content" data-content rows="4" placeholder=${t('options.send.contentPlaceholder')} ?disabled=${this.pending}></textarea>`
            : html`<input id="send-content" data-file type="file" ?disabled=${this.pending} @change=${(e: Event) => {
                if (this.pending) return;
                this.file = (e.target as HTMLInputElement).files?.[0];
                this.validationError = undefined;
              }} />`}
        </div>
        </section>
        <section class="form-section" aria-labelledby="send-protection-title">
          <h3 class="section-title" id="send-protection-title">${t('send.formProtection')}</h3>
          <div class="row-toggle">
            <span id="send-password-toggle-label">${t('options.send.accessPassword')}</span>
            <vw-toggle size="sm" .label=${t('options.send.accessPassword')} .checked=${this.passwordOn} .disabled=${this.pending}
              @vw-toggle-change=${(e: CustomEvent<{ checked: boolean }>) => this.changePasswordEnabled(e)}></vw-toggle>
          </div>
          ${this.passwordOn ? html`<div class="field"><label for="send-password">${t('options.send.accessPassword')}</label><input id="send-password" data-pass type="password" autocomplete="new-password" aria-describedby="send-password-hint" ?disabled=${this.pending} /><p class="hint" id="send-password-hint">${t('send.passwordHint')}</p></div>` : nothing}
          <div class="row-toggle">
            <span id="send-hide-email-label">${t('send.hideEmail')}</span>
            <vw-toggle data-hide-email size="sm" .label=${t('send.hideEmail')} .disabled=${this.pending}></vw-toggle>
          </div>
        </section>
        <section class="form-section" aria-labelledby="send-limits-title">
        <h3 class="section-title" id="send-limits-title">${t('send.formLimits')}</h3>
        <div class="controls">
          <div class="field">
            <label>${t('send.expirationDays')}</label>
            <vw-select data-expiry .options=${expiryOptions} .value=${String(SEND_DATE_PRESET_HOURS.sevenDays)} .label=${t('send.expirationDays')}></vw-select>
            <p class="hint">${t('send.expirationHint')}</p>
          </div>
          <div class="field">
            <label>${t('options.send.maxAccess')}</label>
            <vw-select data-max .options=${maxOptions} .value=${''} .label=${t('options.send.maxAccess')}></vw-select>
          </div>
          <div class="field">
            <label>${t('send.deletionDays')}</label>
            <vw-select data-deletion .options=${expiryOptions} .value=${String(SEND_DATE_PRESET_HOURS.fourteenDays)} .label=${t('send.deletionDays')}></vw-select>
            <p class="hint">${t('send.deletionHint')}</p>
          </div>
        </div>
        <p class="hint">${t('send.copiesRemain')}</p>
        </section>
        ${this.validationError ? html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>` : nothing}
        <div class="actions">
          <button type="button" class="btn-outline" ?disabled=${this.pending} @click=${() => this.closeForm()}>${t('common.cancel')}</button>
          <button type="button" class="btn-primary" ?disabled=${this.pending} @click=${() => this.create()}>
            ${t('options.send.create')}
          </button>
        </div>
      </div>
    `;
  }

  private renderList() {
    if (this.locked) return html`<div class="empty">${t('options.locked')}</div>`;
    const state = this.sends;
    if (state.status === 'loading') return html`<div class="empty">${t('common.loading')}</div>`;
    if (state.status === 'empty' || state.status === 'idle') return html`<div class="group-label">${t('options.send.active')}</div><div class="empty">${t('options.send.empty')}</div>`;
    if (state.status === 'error') return html`<vw-status-message tone="danger" message=${state.message}></vw-status-message>`;
    const active = state.data.filter((send) => !this.hasEnded(send));
    const ended = state.data.filter((send) => this.hasEnded(send));
    return html`
      <section aria-labelledby="send-active-title">
        <div class="group-label" id="send-active-title">${t('options.send.active')} <span class="count">${active.length}</span></div>
        ${active.length ? html`<div class="send-list">${active.map((send) => this.renderSend(send))}</div>` : html`<div class="empty">${t('options.send.empty')}</div>`}
      </section>
      ${ended.length ? html`<section aria-labelledby="send-ended-title"><div class="group-label" id="send-ended-title">${t('send.ended')} <span class="count">${ended.length}</span></div><div class="send-list">${ended.map((send) => this.renderSend(send))}</div></section>` : nothing}
    `;
  }

  private renderSend(send: SendSummary) {
    const dead = this.hasEnded(send);
    const isFile = send.type === 1;
    return html`
      <div class="send ${dead ? 'dead' : ''}" data-send=${send.id}>
        <div class="tile">${uiIcon(isFile ? 'file' : 'text')}</div>
        <div class="meta">
          <div class="name">${send.name}</div>
          <div class="sub">${this.meta(send)}</div>
        </div>
        <div class="send-actions">
          <button type="button" class="icon-btn" title=${t('options.send.copyLink')} aria-label=${t('send.copyAria')} ?disabled=${this.locked || this.pending} @click=${() => this.emit('vw-copy', { value: send.url })}>${uiIcon('link')}</button>
          <button type="button" class="icon-btn danger" data-delete=${send.id} title=${t('common.delete')} aria-label=${t('send.deleteAria')} ?disabled=${this.locked || this.pending} @click=${() => void this.promptDelete(send)}>${uiIcon('trash')}</button>
        </div>
        ${this.confirmingDeleteId === send.id ? html`<div class="delete-confirm" role="region" aria-label=${t('send.deleteNamed', { name: send.name })}>
          <div class="copy"><strong>${t('send.deleteNamed', { name: send.name })}</strong><p class="hint">${t('send.deleteHint')}</p></div>
          <button type="button" class="btn-outline" data-delete-cancel ?disabled=${this.pending} @click=${() => void this.cancelDelete()}>${t('common.cancel')}</button>
          <button type="button" class="btn-outline btn-danger" data-delete-confirm ?disabled=${this.pending} @click=${() => this.deleteSend(send)}>${t('common.delete')}</button>
        </div>` : nothing}
      </div>
    `;
  }
}

customElements.define('vw-send-section', VwSendSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-send-section': VwSendSection;
  }
}
