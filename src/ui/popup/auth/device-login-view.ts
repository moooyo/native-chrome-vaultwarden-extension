import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { controlStyles } from '../../components/styles.js';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/status-message.js';
import { authIdentityStyles, renderAuthIdentity, type AuthIdentityDisplay } from './auth-identity.js';

/** Exactly five independently rendered words used to compare both sides of a device login. */
export type DeviceLoginFingerprint = readonly [string, string, string, string, string];

/** Feature copy supplied by the host until device-login strings have dedicated catalog keys. */
export interface DeviceLoginLabels {
  readonly requesterTitle: string;
  readonly waitingTitle: string;
  readonly waitingDescription: string;
  readonly serverApprovalHint: string;
  readonly compareFingerprintHint: string;
  readonly expiresIn: string;
  readonly expiredTitle: string;
  readonly expiredDescription: string;
  readonly expired: string;
  readonly checkNow: string;
  readonly approverListTitle: string;
  readonly approverListDescription: string;
  readonly approverDetailTitle: string;
  readonly noRequests: string;
  readonly deviceType: string;
  readonly deviceIdentifier: string;
  readonly ipAddress: string;
  readonly createdAt: string;
  readonly approve: string;
  readonly deny: string;
  readonly unavailable: string;
  readonly deviceName: string;
  readonly notKnownTitle: string;
  readonly notKnownDescription: string;
  readonly deniedTitle: string;
  readonly deniedDescription: string;
  readonly twoFactorUnsupportedTitle: string;
  readonly twoFactorUnsupportedDescription: string;
  readonly retryRequiredTitle: string;
  readonly retryRequiredDescription: string;
  readonly outcomeUnknownTitle: string;
  readonly outcomeUnknownDescription: string;
  readonly errorTitle: string;
  readonly errorDescription: string;
  readonly retry: string;
  readonly dismiss: string;
  readonly checkAccountState: string;
}

interface DeviceLoginViewModelBase {
  readonly labels: Readonly<DeviceLoginLabels>;
  readonly busy: boolean;
  readonly notice?: {
    readonly tone: 'info' | 'success' | 'warning' | 'danger';
    readonly message: string;
  };
}

export interface DeviceLoginRequesterViewModel extends DeviceLoginViewModelBase {
  readonly kind: 'requester';
  /** Popup-owned generation. This is not a server request id and is never rendered or emitted. */
  readonly generation: number;
  /** Durable requester owner used only in background-bound actions. */
  readonly ownerGeneration?: number;
  readonly status:
    | 'pending'
    | 'not_known_device'
    | 'denied'
    | 'expired'
    | 'two_factor_unsupported'
    | 'retry_required'
    | 'outcome_unknown'
    | 'error';
  readonly fingerprint?: DeviceLoginFingerprint;
  /** The host owns the clock and supplies a fresh immutable snapshot as this value changes. */
  readonly remainingSeconds?: number;
  readonly serverOrigin?: string;
  readonly email?: string;
  readonly deviceName?: string;
  readonly providers?: readonly number[];
  readonly errorMessage?: string;
}

export interface DeviceLoginApprovalRequestDisplay {
  /** Opaque capability retained in component memory and never rendered into the DOM. */
  readonly requestId: string;
  readonly status: 'pending' | 'expired';
  readonly deviceType: string;
  readonly deviceIdentifier: string;
  readonly ipAddress?: string;
  readonly country?: string;
  readonly createdAt: string;
  readonly fingerprint: DeviceLoginFingerprint;
}

export interface DeviceLoginApproverListViewModel extends DeviceLoginViewModelBase {
  readonly kind: 'approver-list';
  readonly requests: readonly DeviceLoginApprovalRequestDisplay[];
}

export interface DeviceLoginApproverDetailViewModel extends DeviceLoginViewModelBase {
  readonly kind: 'approver-detail';
  readonly request: DeviceLoginApprovalRequestDisplay;
}

/** Immutable, display-only snapshots accepted by the device-login surface. */
export type DeviceLoginViewModel =
  | DeviceLoginRequesterViewModel
  | DeviceLoginApproverListViewModel
  | DeviceLoginApproverDetailViewModel;

/** The only request capability returned by request-scoped actions. */
export interface DeviceLoginRequestActionDetail {
  readonly requestId: string;
}

type DeviceLoginRequestActionType =
  | 'vw-device-login-select'
  | 'vw-device-login-approve'
  | 'vw-device-login-deny';

type DeviceLoginRequesterActionType =
  | 'vw-device-login-check'
  | 'vw-device-login-cancel'
  | 'vw-device-login-retry'
  | 'vw-device-login-dismiss'
  | 'vw-device-login-check-auth-state';

const UNSAFE_DIRECTIONAL_TEXT =
  /[\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069\ufeff]/u;

function hasUnsafeFingerprintText(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true;
  }
  return UNSAFE_DIRECTIONAL_TEXT.test(value);
}

function fingerprintWords(value: unknown): DeviceLoginFingerprint | undefined {
  if (!Array.isArray(value) || value.length !== 5) return undefined;
  if (value.some((word: unknown) => (
    typeof word !== 'string'
    || word.length === 0
    || word.length > 64
    || word.trim() !== word
    || hasUnsafeFingerprintText(word)
  ))) return undefined;
  return value as unknown as DeviceLoginFingerprint;
}

function countdownSeconds(value: number): number {
  return Number.isFinite(value)
    ? Math.min(5_999, Math.max(0, Math.floor(value)))
    : 0;
}

function formatCountdown(value: number): string {
  const seconds = countdownSeconds(value);
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}

function crossedCountdownAnnouncement(previous: number, next: number): boolean {
  if (next > previous) return true;
  if (next >= previous) return false;
  if ([30, 10, 0].some((threshold) => previous > threshold && next <= threshold)) return true;
  return previous > 60 && Math.ceil(next / 60) < Math.ceil(previous / 60);
}

/**
 * Pure device-login presentation. It renders only explicit display fields and emits typed
 * decisions for the popup root. It never imports worker code or places request capabilities or
 * cryptographic material in the DOM.
 */
export class VwDeviceLoginView extends LitElement {
  static override properties = { model: { attribute: false }, identity: { attribute: false } };

  declare model: DeviceLoginViewModel | undefined;
  declare identity: AuthIdentityDisplay | undefined;

  private i18n = new LocalizeController(this);
  private activeContextKey: string | undefined;
  private previousBusy = false;
  private actionLocked = false;
  private countdownContextKey: string | undefined;
  private previousCountdownSeconds: number | undefined;
  private countdownAnnouncement = '';

  constructor() {
    super();
    this.model = undefined;
    this.identity = undefined;
  }

  static override styles = [themeTokens, controlStyles, authIdentityStyles, css`
    :host {
      display: flex;
      flex: 1;
      width: 100%;
      height: 100%;
      min-width: 0;
      min-height: 0;
      overflow: hidden;
      background: var(--vw-panel);
    }
    .surface {
      display: flex;
      flex: 1;
      width: 100%;
      min-width: 0;
      min-height: 0;
      flex-direction: column;
      overflow: hidden;
      color: var(--vw-ink);
    }
    .head {
      display: flex;
      flex: none;
      align-items: center;
      gap: 10px;
      min-width: 0;
      min-height: 62px;
      padding: 16px 18px;
      border-bottom: 1px solid var(--vw-line-1);
    }
    .head-mark,
    .request-icon {
      display: grid;
      place-items: center;
      flex: none;
      border-radius: 8px;
      background: var(--vw-teal-10);
      color: var(--vw-teal-text);
    }
    .head-mark { width: 36px; height: 36px; }
    .head-mark svg { width: 19px; height: 19px; }
    .head-copy { min-width: 0; }
    h1, h2, p { margin: 0; }
    h1 {
      overflow-wrap: anywhere;
      font-size: 18px;
      font-weight: 600;
      letter-spacing: 0;
      line-height: 1.3;
    }
    .subtitle {
      margin-top: 2px;
      overflow-wrap: anywhere;
      color: var(--vw-muted);
      font-size: 11.5px;
    }
    .content {
      display: flex;
      flex: 1;
      min-width: 0;
      min-height: 0;
      flex-direction: column;
      gap: 16px;
      padding: 16px 18px;
      overflow-x: hidden;
      overflow-y: auto;
      scrollbar-color: var(--vw-scrollbar) transparent;
      scrollbar-width: thin;
    }
    .content::-webkit-scrollbar { width: 6px; }
    .content::-webkit-scrollbar-thumb {
      border: 2px solid transparent;
      border-radius: 4px;
      background: var(--vw-scrollbar);
      background-clip: content-box;
    }
    .busy-note,
    .state-line,
    .countdown {
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 0;
    }
    .busy-note,
    .state-line { color: var(--vw-text-2); }
    .busy-note { font-size: 11.5px; }
    .busy-note svg {
      width: 15px;
      height: 15px;
      animation: mvSpin 1.2s linear infinite;
    }
    .state-line svg,
    .countdown svg { width: 17px; height: 17px; flex: none; }
    .state-line svg { color: var(--vw-teal-text); }
    .state-line.expired,
    .state-line.expired svg { color: var(--vw-danger); }
    .state-line.caution,
    .state-line.caution svg { color: var(--vw-sync-amber); }
    .state-copy { min-width: 0; }
    .state-copy h2 { font-size: 13px; font-weight: 600; }
    .state-copy p {
      margin-top: 2px;
      overflow-wrap: anywhere;
      color: var(--vw-muted);
      font-size: 11.5px;
      line-height: 1.45;
    }
    .approval-note,
    .compare-note {
      overflow-wrap: anywhere;
      color: var(--vw-text-2);
      font-size: 12px;
      line-height: 1.5;
    }
    .approval-note {
      padding-left: 10px;
      border-left: 3px solid var(--vw-teal-25);
    }
    .fingerprint-panel {
      min-width: 0;
      padding: 10px;
      border: 1px solid var(--vw-line-2);
      border-radius: 8px;
      background: var(--vw-fill-2);
    }
    .fingerprint-title {
      display: flex;
      align-items: center;
      gap: 6px;
      margin-bottom: 8px;
      color: var(--vw-muted);
      font-size: 10.5px;
      font-weight: 600;
    }
    .fingerprint-title svg { width: 14px; height: 14px; }
    .fingerprint-words {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(96px, 1fr));
      gap: 6px;
      margin: 0;
      padding: 0;
      list-style: none;
    }
    .fingerprint-word {
      display: grid;
      grid-template-columns: 18px minmax(0, 1fr);
      align-items: center;
      gap: 5px;
      min-width: 0;
      min-height: 30px;
      padding: 4px 6px;
      border: 1px solid var(--vw-line-1);
      border-radius: 6px;
      background: var(--vw-card);
      font-family: var(--vw-font-mono);
      font-size: 11px;
    }
    .word-index {
      display: grid;
      place-items: center;
      width: 18px;
      height: 18px;
      border-radius: 50%;
      background: var(--vw-teal-10);
      color: var(--vw-teal-text);
      font-family: var(--vw-font-ui);
      font-size: 9px;
      font-weight: 600;
    }
    .word-value { min-width: 0; overflow-wrap: anywhere; }
    .fingerprint-unavailable {
      overflow-wrap: anywhere;
      color: var(--vw-danger);
      font-size: 11.5px;
    }
    .countdown {
      justify-content: center;
      color: var(--vw-muted);
      font-size: 11.5px;
    }
    .countdown strong {
      color: var(--vw-ink);
      font-family: var(--vw-font-mono);
      font-size: 13px;
      font-weight: 600;
    }
    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip-path: inset(50%);
      white-space: nowrap;
      border: 0;
    }
    .request-list {
      display: flex;
      min-width: 0;
      flex-direction: column;
      gap: 0;
      margin: 0;
      padding: 0;
      list-style: none;
    }
    .request-row {
      display: grid;
      grid-template-columns: 34px minmax(0, 1fr) auto;
      align-items: center;
      gap: 9px;
      width: 100%;
      min-width: 0;
      min-height: 62px;
      padding: 8px 9px;
      border: 0;
      border-bottom: 1px solid var(--vw-line-1);
      border-radius: 0;
      background: var(--vw-card);
      color: var(--vw-ink);
      font-family: var(--vw-font-ui);
      text-align: left;
      cursor: pointer;
    }
    .request-row:hover:not(:disabled) {
      border-color: var(--vw-line-3);
      background: var(--vw-row-hover);
    }
    .request-row:focus-visible { position: relative; outline: 2px solid var(--vw-accent); outline-offset: -2px; }
    .request-row:disabled { cursor: default; opacity: 0.55; }
    .request-icon { width: 34px; height: 34px; }
    .request-icon svg,
    .request-row > svg { width: 15px; height: 15px; }
    .request-row > svg { color: var(--vw-chevron); }
    .request-copy { display: flex; min-width: 0; flex-direction: column; gap: 1px; }
    .request-type,
    .request-id,
    .request-meta { min-width: 0; overflow-wrap: anywhere; }
    .request-type { font-size: 12.5px; font-weight: 600; }
    .request-id { color: var(--vw-text-2); font-size: 11px; }
    .request-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 2px 5px;
      color: var(--vw-muted);
      font-size: 10px;
    }
    .request-expired {
      max-width: 72px;
      overflow-wrap: anywhere;
      color: var(--vw-danger);
      font-size: 10px;
      text-align: right;
    }
    .empty {
      padding: 32px 12px;
      overflow-wrap: anywhere;
      color: var(--vw-muted);
      font-size: 12px;
      text-align: center;
    }
    .metadata {
      margin: 0;
      border-top: 1px solid var(--vw-line-1);
    }
    .metadata-row {
      display: grid;
      grid-template-columns: minmax(84px, 34%) minmax(0, 1fr);
      gap: 10px;
      min-width: 0;
      padding: 8px 0;
      border-bottom: 1px solid var(--vw-line-1);
    }
    .metadata dt { color: var(--vw-muted); font-size: 11px; }
    .metadata dd {
      min-width: 0;
      margin: 0;
      overflow-wrap: anywhere;
      color: var(--vw-ink);
      font-size: 12px;
    }
    .footer {
      display: flex;
      flex: none;
      flex-wrap: wrap;
      gap: 8px;
      padding: 10px 16px 14px;
      border-top: 1px solid var(--vw-line-1);
    }
    .footer .btn {
      flex: 1 1 100px;
      min-width: 0;
      padding-top: 6px;
      padding-right: 12px;
      padding-bottom: 6px;
      padding-left: 12px;
      overflow-wrap: anywhere;
      line-height: 1.2;
      white-space: normal;
    }
    .footer .btn svg { width: 15px; height: 15px; flex: none; }
    vw-status-message { width: 100%; }
    @media (max-width: 340px) {
      .head,
      .content,
      .footer { padding-right: 12px; padding-left: 12px; }
      .metadata-row { grid-template-columns: minmax(72px, 31%) minmax(0, 1fr); }
      .detail-footer [data-action='back'] { flex-basis: 100%; order: -1; }
    }
    @media (prefers-reduced-motion: reduce) {
      .busy-note svg { animation: none; }
    }
  `];

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (!changed.has('model')) return;
    this.updateCountdownAnnouncement(this.model);
    const nextKey = this.contextKey(this.model);
    const nextBusy = this.model?.busy ?? false;
    if (nextKey !== this.activeContextKey || (this.previousBusy && !nextBusy)) {
      this.actionLocked = false;
    }
    this.activeContextKey = nextKey;
    this.previousBusy = nextBusy;
  }

  private updateCountdownAnnouncement(model: DeviceLoginViewModel | undefined): void {
    if (model?.kind !== 'requester' || model.remainingSeconds === undefined) {
      this.countdownContextKey = undefined;
      this.previousCountdownSeconds = undefined;
      this.countdownAnnouncement = '';
      return;
    }

    const contextKey = `${model.generation}:${model.labels.expiresIn}`;
    const seconds = countdownSeconds(model.remainingSeconds);
    if (
      contextKey !== this.countdownContextKey
      || this.previousCountdownSeconds === undefined
      || crossedCountdownAnnouncement(this.previousCountdownSeconds, seconds)
    ) {
      this.countdownAnnouncement = `${model.labels.expiresIn} ${formatCountdown(seconds)}`;
    }
    this.countdownContextKey = contextKey;
    this.previousCountdownSeconds = seconds;
  }

  override disconnectedCallback(): void {
    this.actionLocked = true;
    super.disconnectedCallback();
  }

  private canInteract(model: DeviceLoginViewModel): boolean {
    return this.model === model && !model.busy && !this.actionLocked;
  }

  private contextKey(model: DeviceLoginViewModel | undefined): string | undefined {
    if (!model) return undefined;
    if (model.kind === 'requester') {
      return `${model.kind}:${model.generation}:${model.status}`;
    }
    if (model.kind === 'approver-detail') {
      const { requestId, status } = model.request;
      return `${model.kind}:${requestId.length}:${requestId}:${status}`;
    }
    const requests = model.requests
      .map(({ requestId, status }) => `${requestId.length}:${requestId}:${status}`)
      .join('|');
    return `${model.kind}:${requests}`;
  }

  private emitRequestAction(
    model: DeviceLoginViewModel,
    type: DeviceLoginRequestActionType,
    requestId: string,
  ): void {
    if (!this.canInteract(model) || requestId.length === 0) return;
    this.actionLocked = true;
    this.requestUpdate();
    emit<DeviceLoginRequestActionDetail>(this, type, { requestId });
  }

  private emitRequesterAction(
    model: DeviceLoginRequesterViewModel,
    type: DeviceLoginRequesterActionType,
  ): void {
    if (!this.canInteract(model)) return;
    this.actionLocked = true;
    this.requestUpdate();
    emit(this, type);
  }

  private checkNow(model: DeviceLoginRequesterViewModel): void {
    if (model.status !== 'pending' || this.requesterExpired(model)) return;
    this.emitRequesterAction(model, 'vw-device-login-check');
  }

  private cancel(model: DeviceLoginRequesterViewModel): void {
    if (model.status !== 'pending' && model.status !== 'retry_required') return;
    this.emitRequesterAction(model, 'vw-device-login-cancel');
  }

  private retry(model: DeviceLoginRequesterViewModel): void {
    if (model.status !== 'retry_required') return;
    this.emitRequesterAction(model, 'vw-device-login-retry');
  }

  private dismiss(model: DeviceLoginRequesterViewModel): void {
    if (model.status === 'pending' || model.status === 'retry_required') return;
    this.emitRequesterAction(model, 'vw-device-login-dismiss');
  }

  private checkAuthState(model: DeviceLoginRequesterViewModel): void {
    if (model.status !== 'outcome_unknown') return;
    this.emitRequesterAction(model, 'vw-device-login-check-auth-state');
  }

  private selectRequest(
    model: DeviceLoginApproverListViewModel,
    request: DeviceLoginApprovalRequestDisplay,
  ): void {
    if (
      request.status !== 'pending'
      || !model.requests.includes(request)
    ) return;
    this.emitRequestAction(model, 'vw-device-login-select', request.requestId);
  }

  private decide(
    model: DeviceLoginApproverDetailViewModel,
    type: 'vw-device-login-approve' | 'vw-device-login-deny',
  ): void {
    if (
      model.request.status !== 'pending'
      || !fingerprintWords(model.request.fingerprint)
    ) return;
    this.emitRequestAction(model, type, model.request.requestId);
  }

  private back(model: DeviceLoginApproverDetailViewModel): void {
    if (!this.canInteract(model)) return;
    this.actionLocked = true;
    this.requestUpdate();
    emit(this, 'vw-device-login-back');
  }

  private requesterExpired(model: DeviceLoginRequesterViewModel): boolean {
    return model.status === 'expired'
      || (model.remainingSeconds !== undefined
        && (!Number.isFinite(model.remainingSeconds) || model.remainingSeconds <= 0));
  }

  private renderBusy(model: DeviceLoginViewModel) {
    return model.busy
      ? html`<p class="busy-note" role="status">${uiIcon('refresh')}<span>${t('common.loading')}</span></p>`
      : nothing;
  }

  private renderNotice(model: DeviceLoginViewModel) {
    return model.notice
      ? html`<vw-status-message .tone=${model.notice.tone} .icon=${model.notice.tone === 'danger' ? 'alert' : 'refresh'} .message=${model.notice.message}></vw-status-message>`
      : nothing;
  }

  private renderHead(title: string, subtitle: string, icon: 'shield' | 'idcard') {
    return html`
      <header class="head">
        <span class="head-mark" aria-hidden="true">${uiIcon(icon)}</span>
        <div class="head-copy">
          <h1 id="device-login-title">${title}</h1>
          <p class="subtitle" id="device-login-description">${subtitle}</p>
        </div>
      </header>
    `;
  }

  private renderFingerprint(words: readonly string[], labels: Readonly<DeviceLoginLabels>) {
    const safeWords = fingerprintWords(words);
    return html`
      <section class="fingerprint-panel" aria-labelledby="device-login-fingerprint-title">
        <div class="fingerprint-title" id="device-login-fingerprint-title">
          ${uiIcon('fingerprint')}<span>${t('ssh.fingerprint')}</span>
        </div>
        ${safeWords
          ? html`
              <ol class="fingerprint-words">
                ${safeWords.map((word, index) => html`
                  <li class="fingerprint-word">
                    <span class="word-index" aria-hidden="true">${index + 1}</span>
                    <span class="word-value">${word}</span>
                  </li>
                `)}
              </ol>
            `
          : html`<p class="fingerprint-unavailable" role="alert">${labels.unavailable}</p>`}
      </section>
    `;
  }

  private requesterState(model: DeviceLoginRequesterViewModel): {
    readonly title: string;
    readonly description: string;
    readonly icon: 'alert' | 'clock' | 'refresh';
    readonly tone: '' | 'caution' | 'expired';
  } {
    const { labels } = model;
    if (this.requesterExpired(model)) {
      return { title: labels.expiredTitle, description: labels.expiredDescription, icon: 'alert', tone: 'expired' };
    }
    switch (model.status) {
      case 'pending':
        return { title: labels.waitingTitle, description: labels.waitingDescription, icon: 'clock', tone: '' };
      case 'not_known_device':
        return { title: labels.notKnownTitle, description: labels.notKnownDescription, icon: 'alert', tone: 'caution' };
      case 'denied':
        return { title: labels.deniedTitle, description: labels.deniedDescription, icon: 'alert', tone: 'expired' };
      case 'two_factor_unsupported':
        return { title: labels.twoFactorUnsupportedTitle, description: labels.twoFactorUnsupportedDescription, icon: 'alert', tone: 'caution' };
      case 'retry_required':
        return { title: labels.retryRequiredTitle, description: labels.retryRequiredDescription, icon: 'refresh', tone: 'caution' };
      case 'outcome_unknown':
        return { title: labels.outcomeUnknownTitle, description: labels.outcomeUnknownDescription, icon: 'alert', tone: 'caution' };
      case 'error':
        return { title: labels.errorTitle, description: model.errorMessage || labels.errorDescription, icon: 'alert', tone: 'expired' };
      case 'expired':
        return { title: labels.expiredTitle, description: labels.expiredDescription, icon: 'alert', tone: 'expired' };
    }
  }

  private renderRequesterActions(model: DeviceLoginRequesterViewModel) {
    const { labels } = model;
    const disabled = model.busy || this.actionLocked;
    if (model.status === 'pending') {
      return html`
        <button type="button" class="btn outline" data-action="check" ?disabled=${disabled || this.requesterExpired(model)} @click=${() => this.checkNow(model)}>${uiIcon('refresh')}<span>${labels.checkNow}</span></button>
        <button type="button" class="btn ghost" data-action="cancel" ?disabled=${disabled} @click=${() => this.cancel(model)}>${uiIcon('close')}<span>${t('common.cancel')}</span></button>
      `;
    }
    if (model.status === 'retry_required') {
      return html`
        <button type="button" class="btn outline" data-action="retry" ?disabled=${disabled || this.requesterExpired(model)} @click=${() => this.retry(model)}>${uiIcon('refresh')}<span>${labels.retry}</span></button>
        <button type="button" class="btn ghost" data-action="cancel" ?disabled=${disabled} @click=${() => this.cancel(model)}>${uiIcon('close')}<span>${t('common.cancel')}</span></button>
      `;
    }
    if (model.status === 'outcome_unknown') {
      return html`
        <button type="button" class="btn outline" data-action="check-auth" ?disabled=${disabled} @click=${() => this.checkAuthState(model)}>${uiIcon('refresh')}<span>${labels.checkAccountState}</span></button>
        <button type="button" class="btn ghost" data-action="dismiss" ?disabled=${disabled} @click=${() => this.dismiss(model)}>${uiIcon('close')}<span>${labels.dismiss}</span></button>
      `;
    }
    return html`<button type="button" class="btn outline" data-action="dismiss" ?disabled=${disabled} @click=${() => this.dismiss(model)}>${uiIcon('back')}<span>${labels.dismiss}</span></button>`;
  }

  private renderRequester(model: DeviceLoginRequesterViewModel) {
    const { labels } = model;
    const state = this.requesterState(model);
    const hasContext = Boolean(model.serverOrigin || model.email || model.deviceName);
    return html`
      <section class="surface requester" aria-labelledby="device-login-title" aria-describedby="device-login-description" aria-busy=${model.busy ? 'true' : 'false'}>
        ${this.renderHead(labels.requesterTitle, state.description, 'shield')}
        <main class="content">
          ${this.renderBusy(model)}
          <div class="state-line ${state.tone}" role=${model.status === 'pending' ? 'status' : 'alert'}>
            ${uiIcon(state.icon)}
            <div class="state-copy"><h2>${state.title}</h2><p>${state.description}</p></div>
          </div>
          ${model.status === 'pending' ? html`<p class="approval-note">${labels.serverApprovalHint}</p>` : nothing}
          ${hasContext ? html`
            <dl class="metadata requester-metadata">
              ${model.serverOrigin ? this.metadataRow(t('auth.serverUrl'), model.serverOrigin, labels.unavailable) : nothing}
              ${model.email ? this.metadataRow(t('auth.email'), model.email, labels.unavailable) : nothing}
              ${model.deviceName ? this.metadataRow(labels.deviceName, model.deviceName, labels.unavailable) : nothing}
            </dl>
          ` : nothing}
          ${model.fingerprint ? this.renderFingerprint(model.fingerprint, labels) : nothing}
          ${model.fingerprint ? html`<p class="compare-note">${labels.compareFingerprintHint}</p>` : nothing}
          ${model.remainingSeconds !== undefined ? html`
            <div class="countdown">
              ${uiIcon('clock')}
              <span>${labels.expiresIn}</span>
              <strong role="timer" aria-live="off">${formatCountdown(model.remainingSeconds)}</strong>
              <span
                class="sr-only"
                data-countdown-announcement
                role="status"
                aria-live="polite"
                aria-atomic="true"
              >${this.countdownAnnouncement}</span>
            </div>
          ` : nothing}
        </main>
        <footer class="footer">${this.renderRequesterActions(model)}</footer>
      </section>
    `;
  }

  private renderRequestRow(
    model: DeviceLoginApproverListViewModel,
    request: DeviceLoginApprovalRequestDisplay,
  ) {
    const { labels } = model;
    const expired = request.status === 'expired';
    const disabled = model.busy || this.actionLocked || expired || request.requestId.length === 0;
    return html`
      <li>
        <button
          type="button"
          class="request-row"
          data-action="select"
          ?disabled=${disabled}
          @click=${() => this.selectRequest(model, request)}
        >
          <span class="request-icon" aria-hidden="true">${uiIcon('idcard')}</span>
          <span class="request-copy">
            <span class="request-type">${request.deviceType || labels.unavailable}</span>
            <span class="request-id">${request.deviceIdentifier || labels.unavailable}</span>
            <span class="request-meta">
              <span>${request.ipAddress || labels.unavailable}</span>
              <span aria-hidden="true">/</span>
              <span>${request.country || labels.unavailable}</span>
              <span aria-hidden="true">/</span>
              <span>${request.createdAt || labels.unavailable}</span>
            </span>
          </span>
          ${expired
            ? html`<span class="request-expired">${labels.expired}</span>`
            : uiIcon('chevron')}
        </button>
      </li>
    `;
  }

  private renderApproverList(model: DeviceLoginApproverListViewModel) {
    const { labels } = model;
    return html`
      <section
        class="surface approver-list"
        aria-labelledby="device-login-title"
        aria-describedby="device-login-description"
        aria-busy=${model.busy ? 'true' : 'false'}
      >
        ${this.renderHead(labels.approverListTitle, labels.approverListDescription, 'idcard')}
        <main class="content">
          ${renderAuthIdentity(this.identity)}
          ${this.renderBusy(model)}
          ${this.renderNotice(model)}
          ${model.requests.length > 0
            ? html`<ul class="request-list">${model.requests.map((request) => this.renderRequestRow(model, request))}</ul>`
            : html`<p class="empty" role="status">${labels.noRequests}</p>`}
        </main>
      </section>
    `;
  }

  private metadataRow(label: string, value: string | undefined, unavailable: string) {
    return html`<div class="metadata-row"><dt>${label}</dt><dd>${value || unavailable}</dd></div>`;
  }

  private renderApproverDetail(model: DeviceLoginApproverDetailViewModel) {
    const { labels, request } = model;
    const fingerprintValid = fingerprintWords(request.fingerprint) !== undefined;
    const expired = request.status === 'expired';
    const disabled = model.busy || this.actionLocked;
    const decisionDisabled = disabled || expired || !fingerprintValid || request.requestId.length === 0;
    return html`
      <section
        class="surface approver-detail"
        aria-labelledby="device-login-title"
        aria-describedby="device-login-description"
        aria-busy=${model.busy ? 'true' : 'false'}
      >
        ${this.renderHead(labels.approverDetailTitle, labels.compareFingerprintHint, 'shield')}
        <main class="content">
          ${renderAuthIdentity(this.identity)}
          ${this.renderBusy(model)}
          ${this.renderNotice(model)}
          ${expired
            ? html`
                <div class="state-line expired" role="alert">
                  ${uiIcon('alert')}
                  <div class="state-copy">
                    <h2>${labels.expiredTitle}</h2>
                    <p>${labels.expiredDescription}</p>
                  </div>
                </div>
              `
            : nothing}
          <dl class="metadata">
            ${this.metadataRow(labels.deviceType, request.deviceType, labels.unavailable)}
            ${this.metadataRow(labels.deviceIdentifier, request.deviceIdentifier, labels.unavailable)}
            ${this.metadataRow(labels.ipAddress, request.ipAddress, labels.unavailable)}
            ${this.metadataRow(t('detail.country'), request.country, labels.unavailable)}
            ${this.metadataRow(labels.createdAt, request.createdAt, labels.unavailable)}
          </dl>
          ${this.renderFingerprint(request.fingerprint, labels)}
          <p class="compare-note">${labels.compareFingerprintHint}</p>
        </main>
        <footer class="footer detail-footer">
          <button
            type="button"
            class="btn ghost"
            data-action="back"
            ?disabled=${disabled}
            @click=${() => this.back(model)}
          >${uiIcon('back')}<span>${t('common.back')}</span></button>
          <button
            type="button"
            class="btn danger"
            data-action="deny"
            ?disabled=${decisionDisabled}
            @click=${() => this.decide(model, 'vw-device-login-deny')}
          >${uiIcon('close')}<span>${labels.deny}</span></button>
          <button
            type="button"
            class="btn primary"
            data-action="approve"
            ?disabled=${decisionDisabled}
            @click=${() => this.decide(model, 'vw-device-login-approve')}
          >${uiIcon('check')}<span>${labels.approve}</span></button>
        </footer>
      </section>
    `;
  }

  protected override render() {
    const model = this.model;
    if (!model) return nothing;
    switch (model.kind) {
      case 'requester': return this.renderRequester(model);
      case 'approver-list': return this.renderApproverList(model);
      case 'approver-detail': return this.renderApproverDetail(model);
    }
  }
}

customElements.define('vw-device-login-view', VwDeviceLoginView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-device-login-view': VwDeviceLoginView;
  }
}
