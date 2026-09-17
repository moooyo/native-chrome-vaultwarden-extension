import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { emit } from '../../components/emit.js';
import { uiIcon } from '../../components/icon.js';
import { controlStyles } from '../../components/styles.js';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/status-message.js';
import { authIdentityStyles, renderAuthIdentity, type AuthIdentityDisplay } from '../auth/auth-identity.js';

export type WebsitePasskeyViewState = 'awaiting' | 'executing' | 'error';

export interface WebsitePasskeyDisplayChoice {
  /** Worker-owned identifier. It stays in component memory and is never rendered into the DOM. */
  readonly id: string;
  readonly name: string;
  readonly username?: string;
}

interface WebsitePasskeyViewModelBase {
  /** Opaque registry identifier. It is emitted back to the root but never rendered. */
  readonly ceremonyId: string;
  readonly origin: string;
  readonly rpId: string;
  readonly state: WebsitePasskeyViewState;
  readonly errorMessage?: string;
}

export type WebsitePasskeyViewModel =
  | (WebsitePasskeyViewModelBase & {
      readonly kind: 'get';
      readonly candidates: readonly WebsitePasskeyDisplayChoice[];
    })
  | (WebsitePasskeyViewModelBase & {
      readonly kind: 'create';
      readonly targets: readonly WebsitePasskeyDisplayChoice[];
    });

export type WebsitePasskeySelection =
  | { readonly kind: 'credential'; readonly credentialId: string }
  | { readonly kind: 'new' }
  | { readonly kind: 'target'; readonly cipherId: string };

export interface WebsitePasskeyApproveDetail {
  readonly ceremonyId: string;
  readonly selection: WebsitePasskeySelection;
}

export interface WebsitePasskeyCancelDetail {
  readonly ceremonyId: string;
}

export interface WebsitePasskeyFallbackDetail {
  readonly ceremonyId: string;
}

/**
 * Extension-owned approval surface for a website Passkey ceremony. This view is deliberately pure:
 * it receives a redacted snapshot, renders display labels, and emits one approve/cancel decision.
 * It never imports messaging or vault code and never places ceremony, credential, or cipher ids in DOM.
 */
export class VwWebsitePasskeyView extends LitElement {
  static override properties = {
    model: { attribute: false },
    identity: { attribute: false },
  };

  declare model: WebsitePasskeyViewModel | undefined;
  declare identity: AuthIdentityDisplay | undefined;

  private i18n = new LocalizeController(this);
  private focusedViewKey: string | undefined;
  private activeCeremonyId: string | undefined;
  private decisionLocked = false;

  constructor() {
    super();
    this.model = undefined;
    this.identity = undefined;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    authIdentityStyles,
    css`
      :host {
        display: flex;
        flex: 1;
        min-height: 0;
        background: var(--vw-panel);
      }
      .ceremony {
        display: flex;
        flex: 1;
        min-width: 0;
        min-height: 0;
        flex-direction: column;
        color: var(--vw-ink);
      }
      .head {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 16px 18px;
        border-bottom: 1px solid var(--vw-line-1);
      }
      .mark {
        display: grid;
        place-items: center;
        width: 34px;
        height: 34px;
        flex: none;
        border-radius: var(--vw-radius-chip);
        background: var(--vw-teal-10);
        color: var(--vw-teal-text);
      }
      .mark svg {
        width: 18px;
        height: 18px;
      }
      .head-copy {
        min-width: 0;
      }
      h1 {
        margin: 0;
        font-size: 18px;
        font-weight: 600;
        letter-spacing: 0;
      }
      .subtitle {
        margin: 2px 0 0;
        color: var(--vw-muted);
        font-size: 11.5px;
      }
      .source {
        display: grid;
        grid-template-columns: 18px minmax(0, 1fr);
        gap: 2px 8px;
        padding: 12px 18px;
        border-bottom: 1px solid var(--vw-line-1);
        background: var(--vw-fill-2);
      }
      .source > svg {
        grid-row: 1 / 3;
        align-self: center;
        width: 16px;
        height: 16px;
        color: var(--vw-muted);
      }
      .origin {
        min-width: 0;
        overflow-wrap: anywhere;
        color: var(--vw-ink);
        font-size: 12.5px;
        font-weight: 600;
        unicode-bidi: plaintext;
      }
      .rp {
        min-width: 0;
        overflow: hidden;
        color: var(--vw-muted);
        font-size: 10.5px;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .content {
        display: flex;
        flex: 1;
        min-height: 0;
        flex-direction: column;
        gap: 16px;
        padding: 16px 18px;
        overflow-y: auto;
        scrollbar-color: var(--vw-scrollbar) transparent;
        scrollbar-width: thin;
      }
      .section-label {
        margin: 0;
        color: var(--vw-text-3);
        font-size: 11px;
        font-weight: 600;
      }
      .choices {
        display: flex;
        flex-direction: column;
        gap: 0;
      }
      .choice {
        display: grid;
        grid-template-columns: 32px minmax(0, 1fr) 18px;
        align-items: center;
        gap: 9px;
        width: 100%;
        min-height: 58px;
        padding: 10px 9px;
        border: 0;
        border-bottom: 1px solid var(--vw-line-1);
        border-radius: 0;
        background: var(--vw-card);
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        text-align: left;
        cursor: pointer;
        transition: background-color var(--vw-dur-fast), border-color var(--vw-dur-fast);
      }
      .choice:hover:not(:disabled) {
        border-color: var(--vw-line-3);
        background: var(--vw-row-hover);
      }
      .choice:focus-visible { outline: 2px solid var(--vw-accent); outline-offset: -2px; }
      .choice:disabled {
        cursor: default;
        opacity: 0.55;
      }
      .choice-icon {
        display: grid;
        place-items: center;
        width: 32px;
        height: 32px;
        border-radius: var(--vw-radius-chip);
        background: var(--vw-fill);
        color: var(--vw-teal-text);
      }
      .choice-icon svg,
      .choice > svg {
        width: 15px;
        height: 15px;
      }
      .choice > svg {
        color: var(--vw-chevron);
      }
      .choice-copy {
        display: flex;
        min-width: 0;
        flex-direction: column;
      }
      .choice-name,
      .choice-user {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .choice-name {
        font-size: 13px;
        font-weight: 600;
      }
      .choice-user {
        color: var(--vw-muted);
        font-size: 11.5px;
      }
      .execution {
        display: flex;
        flex: 1;
        min-height: 126px;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 8px;
        text-align: center;
      }
      .execution-icon {
        display: grid;
        place-items: center;
        width: 38px;
        height: 38px;
        border-radius: 50%;
        background: var(--vw-teal-10);
        color: var(--vw-teal-text);
      }
      .execution-icon svg {
        width: 19px;
        height: 19px;
        animation: mvSpin 1.2s linear infinite;
      }
      .execution-title {
        margin: 0;
        font-size: 13px;
        font-weight: 600;
      }
      .execution-hint,
      .empty {
        margin: 0;
        max-width: 260px;
        color: var(--vw-muted);
        font-size: 11.5px;
        line-height: 1.45;
      }
      .footer {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: 8px;
        padding: 10px 16px 14px;
        border-top: 1px solid var(--vw-line-1);
      }
      .footer.awaiting { flex-wrap: wrap; }
      .footer.awaiting .cancel-note { flex-basis: 100%; margin: 0; }
      .fallback-always { min-width: 0; }
      .cancel-note {
        margin-right: auto;
        color: var(--vw-muted);
        font-size: 10.5px;
      }
      .cancel {
        min-width: 108px;
      }
      vw-status-message {
        width: 100%;
      }
      @media (prefers-reduced-motion: reduce) {
        .execution-icon svg { animation: none; }
      }
    `,
  ];

  override connectedCallback(): void {
    super.connectedCallback();
    this.addEventListener('keydown', this.handleKeydown);
  }

  override disconnectedCallback(): void {
    this.removeEventListener('keydown', this.handleKeydown);
    this.decisionLocked = true;
    super.disconnectedCallback();
  }

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (!changed.has('model')) return;
    const ceremonyId = this.model?.ceremonyId;
    if (ceremonyId !== this.activeCeremonyId) {
      this.activeCeremonyId = ceremonyId;
      this.decisionLocked = false;
      this.focusedViewKey = undefined;
    }
  }

  protected override updated(changed: PropertyValues<this>): void {
    if (!changed.has('model') || !this.model) return;
    const viewKey = `${this.model.ceremonyId}:${this.model.state}`;
    if (this.focusedViewKey === viewKey) return;
    this.focusedViewKey = viewKey;
    const focusTarget = this.model.state === 'awaiting'
      ? this.renderRoot.querySelector<HTMLElement>('[data-primary-action], [data-cancel]')
      : this.renderRoot.querySelector<HTMLElement>('[role="dialog"]');
    focusTarget?.focus();
  }

  private canAct(model: WebsitePasskeyViewModel): boolean {
    return model.state === 'awaiting' && model.ceremonyId.length > 0 && !this.decisionLocked;
  }

  private approveCredential(credentialId: string): void {
    const model = this.model;
    if (!model || model.kind !== 'get' || !this.canAct(model)) return;
    if (!model.candidates.some((candidate) => candidate.id === credentialId)) return;
    this.approve(model.ceremonyId, { kind: 'credential', credentialId });
  }

  private approveNew(): void {
    const model = this.model;
    if (!model || model.kind !== 'create' || !this.canAct(model)) return;
    this.approve(model.ceremonyId, { kind: 'new' });
  }

  private approveTarget(cipherId: string): void {
    const model = this.model;
    if (!model || model.kind !== 'create' || !this.canAct(model)) return;
    if (!model.targets.some((target) => target.id === cipherId)) return;
    this.approve(model.ceremonyId, { kind: 'target', cipherId });
  }

  private approve(ceremonyId: string, selection: WebsitePasskeySelection): void {
    const model = this.model;
    if (!model || model.ceremonyId !== ceremonyId || !this.canAct(model)) return;
    this.decisionLocked = true;
    this.model = { ...model, state: 'executing' };
    // The awaiting controls are now structurally gone, so duplicate approval is impossible. Release
    // the local lock for the execution-only cancel action before the root awaits the coordinator.
    this.decisionLocked = false;
    emit<WebsitePasskeyApproveDetail>(this, 'vw-website-passkey-approve', { ceremonyId, selection });
  }

  private cancel(): void {
    const model = this.model;
    if (!model || this.decisionLocked) return;
    this.decisionLocked = true;
    this.requestUpdate();
    emit<WebsitePasskeyCancelDetail>(this, 'vw-website-passkey-cancel', { ceremonyId: model.ceremonyId });
  }

  private fallback(always: boolean): void {
    const model = this.model;
    if (!model || !this.canAct(model)) return;
    this.decisionLocked = true;
    this.requestUpdate();
    emit<WebsitePasskeyFallbackDetail>(
      this,
      always ? 'vw-website-passkey-fallback-always' : 'vw-website-passkey-fallback-once',
      { ceremonyId: model.ceremonyId },
    );
  }

  private readonly handleKeydown = (event: KeyboardEvent): void => {
    if (event.key !== 'Escape' || event.defaultPrevented || !this.model) return;
    event.preventDefault();
    event.stopPropagation();
    this.cancel();
  };

  private renderChoice(
    choice: WebsitePasskeyDisplayChoice,
    action: (id: string) => void,
    icon: 'passkey' | 'user',
    primary = false,
  ) {
    const disabled = this.model?.state !== 'awaiting' || this.decisionLocked;
    return html`
      <button
        type="button"
        class="choice"
        ?disabled=${disabled}
        data-primary-action=${primary ? '' : nothing}
        @click=${() => action(choice.id)}
      >
        <span class="choice-icon" aria-hidden="true">${uiIcon(icon)}</span>
        <span class="choice-copy">
          <span class="choice-name">${choice.name}</span>
          ${choice.username ? html`<span class="choice-user">${choice.username}</span>` : nothing}
        </span>
        ${uiIcon('chevron')}
      </button>
    `;
  }

  private renderAwaiting(model: WebsitePasskeyViewModel) {
    if (model.kind === 'get') {
      return html`
        <p class="section-label">${t('websitePasskey.chooseCredential')}</p>
        ${model.candidates.length > 0
          ? html`<div class="choices">${model.candidates.map((candidate, index) => (
              this.renderChoice(candidate, (credentialId) => this.approveCredential(credentialId), 'passkey', index === 0)
            ))}</div>`
          : html`<p class="empty" role="status">${t('websitePasskey.noCredentials')}</p>`}
      `;
    }
    return html`
      <p class="section-label">${t('websitePasskey.chooseSaveTarget')}</p>
      <div class="choices">
        <button
          type="button"
          class="choice"
          data-primary-action
          ?disabled=${this.decisionLocked || model.state !== 'awaiting'}
          @click=${() => this.approveNew()}
        >
          <span class="choice-icon" aria-hidden="true">${uiIcon('user')}</span>
          <span class="choice-copy">
            <span class="choice-name">${t('websitePasskey.createNew')}</span>
            <span class="choice-user">${t('websitePasskey.createNewHint')}</span>
          </span>
          ${uiIcon('chevron')}
        </button>
        ${model.targets.map((target) => (
          this.renderChoice(target, (cipherId) => this.approveTarget(cipherId), 'passkey')
        ))}
      </div>
    `;
  }

  private renderExecution(model: WebsitePasskeyViewModel) {
    return html`
      <div class="execution" role="status" aria-live="polite">
        <span class="execution-icon" aria-hidden="true">${uiIcon('refresh')}</span>
        <p class="execution-title">${t(model.kind === 'get'
          ? 'websitePasskey.executingGet'
          : 'websitePasskey.executingCreate')}</p>
        <p class="execution-hint">${t('websitePasskey.keepOpen')}</p>
      </div>
    `;
  }

  private renderFooter(model: WebsitePasskeyViewModel) {
    if (model.state === 'awaiting') {
      return html`
        <footer class="footer awaiting">
          <span class="cancel-note">${t('websitePasskey.browserFallbackHint')}</span>
          <button type="button" class="btn outline" data-fallback-once ?disabled=${this.decisionLocked} @click=${() => this.fallback(false)}>${uiIcon('globe')}<span>${t('websitePasskey.fallbackOnce')}</span></button>
          <button type="button" class="btn ghost fallback-always" data-fallback-always ?disabled=${this.decisionLocked} @click=${() => this.fallback(true)}>${t('websitePasskey.fallbackAlways')}</button>
          <button type="button" class="btn ghost" data-cancel ?disabled=${this.decisionLocked} title=${t('websitePasskey.cancelRequest')} @click=${() => this.cancel()}>${uiIcon('close')}<span>${t('websitePasskey.cancelRequest')}</span></button>
        </footer>
      `;
    }
    return html`
      <footer class="footer">
        <span class="cancel-note">${t(model.state === 'executing' ? 'websitePasskey.executingCancelHint' : 'websitePasskey.errorCloseHint')}</span>
        <button type="button" class="btn outline cancel" data-cancel ?disabled=${this.decisionLocked} title=${t(model.state === 'executing' ? 'websitePasskey.cancelExecution' : 'common.close')} @click=${() => this.cancel()}>
          ${uiIcon('close')}<span>${t(model.state === 'executing' ? 'websitePasskey.cancelExecution' : 'common.close')}</span>
        </button>
      </footer>
    `;
  }

  protected override render() {
    const model = this.model;
    if (!model) return nothing;
    const titleKey = model.kind === 'get' ? 'websitePasskey.getTitle' : 'websitePasskey.createTitle';
    const descriptionKey = model.kind === 'get' ? 'websitePasskey.getDescription' : 'websitePasskey.createDescription';
    const executing = model.state === 'executing';
    return html`
      <section
        class="ceremony"
        role="dialog"
        aria-modal="true"
        aria-labelledby="website-passkey-title"
        aria-describedby="website-passkey-description"
        aria-busy=${executing ? 'true' : 'false'}
        tabindex="-1"
      >
        <header class="head">
          <span class="mark" aria-hidden="true">${uiIcon('passkey')}</span>
          <div class="head-copy">
            <h1 id="website-passkey-title">${t(titleKey)}</h1>
            <p class="subtitle" id="website-passkey-description">${t(descriptionKey)}</p>
          </div>
        </header>
        ${model.origin && model.rpId
          ? html`
              <div class="source">
                ${uiIcon('globe')}
                <span class="origin" title=${model.origin}>${model.origin}</span>
                <span class="rp">${t('websitePasskey.rpId', { rpId: model.rpId })}</span>
              </div>
            `
          : nothing}
        <main class="content">
          ${renderAuthIdentity(this.identity)}
          ${model.state === 'error'
            ? html`<vw-status-message
                tone="danger"
                .icon=${'alert'}
                .message=${model.errorMessage || t('websitePasskey.errorDefault')}
              ></vw-status-message>`
            : executing
              ? this.renderExecution(model)
              : this.renderAwaiting(model)}
        </main>
        ${this.renderFooter(model)}
      </section>
    `;
  }
}

customElements.define('vw-website-passkey-view', VwWebsitePasskeyView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-website-passkey-view': VwWebsitePasskeyView;
  }
}
