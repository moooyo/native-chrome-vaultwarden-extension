import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { LocalizeController, t } from '../../i18n/index.js';
import { uiIcon } from '../../components/icon.js';
import { settingsSectionStyles } from './section-styles.js';
import '../../components/setting-card.js';
import '../../components/select-menu.js';
import '../../components/status-message.js';
import '../../components/toggle.js';
import type { SelectOption } from '../../components/select-menu.js';
import { normalizeAutofillBlocklist } from '../../../core/vault/autofill-policy.js';
import { UriMatchStrategy, isUriMatchStrategySetting, type UriMatchStrategySetting } from '../../../core/vault/uri-match.js';
import {
  MAX_WEBSITE_PASSKEY_EXCLUDED_DOMAINS,
  canonicalizeWebsitePasskeyHostname,
} from '../../../background/settings.js';
import {
  MAX_HTTP_AUTH_ORIGINS,
  canonicalizeHttpAuthOrigin,
} from '../../../background/http-auth-settings.js';
import type {
  AutofillSaveDetail,
  HttpAuthSaveDetail,
  SectionStatus,
  ToolbarBadgeSaveDetail,
  WebsitePasskeySaveDetail,
} from '../types.js';

/** Human labels for each URI-match strategy, in display order. */
function strategyOptions(): SelectOption[] {
  return [
    { value: String(UriMatchStrategy.Domain), label: t('options.autofill.matchDomain') },
    { value: String(UriMatchStrategy.Host), label: t('options.autofill.matchHost') },
    { value: String(UriMatchStrategy.StartsWith), label: t('options.autofill.matchStartsWith') },
    { value: String(UriMatchStrategy.Exact), label: t('options.autofill.matchExact') },
    { value: String(UriMatchStrategy.RegularExpression), label: t('options.autofill.matchRegex') },
    { value: String(UriMatchStrategy.Never), label: t('options.autofill.matchNever') },
  ];
}

/**
 * Worker-authoritative autofill and website-passkey policies plus the browser-assigned focused-fill
 * shortcut. The section is fully controlled: it emits complete policy snapshots and never writes
 * storage or calls browser APIs directly. Domain edits remain local until the root accepts a save.
 */
export class VwAutofillSection extends LitElement {
  static override properties = {
    defaultUriMatchStrategy: { attribute: false },
    uriMatchDefaultManaged: { type: Boolean },
    uriMatchDefaultMalformed: { type: Boolean },
    inlineSuggestions: { type: Boolean },
    pageLoadFill: { type: Boolean },
    pageLoadFillDefault: { type: Boolean },
    autoCopyTotp: { type: Boolean },
    showMatchingLoginCount: { type: Boolean },
    activateAutofillManaged: { type: Boolean },
    savePromptEnabled: { type: Boolean },
    updatePromptEnabled: { type: Boolean },
    savePromptExcludedDomains: { attribute: false },
    blockedDomains: { attribute: false },
    autofillPolicyValid: { type: Boolean },
    websitePasskeyEnabled: { type: Boolean },
    websitePasskeyExcludedDomains: { attribute: false },
    websitePasskeyPolicyValid: { type: Boolean },
    websitePasskeyPending: { type: Boolean },
    httpAuthEnabled: { type: Boolean },
    httpAuthAllowedOrigins: { attribute: false },
    httpAuthPolicyValid: { type: Boolean },
    httpAuthPending: { type: Boolean },
    shortcut: { type: String },
    pending: { type: Boolean },
    status: { attribute: false },
    activeTab: { state: true },
    lastSaveGroup: { state: true },
  };

  declare defaultUriMatchStrategy: UriMatchStrategySetting;
  declare uriMatchDefaultManaged: boolean;
  declare uriMatchDefaultMalformed: boolean;
  declare inlineSuggestions: boolean;
  declare pageLoadFill: boolean;
  declare pageLoadFillDefault: boolean;
  declare autoCopyTotp: boolean;
  declare showMatchingLoginCount: boolean;
  declare activateAutofillManaged: boolean;
  declare savePromptEnabled: boolean;
  declare updatePromptEnabled: boolean;
  declare savePromptExcludedDomains: string[];
  declare blockedDomains: string[];
  declare autofillPolicyValid: boolean;
  declare websitePasskeyEnabled: boolean;
  declare websitePasskeyExcludedDomains: string[];
  declare websitePasskeyPolicyValid: boolean;
  declare websitePasskeyPending: boolean;
  declare httpAuthEnabled: boolean;
  declare httpAuthAllowedOrigins: string[];
  declare httpAuthPolicyValid: boolean;
  declare httpAuthPending: boolean;
  declare shortcut: string;
  declare pending: boolean;
  declare status: SectionStatus | undefined;
  private declare activeTab: 'fill' | 'rules' | 'passkeys' | 'http';
  private declare lastSaveGroup: 'policy' | 'badge' | 'passkeys' | 'http' | undefined;
  private retrySave: (() => void) | undefined;

  private i18n = new LocalizeController(this);
  private blockedDomainsDraft: string | undefined;
  private blockedDomainsDirty = false;
  private invalidDomains: string[] = [];
  private savePromptDomainsDraft: string | undefined;
  private savePromptDomainsDirty = false;
  private invalidSavePromptDomains: string[] = [];
  private websitePasskeyDomainsDraft: string | undefined;
  private websitePasskeyDomainsDirty = false;
  private invalidWebsitePasskeyDomains: string[] = [];
  private httpAuthOriginsDraft: string | undefined;
  private httpAuthOriginsDirty = false;
  private invalidHttpAuthOrigins: string[] = [];

  constructor() {
    super();
    this.defaultUriMatchStrategy = UriMatchStrategy.Domain;
    this.uriMatchDefaultManaged = false;
    this.uriMatchDefaultMalformed = false;
    this.inlineSuggestions = false;
    this.pageLoadFill = false;
    this.pageLoadFillDefault = true;
    this.autoCopyTotp = true;
    this.showMatchingLoginCount = true;
    this.activateAutofillManaged = false;
    this.savePromptEnabled = false;
    this.updatePromptEnabled = false;
    this.savePromptExcludedDomains = [];
    this.blockedDomains = [];
    this.autofillPolicyValid = false;
    this.websitePasskeyEnabled = false;
    this.websitePasskeyExcludedDomains = [];
    this.websitePasskeyPolicyValid = false;
    this.websitePasskeyPending = false;
    this.httpAuthEnabled = false;
    this.httpAuthAllowedOrigins = [];
    this.httpAuthPolicyValid = false;
    this.httpAuthPending = false;
    this.shortcut = '';
    this.pending = false;
    this.status = undefined;
    this.activeTab = 'fill';
  }

  static override styles = [
    themeTokens,
    settingsSectionStyles,
    css`
      vw-setting-card[hidden], .policy-warning[hidden], vw-status-message[hidden] { display:none; }
      .settings-sheet > vw-setting-card + vw-setting-card { border-top:0; }
      .settings-sheet vw-setting-card::part(card) { border-bottom:1px solid var(--vw-line-1); }
      .settings-sheet vw-setting-card:last-of-type::part(card) { border-bottom:0; }
      .policy-warning, .settings-sheet > vw-status-message { margin:16px 24px; }
      .feedback-strip { position:sticky; top:0; z-index:2; padding:10px 0 2px; background:var(--vw-options-bg); }
      .feedback-strip .save-feedback { margin-bottom:10px; }
      .empty-origin-note { padding:0 24px 16px; color:var(--vw-muted); font-size:12px; line-height:1.6; }
      .domain-editor { display: flex; flex-direction: column; gap: 10px; width: 100%; min-width: 0; }
      textarea {
        box-sizing: border-box;
        width: 100%;
        min-height: 92px;
        resize: vertical;
        padding: 9px 10px;
        border: 1px solid var(--vw-line-3);
        border-radius: var(--vw-radius-input);
        background: var(--vw-card);
        color: var(--vw-ink);
        font: 12.5px/1.5 var(--vw-font-mono);
      }
      textarea::placeholder { color: var(--vw-text-2); }
      textarea:focus-visible { outline: none; border-color: var(--vw-accent); box-shadow: var(--vw-focus); }
      textarea:disabled { opacity: 0.55; cursor: default; }
      .domain-meta {
        color: var(--vw-text-2);
        font-size: 11.5px;
        line-height: 1.45;
        overflow-wrap: anywhere;
      }
      .domain-error { color: var(--vw-danger); }
      .domain-list {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin: 0;
        padding: 0;
        list-style: none;
      }
      .domain-list li {
        max-width: 100%;
        overflow-wrap: anywhere;
        padding: 3px 7px;
        border: 1px solid var(--vw-line-2);
        border-radius: 6px;
        background: var(--vw-icon-hover);
        color: var(--vw-text-4);
        font: 11.5px/1.35 var(--vw-font-mono);
      }
      .domain-actions, .policy-warning { display: flex; align-items: center; gap: 10px; min-width: 0; }
      .domain-actions { flex-wrap: wrap; }
      .policy-warning {
        justify-content: space-between;
        padding: 8px 12px;
        border: 1px solid var(--vw-sync-amber);
        border-radius: var(--vw-radius-control);
        background: var(--vw-fill-2);
      }
      .policy-warning span { color: var(--vw-text-4); font-size: 12px; line-height: 1.45; }
      .shortcut { display: inline-flex; align-items: center; gap: 10px; }
      .keychip {
        font-family: var(--vw-font-mono);
        font-size: 12px;
        color: var(--vw-ink);
        background: var(--vw-icon-hover);
        border: 1px solid var(--vw-line-3);
        border-radius: 6px;
        padding: 3px 8px;
      }
      .btn-outline {
        height: 30px;
        padding: 0 13px;
        border: 1px solid var(--vw-line-3);
        border-radius: var(--vw-radius-input);
        background: var(--vw-card);
        color: var(--vw-text-4);
        font-family: inherit;
        font-size: 12.5px;
        cursor: pointer;
        max-width: 100%;
        white-space: normal;
      }
      .btn-outline:hover:not(:disabled) { background: var(--vw-row-hover); }
      .btn-outline:disabled { opacity: 0.5; cursor: default; }
      vw-select[inert] { opacity: 0.55; pointer-events: none; }
      button:focus-visible { outline: none; box-shadow: var(--vw-focus); }
    `,
  ];

  private onStrategyChange(value: string): void {
    if (this.uriMatchDefaultManaged || this.pending) return;
    const raw = Number(value);
    if (!isUriMatchStrategySetting(raw)) return;
    this.emitPolicy({ defaultUriMatchStrategy: raw });
  }

  private onPageLoadChange(checked: boolean): void {
    if (this.activateAutofillManaged || this.pending) return;
    this.emitPolicy({ pageLoadFill: checked });
  }

  private emitPolicy(overrides: Partial<AutofillSaveDetail>): void {
    const detail: AutofillSaveDetail = {
      defaultUriMatchStrategy: this.defaultUriMatchStrategy,
      inlineSuggestions: this.inlineSuggestions,
      pageLoadFill: this.pageLoadFill,
      pageLoadFillDefault: this.pageLoadFillDefault,
      autoCopyTotp: this.autoCopyTotp,
      savePromptEnabled: this.savePromptEnabled,
      updatePromptEnabled: this.updatePromptEnabled,
      savePromptExcludedDomains: [...this.savePromptExcludedDomains],
      blockedDomains: [...this.blockedDomains],
      ...overrides,
    };
    this.lastSaveGroup = 'policy';
    this.retrySave = () => emit<AutofillSaveDetail>(this, 'vw-autofill-save', detail);
    this.retrySave();
  }

  private onBlockedDomainsInput(event: Event): void {
    this.blockedDomainsDraft = (event.target as HTMLTextAreaElement).value;
    this.blockedDomainsDirty = true;
    this.invalidDomains = parseBlockedDomains(this.blockedDomainsDraft).invalid;
    this.requestUpdate();
  }

  private saveBlockedDomains(): void {
    const parsed = parseBlockedDomains(this.domainDraft());
    this.invalidDomains = parsed.invalid;
    if (parsed.invalid.length > 0) {
      this.requestUpdate();
      return;
    }
    this.emitPolicy({ blockedDomains: parsed.domains });
  }

  private onSavePromptDomainsInput(event: Event): void {
    this.savePromptDomainsDraft = (event.target as HTMLTextAreaElement).value;
    this.savePromptDomainsDirty = true;
    this.invalidSavePromptDomains = parseBlockedDomains(this.savePromptDomainsDraft).invalid;
    this.requestUpdate();
  }

  private saveSavePromptDomains(): void {
    const parsed = parseBlockedDomains(this.savePromptDomainDraft());
    this.invalidSavePromptDomains = parsed.invalid;
    if (parsed.invalid.length > 0) {
      this.requestUpdate();
      return;
    }
    this.emitPolicy({ savePromptExcludedDomains: parsed.domains });
  }

  private restoreSafeDefaults(): void {
    this.blockedDomainsDraft = '';
    this.blockedDomainsDirty = true;
    this.invalidDomains = [];
    this.emitPolicy({
      defaultUriMatchStrategy: this.uriMatchDefaultManaged
        ? this.defaultUriMatchStrategy
        : UriMatchStrategy.Domain,
      inlineSuggestions: true,
      pageLoadFill: false,
      pageLoadFillDefault: true,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: [],
      blockedDomains: [],
    });
  }

  private emitWebsitePasskeySettings(overrides: Partial<WebsitePasskeySaveDetail>): void {
    const detail: WebsitePasskeySaveDetail = {
      enabled: this.websitePasskeyEnabled,
      excludedDomains: [...this.websitePasskeyExcludedDomains],
      ...overrides,
    };
    this.lastSaveGroup = 'passkeys';
    this.retrySave = () => emit<WebsitePasskeySaveDetail>(this, 'vw-website-passkey-save', detail);
    this.retrySave();
  }

  private onWebsitePasskeyDomainsInput(event: Event): void {
    this.websitePasskeyDomainsDraft = (event.target as HTMLTextAreaElement).value;
    this.websitePasskeyDomainsDirty = true;
    this.invalidWebsitePasskeyDomains = parseWebsitePasskeyDomains(
      this.websitePasskeyDomainsDraft,
    ).invalid;
    this.requestUpdate();
  }

  private saveWebsitePasskeyDomains(): void {
    const parsed = parseWebsitePasskeyDomains(this.websitePasskeyDomainDraft());
    this.invalidWebsitePasskeyDomains = parsed.invalid;
    if (parsed.invalid.length > 0) {
      this.requestUpdate();
      return;
    }
    this.emitWebsitePasskeySettings({ excludedDomains: parsed.domains });
  }

  private emitHttpAuthSettings(overrides: Partial<HttpAuthSaveDetail>): void {
    const detail: HttpAuthSaveDetail = {
      enabled: this.httpAuthEnabled,
      allowedOrigins: [...this.httpAuthAllowedOrigins],
      ...overrides,
    };
    if (detail.enabled && detail.allowedOrigins.length === 0) return;
    this.lastSaveGroup = 'http';
    this.retrySave = () => emit<HttpAuthSaveDetail>(this, 'vw-http-auth-save', detail);
    this.retrySave();
  }

  private onHttpAuthOriginsInput(event: Event): void {
    this.httpAuthOriginsDraft = (event.target as HTMLTextAreaElement).value;
    this.httpAuthOriginsDirty = true;
    this.invalidHttpAuthOrigins = parseHttpAuthOrigins(this.httpAuthOriginsDraft).invalid;
    this.requestUpdate();
  }

  private saveHttpAuthOrigins(): void {
    const parsed = parseHttpAuthOrigins(this.httpAuthOriginDraft());
    this.invalidHttpAuthOrigins = parsed.invalid;
    if (parsed.invalid.length > 0) {
      this.requestUpdate();
      return;
    }
    this.emitHttpAuthSettings({ allowedOrigins: parsed.domains });
  }

  private restoreSafeHttpAuthDefaults(): void {
    this.httpAuthOriginsDraft = '';
    this.httpAuthOriginsDirty = true;
    this.invalidHttpAuthOrigins = [];
    this.emitHttpAuthSettings({ enabled: false, allowedOrigins: [] });
  }

  private domainDraft(): string {
    return this.blockedDomainsDraft ?? this.blockedDomains.join('\n');
  }

  private savePromptDomainDraft(): string {
    return this.savePromptDomainsDraft ?? this.savePromptExcludedDomains.join('\n');
  }

  private websitePasskeyDomainDraft(): string {
    return this.websitePasskeyDomainsDraft ?? this.websitePasskeyExcludedDomains.join('\n');
  }

  private httpAuthOriginDraft(): string {
    return this.httpAuthOriginsDraft ?? this.httpAuthAllowedOrigins.join('\n');
  }

  protected override updated(changed: PropertyValues<this>): void {
    if (changed.has('blockedDomains')) {
      const parsed = parseBlockedDomains(this.domainDraft());
      if (!this.blockedDomainsDirty || sameDomains(parsed.domains, this.blockedDomains)) {
        this.blockedDomainsDraft = this.blockedDomains.join('\n');
        this.blockedDomainsDirty = false;
        this.invalidDomains = [];
      }
    }
    if (changed.has('savePromptExcludedDomains')) {
      const parsed = parseBlockedDomains(this.savePromptDomainDraft());
      if (
        !this.savePromptDomainsDirty
        || sameDomains(parsed.domains, this.savePromptExcludedDomains)
      ) {
        this.savePromptDomainsDraft = this.savePromptExcludedDomains.join('\n');
        this.savePromptDomainsDirty = false;
        this.invalidSavePromptDomains = [];
      }
    }
    if (changed.has('websitePasskeyExcludedDomains')) {
      const parsed = parseWebsitePasskeyDomains(this.websitePasskeyDomainDraft());
      if (
        !this.websitePasskeyDomainsDirty
        || sameDomains(parsed.domains, this.websitePasskeyExcludedDomains)
      ) {
        this.websitePasskeyDomainsDraft = this.websitePasskeyExcludedDomains.join('\n');
        this.websitePasskeyDomainsDirty = false;
        this.invalidWebsitePasskeyDomains = [];
      }
    }
    if (changed.has('httpAuthAllowedOrigins')) {
      const parsed = parseHttpAuthOrigins(this.httpAuthOriginDraft());
      if (!this.httpAuthOriginsDirty || sameDomains(parsed.domains, this.httpAuthAllowedOrigins)) {
        this.httpAuthOriginsDraft = this.httpAuthAllowedOrigins.join('\n');
        this.httpAuthOriginsDirty = false;
        this.invalidHttpAuthOrigins = [];
      }
    }
  }

  private renderSaveFeedback() {
    const saving = this.lastSaveGroup === 'passkeys' ? this.websitePasskeyPending
      : this.lastSaveGroup === 'http' ? this.httpAuthPending : this.pending;
    const state = saving && this.lastSaveGroup ? 'saving'
      : this.status?.tone === 'danger' ? 'error'
        : this.status?.tone === 'success' ? 'saved' : 'idle';
    return html`<div class="feedback-strip"><div class="save-feedback" data-state=${state} role="status" aria-live="polite">
      ${state !== 'idle' ? html`<span class="save-mark" aria-hidden="true">${state === 'saved' ? uiIcon('check') : state === 'error' ? uiIcon('alert') : nothing}</span>` : nothing}
      <span class="save-copy">${state === 'saving' ? t('options.save.saving') : this.status?.message ?? t('options.save.automatic')}</span>
      ${state === 'error' && this.retrySave ? html`<button type="button" class="retry-save" data-retry-save @click=${() => this.retrySave?.()}>${t('common.retry')}</button>` : nothing}
      ${this.status?.tone === 'warning' && this.status.message === t('options.save.refreshFailed') ? html`<button type="button" class="retry-save" data-refresh-settings ?disabled=${this.pending} @click=${() => emit(this, 'vw-settings-refresh')}>${t('common.retry')}</button>` : nothing}
    </div></div>`;
  }

  private onTabKey(event: KeyboardEvent): void {
    const tabs = ['fill', 'rules', 'passkeys', 'http'] as const;
    const index = tabs.indexOf(this.activeTab);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1
      : event.key === 'ArrowRight' ? (index + 1) % tabs.length
        : event.key === 'ArrowLeft' ? (index - 1 + tabs.length) % tabs.length : -1;
    if (next < 0) return;
    event.preventDefault();
    this.activeTab = tabs[next]!;
    void this.updateComplete.then(() => this.renderRoot.querySelector<HTMLButtonElement>(`[data-tab="${this.activeTab}"]`)?.focus());
  }

  protected override render() {
    const tabs = [
      { id: 'fill', label: t('options.autofill.tabFill') },
      { id: 'rules', label: t('options.autofill.tabRules') },
      { id: 'passkeys', label: t('options.autofill.tabPasskeys') },
      { id: 'http', label: 'HTTP Auth' },
    ] as const;
    return html`
      <nav class="section-tabs" role="tablist" aria-label=${t('options.autofill.title')}>
        ${tabs.map((tab) => html`<button type="button" id=${`tab-${tab.id}`} data-tab=${tab.id} role="tab" aria-selected=${this.activeTab === tab.id ? 'true' : 'false'} aria-controls="settings-panel" tabindex=${this.activeTab === tab.id ? 0 : -1} @click=${() => { this.activeTab = tab.id; }} @keydown=${this.onTabKey}>${tab.label}</button>`)}
      </nav>
      <p class="section-note">${t('options.save.browserScope')}</p>
      ${this.renderSaveFeedback()}
      <div class="settings-sheet" id="settings-panel" role="tabpanel" aria-labelledby=${`tab-${this.activeTab}`}>
      <vw-setting-card ?hidden=${this.activeTab !== 'rules'} heading=${t('options.autofill.matchTitle')} description=${t('options.autofill.matchDesc')}>
        <vw-select
          data-strategy
          .options=${strategyOptions()}
          .value=${String(this.defaultUriMatchStrategy)}
          .label=${t('options.autofill.matchTitle')}
          .disabled=${this.pending || this.uriMatchDefaultManaged}
          ?inert=${this.pending || this.uriMatchDefaultManaged}
          aria-disabled=${this.pending || this.uriMatchDefaultManaged ? 'true' : 'false'}
          @vw-select-change=${(e: CustomEvent<{ value: string }>) => this.onStrategyChange(e.detail.value)}
        ></vw-select>
      </vw-setting-card>

      ${this.uriMatchDefaultManaged
        ? html`<vw-status-message
            data-uri-match-managed
            ?hidden=${this.activeTab !== 'rules'}
            tone=${this.uriMatchDefaultMalformed ? 'danger' : 'info'}
            .message=${this.uriMatchDefaultMalformed
              ? t('options.autofill.matchManagedMalformed')
              : t('options.autofill.matchManaged')}
          ></vw-status-message>`
        : this.uriMatchDefaultMalformed
          ? html`<vw-status-message
              data-uri-match-malformed
              ?hidden=${this.activeTab !== 'rules'}
              tone="danger"
              .message=${t('options.autofill.matchMalformed')}
            ></vw-status-message>`
          : nothing}

      <vw-setting-card ?hidden=${this.activeTab !== 'fill'} heading=${t('options.autofill.inline')} description=${t('options.autofill.inlineDesc')}>
        <vw-toggle
          data-inline
          .label=${t('options.autofill.inline')}
          .checked=${this.inlineSuggestions}
          .disabled=${this.pending}
          @vw-toggle-change=${(event: CustomEvent<{ checked: boolean }>) => this.emitPolicy({ inlineSuggestions: event.detail.checked })}
        ></vw-toggle>
      </vw-setting-card>

      <vw-setting-card
        ?hidden=${this.activeTab !== 'fill'}
        heading=${t('options.autofill.toolbarCount')}
        description=${t('options.autofill.toolbarCountDesc')}
      >
        <vw-toggle
          data-toolbar-count
          .label=${t('options.autofill.toolbarCount')}
          .checked=${this.showMatchingLoginCount}
          .disabled=${this.pending}
          @vw-toggle-change=${(event: CustomEvent<{ checked: boolean }>) => {
            this.lastSaveGroup = 'badge';
            const detail: ToolbarBadgeSaveDetail = {
              showMatchingLoginCount: event.detail.checked,
            };
            this.retrySave = () => emit<ToolbarBadgeSaveDetail>(this, 'vw-toolbar-badge-save', detail);
            this.retrySave();
          }}
        ></vw-toggle>
      </vw-setting-card>

      <vw-setting-card ?hidden=${this.activeTab !== 'fill'} heading=${t('options.autofill.pageLoad')} description=${t('options.autofill.pageLoadDesc')}>
        <vw-toggle
          data-page-load
          .label=${t('options.autofill.pageLoad')}
          .checked=${this.pageLoadFill || this.activateAutofillManaged}
          .disabled=${this.pending || this.activateAutofillManaged}
          ?inert=${this.pending || this.activateAutofillManaged}
          aria-disabled=${this.pending || this.activateAutofillManaged ? 'true' : 'false'}
          @vw-toggle-change=${(event: CustomEvent<{ checked: boolean }>) => this.onPageLoadChange(event.detail.checked)}
        ></vw-toggle>
      </vw-setting-card>

      ${this.activateAutofillManaged
        ? html`<vw-status-message
            data-page-load-managed
            ?hidden=${this.activeTab !== 'fill'}
            tone="info"
            .message=${t('options.autofill.pageLoadManaged')}
          ></vw-status-message>`
        : nothing}

      <vw-setting-card
        ?hidden=${this.activeTab !== 'fill'}
        heading=${t('options.autofill.pageLoadDefault')}
        description=${t('options.autofill.pageLoadDefaultDesc')}
      >
        <vw-toggle
          data-page-load-default
          .label=${t('options.autofill.pageLoadDefault')}
          .checked=${this.pageLoadFillDefault}
          .disabled=${this.pending}
          @vw-toggle-change=${(event: CustomEvent<{ checked: boolean }>) => this.emitPolicy({
            pageLoadFillDefault: event.detail.checked,
          })}
        ></vw-toggle>
      </vw-setting-card>

      <vw-setting-card
        ?hidden=${this.activeTab !== 'fill'}
        heading=${t('options.autofill.autoCopyTotp')}
        description=${t('options.autofill.autoCopyTotpDesc')}
      >
        <vw-toggle
          data-auto-copy-totp
          .label=${t('options.autofill.autoCopyTotp')}
          .checked=${this.autoCopyTotp}
          .disabled=${this.pending}
          @vw-toggle-change=${(event: CustomEvent<{ checked: boolean }>) => this.emitPolicy({
            autoCopyTotp: event.detail.checked,
          })}
        ></vw-toggle>
      </vw-setting-card>

      <vw-setting-card ?hidden=${this.activeTab !== 'fill'} heading=${t('options.autofill.savePrompt')} description=${t('options.autofill.savePromptDesc')}>
        <vw-toggle
          data-save-prompt
          .label=${t('options.autofill.savePrompt')}
          .checked=${this.savePromptEnabled}
          .disabled=${this.pending}
          @vw-toggle-change=${(event: CustomEvent<{ checked: boolean }>) => this.emitPolicy({ savePromptEnabled: event.detail.checked })}
        ></vw-toggle>
      </vw-setting-card>

      <vw-setting-card ?hidden=${this.activeTab !== 'fill'} heading=${t('options.autofill.updatePrompt')} description=${t('options.autofill.updatePromptDesc')}>
        <vw-toggle
          data-update-prompt
          .label=${t('options.autofill.updatePrompt')}
          .checked=${this.updatePromptEnabled}
          .disabled=${this.pending}
          @vw-toggle-change=${(event: CustomEvent<{ checked: boolean }>) => this.emitPolicy({ updatePromptEnabled: event.detail.checked })}
        ></vw-toggle>
      </vw-setting-card>

      <vw-setting-card
        stacked
        ?hidden=${this.activeTab !== 'rules'}
        heading=${t('options.autofill.savePromptExcludedDomains')}
        description=${t('options.autofill.savePromptExcludedDomainsDesc')}
      >
        <div class="domain-editor">
          <textarea
            data-save-prompt-domains
            rows="4"
            aria-label=${t('options.autofill.savePromptExcludedDomains')}
            placeholder=${t('options.autofill.savePromptExcludedDomainsPlaceholder')}
            .value=${this.savePromptDomainDraft()}
            ?disabled=${this.pending}
            @input=${this.onSavePromptDomainsInput}
          ></textarea>
          ${this.renderSavePromptDomainState()}
          <div class="domain-actions">
            <button
              type="button"
              class="btn-outline"
              data-save-prompt-domains-save
              ?disabled=${this.pending || !this.savePromptDomainsDirty || this.invalidSavePromptDomains.length > 0}
              @click=${this.saveSavePromptDomains}
            >${t('options.autofill.saveSavePromptExcludedDomains')}</button>
          </div>
        </div>
      </vw-setting-card>

      <vw-setting-card
        ?hidden=${this.activeTab !== 'http'}
        heading=${t('options.autofill.httpAuth')}
        description=${t('options.autofill.httpAuthDesc')}
      >
        <vw-toggle
          data-http-auth
          .label=${t('options.autofill.httpAuth')}
          .checked=${this.httpAuthEnabled}
          .disabled=${this.httpAuthPending || (!this.httpAuthEnabled && this.httpAuthAllowedOrigins.length === 0)}
          @vw-toggle-change=${(event: CustomEvent<{ checked: boolean }>) => this.emitHttpAuthSettings({
            enabled: event.detail.checked,
          })}
        ></vw-toggle>
      </vw-setting-card>

      ${this.activeTab === 'http' && !this.httpAuthEnabled && this.httpAuthAllowedOrigins.length === 0
        ? html`<p class="empty-origin-note" data-http-auth-empty-hint>${t('options.autofill.httpAuthNeedsOrigin')}</p>` : nothing}

      <vw-setting-card
        stacked
        ?hidden=${this.activeTab !== 'http'}
        heading=${t('options.autofill.httpAuthOrigins')}
        description=${t('options.autofill.httpAuthOriginsDesc')}
      >
        <div class="domain-editor">
          <textarea
            data-http-auth-origins
            rows="4"
            aria-label=${t('options.autofill.httpAuthOrigins')}
            placeholder=${t('options.autofill.httpAuthOriginsPlaceholder')}
            .value=${this.httpAuthOriginDraft()}
            ?disabled=${this.httpAuthPending}
            @input=${this.onHttpAuthOriginsInput}
          ></textarea>
          ${this.renderHttpAuthOriginState()}
          <div class="domain-actions">
            <button
              type="button"
              class="btn-outline"
              data-save-http-auth-origins
              ?disabled=${this.httpAuthPending
                || !this.httpAuthOriginsDirty
                || this.invalidHttpAuthOrigins.length > 0}
              @click=${this.saveHttpAuthOrigins}
            >${t('options.autofill.saveHttpAuthOrigins')}</button>
          </div>
        </div>
      </vw-setting-card>

      ${!this.httpAuthPolicyValid
        ? html`
            <div class="policy-warning" ?hidden=${this.activeTab !== 'http'} data-http-auth-policy-warning role="status">
              <span>${t('options.autofill.invalidHttpAuthPolicy')}</span>
              <button
                type="button"
                class="btn-outline"
                data-restore-http-auth-policy
                ?disabled=${this.httpAuthPending}
                @click=${this.restoreSafeHttpAuthDefaults}
              >${t('options.autofill.restoreDefaults')}</button>
            </div>
          `
        : nothing}

      <vw-setting-card
        ?hidden=${this.activeTab !== 'passkeys'}
        heading=${t('options.autofill.websitePasskeys')}
        description=${t('options.autofill.websitePasskeysDesc')}
      >
        <vw-toggle
          data-website-passkeys
          .label=${t('options.autofill.websitePasskeys')}
          .checked=${this.websitePasskeyEnabled}
          .disabled=${this.websitePasskeyPending}
          @vw-toggle-change=${(event: CustomEvent<{ checked: boolean }>) => this.emitWebsitePasskeySettings({
            enabled: event.detail.checked,
          })}
        ></vw-toggle>
      </vw-setting-card>

      <vw-setting-card
        stacked
        ?hidden=${this.activeTab !== 'passkeys'}
        heading=${t('options.autofill.websitePasskeyExcludedDomains')}
        description=${t('options.autofill.websitePasskeyExcludedDomainsDesc')}
      >
        <div class="domain-editor">
          <textarea
            data-website-passkey-domains
            rows="4"
            aria-label=${t('options.autofill.websitePasskeyExcludedDomains')}
            placeholder=${t('options.autofill.websitePasskeyExcludedDomainsPlaceholder')}
            .value=${this.websitePasskeyDomainDraft()}
            ?disabled=${this.websitePasskeyPending}
            @input=${this.onWebsitePasskeyDomainsInput}
          ></textarea>
          ${this.renderWebsitePasskeyDomainState()}
          <div class="domain-actions">
            <button
              type="button"
              class="btn-outline"
              data-save-website-passkey-domains
              ?disabled=${this.websitePasskeyPending
                || !this.websitePasskeyDomainsDirty
                || this.invalidWebsitePasskeyDomains.length > 0}
              @click=${this.saveWebsitePasskeyDomains}
            >${t('options.autofill.saveWebsitePasskeyExcludedDomains')}</button>
          </div>
        </div>
      </vw-setting-card>

      ${!this.websitePasskeyPolicyValid
        ? html`
            <div class="policy-warning" ?hidden=${this.activeTab !== 'passkeys'} data-website-passkey-policy-warning role="status">
              <span>${t('options.autofill.invalidWebsitePasskeyPolicy')}</span>
            </div>
          `
        : nothing}

      <vw-setting-card
        stacked
        ?hidden=${this.activeTab !== 'rules'}
        heading=${t('options.autofill.blockedDomains')}
        description=${t('options.autofill.blockedDomainsDesc')}
      >
        <div class="domain-editor">
          <textarea
            data-blocked-domains
            rows="4"
            aria-label=${t('options.autofill.blockedDomains')}
            placeholder=${t('options.autofill.blockedDomainsPlaceholder')}
            .value=${this.domainDraft()}
            ?disabled=${this.pending}
            @input=${this.onBlockedDomainsInput}
          ></textarea>
          ${this.renderDomainState()}
          <div class="domain-actions">
            <button
              type="button"
              class="btn-outline"
              data-save-domains
              ?disabled=${this.pending || !this.blockedDomainsDirty || this.invalidDomains.length > 0}
              @click=${this.saveBlockedDomains}
            >${t('options.autofill.saveBlockedDomains')}</button>
          </div>
        </div>
      </vw-setting-card>

      ${!this.autofillPolicyValid
        ? html`
            <div class="policy-warning" ?hidden=${this.activeTab !== 'fill' && this.activeTab !== 'rules'} data-policy-warning role="status">
              <span>${t('options.autofill.invalidPolicy')}</span>
              <button
                type="button"
                class="btn-outline"
                data-restore-policy
                ?disabled=${this.pending}
                @click=${this.restoreSafeDefaults}
              >${t('options.autofill.restoreDefaults')}</button>
            </div>
          `
        : nothing}

      <vw-setting-card ?hidden=${this.activeTab !== 'fill'} heading=${t('options.autofill.shortcut')} description=${t('options.autofill.shortcutDesc')}>
        <div class="shortcut">
          <span class="keychip" data-shortcut>${this.shortcut || t('options.autofill.unassigned')}</span>
          <button type="button" class="btn-outline" data-shortcut-change ?disabled=${this.pending} @click=${() => emit(this, 'vw-shortcut-change')}>
            ${t('options.autofill.change')}
          </button>
        </div>
      </vw-setting-card>
      </div>
    `;
  }

  private renderDomainState() {
    const parsed = parseBlockedDomains(this.domainDraft());
    if (this.invalidDomains.length > 0) {
      return html`<div class="domain-meta domain-error" data-domain-error role="alert">${t('options.autofill.blockedDomainsInvalid', { domains: this.invalidDomains.join(', ') })}</div>`;
    }
    if (parsed.domains.length === 0) {
      return html`<div class="domain-meta" data-domain-empty>${t('options.autofill.blockedDomainsEmpty')}</div>`;
    }
    return html`
      <div class="domain-meta" data-domain-count>${t('options.autofill.blockedDomainsCount', { count: parsed.domains.length })}</div>
      <ul class="domain-list" data-domain-list>
        ${parsed.domains.map((domain) => html`<li>${domain}</li>`)}
      </ul>
    `;
  }

  private renderSavePromptDomainState() {
    const parsed = parseBlockedDomains(this.savePromptDomainDraft());
    if (this.invalidSavePromptDomains.length > 0) {
      return html`<div class="domain-meta domain-error" data-save-prompt-domain-error role="alert">${t('options.autofill.savePromptExcludedDomainsInvalid', { domains: this.invalidSavePromptDomains.join(', ') })}</div>`;
    }
    if (parsed.domains.length === 0) {
      return html`<div class="domain-meta" data-save-prompt-domain-empty>${t('options.autofill.savePromptExcludedDomainsEmpty')}</div>`;
    }
    return html`
      <div class="domain-meta" data-save-prompt-domain-count>${t('options.autofill.savePromptExcludedDomainsCount', { count: parsed.domains.length })}</div>
      <ul class="domain-list" data-save-prompt-domain-list>
        ${parsed.domains.map((domain) => html`<li>${domain}</li>`)}
      </ul>
    `;
  }

  private renderWebsitePasskeyDomainState() {
    const parsed = parseWebsitePasskeyDomains(this.websitePasskeyDomainDraft());
    if (this.invalidWebsitePasskeyDomains.length > 0) {
      return html`<div class="domain-meta domain-error" data-website-passkey-domain-error role="alert">${t('options.autofill.websitePasskeyExcludedDomainsInvalid', {
        domains: this.invalidWebsitePasskeyDomains.join(', '),
      })}</div>`;
    }
    if (parsed.domains.length === 0) {
      return html`<div class="domain-meta" data-website-passkey-domain-empty>${t('options.autofill.websitePasskeyExcludedDomainsEmpty')}</div>`;
    }
    return html`
      <div class="domain-meta" data-website-passkey-domain-count>${t('options.autofill.websitePasskeyExcludedDomainsCount', { count: parsed.domains.length })}</div>
      <ul class="domain-list" data-website-passkey-domain-list>
        ${parsed.domains.map((domain) => html`<li>${domain}</li>`)}
      </ul>
    `;
  }

  private renderHttpAuthOriginState() {
    const parsed = parseHttpAuthOrigins(this.httpAuthOriginDraft());
    if (this.invalidHttpAuthOrigins.length > 0) {
      return html`<div class="domain-meta domain-error" data-http-auth-origin-error role="alert">${t('options.autofill.httpAuthOriginsInvalid', {
        origins: this.invalidHttpAuthOrigins.join(', '),
      })}</div>`;
    }
    if (parsed.domains.length === 0) {
      return html`<div class="domain-meta" data-http-auth-origin-empty>${t('options.autofill.httpAuthOriginsEmpty')}</div>`;
    }
    return html`
      <div class="domain-meta" data-http-auth-origin-count>${t('options.autofill.httpAuthOriginsCount', { count: parsed.domains.length })}</div>
      <ul class="domain-list" data-http-auth-origin-list>
        ${parsed.domains.map((origin) => html`<li>${origin}</li>`)}
      </ul>
    `;
  }
}

interface ParsedBlockedDomains {
  domains: string[];
  invalid: string[];
}

function parseBlockedDomains(value: string): ParsedBlockedDomains {
  const entries = value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const normalized = normalizeAutofillBlocklist(entries);
  if (normalized.valid) {
    return { domains: normalized.rules.map((rule) => rule.pattern), invalid: [] };
  }
  const invalid = normalized.errors.map((error) => (
    error.index === undefined ? value : (entries[error.index] ?? value)
  ));
  return { domains: [], invalid };
}

function sameDomains(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((domain, index) => domain === right[index]);
}

function parseWebsitePasskeyDomains(value: string): ParsedBlockedDomains {
  const entries = value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (entries.length > MAX_WEBSITE_PASSKEY_EXCLUDED_DOMAINS) {
    return {
      domains: [],
      invalid: entries.slice(MAX_WEBSITE_PASSKEY_EXCLUDED_DOMAINS),
    };
  }
  const canonical = new Set<string>();
  const invalid: string[] = [];
  for (const entry of entries) {
    try {
      canonical.add(canonicalizeWebsitePasskeyHostname(entry));
    } catch {
      invalid.push(entry);
    }
  }
  return invalid.length > 0
    ? { domains: [], invalid }
    : { domains: [...canonical].sort((left, right) => left.localeCompare(right)), invalid: [] };
}

function parseHttpAuthOrigins(value: string): ParsedBlockedDomains {
  const entries = value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (entries.length > MAX_HTTP_AUTH_ORIGINS) {
    return { domains: [], invalid: entries.slice(MAX_HTTP_AUTH_ORIGINS) };
  }
  const canonical = new Set<string>();
  const invalid: string[] = [];
  for (const entry of entries) {
    try {
      canonical.add(canonicalizeHttpAuthOrigin(entry));
    } catch {
      invalid.push(entry);
    }
  }
  return invalid.length > 0
    ? { domains: [], invalid }
    : { domains: [...canonical].sort((left, right) => left.localeCompare(right)), invalid: [] };
}

customElements.define('vw-autofill-section', VwAutofillSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-autofill-section': VwAutofillSection;
  }
}
