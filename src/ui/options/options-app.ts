import { LitElement, css, html, nothing } from 'lit';
import browser from 'webextension-polyfill';
import { sendRequest } from '../../messaging/protocol.js';
import { WEBSITE_PASSKEY_SCRIPT_MATCHES } from '../../background/website-passkey-script-manager.js';
import { canonicalizeHttpAuthOrigin } from '../../background/http-auth-settings.js';
import {
  canClearVaultTransferRecovery,
  type VaultTransferExportFormat,
  type VaultTransferExportReview,
  type VaultTransferImportResultMessage,
  type VaultTransferPortPreviewModel,
  type VaultTransferRecoveryStatus,
} from '../../messaging/vault-transfer-port.js';
import type { SessionState, AccountSummary } from '../../core/session/session-manager.js';
import type { SendSummary } from '../../core/vault/sends.js';
import type { CollectionSummary } from '../../core/vault/models.js';
import type { OrgPermission } from '../../core/vault/org-permissions.js';
import {
  canonicalizeVaultTransferExportTarget,
  canonicalizeVaultTransferOrganizationId,
  type VaultTransferExportTarget,
} from '../../core/vault/vault-transfer-target.js';
import { isUriMatchStrategySetting, UriMatchStrategy } from '../../core/vault/uri-match.js';
import { isSelectableLockTimeoutSetting } from '../../background/settings.js';
import {
  parseGeneratorPolicySnapshot,
  UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
} from '../../core/generator/enterprise-password-policy.js';
import type { AsyncState } from '../components/async-state.js';
import { initLocale, t } from '../i18n/index.js';
import { initAppearance } from '../theme.js';
import { initPrefs } from '../prefs.js';
import './options-shell.js';
import type { OptionsNavItem } from './options-shell.js';
import './sections/connection-section.js';
import './sections/security-section.js';
import './sections/autofill-section.js';
import './sections/generator-section.js';
import './sections/send-section.js';
import './sections/appearance-section.js';
import './sections/data-section.js';
import type { ExportOrganizationOption } from './sections/data-section.js';
import './sections/about-section.js';
import {
  VaultTransferClient,
  VaultTransferClientError,
  type VaultTransferClientPort,
  type VaultTransferDownloadArtifact,
} from './vault-transfer-client.js';
import type {
  SanitizedImportPreviewDiagnostic,
  SanitizedImportPreviewViewModel,
} from './sections/import-preview.js';
import type {
  AutofillSaveDetail,
  ChangePasswordDetail,
  ConnectionSaveDetail,
  ExportDetail,
  ImportFileDetail,
  ImportPasswordDetail,
  HttpAuthSaveDetail,
  LoadedSettings,
  LockTimeoutSaveDetail,
  OptionsDeps,
  OptionsRequest,
  OptionsVaultTransferClient,
  OptionsSectionId,
  SecuritySaveDetail,
  SectionStatus,
  SendCreateDetail,
  SendDeleteDetail,
  SessionChangeKind,
  ToolbarBadgeSaveDetail,
  WebsitePasskeySaveDetail,
} from './types.js';

const RAIL: OptionsNavItem[] = [
  { id: 'account', labelKey: 'options.nav.account', icon: 'user' },
  { id: 'security', labelKey: 'options.nav.security', icon: 'lock' },
  { id: 'autofill', labelKey: 'options.nav.autofill', icon: 'key' },
  { id: 'generator', labelKey: 'options.nav.generator', icon: 'wand' },
  { id: 'send', labelKey: 'options.nav.send', icon: 'link' },
  { id: 'appearance', labelKey: 'options.nav.appearance', icon: 'sun' },
  { id: 'data', labelKey: 'options.nav.data', icon: 'file' },
  { id: 'about', labelKey: 'options.nav.about', icon: 'alert' },
];

interface QueuedLockTimeoutSave {
  revision: number;
  detail: LockTimeoutSaveDetail;
}

interface QueuedSecuritySave {
  revision: number;
  detail: SecuritySaveDetail;
}

function normalizeLoadedSettings(data: unknown): LoadedSettings {
  const loaded = data as LoadedSettings;
  const uriMatchDefaultValid = isUriMatchStrategySetting(loaded.defaultUriMatchStrategy);
  const policyValid = loaded.autofillPolicyValid === true
    && typeof loaded.inlineSuggestions === 'boolean'
    && typeof loaded.pageLoadFill === 'boolean'
    && typeof loaded.pageLoadFillDefault === 'boolean'
    && typeof loaded.autoCopyTotp === 'boolean'
    && typeof loaded.savePromptEnabled === 'boolean'
    && typeof loaded.updatePromptEnabled === 'boolean'
    && Array.isArray(loaded.savePromptExcludedDomains)
    && loaded.savePromptExcludedDomains.every((domain) => typeof domain === 'string')
    && Array.isArray(loaded.blockedDomains)
    && loaded.blockedDomains.every((domain) => typeof domain === 'string');
  const blockedDomains = policyValid
    && Array.isArray(loaded.blockedDomains)
    && loaded.blockedDomains.every((domain) => typeof domain === 'string')
    ? [...loaded.blockedDomains]
    : [];
  const websitePasskeyState = loaded.websitePasskeys;
  const websitePasskeyValid = websitePasskeyState?.valid === true
    && typeof websitePasskeyState.enabled === 'boolean'
    && Array.isArray(websitePasskeyState.excludedDomains)
    && websitePasskeyState.excludedDomains.every((domain) => typeof domain === 'string');
  return {
    ...loaded,
    defaultUriMatchStrategy: uriMatchDefaultValid
      ? loaded.defaultUriMatchStrategy
      : UriMatchStrategy.Never,
    inlineSuggestions: policyValid && typeof loaded.inlineSuggestions === 'boolean'
      ? loaded.inlineSuggestions
      : false,
    pageLoadFill: policyValid && typeof loaded.pageLoadFill === 'boolean'
      ? loaded.pageLoadFill
      : false,
    pageLoadFillDefault: policyValid && typeof loaded.pageLoadFillDefault === 'boolean'
      ? loaded.pageLoadFillDefault
      : false,
    autoCopyTotp: policyValid && typeof loaded.autoCopyTotp === 'boolean'
      ? loaded.autoCopyTotp
      : false,
    showMatchingLoginCount: typeof loaded.showMatchingLoginCount === 'boolean'
      ? loaded.showMatchingLoginCount
      : true,
    savePromptEnabled: policyValid ? loaded.savePromptEnabled : false,
    updatePromptEnabled: policyValid ? loaded.updatePromptEnabled : false,
    savePromptExcludedDomains: policyValid ? [...loaded.savePromptExcludedDomains] : [],
    blockedDomains,
    autofillPolicyValid: policyValid,
    websitePasskeys: websitePasskeyValid
      ? {
          enabled: websitePasskeyState.enabled,
          excludedDomains: [...websitePasskeyState.excludedDomains],
          valid: true,
        }
      : { enabled: false, excludedDomains: [], valid: false },
    httpAuth: loaded.httpAuth?.valid === true
      && typeof loaded.httpAuth.enabled === 'boolean'
      && Array.isArray(loaded.httpAuth.allowedOrigins)
      && loaded.httpAuth.allowedOrigins.every((origin) => typeof origin === 'string')
      ? {
          enabled: loaded.httpAuth.enabled,
          allowedOrigins: [...loaded.httpAuth.allowedOrigins],
          valid: true,
        }
      : { enabled: false, allowedOrigins: [], valid: false },
    enterprisePolicy: {
      pinUnlockAllowed: loaded.enterprisePolicy?.pinUnlockAllowed !== false,
      maximumVaultTimeoutManaged: loaded.enterprisePolicy?.maximumVaultTimeoutManaged === true,
      maximumVaultTimeoutMode: loaded.enterprisePolicy?.maximumVaultTimeoutMode === 'systemLock'
        || loaded.enterprisePolicy?.maximumVaultTimeoutMode === 'immediate'
        ? loaded.enterprisePolicy.maximumVaultTimeoutMode
        : 'local',
      uriMatchDefaultManaged: loaded.enterprisePolicy?.uriMatchDefaultManaged === true,
      uriMatchDefaultMalformed: loaded.enterprisePolicy?.uriMatchDefaultMalformed === true
        || !uriMatchDefaultValid,
      activateAutofillManaged: loaded.enterprisePolicy?.activateAutofillManaged === true,
    },
    generator: parseGeneratorPolicySnapshot(loaded.generator)
      ?? UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
  };
}

function createDefaultDeps(): OptionsDeps {
  return {
    request: sendRequest,
    getCommands: () => browser.commands.getAll(),
    async openShortcutSettings() {
      await browser.tabs.create({ url: 'chrome://extensions/shortcuts' });
    },
    subscribeSessionChanges(listener) {
      const onChanged = (changes: Record<string, unknown>, areaName: string): void => {
        const sessionKeyChanged = areaName === 'session' && (
          Object.prototype.hasOwnProperty.call(changes, 'sessionSecrets')
          || Object.prototype.hasOwnProperty.call(changes, 'userKey')
        );
        const accountChanged = areaName === 'local'
          && activeAccountIdentityChanged(changes.auth);
        if (sessionKeyChanged) listener('keyMaterial');
        else if (accountChanged) listener('account');
      };
      browser.storage.onChanged.addListener(onChanged);
      return () => browser.storage.onChanged.removeListener(onChanged);
    },
    async requestOrigins(origins) {
      return browser.permissions.request({ origins });
    },
    createVaultTransferClient() {
      return new VaultTransferClient({
        connectPort(name) {
          return browser.runtime.connect({ name }) as unknown as VaultTransferClientPort;
        },
        readSlice(slice) {
          return slice.arrayBuffer();
        },
        download: downloadVaultTransferArtifact,
        confirmExportReview: confirmVaultTransferExportReview,
        ackClientEvent: async (ackId) => {
          await sendRequest({ type: 'clientEvent.ack', ackId });
        },
      });
    },
    extensionVersion() {
      return browser.runtime.getManifest().version;
    },
  };
}

function activeAccountIdentityChanged(change: unknown): boolean {
  if (typeof change !== 'object' || change === null || Array.isArray(change)) return false;
  const record = change as Record<string, unknown>;
  return storedAuthIdentity(record.oldValue) !== storedAuthIdentity(record.newValue);
}

function storedAuthIdentity(value: unknown): string {
  if (value === undefined) return 'absent';
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return 'invalid';
  const email = (value as Record<string, unknown>).email;
  return typeof email === 'string' && email.trim().length > 0
    ? `email:${email.trim().toLowerCase()}`
    : 'invalid';
}

function downloadVaultTransferArtifact(artifact: VaultTransferDownloadArtifact): void {
  const url = URL.createObjectURL(artifact.blob);
  const anchor = document.createElement('a');
  try {
    anchor.href = url;
    anchor.download = safeVaultTransferFileName(artifact.fileName, artifact.format);
    document.body.appendChild(anchor);
    anchor.click();
  } finally {
    anchor.remove();
    URL.revokeObjectURL(url);
  }
}

function confirmVaultTransferExportReview(review: VaultTransferExportReview): boolean {
  const warningCount = review.warnings.reduce((total, warning) => total + warning.count, 0);
  return window.confirm(t('options.data.exportCsvReviewConfirm', {
    exported: review.exportedItemCount,
    omitted: review.omittedItemCount,
    warnings: warningCount,
  }));
}

function safeVaultTransferFileName(fileName: string, format: VaultTransferExportFormat): string {
  const fallback = format === 'zip'
    ? 'miyu-vault.zip'
    : format === 'csv' ? 'miyu-vault.csv' : 'miyu-vault.json';
  const expectedSuffix = format === 'zip' ? '.zip' : format === 'csv' ? '.csv' : '.json';
  if (
    typeof fileName !== 'string'
    || fileName.length < 1
    || fileName.length > 255
    || /[<>:"/\\|?*]/.test(fileName)
    || hasUnsafeFileNameCodeUnit(fileName)
    || /[. ]$/.test(fileName)
    || fileName.includes('..')
    || !fileName.toLowerCase().endsWith(expectedSuffix)
  ) {
    return fallback;
  }
  const stem = fileName.split('.')[0]?.toUpperCase() ?? '';
  if (/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/.test(stem)) return fallback;
  return fileName;
}

function exportAuthorizationId(data: unknown): string | undefined {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return undefined;
  const record = data as Record<string, unknown>;
  if (
    typeof record.authorizationId !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(record.authorizationId)
    || typeof record.expiresAt !== 'number'
    || !Number.isFinite(record.expiresAt)
    || record.expiresAt < 0
  ) return undefined;
  return record.authorizationId;
}

function exportOrganizationOptions(data: unknown): readonly ExportOrganizationOption[] {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return [];
  const listing = data as { collections?: unknown; orgPermissions?: unknown };
  if (!Array.isArray(listing.collections) || !Array.isArray(listing.orgPermissions)) return [];
  const managed = new Set<string>();
  for (const candidate of listing.collections as CollectionSummary[]) {
    if (!candidate || candidate.manage !== true) continue;
    try {
      managed.add(canonicalizeVaultTransferOrganizationId(candidate.organizationId));
    } catch {
      // Invalid worker projections are ignored rather than becoming organization authority.
    }
  }
  const byId = new Map<string, ExportOrganizationOption>();
  for (const candidate of listing.orgPermissions as OrgPermission[]) {
    if (!candidate || candidate.isMember !== true || typeof candidate.name !== 'string'
      || candidate.name.length === 0) continue;
    try {
      const id = canonicalizeVaultTransferOrganizationId(candidate.id);
      if (managed.has(id) && !byId.has(id)) {
        byId.set(id, Object.freeze({ id, name: candidate.name }));
      }
    } catch {
      // Invalid worker projections are ignored rather than becoming organization authority.
    }
  }
  return Object.freeze([...byId.values()].sort((left, right) => (
    left.name.localeCompare(right.name) || left.id.localeCompare(right.id)
  )));
}

function hasUnsafeFileNameCodeUnit(fileName: string): boolean {
  for (let index = 0; index < fileName.length; index += 1) {
    const codeUnit = fileName.charCodeAt(index);
    if (codeUnit <= 0x1f || codeUnit === 0x7f) return true;
  }
  return false;
}

function toImportPreviewModel(preview: VaultTransferPortPreviewModel): SanitizedImportPreviewViewModel {
  return {
    format: preview.format === 'csv'
      ? 'bitwarden-csv'
      : (preview.format === 'zip'
          ? 'bitwarden-zip'
          : (preview.format === 'encrypted-json'
              ? 'bitwarden-encrypted-json'
              : 'bitwarden-json')),
    scope: preview.scope,
    counts: {
      folders: preview.counts.folders,
      collections: preview.counts.collections,
      items: preview.counts.items,
      attachments: preview.counts.attachments,
    },
    diagnostics: {
      errors: toImportPreviewDiagnostics(preview.diagnostics.errors),
      warnings: toImportPreviewDiagnostics(preview.diagnostics.warnings),
      unsupported: toImportPreviewDiagnostics(preview.diagnostics.unsupported),
    },
    organizationTargetRequired: preview.organizationTargetRequired,
    hasUnknownOutcome: preview.hasUnknownOutcome,
    canCommit: preview.canCommit,
  };
}

function toImportPreviewDiagnostics(
  diagnostics: VaultTransferPortPreviewModel['diagnostics']['errors'],
): SanitizedImportPreviewDiagnostic[] {
  return diagnostics.map(({ code, count }) => ({ code, count, message: '' }));
}

/**
 * The MiYu options root. Owns loaded settings, the active section, vault lock state, the blocking
 * action `pending` flag, coalesced security-setting saves, per-section status banners, the Sends
 * list, and the account identity for the sidebar. Performs every worker request via the injectable
 * `deps` and hands plain props to the section components, reacting to their typed events.
 * Appearance and generator defaults are managed by their sections through the UI-local
 * appearance/prefs modules.
 *
 * Connection/account and website-passkey enablement can lead to host-permission prompts. Their
 * handlers request the exact origins synchronously in the user gesture as the first await before
 * persisting any setting that depends on the grant.
 */
export class VwOptionsApp extends LitElement {
  static override properties = {
    selected: { type: String },
    settings: { attribute: false },
    locked: { type: Boolean },
    pending: { type: Boolean },
    awaitingImportPassword: { type: Boolean },
    importPreview: { attribute: false },
    transferRecoveryStatus: { attribute: false },
    transferRecoveryPending: { type: Boolean },
    transferRecoveryUnavailable: { type: Boolean },
    connectionStatus: { attribute: false },
    securityStatus: { attribute: false },
    autofillStatus: { attribute: false },
    websitePasskeyPending: { type: Boolean },
    httpAuthPending: { type: Boolean },
    dataStatus: { attribute: false },
    sendsState: { attribute: false },
    sendStatus: { attribute: false },
    accountEmail: { type: String },
    accountName: { type: String },
    autofillShortcut: { type: String },
    lastSync: { type: Number },
    syncing: { type: Boolean },
    policyRefreshPending: { type: Boolean },
    exportOrganizations: { attribute: false },
  };

  declare selected: OptionsSectionId;
  declare settings: LoadedSettings | undefined;
  declare locked: boolean;
  declare pending: boolean;
  declare awaitingImportPassword: boolean;
  declare importPreview: SanitizedImportPreviewViewModel | undefined;
  declare transferRecoveryStatus: VaultTransferRecoveryStatus | undefined;
  declare transferRecoveryPending: boolean;
  declare transferRecoveryUnavailable: boolean;
  declare connectionStatus: SectionStatus | undefined;
  declare securityStatus: SectionStatus | undefined;
  declare autofillStatus: SectionStatus | undefined;
  declare websitePasskeyPending: boolean;
  declare httpAuthPending: boolean;
  declare dataStatus: SectionStatus | undefined;
  declare sendsState: AsyncState<SendSummary[]>;
  declare sendStatus: SectionStatus | undefined;
  declare accountEmail: string;
  declare accountName: string;
  declare autofillShortcut: string;
  declare lastSync: number | undefined;
  declare syncing: boolean;
  declare policyRefreshPending: boolean;
  declare exportOrganizations: readonly ExportOrganizationOption[];

  deps: OptionsDeps = createDefaultDeps();

  private selectedImportFile: File | undefined;
  private vaultTransferClient: OptionsVaultTransferClient | undefined;
  private vaultTransferRecoveryClient: OptionsVaultTransferClient | undefined;
  private transferEpoch = 0;
  private transferPending = false;
  private recoveryEpoch = 0;
  private sendStatusEpoch = 0;
  private sessionState: SessionState = 'locked';
  private sessionEpoch = 0;
  private sessionRefreshSeq = 0;
  private accountIdentityRefreshSeq = 0;
  private settingsRefreshSeq = 0;
  private exportOrganizationsRefreshSeq = 0;
  private unsubscribeSessionChanges: (() => void) | undefined;
  private securityStatusRevision = 0;
  private queuedLockTimeoutSave: QueuedLockTimeoutSave | undefined;
  private lockTimeoutSaveRunning = false;
  private queuedSecuritySave: QueuedSecuritySave | undefined;
  private securitySaveRunning = false;
  private websitePasskeyGeneration = 0;
  private httpAuthGeneration = 0;

  constructor() {
    super();
    this.selected = 'account';
    this.settings = undefined;
    this.locked = true;
    this.pending = false;
    this.awaitingImportPassword = false;
    this.importPreview = undefined;
    this.transferRecoveryStatus = undefined;
    this.transferRecoveryPending = false;
    this.transferRecoveryUnavailable = false;
    this.connectionStatus = undefined;
    this.securityStatus = undefined;
    this.autofillStatus = undefined;
    this.websitePasskeyPending = false;
    this.httpAuthPending = false;
    this.dataStatus = undefined;
    this.sendsState = { status: 'idle' };
    this.sendStatus = undefined;
    this.accountEmail = '';
    this.accountName = '';
    this.autofillShortcut = '';
    this.lastSync = undefined;
    this.syncing = false;
    this.policyRefreshPending = true;
    this.exportOrganizations = [];
    this.selectedImportFile = undefined;
  }

  static override styles = css`
    :host { display: block; min-height: 100vh; }
  `;

  override connectedCallback(): void {
    super.connectedCallback();
    browser.runtime.onMessage.addListener(this.handleEnterprisePolicyClientChanged);
    this.unsubscribeSessionChanges = this.deps.subscribeSessionChanges((kind) => this.handleSessionChange(kind));
    window.addEventListener('focus', this.handleWindowFocus);
    void this.bootstrap();
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.unsubscribeSessionChanges?.();
    this.unsubscribeSessionChanges = undefined;
    window.removeEventListener('focus', this.handleWindowFocus);
    browser.runtime.onMessage.removeListener(this.handleEnterprisePolicyClientChanged);
    this.sessionRefreshSeq += 1;
    this.accountIdentityRefreshSeq += 1;
    this.settingsRefreshSeq += 1;
    this.exportOrganizationsRefreshSeq += 1;
    this.websitePasskeyGeneration += 1;
    this.websitePasskeyPending = false;
    this.httpAuthGeneration += 1;
    this.httpAuthPending = false;
    this.invalidateVaultTransfer();
    this.applySessionState('locked');
  }

  private readonly handleWindowFocus = (): void => {
    this.scheduleSessionAndAccountRefresh();
    void this.refreshSettings();
    void this.refreshShortcut();
  };

  private handleSessionChange(kind: SessionChangeKind): void {
    this.revokeCachedEnterprisePolicy();
    void this.refreshSettings();
    if (kind === 'keyMaterial') {
      this.sessionEpoch += 1;
      this.locked = true;
      this.clearSessionSensitiveState();
      this.scheduleSessionAndAccountRefresh();
      return;
    }
    this.sessionEpoch += 1;
    this.locked = true;
    this.clearSessionSensitiveState();
    this.transferRecoveryUnavailable = true;
    this.accountEmail = '';
    this.accountName = '';
    this.scheduleSessionAndAccountRefresh();
  }

  private async bootstrap(): Promise<void> {
    await Promise.all([initLocale(), initAppearance(), initPrefs()]);
    await this.init();
  }

  private async init(): Promise<void> {
    const accountSeq = ++this.accountIdentityRefreshSeq;
    const state = await this.refreshSessionState(true);
    await this.refreshSettings();
    if (accountSeq === this.accountIdentityRefreshSeq) {
      const identityCurrent = await this.refreshAccountIdentity(accountSeq);
      if (accountSeq === this.accountIdentityRefreshSeq && state === 'unlocked') {
        if (identityCurrent) {
          const wasLocked = this.locked;
          this.applySessionState('unlocked');
          if (wasLocked && !this.locked) void this.loadSends();
          if (this.selected === 'data') {
            void this.refreshVaultTransferRecovery();
            void this.loadExportOrganizations();
          }
        } else {
          this.applySessionState('locked');
        }
      }
    }
    await this.refreshShortcut();
  }

  private applySessionState(state: SessionState): void {
    const changed = state !== this.sessionState;
    if (changed) {
      this.sessionState = state;
      this.sessionEpoch += 1;
    }
    this.locked = state !== 'unlocked';
    if (state === 'unlocked') {
      if (changed && this.selected === 'data') {
        void this.refreshVaultTransferRecovery();
        void this.loadExportOrganizations();
      }
      return;
    }
    this.clearSessionSensitiveState();
    if (state === 'loggedOut') {
      this.accountEmail = '';
      this.accountName = '';
    }
  }

  private readonly handleEnterprisePolicyClientChanged = (message: unknown): void => {
    if (
      typeof message !== 'object'
      || message === null
      || Array.isArray(message)
      || Object.keys(message).length !== 2
      || !Object.hasOwn(message, 'type')
      || !Object.hasOwn(message, 'phase')
      || (message as { type?: unknown }).type !== 'enterprisePolicy.clientChanged'
    ) return;
    const phase = (message as { phase?: unknown }).phase;
    if (phase !== 'revoke' && phase !== 'refresh') return;
    this.revokeCachedEnterprisePolicy();
    if (phase === 'refresh') void this.refreshSettings();
  };

  private revokeCachedEnterprisePolicy(): void {
    this.settingsRefreshSeq += 1;
    this.policyRefreshPending = true;
    if (this.settings) {
      this.settings = {
        ...this.settings,
        generator: UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
      };
    }
  }

  private async refreshSettings(): Promise<boolean> {
    const sequence = ++this.settingsRefreshSeq;
    this.policyRefreshPending = true;
    let response: Awaited<ReturnType<OptionsRequest>>;
    try {
      response = await this.deps.request({ type: 'settings.get' });
    } catch {
      return false;
    }
    if (!this.isConnected || sequence !== this.settingsRefreshSeq || !response.ok) return false;
    this.settings = normalizeLoadedSettings(response.data);
    this.policyRefreshPending = false;
    return true;
  }

  private clearSessionSensitiveState(): void {
    this.sendStatusEpoch += 1;
    this.sendsState = { status: 'idle' };
    this.sendStatus = undefined;
    this.invalidateVaultTransfer();
    this.dataStatus = undefined;
    this.exportOrganizationsRefreshSeq += 1;
    this.exportOrganizations = [];
  }

  private isCurrentUnlockedEpoch(epoch: number): boolean {
    return !this.locked && epoch === this.sessionEpoch;
  }

  private isLoggedOut(): boolean {
    return this.sessionState === 'loggedOut';
  }

  private async refreshSessionState(deferUnlocked = false): Promise<SessionState | undefined> {
    const seq = ++this.sessionRefreshSeq;
    const wasLocked = this.locked;
    const response = await this.deps.request({ type: 'auth.getState' });
    if (seq !== this.sessionRefreshSeq) return undefined;
    if (!response.ok) {
      this.applySessionState('locked');
      return undefined;
    }
    const state = (response.data as { state: SessionState }).state;
    if (deferUnlocked && state === 'unlocked') return state;
    this.applySessionState(state);
    if (wasLocked && !this.locked) {
      void this.loadSends();
      if (this.selected === 'data') {
        void this.refreshVaultTransferRecovery();
        void this.loadExportOrganizations();
      }
    }
    return state;
  }

  private scheduleSessionAndAccountRefresh(): void {
    const seq = ++this.accountIdentityRefreshSeq;
    void this.refreshSessionAndAccountIdentity(seq);
  }

  private async refreshSessionAndAccountIdentity(seq: number): Promise<void> {
    const state = await this.refreshSessionState(true);
    if (seq !== this.accountIdentityRefreshSeq || state === undefined) return;
    const sessionEpoch = this.sessionEpoch;
    const identityCurrent = await this.refreshAccountIdentity(seq);
    if (!identityCurrent) return;
    if (seq !== this.accountIdentityRefreshSeq || sessionEpoch !== this.sessionEpoch) return;
    if (state !== 'unlocked') return;
    const wasLocked = this.locked;
    this.applySessionState('unlocked');
    if (wasLocked && !this.locked) void this.loadSends();
    if (this.selected === 'data') {
      void this.refreshVaultTransferRecovery();
      void this.loadExportOrganizations();
    }
  }

  private async refreshAccountIdentity(seq = ++this.accountIdentityRefreshSeq): Promise<boolean> {
    if (seq !== this.accountIdentityRefreshSeq) return false;
    if (this.isLoggedOut()) {
      this.accountEmail = '';
      this.accountName = '';
      return true;
    }
    const epoch = this.sessionEpoch;
    const response = await this.deps.request({ type: 'auth.listAccounts' });
    if (seq !== this.accountIdentityRefreshSeq || epoch !== this.sessionEpoch || this.isLoggedOut()) {
      return false;
    }
    if (!response.ok) return false;
    const accounts = (response.data as { accounts?: Array<AccountSummary & { name?: string }> } | null)?.accounts ?? [];
    const active = accounts.find((account) => account.active);
    if (!active || typeof active.email !== 'string' || active.email.length < 1) return false;
    this.accountEmail = active.email;
    this.accountName = active.name ?? '';
    return true;
  }

  private async refreshShortcut(): Promise<void> {
    try {
      const commands = await this.deps.getCommands();
      this.autofillShortcut = commands.find((command) => command.name === 'autofill-focused')?.shortcut ?? '';
    } catch {
      this.autofillShortcut = '';
    }
  }

  private async loadExportOrganizations(): Promise<void> {
    const sequence = ++this.exportOrganizationsRefreshSeq;
    const sessionEpoch = this.sessionEpoch;
    if (!this.isCurrentUnlockedEpoch(sessionEpoch)) return;
    let response: Awaited<ReturnType<OptionsRequest>>;
    try {
      response = await this.deps.request({ type: 'vault.listItems' });
    } catch {
      if (sequence === this.exportOrganizationsRefreshSeq
        && this.isCurrentUnlockedEpoch(sessionEpoch)) this.exportOrganizations = [];
      return;
    }
    if (sequence !== this.exportOrganizationsRefreshSeq
      || !this.isCurrentUnlockedEpoch(sessionEpoch)) return;
    this.exportOrganizations = response.ok ? exportOrganizationOptions(response.data) : [];
  }

  private async handleShortcutChange(): Promise<void> {
    try {
      await this.deps.openShortcutSettings();
    } catch {
      this.autofillStatus = { message: t('common.error'), tone: 'danger' };
    }
  }

  private onNav(event: CustomEvent<{ id: string }>): void {
    const id = event.detail.id;
    if (!RAIL.some((item) => item.id === id)) return;
    if (this.selected === 'send' && id !== 'send'
      && !(this.renderRoot.querySelector('vw-send-section')?.promptForUnsavedEdits() ?? true)) return;
    this.selected = id as OptionsSectionId;
    if (this.selected === 'data' && !this.locked) {
      void this.refreshVaultTransferRecovery();
      void this.loadExportOrganizations();
    }
  }

  // --- account & sync ------------------------------------------------------------------------
  private async handleConnectionSave(event: CustomEvent<ConnectionSaveDetail>): Promise<void> {
    if (this.pending) return;
    const serverUrl = event.detail.serverUrl;
    const originPattern = `${new URL(serverUrl).origin}/*`;
    this.pending = true;
    this.connectionStatus = undefined;
    try {
      const granted = await this.deps.requestOrigins([originPattern]);
      if (!granted) {
        this.connectionStatus = { message: t('common.error'), tone: 'danger' };
        return;
      }
      const response = await this.deps.request({ type: 'settings.save', serverUrl });
      if (!response.ok) {
        this.connectionStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      if (this.settings) this.settings = { ...this.settings, serverUrl };
      this.connectionStatus = { message: t('common.done'), tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private async handleSync(): Promise<void> {
    if (this.locked || this.syncing) return;
    this.syncing = true;
    try {
      const response = await this.deps.request({ type: 'vault.sync' });
      if (response.ok) {
        this.lastSync = Date.now();
        await this.refreshSettings();
        if (this.selected === 'data') void this.loadExportOrganizations();
      }
      else this.connectionStatus = { message: response.error.message, tone: 'danger' };
    } finally {
      this.syncing = false;
    }
  }

  // --- security ------------------------------------------------------------------------------
  private async handleAutofillSave(event: CustomEvent<AutofillSaveDetail>): Promise<void> {
    if (this.locked || this.pending || this.policyRefreshPending) return;
    const serverUrl = this.settings?.serverUrl;
    const uriMatchDefaultManaged = this.settings?.enterprisePolicy.uriMatchDefaultManaged === true;
    const activateAutofillManaged = this.settings?.enterprisePolicy.activateAutofillManaged === true;
    this.pending = true;
    this.autofillStatus = undefined;
    try {
      const response = await this.deps.request({
        type: 'settings.save',
        ...(serverUrl === undefined ? {} : { serverUrl }),
        ...(uriMatchDefaultManaged
          ? {}
          : { defaultUriMatchStrategy: event.detail.defaultUriMatchStrategy }),
        autofillSettings: {
           inlineSuggestions: event.detail.inlineSuggestions,
           pageLoadFill: activateAutofillManaged
             ? this.settings?.pageLoadFill ?? false
             : event.detail.pageLoadFill,
           pageLoadFillDefault: event.detail.pageLoadFillDefault,
           autoCopyTotp: event.detail.autoCopyTotp,
           savePromptEnabled: event.detail.savePromptEnabled,
           updatePromptEnabled: event.detail.updatePromptEnabled,
           savePromptExcludedDomains: event.detail.savePromptExcludedDomains,
           blockedDomains: event.detail.blockedDomains,
        },
      });
      if (!response.ok) {
        this.autofillStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      await this.refreshSettings();
      this.autofillStatus = { message: t('common.done'), tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private handleLockTimeoutSave(event: CustomEvent<LockTimeoutSaveDetail>): void {
    if (this.settings?.enterprisePolicy.maximumVaultTimeoutManaged === true) return;
    if (!isSelectableLockTimeoutSetting(event.detail.lockTimeout)) return;
    const revision = ++this.securityStatusRevision;
    const detail = { ...event.detail };
    this.securityStatus = undefined;
    if (this.settings) this.settings = { ...this.settings, lockTimeout: detail.lockTimeout };
    this.queuedLockTimeoutSave = { revision, detail };
    void this.flushLockTimeoutSaves();
  }

  private async handleToolbarBadgeSave(event: CustomEvent<ToolbarBadgeSaveDetail>): Promise<void> {
    if (this.locked || this.pending || typeof event.detail.showMatchingLoginCount !== 'boolean') return;
    this.pending = true;
    this.autofillStatus = undefined;
    try {
      const response = await this.deps.request({
        type: 'settings.save',
        showMatchingLoginCount: event.detail.showMatchingLoginCount,
      });
      if (!response.ok) {
        this.autofillStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      await this.refreshSettings();
      this.autofillStatus = { message: t('common.done'), tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  private async handleWebsitePasskeySave(
    event: CustomEvent<WebsitePasskeySaveDetail>,
  ): Promise<void> {
    const detail = event.detail;
    const generation = ++this.websitePasskeyGeneration;
    const wasEnabled = this.settings?.websitePasskeys.enabled === true;
    this.websitePasskeyPending = true;
    this.autofillStatus = undefined;
    try {
      if (!wasEnabled && detail.enabled === true) {
        let granted: boolean;
        try {
          granted = await this.deps.requestOrigins([...WEBSITE_PASSKEY_SCRIPT_MATCHES]);
        } catch {
          if (generation === this.websitePasskeyGeneration) {
            this.autofillStatus = {
              message: t('options.autofill.websitePasskeyPermissionError'),
              tone: 'danger',
            };
          }
          return;
        }
        if (generation !== this.websitePasskeyGeneration) return;
        if (!granted) {
          this.autofillStatus = {
            message: t('options.autofill.websitePasskeyPermissionDenied'),
            tone: 'danger',
          };
          return;
        }
      }
      if (generation !== this.websitePasskeyGeneration) return;
      const response = await this.deps.request({
        type: 'settings.saveWebsitePasskeys',
        enabled: detail.enabled,
        excludedDomains: [...detail.excludedDomains],
      });
      if (generation !== this.websitePasskeyGeneration) return;
      if (!response.ok) {
        this.autofillStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      if (this.settings) {
        this.settings = {
          ...this.settings,
          websitePasskeys: {
            enabled: detail.enabled,
            excludedDomains: [...detail.excludedDomains],
            valid: true,
          },
        };
      }
      this.autofillStatus = {
        message: t('options.autofill.websitePasskeySaved'),
        tone: 'success',
      };
    } finally {
      if (generation === this.websitePasskeyGeneration) this.websitePasskeyPending = false;
    }
  }

  private async handleHttpAuthSave(event: CustomEvent<HttpAuthSaveDetail>): Promise<void> {
    const detail = event.detail;
    const generation = ++this.httpAuthGeneration;
    this.httpAuthPending = true;
    this.autofillStatus = undefined;
    try {
      if (detail.enabled) {
        let permissionOrigins: string[];
        try {
          permissionOrigins = detail.allowedOrigins.map((origin) => (
            `${canonicalizeHttpAuthOrigin(origin)}/*`
          ));
        } catch {
          this.autofillStatus = {
            message: t('options.autofill.httpAuthPermissionDenied'),
            tone: 'danger',
          };
          return;
        }
        let granted = false;
        if (permissionOrigins.length > 0) {
          try {
            granted = await this.deps.requestOrigins(permissionOrigins);
          } catch {
            granted = false;
          }
        }
        if (generation !== this.httpAuthGeneration) return;
        if (!granted) {
          this.autofillStatus = {
            message: t('options.autofill.httpAuthPermissionDenied'),
            tone: 'danger',
          };
          return;
        }
      }
      const response = await this.deps.request({
        type: 'settings.saveHttpAuth',
        enabled: detail.enabled,
        allowedOrigins: [...detail.allowedOrigins],
      });
      if (generation !== this.httpAuthGeneration) return;
      if (!response.ok) {
        this.autofillStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      if (this.settings) {
        this.settings = {
          ...this.settings,
          httpAuth: {
            enabled: detail.enabled,
            allowedOrigins: [...detail.allowedOrigins],
            valid: true,
          },
        };
      }
      this.autofillStatus = {
        message: t('options.autofill.httpAuthSaved'),
        tone: 'success',
      };
    } finally {
      if (generation === this.httpAuthGeneration) this.httpAuthPending = false;
    }
  }

  private async flushLockTimeoutSaves(): Promise<void> {
    if (this.lockTimeoutSaveRunning) return;
    this.lockTimeoutSaveRunning = true;
    try {
      while (this.queuedLockTimeoutSave !== undefined) {
        const save = this.queuedLockTimeoutSave;
        this.queuedLockTimeoutSave = undefined;
        const serverUrl = this.settings?.serverUrl;
        if (serverUrl === undefined) {
          if (save.revision === this.securityStatusRevision) {
            this.securityStatus = { message: t('options.account.serverDesc'), tone: 'danger' };
          }
          continue;
        }
        try {
          const response = await this.deps.request({
            type: 'settings.save',
            serverUrl,
            lockTimeout: save.detail.lockTimeout,
          });
          if (save.revision !== this.securityStatusRevision) continue;
          this.securityStatus = response.ok
            ? { message: t('common.done'), tone: 'success' }
            : { message: response.error.message, tone: 'danger' };
        } catch (error) {
          if (save.revision === this.securityStatusRevision) {
            this.securityStatus = {
              message: error instanceof Error ? error.message : t('common.error'),
              tone: 'danger',
            };
          }
        }
      }
    } finally {
      this.lockTimeoutSaveRunning = false;
    }
  }

  private handleSecuritySave(event: CustomEvent<SecuritySaveDetail>): void {
    if (this.settings?.enterprisePolicy.maximumVaultTimeoutManaged === true
      && event.detail.onIdleAction !== this.settings.onIdleAction) return;
    const revision = ++this.securityStatusRevision;
    const detail = { ...event.detail };
    this.securityStatus = undefined;
    if (this.settings) {
      this.settings = {
        ...this.settings,
        onIdleAction: detail.onIdleAction,
        clipboardClearSeconds: detail.clipboardClearSeconds,
      };
    }
    this.queuedSecuritySave = { revision, detail };
    void this.flushSecuritySaves();
  }

  private async flushSecuritySaves(): Promise<void> {
    if (this.securitySaveRunning) return;
    this.securitySaveRunning = true;
    try {
      while (this.queuedSecuritySave !== undefined) {
        const save = this.queuedSecuritySave;
        this.queuedSecuritySave = undefined;
        try {
          const response = await this.deps.request({
            type: 'settings.saveSecurity',
            onIdleAction: save.detail.onIdleAction,
            clipboardClearSeconds: save.detail.clipboardClearSeconds,
          });
          if (save.revision === this.securityStatusRevision && !response.ok) {
            this.securityStatus = { message: response.error.message, tone: 'danger' };
          }
        } catch (error) {
          if (save.revision === this.securityStatusRevision) {
            this.securityStatus = {
              message: error instanceof Error ? error.message : t('common.error'),
              tone: 'danger',
            };
          }
        }
      }
    } finally {
      this.securitySaveRunning = false;
    }
  }

  private async handleChangePassword(event: CustomEvent<ChangePasswordDetail>): Promise<void> {
    if (this.locked || this.pending) return;
    const revision = ++this.securityStatusRevision;
    this.pending = true;
    this.securityStatus = undefined;
    try {
      const response = await this.deps.request({
        type: 'auth.changePassword',
        currentPassword: event.detail.currentPassword,
        newPassword: event.detail.newPassword,
        masterPasswordHint: event.detail.masterPasswordHint,
      });
      if (!response.ok && response.error.code !== 'outcome_unknown') {
        if (revision === this.securityStatusRevision) {
          this.securityStatus = { message: response.error.message, tone: 'danger' };
        }
        return;
      }
      const accountSeq = ++this.accountIdentityRefreshSeq;
      await this.refreshSessionAndAccountIdentity(accountSeq);
      if (revision === this.securityStatusRevision) {
        this.securityStatus = response.ok
          ? { message: t('common.done'), tone: 'success' }
          : { message: response.error.message, tone: 'danger' };
      }
    } finally {
      this.pending = false;
    }
  }

  // --- Send ----------------------------------------------------------------------------------
  private async loadSends(): Promise<void> {
    if (this.locked) {
      this.sendsState = { status: 'idle' };
      return;
    }
    const epoch = this.sessionEpoch;
    this.sendsState = { status: 'loading' };
    const response = await this.deps.request({ type: 'sends.list' });
    if (!this.isCurrentUnlockedEpoch(epoch)) return;
    if (!response.ok) {
      this.sendsState = { status: 'error', message: response.error.message };
      return;
    }
    const sends = (response.data as { sends?: SendSummary[] } | null)?.sends ?? [];
    this.sendsState = sends.length > 0 ? { status: 'ready', data: sends } : { status: 'empty' };
  }

  private async handleSendCreate(event: CustomEvent<SendCreateDetail>): Promise<void> {
    if (this.locked || this.pending) return;
    const epoch = this.sessionEpoch;
    this.sendStatusEpoch += 1;
    this.pending = true;
    this.sendStatus = undefined;
    try {
      const detail = event.detail;
      const response = detail.kind === 'text'
        ? await this.deps.request({ type: 'sends.createText', input: detail.input })
        : await this.deps.request({ type: 'sends.createFile', input: detail.input, dataB64: detail.dataB64, fileName: detail.fileName });
      if (!this.isCurrentUnlockedEpoch(epoch)) return;
      if (!response.ok) {
        this.sendStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      const send = (response.data as { send?: SendSummary } | null)?.send;
      if (send) {
        const copied = await this.copyToClipboard(send.url);
        if (!this.isCurrentUnlockedEpoch(epoch)) return;
        this.sendStatus = copied
          ? { message: t('send.createdCopied'), tone: 'success' }
          : { message: t('send.createdCopyFailed'), tone: 'warning' };
      } else {
        this.sendStatus = { message: t('send.created'), tone: 'success' };
      }
      await this.loadSends();
    } finally {
      this.pending = false;
    }
  }

  private async handleSendDelete(event: CustomEvent<SendDeleteDetail>): Promise<void> {
    if (this.locked || this.pending) return;
    const epoch = this.sessionEpoch;
    this.sendStatusEpoch += 1;
    this.pending = true;
    try {
      const response = await this.deps.request({ type: 'sends.delete', id: event.detail.id });
      if (!this.isCurrentUnlockedEpoch(epoch)) return;
      if (!response.ok) this.sendStatus = { message: response.error.message, tone: 'danger' };
      else await this.loadSends();
    } finally {
      this.pending = false;
    }
  }

  private async handleCopy(event: CustomEvent<{ value: string }>): Promise<void> {
    if (this.locked) return;
    const epoch = this.sendStatusEpoch;
    const sessionEpoch = this.sessionEpoch;
    const copied = await this.copyToClipboard(event.detail.value);
    if (epoch !== this.sendStatusEpoch || !this.isCurrentUnlockedEpoch(sessionEpoch)) return;
    this.sendStatus = copied
      ? { message: t('options.send.linkCopied'), tone: 'success' }
      : { message: t('common.copyFailed'), tone: 'danger' };
  }

  private async copyToClipboard(value: string): Promise<boolean> {
    try {
      await navigator.clipboard.writeText(value);
      void this.deps.request({ type: 'clipboard.scheduleClear', value });
      return true;
    } catch {
      return false;
    }
  }

  // --- data ----------------------------------------------------------------------------------
  private async refreshVaultTransferRecovery(): Promise<void> {
    if (this.locked || this.selected !== 'data' || this.transferPending
      || this.transferRecoveryPending
      || this.vaultTransferClient !== undefined) return;
    const previous = this.vaultTransferRecoveryClient;
    this.vaultTransferRecoveryClient = undefined;
    try {
      previous?.dispose();
    } catch {
      // A superseded status query has no state worth retaining.
    }

    const sessionEpoch = this.sessionEpoch;
    const recoveryEpoch = ++this.recoveryEpoch;
    this.transferRecoveryPending = true;
    this.transferRecoveryStatus = undefined;
    let client: OptionsVaultTransferClient | undefined;
    try {
      client = this.deps.createVaultTransferClient();
      this.vaultTransferRecoveryClient = client;
      const status = await client.inspectRecovery();
      if (!this.isCurrentRecovery(recoveryEpoch, sessionEpoch)) return;
      this.transferRecoveryStatus = status;
      if (this.transferRecoveryUnavailable) this.dataStatus = undefined;
      this.transferRecoveryUnavailable = false;
    } catch {
      if (!this.isCurrentRecovery(recoveryEpoch, sessionEpoch)) return;
      this.transferRecoveryStatus = undefined;
      this.transferRecoveryUnavailable = true;
      this.dataStatus = { message: t('options.data.recovery.loadFailed'), tone: 'danger' };
    } finally {
      this.releaseVaultTransferRecoveryClient(client);
      if (recoveryEpoch === this.recoveryEpoch) this.transferRecoveryPending = false;
    }
  }

  private async handleTransferRecoveryClear(): Promise<void> {
    const status = this.transferRecoveryStatus;
    if (this.selected !== 'data' || this.locked || this.pending
      || this.transferPending || this.transferRecoveryPending
      || !status || !canClearVaultTransferRecovery(status)) return;
    if (typeof window !== 'undefined'
      && !window.confirm(t('options.data.recovery.finalConfirm'))) return;

    const sessionEpoch = this.sessionEpoch;
    const recoveryEpoch = ++this.recoveryEpoch;
    this.transferRecoveryPending = true;
    let client: OptionsVaultTransferClient | undefined;
    try {
      client = this.deps.createVaultTransferClient();
      this.vaultTransferRecoveryClient = client;
      const result = await client.clearRecovery(status);
      if (!this.isCurrentRecovery(recoveryEpoch, sessionEpoch)) return;
      this.transferRecoveryStatus = undefined;
      this.transferRecoveryUnavailable = false;
      this.dataStatus = {
        message: t('options.data.recovery.cleared', { count: result.cleared }),
        tone: 'success',
      };
    } catch (error) {
      if (!this.isCurrentRecovery(recoveryEpoch, sessionEpoch)) return;
      this.dataStatus = {
        message: error instanceof VaultTransferClientError
          && error.code === 'recovery_not_clearable'
          ? t('options.data.recovery.blocked')
          : t('options.data.recovery.loadFailed'),
        tone: 'danger',
      };
    } finally {
      this.releaseVaultTransferRecoveryClient(client);
      if (recoveryEpoch === this.recoveryEpoch) this.transferRecoveryPending = false;
    }
    if (this.isCurrentRecovery(recoveryEpoch, sessionEpoch)) {
      await this.refreshVaultTransferRecovery();
    }
  }

  private async handleExport(event: CustomEvent<ExportDetail>): Promise<void> {
    if (this.locked || this.pending || this.transferRecoveryPending
      || this.awaitingImportPassword || this.importPreview) return;
    const format = event.detail.format;
    if (format !== 'json' && format !== 'encrypted-json' && format !== 'csv' && format !== 'zip') {
      this.dataStatus = { message: t('options.data.transferError'), tone: 'danger' };
      return;
    }
    let target: VaultTransferExportTarget;
    try {
      target = canonicalizeVaultTransferExportTarget(
        event.detail.target ?? { kind: 'personal' },
      );
    } catch {
      this.dataStatus = { message: t('options.data.transferError'), tone: 'danger' };
      return;
    }
    if ((target.kind === 'organization'
        && !this.exportOrganizations.some((organization) => organization.id === target.organizationId))
      || (target.kind === 'organization' && format === 'zip')) {
      this.dataStatus = { message: t('options.data.transferError'), tone: 'danger' };
      return;
    }
    const encryptionType = event.detail.encryptionType;
    if ((format === 'encrypted-json'
      && encryptionType !== 'account'
      && encryptionType !== 'file')
      || (format !== 'encrypted-json' && encryptionType !== undefined)
      || (encryptionType === 'account' && event.detail.filePassword !== undefined)
      || (encryptionType === 'file'
        && (typeof event.detail.filePassword !== 'string' || event.detail.filePassword.length === 0))) {
      this.dataStatus = { message: t('options.data.transferError'), tone: 'danger' };
      return;
    }
    let masterPassword = event.detail.masterPassword;
    let filePassword = encryptionType === 'file' ? event.detail.filePassword : undefined;
    const sessionEpoch = this.sessionEpoch;
    const transferEpoch = ++this.transferEpoch;
    this.transferPending = true;
    this.pending = true;
    this.dataStatus = { message: t('options.data.exporting'), tone: 'info' };
    let client: OptionsVaultTransferClient | undefined;
    try {
      const authorizationOperation = this.deps.request({
        type: 'vault.authorizeExport',
        format,
        ...(encryptionType ? { encryptionType } : {}),
        target,
        masterPassword,
      });
      event.detail.masterPassword = '';
      if (event.detail.filePassword !== undefined) event.detail.filePassword = '';
      masterPassword = '';
      const authorizationResponse = await authorizationOperation;
      if (!this.isCurrentTransfer(transferEpoch, sessionEpoch)) return;
      if (!authorizationResponse.ok) {
        this.dataStatus = {
          message: t('options.data.exportVerificationFailed'),
          tone: 'danger',
        };
        return;
      }
      const authorizationId = exportAuthorizationId(authorizationResponse.data);
      if (!authorizationId) {
        this.dataStatus = { message: t('options.data.transferError'), tone: 'danger' };
        return;
      }
      client = this.getVaultTransferClient();
      const operation = format === 'encrypted-json' && encryptionType === 'file'
        ? client.export(format, authorizationId, filePassword, target)
        : client.export(format, authorizationId, undefined, target);
      filePassword = undefined;
      const artifact = await operation;
      if (!this.isCurrentTransfer(transferEpoch, sessionEpoch)) return;
      const warningCount = artifact.review?.warnings.reduce(
        (total, warning) => total + warning.count,
        0,
      ) ?? 0;
      this.dataStatus = warningCount > 0
        ? {
            message: t('options.data.exportedWithWarnings', { count: warningCount }),
            tone: 'warning',
          }
        : { message: t('options.data.exported'), tone: 'success' };
    } catch (error) {
      if (this.isCurrentTransfer(transferEpoch, sessionEpoch)) {
        this.dataStatus = this.transferErrorStatus(error);
      }
    } finally {
      this.releaseVaultTransferClient(client);
      this.finishTransferPending(transferEpoch);
    }
  }

  private async handleImportFile(event: CustomEvent<ImportFileDetail>): Promise<void> {
    if (this.locked || this.pending || this.transferRecoveryPending
      || this.transferRecoveryUnavailable
      || (this.transferRecoveryStatus?.count ?? 0) > 0) return;
    this.invalidateVaultTransfer();
    this.selectedImportFile = event.detail.file;
    await this.inspectImportFile(event.detail.file);
  }

  private async handleImportPassword(event: CustomEvent<ImportPasswordDetail>): Promise<void> {
    if (this.locked || this.pending || this.transferRecoveryPending
      || !this.awaitingImportPassword) return;
    const file = this.selectedImportFile;
    if (!file) return;
    const operation = this.inspectImportFile(file, event.detail.password);
    await operation;
  }

  private async inspectImportFile(file: File, password?: string): Promise<void> {
    const sessionEpoch = this.sessionEpoch;
    const transferEpoch = ++this.transferEpoch;
    const usedPassword = password !== undefined;
    this.transferPending = true;
    this.pending = true;
    this.dataStatus = undefined;
    this.awaitingImportPassword = false;
    this.importPreview = undefined;
    try {
      this.dataStatus = { message: t('options.data.inspecting'), tone: 'info' };
      const client = this.getVaultTransferClient();
      const operation = password === undefined ? client.import(file) : client.import(file, password);
      const preview = await operation;
      if (!this.isCurrentTransfer(transferEpoch, sessionEpoch)) return;
      this.selectedImportFile = undefined;
      this.awaitingImportPassword = false;
      this.importPreview = toImportPreviewModel(preview);
      this.dataStatus = undefined;
    } catch (error) {
      if (!this.isCurrentTransfer(transferEpoch, sessionEpoch)) return;
      const code = error instanceof VaultTransferClientError ? error.code : undefined;
      if (code === 'password_required' || (usedPassword && code === 'inspection_failed')) {
        this.awaitingImportPassword = true;
        this.dataStatus = usedPassword
          ? { message: t('options.data.importPasswordInvalid'), tone: 'danger' }
          : { message: t('options.data.importPasswordRequired'), tone: 'info' };
        return;
      }
      this.selectedImportFile = undefined;
      this.awaitingImportPassword = false;
      this.dataStatus = this.transferErrorStatus(error);
    } finally {
      this.finishTransferPending(transferEpoch);
    }
  }

  private async handleImportConfirm(): Promise<void> {
    if (this.locked || this.pending || this.transferRecoveryPending || !this.importPreview) return;
    const client = this.vaultTransferClient;
    if (!client || !this.importPreview.canCommit) return;
    const sessionEpoch = this.sessionEpoch;
    const transferEpoch = ++this.transferEpoch;
    this.transferPending = true;
    this.pending = true;
    this.dataStatus = { message: t('options.data.committing'), tone: 'info' };
    try {
      const result = await client.confirm();
      if (!this.isCurrentTransfer(transferEpoch, sessionEpoch)) return;
      this.importPreview = undefined;
      this.dataStatus = this.importResultStatus(result);
    } catch {
      if (!this.isCurrentTransfer(transferEpoch, sessionEpoch)) return;
      this.importPreview = undefined;
      this.dataStatus = this.importCommitErrorStatus();
    } finally {
      this.releaseVaultTransferClient(client);
      this.finishTransferPending(transferEpoch);
    }
    if (this.isCurrentTransfer(transferEpoch, sessionEpoch)) {
      await this.refreshVaultTransferRecovery();
    }
  }

  private handleImportCancel(): void {
    if (this.transferPending || this.transferRecoveryPending
      || this.transferRecoveryUnavailable
      || (this.transferRecoveryStatus?.count ?? 0) > 0) return;
    this.invalidateVaultTransfer();
    this.dataStatus = { message: t('options.data.cancelled'), tone: 'info' };
  }

  private getVaultTransferClient(): OptionsVaultTransferClient {
    this.vaultTransferClient ??= this.deps.createVaultTransferClient();
    return this.vaultTransferClient;
  }

  private releaseVaultTransferClient(client: OptionsVaultTransferClient | undefined): void {
    if (!client || this.vaultTransferClient !== client) return;
    this.vaultTransferClient = undefined;
    try {
      client.dispose();
    } catch {
      // A terminal transfer client does not need further recovery.
    }
  }

  private releaseVaultTransferRecoveryClient(client: OptionsVaultTransferClient | undefined): void {
    if (!client || this.vaultTransferRecoveryClient !== client) return;
    this.vaultTransferRecoveryClient = undefined;
    try {
      client.dispose();
    } catch {
      // Recovery Port disposal is terminal even when the Port has already closed.
    }
  }

  private invalidateVaultTransferRecovery(): void {
    this.recoveryEpoch += 1;
    const client = this.vaultTransferRecoveryClient;
    this.vaultTransferRecoveryClient = undefined;
    try {
      client?.dispose();
    } catch {
      // Session invalidation is authoritative even if Port disposal reports an error.
    }
    this.transferRecoveryPending = false;
    this.transferRecoveryStatus = undefined;
    this.transferRecoveryUnavailable = false;
  }

  private invalidateVaultTransfer(): void {
    this.invalidateVaultTransferRecovery();
    this.transferEpoch += 1;
    const wasTransferPending = this.transferPending;
    const client = this.vaultTransferClient;
    this.vaultTransferClient = undefined;
    try {
      client?.cancel();
    } catch {
      // Cancellation is best effort after a Port failure.
    }
    try {
      client?.dispose();
    } catch {
      // Disposal is terminal even when the underlying Port is already gone.
    }
    this.transferPending = false;
    if (wasTransferPending) this.pending = false;
    this.awaitingImportPassword = false;
    this.importPreview = undefined;
    this.selectedImportFile = undefined;
  }

  private finishTransferPending(transferEpoch: number): void {
    if (transferEpoch !== this.transferEpoch) return;
    this.transferPending = false;
    this.pending = false;
  }

  private isCurrentTransfer(transferEpoch: number, sessionEpoch: number): boolean {
    return transferEpoch === this.transferEpoch && this.isCurrentUnlockedEpoch(sessionEpoch);
  }

  private isCurrentRecovery(recoveryEpoch: number, sessionEpoch: number): boolean {
    return recoveryEpoch === this.recoveryEpoch
      && this.selected === 'data'
      && this.isCurrentUnlockedEpoch(sessionEpoch);
  }

  private transferErrorStatus(error: unknown): SectionStatus {
    if (!(error instanceof VaultTransferClientError)) {
      return { message: t('options.data.transferError'), tone: 'danger' };
    }
    switch (error.code) {
      case 'lease_changed':
        return { message: t('options.data.sessionChanged'), tone: 'danger' };
      case 'disconnected':
        return { message: t('options.data.disconnected'), tone: 'danger' };
      case 'expired':
      case 'timeout':
        return { message: t('options.data.expired'), tone: 'danger' };
      case 'export_authorization_invalid':
        return { message: t('options.data.exportVerificationFailed'), tone: 'danger' };
      case 'outcome_unknown':
        return { message: t('options.data.result.reconcileRequired'), tone: 'danger' };
      case 'cancelled':
      case 'disposed':
        return { message: t('options.data.cancelled'), tone: 'info' };
      default:
        return { message: t('options.data.transferError'), tone: 'danger' };
    }
  }

  private importCommitErrorStatus(): SectionStatus {
    return { message: t('options.data.result.unconfirmed'), tone: 'danger' };
  }

  private importResultStatus(result: VaultTransferImportResultMessage): SectionStatus {
    const counts = {
      committed: result.counts.committed,
      rejected: result.counts.rejected,
      skipped: result.counts.skipped,
      unknown: result.counts.outcomeUnknown,
    };
    if (result.status === 'completed') {
      return { message: t('options.data.result.completed', counts), tone: 'success' };
    }
    if (result.status === 'outcome_unknown' || result.counts.outcomeUnknown > 0) {
      return {
        message: `${t('options.data.result.unknown', counts)} ${t('options.data.result.reconcileRequired')}`,
        tone: 'danger',
      };
    }
    if (result.status === 'partial') {
      const message = t('options.data.result.partial', counts);
      return {
        message: result.mustSyncBeforeRetry
          ? `${message} ${t('options.data.result.reconcileRequired')}`
          : message,
        tone: 'warning',
      };
    }
    const message = t('options.data.result.blocked', counts);
    return {
      message: result.mustSyncBeforeRetry
        ? `${message} ${t('options.data.result.reconcileRequired')}`
        : message,
      tone: 'danger',
    };
  }

  private async handleDeleteLocal(): Promise<void> {
    if (this.locked || this.pending || this.transferRecoveryPending) return;
    // Removing local data signs the account out on this device; the cloud vault is untouched.
    if (typeof window !== 'undefined' && !window.confirm(t('options.data.deleteLocalDesc'))) return;
    this.pending = true;
    try {
      const response = await this.deps.request({ type: 'auth.logout' });
      if (!response.ok) {
        this.dataStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      this.applySessionState('loggedOut');
      this.dataStatus = { message: t('common.done'), tone: 'success' };
    } finally {
      this.pending = false;
    }
  }

  /** Signs the account out from the sidebar footer control: clears the session on this device and
   *  drops the local account identity. The cloud vault is untouched. Guarded by a confirm, since
   *  re-authenticating a self-hosted vault means re-entering the server URL and credentials. */
  private async handleLogout(): Promise<void> {
    if (this.pending) return;
    if (typeof window !== 'undefined' && !window.confirm(t('options.footer.logoutConfirm'))) return;
    this.pending = true;
    try {
      const response = await this.deps.request({ type: 'auth.logout' });
      if (!response.ok) {
        this.connectionStatus = { message: response.error.message, tone: 'danger' };
        return;
      }
      this.applySessionState('loggedOut');
    } finally {
      this.pending = false;
    }
  }

  private async handleLockNow(): Promise<void> {
    if (this.pending) return;
    const revision = ++this.securityStatusRevision;
    this.pending = true;
    try {
      const response = await this.deps.request({ type: 'auth.lock' });
      if (response.ok) this.applySessionState('locked');
      else if (revision === this.securityStatusRevision) {
        this.securityStatus = { message: response.error.message, tone: 'danger' };
      }
    } finally {
      this.pending = false;
    }
  }

  // --- render --------------------------------------------------------------------------------
  private renderSection() {
    switch (this.selected) {
      case 'account':
        return html`<vw-connection-section
          .serverUrl=${this.settings?.serverUrl ?? ''}
          .accountEmail=${this.accountEmail}
          .accountName=${this.accountName}
          .lastSync=${this.lastSync}
          .syncing=${this.syncing}
          ?pending=${this.pending}
          .status=${this.connectionStatus}
        ></vw-connection-section>`;
      case 'security':
        return html`<vw-security-section
          .lockTimeout=${this.settings?.lockTimeout ?? '15'}
          .onIdleAction=${this.settings?.onIdleAction ?? 'lock'}
          .clipboardClearSeconds=${this.settings?.clipboardClearSeconds ?? '60'}
          .timeoutManaged=${this.settings?.enterprisePolicy.maximumVaultTimeoutManaged ?? false}
          .timeoutMode=${this.settings?.enterprisePolicy.maximumVaultTimeoutMode ?? 'local'}
          .pinUnlockAllowed=${this.settings?.enterprisePolicy.pinUnlockAllowed ?? true}
          ?locked=${this.locked}
          ?pending=${this.pending}
          .status=${this.securityStatus}
        ></vw-security-section>`;
      case 'autofill':
        return html`<vw-autofill-section
          .defaultUriMatchStrategy=${this.settings?.defaultUriMatchStrategy ?? 0}
          .uriMatchDefaultManaged=${this.settings?.enterprisePolicy.uriMatchDefaultManaged ?? false}
          .uriMatchDefaultMalformed=${this.settings?.enterprisePolicy.uriMatchDefaultMalformed ?? false}
           .inlineSuggestions=${this.settings?.inlineSuggestions ?? false}
           .pageLoadFill=${this.settings?.pageLoadFill ?? false}
           .pageLoadFillDefault=${this.settings?.pageLoadFillDefault ?? false}
           .autoCopyTotp=${this.settings?.autoCopyTotp ?? true}
           .showMatchingLoginCount=${this.settings?.showMatchingLoginCount ?? true}
           .activateAutofillManaged=${this.settings?.enterprisePolicy.activateAutofillManaged ?? false}
           .savePromptEnabled=${this.settings?.savePromptEnabled ?? false}
           .updatePromptEnabled=${this.settings?.updatePromptEnabled ?? false}
           .savePromptExcludedDomains=${this.settings?.savePromptExcludedDomains ?? []}
           .blockedDomains=${this.settings?.blockedDomains ?? []}
          .autofillPolicyValid=${this.settings?.autofillPolicyValid ?? false}
          .websitePasskeyEnabled=${this.settings?.websitePasskeys.enabled ?? false}
          .websitePasskeyExcludedDomains=${this.settings?.websitePasskeys.excludedDomains ?? []}
          .websitePasskeyPolicyValid=${this.settings?.websitePasskeys.valid ?? false}
          .websitePasskeyPending=${this.websitePasskeyPending}
          .httpAuthEnabled=${this.settings?.httpAuth.enabled ?? false}
          .httpAuthAllowedOrigins=${this.settings?.httpAuth.allowedOrigins ?? []}
          .httpAuthPolicyValid=${this.settings?.httpAuth.valid ?? false}
          .httpAuthPending=${this.httpAuthPending}
          .shortcut=${this.autofillShortcut}
          ?pending=${this.pending || this.locked || this.policyRefreshPending}
          .status=${this.autofillStatus}
        ></vw-autofill-section>`;
      case 'generator':
        return html`<vw-generator-section></vw-generator-section>`;
      case 'send':
        return html`<vw-send-section
          .sends=${this.sendsState}
          ?locked=${this.locked}
          ?pending=${this.pending}
          .status=${this.sendStatus}
        ></vw-send-section>`;
      case 'appearance':
        return html`<vw-appearance-section></vw-appearance-section>`;
      case 'data':
        return html`<vw-data-section
          ?locked=${this.locked}
          ?pending=${this.pending}
          .exportOrganizations=${this.exportOrganizations}
          .recoveryPending=${this.transferRecoveryPending}
          .recoveryUnavailable=${this.transferRecoveryUnavailable}
          .awaitingImportPassword=${this.awaitingImportPassword}
          .importPreview=${this.importPreview}
          .recoveryStatus=${this.transferRecoveryStatus}
          .status=${this.dataStatus}
        ></vw-data-section>`;
      case 'about':
        return html`<vw-about-section .version=${this.deps.extensionVersion()}></vw-about-section>`;
    }
  }

  protected override render() {
    return html`
      <vw-options-shell
        .items=${RAIL}
        .selected=${this.selected}
        .version=${this.deps.extensionVersion()}
        @vw-nav-change=${(e: CustomEvent<{ id: string }>) => this.onNav(e)}
        @vw-logout=${() => void this.handleLogout()}
        @vw-connection-save=${(e: CustomEvent<ConnectionSaveDetail>) => void this.handleConnectionSave(e)}
        @vw-sync-now=${() => void this.handleSync()}
        @vw-autofill-save=${(e: CustomEvent<AutofillSaveDetail>) => void this.handleAutofillSave(e)}
        @vw-toolbar-badge-save=${(e: CustomEvent<ToolbarBadgeSaveDetail>) => void this.handleToolbarBadgeSave(e)}
        @vw-website-passkey-save=${(e: CustomEvent<WebsitePasskeySaveDetail>) => void this.handleWebsitePasskeySave(e)}
        @vw-http-auth-save=${(e: CustomEvent<HttpAuthSaveDetail>) => void this.handleHttpAuthSave(e)}
        @vw-shortcut-change=${() => void this.handleShortcutChange()}
        @vw-lock-timeout-save=${(e: CustomEvent<LockTimeoutSaveDetail>) => void this.handleLockTimeoutSave(e)}
         @vw-security-save=${(e: CustomEvent<SecuritySaveDetail>) => void this.handleSecuritySave(e)}
         @vw-lock-now=${() => void this.handleLockNow()}
        @vw-change-password=${(e: CustomEvent<ChangePasswordDetail>) => void this.handleChangePassword(e)}
        @vw-send-create=${(e: CustomEvent<SendCreateDetail>) => void this.handleSendCreate(e)}
        @vw-send-delete=${(e: CustomEvent<SendDeleteDetail>) => void this.handleSendDelete(e)}
        @vw-copy=${(e: CustomEvent<{ value: string }>) => void this.handleCopy(e)}
        @vw-export=${(e: CustomEvent<ExportDetail>) => void this.handleExport(e)}
        @vw-import-file=${(e: CustomEvent<ImportFileDetail>) => void this.handleImportFile(e)}
        @vw-import-password=${(e: CustomEvent<ImportPasswordDetail>) => void this.handleImportPassword(e)}
        @vw-import-cancel=${() => this.handleImportCancel()}
        @vw-import-preview-confirm=${() => void this.handleImportConfirm()}
        @vw-import-preview-cancel=${() => this.handleImportCancel()}
        @vw-transfer-recovery-clear=${() => void this.handleTransferRecoveryClear()}
        @vw-delete-local=${() => void this.handleDeleteLocal()}
      >
        ${this.renderSection() ?? nothing}
      </vw-options-shell>
    `;
  }
}

customElements.define('vw-options-app', VwOptionsApp);

declare global {
  interface HTMLElementTagNameMap {
    'vw-options-app': VwOptionsApp;
  }
}
