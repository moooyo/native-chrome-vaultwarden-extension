import type { sendRequest } from '../../messaging/protocol.js';
import type { UriMatchStrategySetting } from '../../core/vault/uri-match.js';
import type { GeneratorPolicySnapshot } from '../../core/generator/enterprise-password-policy.js';
import type {
  LockTimeoutSetting,
  OnIdleAction,
  ClipboardClearSetting,
  SelectableLockTimeoutSetting,
} from '../../background/settings.js';
import type { StatusTone } from '../components/status-message.js';
import type { EffectiveVaultTimeoutMode } from '../../background/vault-timeout-policy.js';
import type {
  VaultTransferExportFormat,
  VaultTransferImportResultMessage,
  VaultTransferPortPreviewModel,
  VaultTransferRecoveryClearedMessage,
  VaultTransferRecoveryStatus,
} from '../../messaging/vault-transfer-port.js';
import type {
  VaultTransferDownloadArtifact,
  VaultTransferFile,
} from './vault-transfer-client.js';
import type { VaultTransferExportTarget } from '../../core/vault/vault-transfer-target.js';

/** The worker request function every options surface is injected with; never called directly by
 *  the section components — only `VwOptionsApp` performs requests. */
export type OptionsRequest = typeof sendRequest;

/** Browser command metadata needed to render the currently assigned shortcut. */
export interface ShortcutCommand {
  name?: string;
  shortcut?: string;
}

/** Coarse storage signal exposed to the options root without leaking storage values. */
export type SessionChangeKind = 'keyMaterial' | 'account';

/** Minimal transfer-client surface consumed by the options root. */
export interface OptionsVaultTransferClient {
  import(file: VaultTransferFile, password?: string): Promise<VaultTransferPortPreviewModel>;
  confirm(): Promise<VaultTransferImportResultMessage>;
  export(
    format: VaultTransferExportFormat,
    authorizationId: string,
    filePassword?: string,
    target?: VaultTransferExportTarget,
  ): Promise<VaultTransferDownloadArtifact>;
  inspectRecovery(): Promise<VaultTransferRecoveryStatus>;
  clearRecovery(status: VaultTransferRecoveryStatus): Promise<VaultTransferRecoveryClearedMessage>;
  cancel(): void;
  dispose(): void;
}

/**
 * The narrow dependency seam the dormant Lit options root is constructed with. Every side effect
 * the root needs (worker requests, session-change observation, browser commands, host-permission
 * prompts, the privileged transfer client, and the extension version) is injected here so tests can supply
 * fakes instead of touching real browser APIs.
 */
export interface OptionsDeps {
  request: OptionsRequest;
  requestOrigins(origins: string[]): Promise<boolean>;
  createVaultTransferClient(): OptionsVaultTransferClient;
  extensionVersion(): string;
  getCommands(): Promise<ShortcutCommand[]>;
  openShortcutSettings(): Promise<void>;
  subscribeSessionChanges(listener: (kind: SessionChangeKind) => void): () => void;
}

/** The non-secret settings the root loads once from `settings.get` and hands down as props. */
export interface LoadedSettings {
  serverUrl?: string;
  defaultUriMatchStrategy: UriMatchStrategySetting;
  inlineSuggestions: boolean;
  pageLoadFill: boolean;
  pageLoadFillDefault: boolean;
  autoCopyTotp: boolean;
  showMatchingLoginCount: boolean;
  savePromptEnabled: boolean;
  updatePromptEnabled: boolean;
  savePromptExcludedDomains: string[];
  blockedDomains: string[];
  autofillPolicyValid: boolean;
  websitePasskeys: {
    enabled: boolean;
    excludedDomains: string[];
    valid: boolean;
  };
  httpAuth: {
    enabled: boolean;
    allowedOrigins: string[];
    valid: boolean;
  };
  lockTimeout: LockTimeoutSetting;
  onIdleAction: OnIdleAction;
  clipboardClearSeconds: ClipboardClearSetting;
  enterprisePolicy: {
    pinUnlockAllowed: boolean;
    maximumVaultTimeoutManaged: boolean;
    maximumVaultTimeoutMode: EffectiveVaultTimeoutMode;
    uriMatchDefaultManaged: boolean;
    uriMatchDefaultMalformed: boolean;
    activateAutofillManaged: boolean;
  };
  generator: GeneratorPolicySnapshot;
}

/** A section-local status banner the root drives on exactly one section at a time. */
export interface SectionStatus {
  message: string;
  tone: StatusTone;
}

/** The rail sections, in display order. */
export type OptionsSectionId =
  | 'account'
  | 'security'
  | 'autofill'
  | 'generator'
  | 'send'
  | 'appearance'
  | 'data'
  | 'about';

/** `vw-change-password`: a validated master-password change the root performs via `auth.changePassword`. */
export interface ChangePasswordDetail {
  currentPassword: string;
  newPassword: string;
  masterPasswordHint: string;
}

/** `vw-send-create`: a text or file Send the root creates (file variant carries the read bytes). */
export type SendCreateDetail =
  | { kind: 'text'; input: import('../../core/vault/sends.js').SendInput }
  | { kind: 'file'; input: import('../../core/vault/sends.js').SendInput; dataB64: string; fileName: string };

/** `vw-send-delete`: the Send to delete. */
export interface SendDeleteDetail {
  id: string;
}

/** `vw-connection-save`: the already-normalized server URL the root should persist (after it has
 *  requested host permission for the URL's origin). */
export interface ConnectionSaveDetail {
  serverUrl: string;
}

/** `vw-autofill-save`: one complete worker-authoritative autofill policy snapshot. */
export interface AutofillSaveDetail {
  defaultUriMatchStrategy: UriMatchStrategySetting;
  inlineSuggestions: boolean;
  pageLoadFill: boolean;
  pageLoadFillDefault: boolean;
  autoCopyTotp: boolean;
  savePromptEnabled: boolean;
  updatePromptEnabled: boolean;
  savePromptExcludedDomains: string[];
  blockedDomains: string[];
}

/** Display-only toolbar counter preference; independent from autofill authorization policy. */
export interface ToolbarBadgeSaveDetail {
  showMatchingLoginCount: boolean;
}

/** `vw-website-passkey-save`: one complete website-passkey policy snapshot. */
export interface WebsitePasskeySaveDetail {
  enabled: boolean;
  excludedDomains: string[];
}

/** `vw-http-auth-save`: one complete exact-origin HTTP Basic policy snapshot. */
export interface HttpAuthSaveDetail {
  enabled: boolean;
  allowedOrigins: string[];
}

/** `vw-lock-timeout-save`: the chosen automatic lock timeout. */
export interface LockTimeoutSaveDetail {
  lockTimeout: SelectableLockTimeoutSetting;
}

/** `vw-security-save`: the save-on-change idle action and clipboard-clear window. */
export interface SecuritySaveDetail {
  onIdleAction: OnIdleAction;
  clipboardClearSeconds: ClipboardClearSetting;
}

/** `vw-export`: request a vault export in the explicitly selected format. */
export interface ExportDetail {
  format: VaultTransferExportFormat;
  masterPassword: string;
  target: VaultTransferExportTarget;
  /** Required only when format is encrypted-json. */
  encryptionType?: 'account' | 'file';
  filePassword?: string;
}

/** `vw-import-file`: the file the user chose to stream to the privileged transfer worker. */
export interface ImportFileDetail {
  file: File;
}

/** `vw-import-password`: the export password the user supplied for a password-protected import. */
export interface ImportPasswordDetail {
  password: string;
}
