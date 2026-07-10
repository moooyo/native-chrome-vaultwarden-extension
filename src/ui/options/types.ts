import type { sendRequest } from '../../messaging/protocol.js';
import type { UriMatchStrategySetting } from '../../core/vault/uri-match.js';
import type { LockTimeoutSetting, OnIdleAction, ClipboardClearSetting } from '../../background/settings.js';
import type { StatusTone } from '../components/status-message.js';

/** The worker request function every options surface is injected with; never called directly by
 *  the section components — only `VwOptionsApp` performs requests. */
export type OptionsRequest = typeof sendRequest;

/**
 * The narrow dependency seam the dormant Lit options root is constructed with. Every side effect
 * the root needs (worker requests, host-permission prompts, file download/read, and the extension
 * version) is injected here so tests can supply fakes instead of touching real browser APIs.
 */
export interface OptionsDeps {
  request: OptionsRequest;
  requestOrigins(origins: string[]): Promise<boolean>;
  downloadText(content: string, fileName: string): void;
  readFile(file: File): Promise<string>;
  extensionVersion(): string;
}

/** The non-secret settings the root loads once from `settings.get` and hands down as props. */
export interface LoadedSettings {
  serverUrl?: string;
  defaultUriMatchStrategy: UriMatchStrategySetting;
  lockTimeout: LockTimeoutSetting;
  onIdleAction: OnIdleAction;
  clipboardClearSeconds: ClipboardClearSetting;
}

/** A section-local status banner the root drives on exactly one section at a time. */
export interface SectionStatus {
  message: string;
  tone: StatusTone;
}

/** The rail sections, in display order. */
export type OptionsSectionId = 'connection' | 'security' | 'autofill' | 'data' | 'about';

/** `vw-connection-save`: the already-normalized server URL the root should persist (after it has
 *  requested host permission for the URL's origin). */
export interface ConnectionSaveDetail {
  serverUrl: string;
}

/** `vw-autofill-save`: the chosen default URI match strategy. */
export interface AutofillSaveDetail {
  defaultUriMatchStrategy: UriMatchStrategySetting;
}

/** `vw-lock-timeout-save`: the chosen automatic lock timeout. */
export interface LockTimeoutSaveDetail {
  lockTimeout: LockTimeoutSetting;
}

/** `vw-security-save`: the save-on-change idle action and clipboard-clear window. */
export interface SecuritySaveDetail {
  onIdleAction: OnIdleAction;
  clipboardClearSeconds: ClipboardClearSetting;
}

/** `vw-export`: request a vault export; `password` present means a password-protected (encrypted)
 *  export, absent means an explicit plaintext export. */
export interface ExportDetail {
  password?: string;
}

/** `vw-import-file`: the file the user chose to import; the root reads and classifies it. */
export interface ImportFileDetail {
  file: File;
}

/** `vw-import-password`: the export password the user supplied for a password-protected import. */
export interface ImportPasswordDetail {
  password: string;
}
