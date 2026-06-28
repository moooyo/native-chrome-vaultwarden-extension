import browser from 'webextension-polyfill';
import type { AuthResult } from '../core/session/auth-service.js';
import type { SessionState } from '../core/session/session-manager.js';
import type { CipherInput, CipherSummary, CollectionSummary, DecryptedCipher, FieldName, FolderSummary } from '../core/vault/models.js';
import type { UriMatchStrategySetting } from '../core/vault/uri-match.js';
import type { TotpResult } from '../core/vault/totp.js';
import type { LockTimeoutSetting } from '../background/settings.js';
import type { AppErrorCode } from '../core/errors.js';

export interface AutofillCandidate {
  id: string;
  name: string;
  username?: string;
  matchedUri: string;
  matchType: UriMatchStrategySetting;
  favorite: boolean;
}

export interface AutofillCredentials {
  username?: string;
  password?: string;
  /** Current TOTP code for the login, when it carries a TOTP secret. Generated fresh in the worker. */
  totp?: string;
}

export type RequestMessage =
  | { type: 'auth.getState' }
  | { type: 'auth.login'; email: string; masterPassword: string }
  | { type: 'auth.submitTwoFactor'; provider: 0 | 1; code: string; remember?: boolean }
  | { type: 'auth.sendEmailCode' }
  | { type: 'auth.unlock'; masterPassword: string }
  | { type: 'auth.lock' }
  | { type: 'auth.logout' }
  | { type: 'vault.sync' }
  | { type: 'vault.listItems' }
  | { type: 'vault.getField'; id: string; field: FieldName }
  | { type: 'vault.getCipherDetail'; id: string }
  | { type: 'vault.getTotp'; id: string }
  | { type: 'vault.getSkippedOrgCount' }
  | { type: 'vault.createFolder'; name: string }
  | { type: 'vault.renameFolder'; id: string; name: string }
  | { type: 'vault.deleteFolder'; id: string }
  | { type: 'vault.createCipher'; input: CipherInput }
  | { type: 'vault.updateCipher'; id: string; input: CipherInput }
  | { type: 'vault.deleteCipher'; id: string }
  | { type: 'vault.getCipherInput'; id: string }
  | { type: 'settings.get' }
  | { type: 'settings.save'; serverUrl: string; defaultUriMatchStrategy?: UriMatchStrategySetting; lockTimeout?: LockTimeoutSetting }
  | { type: 'autofill.findCandidates'; frameUrl: string; formSignature?: string }
  | { type: 'autofill.getCredentials'; cipherId: string; frameUrl: string };

export type ResponseMessage =
  | { ok: true; data: { state: SessionState } }
  | { ok: true; data: AuthResult }
  | { ok: true; data: { items: CipherSummary[]; folders: FolderSummary[]; collections: CollectionSummary[] } }
  | { ok: true; data: { value?: string } }
  | { ok: true; data: { cipher: DecryptedCipher | null } }
  | { ok: true; data: { input: CipherInput | null } }
  | { ok: true; data: { totp: TotpResult | null } }
  | { ok: true; data: { count: number } }
  | { ok: true; data: { serverUrl?: string; defaultUriMatchStrategy: UriMatchStrategySetting; lockTimeout: LockTimeoutSetting } }
  | { ok: true; data: null }
  | { ok: true; data: AutofillCandidate[] }
  | { ok: true; data: AutofillCredentials }
  | { ok: false; error: { code: AppErrorCode; message: string } };

export async function sendRequest(request: RequestMessage): Promise<ResponseMessage> {
  return browser.runtime.sendMessage(request) as Promise<ResponseMessage>;
}
