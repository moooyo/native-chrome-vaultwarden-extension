import browser from 'webextension-polyfill';
import type { AuthResult } from '../core/session/auth-service.js';
import type { SessionState, AccountSummary } from '../core/session/session-manager.js';
import type { CipherInput, CipherSummary, CollectionSummary, DecryptedCipher, FieldName, FolderSummary } from '../core/vault/models.js';
import type { UriMatchStrategySetting } from '../core/vault/uri-match.js';
import type { TotpResult } from '../core/vault/totp.js';
import type { SaveLoginPrompt } from '../core/vault/vault-service.js';
import type { PasswordHealthEntry } from '../core/vault/password-health.js';
import type { PasskeyAssertion } from '../core/vault/fido2.js';
import type { LockTimeoutSetting } from '../background/settings.js';
import type { AppErrorCode } from '../core/errors.js';

export interface AutofillCandidate {
  id: string;
  name: string;
  username?: string;
  matchedUri: string;
  matchType: UriMatchStrategySetting;
  favorite: boolean;
  /** True when the item is master-password-reprompt protected; it cannot be filled inline. */
  reprompt?: boolean;
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
  | { type: 'auth.register'; email: string; masterPassword: string; name?: string }
  | { type: 'auth.submitTwoFactor'; provider: 0 | 1; code: string; remember?: boolean }
  | { type: 'auth.sendEmailCode' }
  | { type: 'auth.unlock'; masterPassword: string }
  | { type: 'auth.verifyMasterPassword'; masterPassword: string }
  | { type: 'auth.unlockWithPin'; pin: string }
  | { type: 'auth.setPin'; pin: string }
  | { type: 'auth.disablePin' }
  | { type: 'auth.pinStatus' }
  | { type: 'auth.lock' }
  | { type: 'auth.logout' }
  | { type: 'auth.listAccounts' }
  | { type: 'auth.switchAccount'; email: string }
  | { type: 'auth.removeAccount'; email: string }
  | { type: 'vault.sync' }
  | { type: 'vault.listItems' }
  | { type: 'vault.getField'; id: string; field: FieldName; masterPassword?: string }
  | { type: 'vault.getCustomField'; id: string; index: number; masterPassword?: string }
  | { type: 'vault.getPasswordHistory'; id: string; masterPassword?: string }
  | { type: 'vault.getCipherDetail'; id: string }
  | { type: 'vault.getTotp'; id: string; masterPassword?: string }
  | { type: 'vault.getSkippedOrgCount' }
  | { type: 'vault.getPasswordHealth' }
  | { type: 'vault.export' }
  | { type: 'vault.import'; json: string }
  | { type: 'vault.hasPasskey'; rpId: string; allowedCredentialIds?: string[] }
  | { type: 'vault.getPasskeyAssertion'; rpId: string; origin: string; challenge: string; allowedCredentialIds?: string[]; userVerified?: boolean }
  | { type: 'vault.createFolder'; name: string }
  | { type: 'vault.renameFolder'; id: string; name: string }
  | { type: 'vault.deleteFolder'; id: string }
  | { type: 'vault.createCipher'; input: CipherInput }
  | { type: 'vault.updateCipher'; id: string; input: CipherInput }
  | { type: 'vault.deleteCipher'; id: string }
  | { type: 'vault.softDeleteCipher'; id: string }
  | { type: 'vault.restoreCipher'; id: string }
  | { type: 'vault.getCipherInput'; id: string; masterPassword?: string }
  | { type: 'settings.get' }
  | { type: 'settings.save'; serverUrl: string; defaultUriMatchStrategy?: UriMatchStrategySetting; lockTimeout?: LockTimeoutSetting }
  | { type: 'autofill.findCandidates'; frameUrl: string; formSignature?: string }
  | { type: 'autofill.getCredentials'; cipherId: string; frameUrl: string }
  | { type: 'autofill.checkSaveLogin'; frameUrl: string; username?: string; password: string }
  | { type: 'autofill.saveLogin'; frameUrl: string; username?: string; password: string }
  | { type: 'autofill.updateLogin'; cipherId: string; frameUrl: string; password: string };

export type ResponseMessage =
  | { ok: true; data: { state: SessionState } }
  | { ok: true; data: AuthResult }
  | { ok: true; data: { items: CipherSummary[]; folders: FolderSummary[]; collections: CollectionSummary[] } }
  | { ok: true; data: { value?: string } }
  | { ok: true; data: { cipher: DecryptedCipher | null } }
  | { ok: true; data: { input: CipherInput | null } }
  | { ok: true; data: { totp: TotpResult | null } }
  | { ok: true; data: { count: number } }
  | { ok: true; data: { entries: PasswordHealthEntry[] } }
  | { ok: true; data: { history: Array<{ password: string; lastUsedDate?: string }> } }
  | { ok: true; data: { json: string } }
  | { ok: true; data: { imported: number } }
  | { ok: true; data: { enabled: boolean } }
  | { ok: true; data: { verified: boolean } }
  | { ok: true; data: { matches: boolean } }
  | { ok: true; data: { assertion: PasskeyAssertion | null } }
  | { ok: true; data: { accounts: AccountSummary[] } }
  | { ok: true; data: { serverUrl?: string; defaultUriMatchStrategy: UriMatchStrategySetting; lockTimeout: LockTimeoutSetting } }
  | { ok: true; data: null }
  | { ok: true; data: AutofillCandidate[] }
  | { ok: true; data: AutofillCredentials }
  | { ok: true; data: SaveLoginPrompt }
  | { ok: false; error: { code: AppErrorCode; message: string } };

export async function sendRequest(request: RequestMessage): Promise<ResponseMessage> {
  return browser.runtime.sendMessage(request) as Promise<ResponseMessage>;
}
