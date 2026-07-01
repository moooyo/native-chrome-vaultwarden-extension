import browser from 'webextension-polyfill';
import type { AuthResult } from '../core/session/auth-service.js';
import type { SessionState, AccountSummary } from '../core/session/session-manager.js';
import type { CipherInput, CipherSummary, CollectionSummary, DecryptedCipher, FieldName, FolderSummary } from '../core/vault/models.js';
import type { UriMatchStrategySetting } from '../core/vault/uri-match.js';
import type { TotpResult } from '../core/vault/totp.js';
import type { SaveLoginPrompt } from '../core/vault/vault-service.js';
import type { SendInput, SendSummary, UpdateSendInput } from '../core/vault/sends.js';
import type { PasswordHealthEntry } from '../core/vault/password-health.js';
import type { PasskeyAssertion } from '../core/vault/fido2.js';
import type { LockTimeoutSetting } from '../background/settings.js';
import type { AppErrorCode } from '../core/errors.js';
import type { OrgPermission } from '../core/vault/org-permissions.js';

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

export type FillKind = 'card' | 'identity';

/** A card/identity candidate for the fill popover. Carries no secret — subtitle is brand/full name. */
export interface FillItemCandidate {
  id: string;
  name: string;
  subtitle?: string;
  favorite: boolean;
  /** True when reprompt-protected; cannot be filled inline (worker refuses). */
  reprompt?: boolean;
}

/** Fillable card fields. Number + code are sensitive; released only on explicit user selection. */
export interface CardFillData {
  cardholderName?: string;
  number?: string;
  expMonth?: string;
  expYear?: string;
  code?: string;
}

/** Fillable identity fields. National-ID secrets (ssn/passport/license) are intentionally absent. */
export interface IdentityFillData {
  title?: string;
  firstName?: string;
  middleName?: string;
  lastName?: string;
  address1?: string;
  address2?: string;
  address3?: string;
  city?: string;
  state?: string;
  postalCode?: string;
  country?: string;
  company?: string;
  email?: string;
  phone?: string;
  username?: string;
}

/** Background → content: fill a detected form (scope 'form') or only the last right-clicked field
 *  (scope 'field') with the chosen card/identity. Sent via tabs.sendMessage from the context menu. */
export interface FillCommand {
  type: 'autofill.fill';
  scope: 'form' | 'field';
  kind: FillKind;
  data: CardFillData | IdentityFillData;
}

/** Background → content: the chosen item could not be released inline (reprompt-protected). */
export interface FillErrorCommand {
  type: 'autofill.fillError';
  code: 'reprompt_required';
}

/** Background → content: fill the currently-focused field's form via the keyboard shortcut. */
export interface FocusedFillCommand {
  type: 'autofill.focusedFill';
}

export type ContentCommand = FillCommand | FillErrorCommand | FocusedFillCommand;

export type RequestMessage =
  | { type: 'auth.getState' }
  | { type: 'auth.login'; email: string; masterPassword: string }
  | { type: 'auth.register'; email: string; masterPassword: string; name?: string }
  | { type: 'auth.submitTwoFactor'; provider: number; code: string; remember?: boolean }
  | { type: 'auth.sendEmailCode' }
  | { type: 'auth.unlock'; masterPassword: string }
  | { type: 'auth.verifyMasterPassword'; masterPassword: string }
  | { type: 'auth.changePassword'; currentPassword: string; newPassword: string }
  | { type: 'auth.changeKdf'; currentPassword: string; iterations: number }
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
  | { type: 'vault.getAttachment'; cipherId: string; attachmentId: string; masterPassword?: string }
  | { type: 'vault.addAttachment'; cipherId: string; fileName: string; dataB64: string; masterPassword?: string }
  | { type: 'vault.deleteAttachment'; cipherId: string; attachmentId: string }
  | { type: 'vault.getCipherDetail'; id: string }
  | { type: 'vault.getTotp'; id: string; masterPassword?: string }
  | { type: 'vault.getSkippedOrgCount' }
  | { type: 'vault.getPasswordHealth' }
  | { type: 'vault.checkPwned' }
  | { type: 'vault.export'; password?: string }
  | { type: 'vault.import'; content: string; password?: string }
  | { type: 'vault.hasPasskey'; rpId: string; allowedCredentialIds?: string[] }
  | { type: 'vault.getPasskeyAssertion'; rpId: string; origin: string; challenge: string; allowedCredentialIds?: string[]; userVerified?: boolean }
  | { type: 'vault.createFolder'; name: string }
  | { type: 'vault.renameFolder'; id: string; name: string }
  | { type: 'vault.deleteFolder'; id: string }
  | { type: 'vault.createCollection'; organizationId: string; name: string }
  | { type: 'vault.renameCollection'; organizationId: string; id: string; name: string }
  | { type: 'vault.deleteCollection'; organizationId: string; id: string }
  | { type: 'vault.setCipherCollections'; id: string; collectionIds: string[] }
  | { type: 'vault.createCipher'; input: CipherInput }
  | { type: 'vault.updateCipher'; id: string; input: CipherInput }
  | { type: 'vault.deleteCipher'; id: string }
  | { type: 'vault.softDeleteCipher'; id: string }
  | { type: 'vault.restoreCipher'; id: string }
  | { type: 'vault.shareCipher'; id: string; organizationId: string; collectionIds: string[]; masterPassword?: string }
  | { type: 'vault.getCipherInput'; id: string; masterPassword?: string }
  | { type: 'settings.get' }
  | { type: 'settings.save'; serverUrl: string; defaultUriMatchStrategy?: UriMatchStrategySetting; lockTimeout?: LockTimeoutSetting }
  | { type: 'autofill.findCandidates'; frameUrl: string; formSignature?: string }
  | { type: 'autofill.getCredentials'; cipherId: string; frameUrl: string }
  | { type: 'sends.list' }
  | { type: 'sends.createText'; input: SendInput }
  | { type: 'sends.createFile'; input: SendInput; dataB64: string; fileName: string }
  | { type: 'sends.update'; id: string; input: UpdateSendInput }
  | { type: 'sends.delete'; id: string }
  | { type: 'autofill.checkSaveLogin'; frameUrl: string; username?: string; password: string }
  | { type: 'autofill.saveLogin'; frameUrl: string; username?: string; password: string }
  | { type: 'autofill.updateLogin'; cipherId: string; frameUrl: string; password: string }
  | { type: 'autofill.findFillItems'; kind: FillKind }
  | { type: 'autofill.getFillData'; cipherId: string; kind: FillKind };

export type ResponseMessage =
  | { ok: true; data: { state: SessionState } }
  | { ok: true; data: AuthResult }
  | { ok: true; data: { items: CipherSummary[]; folders: FolderSummary[]; collections: CollectionSummary[]; orgPermissions: OrgPermission[] } }
  | { ok: true; data: { value?: string } }
  | { ok: true; data: { cipher: DecryptedCipher | null } }
  | { ok: true; data: { input: CipherInput | null } }
  | { ok: true; data: { totp: TotpResult | null } }
  | { ok: true; data: { count: number } }
  | { ok: true; data: { entries: PasswordHealthEntry[] } }
  | { ok: true; data: { entries: Array<{ id: string; pwnedCount: number }> } }
  | { ok: true; data: { history: Array<{ password: string; lastUsedDate?: string }> } }
  | { ok: true; data: { fileName: string; dataB64: string } }
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
  | { ok: true; data: FillItemCandidate[] }
  | { ok: true; data: CardFillData | IdentityFillData }
  | { ok: true; data: SaveLoginPrompt }
  | { ok: true; data: { sends: SendSummary[] } }
  | { ok: true; data: { send: SendSummary } }
  | { ok: false; error: { code: AppErrorCode; message: string } };

export async function sendRequest(request: RequestMessage): Promise<ResponseMessage> {
  return browser.runtime.sendMessage(request) as Promise<ResponseMessage>;
}
