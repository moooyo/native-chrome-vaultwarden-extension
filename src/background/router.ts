import type { AuthService } from '../core/session/auth-service.js';
import type { VaultService } from '../core/vault/vault-service.js';
import type { UriMatchStrategySetting } from '../core/vault/uri-match.js';
import type { LockTimeoutSetting, OnIdleAction, ClipboardClearSetting } from './settings.js';
import { normalizeServerUrl } from './settings.js';
import type { RequestMessage, ResponseMessage, TabFillOutcome, TabSuggestionsOutcome, TabSuggestionTarget } from '../messaging/protocol.js';
import { AppError } from '../core/errors.js';

export interface RouterDeps {
  auth: Partial<AuthService>;
  vault: Partial<VaultService>;
  settings: {
    getServerUrl(): Promise<string | undefined>;
    saveServerUrl(serverUrl: string): Promise<void>;
    getDefaultUriMatchStrategy(): Promise<UriMatchStrategySetting>;
    saveDefaultUriMatchStrategy(strategy: UriMatchStrategySetting): Promise<void>;
    getLockTimeout(): Promise<LockTimeoutSetting>;
    saveLockTimeout(value: LockTimeoutSetting): Promise<void>;
    getOnIdleAction(): Promise<OnIdleAction>;
    saveOnIdleAction(value: OnIdleAction): Promise<void>;
    getClipboardClearSetting(): Promise<ClipboardClearSetting>;
    saveClipboardClearSetting(value: ClipboardClearSetting): Promise<void>;
  };
  clipboard?: { scheduleClear(): Promise<void> };
  tabAutofill?: {
    getSuggestions(tabId: number): Promise<TabSuggestionsOutcome>;
    fill(tabId: number, cipherId: string, target: TabSuggestionTarget): Promise<TabFillOutcome>;
  };
}

export function createRouter(deps: RouterDeps) {
  return {
    async handle(request: RequestMessage): Promise<ResponseMessage> {
      try {
        switch (request.type) {
          case 'auth.getState':
            if (!deps.auth.getState) throw new Error('auth.getState is not wired');
            return { ok: true, data: { state: await deps.auth.getState() } };
          case 'auth.login':
            if (!deps.auth.login) throw new Error('auth.login is not wired');
            return { ok: true, data: await deps.auth.login({ email: request.email, masterPassword: request.masterPassword }) };
          case 'auth.register':
            if (!deps.auth.register) throw new Error('auth.register is not wired');
            return {
              ok: true,
              data: await deps.auth.register(
                request.name === undefined
                  ? { email: request.email, masterPassword: request.masterPassword }
                  : { email: request.email, masterPassword: request.masterPassword, name: request.name },
              ),
            };
          case 'auth.submitTwoFactor':
            if (!deps.auth.submitTwoFactor) throw new Error('auth.submitTwoFactor is not wired');
            return {
              ok: true,
              data: await deps.auth.submitTwoFactor(
                request.remember === undefined
                  ? { provider: request.provider, code: request.code }
                  : { provider: request.provider, code: request.code, remember: request.remember },
              ),
            };
          case 'auth.sendEmailCode':
            if (!deps.auth.sendEmailCode) throw new Error('auth.sendEmailCode is not wired');
            await deps.auth.sendEmailCode();
            return { ok: true, data: null };
          case 'auth.unlock':
            if (!deps.auth.unlock) throw new Error('auth.unlock is not wired');
            await deps.auth.unlock(request.masterPassword);
            return { ok: true, data: null };
          case 'auth.verifyMasterPassword':
            if (!deps.auth.verifyMasterPassword) throw new Error('auth.verifyMasterPassword is not wired');
            return { ok: true, data: { verified: await deps.auth.verifyMasterPassword(request.masterPassword) } };
          case 'auth.changePassword':
            if (!deps.auth.changeMasterPassword) throw new Error('auth.changeMasterPassword is not wired');
            await deps.auth.changeMasterPassword(request.currentPassword, request.newPassword);
            return { ok: true, data: null };
          case 'auth.changeKdf':
            if (!deps.auth.changeKdfIterations) throw new Error('auth.changeKdfIterations is not wired');
            await deps.auth.changeKdfIterations(request.currentPassword, request.iterations);
            return { ok: true, data: null };
          case 'auth.rotateAccountKey':
            if (!deps.auth.rotateAccountKey) throw new Error('auth.rotateAccountKey is not wired');
            await deps.auth.rotateAccountKey(request.masterPassword);
            return { ok: true, data: null };
          case 'auth.unlockWithPin':
            if (!deps.auth.unlockWithPin) throw new Error('auth.unlockWithPin is not wired');
            await deps.auth.unlockWithPin(request.pin);
            return { ok: true, data: null };
          case 'auth.setPin':
            if (!deps.auth.setPin) throw new Error('auth.setPin is not wired');
            await deps.auth.setPin(request.pin);
            return { ok: true, data: null };
          case 'auth.disablePin':
            if (!deps.auth.disablePin) throw new Error('auth.disablePin is not wired');
            await deps.auth.disablePin();
            return { ok: true, data: null };
          case 'auth.pinStatus':
            if (!deps.auth.isPinEnabled) throw new Error('auth.isPinEnabled is not wired');
            return { ok: true, data: { enabled: await deps.auth.isPinEnabled() } };
          case 'auth.lock':
            if (!deps.auth.lock) throw new Error('auth.lock is not wired');
            await deps.auth.lock();
            return { ok: true, data: null };
          case 'auth.logout':
            if (!deps.auth.logout) throw new Error('auth.logout is not wired');
            await deps.auth.logout();
            return { ok: true, data: null };
          case 'auth.listAccounts':
            if (!deps.auth.listAccounts) throw new Error('auth.listAccounts is not wired');
            return { ok: true, data: { accounts: await deps.auth.listAccounts() } };
          case 'auth.switchAccount':
            if (!deps.auth.switchAccount) throw new Error('auth.switchAccount is not wired');
            await deps.auth.switchAccount(request.email);
            return { ok: true, data: null };
          case 'auth.removeAccount':
            if (!deps.auth.removeAccount) throw new Error('auth.removeAccount is not wired');
            await deps.auth.removeAccount(request.email);
            return { ok: true, data: null };
          case 'auth.forgetDevice':
            if (!deps.auth.forgetDevice) throw new Error('auth.forgetDevice is not wired');
            await deps.auth.forgetDevice(request.email);
            return { ok: true, data: null };
          case 'auth.isDeviceRemembered':
            if (!deps.auth.isDeviceRemembered) throw new Error('auth.isDeviceRemembered is not wired');
            return { ok: true, data: { remembered: await deps.auth.isDeviceRemembered(request.email) } };
          case 'vault.sync':
            if (!deps.vault.sync) throw new Error('vault.sync is not wired');
            return { ok: true, data: await deps.vault.sync() };
          case 'vault.listItems':
            if (!deps.vault.listItems) throw new Error('vault.listItems is not wired');
            return { ok: true, data: await deps.vault.listItems() };
          case 'vault.getField': {
            if (!deps.vault.getField) throw new Error('vault.getField is not wired');
            const value = await deps.vault.getField(request.id, request.field, request.masterPassword);
            return { ok: true, data: value === undefined ? {} : { value } };
          }
          case 'vault.getCustomField': {
            if (!deps.vault.getCustomField) throw new Error('vault.getCustomField is not wired');
            const value = await deps.vault.getCustomField(request.id, request.index, request.masterPassword);
            return { ok: true, data: value === undefined ? {} : { value } };
          }
          case 'vault.getCipherDetail': {
            if (!deps.vault.getCipherDetail) throw new Error('vault.getCipherDetail is not wired');
            const cipher = await deps.vault.getCipherDetail(request.id);
            return { ok: true, data: { cipher: cipher ?? null } };
          }
          case 'vault.getAttachment': {
            if (!deps.vault.getAttachment) throw new Error('vault.getAttachment is not wired');
            return { ok: true, data: await deps.vault.getAttachment(request.cipherId, request.attachmentId, request.masterPassword) };
          }
          case 'vault.addAttachment': {
            if (!deps.vault.addAttachment) throw new Error('vault.addAttachment is not wired');
            return { ok: true, data: await deps.vault.addAttachment(request.cipherId, request.fileName, request.dataB64, request.masterPassword) };
          }
          case 'vault.deleteAttachment': {
            if (!deps.vault.deleteAttachment) throw new Error('vault.deleteAttachment is not wired');
            return { ok: true, data: await deps.vault.deleteAttachment(request.cipherId, request.attachmentId) };
          }
          case 'vault.getPasswordHistory': {
            if (!deps.vault.getPasswordHistory) throw new Error('vault.getPasswordHistory is not wired');
            return { ok: true, data: { history: await deps.vault.getPasswordHistory(request.id, request.masterPassword) } };
          }
          case 'vault.getTotp': {
            if (!deps.vault.getTotpCode) throw new Error('vault.getTotpCode is not wired');
            const totp = await deps.vault.getTotpCode(request.id, request.masterPassword);
            return { ok: true, data: { totp: totp ?? null } };
          }
          case 'vault.getTotpCodes': {
            if (!deps.vault.listTotpCodes) throw new Error('vault.listTotpCodes is not wired');
            return { ok: true, data: { totpEntries: await deps.vault.listTotpCodes() } };
          }
          case 'vault.getSkippedOrgCount': {
            if (!deps.vault.getSkippedOrgCount) throw new Error('vault.getSkippedOrgCount is not wired');
            return { ok: true, data: { count: await deps.vault.getSkippedOrgCount() } };
          }
          case 'vault.getPasswordHealth': {
            if (!deps.vault.getPasswordHealth) throw new Error('vault.getPasswordHealth is not wired');
            return { ok: true, data: { entries: await deps.vault.getPasswordHealth() } };
          }
          case 'vault.checkPwned': {
            if (!deps.vault.getPwnedReport) throw new Error('vault.getPwnedReport is not wired');
            return { ok: true, data: { entries: await deps.vault.getPwnedReport() } };
          }
          case 'vault.export': {
            if (!deps.vault.exportVault) throw new Error('vault.exportVault is not wired');
            return { ok: true, data: { json: await deps.vault.exportVault(request.password) } };
          }
          case 'vault.import': {
            if (!deps.vault.importVault) throw new Error('vault.importVault is not wired');
            return { ok: true, data: { imported: await deps.vault.importVault(request.content, request.password) } };
          }
          case 'vault.hasPasskey': {
            if (!deps.vault.hasMatchingPasskey) throw new Error('vault.hasMatchingPasskey is not wired');
            const matches = await deps.vault.hasMatchingPasskey({
              rpId: request.rpId,
              origin: request.origin,
              ...(request.allowedCredentialIds ? { allowedCredentialIds: request.allowedCredentialIds } : {}),
            });
            return { ok: true, data: { matches } };
          }
          case 'vault.getPasskeyCandidates': {
            if (!deps.vault.listPasskeyCandidates) throw new Error('vault.listPasskeyCandidates is not wired');
            const candidates = await deps.vault.listPasskeyCandidates({
              rpId: request.rpId,
              origin: request.origin,
              ...(request.allowedCredentialIds ? { allowedCredentialIds: request.allowedCredentialIds } : {}),
            });
            return { ok: true, data: { candidates } };
          }
          case 'vault.getPasskeyAssertion': {
            if (!deps.vault.getPasskeyAssertion) throw new Error('vault.getPasskeyAssertion is not wired');
            const assertion = await deps.vault.getPasskeyAssertion({
              rpId: request.rpId,
              origin: request.origin,
              challenge: request.challenge,
              ...(request.allowedCredentialIds ? { allowedCredentialIds: request.allowedCredentialIds } : {}),
              ...(request.userVerified !== undefined ? { userVerified: request.userVerified } : {}),
            });
            return { ok: true, data: { assertion: assertion ?? null } };
          }
          case 'vault.getPasskeyTargets': {
            if (!deps.vault.getPasskeyTargets) throw new Error('vault.getPasskeyTargets is not wired');
            return { ok: true, data: { targets: await deps.vault.getPasskeyTargets({ rpId: request.rpId, origin: request.origin }) } };
          }
          case 'vault.createPasskey': {
            if (!deps.vault.createPasskey) throw new Error('vault.createPasskey is not wired');
            const registration = await deps.vault.createPasskey({
              rpId: request.rpId,
              challenge: request.challenge,
              origin: request.origin,
              ...(request.rpName ? { rpName: request.rpName } : {}),
              ...(request.userHandle ? { userHandle: request.userHandle } : {}),
              ...(request.userName ? { userName: request.userName } : {}),
              ...(request.userDisplayName ? { userDisplayName: request.userDisplayName } : {}),
              ...(request.userVerified !== undefined ? { userVerified: request.userVerified } : {}),
              ...(request.targetCipherId ? { targetCipherId: request.targetCipherId } : {}),
            });
            return { ok: true, data: { registration } };
          }
          case 'vault.createFolder':
            if (!deps.vault.createFolder) throw new Error('vault.createFolder is not wired');
            return { ok: true, data: await deps.vault.createFolder(request.name) };
          case 'vault.renameFolder':
            if (!deps.vault.renameFolder) throw new Error('vault.renameFolder is not wired');
            return { ok: true, data: await deps.vault.renameFolder(request.id, request.name) };
          case 'vault.deleteFolder':
            if (!deps.vault.deleteFolder) throw new Error('vault.deleteFolder is not wired');
            return { ok: true, data: await deps.vault.deleteFolder(request.id) };
          case 'vault.createCollection':
            if (!deps.vault.createCollection) throw new Error('vault.createCollection is not wired');
            return { ok: true, data: await deps.vault.createCollection(request.organizationId, request.name) };
          case 'vault.renameCollection':
            if (!deps.vault.renameCollection) throw new Error('vault.renameCollection is not wired');
            return { ok: true, data: await deps.vault.renameCollection(request.organizationId, request.id, request.name) };
          case 'vault.deleteCollection':
            if (!deps.vault.deleteCollection) throw new Error('vault.deleteCollection is not wired');
            return { ok: true, data: await deps.vault.deleteCollection(request.organizationId, request.id) };
          case 'vault.setCipherCollections':
            if (!deps.vault.setCipherCollections) throw new Error('vault.setCipherCollections is not wired');
            return { ok: true, data: await deps.vault.setCipherCollections(request.id, request.collectionIds) };
          case 'vault.createCipher':
            if (!deps.vault.createCipher) throw new Error('vault.createCipher is not wired');
            return { ok: true, data: await deps.vault.createCipher(request.input) };
          case 'vault.updateCipher':
            if (!deps.vault.updateCipher) throw new Error('vault.updateCipher is not wired');
            return { ok: true, data: await deps.vault.updateCipher(request.id, request.input) };
          case 'vault.deleteCipher':
            if (!deps.vault.deleteCipher) throw new Error('vault.deleteCipher is not wired');
            return { ok: true, data: await deps.vault.deleteCipher(request.id) };
          case 'vault.softDeleteCipher':
            if (!deps.vault.softDeleteCipher) throw new Error('vault.softDeleteCipher is not wired');
            return { ok: true, data: await deps.vault.softDeleteCipher(request.id) };
          case 'vault.restoreCipher':
            if (!deps.vault.restoreCipher) throw new Error('vault.restoreCipher is not wired');
            return { ok: true, data: await deps.vault.restoreCipher(request.id) };
          case 'vault.shareCipher':
            if (!deps.vault.shareCipher) throw new Error('vault.shareCipher is not wired');
            return { ok: true, data: await deps.vault.shareCipher(request.id, request.organizationId, request.collectionIds, request.masterPassword) };
          case 'vault.getCipherInput': {
            if (!deps.vault.getCipherInput) throw new Error('vault.getCipherInput is not wired');
            const input = await deps.vault.getCipherInput(request.id, request.masterPassword);
            return { ok: true, data: { input: input ?? null } };
          }
          case 'settings.get': {
            const serverUrl = await deps.settings.getServerUrl();
            const defaultUriMatchStrategy = await deps.settings.getDefaultUriMatchStrategy();
            const lockTimeout = await deps.settings.getLockTimeout();
            const onIdleAction = await deps.settings.getOnIdleAction();
            const clipboardClearSeconds = await deps.settings.getClipboardClearSetting();
            const base = { defaultUriMatchStrategy, lockTimeout, onIdleAction, clipboardClearSeconds };
            return { ok: true, data: serverUrl === undefined ? base : { serverUrl, ...base } };
          }
          case 'settings.save':
            {
              const currentServerUrl = await deps.settings.getServerUrl();
              const nextServerUrl = normalizeServerUrl(request.serverUrl);
              if (currentServerUrl !== undefined && normalizeServerUrl(currentServerUrl) !== nextServerUrl) {
                if (!deps.auth.resetForServerChange) throw new Error('auth.resetForServerChange is not wired');
                await deps.auth.resetForServerChange();
              }
            }
            await deps.settings.saveServerUrl(request.serverUrl);
            if (request.defaultUriMatchStrategy !== undefined) {
              await deps.settings.saveDefaultUriMatchStrategy(request.defaultUriMatchStrategy);
            }
            if (request.lockTimeout !== undefined) {
              await deps.settings.saveLockTimeout(request.lockTimeout);
            }
            return { ok: true, data: null };
          case 'settings.saveSecurity':
            await deps.settings.saveOnIdleAction(request.onIdleAction);
            await deps.settings.saveClipboardClearSetting(request.clipboardClearSeconds);
            return { ok: true, data: null };
          case 'clipboard.scheduleClear':
            if (!deps.clipboard) throw new Error('clipboard is not wired');
            await deps.clipboard.scheduleClear();
            return { ok: true, data: null };
          case 'sends.list': {
            if (!deps.vault.listSends) throw new Error('vault.listSends is not wired');
            const serverUrl = await deps.settings.getServerUrl();
            if (!serverUrl) throw new AppError('error', 'Server URL is not configured');
            return { ok: true, data: { sends: await deps.vault.listSends(serverUrl) } };
          }
          case 'sends.createText': {
            if (!deps.vault.createTextSend) throw new Error('vault.createTextSend is not wired');
            const serverUrl = await deps.settings.getServerUrl();
            if (!serverUrl) throw new AppError('error', 'Server URL is not configured');
            return { ok: true, data: { send: await deps.vault.createTextSend(request.input, serverUrl) } };
          }
          case 'sends.createFile': {
            if (!deps.vault.createFileSend) throw new Error('vault.createFileSend is not wired');
            const serverUrl = await deps.settings.getServerUrl();
            if (!serverUrl) throw new AppError('error', 'Server URL is not configured');
            return { ok: true, data: { send: await deps.vault.createFileSend(request.input, request.dataB64, request.fileName, serverUrl) } };
          }
          case 'sends.update': {
            if (!deps.vault.updateSend) throw new Error('vault.updateSend is not wired');
            const serverUrl = await deps.settings.getServerUrl();
            if (!serverUrl) throw new AppError('error', 'Server URL is not configured');
            return { ok: true, data: { send: await deps.vault.updateSend(request.id, request.input, serverUrl) } };
          }
          case 'sends.delete': {
            if (!deps.vault.deleteSend) throw new Error('vault.deleteSend is not wired');
            await deps.vault.deleteSend(request.id);
            return { ok: true, data: null };
          }
          case 'autofill.findCandidates': {
            if (!deps.vault.findAutofillCandidates) throw new Error('vault.findAutofillCandidates is not wired');
            const defaultStrategy = await deps.settings.getDefaultUriMatchStrategy();
            return { ok: true, data: await deps.vault.findAutofillCandidates(request.frameUrl, defaultStrategy) };
          }
          case 'autofill.getCredentials': {
            if (!deps.vault.getAutofillCredentials) throw new Error('vault.getAutofillCredentials is not wired');
            const defaultStrategy = await deps.settings.getDefaultUriMatchStrategy();
            return { ok: true, data: await deps.vault.getAutofillCredentials(request.cipherId, request.frameUrl, defaultStrategy) };
          }
          case 'autofill.checkSaveLogin': {
            if (!deps.vault.checkSaveLogin) throw new Error('vault.checkSaveLogin is not wired');
            const defaultStrategy = await deps.settings.getDefaultUriMatchStrategy();
            const submitted = request.username === undefined ? { password: request.password } : { username: request.username, password: request.password };
            return { ok: true, data: await deps.vault.checkSaveLogin(request.frameUrl, submitted, defaultStrategy) };
          }
          case 'autofill.saveLogin': {
            if (!deps.vault.saveLogin) throw new Error('vault.saveLogin is not wired');
            return { ok: true, data: await deps.vault.saveLogin(request.frameUrl, request.username, request.password) };
          }
          case 'autofill.updateLogin': {
            if (!deps.vault.updateLoginPassword) throw new Error('vault.updateLoginPassword is not wired');
            const defaultStrategy = await deps.settings.getDefaultUriMatchStrategy();
            return { ok: true, data: await deps.vault.updateLoginPassword(request.cipherId, request.password, request.frameUrl, defaultStrategy) };
          }
          case 'autofill.findFillItems': {
            if (!deps.vault.findFillItems) throw new Error('vault.findFillItems is not wired');
            return { ok: true, data: await deps.vault.findFillItems(request.kind) };
          }
          case 'autofill.getFillData': {
            if (!deps.vault.getFillData) throw new Error('vault.getFillData is not wired');
            return { ok: true, data: await deps.vault.getFillData(request.cipherId, request.kind) };
          }
          case 'autofill.getTabSuggestions': {
            if (!deps.tabAutofill) throw new Error('tabAutofill is not wired');
            return { ok: true, data: { outcome: await deps.tabAutofill.getSuggestions(request.tabId) } };
          }
          case 'autofill.fillTabSuggestion': {
            if (!deps.tabAutofill) throw new Error('tabAutofill is not wired');
            return { ok: true, data: { outcome: await deps.tabAutofill.fill(request.tabId, request.cipherId, request.target) } };
          }
        }
      } catch (err) {
        if (err instanceof AppError) {
          return { ok: false, error: { code: err.code, message: err.message } };
        }
        return { ok: false, error: { code: 'error', message: err instanceof Error ? err.message : String(err) } };
      }
    },
  };
}
