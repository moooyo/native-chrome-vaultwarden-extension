import type { AuthService } from '../core/session/auth-service.js';
import type { VaultService } from '../core/vault/vault-service.js';
import type { UriMatchStrategySetting } from '../core/vault/uri-match.js';
import type { LockTimeoutSetting } from './settings.js';
import type { RequestMessage, ResponseMessage } from '../messaging/protocol.js';
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
          case 'vault.getTotp': {
            if (!deps.vault.getTotpCode) throw new Error('vault.getTotpCode is not wired');
            const totp = await deps.vault.getTotpCode(request.id, request.masterPassword);
            return { ok: true, data: { totp: totp ?? null } };
          }
          case 'vault.getSkippedOrgCount': {
            if (!deps.vault.getSkippedOrgCount) throw new Error('vault.getSkippedOrgCount is not wired');
            return { ok: true, data: { count: await deps.vault.getSkippedOrgCount() } };
          }
          case 'vault.getPasswordHealth': {
            if (!deps.vault.getPasswordHealth) throw new Error('vault.getPasswordHealth is not wired');
            return { ok: true, data: { entries: await deps.vault.getPasswordHealth() } };
          }
          case 'vault.export': {
            if (!deps.vault.exportVault) throw new Error('vault.exportVault is not wired');
            return { ok: true, data: { json: await deps.vault.exportVault() } };
          }
          case 'vault.import': {
            if (!deps.vault.importVault) throw new Error('vault.importVault is not wired');
            return { ok: true, data: { imported: await deps.vault.importVault(request.json) } };
          }
          case 'vault.hasPasskey': {
            if (!deps.vault.hasMatchingPasskey) throw new Error('vault.hasMatchingPasskey is not wired');
            const matches = await deps.vault.hasMatchingPasskey({
              rpId: request.rpId,
              ...(request.allowedCredentialIds ? { allowedCredentialIds: request.allowedCredentialIds } : {}),
            });
            return { ok: true, data: { matches } };
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
          case 'vault.createFolder':
            if (!deps.vault.createFolder) throw new Error('vault.createFolder is not wired');
            return { ok: true, data: await deps.vault.createFolder(request.name) };
          case 'vault.renameFolder':
            if (!deps.vault.renameFolder) throw new Error('vault.renameFolder is not wired');
            return { ok: true, data: await deps.vault.renameFolder(request.id, request.name) };
          case 'vault.deleteFolder':
            if (!deps.vault.deleteFolder) throw new Error('vault.deleteFolder is not wired');
            return { ok: true, data: await deps.vault.deleteFolder(request.id) };
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
          case 'vault.getCipherInput': {
            if (!deps.vault.getCipherInput) throw new Error('vault.getCipherInput is not wired');
            const input = await deps.vault.getCipherInput(request.id, request.masterPassword);
            return { ok: true, data: { input: input ?? null } };
          }
          case 'settings.get': {
            const serverUrl = await deps.settings.getServerUrl();
            const defaultUriMatchStrategy = await deps.settings.getDefaultUriMatchStrategy();
            const lockTimeout = await deps.settings.getLockTimeout();
            return { ok: true, data: serverUrl === undefined ? { defaultUriMatchStrategy, lockTimeout } : { serverUrl, defaultUriMatchStrategy, lockTimeout } };
          }
          case 'settings.save':
            await deps.settings.saveServerUrl(request.serverUrl);
            if (request.defaultUriMatchStrategy !== undefined) {
              await deps.settings.saveDefaultUriMatchStrategy(request.defaultUriMatchStrategy);
            }
            if (request.lockTimeout !== undefined) {
              await deps.settings.saveLockTimeout(request.lockTimeout);
            }
            return { ok: true, data: null };
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
