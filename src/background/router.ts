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
          case 'auth.lock':
            if (!deps.auth.lock) throw new Error('auth.lock is not wired');
            await deps.auth.lock();
            return { ok: true, data: null };
          case 'auth.logout':
            if (!deps.auth.logout) throw new Error('auth.logout is not wired');
            await deps.auth.logout();
            return { ok: true, data: null };
          case 'vault.sync':
            if (!deps.vault.sync) throw new Error('vault.sync is not wired');
            return { ok: true, data: await deps.vault.sync() };
          case 'vault.listItems':
            if (!deps.vault.listItems) throw new Error('vault.listItems is not wired');
            return { ok: true, data: await deps.vault.listItems() };
          case 'vault.getField': {
            if (!deps.vault.getField) throw new Error('vault.getField is not wired');
            const value = await deps.vault.getField(request.id, request.field);
            return { ok: true, data: value === undefined ? {} : { value } };
          }
          case 'vault.getCipherDetail': {
            if (!deps.vault.getCipherDetail) throw new Error('vault.getCipherDetail is not wired');
            const cipher = await deps.vault.getCipherDetail(request.id);
            return { ok: true, data: { cipher: cipher ?? null } };
          }
          case 'vault.getTotp': {
            if (!deps.vault.getTotpCode) throw new Error('vault.getTotpCode is not wired');
            const totp = await deps.vault.getTotpCode(request.id);
            return { ok: true, data: { totp: totp ?? null } };
          }
          case 'vault.getSkippedOrgCount': {
            if (!deps.vault.getSkippedOrgCount) throw new Error('vault.getSkippedOrgCount is not wired');
            return { ok: true, data: { count: await deps.vault.getSkippedOrgCount() } };
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
