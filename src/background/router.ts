import type { AuthService } from '../core/session/auth-service.js';
import type { VaultService } from '../core/vault/vault-service.js';
import type { RequestMessage, ResponseMessage } from '../messaging/protocol.js';

export interface RouterDeps {
  auth: Partial<AuthService>;
  vault: Partial<VaultService>;
  settings: {
    getServerUrl(): Promise<string | undefined>;
    saveServerUrl(serverUrl: string): Promise<void>;
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
          case 'settings.get': {
            const serverUrl = await deps.settings.getServerUrl();
            return { ok: true, data: serverUrl === undefined ? {} : { serverUrl } };
          }
          case 'settings.save':
            await deps.settings.saveServerUrl(request.serverUrl);
            return { ok: true, data: null };
        }
      } catch (err) {
        return { ok: false, error: { code: 'error', message: err instanceof Error ? err.message : String(err) } };
      }
    },
  };
}
