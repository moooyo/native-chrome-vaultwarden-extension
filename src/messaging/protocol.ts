import browser from 'webextension-polyfill';
import type { AuthResult } from '../core/session/auth-service.js';
import type { SessionState } from '../core/session/session-manager.js';
import type { CipherSummary, FieldName } from '../core/vault/models.js';

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
  | { type: 'settings.get' }
  | { type: 'settings.save'; serverUrl: string };

export type ResponseMessage =
  | { ok: true; data: { state: SessionState } }
  | { ok: true; data: AuthResult }
  | { ok: true; data: CipherSummary[] }
  | { ok: true; data: { value?: string } }
  | { ok: true; data: { serverUrl?: string } }
  | { ok: true; data: null }
  | { ok: false; error: { code: string; message: string } };

export async function sendRequest(request: RequestMessage): Promise<ResponseMessage> {
  return browser.runtime.sendMessage(request) as Promise<ResponseMessage>;
}
