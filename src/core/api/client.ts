import type { KeyValueStore } from '../../platform/store.js';
import type {
  CipherRequest,
  CipherResponse,
  FolderResponse,
  LoginSuccessResponse,
  PreloginResponse,
  RefreshTokenResponse,
  RegisterRequest,
  SyncResponse,
  TwoFactorRequiredResponse,
} from './types.js';

export interface PasswordLoginInput {
  email: string;
  masterPasswordHash: string;
  twoFactorProvider?: number;
  twoFactorToken?: string;
  remember?: boolean;
}

export type PasswordLoginResult =
  | { kind: 'success'; data: LoginSuccessResponse }
  | { kind: 'twoFactor'; providers: number[]; token?: string };

export type FetchFn = typeof fetch;

export interface ApiClientDeps {
  serverUrlProvider(): Promise<string>;
  fetchFn?: FetchFn;
  localStore: KeyValueStore;
}

const DEVICE_ID_KEY = 'deviceIdentifier';

export class ApiClient {
  private readonly fetchFn: FetchFn;
  private deviceIdentifierPromise: Promise<string> | undefined;

  constructor(private readonly deps: ApiClientDeps) {
    this.fetchFn = deps.fetchFn ?? globalThis.fetch.bind(globalThis);
  }

  async passwordLogin(input: PasswordLoginInput): Promise<PasswordLoginResult> {
    const form = new URLSearchParams();
    form.set('grant_type', 'password');
    form.set('username', input.email.trim().toLowerCase());
    form.set('password', input.masterPasswordHash);
    form.set('scope', 'api offline_access');
    form.set('client_id', 'browser');
    form.set('device_type', '2');
    form.set('device_identifier', await this.getDeviceIdentifier());
    form.set('device_name', 'chrome');
    if (input.twoFactorProvider !== undefined && input.twoFactorToken) {
      form.set('two_factor_provider', String(input.twoFactorProvider));
      form.set('two_factor_token', input.twoFactorToken);
      form.set('two_factor_remember', input.remember ? '1' : '0');
    }

    const response = await this.fetchFn(await this.url('/identity/connect/token'), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    const body = await response.json();
    if (response.ok) return { kind: 'success', data: body as LoginSuccessResponse };

    if (response.status === 400 && isTwoFactorRequired(body)) {
      const raw = body.TwoFactorProviders;
      const providers = (
        Array.isArray(raw)
          ? raw.map(Number)
          : Object.keys(raw).map(Number)
      ).filter(n => !Number.isNaN(n)).sort((a, b) => a - b);
      const result: PasswordLoginResult = {
        kind: 'twoFactor',
        providers,
        ...(body.TwoFactorToken !== undefined ? { token: body.TwoFactorToken } : {}),
      };
      return result;
    }
    throw new ApiHttpError(response.status, body);
  }

  async sendEmailLogin(input: { email: string; twoFactorToken: string }): Promise<void> {
    await this.jsonRequest('/api/two-factor/send-email-login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: input.email.trim().toLowerCase(), token: input.twoFactorToken }),
    });
  }

  async prelogin(email: string): Promise<PreloginResponse> {
    return this.jsonRequest<PreloginResponse>('/identity/accounts/prelogin', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: email.trim().toLowerCase() }),
    });
  }

  /** Register a new account. All key material in `data` is derived client-side (zero-knowledge). */
  async register(data: RegisterRequest): Promise<void> {
    await this.noBodyRequest('/identity/accounts/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(data),
    });
  }

  async refresh(refreshToken: string): Promise<RefreshTokenResponse> {
    const form = new URLSearchParams();
    form.set('grant_type', 'refresh_token');
    form.set('refresh_token', refreshToken);
    form.set('client_id', 'browser');
    form.set('device_type', '2');
    form.set('device_identifier', await this.getDeviceIdentifier());
    form.set('device_name', 'chrome');
    const response = await this.fetchFn(await this.url('/identity/connect/token'), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    const body = await response.json();
    if (!response.ok) throw new ApiHttpError(response.status, body);
    return body as RefreshTokenResponse;
  }

  async sync(accessToken: string): Promise<SyncResponse> {
    return this.jsonRequest<SyncResponse>('/api/sync', {
      method: 'GET',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Create a folder. `encryptedName` is an encType=2 EncString of the folder name. */
  async createFolder(accessToken: string, encryptedName: string): Promise<FolderResponse> {
    return this.jsonRequest<FolderResponse>('/api/folders', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ name: encryptedName }),
    });
  }

  /** Rename a folder. `encryptedName` is an encType=2 EncString of the new name. */
  async updateFolder(accessToken: string, id: string, encryptedName: string): Promise<FolderResponse> {
    return this.jsonRequest<FolderResponse>(`/api/folders/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ name: encryptedName }),
    });
  }

  async deleteFolder(accessToken: string, id: string): Promise<void> {
    await this.noBodyRequest(`/api/folders/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Create a personal cipher. `cipher` carries EncString field values. */
  async createCipher(accessToken: string, cipher: CipherRequest): Promise<CipherResponse> {
    return this.jsonRequest<CipherResponse>('/api/ciphers', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(cipher),
    });
  }

  async updateCipher(accessToken: string, id: string, cipher: CipherRequest): Promise<CipherResponse> {
    return this.jsonRequest<CipherResponse>(`/api/ciphers/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(cipher),
    });
  }

  /** Hard-delete a cipher. */
  async deleteCipher(accessToken: string, id: string): Promise<void> {
    await this.noBodyRequest(`/api/ciphers/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Send a request that may return an empty body (DELETE endpoints); throws on a non-OK status. */
  private async noBodyRequest(path: string, init: RequestInit): Promise<void> {
    const response = await this.fetchFn(await this.url(path), init);
    if (!response.ok) {
      const text = await response.text();
      let body: unknown;
      try { body = JSON.parse(text); } catch { body = text; }
      throw new ApiHttpError(response.status, body);
    }
  }

  async getDeviceIdentifier(): Promise<string> {
    if (!this.deviceIdentifierPromise) {
      this.deviceIdentifierPromise = this.loadOrCreateDeviceIdentifier().catch(error => {
        this.deviceIdentifierPromise = undefined;
        throw error;
      });
    }
    return this.deviceIdentifierPromise;
  }

  private async loadOrCreateDeviceIdentifier(): Promise<string> {
    const existing = await this.deps.localStore.get<string>(DEVICE_ID_KEY);
    if (existing) return existing;
    const id = crypto.randomUUID();
    await this.deps.localStore.set(DEVICE_ID_KEY, id);
    return id;
  }

  private async jsonRequest<T>(path: string, init: RequestInit): Promise<T> {
    const response = await this.fetchFn(await this.url(path), init);
    const text = await response.text();

    if (!response.ok) {
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
      throw new ApiHttpError(response.status, body);
    }

    return JSON.parse(text) as T;
  }

  private async url(path: string): Promise<string> {
    const base = await this.deps.serverUrlProvider();
    const normalized = base.endsWith('/') ? base : `${base}/`;
    return new URL(path.replace(/^\//, ''), normalized).toString();
  }
}

export class ApiHttpError extends Error {
  constructor(public readonly status: number, public readonly body: unknown) {
    super(`Vaultwarden API error ${status}`);
    this.name = 'ApiHttpError';
  }
}

function isTwoFactorRequired(body: unknown): body is TwoFactorRequiredResponse {
  if (typeof body !== 'object' || body === null) return false;
  const candidate = body as Partial<TwoFactorRequiredResponse>;
  return candidate.error === 'invalid_grant'
    && typeof candidate.error_description === 'string'
    && candidate.error_description.toLowerCase().replace('-', ' ').includes('two factor')
    && (Array.isArray(candidate.TwoFactorProviders)
      || (typeof candidate.TwoFactorProviders === 'object' && candidate.TwoFactorProviders !== null));
}
