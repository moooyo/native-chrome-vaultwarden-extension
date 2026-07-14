import type { KeyValueStore } from '../../platform/store.js';
import type {
  CipherRequest,
  CipherResponse,
  CollectionAccess,
  CollectionAccessDetails,
  CollectionResponse,
  EmergencyAccessGrant,
  FolderResponse,
  LoginSuccessResponse,
  OrgPublicKeyResponse,
  PreloginResponse,
  RefreshTokenResponse,
  RegisterRequest,
  RotateKeyData,
  SendFileUploadResponse,
  SendRequest,
  SendResponse,
  SyncResponse,
  TwoFactorRequiredResponse,
  UserPublicKeyResponse,
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
const REQUEST_TIMEOUT_MS = 30_000;

export class ApiClient {
  private readonly fetchFn: FetchFn;
  private deviceIdentifierPromise: Promise<string> | undefined;

  constructor(private readonly deps: ApiClientDeps) {
    this.fetchFn = deps.fetchFn ?? globalThis.fetch.bind(globalThis);
  }

  async passwordLogin(input: PasswordLoginInput): Promise<PasswordLoginResult> {
    const form = await this.baseTokenForm();
    form.set('grant_type', 'password');
    form.set('username', input.email.trim().toLowerCase());
    form.set('password', input.masterPasswordHash);
    form.set('scope', 'api offline_access');
    if (input.twoFactorProvider !== undefined && input.twoFactorToken) {
      form.set('two_factor_provider', String(input.twoFactorProvider));
      form.set('two_factor_token', input.twoFactorToken);
      form.set('two_factor_remember', input.remember ? '1' : '0');
    }

    const { response, body } = await this.tokenRequest(form);
    if (response.ok) {
      if (!isRecord(body) || typeof body.access_token !== 'string') {
        throw new Error('login response is missing access_token');
      }
      return { kind: 'success', data: body as unknown as LoginSuccessResponse };
    }

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
    // Vaultwarden returns 200 with an EMPTY body here, so this must not try to JSON-parse the response.
    await this.noBodyRequest('/api/two-factor/send-email-login', {
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
    const form = await this.baseTokenForm();
    form.set('grant_type', 'refresh_token');
    form.set('refresh_token', refreshToken);
    const { response, body } = await this.tokenRequest(form);
    if (!response.ok) throw new ApiHttpError(response.status, body);
    if (!isRecord(body) || typeof body.access_token !== 'string') {
      throw new Error('refresh response is missing access_token');
    }
    return body as unknown as RefreshTokenResponse;
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

  /** Create a collection in an org. `encryptedName` is an encType=2 EncString under the ORG key.
   *  groups/users are mandatory on Vaultwarden (empty is fine — an access-all manager still sees it). */
  async createCollection(accessToken: string, orgId: string, encryptedName: string): Promise<CollectionResponse> {
    return this.jsonRequest<CollectionResponse>(`/api/organizations/${encodeURIComponent(orgId)}/collections`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ name: encryptedName, groups: [], users: [], externalId: null }),
    });
  }

  /** Fetch a collection's current group/user access so a rename can preserve it (name-only PUT wipes it). */
  async getCollectionDetails(accessToken: string, orgId: string, id: string): Promise<CollectionAccessDetails> {
    return this.jsonRequest<CollectionAccessDetails>(`/api/organizations/${encodeURIComponent(orgId)}/collections/${encodeURIComponent(id)}/details`, {
      method: 'GET',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Rename a collection, RESENDING the preserved groups/users so access is not wiped. */
  async updateCollection(accessToken: string, orgId: string, id: string, encryptedName: string, access: CollectionAccess): Promise<CollectionResponse> {
    return this.jsonRequest<CollectionResponse>(`/api/organizations/${encodeURIComponent(orgId)}/collections/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ name: encryptedName, groups: access.groups, users: access.users, externalId: null }),
    });
  }

  async deleteCollection(accessToken: string, orgId: string, id: string): Promise<void> {
    await this.noBodyRequest(`/api/organizations/${encodeURIComponent(orgId)}/collections/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Set a cipher's collection membership. Return ignored; re-sync is the source of truth. */
  async updateCipherCollections(accessToken: string, id: string, collectionIds: string[]): Promise<void> {
    await this.noBodyRequest(`/api/ciphers/${encodeURIComponent(id)}/collections`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ collectionIds }),
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

  /** Move a personal cipher into an organization (share): re-encrypted under the org key + collections. */
  async shareCipher(accessToken: string, id: string, body: { cipher: CipherRequest; collectionIds: string[] }): Promise<CipherResponse> {
    return this.jsonRequest<CipherResponse>(`/api/ciphers/${encodeURIComponent(id)}/share`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(body),
    });
  }

  /** Hard-delete a cipher. */
  async deleteCipher(accessToken: string, id: string): Promise<void> {
    await this.noBodyRequest(`/api/ciphers/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Soft-delete a cipher: move it to the trash (sets deletedDate server-side; recoverable). */
  async softDeleteCipher(accessToken: string, id: string): Promise<void> {
    await this.noBodyRequest(`/api/ciphers/${encodeURIComponent(id)}/delete`, {
      method: 'PUT',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Restore a cipher from the trash (clears deletedDate server-side). */
  async restoreCipher(accessToken: string, id: string): Promise<void> {
    await this.noBodyRequest(`/api/ciphers/${encodeURIComponent(id)}/restore`, {
      method: 'PUT',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** List the account's Sends. */
  async listSends(accessToken: string): Promise<SendResponse[]> {
    const res = await this.jsonRequest<{ data?: SendResponse[] }>('/api/sends', {
      method: 'GET',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    return res.data ?? [];
  }

  /** Create a (text) Send. */
  async createSend(accessToken: string, send: SendRequest): Promise<SendResponse> {
    return this.jsonRequest<SendResponse>('/api/sends', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(send),
    });
  }

  /** Create a file Send (v2): POST the metadata, get back where to upload the encrypted blob. */
  async createSendFile(accessToken: string, send: SendRequest): Promise<SendFileUploadResponse> {
    return this.jsonRequest<SendFileUploadResponse>('/api/sends/file/v2', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(send),
    });
  }

  /** Upload the encrypted Send file blob to the URL returned by createSendFile (multipart, 204). The
   *  multipart filename is the encrypted file name, mirroring the attachment upload. */
  async uploadSendFileData(accessToken: string, url: string, data: Uint8Array, encryptedFileName: string): Promise<void> {
    const form = new FormData();
    form.append('data', new Blob([data as BlobPart], { type: 'application/octet-stream' }), encryptedFileName);
    if (/^https?:\/\//i.test(url)) {
      // Absolute upload URL (direct-blob storage): gate the bearer token to the configured origin.
      const sameOrigin = await this.isConfiguredOrigin(url);
      const response = await this.fetchWithTimeout(url, {
        method: 'POST',
        headers: sameOrigin ? { authorization: `Bearer ${accessToken}` } : {},
        body: form,
      });
      if (!response.ok) throw new ApiHttpError(response.status, await response.text());
      return;
    }
    const path = url.startsWith('/api') ? url : `/api${url}`;
    await this.noBodyRequest(path, {
      method: 'POST',
      headers: { authorization: `Bearer ${accessToken}` }, // no content-type: browser sets the multipart boundary
      body: form,
    });
  }

  /** Delete a Send. */
  async deleteSend(accessToken: string, id: string): Promise<void> {
    await this.noBodyRequest(`/api/sends/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Update a Send's metadata (PUT). The send key is unchanged; the body carries the existing key. */
  async updateSend(accessToken: string, id: string, send: SendRequest): Promise<SendResponse> {
    return this.jsonRequest<SendResponse>(`/api/sends/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(send),
    });
  }

  /** Remove a Send's password via the dedicated endpoint (PUT /api/sends/{id}/remove-password). */
  async removeSendPassword(accessToken: string, id: string): Promise<void> {
    await this.jsonRequest<SendResponse>(`/api/sends/${encodeURIComponent(id)}/remove-password`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: '{}',
    });
  }

  /** Download an attachment's encrypted blob from its (absolute) URL. */
  async downloadAttachment(url: string, accessToken: string): Promise<Uint8Array> {
    // The URL comes from the sync response and may point off-origin (CDN/blob storage). Only attach the
    // bearer token when the host is the configured server, so a malicious/MITM'd URL can't capture it.
    const sameOrigin = await this.isConfiguredOrigin(url);
    const headers = sameOrigin ? { authorization: `Bearer ${accessToken}` } : {};
    const response = await this.fetchWithTimeout(url, { headers });
    if (!response.ok) throw new ApiHttpError(response.status, await response.text());
    return new Uint8Array(await response.arrayBuffer());
  }

  /** Upload an encrypted attachment (legacy single-POST multipart, supported by Vaultwarden). The
   *  multipart file's filename is the encrypted file name (an EncString); `key` wraps the file key. */
  async uploadAttachment(accessToken: string, cipherId: string, params: { key: string; encryptedFileName: string; data: Uint8Array }): Promise<CipherResponse> {
    const form = new FormData();
    form.append('key', params.key);
    form.append('data', new Blob([params.data as BlobPart], { type: 'application/octet-stream' }), params.encryptedFileName);
    return this.jsonRequest<CipherResponse>(`/api/ciphers/${encodeURIComponent(cipherId)}/attachment`, {
      method: 'POST',
      headers: { authorization: `Bearer ${accessToken}` }, // no content-type: the browser sets the multipart boundary
      body: form,
    });
  }

  /** Delete one attachment from a cipher. */
  async deleteAttachment(accessToken: string, cipherId: string, attachmentId: string): Promise<void> {
    await this.noBodyRequest(`/api/ciphers/${encodeURIComponent(cipherId)}/attachment/${encodeURIComponent(attachmentId)}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }

  /** Change the master password: the UserKey is re-wrapped under the new password (`key`); ciphers stay valid. */
  async changePassword(accessToken: string, body: { masterPasswordHash: string; newMasterPasswordHash: string; key: string; masterPasswordHint?: string }): Promise<void> {
    await this.noBodyRequest('/api/accounts/password', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(body),
    });
  }

  /** Change KDF settings: the UserKey is re-wrapped under the password re-derived with the new KDF. */
  async changeKdf(accessToken: string, body: { kdf: number; kdfIterations: number; masterPasswordHash: string; newMasterPasswordHash: string; key: string }): Promise<void> {
    await this.noBodyRequest('/api/accounts/kdf', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(body),
    });
  }

  async rotateAccountKey(accessToken: string, body: RotateKeyData): Promise<void> {
    await this.noBodyRequest('/api/accounts/key-management/rotate-user-account-keys', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(body),
    });
  }

  /** Grants where THIS user is the grantor (people who can access my vault). Non-empty => rotation fails closed. */
  async getTrustedEmergencyAccess(accessToken: string): Promise<EmergencyAccessGrant[]> {
    const res = await this.jsonRequest<{ data?: EmergencyAccessGrant[] }>('/api/emergency-access/trusted', { method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
    return res.data ?? [];
  }

  async getOrganizationPublicKey(accessToken: string, orgId: string): Promise<OrgPublicKeyResponse> {
    return this.jsonRequest<OrgPublicKeyResponse>(`/api/organizations/${encodeURIComponent(orgId)}/keys`, { method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
  }

  async getAccountPublicKey(accessToken: string): Promise<UserPublicKeyResponse> {
    return this.jsonRequest<UserPublicKeyResponse>('/api/accounts/keys', { method: 'GET', headers: { authorization: `Bearer ${accessToken}` } });
  }

  /** Send a request that may return an empty body (DELETE endpoints); throws on a non-OK status. */
  private async noBodyRequest(path: string, init: RequestInit): Promise<void> {
    const response = await this.fetchWithTimeout(await this.url(path), init);
    if (!response.ok) {
      throw new ApiHttpError(response.status, await this.parseBody(response));
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
    const response = await this.fetchWithTimeout(await this.url(path), init);
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

  /** Shared form for the two /identity/connect/token grants (password + refresh): device fields. */
  private async baseTokenForm(): Promise<URLSearchParams> {
    const form = new URLSearchParams();
    form.set('client_id', 'browser');
    form.set('device_type', '2');
    form.set('device_identifier', await this.getDeviceIdentifier());
    form.set('device_name', 'chrome');
    return form;
  }

  /** POST a token grant and return the raw response + best-effort parsed body (each caller maps status). */
  private async tokenRequest(form: URLSearchParams): Promise<{ response: Response; body: unknown }> {
    const response = await this.fetchWithTimeout(await this.url('/identity/connect/token'), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    return { response, body: await this.parseBody(response) };
  }

  /** Read the body as JSON, falling back to the raw text when it is empty or not JSON. */
  private async parseBody(response: Response): Promise<unknown> {
    const text = await response.text();
    if (!text) return text;
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }

  private async isConfiguredOrigin(url: string): Promise<boolean> {
    try {
      return new URL(url).origin === new URL(await this.deps.serverUrlProvider()).origin;
    } catch {
      return false;
    }
  }

  /** fetch with a hard deadline: aborts the request after REQUEST_TIMEOUT_MS and maps it to a clear error. */
  private async fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      return await this.fetchFn(url, { ...init, signal: controller.signal });
    } catch (error) {
      if (controller.signal.aborted) throw new ApiTimeoutError(REQUEST_TIMEOUT_MS);
      throw error;
    } finally {
      clearTimeout(timer);
    }
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

export class ApiTimeoutError extends Error {
  constructor(public readonly timeoutMs: number) {
    super(`Vaultwarden API request timed out after ${timeoutMs}ms`);
    this.name = 'ApiTimeoutError';
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
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
