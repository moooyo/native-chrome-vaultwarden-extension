import type { KeyValueStore } from '../../platform/store.js';
import type { PreloginResponse } from './types.js';

export type FetchFn = typeof fetch;

export interface ApiClientDeps {
  serverUrlProvider(): Promise<string>;
  fetchFn?: FetchFn;
  localStore: KeyValueStore;
}

const DEVICE_ID_KEY = 'deviceIdentifier';

export class ApiClient {
  private readonly fetchFn: FetchFn;

  constructor(private readonly deps: ApiClientDeps) {
    this.fetchFn = deps.fetchFn ?? globalThis.fetch.bind(globalThis);
  }

  async prelogin(email: string): Promise<PreloginResponse> {
    return this.jsonRequest<PreloginResponse>('/identity/accounts/prelogin', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: email.trim().toLowerCase() }),
    });
  }

  async getDeviceIdentifier(): Promise<string> {
    const existing = await this.deps.localStore.get<string>(DEVICE_ID_KEY);
    if (existing) return existing;
    const id = crypto.randomUUID();
    await this.deps.localStore.set(DEVICE_ID_KEY, id);
    return id;
  }

  private async jsonRequest<T>(path: string, init: RequestInit): Promise<T> {
    const response = await this.fetchFn(await this.url(path), init);
    const text = await response.text();
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      body = text || null;
    }
    if (!response.ok) {
      throw new ApiHttpError(response.status, body);
    }
    return body as T;
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
  }
}
