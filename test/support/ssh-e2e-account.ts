import { randomUUID } from 'node:crypto';

import { ApiClient, ApiHttpError, BITWARDEN_CLIENT_VERSION } from '../../src/core/api/client.js';
import type { LoginSuccessResponse } from '../../src/core/api/types.js';
import { buildRegistration, type RegistrationKeys } from '../../src/core/crypto/registration.js';
import type { KeyValueStore } from '../../src/platform/store.js';

const AUTHORIZED_SERVER = 'http://127.0.0.1:18082/';
const REQUEST_TIMEOUT_MS = 30_000;

export interface PreparedSshE2eAccount {
  readonly email: string;
  readonly name: string;
  readonly masterPasswordHash: string;
  readonly registration: RegistrationKeys;
}

export interface RegisteredSshE2eAccount {
  readonly accessToken: string;
  readonly login: LoginSuccessResponse;
}

export type AccountCleanupResult = 'deleted' | 'absent';

export function createSshE2eIdentity(): { email: string; password: string; name: string } {
  const emailNonce = randomUUID();
  const passwordNonce = randomUUID();
  return {
    email: `miyu-ssh-e2e-${emailNonce}@example.com`,
    password: `MiYu-Type5-${passwordNonce}-Aa1!`,
    name: 'MiYu SSH E2E',
  };
}

export async function prepareSshE2eAccount(
  email: string,
  password: string,
  name: string,
): Promise<PreparedSshE2eAccount> {
  const registration = await buildRegistration(email, password);
  return Object.freeze({
    email: email.trim().toLowerCase(),
    name,
    masterPasswordHash: registration.masterPasswordHash,
    registration,
  });
}

export async function registerSshE2eAccount(
  serverUrl: string,
  account: PreparedSshE2eAccount,
): Promise<RegisteredSshE2eAccount> {
  const canonicalServer = requireAuthorizedServer(serverUrl);
  const api = createApi(canonicalServer);
  const emailVerificationToken = await requestRegistrationToken(canonicalServer, account.email, account.name);
  await api.register({
    ...account.registration,
    masterPasswordHint: '',
    email: account.email,
    name: account.name,
    ...(emailVerificationToken ? { emailVerificationToken } : {}),
  });
  const login = await api.passwordLogin({
    email: account.email,
    masterPasswordHash: account.masterPasswordHash,
  });
  if (login.kind !== 'success') {
    throw new Error('Disposable account unexpectedly requires two-factor authentication');
  }
  return Object.freeze({ accessToken: login.data.access_token, login: login.data });
}

/**
 * Delete a possibly-created account. Callers arm this before registration so a committed request
 * whose response is lost is still reconciled. A stale preferred token is retried through a fresh
 * password login; invalid credentials then prove that the disposable account is already absent.
 */
export async function cleanupSshE2eAccount(
  serverUrl: string,
  account: PreparedSshE2eAccount,
  preferredAccessToken?: string,
): Promise<AccountCleanupResult> {
  const canonicalServer = requireAuthorizedServer(serverUrl);
  let firstFailure: unknown;
  if (preferredAccessToken) {
    try {
      const status = await deleteAccount(canonicalServer, preferredAccessToken, account.masterPasswordHash);
      if (status >= 200 && status < 300) return 'deleted';
      firstFailure = new Error(`Initial disposable account cleanup failed with HTTP ${status}`);
    } catch (error) {
      firstFailure = error;
    }
  }

  const api = createApi(canonicalServer);
  let login;
  try {
    login = await api.passwordLogin({
      email: account.email,
      masterPasswordHash: account.masterPasswordHash,
    });
  } catch (error) {
    if (error instanceof ApiHttpError && error.status === 400) return 'absent';
    throw new AggregateError(
      [firstFailure, error].filter((failure) => failure !== undefined),
      'Disposable account cleanup login failed',
      { cause: error },
    );
  }
  if (login.kind !== 'success') {
    throw new Error('Disposable account cleanup unexpectedly requires two-factor authentication');
  }
  let status: number;
  try {
    status = await deleteAccount(canonicalServer, login.data.access_token, account.masterPasswordHash);
  } catch (error) {
    throw new AggregateError(
      [firstFailure, error].filter((failure) => failure !== undefined),
      'Disposable account cleanup retry failed',
      { cause: error },
    );
  }
  if (status >= 200 && status < 300) return 'deleted';
  throw new AggregateError(
    [firstFailure, new Error(`Retry cleanup failed with HTTP ${status}`)].filter((failure) => failure !== undefined),
    'Disposable account cleanup failed',
  );
}

function createApi(serverUrl: string): ApiClient {
  return new ApiClient({
    serverUrlProvider: async () => serverUrl,
    fetchFn: fetch,
    localStore: createMemoryStore(),
  });
}

function createMemoryStore(): KeyValueStore {
  const values = new Map<string, unknown>();
  return {
    async get<T>(key: string): Promise<T | undefined> {
      return values.get(key) as T | undefined;
    },
    async set(key: string, value: unknown): Promise<void> {
      values.set(key, value);
    },
    async remove(key: string): Promise<void> {
      values.delete(key);
    },
    async clear(): Promise<void> {
      values.clear();
    },
  };
}

async function requestRegistrationToken(
  serverUrl: string,
  email: string,
  name: string,
): Promise<string | undefined> {
  const response = await boundedFetch(
    new URL('identity/accounts/register/send-verification-email', serverUrl),
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'Bitwarden-Client-Version': BITWARDEN_CLIENT_VERSION,
      },
      body: JSON.stringify({ email, name }),
    },
  );
  if (response.status === 404) return undefined;
  if (!response.ok) throw new Error(`Disposable registration start failed with HTTP ${response.status}`);
  const text = (await response.text()).trim();
  if (!text) return undefined;
  let token: unknown = text;
  try {
    token = JSON.parse(text) as unknown;
  } catch {
    // Vaultwarden versions differ: some return a JSON string, others return the opaque token raw.
  }
  if (typeof token !== 'string' || token.length === 0 || token.length > 8_192 || /\s/u.test(token)) {
    throw new Error('Disposable registration start returned an invalid token');
  }
  return token;
}

async function deleteAccount(
  serverUrl: string,
  accessToken: string,
  masterPasswordHash: string,
): Promise<number> {
  const response = await boundedFetch(new URL('api/accounts', serverUrl), {
    method: 'DELETE',
    headers: {
      authorization: `Bearer ${accessToken}`,
      'content-type': 'application/json',
      'Bitwarden-Client-Version': BITWARDEN_CLIENT_VERSION,
    },
    body: JSON.stringify({ masterPasswordHash }),
  });
  await response.body?.cancel().catch(() => undefined);
  return response.status;
}

async function boundedFetch(url: URL, init: RequestInit): Promise<Response> {
  return fetch(url, {
    ...init,
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
}

function requireAuthorizedServer(serverUrl: string): string {
  let canonical: string;
  try {
    canonical = new URL(serverUrl).toString();
  } catch {
    throw new Error('SSH E2E server URL is invalid');
  }
  if (canonical !== AUTHORIZED_SERVER) {
    throw new Error(`SSH E2E is restricted to ${AUTHORIZED_SERVER}`);
  }
  return canonical;
}
