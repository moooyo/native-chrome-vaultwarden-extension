// @vitest-environment node
// Live SignalR integration test. It is hard-bound to the authorized test-env SSH tunnel.
import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: {}, session: {} } },
}));

import { ApiClient, BITWARDEN_CLIENT_VERSION } from '../../src/core/api/client.js';
import { normalizeServerConfig } from '../../src/core/api/server-capabilities.js';
import {
  deriveMasterKey,
  deriveMasterPasswordHash,
  parseKdfConfig,
  stretchMasterKey,
} from '../../src/core/crypto/kdf.js';
import { unwrapSymmetricKey, type SymmetricKey } from '../../src/core/crypto/keys.js';
import { buildRegistration } from '../../src/core/crypto/registration.js';
import { AccountLeaseGate } from '../../src/core/session/account-gate.js';
import { decryptCipher } from '../../src/core/vault/decrypt.js';
import { encryptCipher } from '../../src/core/vault/encrypt.js';
import { createMemoryStore } from '../../src/platform/store.js';
import { ServerCapabilityManager } from '../../src/background/server-capability-manager.js';
import {
  PRODUCTION_SERVER_CAPABILITY_DECLARATION,
  fetchFixedServerConfig,
} from '../../src/background/server-capability-production.js';
import {
  createVaultNotificationProductionRuntime,
  type VaultNotificationProductionRuntime,
  type VaultNotificationProductionApi,
} from '../../src/background/vault-notification-production.js';
import { VAULT_NOTIFICATION_TYPE } from '../../src/background/vault-notification-lifecycle.js';
import {
  createSignalRNotificationsConnection,
  VAULT_NOTIFICATIONS_RECONNECT_ALARM,
  type NotificationsConnectionFactory,
  type NotificationsHubConnection,
} from '../../src/background/vault-notifications.js';
import {
  createVaultSyncScheduler,
  VAULT_SYNC_ALARM,
  type VaultSyncScheduler,
} from '../../src/background/vault-sync-scheduler.js';

const LIVE = process.env.LIVE === '1';
const AUTHORIZED_SERVER = 'http://127.0.0.1:18082/';
const SERVER = new URL(process.env.MIYU_SERVER ?? AUTHORIZED_SERVER).toString();
const EVENT_TIMEOUT_MS = 30_000;

if (LIVE && SERVER !== AUTHORIZED_SERVER) {
  throw new Error(`notifications live test is restricted to ${AUTHORIZED_SERVER}`);
}

interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
  reject(error: Error): void;
}

interface TokenRequestObservation {
  readonly fields: readonly string[];
  readonly deviceIdentifier?: string;
}

interface RequestObservation {
  readonly pathname: string;
  readonly version?: string;
  readonly credentials?: RequestCredentials;
  readonly token?: TokenRequestObservation;
}

interface NotificationObservation {
  readonly type?: number;
  readonly usedPascalType: boolean;
  readonly usedCamelType: boolean;
  readonly contextMatchesMutatingDevice: boolean;
  readonly contextDiffersFromListeningDevice: boolean;
}

interface NotificationSyncObservation {
  readonly reason: string;
  readonly policy: string;
  readonly sawUpdatedCipher: boolean;
}

class MemoryAlarms {
  private readonly scheduled = new Map<string, Readonly<Record<string, number>>>();

  async get(name: string): Promise<{ name: string } | undefined> {
    return this.scheduled.has(name) ? { name } : undefined;
  }

  async create(name: string, options: Readonly<Record<string, number>>): Promise<void> {
    this.scheduled.set(name, options);
  }

  async clear(name: string): Promise<boolean> {
    return this.scheduled.delete(name);
  }

  async clearAll(): Promise<void> {
    this.scheduled.clear();
  }
}

function deferred<T>(): Deferred<T> {
  let settled = false;
  let resolvePromise!: (value: T) => void;
  let rejectPromise!: (error: Error) => void;
  const promise = new Promise<T>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return {
    promise,
    resolve(value) {
      if (settled) return;
      settled = true;
      resolvePromise(value);
    },
    reject(error) {
      if (settled) return;
      settled = true;
      rejectPromise(error);
    },
  };
}

async function withTimeout<T>(operation: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out`)), EVENT_TIMEOUT_MS);
  });
  try {
    return await Promise.race([operation, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function createObservedFetch(observations: RequestObservation[]): typeof fetch {
  return async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const request = input instanceof Request ? input : undefined;
    const url = new URL(request?.url ?? input.toString());
    const headers = new Headers(init?.headers ?? request?.headers);
    const version = headers.get('Bitwarden-Client-Version') ?? undefined;
    const body = init?.body;
    let token: TokenRequestObservation | undefined;
    if (url.pathname.endsWith('/identity/connect/token') && typeof body === 'string') {
      const form = new URLSearchParams(body);
      const deviceIdentifier = form.get('deviceIdentifier');
      token = Object.freeze({
        fields: Object.freeze([...form.keys()].sort()),
        ...(deviceIdentifier ? { deviceIdentifier } : {}),
      });
    }
    observations.push(Object.freeze({
      pathname: url.pathname,
      ...(version ? { version } : {}),
      ...(init?.credentials ? { credentials: init.credentials } : {}),
      ...(token ? { token } : {}),
    }));
    return globalThis.fetch(input, init);
  };
}

async function requestRegistrationToken(
  fetchFn: typeof fetch,
  email: string,
): Promise<string | undefined> {
  const response = await fetchFn(new URL('identity/accounts/register/send-verification-email', SERVER), {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'Bitwarden-Client-Version': BITWARDEN_CLIENT_VERSION,
    },
    body: JSON.stringify({ email, name: 'Notifications Live Test' }),
  });
  if (response.status === 404) return undefined;
  if (!response.ok) throw new Error(`registration start failed with status ${response.status}`);
  const text = await response.text();
  if (!text.trim()) return undefined;
  let token: unknown;
  try {
    token = JSON.parse(text) as unknown;
  } catch {
    token = text.trim();
  }
  if (typeof token !== 'string' || token.length === 0 || token.length > 16_384) {
    throw new Error('registration start returned an invalid token');
  }
  return token;
}

async function deleteAccount(
  fetchFn: typeof fetch,
  accessToken: string,
  masterPasswordHash: string,
): Promise<void> {
  const response = await fetchFn(new URL('api/accounts', SERVER), {
    method: 'DELETE',
    headers: {
      authorization: `Bearer ${accessToken}`,
      'content-type': 'application/json',
      'Bitwarden-Client-Version': BITWARDEN_CLIENT_VERSION,
    },
    body: JSON.stringify({ masterPasswordHash }),
  });
  if (!response.ok) throw new Error(`account cleanup failed with status ${response.status}`);
}

function clearKey(key: SymmetricKey | undefined): void {
  key?.encKey.fill(0);
  key?.macKey.fill(0);
}

function readAliasedDataProperty(
  value: unknown,
  canonical: string,
  camelCase: string,
): { readonly value?: unknown; readonly hasCanonical: boolean; readonly hasCamelCase: boolean } {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return { hasCanonical: false, hasCamelCase: false };
  }
  const record = value as Record<string, unknown>;
  const canonicalDescriptor = Object.getOwnPropertyDescriptor(record, canonical);
  const camelDescriptor = Object.getOwnPropertyDescriptor(record, camelCase);
  const hasCanonical = Boolean(canonicalDescriptor && 'value' in canonicalDescriptor);
  const hasCamelCase = Boolean(camelDescriptor && 'value' in camelDescriptor);
  const canonicalValue = hasCanonical ? canonicalDescriptor?.value : undefined;
  const camelValue = hasCamelCase ? camelDescriptor?.value : undefined;
  return {
    ...(hasCanonical ? { value: canonicalValue } : hasCamelCase ? { value: camelValue } : {}),
    hasCanonical,
    hasCamelCase,
  };
}

function observeNotification(
  message: unknown,
  listeningDevice: string,
  mutatingDevice: string,
): NotificationObservation {
  const type = readAliasedDataProperty(message, 'Type', 'type');
  const contextId = readAliasedDataProperty(message, 'ContextId', 'contextId').value;
  return Object.freeze({
    ...(typeof type.value === 'number' ? { type: type.value } : {}),
    usedPascalType: type.hasCanonical,
    usedCamelType: type.hasCamelCase,
    contextMatchesMutatingDevice: contextId === mutatingDevice,
    contextDiffersFromListeningDevice: contextId !== listeningDevice,
  });
}

function createObservedConnectionFactory(input: {
  readonly listeningDevice: string;
  readonly mutatingDevice: string;
  readonly events: string[];
  readonly connectionReady: Deferred<void>;
  readonly notificationReceived: Deferred<NotificationObservation>;
  readonly onHubUrl: (hubUrl: string) => void;
}): NotificationsConnectionFactory {
  return (options) => {
    input.events.push('connection-created');
    input.onHubUrl(options.hubUrl);
    const connection = createSignalRNotificationsConnection(options);
    const observed: NotificationsHubConnection = {
      async start(): Promise<void> {
        input.events.push('connection-started');
        try {
          await connection.start();
          input.events.push('connection-ready');
          input.connectionReady.resolve(undefined);
        } catch {
          input.connectionReady.reject(new Error('SignalR connection failed'));
          throw new Error('SignalR connection failed');
        }
      },
      stop: () => connection.stop(),
      on(methodName, handler): void {
        if (methodName !== 'ReceiveMessage') {
          connection.on(methodName, handler);
          return;
        }
        connection.on(methodName, (...args: unknown[]) => {
          const observation = observeNotification(
            args[0],
            input.listeningDevice,
            input.mutatingDevice,
          );
          input.events.push('notification-received');
          input.notificationReceived.resolve(observation);
          return handler(...args);
        });
      },
      onclose: (handler) => connection.onclose(handler),
    };
    return observed;
  };
}

(LIVE ? describe : describe.skip)('live SignalR notifications against test-env', () => {
  it('connects while locked after authoritative catch-up and coalesces another device mutation into sync', async () => {
    const localStoreA = createMemoryStore();
    const localStoreB = createMemoryStore();
    const requestObservationsA: RequestObservation[] = [];
    const requestObservationsB: RequestObservation[] = [];
    const fetchA = createObservedFetch(requestObservationsA);
    const fetchB = createObservedFetch(requestObservationsB);
    const apiA = new ApiClient({
      serverUrlProvider: async () => SERVER,
      fetchFn: fetchA,
      localStore: localStoreA,
    });
    const apiB = new ApiClient({
      serverUrlProvider: async () => SERVER,
      fetchFn: fetchB,
      localStore: localStoreB,
    });
    const unique = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
    const email = `notifications-${unique}@example.com`;
    const password = `Notifications-Live-${unique}-Pass!`;
    const initialName = `Notifications initial ${unique}`;
    const updatedName = `Notifications updated ${unique}`;
    const alarms = new MemoryAlarms();
    const events: string[] = [];
    const connectionReady = deferred<void>();
    const postConnectionCatchUp = deferred<void>();
    const notificationReceived = deferred<NotificationObservation>();
    const notificationSync = deferred<NotificationSyncObservation>();
    const fixedLogEvents: string[] = [];
    let runtime: VaultNotificationProductionRuntime | undefined;
    let syncScheduler: VaultSyncScheduler | undefined;
    let accessTokenA: string | undefined;
    let accessTokenB: string | undefined;
    let masterPasswordHash: string | undefined;
    let masterKey: Uint8Array | undefined;
    let stretched: SymmetricKey | undefined;
    let userKey: SymmetricKey | undefined;
    let registered = false;
    let failure: unknown;
    let cleanupFailure: Error | undefined;

    try {
      const configResponse = await apiA.getServerConfig(65_536);
      const config = normalizeServerConfig(configResponse.body);
      const expectedNotificationsBase = new URL('notifications/', SERVER).toString();
      expect(config.protocolVersion).toMatch(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u);
      expect(config.environment.notifications).toBe(expectedNotificationsBase);
      expect(configResponse.responseBytes).toBeGreaterThan(0);

      const registration = await buildRegistration(email, password);
      masterPasswordHash = registration.masterPasswordHash;
      const emailVerificationToken = await requestRegistrationToken(fetchA, email);
      await apiA.register({
        ...registration,
        masterPasswordHint: '',
        email,
        name: 'Notifications Live Test',
        ...(emailVerificationToken ? { emailVerificationToken } : {}),
      });
      registered = true;

      const prelogin = parseKdfConfig(await apiA.prelogin(email));
      masterKey = await deriveMasterKey(password, email, prelogin);
      expect(await deriveMasterPasswordHash(masterKey, password)).toBe(masterPasswordHash);
      const [loginA, loginB] = await Promise.all([
        apiA.passwordLogin({ email, masterPasswordHash }),
        apiB.passwordLogin({ email, masterPasswordHash }),
      ]);
      expect(loginA.kind).toBe('success');
      expect(loginB.kind).toBe('success');
      if (loginA.kind !== 'success' || loginB.kind !== 'success') {
        throw new Error('registered notification account did not log in on both devices');
      }
      accessTokenA = loginA.data.access_token;
      accessTokenB = loginB.data.access_token;

      const listeningDevice = await apiA.getDeviceIdentifier();
      const mutatingDevice = await apiB.getDeviceIdentifier();
      expect(mutatingDevice).not.toBe(listeningDevice);
      const tokenA = requestObservationsA.find((entry) => entry.token)?.token;
      const tokenB = requestObservationsB.find((entry) => entry.token)?.token;
      const expectedTokenFields = [
        'client_id',
        'deviceIdentifier',
        'deviceName',
        'deviceType',
        'grant_type',
        'password',
        'scope',
        'username',
      ];
      expect(tokenA).toEqual({ fields: expectedTokenFields, deviceIdentifier: listeningDevice });
      expect(tokenB).toEqual({ fields: expectedTokenFields, deviceIdentifier: mutatingDevice });
      expect(tokenA?.fields.some((field) => field.includes('_identifier'))).toBe(false);
      expect(tokenB?.fields.some((field) => field.includes('_identifier'))).toBe(false);

      stretched = await stretchMasterKey(masterKey);
      userKey = await unwrapSymmetricKey(loginA.data.Key, stretched);
      masterKey.fill(0);
      masterKey = undefined;
      clearKey(stretched);
      stretched = undefined;

      const created = await apiB.createCipher(accessTokenB, await encryptCipher({
        type: 1,
        name: initialName,
        login: { username: 'notification-user', password: 'initial-password' },
      }, userKey));

      const accountGate = new AccountLeaseGate();
      accountGate.initialize({ serverUrl: SERVER, accountIdentity: email });
      let catchUpCount = 0;
      let notificationSyncCount = 0;
      syncScheduler = createVaultSyncScheduler({
        getSessionContext: async () => ({
          state: 'unlocked',
          identity: `${SERVER}\n${email}`,
        }),
        requestSync: async (reason, policy) => {
          if (reason !== 'notification') return;
          notificationSyncCount++;
          events.push('notification-sync-started');
          try {
            const sync = await apiA.sync(accessTokenA!);
            const cipher = sync.ciphers.find((candidate) => candidate.id === created.id);
            const decrypted = cipher ? await decryptCipher(cipher, userKey!) : undefined;
            events.push('notification-sync-completed');
            notificationSync.resolve({
              reason,
              policy,
              sawUpdatedCipher: decrypted?.name === updatedName,
            });
          } catch {
            notificationSync.reject(new Error('notification sync failed'));
            throw new Error('notification sync failed');
          }
        },
        rebuildCache: async () => {},
        isDirty: async () => false,
        metadataStore: localStoreA,
        alarms,
        onBackgroundError: () => fixedLogEvents.push('sync_failed'),
      });

      let hubUrl: string | undefined;
      const notificationApi: VaultNotificationProductionApi = {
        getDeviceIdentifier: () => apiA.getDeviceIdentifier(),
      };
      const capabilityApi = {
        forServer: (serverUrl: string) => apiA.forServer(serverUrl),
      };
      const capabilities = new ServerCapabilityManager({
        captureIdentity: () => {
          const lease = accountGate.capture();
          return {
            identity: {
              serverUrl: lease.serverUrl,
              accountIdentity: lease.accountIdentity,
            },
            lease,
          };
        },
        assertIdentityCurrent: (lease) => accountGate.assert(lease),
        fetchConfig: (request) => fetchFixedServerConfig(capabilityApi, request),
        clientDeclaration: PRODUCTION_SERVER_CAPABILITY_DECLARATION,
      });
      runtime = createVaultNotificationProductionRuntime({
        capabilities,
        api: notificationApi,
        auth: {
          getAccountAccessToken: async (accountLease) => {
            accountGate.assert(accountLease);
            return accessTokenA!;
          },
          logout: async () => {},
        },
        vault: {
          sync: async () => {
            catchUpCount++;
            const ordinal = catchUpCount;
            events.push(`catch-up-${ordinal}-started`);
            const sync = await apiA.sync(accessTokenA!);
            if (ordinal === 1) {
              expect(sync.ciphers.some((candidate) => candidate.id === created.id)).toBe(true);
            }
            events.push(`catch-up-${ordinal}-completed`);
            if (ordinal >= 2) postConnectionCatchUp.resolve(undefined);
          },
        },
        syncScheduler,
        captureAccountLease: () => accountGate.capture(),
        assertAccountLease: (lease) => accountGate.assert(lease),
        alarms,
        logger: { warn: (event) => fixedLogEvents.push(event) },
        createConnection: createObservedConnectionFactory({
          listeningDevice,
          mutatingDevice,
          events,
          connectionReady,
          notificationReceived,
          onHubUrl: (value) => { hubUrl = value; },
        }),
      });

      await Promise.all([
        runtime.startup('locked'),
        withTimeout(connectionReady.promise, 'SignalR connection'),
      ]);
      await withTimeout(postConnectionCatchUp.promise, 'post-connection catch-up');

      expect(hubUrl).toBe(new URL('hub', expectedNotificationsBase).toString());
      expect(events.indexOf('catch-up-1-started')).toBeLessThan(
        events.indexOf('connection-created'),
      );
      expect(events.indexOf('catch-up-1-completed')).toBeLessThan(
        events.indexOf('connection-ready'),
      );

      await apiB.updateCipher(accessTokenB, created.id, await encryptCipher({
        type: 1,
        name: updatedName,
        login: { username: 'notification-user', password: 'updated-password' },
      }, userKey));

      const [notification, synchronized] = await Promise.all([
        withTimeout(notificationReceived.promise, 'cross-device notification'),
        withTimeout(notificationSync.promise, 'coalesced notification sync'),
      ]);
      expect(notification).toMatchObject({
        type: VAULT_NOTIFICATION_TYPE.SyncCipherUpdate,
        contextMatchesMutatingDevice: true,
        contextDiffersFromListeningDevice: true,
      });
      expect(notification.usedPascalType || notification.usedCamelType).toBe(true);
      expect(synchronized).toEqual({
        reason: 'notification',
        policy: 'coalesce',
        sawUpdatedCipher: true,
      });
      expect(notificationSyncCount).toBe(1);
      expect(events.indexOf('notification-received')).toBeLessThan(
        events.indexOf('notification-sync-started'),
      );
      expect(fixedLogEvents).toEqual([]);

      const allApiObservations = [...requestObservationsA, ...requestObservationsB];
      expect(allApiObservations.length).toBeGreaterThan(0);
      expect(allApiObservations.every((entry) => entry.version === BITWARDEN_CLIENT_VERSION))
        .toBe(true);
      expect(requestObservationsA.find((entry) => entry.pathname.endsWith('/api/config')))
        .toMatchObject({ credentials: 'omit', version: BITWARDEN_CLIENT_VERSION });
    } catch (error) {
      failure = error;
    } finally {
      try {
        await runtime?.lifecycle.stop();
      } catch {
        cleanupFailure = new Error('notification lifecycle cleanup failed');
      }
      syncScheduler?.dispose();
      await alarms.clear(VAULT_NOTIFICATIONS_RECONNECT_ALARM);
      await alarms.clear(VAULT_SYNC_ALARM);
      await alarms.clearAll();
      masterKey?.fill(0);
      clearKey(stretched);
      clearKey(userKey);
      try {
        if (registered && masterPasswordHash) {
          let cleanupToken = accessTokenA ?? accessTokenB;
          if (!cleanupToken) {
            const cleanupLogin = await apiA.passwordLogin({ email, masterPasswordHash });
            if (cleanupLogin.kind === 'success') cleanupToken = cleanupLogin.data.access_token;
          }
          if (cleanupToken) {
            await deleteAccount(fetchA, cleanupToken, masterPasswordHash);
          } else {
            cleanupFailure ??= new Error('account cleanup authentication failed');
          }
        }
      } catch {
        cleanupFailure ??= new Error('account cleanup failed');
      }
      await localStoreA.clear();
      await localStoreB.clear();
    }

    if (failure && cleanupFailure) {
      throw new AggregateError([failure, cleanupFailure], 'notification test and cleanup failed');
    }
    if (failure) throw failure;
    if (cleanupFailure) throw cleanupFailure;
  }, 180_000);
});
