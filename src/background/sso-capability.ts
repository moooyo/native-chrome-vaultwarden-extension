import type { ApiClient } from '../core/api/client.js';
import { AppError } from '../core/errors.js';
import {
  evaluateServerCapabilities,
  scopeEndpointProbe,
  scopeServerObservation,
} from '../core/api/server-capabilities.js';
import type { ServerLease } from '../core/session/account-gate.js';
import type {
  ServerCapabilityLease,
  ServerCapabilityManager,
  ServerCapabilitySnapshot,
} from './server-capability-manager.js';

export interface SsoLaunchAuthorization {
  readonly serverUrl: string;
  readonly serverGeneration: number;
  readonly capabilityGeneration: number;
  readonly vaultUrl: string;
  readonly identityUrl: string;
  readonly ssoUrl?: string;
  readonly emailTwoFactorMode: 'vaultwarden-device' | 'bitwarden-session';
  assertCurrent(): void;
}

export interface SsoCapabilityDeps<IdentityLease extends object> {
  readonly manager: ServerCapabilityManager<IdentityLease>;
  readonly api: Pick<ApiClient, 'forServer'>;
  readonly captureServerLease: () => ServerLease;
  readonly assertServerLease: (lease: ServerLease) => void;
}

/** Resolve one fail-closed standard SSO launch against the current server capability generation. */
export async function authorizeSsoLaunch<IdentityLease extends object>(
  deps: SsoCapabilityDeps<IdentityLease>,
): Promise<SsoLaunchAuthorization> {
  const serverLease = deps.captureServerLease();
  deps.assertServerLease(serverLease);
  await deps.manager.resolve({ forceRefresh: true });
  deps.assertServerLease(serverLease);
  const capabilityLease = deps.manager.capture();
  const snapshot = deps.manager.assert(capabilityLease);
  const endpoints = requireSsoEndpoints(snapshot);
  assertSameServerService(serverLease.serverUrl, endpoints.vaultUrl, 'Web Vault');
  assertSameServerService(serverLease.serverUrl, endpoints.identityUrl, 'Identity');

  const emailTwoFactorMode = snapshot.capabilities.config.serverKind === 'vaultwarden'
    ? 'vaultwarden-device' as const
    : 'bitwarden-session' as const;
  if (snapshot.capabilities.config.serverKind === 'vaultwarden') {
    await assertVaultwardenSsoAvailable(deps, serverLease, capabilityLease, snapshot, endpoints.identityUrl);
  } else if (!isKnownBitwarden(snapshot)) {
    throw unavailable();
  } else {
    if (!endpoints.ssoUrl) throw unavailable();
    assertSameServerService(serverLease.serverUrl, endpoints.ssoUrl, 'SSO');
  }

  const initial = Object.freeze({
    serverUrl: serverLease.serverUrl,
    serverGeneration: serverLease.serverGeneration,
    capabilityGeneration: capabilityLease.generation,
    emailTwoFactorMode,
    ...endpoints,
  });
  const assertCurrent = (): void => {
    try {
      deps.assertServerLease(serverLease);
      const current = requireSsoEndpoints(deps.manager.assert(capabilityLease));
      if (
        current.vaultUrl !== initial.vaultUrl
        || current.identityUrl !== initial.identityUrl
        || current.ssoUrl !== initial.ssoUrl
      ) throw unavailable();
    } catch {
      throw unavailable();
    }
  };
  assertCurrent();
  return Object.freeze({ ...initial, assertCurrent });
}

async function assertVaultwardenSsoAvailable<IdentityLease extends object>(
  deps: SsoCapabilityDeps<IdentityLease>,
  serverLease: ServerLease,
  capabilityLease: ServerCapabilityLease,
  snapshot: ServerCapabilitySnapshot,
  identityUrl: string,
): Promise<void> {
  const fixed = deps.api
    .forServer(serverLease.serverUrl)
    .withRequestGuard(() => {
      deps.assertServerLease(serverLease);
      deps.manager.assert(capabilityLease);
    });
  let implementationVersion: string;
  try {
    implementationVersion = await fixed.getServerVersion();
    deps.assertServerLease(serverLease);
    deps.manager.assert(capabilityLease);
    await fixed.probeVaultwardenSso(identityUrl);
    deps.assertServerLease(serverLease);
    deps.manager.assert(capabilityLease);
  } catch {
    throw unavailable();
  }
  const scope = snapshot.capabilities.scope;
  const config = snapshot.capabilities.config;
  const evaluated = evaluateServerCapabilities(scope, {
    config: scopeServerObservation(scope, {
      ...(config.protocolVersion ? { version: config.protocolVersion } : {}),
      server: { name: config.serverName ?? 'Vaultwarden' },
      environment: config.environment,
      featureStates: config.featureStates,
    }),
    implementationVersion: scopeServerObservation(scope, implementationVersion),
    vaultwardenSso: scopeEndpointProbe(scope, 'supported'),
  });
  if (evaluated.features.vaultwardenSso !== 'available') throw unavailable();
}

function requireSsoEndpoints(snapshot: ServerCapabilitySnapshot): {
  readonly vaultUrl: string;
  readonly identityUrl: string;
  readonly ssoUrl?: string;
} {
  const environment = snapshot.capabilities.config.environment;
  if (snapshot.availability !== 'available' || !environment.vault || !environment.identity) {
    throw unavailable();
  }
  return Object.freeze({
    vaultUrl: environment.vault,
    identityUrl: environment.identity,
    ...(environment.sso ? { ssoUrl: environment.sso } : {}),
  });
}

function isKnownBitwarden(snapshot: ServerCapabilitySnapshot): boolean {
  const config = snapshot.capabilities.config;
  if (config.serverKind === 'bitwarden') return true;
  return config.serverKind === 'unknown'
    && config.serverName === undefined
    && config.protocolVersion !== undefined;
}

function assertSameServerService(serverUrl: string, serviceUrl: string, label: string): void {
  const server = new URL(serverUrl);
  const service = new URL(serviceUrl);
  const basePath = server.pathname.endsWith('/') ? server.pathname : `${server.pathname}/`;
  if (
    server.origin !== service.origin
    || !service.pathname.startsWith(basePath)
    || service.username
    || service.password
  ) {
    throw new AppError('denied', `${label} uses an unsupported split-origin service.`);
  }
}

function unavailable(): AppError {
  return new AppError('denied', 'Standard SSO is unavailable for this server.');
}
