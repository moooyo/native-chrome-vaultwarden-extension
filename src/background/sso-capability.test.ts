import { describe, expect, it, vi } from 'vitest';

import {
  MIN_SAFE_VAULTWARDEN_SSO_RELEASE,
  MIN_VAULTWARDEN_SSO_PROTOCOL_VERSION,
} from '../core/api/server-capabilities.js';
import type { ServerLease } from '../core/session/account-gate.js';
import { ServerCapabilityManager } from './server-capability-manager.js';
import { authorizeSsoLaunch } from './sso-capability.js';

const SERVER = 'https://vault.example/tenant/';
const VAULT = 'https://vault.example/tenant/vault/';
const IDENTITY = 'https://vault.example/tenant/identity/';
const SSO = 'https://vault.example/tenant/sso/';

describe('standard SSO capability authorization', () => {
  it('requires all Vaultwarden protocol, implementation-release, and positive-probe gates', async () => {
    const ready = makeHarness({
      config: vaultwardenConfig(),
      implementationVersion: MIN_SAFE_VAULTWARDEN_SSO_RELEASE,
    });

    await expect(authorizeSsoLaunch(ready.deps)).resolves.toMatchObject({
      serverUrl: SERVER,
      serverGeneration: 7,
      vaultUrl: VAULT,
      identityUrl: IDENTITY,
      emailTwoFactorMode: 'vaultwarden-device',
    });
    expect(ready.getServerVersion).toHaveBeenCalledOnce();
    expect(ready.probeVaultwardenSso).toHaveBeenCalledWith(IDENTITY);

    const oldProtocol = makeHarness({
      config: vaultwardenConfig({ version: '2025.11.9' }),
      implementationVersion: MIN_SAFE_VAULTWARDEN_SSO_RELEASE,
    });
    await expect(authorizeSsoLaunch(oldProtocol.deps)).rejects.toMatchObject({
      code: 'denied',
    });

    const oldRelease = makeHarness({
      config: vaultwardenConfig(),
      implementationVersion: '1.35.9',
    });
    await expect(authorizeSsoLaunch(oldRelease.deps)).rejects.toMatchObject({
      code: 'denied',
    });

    const failedProbe = makeHarness({
      config: vaultwardenConfig(),
      implementationVersion: MIN_SAFE_VAULTWARDEN_SSO_RELEASE,
      probeError: new Error('unsupported'),
    });
    await expect(authorizeSsoLaunch(failedProbe.deps)).rejects.toMatchObject({
      code: 'denied',
    });
  });

  it('does not require environment.sso for an otherwise eligible Vaultwarden server', async () => {
    const harness = makeHarness({
      config: vaultwardenConfig({
        environment: { vault: VAULT, identity: IDENTITY },
      }),
      implementationVersion: '1.36.0',
    });

    const authorization = await authorizeSsoLaunch(harness.deps);
    expect(authorization.ssoUrl).toBeUndefined();
    expect(authorization.emailTwoFactorMode).toBe('vaultwarden-device');
  });

  it('admits official Bitwarden only when vault, identity, and SSO services stay in-origin', async () => {
    const sameOrigin = makeHarness({ config: officialConfig() });

    const authorization = await authorizeSsoLaunch(sameOrigin.deps);
    expect(authorization).toMatchObject({
      vaultUrl: VAULT,
      identityUrl: IDENTITY,
      ssoUrl: SSO,
      emailTwoFactorMode: 'bitwarden-session',
    });
    expect(sameOrigin.getServerVersion).not.toHaveBeenCalled();
    expect(sameOrigin.probeVaultwardenSso).not.toHaveBeenCalled();

    const splitIdentity = makeHarness({
      config: officialConfig({
        environment: {
          vault: VAULT,
          identity: 'https://identity.example/identity/',
          sso: SSO,
        },
      }),
    });
    await expect(authorizeSsoLaunch(splitIdentity.deps)).rejects.toMatchObject({
      code: 'denied',
    });
  });

  it('rejects unknown server implementations even when all environment URLs look usable', async () => {
    const harness = makeHarness({
      config: {
        version: '2026.8.0',
        server: { name: 'Unknown Password Server' },
        environment: { vault: VAULT, identity: IDENTITY, sso: SSO },
        featureStates: {},
      },
    });

    await expect(authorizeSsoLaunch(harness.deps)).rejects.toMatchObject({
      code: 'denied',
      message: 'Standard SSO is unavailable for this server.',
    });
  });
});

function vaultwardenConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: MIN_VAULTWARDEN_SSO_PROTOCOL_VERSION,
    server: { name: 'Vaultwarden' },
    environment: { vault: VAULT, identity: IDENTITY },
    featureStates: {},
    ...overrides,
  };
}

function officialConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: '2026.8.0',
    server: { name: 'Bitwarden' },
    environment: { vault: VAULT, identity: IDENTITY, sso: SSO },
    featureStates: {},
    ...overrides,
  };
}

function makeHarness(options: {
  config: Record<string, unknown>;
  implementationVersion?: string;
  probeError?: Error;
}) {
  const identityLease = Object.freeze({ id: 'identity-lease' });
  const serverLease: ServerLease = Object.freeze({ serverGeneration: 7, serverUrl: SERVER });
  const assertServerLease = vi.fn((lease: ServerLease) => {
    if (lease !== serverLease) throw new Error('stale server lease');
  });
  const manager = new ServerCapabilityManager<object>({
    captureIdentity: () => ({
      identity: { serverUrl: SERVER },
      lease: identityLease,
    }),
    assertIdentityCurrent: (lease) => {
      if (lease !== identityLease) throw new Error('stale identity lease');
    },
    fetchConfig: async () => ({ body: options.config, responseBytes: 1_024 }),
  });
  const getServerVersion = vi.fn(async () => options.implementationVersion ?? '1.36.0');
  const probeVaultwardenSso = vi.fn(async (_identityUrl: string) => {
    if (options.probeError) throw options.probeError;
  });
  const api = {
    forServer: vi.fn((_serverUrl: string) => ({
      withRequestGuard: (assertCurrent: () => void) => ({
        getServerVersion: async () => {
          assertCurrent();
          return getServerVersion();
        },
        probeVaultwardenSso: async (identityUrl: string) => {
          assertCurrent();
          return probeVaultwardenSso(identityUrl);
        },
      }),
    })),
  };
  return {
    deps: {
      manager,
      api: api as never,
      captureServerLease: () => serverLease,
      assertServerLease,
    },
    api,
    getServerVersion,
    probeVaultwardenSso,
  };
}
