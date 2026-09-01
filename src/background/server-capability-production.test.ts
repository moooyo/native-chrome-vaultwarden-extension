import { describe, expect, it, vi } from 'vitest';
import { BITWARDEN_CLIENT_VERSION } from '../core/api/client.js';
import { createServerCapabilityScope, evaluateServerCapabilities, scopeServerObservation } from '../core/api/server-capabilities.js';
import {
  PRODUCTION_SERVER_CAPABILITY_DECLARATION,
  fetchFixedServerConfig,
} from './server-capability-production.js';
import {
  ServerCapabilityManager,
  authorizeSshCipherType5Write,
} from './server-capability-manager.js';

describe('production server capability boundary', () => {
  it('advertises the complete type-5 protocol surface atomically', () => {
    expect(BITWARDEN_CLIENT_VERSION).toBe('2024.12.0');
    expect(PRODUCTION_SERVER_CAPABILITY_DECLARATION).toEqual({
      advertisedProtocolVersion: '2024.12.0',
      supportedCipherTypes: [1, 2, 3, 4, 5],
    });
    expect(Object.isFrozen(PRODUCTION_SERVER_CAPABILITY_DECLARATION)).toBe(true);
    expect(Object.isFrozen(PRODUCTION_SERVER_CAPABILITY_DECLARATION.supportedCipherTypes)).toBe(true);

    const scope = createServerCapabilityScope('https://vault.example/tenant/', 1);
    const capabilities = evaluateServerCapabilities(scope, {
      config: scopeServerObservation(scope, {
        version: '2026.8.0',
        server: {},
        featureStates: { 'ssh-key-vault-item': false },
      }),
    }, PRODUCTION_SERVER_CAPABILITY_DECLARATION);
    expect(capabilities.features.sshCipherType5).toBe('available');
  });

  it('issues a revocable type-5 write authorization with the production declaration', async () => {
    const identityLease = Object.freeze({ generation: 1 });
    const manager = new ServerCapabilityManager({
      captureIdentity: () => ({
        identity: {
          serverUrl: 'https://vault.example/tenant/',
          accountIdentity: 'alice@example.test',
        },
        lease: identityLease,
      }),
      assertIdentityCurrent: (lease) => {
        if (lease !== identityLease) throw new Error('stale account');
      },
      fetchConfig: async () => ({
        body: { version: '2026.8.0', server: {}, featureStates: {} },
        responseBytes: 64,
      }),
      clientDeclaration: PRODUCTION_SERVER_CAPABILITY_DECLARATION,
    });

    const authorization = await authorizeSshCipherType5Write(manager);
    expect(() => authorization.assertCurrent()).not.toThrow();
  });

  it('pins /api/config to the complete canonical base path and byte limit', async () => {
    const getServerConfig = vi.fn(async () => ({ body: {}, responseBytes: 2 }));
    const api = { forServer: vi.fn(() => ({ getServerConfig })) };

    await expect(fetchFixedServerConfig(api, {
      serverUrl: 'https://vault.example/tenant/',
      configUrl: 'https://vault.example/tenant/api/config',
      maxResponseBytes: 65_536,
      credentials: 'omit',
    })).resolves.toEqual({ body: {}, responseBytes: 2 });

    expect(api.forServer).toHaveBeenCalledWith('https://vault.example/tenant/');
    expect(getServerConfig).toHaveBeenCalledWith(65_536);
  });

  it('rejects mutated request semantics before selecting an API client', async () => {
    const api = {
      forServer: vi.fn(() => ({ getServerConfig: vi.fn() })),
    };

    await expect(fetchFixedServerConfig(api, {
      serverUrl: 'https://vault.example/tenant/',
      configUrl: 'https://vault.example/api/config',
      maxResponseBytes: 65_536,
      credentials: 'omit',
    })).rejects.toThrow('The server capability request is invalid');
    expect(api.forServer).not.toHaveBeenCalled();
  });
});
