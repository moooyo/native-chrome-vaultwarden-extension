import { describe, expect, it } from 'vitest';
import {
  ARCHIVE_FEATURE_FLAG,
  MIN_ARCHIVE_PROTOCOL_VERSION,
  UNKNOWN_CIPHER_TYPE_POLICY,
  classifyCipherType,
  createServerCapabilityScope,
  evaluateServerCapabilities,
  isCapabilityAvailable,
  normalizeServerConfig,
  normalizeServerEnvironmentUrl,
  scopeEndpointProbe,
  scopeServerObservation,
} from './server-capabilities.js';

function vaultwardenConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: '2025.12.0',
    server: { name: 'Vaultwarden' },
    featureStates: {},
    ...overrides,
  };
}

describe('server capability scope', () => {
  it('canonicalizes a complete server base URL and binds it to a non-negative generation', () => {
    expect(createServerCapabilityScope(' HTTPS://Vault.Example.Test:443/a ', 4)).toEqual({
      serverUrl: 'https://vault.example.test/a/',
      serverGeneration: 4,
    });
    expect(createServerCapabilityScope('http://LOCALHOST:80/vault', 0)).toEqual({
      serverUrl: 'http://localhost/vault/',
      serverGeneration: 0,
    });
  });

  it.each([
    ['relative URL', '/vault', 0],
    ['non-HTTP URL', 'file:///vault', 0],
    ['insecure remote URL', 'http://vault.example.test', 0],
    ['credentials', 'https://user:password@vault.example.test', 0],
    ['query', 'https://vault.example.test/?tenant=a', 0],
    ['fragment', 'https://vault.example.test/#tenant-a', 0],
    ['encoded separator', 'https://vault.example.test/vault%2fchild', 0],
    ['negative generation', 'https://vault.example.test', -1],
    ['fractional generation', 'https://vault.example.test', 1.5],
  ])('rejects an invalid %s', (_label, url, generation) => {
    expect(() => createServerCapabilityScope(url, generation)).toThrow();
  });
});

describe('server config normalization', () => {
  it('normalizes the server identity, protocol version, and primitive feature states', () => {
    expect(normalizeServerConfig({
      version: '2025.12.0+build.4',
      server: { name: '  Vaultwarden  ' },
      featureStates: {
        [ARCHIVE_FEATURE_FLAG]: true,
        rollout: 25,
        channel: 'stable',
        ignored: null,
      },
    })).toEqual({
      serverKind: 'vaultwarden',
      serverName: 'Vaultwarden',
      protocolVersion: '2025.12.0',
      environment: {},
      featureStates: {
        [ARCHIVE_FEATURE_FLAG]: true,
        rollout: 25,
        channel: 'stable',
      },
    });
  });

  it.each([null, [], true, { version: 'latest' }, { server: { name: 42 } }])(
    'fails closed for malformed or incomplete config: %j',
    (value) => {
      expect(normalizeServerConfig(value)).toMatchObject({
        serverKind: 'unknown',
        featureStates: {},
      });
    },
  );

  it('ignores every feature state when the untrusted map exceeds its bound', () => {
    const featureStates = Object.fromEntries(
      Array.from({ length: 513 }, (_, index) => [`flag-${index}`, true]),
    );
    expect(normalizeServerConfig(vaultwardenConfig({ featureStates })).featureStates).toEqual({});
  });

  it('does not retain an unbounded string feature value', () => {
    expect(normalizeServerConfig(vaultwardenConfig({
      featureStates: { oversized: 'x'.repeat(4_097), retained: 'stable' },
    })).featureStates).toEqual({ retained: 'stable' });
  });

  it('normalizes the real Bitwarden Lite environment shape without retaining unrelated metadata', () => {
    const normalized = normalizeServerConfig({
      version: '2026.8.0',
      server: {},
      environment: {
        vault: 'http://127.0.0.1:18082',
        api: 'http://127.0.0.1:18082/base/api',
        identity: 'https://identity.example.test/tenant',
        notifications: 'https://push.example.test/tenant/notifications',
        sso: 'https://identity.example.test/tenant/sso/',
        fillAssistRules: 'https://example.test/must-not-be-retained',
        arbitrarySecret: 'must-not-escape',
      },
      push: {
        pushTechnology: 0,
        vapidPublicKey: 'must-not-escape',
      },
      featureStates: {},
    });

    expect(normalized).toEqual({
      serverKind: 'unknown',
      protocolVersion: '2026.8.0',
      environment: {
        vault: 'http://127.0.0.1:18082/',
        api: 'http://127.0.0.1:18082/base/api/',
        identity: 'https://identity.example.test/tenant/',
        notifications: 'https://push.example.test/tenant/notifications/',
        sso: 'https://identity.example.test/tenant/sso/',
      },
      featureStates: {},
    });
    expect(JSON.stringify(normalized)).not.toContain('fillAssistRules');
    expect(JSON.stringify(normalized)).not.toContain('must-not-escape');
    expect(Object.isFrozen(normalized.environment)).toBe(true);
  });

  it.each([
    ['relative URL', '/notifications'],
    ['non-HTTP URL', 'wss://push.example.test/notifications'],
    ['insecure remote URL', 'http://push.example.test/notifications'],
    ['credentials', 'https://user:password@push.example.test/notifications'],
    ['query', 'https://push.example.test/notifications?token=secret'],
    ['fragment', 'https://push.example.test/notifications#secret'],
    ['backslash', 'https://push.example.test\\notifications'],
    ['encoded separator', 'https://push.example.test/base%2fnotifications'],
    ['dot segment', 'https://push.example.test/base/../notifications'],
    ['encoded dot segment', 'https://push.example.test/base/%2e%2e/notifications'],
    ['surrounding whitespace', ' https://push.example.test/notifications'],
    ['embedded whitespace', 'https://push.example.test/not ifications'],
  ])('rejects a hostile environment %s', (_label, value) => {
    expect(normalizeServerEnvironmentUrl(value)).toBeUndefined();
  });

  it('preserves service base paths while canonicalizing the trailing slash', () => {
    expect(normalizeServerEnvironmentUrl('https://push.example.test/tenant/notifications'))
      .toBe('https://push.example.test/tenant/notifications/');
    expect(normalizeServerEnvironmentUrl('http://[::1]:18082/base/api'))
      .toBe('http://[::1]:18082/base/api/');
  });
});

describe('scoped capability evidence', () => {
  const scope = createServerCapabilityScope('https://vault.example.test', 3);
  const config = scopeServerObservation(scope, vaultwardenConfig());

  it('ignores config and probes from another generation or origin', () => {
    const oldScope = createServerCapabilityScope('https://vault.example.test', 2);
    const otherOrigin = createServerCapabilityScope('https://other.example.test', 3);
    const result = evaluateServerCapabilities(scope, {
      config: scopeServerObservation(oldScope, vaultwardenConfig({
        featureStates: { [ARCHIVE_FEATURE_FLAG]: true },
      })),
      loginWithDevice: scopeEndpointProbe(otherOrigin, 'supported'),
      fido2TwoFactorProviderMetadata: scopeServerObservation(oldScope, {
        challenge: 'Y2hhbGxlbmdl', rpId: 'vault.example.test',
      }),
    });

    expect(result.config.serverKind).toBe('unknown');
    expect(result.features).toMatchObject({
      fido2TwoFactor: 'unknown',
      loginWithDevice: 'unknown',
      archive: 'unknown',
    });
  });

  it('does not accept evidence from another base path on the same origin', () => {
    const vaultA = createServerCapabilityScope('https://vault.example.test/vault-a', 3);
    const vaultB = createServerCapabilityScope('https://vault.example.test/vault-b', 3);
    const result = evaluateServerCapabilities(vaultB, {
      config: scopeServerObservation(vaultA, vaultwardenConfig({
        featureStates: { [ARCHIVE_FEATURE_FLAG]: true },
      })),
    });

    expect(result.scope.serverUrl).toBe('https://vault.example.test/vault-b/');
    expect(result.config.serverKind).toBe('unknown');
    expect(result.features.archive).toBe('unknown');
  });

  it('maps endpoint probe states without treating transient or unprobed evidence as support', () => {
    expect(evaluateServerCapabilities(scope, {
      config,
      loginWithDevice: scopeEndpointProbe(scope, 'supported'),
    }).features.loginWithDevice).toBe('available');
    expect(evaluateServerCapabilities(scope, {
      config,
      loginWithDevice: scopeEndpointProbe(scope, 'unsupported'),
    }).features.loginWithDevice).toBe('unavailable');
    for (const state of ['unprobed', 'transient_error'] as const) {
      expect(evaluateServerCapabilities(scope, {
        config,
        loginWithDevice: scopeEndpointProbe(scope, state),
      }).features.loginWithDevice).toBe('unknown');
    }
  });
});

describe('authentication capability decisions', () => {
  const scope = createServerCapabilityScope('https://vault.example.test', 3);
  const config = scopeServerObservation(scope, vaultwardenConfig());

  it('enables FIDO2 two-factor only from concrete provider-7 WebAuthn metadata', () => {
    const direct = scopeServerObservation(scope, {
      challenge: 'Y2hhbGxlbmdl',
      rpId: 'vault.example.test',
      allowCredentials: [],
    });
    const providerMap = scopeServerObservation(scope, {
      0: null,
      7: { challenge: 'YW5vdGhlcg', rpId: 'vault.example.test' },
    });

    expect(evaluateServerCapabilities(scope, { config, fido2TwoFactorProviderMetadata: direct })
      .features.fido2TwoFactor).toBe('available');
    expect(evaluateServerCapabilities(scope, { config, fido2TwoFactorProviderMetadata: providerMap })
      .features.fido2TwoFactor).toBe('available');
    expect(evaluateServerCapabilities(scope, {
      config,
      fido2TwoFactorProviderMetadata: scopeServerObservation(scope, {
        challenge: 'not base64url=', rpId: 'https://vault.example.test',
      }),
    }).features.fido2TwoFactor).toBe('unavailable');
    expect(evaluateServerCapabilities(scope, { config }).features.fido2TwoFactor).toBe('unknown');
  });

  it('requires an explicit, well-formed assertion-options payload for account passkey login', () => {
    expect(evaluateServerCapabilities(scope, { config }).features.accountPasskey).toBe('unavailable');
    expect(evaluateServerCapabilities(scope, {
      config,
      accountPasskeyAssertionOptions: scopeServerObservation(scope, {
        token: 'one-time-token',
        options: { challenge: 'Y2hhbGxlbmdl', rpId: 'vault.example.test' },
      }),
    }).features.accountPasskey).toBe('available');
    expect(evaluateServerCapabilities(scope, {
      config,
      accountPasskeyAssertionOptions: scopeServerObservation(scope, {
        token: '', options: { challenge: 'Y2hhbGxlbmdl', rpId: 'vault.example.test' },
      }),
    }).features.accountPasskey).toBe('unavailable');
  });

  it('requires a patched Vaultwarden release, compatible config, and a positive SSO probe', () => {
    const probe = scopeEndpointProbe(scope, 'supported');
    const safeRelease = scopeServerObservation(scope, '1.37.2');
    expect(evaluateServerCapabilities(scope, {
      config,
      implementationVersion: safeRelease,
      vaultwardenSso: probe,
    }).features.vaultwardenSso).toBe('available');

    expect(evaluateServerCapabilities(scope, {
      config,
      implementationVersion: scopeServerObservation(scope, '1.35.0'),
      vaultwardenSso: probe,
    }).features.vaultwardenSso).toBe('unavailable');
    expect(evaluateServerCapabilities(scope, {
      config,
      implementationVersion: scopeServerObservation(scope, '1.36.0-rc.1'),
      vaultwardenSso: probe,
    }).features.vaultwardenSso).toBe('unavailable');
    expect(evaluateServerCapabilities(scope, {
      config,
      vaultwardenSso: probe,
    }).features.vaultwardenSso).toBe('unknown');
  });

  it('does not classify Bitwarden or an unknown server as Vaultwarden SSO', () => {
    const probe = scopeEndpointProbe(scope, 'supported');
    const release = scopeServerObservation(scope, '1.37.2');
    expect(evaluateServerCapabilities(scope, {
      config: scopeServerObservation(scope, {
        version: '2026.8.0', server: { name: 'Bitwarden' }, featureStates: {},
      }),
      implementationVersion: release,
      vaultwardenSso: probe,
    }).features.vaultwardenSso).toBe('unavailable');
    expect(evaluateServerCapabilities(scope, {
      implementationVersion: release,
      vaultwardenSso: probe,
    }).features.vaultwardenSso).toBe('unknown');
  });
});

describe('vault capability decisions', () => {
  const scope = createServerCapabilityScope('https://vault.example.test', 3);

  it('enables SSH type 5 only when both the client and server compatibility are explicit', () => {
    const config = scopeServerObservation(scope, vaultwardenConfig());
    const readyClient = {
      advertisedProtocolVersion: '2024.12.0',
      supportedCipherTypes: [1, 2, 3, 4, 5],
    } as const;
    expect(evaluateServerCapabilities(scope, { config }, readyClient).features.sshCipherType5)
      .toBe('available');
    expect(evaluateServerCapabilities(scope, { config }, {
      supportedCipherTypes: readyClient.supportedCipherTypes,
    }).features.sshCipherType5).toBe('unavailable');
    expect(evaluateServerCapabilities(scope, { config }, {
      advertisedProtocolVersion: '2024.12.0',
      supportedCipherTypes: [1, 2, 3, 4],
    }).features.sshCipherType5).toBe('unavailable');
  });

  it('supports protocol-defined SSH type 5 with an empty server identity', () => {
    const readyClient = {
      advertisedProtocolVersion: '2026.8.0', supportedCipherTypes: [1, 2, 3, 4, 5],
    } as const;
    const liteConfig = scopeServerObservation(scope, {
      version: '2026.8.0',
      server: {},
      environment: {
        api: 'https://vault.example.test/base/api',
        notifications: 'https://vault.example.test/base/notifications',
      },
      featureStates: {},
    });

    const capabilities = evaluateServerCapabilities(scope, { config: liteConfig }, readyClient);
    expect(capabilities.config.serverKind).toBe('unknown');
    expect(capabilities.config.environment.notifications)
      .toBe('https://vault.example.test/base/notifications/');
    expect(capabilities.features.sshCipherType5).toBe('available');
  });

  it('denies SSH below the minimum or without a complete client declaration', () => {
    const readyClient = {
      advertisedProtocolVersion: '2025.12.0', supportedCipherTypes: [5],
    } as const;
    expect(evaluateServerCapabilities(scope, {
      config: scopeServerObservation(scope, {
        version: '2024.11.0', server: {}, featureStates: {},
      }),
    }, readyClient).features.sshCipherType5).toBe('unavailable');
    expect(evaluateServerCapabilities(scope, {
      config: scopeServerObservation(scope, {
        version: '2026.8.0', server: {}, featureStates: {},
      }),
    }, {
      advertisedProtocolVersion: '2026.8.0', supportedCipherTypes: [1, 2, 3, 4],
    }).features.sshCipherType5).toBe('unavailable');
    expect(evaluateServerCapabilities(scope, {}, readyClient).features.sshCipherType5).toBe('unknown');
  });

  it('ignores the obsolete SSH feature flag after protocol and client gates pass', () => {
    const readyClient = {
      advertisedProtocolVersion: '2024.12.0', supportedCipherTypes: [1, 2, 3, 4, 5],
    } as const;
    const config = scopeServerObservation(scope, vaultwardenConfig({
      featureStates: { 'ssh-key-vault-item': false },
    }));

    expect(evaluateServerCapabilities(scope, { config }, readyClient).features.sshCipherType5)
      .toBe('available');
  });

  it('honors an explicit boolean archive flag before protocol-version inference', () => {
    const enabledWithoutVersion = scopeServerObservation(scope, {
      server: {}, featureStates: { [ARCHIVE_FEATURE_FLAG]: true },
    });
    const disabledWithoutVersion = scopeServerObservation(scope, {
      server: {}, featureStates: { [ARCHIVE_FEATURE_FLAG]: false },
    });
    const disabledOnNewProtocol = scopeServerObservation(scope, {
      version: '2026.8.0', server: {}, featureStates: { [ARCHIVE_FEATURE_FLAG]: false },
    });

    expect(evaluateServerCapabilities(scope, { config: enabledWithoutVersion }).features.archive)
      .toBe('available');
    expect(evaluateServerCapabilities(scope, { config: disabledWithoutVersion }).features.archive)
      .toBe('unavailable');
    expect(evaluateServerCapabilities(scope, { config: disabledOnNewProtocol }).features.archive)
      .toBe('unavailable');
  });

  it.each([
    MIN_ARCHIVE_PROTOCOL_VERSION,
    '2026.8.0',
    '2027.1.0',
  ])('infers archive support from protocol %s after the flag was removed', (version) => {
    const config = scopeServerObservation(scope, {
      version, server: {}, featureStates: {},
    });
    expect(evaluateServerCapabilities(scope, { config }).features.archive).toBe('available');
  });

  it.each([
    '2025.12.0',
    '2026.3.99',
    '2026.4.0-rc.1',
  ])('keeps archive unavailable on pre-removal protocol %s without a flag', (version) => {
    const config = scopeServerObservation(scope, {
      version, server: {}, featureStates: {},
    });
    expect(evaluateServerCapabilities(scope, { config }).features.archive).toBe('unavailable');
  });

  it('keeps archive unknown without config or when the available evidence is indeterminate', () => {
    const missingVersion = scopeServerObservation(scope, {
      server: {}, featureStates: {},
    });
    const invalidVersion = scopeServerObservation(scope, {
      version: 'latest', server: {}, featureStates: {},
    });
    const nonBooleanFlag = scopeServerObservation(scope, {
      version: '2026.8.0', server: {}, featureStates: { [ARCHIVE_FEATURE_FLAG]: 'true' },
    });

    expect(evaluateServerCapabilities(scope).features.archive).toBe('unknown');
    expect(evaluateServerCapabilities(scope, { config: missingVersion }).features.archive)
      .toBe('unknown');
    expect(evaluateServerCapabilities(scope, { config: invalidVersion }).features.archive)
      .toBe('unknown');
    expect(evaluateServerCapabilities(scope, { config: nonBooleanFlag }).features.archive)
      .toBe('unknown');
  });
});

describe('unknown cipher type policy', () => {
  it('allows only explicitly supported cipher types to materialize secrets or mutate', () => {
    expect(classifyCipherType(5, [1, 2, 3, 4, 5])).toEqual({
      kind: 'supported',
      type: 5,
      preserveEncrypted: true,
      allowSecretMaterialization: true,
      allowMutation: true,
      exportBehavior: 'include',
    });
    expect(classifyCipherType(6, [1, 2, 3, 4, 5])).toEqual({
      kind: 'unknown',
      type: 6,
      ...UNKNOWN_CIPHER_TYPE_POLICY,
    });
    expect(classifyCipherType(256, [1, 2, 3, 4, 5])).toMatchObject({
      kind: 'unknown',
      type: 256,
    });
  });

  it.each([0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, '6', null])('rejects invalid cipher type %j', (type) => {
    expect(classifyCipherType(type, [1, 2, 3, 4, 5])).toEqual({
      kind: 'invalid',
      preserveEncrypted: false,
      allowSecretMaterialization: false,
      allowMutation: false,
      exportBehavior: 'reject',
    });
  });

  it('keeps unknown behavior fail closed and exposes an exact availability helper', () => {
    expect(UNKNOWN_CIPHER_TYPE_POLICY).toEqual({
      preserveEncrypted: true,
      allowSecretMaterialization: false,
      allowMutation: false,
      exportBehavior: 'reject',
    });
    expect(isCapabilityAvailable('available')).toBe(true);
    expect(isCapabilityAvailable('unknown')).toBe(false);
    expect(isCapabilityAvailable('unavailable')).toBe(false);
  });
});
