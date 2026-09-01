import { describe, expect, it, vi } from 'vitest';
import {
  WebsitePasskeyPolicyGate,
  defaultWebsitePasskeyPolicySource,
} from './website-passkey-policy.js';
import {
  WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION,
  type WebsitePasskeySettings,
} from './settings.js';

function settings(overrides: Partial<WebsitePasskeySettings> = {}): WebsitePasskeySettings {
  return {
    schemaVersion: WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION,
    enabled: true,
    excludedDomains: [],
    ...overrides,
  };
}

describe('WebsitePasskeyPolicyGate URL policy', () => {
  it('is fail-closed before a snapshot is published and with the default disabled snapshot', () => {
    const gate = new WebsitePasskeyPolicyGate();
    expect(() => gate.evaluate(gate.capture(), 'https://example.com')).toThrow(/policy changed/i);

    gate.publish(defaultWebsitePasskeyPolicySource());
    expect(gate.evaluate(gate.capture(), 'https://example.com')).toEqual({
      enabled: false,
      allowed: false,
      host: 'example.com',
    });
  });

  it.each([
    ['https://example.com/login', 'example.com'],
    ['https://BÜCHER.example/login', 'xn--bcher-kva.example'],
    ['http://localhost:8080/login', 'localhost'],
    ['http://127.0.0.1:8080/login', '127.0.0.1'],
    ['http://127.1/login', '127.0.0.1'],
  ])('allows supported browser URL %s', (url, host) => {
    const gate = new WebsitePasskeyPolicyGate();
    gate.publish({ settings: settings(), configuredVaultUrl: 'https://vault.example/base/' });

    expect(gate.evaluate(gate.capture(), url)).toEqual({ enabled: true, allowed: true, host });
  });

  it.each([
    'http://example.com',
    'http://127.0.0.2',
    'http://[::1]',
    'file:///tmp/passkey',
    'data:text/plain,passkey',
    'https://user@example.com',
    'https://user:secret@example.com',
    'not a URL',
    'https://example.com/\u0000',
  ])('rejects unsupported or ambiguous browser URL %s', (url) => {
    const gate = new WebsitePasskeyPolicyGate();
    gate.publish({ settings: settings() });
    const decision = gate.evaluate(gate.capture(), url);

    expect(decision.allowed).toBe(false);
    expect(Object.keys(decision).every((key) => ['enabled', 'allowed', 'host'].includes(key))).toBe(true);
  });

  it('blocks only an exact canonical excluded hostname', () => {
    const gate = new WebsitePasskeyPolicyGate();
    gate.publish({ settings: settings({ excludedDomains: ['BÜCHER.example'] }) });
    const lease = gate.capture();

    expect(gate.evaluate(lease, 'https://bücher.example/login')).toMatchObject({ allowed: false });
    expect(gate.evaluate(lease, 'https://login.bücher.example/login')).toMatchObject({ allowed: true });
    expect(gate.evaluate(lease, 'https://notbücher.example/login')).toMatchObject({ allowed: true });
  });

  it('blocks the configured vault origin regardless of path and normalizes a trailing dot', () => {
    const gate = new WebsitePasskeyPolicyGate();
    gate.publish({ settings: settings(), configuredVaultUrl: 'https://Vault.Example./base/' });
    const lease = gate.capture();

    expect(gate.evaluate(lease, 'https://vault.example/login')).toMatchObject({ allowed: false });
    expect(gate.evaluate(lease, 'https://vault.example:8443/login')).toMatchObject({ allowed: true });
    expect(gate.evaluate(lease, 'https://other.example/login')).toMatchObject({ allowed: true });
  });

  it('applies the shared autofill blocked-domain rules to passkey interactions', () => {
    const gate = new WebsitePasskeyPolicyGate();
    gate.publish({
      settings: settings(),
      blockedDomains: ['blocked.example', 'https://origin.example:8443'],
    });
    const lease = gate.capture();

    expect(gate.evaluate(lease, 'https://login.blocked.example/passkey').allowed).toBe(false);
    expect(gate.evaluate(lease, 'https://origin.example:8443/passkey').allowed).toBe(false);
    expect(gate.evaluate(lease, 'https://origin.example/passkey').allowed).toBe(true);
  });

  it('rejects an invalid configured vault URL and revokes the previous snapshot first', () => {
    const gate = new WebsitePasskeyPolicyGate();
    gate.publish({ settings: settings(), configuredVaultUrl: 'https://vault.example' });
    const oldLease = gate.capture();

    expect(() => gate.publish({ settings: settings(), configuredVaultUrl: 'ftp://vault.example' }))
      .toThrow(/invalid vault URL/i);
    expect(() => gate.assert(oldLease)).toThrow(/policy changed/i);
    expect(() => gate.evaluate(gate.capture(), 'https://example.com')).toThrow(/policy changed/i);
  });
});

describe('WebsitePasskeyPolicyGate revocation', () => {
  it('rejects forged and foreign leases', () => {
    const first = new WebsitePasskeyPolicyGate();
    const second = new WebsitePasskeyPolicyGate();
    first.publish({ settings: settings() });
    second.publish({ settings: settings() });

    expect(() => first.assert({ generation: 1 })).toThrow();
    expect(() => first.assert(second.capture())).toThrow();
  });

  it('revokes an old lease across disabled-to-enabled ABA publication', () => {
    const gate = new WebsitePasskeyPolicyGate();
    gate.publish({ settings: settings({ enabled: true }) });
    const lease = gate.capture();
    expect(gate.evaluate(lease, 'https://example.com').allowed).toBe(true);

    gate.publish({ settings: settings({ enabled: false }) });
    gate.publish({ settings: settings({ enabled: true }) });

    expect(() => gate.assert(lease)).toThrow(/policy changed/i);
    expect(gate.evaluate(gate.capture(), 'https://example.com').allowed).toBe(true);
  });

  it('invalidates synchronously for settings, session, or server transition callers', () => {
    const gate = new WebsitePasskeyPolicyGate();
    gate.publish({ settings: settings() });
    const lease = gate.capture();

    gate.invalidate();

    expect(() => gate.assert(lease)).toThrow(/policy changed/i);
    expect(() => gate.assert(gate.capture())).toThrow(/policy changed/i);
  });

  it('reasserts after an injected interaction decision and fails closed on callback errors', () => {
    const invalidatingDecision = vi.fn(() => {
      gate.invalidate();
      return false;
    });
    const gate = new WebsitePasskeyPolicyGate({ isInteractionBlocked: invalidatingDecision });
    gate.publish({ settings: settings() });

    expect(() => gate.evaluate(gate.capture(), 'https://Example.COM/login')).toThrow(/policy changed/i);
    expect(invalidatingDecision).toHaveBeenCalledWith('https://example.com/login');

    const throwingGate = new WebsitePasskeyPolicyGate({
      isInteractionBlocked: () => { throw new Error('unavailable'); },
    });
    throwingGate.publish({ settings: settings() });
    expect(throwingGate.evaluate(throwingGate.capture(), 'https://example.com'))
      .toMatchObject({ allowed: false });
  });

  it('honors an injected blocked-interaction decision and returns a frozen public decision', () => {
    const blocked = new WebsitePasskeyPolicyGate({ isInteractionBlocked: () => true });
    blocked.publish({ settings: settings() });
    const denied = blocked.evaluate(blocked.capture(), 'https://example.com');
    expect(denied).toEqual({ enabled: true, allowed: false, host: 'example.com' });
    expect(Object.isFrozen(denied)).toBe(true);

    const allowed = new WebsitePasskeyPolicyGate({ isInteractionBlocked: () => false });
    allowed.publish({ settings: settings() });
    const lease = allowed.capture();
    expect(allowed.assertAllowed(lease, 'https://example.com')).toEqual({
      enabled: true,
      allowed: true,
      host: 'example.com',
    });
  });
});
