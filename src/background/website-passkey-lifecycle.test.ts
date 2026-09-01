import { describe, expect, it, vi } from 'vitest';
import type { SessionState } from '../core/session/session-manager.js';
import {
  WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION,
  type WebsitePasskeySettings,
} from './settings.js';
import {
  WebsitePasskeyLifecycle,
  type WebsitePasskeyLifecycleSettings,
} from './website-passkey-lifecycle.js';
import { WebsitePasskeyPolicyGate } from './website-passkey-policy.js';
import type { WebsitePasskeyScriptState } from './website-passkey-script-manager.js';

function websiteSettings(
  overrides: Partial<WebsitePasskeySettings> = {},
): WebsitePasskeySettings {
  return {
    schemaVersion: WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION,
    enabled: true,
    excludedDomains: [],
    ...overrides,
  };
}

function deferred<Value>() {
  let resolve!: (value: Value) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<Value>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function makeHarness() {
  let currentSettings: Readonly<WebsitePasskeySettings> = websiteSettings();
  let blockedDomains: readonly string[] = [];
  let currentServer: string | undefined = 'https://vault.example/';
  const source: WebsitePasskeyLifecycleSettings = {
    getWebsitePasskeySettings: vi.fn(async () => currentSettings),
    getAutofillSettings: vi.fn(async () => ({ blockedDomains })),
    getServerUrl: vi.fn(async () => currentServer),
  };
  const gate = new WebsitePasskeyPolicyGate();
  const publish = vi.spyOn(gate, 'publish');
  const invalidate = vi.spyOn(gate, 'invalidate');
  const states: Readonly<WebsitePasskeyScriptState>[] = [];
  const reconcileScripts = vi.fn(async (state: Readonly<WebsitePasskeyScriptState>) => {
    states.push(state);
  });
  const lifecycle = new WebsitePasskeyLifecycle({
    settings: source,
    policy: gate,
    scripts: { reconcile: reconcileScripts },
  });
  return {
    source,
    gate,
    publish,
    invalidate,
    states,
    reconcileScripts,
    lifecycle,
    setSettings(value: Readonly<WebsitePasskeySettings>) {
      currentSettings = value;
    },
    setBlockedDomains(value: readonly string[]) {
      blockedDomains = value;
    },
    setServer(value: string | undefined) {
      currentServer = value;
    },
  };
}

describe('WebsitePasskeyLifecycle publication', () => {
  it('publishes policy before reconciling a frozen script state', async () => {
    const harness = makeHarness();
    const calls: string[] = [];
    harness.publish.mockImplementation((source) => {
      calls.push('publish');
      return WebsitePasskeyPolicyGate.prototype.publish.call(harness.gate, source);
    });
    harness.reconcileScripts.mockImplementation(async (state) => {
      calls.push('scripts');
      harness.states.push(state);
      expect(Object.isFrozen(state)).toBe(true);
      expect(harness.gate.evaluate(harness.gate.capture(), 'https://example.com').allowed).toBe(true);
    });

    await harness.lifecycle.reconcile('locked');

    expect(calls).toEqual(['publish', 'scripts']);
    expect(harness.states).toEqual([{
      enabled: true,
      sessionState: 'locked',
      policyGeneration: 1,
    }]);
  });

  it('deduplicates repeated source and session snapshots without revoking an active lease', async () => {
    const harness = makeHarness();
    await harness.lifecycle.reconcile('unlocked');
    const lease = harness.gate.capture();

    await harness.lifecycle.reconcile('unlocked');
    await harness.lifecycle.reconcile('unlocked');

    expect(harness.publish).toHaveBeenCalledTimes(1);
    expect(harness.invalidate).not.toHaveBeenCalled();
    expect(() => harness.gate.assert(lease)).not.toThrow();
    expect(harness.states.map((state) => state.policyGeneration)).toEqual([1, 1, 1]);
  });

  it('publishes a new generation for settings or server changes', async () => {
    const harness = makeHarness();
    await harness.lifecycle.reconcile('unlocked');
    const settingsLease = harness.gate.capture();

    harness.setSettings(websiteSettings({ excludedDomains: ['blocked.example'] }));
    await harness.lifecycle.reconcile('unlocked');
    expect(() => harness.gate.assert(settingsLease)).toThrow(/policy changed/i);
    expect(harness.gate.evaluate(harness.gate.capture(), 'https://blocked.example').allowed).toBe(false);
    const serverLease = harness.gate.capture();

    harness.setServer('https://new-vault.example/');
    await harness.lifecycle.reconcile('unlocked');
    expect(() => harness.gate.assert(serverLease)).toThrow(/policy changed/i);
    expect(harness.gate.evaluate(harness.gate.capture(), 'https://new-vault.example').allowed).toBe(false);
    expect(harness.publish).toHaveBeenCalledTimes(3);
  });

  it('revokes passkey interactions when the shared blocked-domain policy changes', async () => {
    const harness = makeHarness();
    await harness.lifecycle.reconcile('unlocked');
    const lease = harness.gate.capture();

    harness.setBlockedDomains(['example.com']);
    await harness.lifecycle.reconcile('unlocked');

    expect(() => harness.gate.assert(lease)).toThrow(/policy changed/i);
    expect(harness.gate.evaluate(harness.gate.capture(), 'https://login.example.com').allowed)
      .toBe(false);
  });

  it('invalidates synchronously and republishes an unchanged source after explicit invalidation', async () => {
    const harness = makeHarness();
    await harness.lifecycle.reconcile('unlocked');
    const lease = harness.gate.capture();

    harness.lifecycle.invalidate();

    expect(() => harness.gate.assert(lease)).toThrow(/policy changed/i);
    expect(() => harness.gate.assert(harness.gate.capture())).toThrow(/policy changed/i);
    await harness.lifecycle.reconcile('unlocked');
    expect(harness.publish).toHaveBeenCalledTimes(2);
    expect(harness.gate.evaluate(harness.gate.capture(), 'https://example.com').allowed).toBe(true);
  });

  it('preserves availability across lock and revokes it when the account becomes unavailable', async () => {
    const harness = makeHarness();
    await harness.lifecycle.reconcile('unlocked');
    const unlockedLease = harness.gate.capture();

    const locking = harness.lifecycle.reconcile('locked');
    expect(() => harness.gate.assert(unlockedLease)).not.toThrow();
    await locking;
    const lockedLease = harness.gate.capture();

    const loggingOut = harness.lifecycle.reconcile('loggedOut');
    expect(() => harness.gate.assert(lockedLease)).toThrow(/policy changed/i);
    await loggingOut;

    expect(harness.states.slice(-2)).toEqual([
      { enabled: true, sessionState: 'locked', policyGeneration: 1 },
      { enabled: true, sessionState: 'loggedOut', policyGeneration: 3 },
    ]);
  });
});

describe('WebsitePasskeyLifecycle source consistency and failures', () => {
  it('retries a mixed settings/server read and publishes only a stable pair', async () => {
    const harness = makeHarness();
    const first = websiteSettings({ excludedDomains: ['old.example'] });
    const stable = websiteSettings({ excludedDomains: ['new.example'] });
    vi.mocked(harness.source.getWebsitePasskeySettings)
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(stable)
      .mockResolvedValueOnce(stable);
    vi.mocked(harness.source.getServerUrl).mockResolvedValue('https://new-vault.example/');

    await harness.lifecycle.reconcile('unlocked');

    expect(harness.publish).toHaveBeenCalledTimes(1);
    expect(harness.publish).toHaveBeenCalledWith({
      settings: expect.objectContaining({ excludedDomains: ['new.example'] }),
      blockedDomains: [],
      configuredVaultUrl: 'https://new-vault.example/',
    });
  });

  it('fails closed when the combined source never stabilizes', async () => {
    const harness = makeHarness();
    vi.mocked(harness.source.getWebsitePasskeySettings)
      .mockResolvedValueOnce(websiteSettings({ enabled: true }))
      .mockResolvedValueOnce(websiteSettings({ enabled: false }))
      .mockResolvedValueOnce(websiteSettings({ enabled: true }));

    await expect(harness.lifecycle.reconcile('locked')).rejects.toThrow(/did not stabilize/i);

    expect(harness.publish).not.toHaveBeenCalled();
    expect(() => harness.gate.assert(harness.gate.capture())).toThrow(/policy changed/i);
    expect(harness.states).toEqual([{
      enabled: false,
      sessionState: 'locked',
      policyGeneration: 1,
    }]);
  });

  it('fails closed on a corrupt settings record and recovers on the next reconciliation', async () => {
    const harness = makeHarness();
    await harness.lifecycle.reconcile('unlocked');
    const lease = harness.gate.capture();
    vi.mocked(harness.source.getWebsitePasskeySettings)
      .mockResolvedValueOnce({ enabled: true } as unknown as WebsitePasskeySettings);

    await expect(harness.lifecycle.reconcile('unlocked')).rejects.toThrow(/invalid website passkey settings/i);
    expect(() => harness.gate.assert(lease)).toThrow(/policy changed/i);
    expect(harness.states.at(-1)).toMatchObject({ enabled: false, sessionState: 'unlocked' });

    await expect(harness.lifecycle.reconcile('unlocked')).resolves.toBeUndefined();
    expect(harness.gate.evaluate(harness.gate.capture(), 'https://example.com').allowed).toBe(true);
  });

  it('fails closed when policy publication rejects a corrupt server URL and then recovers', async () => {
    const harness = makeHarness();
    harness.setServer('ftp://vault.example/');

    await expect(harness.lifecycle.reconcile('unlocked')).rejects.toThrow(/invalid vault URL/i);
    expect(() => harness.gate.assert(harness.gate.capture())).toThrow(/policy changed/i);
    expect(harness.states.at(-1)).toMatchObject({ enabled: false });

    harness.setServer('https://vault.example/');
    await harness.lifecycle.reconcile('unlocked');
    expect(harness.gate.evaluate(harness.gate.capture(), 'https://example.com').allowed).toBe(true);
  });

  it('propagates final script errors but leaves the lifecycle retryable without republishing', async () => {
    const harness = makeHarness();
    harness.reconcileScripts.mockRejectedValueOnce(new Error('notification failed'));

    await expect(harness.lifecycle.reconcile('unlocked')).rejects.toThrow('notification failed');
    await expect(harness.lifecycle.reconcile('unlocked')).resolves.toBeUndefined();

    expect(harness.publish).toHaveBeenCalledTimes(1);
    expect(harness.reconcileScripts).toHaveBeenCalledTimes(2);
  });

  it('reports source and fail-closed script failures together', async () => {
    const harness = makeHarness();
    vi.mocked(harness.source.getWebsitePasskeySettings).mockRejectedValueOnce(new Error('storage failed'));
    harness.reconcileScripts.mockRejectedValueOnce(new Error('unregister failed'));

    const error = await harness.lifecycle.reconcile('unlocked').catch((failure: unknown) => failure);

    expect(error).toBeInstanceOf(AggregateError);
    expect((error as AggregateError).errors).toEqual([
      expect.objectContaining({ message: 'storage failed' }),
      expect.objectContaining({ message: 'unregister failed' }),
    ]);
    await expect(harness.lifecycle.reconcile('unlocked')).resolves.toBeUndefined();
  });
});

describe('WebsitePasskeyLifecycle races', () => {
  it('does not let an older asynchronous read overwrite a newer published revision', async () => {
    const harness = makeHarness();
    const oldRead = deferred<Readonly<WebsitePasskeySettings>>();
    const enabled = websiteSettings({ enabled: true });
    const disabled = websiteSettings({ enabled: false });
    vi.mocked(harness.source.getWebsitePasskeySettings)
      .mockImplementationOnce(() => oldRead.promise)
      .mockResolvedValueOnce(disabled)
      .mockResolvedValueOnce(disabled)
      .mockResolvedValueOnce(enabled);

    const oldRevision = harness.lifecycle.reconcile('unlocked');
    const latestRevision = harness.lifecycle.reconcile('unlocked');
    await latestRevision;
    oldRead.resolve(enabled);
    await oldRevision;

    expect(harness.publish).toHaveBeenCalledTimes(1);
    expect(harness.publish.mock.calls[0]?.[0].settings.enabled).toBe(false);
    expect(harness.gate.evaluate(harness.gate.capture(), 'https://example.com')).toMatchObject({
      enabled: false,
      allowed: false,
    });
  });

  it('publishes a new policy while an older script notification is still pending', async () => {
    const harness = makeHarness();
    const releaseFirstNotification = deferred<void>();
    harness.reconcileScripts.mockImplementationOnce(async (state) => {
      harness.states.push(state);
      await releaseFirstNotification.promise;
    });

    const enabling = harness.lifecycle.reconcile('unlocked');
    await vi.waitFor(() => expect(harness.reconcileScripts).toHaveBeenCalledTimes(1));
    harness.setSettings(websiteSettings({ enabled: false }));
    const disabling = harness.lifecycle.reconcile('unlocked');

    await vi.waitFor(() => expect(harness.publish).toHaveBeenCalledTimes(2));
    expect(harness.reconcileScripts).toHaveBeenCalledTimes(1);
    expect(harness.gate.evaluate(harness.gate.capture(), 'https://example.com')).toMatchObject({
      enabled: false,
      allowed: false,
    });

    releaseFirstNotification.resolve();
    await Promise.all([enabling, disabling]);
    expect(harness.states.map((state) => state.enabled)).toEqual([true, false]);
  });

  it('captures an overlapping enable-disable-enable ABA without publishing the stale middle value', async () => {
    const harness = makeHarness();
    harness.setSettings(websiteSettings({ enabled: true }));
    await harness.lifecycle.reconcile('unlocked');
    const originalLease = harness.gate.capture();
    const middleRead = deferred<Readonly<WebsitePasskeySettings>>();
    const finalRead = deferred<Readonly<WebsitePasskeySettings>>();
    const disabled = websiteSettings({ enabled: false });
    const enabled = websiteSettings({ enabled: true });
    vi.mocked(harness.source.getWebsitePasskeySettings)
      .mockImplementationOnce(() => middleRead.promise)
      .mockImplementationOnce(() => finalRead.promise)
      .mockResolvedValueOnce(disabled)
      .mockResolvedValueOnce(enabled);

    const middleRevision = harness.lifecycle.reconcile('unlocked');
    const finalRevision = harness.lifecycle.reconcile('unlocked');
    middleRead.resolve(disabled);
    await middleRevision;

    expect(() => harness.gate.assert(originalLease)).toThrow(/policy changed/i);
    expect(harness.publish).toHaveBeenCalledTimes(1);

    finalRead.resolve(enabled);
    await finalRevision;

    expect(harness.publish).toHaveBeenCalledTimes(2);
    expect(harness.publish.mock.calls.every(([source]) => source.settings.enabled)).toBe(true);
    expect(harness.gate.evaluate(harness.gate.capture(), 'https://example.com').allowed).toBe(true);
  });

  it('captures an overlapping server A-B-A ABA as a policy generation change', async () => {
    const harness = makeHarness();
    await harness.lifecycle.reconcile('unlocked');
    const originalLease = harness.gate.capture();
    const middleRead = deferred<string | undefined>();
    const finalRead = deferred<string | undefined>();
    vi.mocked(harness.source.getServerUrl)
      .mockImplementationOnce(() => middleRead.promise)
      .mockImplementationOnce(() => finalRead.promise)
      .mockResolvedValueOnce('https://middle-vault.example/')
      .mockResolvedValueOnce('https://vault.example/');

    const middleRevision = harness.lifecycle.reconcile('unlocked');
    const finalRevision = harness.lifecycle.reconcile('unlocked');
    middleRead.resolve('https://middle-vault.example/');
    await middleRevision;

    expect(() => harness.gate.assert(originalLease)).toThrow(/policy changed/i);
    expect(harness.publish).toHaveBeenCalledTimes(1);

    finalRead.resolve('https://vault.example/');
    await finalRevision;

    expect(harness.publish).toHaveBeenCalledTimes(2);
    expect(harness.publish.mock.calls.every(([source]) => (
      source.configuredVaultUrl === 'https://vault.example/'
    ))).toBe(true);
    expect(harness.gate.evaluate(harness.gate.capture(), 'https://vault.example').allowed).toBe(false);
  });

  it('republishes only the latest value when an ABA middle read arrives last', async () => {
    const harness = makeHarness();
    await harness.lifecycle.reconcile('unlocked');
    const originalLease = harness.gate.capture();
    const middleRead = deferred<Readonly<WebsitePasskeySettings>>();
    const finalRead = deferred<Readonly<WebsitePasskeySettings>>();
    const disabled = websiteSettings({ enabled: false });
    const enabled = websiteSettings({ enabled: true });
    vi.mocked(harness.source.getWebsitePasskeySettings)
      .mockImplementationOnce(() => middleRead.promise)
      .mockImplementationOnce(() => finalRead.promise)
      .mockResolvedValueOnce(enabled)
      .mockResolvedValueOnce(disabled);

    const middleRevision = harness.lifecycle.reconcile('unlocked');
    const finalRevision = harness.lifecycle.reconcile('unlocked');
    finalRead.resolve(enabled);
    await finalRevision;
    expect(() => harness.gate.assert(originalLease)).not.toThrow();

    middleRead.resolve(disabled);
    await middleRevision;

    expect(() => harness.gate.assert(originalLease)).toThrow(/policy changed/i);
    expect(harness.publish).toHaveBeenCalledTimes(2);
    expect(harness.publish.mock.calls.every(([source]) => source.settings.enabled)).toBe(true);
    expect(harness.gate.evaluate(harness.gate.capture(), 'https://example.com').allowed).toBe(true);
  });

  it('keeps one availability generation across locked-unlocked-locked transitions', async () => {
    const harness = makeHarness();
    await harness.lifecycle.reconcile('locked');
    const lease = harness.gate.capture();

    const unlocking = harness.lifecycle.reconcile('unlocked');
    const locking = harness.lifecycle.reconcile('locked');
    expect(() => harness.gate.assert(lease)).not.toThrow();
    await Promise.all([unlocking, locking]);

    expect(harness.states.at(-1)).toMatchObject({ enabled: true, sessionState: 'locked' });
    expect(harness.publish).toHaveBeenCalledTimes(1);
    expect(harness.gate.evaluate(harness.gate.capture(), 'https://example.com').allowed).toBe(true);
  });

  it('rejects malformed session state before reading settings', () => {
    const harness = makeHarness();

    expect(() => harness.lifecycle.reconcile('unknown' as SessionState))
      .toThrow('Invalid website passkey session state');
    expect(harness.source.getWebsitePasskeySettings).not.toHaveBeenCalled();
  });
});
