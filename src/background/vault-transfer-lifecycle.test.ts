import { describe, expect, it, vi } from 'vitest';
import {
  createVaultTransferLeaseBindings,
  createVaultTransferLifecycle,
  createVaultTransferReadiness,
  registerVaultTransferPortListener,
  type VaultTransferLifecycleController,
} from './vault-transfer-lifecycle.js';

function deferred(): { readonly promise: Promise<void>; readonly resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

function controller(
  overrides: Partial<VaultTransferLifecycleController> = {},
): VaultTransferLifecycleController {
  return {
    revokeAll: vi.fn(async () => 0),
    inspectJournalForStartup: vi.fn(async () => ({ kind: 'none' })),
    reconcileCurrentAccount: vi.fn(async () => ({ reconciled: 0 })),
    ...overrides,
  };
}

function leaseGate() {
  let generation = 0;
  const issued = new WeakSet<object>();
  return {
    capture() {
      const lease = Object.freeze({ generation });
      issued.add(lease);
      return lease;
    },
    assert(lease: { readonly generation: number }) {
      if (!issued.has(lease) || lease.generation !== generation) throw new Error('stale lease');
    },
    invalidate() { generation += 1; },
  };
}

describe('vault transfer lease bindings', () => {
  it('keeps staged plaintext policy-bound without pinning the controller across policy publication', () => {
    const account = leaseGate();
    const session = leaseGate();
    const policy = leaseGate();
    const bindings = createVaultTransferLeaseBindings(account, session, policy);
    const stagedPlaintext = bindings.captureSecurity();
    const commitContext = bindings.captureAccountSession();

    policy.invalidate();

    expect(() => bindings.assertSecurity(stagedPlaintext)).toThrow('stale lease');
    expect(() => bindings.assertAccountSession(commitContext)).not.toThrow();
    session.invalidate();
    expect(() => bindings.assertAccountSession(commitContext)).toThrow('stale lease');
  });
});

describe('vault transfer lifecycle', () => {
  it('invokes memory revocation synchronously and holds reconciliation behind durable cleanup', async () => {
    const cleanup = deferred();
    let revoked = false;
    const reconcileCurrentAccount = vi.fn(async () => undefined);
    const lifecycle = createVaultTransferLifecycle(controller({
      revokeAll: vi.fn(() => {
        revoked = true;
        return cleanup.promise.then(() => 1);
      }),
      reconcileCurrentAccount,
    }), vi.fn());

    lifecycle.revokeAtTransitionStart();
    const reconciling = lifecycle.reconcile();

    expect(revoked).toBe(true);
    await Promise.resolve();
    expect(reconcileCurrentAccount).not.toHaveBeenCalled();
    cleanup.resolve();
    await reconciling;
    expect(reconcileCurrentAccount).toHaveBeenCalledOnce();
  });

  it('still invokes transition revocation while reconciliation is pending', async () => {
    const reconciliation = deferred();
    let revoked = false;
    const reconcileCurrentAccount = vi.fn(() => reconciliation.promise);
    const lifecycle = createVaultTransferLifecycle(controller({
      reconcileCurrentAccount,
      revokeAll: vi.fn(async () => {
        revoked = true;
        return 0;
      }),
    }), vi.fn());
    const pending = lifecycle.reconcile();
    await vi.waitFor(() => expect(reconcileCurrentAccount).toHaveBeenCalledOnce());

    lifecycle.revokeAtTransitionStart();

    expect(revoked).toBe(true);
    reconciliation.resolve();
    await pending;
  });

  it('contains a synchronous revocation adapter failure without failing the auth transition', () => {
    const failure = new Error('adapter failed synchronously');
    const onError = vi.fn();
    const lifecycle = createVaultTransferLifecycle(controller({
      revokeAll: (() => { throw failure; }) as VaultTransferLifecycleController['revokeAll'],
    }), onError);

    expect(() => lifecycle.revokeAtTransitionStart()).not.toThrow();
    expect(onError).toHaveBeenCalledWith('revoke', failure);
  });

  it('serializes reconcile attempts and permits retry after a failed attempt', async () => {
    const first = deferred();
    const reconcileCurrentAccount = vi.fn()
      .mockImplementationOnce(async () => {
        await first.promise;
        throw new Error('first failed');
      })
      .mockResolvedValueOnce(undefined);
    const lifecycle = createVaultTransferLifecycle(
      controller({ reconcileCurrentAccount }),
      vi.fn(),
    );

    const firstAttempt = lifecycle.reconcile();
    const secondAttempt = lifecycle.reconcile();
    await vi.waitFor(() => expect(reconcileCurrentAccount).toHaveBeenCalledOnce());
    first.resolve();
    await expect(firstAttempt).rejects.toThrow('first failed');
    await expect(secondAttempt).resolves.toBeUndefined();
    expect(reconcileCurrentAccount).toHaveBeenCalledTimes(2);
  });

  it('inspects before unlocked reconciliation and keeps a reconcile failure local', async () => {
    const events: string[] = [];
    const failure = new Error('sync unavailable');
    const onError = vi.fn();
    const lifecycle = createVaultTransferLifecycle(controller({
      inspectJournalForStartup: vi.fn(async () => { events.push('inspect'); }),
      reconcileCurrentAccount: vi.fn(async () => {
        events.push('reconcile');
        throw failure;
      }),
    }), onError);

    await expect(lifecycle.inspectForStartup()).resolves.toBeUndefined();
    await expect(lifecycle.reconcileAfterStartup('unlocked')).resolves.toBeUndefined();

    expect(events).toEqual(['inspect', 'reconcile']);
    expect(onError).toHaveBeenCalledWith('startup-reconcile', failure);
  });

  it('propagates startup inspection failure and never attempts reconciliation', async () => {
    const reconcileCurrentAccount = vi.fn(async () => undefined);
    const lifecycle = createVaultTransferLifecycle(controller({
      inspectJournalForStartup: vi.fn(async () => { throw new Error('journal corrupt'); }),
      reconcileCurrentAccount,
    }), vi.fn());

    await expect(lifecycle.inspectForStartup()).rejects.toThrow('journal corrupt');
    expect(reconcileCurrentAccount).not.toHaveBeenCalled();
  });

  it('does not attempt account reconciliation while startup is locked', async () => {
    const reconcileCurrentAccount = vi.fn(async () => undefined);
    const lifecycle = createVaultTransferLifecycle(
      controller({ reconcileCurrentAccount }),
      vi.fn(),
    );

    await lifecycle.inspectForStartup();
    await lifecycle.reconcileAfterStartup('locked');

    expect(reconcileCurrentAccount).not.toHaveBeenCalled();
  });
});

describe('vault transfer readiness', () => {
  it('does not poison ordinary security readiness when journal inspection rejects', async () => {
    const failure = new Error('transfer journal unavailable');
    const securityReady = Promise.resolve<'unlocked'>('unlocked');
    const lifecycle = {
      inspectForStartup: vi.fn(async () => { throw failure; }),
      reconcileAfterStartup: vi.fn(async () => undefined),
    };

    const transferReady = createVaultTransferReadiness(securityReady, lifecycle);

    await expect(securityReady).resolves.toBe('unlocked');
    await expect(transferReady).rejects.toBe(failure);
    expect(lifecycle.reconcileAfterStartup).not.toHaveBeenCalled();
  });
});

describe('vault transfer Port registration', () => {
  it('installs synchronously and binds every Port to the exact runtime identity', () => {
    let listener: ((port: { readonly token: string }) => void) | undefined;
    const handler = { handle: vi.fn(() => true) };
    const runtime = {
      id: 'abcdefghijklmnop',
      getURL: vi.fn(() => 'chrome-extension://abcdefghijklmnop/'),
      onConnect: {
        addListener: vi.fn((candidate: (port: { readonly token: string }) => void) => {
          listener = candidate;
        }),
      },
    };

    registerVaultTransferPortListener(runtime, handler);

    expect(runtime.onConnect.addListener).toHaveBeenCalledOnce();
    const port = { token: 'cold-port' };
    listener?.(port);
    expect(handler.handle).toHaveBeenCalledWith(
      port,
      'chrome-extension://abcdefghijklmnop/',
      'abcdefghijklmnop',
    );
  });
});
