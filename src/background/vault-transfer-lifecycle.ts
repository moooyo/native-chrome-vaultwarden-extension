export interface VaultTransferLeaseGate<Lease> {
  capture(): Lease;
  assert(lease: Lease): unknown;
}

export interface VaultTransferAccountSessionLeases<AccountLease, SessionLease> {
  readonly account: AccountLease;
  readonly session: SessionLease;
}

export interface VaultTransferSecurityLeases<AccountLease, SessionLease, PolicyLease>
  extends VaultTransferAccountSessionLeases<AccountLease, SessionLease> {
  readonly enterprisePolicy: PolicyLease;
}

/**
 * Keep uploaded plaintext bound to its preview policy, while allowing VaultService to rotate its
 * own policy lease during the post-commit authoritative sync.
 */
export function createVaultTransferLeaseBindings<AccountLease, SessionLease, PolicyLease>(
  accountGate: VaultTransferLeaseGate<AccountLease>,
  sessionGate: VaultTransferLeaseGate<SessionLease>,
  policyGate: VaultTransferLeaseGate<PolicyLease>,
) {
  const assertAccountSession = (
    leases: VaultTransferAccountSessionLeases<AccountLease, SessionLease>,
  ): void => {
    accountGate.assert(leases.account);
    sessionGate.assert(leases.session);
  };
  const captureAccountSession = (): VaultTransferAccountSessionLeases<
    AccountLease,
    SessionLease
  > => {
    const leases = Object.freeze({
      account: accountGate.capture(),
      session: sessionGate.capture(),
    });
    assertAccountSession(leases);
    return leases;
  };
  const assertSecurity = (
    leases: VaultTransferSecurityLeases<AccountLease, SessionLease, PolicyLease>,
  ): void => {
    assertAccountSession(leases);
    policyGate.assert(leases.enterprisePolicy);
  };
  const captureSecurity = (): VaultTransferSecurityLeases<
    AccountLease,
    SessionLease,
    PolicyLease
  > => {
    const leases = Object.freeze({
      account: accountGate.capture(),
      session: sessionGate.capture(),
      enterprisePolicy: policyGate.capture(),
    });
    assertSecurity(leases);
    return leases;
  };
  return Object.freeze({
    captureSecurity,
    assertSecurity,
    captureAccountSession,
    assertAccountSession,
  });
}

export interface VaultTransferLifecycleController {
  revokeAll(): Promise<number>;
  inspectJournalForStartup(): Promise<unknown>;
  reconcileCurrentAccount(): Promise<unknown>;
}

export type VaultTransferLifecycleErrorPhase = 'revoke' | 'startup-reconcile';

export interface VaultTransferLifecycle {
  /** Invocation synchronously enters the controller's revocation phase before this method returns. */
  revokeAtTransitionStart(): void;
  reconcile(): Promise<void>;
  inspectForStartup(): Promise<void>;
  reconcileAfterStartup(state: 'loggedOut' | 'locked' | 'restricted' | 'unlocked'): Promise<void>;
}

/**
 * Serializes durable cleanup and reconciliation without delaying the synchronous memory-revocation
 * edge used by AuthService transition-start notifications.
 */
export function createVaultTransferLifecycle(
  controller: VaultTransferLifecycleController,
  onError: (phase: VaultTransferLifecycleErrorPhase, error: unknown) => void,
): VaultTransferLifecycle {
  let revocationCleanup: Promise<void> = Promise.resolve();
  let reconcileTail: Promise<void> = Promise.resolve();

  const revokeAtTransitionStart = (): void => {
    const priorCleanup = revocationCleanup;
    // revokeAll is deliberately invoked outside a Promise callback. Its implementation clears every
    // plaintext owner before its first await, while journal cancellation continues asynchronously.
    let currentCleanup: Promise<void>;
    try {
      currentCleanup = Promise.resolve(controller.revokeAll())
        .then(() => undefined)
        .catch((error: unknown) => { report('revoke', error); });
    } catch (error) {
      report('revoke', error);
      currentCleanup = Promise.resolve();
    }
    revocationCleanup = Promise.all([priorCleanup, currentCleanup]).then(() => undefined);
  };

  const reconcile = (): Promise<void> => {
    const operation = reconcileTail.then(async () => {
      await revocationCleanup;
      await controller.reconcileCurrentAccount();
    });
    // A failed attempt must not poison later explicit sync or unlock recovery attempts.
    reconcileTail = operation.catch(() => undefined);
    return operation;
  };

  const inspectForStartup = async (): Promise<void> => {
    await controller.inspectJournalForStartup();
  };

  const reconcileAfterStartup = async (
    state: 'loggedOut' | 'locked' | 'restricted' | 'unlocked',
  ): Promise<void> => {
    if (state !== 'unlocked') return;
    try {
      await reconcile();
    } catch (error) {
      report('startup-reconcile', error);
    }
  };

  const report = (phase: VaultTransferLifecycleErrorPhase, error: unknown): void => {
    try {
      onError(phase, error);
    } catch {
      // Error reporting must never reopen or derail an AuthService transition.
    }
  };

  return { revokeAtTransitionStart, reconcile, inspectForStartup, reconcileAfterStartup };
}

/** Keep transfer recovery failure independent from the ordinary background security boundary. */
export function createVaultTransferReadiness(
  securityReady: PromiseLike<'loggedOut' | 'locked' | 'restricted' | 'unlocked'>,
  lifecycle: Pick<VaultTransferLifecycle, 'inspectForStartup' | 'reconcileAfterStartup'>,
): Promise<void> {
  return Promise.resolve(securityReady).then(async (state) => {
    await lifecycle.inspectForStartup();
    await lifecycle.reconcileAfterStartup(state);
  });
}

export interface RuntimeConnectEvent<Port> {
  addListener(listener: (port: Port) => void): void;
}

export interface VaultTransferRuntimeBoundary<Port> {
  readonly id: string;
  readonly onConnect: RuntimeConnectEvent<Port>;
  getURL(path: string): string;
}

export interface VaultTransferPortBoundary<Port> {
  handle(port: Port, extensionBaseUrl: string, extensionId: string): boolean;
}

/** Install the Port listener synchronously so the first cold-start message can be queued by ready. */
export function registerVaultTransferPortListener<Port>(
  runtime: VaultTransferRuntimeBoundary<Port>,
  handler: VaultTransferPortBoundary<Port>,
): void {
  const extensionBaseUrl = runtime.getURL('');
  const extensionId = runtime.id;
  runtime.onConnect.addListener((port) => {
    handler.handle(port, extensionBaseUrl, extensionId);
  });
}
