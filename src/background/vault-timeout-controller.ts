import { AppError } from '../core/errors.js';
import type { SessionState } from '../core/session/session-manager.js';
import type {
  AuthTokenStorage,
  AuthTokenStorageReason,
} from '../core/session/session-manager.js';
import type { OnIdleAction } from './settings.js';
import type { EffectiveVaultTimeoutSettings } from './vault-timeout-policy.js';
import type { VaultTimeoutStateStore } from './vault-timeout-state.js';

export const VAULT_TIMEOUT_ALARM = 'vault-timeout-deadline';

export async function initializeVaultTimeoutAndReadFreshState(
  controller: Pick<VaultTimeoutController, 'initialize'>,
  getState: () => Promise<SessionState>,
): Promise<SessionState> {
  await controller.initialize();
  return getState();
}

export interface VaultTimeoutContext {
  readonly state: SessionState;
  readonly accountKey?: string;
  readonly email?: string;
  readonly credentialId?: string;
  readonly tokenRevision?: string;
  readonly sessionBindingId?: string;
}
export interface VaultTimeoutActivityLease {
  readonly generation: number;
  readonly accountKey: string;
  readonly sessionBindingId: string;
}
export type VaultTimeoutReleaseLease = VaultTimeoutActivityLease;
export interface VaultTimeoutReleaseProof {
  readonly generation: number;
  readonly accountKey: string;
  readonly sessionBindingId: string;
  readonly issuedMonotonicAt: number;
  readonly monotonicDeadlineAt: number | null;
}
export interface VaultTimeoutReconfigureOptions {
  readonly clearLocalActionOwners?: boolean;
  readonly clearLocalTimeoutOwners?: boolean;
}
export interface VaultTimeoutControllerDeps {
  readonly state: VaultTimeoutStateStore;
  readonly alarms: {
    create(name: string, options: { when: number }): void | Promise<void>;
    clear(name: string): boolean | Promise<boolean>;
  };
  readonly getContext: () => Promise<VaultTimeoutContext>;
  readonly getConfig: () => Promise<EffectiveVaultTimeoutSettings>;
  readonly reconcileTokenStorage?: (
    expected: {
      readonly accountKey: string;
      readonly email: string;
      readonly credentialId?: string;
      readonly tokenRevision?: string;
      readonly sessionBindingId?: string;
    },
    target: AuthTokenStorage,
    reason: AuthTokenStorageReason,
  ) => Promise<void>;
  readonly applyAction: (
    expected: { readonly accountKey: string; readonly email: string; readonly sessionBindingId: string },
    action: OnIdleAction,
  ) => Promise<void>;
  readonly now?: () => number;
  readonly monotonicNow?: () => number;
  readonly logger?: { warn(event: 'vault_timeout_action_failed' | 'vault_timeout_activity_failed'): void };
}

const LEASE_OWNER: unique symbol = Symbol('vaultTimeoutActivityLeaseOwner');
interface OwnedLease extends VaultTimeoutActivityLease { readonly [LEASE_OWNER]: symbol }
const RELEASE_PROOF_OWNER: unique symbol = Symbol('vaultTimeoutReleaseProofOwner');
interface OwnedReleaseProof extends VaultTimeoutReleaseProof { readonly [RELEASE_PROOF_OWNER]: symbol }
interface ActiveRun {
  readonly generation: number;
  readonly accountKey: string;
  readonly email: string;
  readonly sessionBindingId: string;
  readonly action: OnIdleAction;
  readonly lockOnSystemLock: boolean;
  readonly timeoutMs: number | null;
  lastVaultActivityAt: number;
  lastObservedAt: number;
  lastMonotonicObservedAt: number;
  deadlineAt: number | null;
  monotonicDeadlineAt: number | null;
  expired: boolean;
  actionStarted: boolean;
}
type ControllerPhase = 'uninitialized' | 'ready' | 'transitioning' | 'failed';
interface FailClosedTarget {
  readonly accountKey: string;
  readonly email: string;
  readonly sessionBindingId: string;
}
interface PendingAction {
  readonly id: number;
  readonly promise: Promise<void>;
}

/** Hydrated account/session deadline. Alarms wake the worker but never authorize a stale action. */
export class VaultTimeoutController {
  private readonly leaseOwner = Symbol('vaultTimeoutController');
  private readonly issuedLeases = new WeakSet<object>();
  private readonly issuedReleaseProofs = new WeakSet<object>();
  private generation = 0;
  private phase: ControllerPhase = 'uninitialized';
  private run: ActiveRun | undefined;
  private reconcileTarget: FailClosedTarget | undefined;
  private operationTail: Promise<void> = Promise.resolve();
  private actionTail: Promise<void> = Promise.resolve();
  private pendingAction: PendingAction | undefined;
  private actionSequence = 0;
  private resetRecoverySticky = false;
  private executingTerminalAction = false;

  constructor(private readonly deps: VaultTimeoutControllerDeps) {}

  needsReconfigure(): boolean { return this.phase === 'failed'; }

  async settlePendingAction(): Promise<void> {
    for (;;) {
      const pending = this.pendingAction;
      if (!pending) return;
      await pending.promise;
      if (this.pendingAction === pending) return;
    }
  }

  async failClosed(): Promise<void> {
    if (this.phase === 'failed') return this.settlePendingAction();
    let target: FailClosedTarget | undefined;
    await this.serialize(async () => {
      target = this.enterFailedState(this.run);
    });
    await this.finishFailClosed(target);
  }

  async initialize(): Promise<void> {
    let target: FailClosedTarget | undefined;
    try {
      await this.serialize(async () => {
        try {
          await this.reconcile(false);
        } catch (error) {
          target = this.enterFailedState(this.run);
          throw error;
        }
      });
      await this.settlePendingAction();
    } catch (error) {
      await this.finishFailClosed(target);
      throw error;
    }
  }

  /** This guard performs no storage read and is safe to call from every SessionGate entry. */
  preflight(): void {
    if (this.phase !== 'ready') throw new AppError('locked', 'Vault timeout state is unavailable');
    const run = this.run;
    if (!run) return;
    this.observeAndExpireIfDue(run, this.now(), this.monotonicNow());
    if (run.expired) throw new AppError('locked', 'Vault session timed out');
  }

  captureActivity(): VaultTimeoutActivityLease | undefined {
    return this.captureOwnedLease();
  }

  captureRelease(): VaultTimeoutReleaseLease {
    const lease = this.captureOwnedLease();
    if (!lease) throw new AppError('locked', 'Vault release state is unavailable');
    return lease;
  }

  async checkpointRelease(lease: VaultTimeoutReleaseLease): Promise<VaultTimeoutReleaseProof> {
    let runForFailure: ActiveRun | undefined;
    try {
      return await this.serialize(async () => {
        const run = this.currentRun(lease);
        if (!run) throw new AppError('locked', 'Vault release lease is stale');
        runForFailure = run;
        const now = this.now();
        const monotonicNow = this.monotonicNow();
        const priorObservedAt = run.lastObservedAt;
        const expired = this.observeAndExpireIfDue(run, now, monotonicNow);
        if (now >= priorObservedAt) await this.persistObservation(run, now);
        const endNow = this.now();
        const endMonotonicNow = this.monotonicNow();
        const expiredDuringCheckpoint = endNow < now
          || endMonotonicNow < monotonicNow
          || (run.deadlineAt !== null && endNow >= run.deadlineAt)
          || (run.monotonicDeadlineAt !== null && endMonotonicNow >= run.monotonicDeadlineAt);
        if (expired || expiredDuringCheckpoint || !this.isCurrent(run)) {
          this.expire(run);
          throw new AppError('locked', 'Vault session timed out');
        }
        if (now >= priorObservedAt) run.lastObservedAt = now;
        run.lastMonotonicObservedAt = endMonotonicNow;
        return this.issueReleaseProof(run, endMonotonicNow);
      });
    } catch (error) {
      if (runForFailure) this.expire(runForFailure);
      await this.settlePendingAction();
      if (error instanceof AppError) throw error;
      throw new AppError('locked', 'Vault release checkpoint could not be persisted');
    }
  }

  assertRelease(proof: VaultTimeoutReleaseProof): void {
    const owned = proof as Partial<OwnedReleaseProof>;
    if (owned[RELEASE_PROOF_OWNER] !== this.leaseOwner
        || !this.issuedReleaseProofs.delete(proof as object)) {
      throw new AppError('locked', 'Vault release proof is invalid');
    }
    const run = this.run;
    const monotonicNow = this.monotonicNow();
    const proofTimeInvalid = monotonicNow < proof.issuedMonotonicAt
      || (proof.monotonicDeadlineAt !== null && monotonicNow >= proof.monotonicDeadlineAt);
    if (run && proofTimeInvalid) this.expire(run);
    if (this.phase !== 'ready'
        || !run
        || run.expired
        || proofTimeInvalid
        || run.generation !== proof.generation
        || run.accountKey !== proof.accountKey
        || run.sessionBindingId !== proof.sessionBindingId) {
      throw new AppError('locked', 'Vault release proof is stale');
    }
  }

  private captureOwnedLease(): OwnedLease | undefined {
    this.preflight();
    const run = this.run;
    if (!run) return undefined;
    const lease: OwnedLease = Object.freeze({
      generation: run.generation,
      accountKey: run.accountKey,
      sessionBindingId: run.sessionBindingId,
      [LEASE_OWNER]: this.leaseOwner,
    });
    this.issuedLeases.add(lease);
    return lease;
  }

  async recordActivity(lease: VaultTimeoutActivityLease | undefined): Promise<void> {
    if (!lease) return;
    let runForFailure: ActiveRun | undefined;
    try {
      await this.serialize(async () => {
        const run = this.currentRun(lease);
        if (!run) return;
        runForFailure = run;
        const now = this.now();
        const monotonicNow = this.monotonicNow();
        const priorObservedAt = run.lastObservedAt;
        if (this.observeAndExpireIfDue(run, now, monotonicNow)) {
          if (now >= priorObservedAt) {
            await this.persistObservation(run, now);
            run.lastObservedAt = now;
          }
          return;
        }
        await this.deps.state.setActivity({
          accountKey: run.accountKey,
          email: run.email,
          sessionBindingId: run.sessionBindingId,
          lastVaultActivityAt: now,
          lastObservedAt: now,
        });
        if (!this.isCurrent(run)) return;
        run.lastVaultActivityAt = now;
        run.lastObservedAt = Math.max(run.lastObservedAt, now);
        run.lastMonotonicObservedAt = Math.max(run.lastMonotonicObservedAt, monotonicNow);
        run.deadlineAt = run.timeoutMs === null ? null : deadline(now, run.timeoutMs);
        run.monotonicDeadlineAt = run.timeoutMs === null
          ? null
          : monotonicDeadline(monotonicNow, run.timeoutMs);
        await this.schedule(run);
      });
      await this.settlePendingAction();
    } catch {
      if (runForFailure) this.expire(runForFailure);
      await this.settlePendingAction().catch(() => undefined);
      this.deps.logger?.warn('vault_timeout_activity_failed');
    }
  }

  async reconfigure(options: VaultTimeoutReconfigureOptions = {}): Promise<void> {
    let failureTarget: FailClosedTarget | undefined;
    try {
      await this.serialize(async () => {
        if (this.phase === 'uninitialized' || this.phase === 'transitioning') return;
        const previousRun = this.run;
        this.phase = 'transitioning';
        this.generation += 1;
        this.run = undefined;
        try {
          if (options.clearLocalActionOwners || options.clearLocalTimeoutOwners) {
            await this.deps.state.clearCloseLogoutProvenance({
              ...(options.clearLocalActionOwners ? { action: 'local' as const } : {}),
              ...(options.clearLocalTimeoutOwners ? { timeout: 'local' as const } : {}),
            });
          }
          await this.reconcile(false);
        } catch (error) {
          failureTarget = this.enterFailedState(this.run ?? previousRun);
          throw error;
        }
      });
      await this.settlePendingAction();
    } catch (error) {
      await this.finishFailClosed(failureTarget);
      throw error;
    }
  }

  transitionStarted(): void {
    this.generation += 1;
    this.phase = 'transitioning';
    this.run = undefined;
    void Promise.resolve(this.deps.alarms.clear(VAULT_TIMEOUT_ALARM)).catch(() => undefined);
  }

  async transitionSettled(succeeded: boolean, state: SessionState): Promise<void> {
    let target: FailClosedTarget | undefined;
    try {
      await this.serialize(async () => {
        try {
          await this.reconcile(succeeded && state === 'unlocked');
        } catch (error) {
          target = this.enterFailedState(this.run);
          throw error;
        }
      });
      if (!this.executingTerminalAction) await this.settlePendingAction();
    } catch (error) {
      if (!this.executingTerminalAction) await this.finishFailClosed(target);
      throw error;
    }
  }

  async handleAlarm(name: string): Promise<void> {
    if (name !== VAULT_TIMEOUT_ALARM) return;
    try {
      await this.serialize(async () => {
        if (this.phase !== 'ready') return;
        const run = this.run;
        if (!run || run.deadlineAt === null) return;
        const now = this.now();
        const monotonicNow = this.monotonicNow();
        const priorObservedAt = run.lastObservedAt;
        const expired = this.observeAndExpireIfDue(run, now, monotonicNow);
        if (now < priorObservedAt) return;
        try {
          await this.persistObservation(run, now);
          run.lastObservedAt = now;
        } catch (error) {
          this.expire(run);
          throw error;
        }
        if (expired) return;
        if (this.isCurrent(run)) await this.schedule(run);
      });
    } finally {
      await this.settlePendingAction();
    }
  }

  async handleSystemLocked(): Promise<void> {
    await this.serialize(async () => {
      const run = this.run;
      if (this.phase !== 'ready' || !run?.lockOnSystemLock || run.expired) return;
      this.expire(run);
    });
    await this.settlePendingAction();
  }

  private async reconcile(seedActivity: boolean): Promise<void> {
    this.reconcileTarget = undefined;
    const context = await this.deps.getContext();
    this.reconcileTarget = failClosedTarget(context);
    const config = await this.deps.getConfig();
    const { accountKey, email } = context;
    if (accountKey && email) {
      await this.deps.reconcileTokenStorage?.({
        accountKey,
        email,
        ...(context.credentialId ? { credentialId: context.credentialId } : {}),
        ...(context.tokenRevision ? { tokenRevision: context.tokenRevision } : {}),
        ...(context.sessionBindingId ? { sessionBindingId: context.sessionBindingId } : {}),
      }, config.logoutOnBrowserClose ? 'session' : 'local', tokenStorageReason(config));
      if (config.logoutOnBrowserClose) {
        if (config.closeLogoutActionProvenance === null
            || config.closeLogoutTimeoutProvenance === null) {
          throw new Error('Invalid close/logout timeout provenance');
        }
        await this.deps.state.armCloseLogout({
          accountKey,
          email,
          actionProvenance: config.closeLogoutActionProvenance,
          timeoutProvenance: config.closeLogoutTimeoutProvenance,
        });
      } else {
        await this.deps.state.disarmCloseLogout(accountKey);
      }
    }

    if (context.state !== 'unlocked' || !accountKey || !email || !context.sessionBindingId) {
      this.generation += 1;
      this.run = undefined;
      await Promise.resolve(this.deps.alarms.clear(VAULT_TIMEOUT_ALARM));
      this.phase = 'ready';
      return;
    }

    let activity = await this.deps.state.getActivity();
    if (seedActivity
        || !activity
        || activity.accountKey !== accountKey
        || activity.email !== email
        || activity.sessionBindingId !== context.sessionBindingId) {
      const lastVaultActivityAt = this.now();
      await this.deps.state.setActivity({
        accountKey,
        email,
        sessionBindingId: context.sessionBindingId,
        lastVaultActivityAt,
        lastObservedAt: lastVaultActivityAt,
      });
      activity = {
        schemaVersion: 2,
        accountKey,
        email,
        sessionBindingId: context.sessionBindingId,
        lastVaultActivityAt,
        lastObservedAt: lastVaultActivityAt,
      };
    }

    const now = this.now();
    if (now >= activity.lastObservedAt) {
      await this.deps.state.setActivity({
        accountKey: activity.accountKey,
        email: activity.email,
        sessionBindingId: activity.sessionBindingId,
        lastVaultActivityAt: activity.lastVaultActivityAt,
        lastObservedAt: now,
      });
      activity = { ...activity, lastObservedAt: now };
    }
    const timeoutMs = config.idleSeconds === null ? null : config.idleSeconds * 1_000;
    const monotonicNow = this.monotonicNow();
    const wallDeadlineAt = timeoutMs === null ? null : deadline(activity.lastVaultActivityAt, timeoutMs);
    const run: ActiveRun = {
      generation: ++this.generation,
      accountKey,
      email,
      sessionBindingId: context.sessionBindingId,
      action: config.onIdleAction,
      lockOnSystemLock: config.lockOnSystemLock,
      timeoutMs,
      lastVaultActivityAt: activity.lastVaultActivityAt,
      lastObservedAt: activity.lastObservedAt,
      lastMonotonicObservedAt: monotonicNow,
      deadlineAt: wallDeadlineAt,
      monotonicDeadlineAt: wallDeadlineAt === null
        ? null
        : monotonicDeadline(monotonicNow, Math.max(0, wallDeadlineAt - now)),
      expired: false,
      actionStarted: false,
    };
    this.run = run;
    if (this.observeAndExpireIfDue(run, now, monotonicNow)) {
      this.phase = 'ready';
      return;
    }
    await this.schedule(run);
    this.phase = 'ready';
  }

  private observeAndExpireIfDue(run: ActiveRun, now: number, monotonicNow: number): boolean {
    if (run.expired) return true;
    if (now < run.lastObservedAt || monotonicNow < run.lastMonotonicObservedAt) {
      this.expire(run);
      return true;
    }
    run.lastMonotonicObservedAt = monotonicNow;
    if ((run.deadlineAt !== null && now >= run.deadlineAt)
        || (run.monotonicDeadlineAt !== null && monotonicNow >= run.monotonicDeadlineAt)) {
      this.expire(run);
      return true;
    }
    return false;
  }

  private expire(run: ActiveRun): void {
    if (!this.isCurrent(run) || run.expired) return;
    run.expired = true;
    if (run.actionStarted) return;
    run.actionStarted = true;
    this.queueTerminalAction({
      accountKey: run.accountKey,
      email: run.email,
      sessionBindingId: run.sessionBindingId,
    }, run.action);
  }

  private enterFailedState(run: ActiveRun | undefined): FailClosedTarget | undefined {
    const target = this.reconcileTarget ?? (run ? {
      accountKey: run.accountKey,
      email: run.email,
      sessionBindingId: run.sessionBindingId,
    } : undefined);
    this.phase = 'failed';
    this.generation += 1;
    this.run = undefined;
    return target;
  }

  private async finishFailClosed(target: FailClosedTarget | undefined): Promise<void> {
    await this.queueTerminalAction(target, 'logout');
  }

  private queueTerminalAction(
    target: FailClosedTarget | undefined,
    action: OnIdleAction,
  ): Promise<void> {
    const id = ++this.actionSequence;
    const operation = this.actionTail.then(() => this.executeTerminalAction(target, action));
    const tracked = operation.finally(() => {
      if (this.pendingAction?.id === id) this.pendingAction = undefined;
    });
    this.actionTail = tracked.then(() => undefined, () => undefined);
    this.pendingAction = { id, promise: tracked };
    return tracked;
  }

  private async executeTerminalAction(
    target: FailClosedTarget | undefined,
    action: OnIdleAction,
  ): Promise<void> {
    let recoveryArmed = false;
    try {
      await this.deps.state.armResetAllRecovery();
      recoveryArmed = true;
    } catch {
      // The account-scoped action remains an independent terminal path.
    }
    try {
      await Promise.resolve(this.deps.alarms.clear(VAULT_TIMEOUT_ALARM));
    } catch {
      // Synchronous guards already deny access while terminal cleanup is pending.
    }
    if (!target) {
      if (recoveryArmed) {
        this.resetRecoverySticky = true;
        return;
      }
      return this.retryResetRecovery();
    }
    try {
      this.executingTerminalAction = true;
      await this.deps.applyAction(target, action);
    } catch {
      this.deps.logger?.warn('vault_timeout_action_failed');
      if (recoveryArmed) {
        this.resetRecoverySticky = true;
        return;
      }
      return this.retryResetRecovery();
    } finally {
      this.executingTerminalAction = false;
    }
    if (recoveryArmed && !this.resetRecoverySticky) {
      try {
        await this.deps.state.disarmResetAllRecovery();
      } catch {
        // A leftover marker causes a conservative reset on the next worker startup.
      }
    }
  }

  private async retryResetRecovery(): Promise<void> {
    try {
      await this.deps.state.armResetAllRecovery();
      this.resetRecoverySticky = true;
    } catch (error) {
      throw new Error('Vault timeout fail-closed recovery could not be persisted', { cause: error });
    }
  }

  private persistObservation(run: ActiveRun, lastObservedAt: number): Promise<void> {
    return this.deps.state.setActivity({
      accountKey: run.accountKey,
      email: run.email,
      sessionBindingId: run.sessionBindingId,
      lastVaultActivityAt: run.lastVaultActivityAt,
      lastObservedAt,
    });
  }

  private issueReleaseProof(run: ActiveRun, issuedMonotonicAt: number): VaultTimeoutReleaseProof {
    const proof: OwnedReleaseProof = Object.freeze({
      generation: run.generation,
      accountKey: run.accountKey,
      sessionBindingId: run.sessionBindingId,
      issuedMonotonicAt,
      monotonicDeadlineAt: run.monotonicDeadlineAt,
      [RELEASE_PROOF_OWNER]: this.leaseOwner,
    });
    this.issuedReleaseProofs.add(proof);
    return proof;
  }

  private async schedule(run: ActiveRun): Promise<void> {
    if (!this.isCurrent(run)) return;
    await Promise.resolve(this.deps.alarms.clear(VAULT_TIMEOUT_ALARM));
    if (!this.isCurrent(run) || run.deadlineAt === null || run.expired) return;
    await Promise.resolve(this.deps.alarms.create(VAULT_TIMEOUT_ALARM, { when: run.deadlineAt }));
  }

  private currentRun(lease: VaultTimeoutActivityLease): ActiveRun | undefined {
    const owned = lease as Partial<OwnedLease>;
    if (owned[LEASE_OWNER] !== this.leaseOwner || !this.issuedLeases.has(lease as object)) return undefined;
    const run = this.run;
    return run
      && run.generation === lease.generation
      && run.accountKey === lease.accountKey
      && run.sessionBindingId === lease.sessionBindingId
      && !run.expired
      ? run
      : undefined;
  }

  private isCurrent(run: ActiveRun): boolean {
    return this.run === run && run.generation === this.generation;
  }

  private now(): number {
    const now = this.deps.now?.() ?? Date.now();
    if (!Number.isSafeInteger(now) || now < 0) throw new Error('Invalid vault timeout clock');
    return now;
  }

  private monotonicNow(): number {
    const now = this.deps.monotonicNow?.() ?? performance.now();
    if (!Number.isFinite(now) || now < 0) throw new Error('Invalid vault timeout monotonic clock');
    return now;
  }

  private serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.operationTail.then(operation, operation);
    this.operationTail = result.then(() => undefined, () => undefined);
    return result;
  }
}

function tokenStorageReason(config: EffectiveVaultTimeoutSettings): AuthTokenStorageReason {
  if (!config.logoutOnBrowserClose) return 'conservative';
  if (config.closeLogoutActionProvenance === 'local') return 'localLogout';
  return config.failClosed ? 'conservative' : 'effectivePolicy';
}

function deadline(lastActivityAt: number, timeoutMs: number): number {
  const value = lastActivityAt + timeoutMs;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || !Number.isSafeInteger(value)) {
    throw new Error('Invalid vault timeout deadline');
  }
  return value;
}

function monotonicDeadline(now: number, remainingMs: number): number {
  const value = now + remainingMs;
  if (!Number.isFinite(remainingMs) || remainingMs < 0 || !Number.isFinite(value)) {
    throw new Error('Invalid vault timeout monotonic deadline');
  }
  return value;
}

function failClosedTarget(context: VaultTimeoutContext): FailClosedTarget | undefined {
  return context.accountKey && context.email && context.sessionBindingId
    ? {
        accountKey: context.accountKey,
        email: context.email,
        sessionBindingId: context.sessionBindingId,
      }
    : undefined;
}
