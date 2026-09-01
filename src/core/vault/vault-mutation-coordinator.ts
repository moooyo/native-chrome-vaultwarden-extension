export const DEFAULT_MAX_COORDINATED_ACCOUNTS = 32;
export const DEFAULT_MAX_PENDING_PER_ACCOUNT = 64;

export type VaultSyncPolicy = 'coalesce' | 'force';

export type MutationCommitFailureStatus = 'not_committed' | 'conflict' | 'outcome_unknown';

export interface FailedMutationOutcome {
  readonly status: MutationCommitFailureStatus;
  readonly error: unknown;
}

export type MutationOutcome<Result, Commit = unknown> =
  | FailedMutationOutcome
  | { status: 'committed_unsynced'; commitResult: Awaited<Commit>; error: unknown }
  | { status: 'committed'; value: Awaited<Result> };

export type VaultCoordinatorErrorCode =
  | 'account_capacity'
  | 'queue_capacity'
  | 'account_invalidated'
  | 'account_suspended'
  | 'reconcile_required'
  | 'terminal_not_committed';

export class VaultCoordinatorError extends Error {
  constructor(
    readonly code: VaultCoordinatorErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'VaultCoordinatorError';
  }
}

/** An explicit classification for a remote mutation request that failed before a known commit. */
export class VaultMutationCommitError extends Error {
  constructor(
    readonly status: MutationCommitFailureStatus,
    message: string,
  ) {
    super(message);
    this.name = 'VaultMutationCommitError';
  }
}

export interface VaultSyncTaskContext<
  AccountKey,
  Lease,
  SyncReason extends string,
> {
  readonly account: AccountKey;
  readonly lease: Lease;
  readonly reason: SyncReason;
  readonly policy: VaultSyncPolicy;
  readonly assertCurrent: () => void;
}

export interface VaultMutationTaskContext<
  AccountKey,
  Lease,
  MutationKind extends string,
> {
  readonly account: AccountKey;
  readonly lease: Lease;
  readonly kind: MutationKind;
  readonly assertCurrent: () => void;
}

export interface VaultTerminalTaskContext<AccountKey, Lease> {
  readonly account: AccountKey;
  readonly lease: Lease;
  /** Revalidate the queued preflight against the lane epoch and external account lease. */
  readonly assertCurrent: () => void;
  /**
   * Irreversibly suspend this account lane and cancel every later queued task. Call this exactly
   * once, only after preflight succeeds and immediately before entering the terminal commit path.
   * The active terminal task keeps its FIFO turn and may invalidate or log out the account itself.
   */
  readonly commitTerminal: () => number;
}

export interface VaultMutationTask<
  AccountKey,
  Lease,
  MutationKind extends string,
  Commit,
  Result,
> {
  /** Execute the remote write exactly once. The coordinator never retries this callback. */
  readonly commit: (
    context: VaultMutationTaskContext<AccountKey, Lease, MutationKind>,
  ) => Commit | PromiseLike<Commit>;
  /** Reconcile local state after a known remote commit, inside the same FIFO queue turn. */
  readonly reconcile: (
    commitResult: Awaited<Commit>,
    context: VaultMutationTaskContext<AccountKey, Lease, MutationKind>,
  ) => Result | PromiseLike<Result>;
}

export interface MutationFailureContext<
  AccountKey,
  Lease,
  MutationKind extends string,
> {
  readonly account: AccountKey;
  readonly lease: Lease;
  readonly kind: MutationKind;
}

/** Durable write-ahead marker used to survive extension worker or coordinator restarts. */
export interface VaultMutationDirtyAdapter<AccountKey> {
  readonly readDirty: (account: AccountKey) => boolean | PromiseLike<boolean>;
  readonly markDirty: (account: AccountKey) => void | PromiseLike<void>;
  readonly clearDirty: (account: AccountKey) => void | PromiseLike<void>;
}

export interface VaultMutationCoordinatorOptions<
  AccountKey,
  Lease,
  MutationKind extends string,
> {
  /** Capture the external authorization/session fence synchronously, before queueing. */
  readonly captureLease: (account: AccountKey) => Lease;
  /** Assert the external fence synchronously immediately before protected work. */
  readonly assertLease: (account: AccountKey, lease: Lease) => void;
  /** Classify a rejected remote write. Unclassified failures are conservatively outcome_unknown. */
  readonly classifyCommitError?: (
    error: unknown,
    context: MutationFailureContext<AccountKey, Lease, MutationKind>,
  ) => MutationCommitFailureStatus | undefined;
  readonly dirtyAdapter?: VaultMutationDirtyAdapter<AccountKey>;
  readonly maxAccounts?: number;
  readonly maxPendingPerAccount?: number;
}

export interface VaultAccountMutationLane<
  AccountKey,
  Lease,
  SyncResult,
  SyncReason extends string,
  MutationKind extends string,
> {
  readonly requestSync: (
    reason: SyncReason,
    policy: VaultSyncPolicy,
    task: (
      context: VaultSyncTaskContext<AccountKey, Lease, SyncReason>,
    ) => SyncResult | PromiseLike<SyncResult>,
  ) => Promise<Awaited<SyncResult>>;
  readonly runMutation: <Commit, Result>(
    kind: MutationKind,
    task: VaultMutationTask<AccountKey, Lease, MutationKind, Commit, Result>,
  ) => Promise<MutationOutcome<Result, Commit>>;
  /**
   * Run an exclusive terminal operation in the same per-account FIFO lane. A rejection before
   * `commitTerminal()` leaves admission unchanged; after it, queued and new ordinary work is denied.
   */
  readonly runTerminal: <Result>(
    task: (
      context: VaultTerminalTaskContext<AccountKey, Lease>,
    ) => Result | PromiseLike<Result>,
  ) => Promise<Awaited<Result>>;
}

interface QueueEntry {
  readonly run: () => Promise<void>;
  readonly settle: () => void;
  readonly cancel: (error: unknown) => void;
}

interface SyncSlot<Lease, SyncResult> {
  readonly token: symbol;
  readonly epoch: number;
  readonly lease: Lease;
  readonly policy: VaultSyncPolicy;
  readonly promise: Promise<SyncResult>;
}

interface AccountLane<Lease, SyncResult> {
  readonly queue: QueueEntry[];
  epoch: number;
  draining: boolean;
  active: boolean;
  suspended: boolean;
  terminal: 'none' | 'committed_active' | 'sealed';
  terminalLease: Lease | null;
  retireOnIdle: boolean;
  needsReconcile: boolean;
  dirtyLoaded: boolean;
  dirtyLoad: Promise<void> | null;
  activeSync: SyncSlot<Lease, SyncResult> | null;
  tailSync: SyncSlot<Lease, SyncResult> | null;
}

/**
 * Coordinates all syncs and mutations for a stable account key. Different accounts may run in
 * parallel, while each account gets one bounded FIFO lane. Callers must perform every remote write
 * and its reconciliation through one runMutation task; recursively awaiting a public coordinator
 * method from inside a task would wait on the task itself.
 */
export class VaultMutationCoordinator<
  AccountKey,
  Lease,
  SyncResult,
  SyncReason extends string = string,
  MutationKind extends string = string,
> {
  private readonly lanes = new Map<AccountKey, AccountLane<Lease, Awaited<SyncResult>>>();
  private readonly maxAccounts: number;
  private readonly maxPendingPerAccount: number;

  constructor(
    private readonly options: VaultMutationCoordinatorOptions<AccountKey, Lease, MutationKind>,
  ) {
    this.maxAccounts = positiveInteger(
      options.maxAccounts ?? DEFAULT_MAX_COORDINATED_ACCOUNTS,
      'maxAccounts',
    );
    this.maxPendingPerAccount = positiveInteger(
      options.maxPendingPerAccount ?? DEFAULT_MAX_PENDING_PER_ACCOUNT,
      'maxPendingPerAccount',
    );
  }

  /** Bind the public task signatures to one account without retaining an idle facade or lane. */
  forAccount(
    account: AccountKey,
  ): VaultAccountMutationLane<AccountKey, Lease, SyncResult, SyncReason, MutationKind> {
    return Object.freeze({
      requestSync: (
        reason: SyncReason,
        policy: VaultSyncPolicy,
        task: (
          context: VaultSyncTaskContext<AccountKey, Lease, SyncReason>,
        ) => SyncResult | PromiseLike<SyncResult>,
      ) => this.requestSync(account, reason, policy, task),
      runMutation: <Commit, Result>(
        kind: MutationKind,
        task: VaultMutationTask<AccountKey, Lease, MutationKind, Commit, Result>,
      ) => this.runMutation(account, kind, task),
      runTerminal: <Result>(
        task: (
          context: VaultTerminalTaskContext<AccountKey, Lease>,
        ) => Result | PromiseLike<Result>,
      ) => this.runTerminal(account, task),
    });
  }

  get trackedAccountCount(): number {
    return this.lanes.size;
  }

  pendingCount(account: AccountKey): number {
    return this.lanes.get(account)?.queue.length ?? 0;
  }

  async requiresReconcile(account: AccountKey): Promise<boolean> {
    const lane = this.lanes.get(account) ?? this.getOrCreateLane(account);
    try {
      await this.ensureDirtyLoaded(account, lane);
      return lane.needsReconcile;
    } finally {
      this.deleteLaneIfIdle(account, lane);
    }
  }

  /**
   * Invalidate an existing lane epoch and cancel work that has not started. Active work cannot be
   * forcibly stopped, but its next coordinator assertion fails. An account without a lane needs no
   * in-memory tombstone because the external account lease rejects stale work. Ordinary suspended
   * lanes are reclaimed once idle; a committed terminal lane remains sealed until trusted reset or
   * retirement after the owning account has been removed.
   */
  invalidateAccount(account: AccountKey, message = 'Vault account was invalidated'): number {
    const lane = this.lanes.get(account);
    if (!lane) return 0;

    lane.epoch += 1;
    lane.suspended = true;
    const queued = lane.queue.splice(0);
    const error = new VaultCoordinatorError('account_invalidated', message);
    for (const entry of queued) entry.cancel(error);
    lane.tailSync = null;
    this.deleteLaneIfIdle(account, lane);
    return queued.length;
  }

  /** Resume admission after the caller has established a fresh account/session lease. */
  resumeAccount(account: AccountKey): boolean {
    const lane = this.lanes.get(account);
    if (!lane || !lane.suspended) return false;
    if (lane.terminal !== 'none') return false;
    lane.epoch += 1;
    lane.suspended = false;
    this.deleteLaneIfIdle(account, lane);
    return true;
  }

  /**
   * Reopen a sealed terminal lane only after a trusted caller established a fresh authenticated
   * session. Active terminal work cannot be reset, and ordinary suspended lanes use resumeAccount.
   */
  resetTerminatedAccount(account: AccountKey): boolean {
    const lane = this.lanes.get(account);
    if (!lane || lane.terminal !== 'sealed' || lane.active) return false;
    const terminalLease = lane.terminalLease;
    if (terminalLease === null) return false;
    try {
      this.options.assertLease(account, terminalLease);
      return false;
    } catch {
      // The terminal operation's original external lease must be stale before this lane can reopen.
    }
    try {
      const freshLease = this.options.captureLease(account);
      this.options.assertLease(account, freshLease);
    } catch {
      return false;
    }
    lane.epoch += 1;
    lane.terminal = 'none';
    lane.terminalLease = null;
    lane.retireOnIdle = false;
    lane.suspended = false;
    this.deleteLaneIfIdle(account, lane);
    return true;
  }

  /**
   * Retire a committed terminal lane after the owning account was fully reset. Active terminal work
   * remains exclusive until its queue turn settles; the idle drain then removes the sealed tombstone
   * without ever reopening admission.
   */
  retireTerminatedAccount(account: AccountKey): boolean {
    const lane = this.lanes.get(account);
    if (
      !lane
      || !lane.suspended
      || lane.terminal === 'none'
      || lane.terminalLease === null
    ) return false;
    try {
      this.options.assertLease(account, lane.terminalLease);
      return false;
    } catch {
      // Retirement is safe only after the terminal operation's external lease became stale.
    }
    try {
      const freshLease = this.options.captureLease(account);
      this.options.assertLease(account, freshLease);
      return false;
    } catch {
      // No fresh account lease exists; a later login will create a new lane if this account returns.
    }
    if (lane.needsReconcile && this.options.dirtyAdapter === undefined) return false;
    lane.retireOnIdle = true;
    this.deleteLaneIfIdle(account, lane);
    return true;
  }

  private requestSync(
    account: AccountKey,
    reason: SyncReason,
    policy: VaultSyncPolicy,
    task: (
      context: VaultSyncTaskContext<AccountKey, Lease, SyncReason>,
    ) => SyncResult | PromiseLike<SyncResult>,
  ): Promise<Awaited<SyncResult>> {
    try {
      const existing = this.lanes.get(account);
      if (existing?.suspended) return Promise.reject(this.accountSuspendedError());
      const lease = this.options.captureLease(account);
      if (existing) {
        if (
          existing.tailSync
          && this.isSyncSlotCurrent(account, existing, existing.tailSync)
          && (policy === 'coalesce' || existing.tailSync.policy === 'force')
        ) {
          return existing.tailSync.promise;
        }
        if (
          policy === 'coalesce'
          && existing.queue.length === 0
          && existing.activeSync
          && this.isSyncSlotCurrent(account, existing, existing.activeSync)
        ) {
          return existing.activeSync.promise;
        }
      }

      const lane = existing ?? this.getOrCreateLane(account);
      const epoch = lane.epoch;
      const token = Symbol('syncSlot');
      const promise = this.enqueue<Awaited<SyncResult>>(account, lane, async (): Promise<Awaited<SyncResult>> => {
        if (lane.tailSync?.token === token) lane.tailSync = null;
        lane.activeSync = { token, epoch, lease, policy, promise };
        const context = Object.freeze({
          account,
          lease,
          reason,
          policy,
          assertCurrent: () => this.assertCurrent(account, lane, epoch, lease),
        });
        try {
          context.assertCurrent();
          const result: Awaited<SyncResult> = await task(context);
          context.assertCurrent();
          await this.clearDirty(account, lane);
          context.assertCurrent();
          return result;
        } finally {
          if (lane.activeSync?.token === token) lane.activeSync = null;
        }
      }, () => {
        if (lane.tailSync?.token === token) lane.tailSync = null;
      });
      lane.tailSync = { token, epoch, lease, policy, promise };
      return promise;
    } catch (error) {
      return Promise.reject(error);
    }
  }

  private runMutation<Commit, Result>(
    account: AccountKey,
    kind: MutationKind,
    task: VaultMutationTask<AccountKey, Lease, MutationKind, Commit, Result>,
  ): Promise<MutationOutcome<Result, Commit>> {
    try {
      const existing = this.lanes.get(account);
      if (existing?.suspended) {
        return Promise.resolve({ status: 'not_committed', error: this.accountSuspendedError() });
      }
      const lease = this.options.captureLease(account);
      const lane = existing ?? this.getOrCreateLane(account);
      const epoch = lane.epoch;
      const promise = this.enqueue(account, lane, () => this.executeMutation(
        account,
        lane,
        epoch,
        lease,
        kind,
        task,
      ));
      // A sync before this mutation cannot satisfy requests made after it.
      lane.tailSync = null;
      return promise.catch((error: unknown): MutationOutcome<Result, Commit> => ({
        status: 'not_committed',
        error,
      }));
    } catch (error) {
      return Promise.resolve<MutationOutcome<Result, Commit>>({
        status: 'not_committed',
        error,
      });
    }
  }

  private runTerminal<Result>(
    account: AccountKey,
    task: (
      context: VaultTerminalTaskContext<AccountKey, Lease>,
    ) => Result | PromiseLike<Result>,
  ): Promise<Awaited<Result>> {
    try {
      const existing = this.lanes.get(account);
      if (existing?.suspended) return Promise.reject(this.accountSuspendedError());
      const lease = this.options.captureLease(account);
      const lane = existing ?? this.getOrCreateLane(account);
      const epoch = lane.epoch;
      const promise = this.enqueue(account, lane, async (): Promise<Awaited<Result>> => {
        const state: { phase: 'preflight' | 'committed' | 'settled' } = {
          phase: 'preflight',
        };
        const context: VaultTerminalTaskContext<AccountKey, Lease> = Object.freeze({
          account,
          lease,
          assertCurrent: () => this.assertCurrent(account, lane, epoch, lease),
          commitTerminal: () => {
            if (state.phase !== 'preflight') {
              throw new VaultCoordinatorError(
                'terminal_not_committed',
                'The terminal barrier can no longer be committed',
              );
            }
            this.assertCurrent(account, lane, epoch, lease);
            state.phase = 'committed';
            lane.terminal = 'committed_active';
            lane.terminalLease = lease;
            lane.retireOnIdle = false;
            return this.invalidateAccount(
              account,
              'Vault account entered a terminal operation',
            );
          },
        });
        context.assertCurrent();
        try {
          const result: Awaited<Result> = await task(context);
          if (state.phase === 'preflight') {
            throw new VaultCoordinatorError(
              'terminal_not_committed',
              'The terminal task completed without committing its barrier',
            );
          }
          return result;
        } finally {
          if (state.phase === 'committed' && lane.terminal === 'committed_active') {
            lane.terminal = 'sealed';
          }
          state.phase = 'settled';
        }
      });
      lane.tailSync = null;
      return promise;
    } catch (error) {
      return Promise.reject(error);
    }
  }

  private async executeMutation<Commit, Result>(
    account: AccountKey,
    lane: AccountLane<Lease, Awaited<SyncResult>>,
    epoch: number,
    lease: Lease,
    kind: MutationKind,
    task: VaultMutationTask<AccountKey, Lease, MutationKind, Commit, Result>,
  ): Promise<MutationOutcome<Result, Commit>> {
    const context = Object.freeze({
      account,
      lease,
      kind,
      assertCurrent: () => this.assertCurrent(account, lane, epoch, lease),
    });

    try {
      context.assertCurrent();
      await this.ensureDirtyLoaded(account, lane);
      context.assertCurrent();
    } catch (error) {
      return { status: 'not_committed', error };
    }
    if (lane.needsReconcile) {
      return {
        status: 'not_committed',
        error: new VaultCoordinatorError(
          'reconcile_required',
          'A previous vault mutation must be reconciled before another write',
        ),
      };
    }

    try {
      await this.markDirty(account, lane);
    } catch (error) {
      return { status: 'not_committed', error };
    }
    try {
      context.assertCurrent();
    } catch (error) {
      await this.clearKnownNotCommitted(account, lane);
      return { status: 'not_committed', error };
    }

    let commitResult: Awaited<Commit>;
    try {
      commitResult = await task.commit(context);
    } catch (error) {
      const status = this.classifyCommitFailure(error, { account, lease, kind });
      if (status === 'not_committed') await this.clearKnownNotCommitted(account, lane);
      return {
        status,
        error,
      };
    }

    try {
      context.assertCurrent();
      const value = await task.reconcile(commitResult, context);
      context.assertCurrent();
      await this.clearDirty(account, lane);
      context.assertCurrent();
      return { status: 'committed', value };
    } catch (error) {
      return { status: 'committed_unsynced', commitResult, error };
    }
  }

  private async ensureDirtyLoaded(
    account: AccountKey,
    lane: AccountLane<Lease, Awaited<SyncResult>>,
  ): Promise<void> {
    if (lane.dirtyLoaded) return;
    const adapter = this.options.dirtyAdapter;
    if (!adapter) {
      lane.dirtyLoaded = true;
      return;
    }

    let load = lane.dirtyLoad;
    if (!load) {
      load = (async () => {
        const dirty = await adapter.readDirty(account);
        lane.needsReconcile = lane.needsReconcile || dirty;
        lane.dirtyLoaded = true;
      })();
      lane.dirtyLoad = load;
    }
    try {
      await load;
    } finally {
      if (lane.dirtyLoad === load) lane.dirtyLoad = null;
    }
  }

  private async markDirty(
    account: AccountKey,
    lane: AccountLane<Lease, Awaited<SyncResult>>,
  ): Promise<void> {
    await this.options.dirtyAdapter?.markDirty(account);
    lane.dirtyLoaded = true;
    lane.needsReconcile = true;
  }

  private async clearDirty(
    account: AccountKey,
    lane: AccountLane<Lease, Awaited<SyncResult>>,
  ): Promise<void> {
    await this.options.dirtyAdapter?.clearDirty(account);
    lane.dirtyLoaded = true;
    lane.needsReconcile = false;
  }

  private async clearKnownNotCommitted(
    account: AccountKey,
    lane: AccountLane<Lease, Awaited<SyncResult>>,
  ): Promise<void> {
    try {
      await this.clearDirty(account, lane);
    } catch {
      // Keep the conservative dirty state. A later successful sync can clear the durable marker.
    }
  }

  private accountSuspendedError(): VaultCoordinatorError {
    return new VaultCoordinatorError(
      'account_suspended',
      'Vault account is suspended until a fresh session resumes admission',
    );
  }

  private classifyCommitFailure(
    error: unknown,
    context: MutationFailureContext<AccountKey, Lease, MutationKind>,
  ): MutationCommitFailureStatus {
    if (error instanceof VaultMutationCommitError) return error.status;
    try {
      return this.options.classifyCommitError?.(error, context) ?? 'outcome_unknown';
    } catch {
      return 'outcome_unknown';
    }
  }

  private assertCurrent(
    account: AccountKey,
    lane: AccountLane<Lease, Awaited<SyncResult>>,
    epoch: number,
    lease: Lease,
  ): void {
    if (this.lanes.get(account) !== lane || lane.epoch !== epoch || lane.suspended) {
      throw new VaultCoordinatorError('account_invalidated', 'Vault account changed during operation');
    }
    this.options.assertLease(account, lease);
  }

  private isSyncSlotCurrent(
    account: AccountKey,
    lane: AccountLane<Lease, Awaited<SyncResult>>,
    slot: SyncSlot<Lease, Awaited<SyncResult>>,
  ): boolean {
    if (slot.epoch !== lane.epoch) return false;
    try {
      this.options.assertLease(account, slot.lease);
      return true;
    } catch {
      return false;
    }
  }

  private getOrCreateLane(account: AccountKey): AccountLane<Lease, Awaited<SyncResult>> {
    const current = this.lanes.get(account);
    if (current) return current;
    if (this.lanes.size >= this.maxAccounts) {
      throw new VaultCoordinatorError(
        'account_capacity',
        `Vault coordinator account capacity (${this.maxAccounts}) was reached`,
      );
    }
    const lane: AccountLane<Lease, Awaited<SyncResult>> = {
      queue: [],
      epoch: 0,
      draining: false,
      active: false,
      suspended: false,
      terminal: 'none',
      terminalLease: null,
      retireOnIdle: false,
      needsReconcile: false,
      dirtyLoaded: this.options.dirtyAdapter === undefined,
      dirtyLoad: null,
      activeSync: null,
      tailSync: null,
    };
    this.lanes.set(account, lane);
    return lane;
  }

  private enqueue<Result>(
    account: AccountKey,
    lane: AccountLane<Lease, Awaited<SyncResult>>,
    operation: () => Result | Promise<Result>,
    onCancel?: () => void,
  ): Promise<Result> {
    if (lane.queue.length >= this.maxPendingPerAccount) {
      throw new VaultCoordinatorError(
        'queue_capacity',
        `Vault coordinator queue capacity (${this.maxPendingPerAccount}) was reached`,
      );
    }

    let settled = false;
    let completed = false;
    let succeeded = false;
    let completedResult!: Result;
    let completedError: unknown;
    let resolveResult!: (result: Result | PromiseLike<Result>) => void;
    let rejectResult!: (error: unknown) => void;
    const promise = new Promise<Result>((resolve, reject) => {
      resolveResult = resolve;
      rejectResult = reject;
    });
    const entry: QueueEntry = {
      run: async () => {
        if (settled) return;
        try {
          completedResult = await operation();
          succeeded = true;
        } catch (error) {
          completedError = error;
        }
        completed = true;
      },
      settle: () => {
        if (settled || !completed) return;
        settled = true;
        if (succeeded) resolveResult(completedResult);
        else rejectResult(completedError);
      },
      cancel: (error: unknown) => {
        if (settled) return;
        settled = true;
        onCancel?.();
        rejectResult(error);
      },
    };
    lane.queue.push(entry);
    this.scheduleDrain(account, lane);
    return promise;
  }

  private scheduleDrain(account: AccountKey, lane: AccountLane<Lease, Awaited<SyncResult>>): void {
    if (lane.draining) return;
    lane.draining = true;
    queueMicrotask(() => { void this.drain(account, lane); });
  }

  private async drain(
    account: AccountKey,
    lane: AccountLane<Lease, Awaited<SyncResult>>,
  ): Promise<void> {
    try {
      let entry = lane.queue.shift();
      while (entry) {
        lane.active = true;
        await entry.run();
        lane.active = false;
        if (lane.queue.length === 0) {
          lane.draining = false;
          this.deleteLaneIfIdle(account, lane);
          entry.settle();
          return;
        }
        entry.settle();
        entry = lane.queue.shift();
      }
    } finally {
      lane.active = false;
      if (lane.draining) {
        lane.draining = false;
        if (lane.queue.length > 0) this.scheduleDrain(account, lane);
        else this.deleteLaneIfIdle(account, lane);
      }
    }
  }

  private deleteLaneIfIdle(
    account: AccountKey,
    lane: AccountLane<Lease, Awaited<SyncResult>>,
  ): void {
    if (
      this.lanes.get(account) !== lane
      || lane.active
      || lane.queue.length > 0
      || lane.activeSync !== null
      || lane.tailSync !== null
      || lane.dirtyLoad !== null
    ) return;
    if (lane.retireOnIdle && lane.terminal === 'sealed') {
      this.lanes.delete(account);
      return;
    }
    if (
      (!lane.suspended && !lane.needsReconcile)
      || (lane.suspended && lane.terminal === 'none')
    ) this.lanes.delete(account);
  }
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive safe integer`);
  }
  return value;
}
