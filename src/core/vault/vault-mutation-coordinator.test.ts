import { describe, expect, expectTypeOf, it, vi } from 'vitest';
import {
  VaultMutationCommitError,
  VaultMutationCoordinator,
  type MutationOutcome,
  type MutationCommitFailureStatus,
  type MutationFailureContext,
  type VaultMutationCoordinatorOptions,
  type VaultMutationDirtyAdapter,
  type VaultMutationTask,
  type VaultMutationTaskContext,
  type VaultSyncTaskContext,
  type VaultTerminalTaskContext,
} from './vault-mutation-coordinator.js';

interface TestLease {
  readonly generation: number;
}

type TestSyncReason = 'startup' | 'automatic' | 'manual';
type TestMutationKind = 'create' | 'update' | 'delete';

interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
  reject(error: unknown): void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}

function makeCoordinator(options: {
  maxAccounts?: number;
  maxPendingPerAccount?: number;
  classifyCommitError?: (
    error: unknown,
    context: MutationFailureContext<string, TestLease, TestMutationKind>,
  ) => MutationCommitFailureStatus | undefined;
  dirtyAdapter?: VaultMutationDirtyAdapter<string>;
} = {}) {
  const generations = new Map<string, number>();
  const unavailable = new Set<string>();
  const captureLease = vi.fn((account: string): TestLease => {
    if (unavailable.has(account)) throw new Error('no active lease');
    return { generation: generations.get(account) ?? 0 };
  });
  const assertLease = vi.fn((account: string, lease: TestLease): void => {
    if (unavailable.has(account)) throw new Error('no active lease');
    if (lease.generation !== (generations.get(account) ?? 0)) throw new Error('stale lease');
  });
  const coordinator = new VaultMutationCoordinator<
    string,
    TestLease,
    string,
    TestSyncReason,
    TestMutationKind
  >({
    captureLease,
    assertLease,
    ...(options.maxAccounts === undefined ? {} : { maxAccounts: options.maxAccounts }),
    ...(options.maxPendingPerAccount === undefined
      ? {}
      : { maxPendingPerAccount: options.maxPendingPerAccount }),
    ...(options.classifyCommitError
      ? { classifyCommitError: options.classifyCommitError }
      : {}),
    ...(options.dirtyAdapter ? { dirtyAdapter: options.dirtyAdapter } : {}),
  });
  return {
    coordinator,
    captureLease,
    assertLease,
    setGeneration(account: string, generation: number): void {
      generations.set(account, generation);
    },
    setLeaseAvailable(account: string, available: boolean): void {
      if (available) unavailable.delete(account);
      else unavailable.add(account);
    },
  };
}

function memoryDirtyAdapter() {
  const dirty = new Set<string>();
  const readDirty = vi.fn(async (account: string) => dirty.has(account));
  const markDirty = vi.fn(async (account: string) => { dirty.add(account); });
  const clearDirty = vi.fn(async (account: string) => { dirty.delete(account); });
  const adapter: VaultMutationDirtyAdapter<string> = {
    readDirty,
    markDirty,
    clearDirty,
  };
  return { adapter, dirty, readDirty, markDirty, clearDirty };
}

describe('VaultMutationCoordinator', () => {
  it('runs different accounts concurrently and preserves FIFO through mutation reconciliation', async () => {
    const { coordinator } = makeCoordinator();
    const accountA = coordinator.forAccount('account-a');
    const accountB = coordinator.forAccount('account-b');
    const firstStarted = deferred<void>();
    const releaseFirst = deferred<void>();
    const events: string[] = [];

    const first = accountA.runMutation('create', {
      commit: async () => {
        events.push('a1:commit');
        firstStarted.resolve(undefined);
        await releaseFirst.promise;
        return 'a1-receipt';
      },
      reconcile: async () => {
        events.push('a1:reconcile');
        return 'a1-done';
      },
    });
    await firstStarted.promise;

    const second = accountA.runMutation('update', {
      commit: async () => {
        events.push('a2:commit');
        return 'a2-receipt';
      },
      reconcile: async () => {
        events.push('a2:reconcile');
        return 'a2-done';
      },
    });
    const otherAccount = accountB.runMutation('delete', {
      commit: async () => {
        events.push('b1:commit');
        return 'b1-receipt';
      },
      reconcile: async () => {
        events.push('b1:reconcile');
        return 'b1-done';
      },
    });

    await expect(otherAccount).resolves.toEqual({ status: 'committed', value: 'b1-done' });
    expect(events).toEqual(['a1:commit', 'b1:commit', 'b1:reconcile']);

    releaseFirst.resolve(undefined);
    await expect(first).resolves.toEqual({ status: 'committed', value: 'a1-done' });
    await expect(second).resolves.toEqual({ status: 'committed', value: 'a2-done' });
    expect(events).toEqual([
      'a1:commit',
      'b1:commit',
      'b1:reconcile',
      'a1:reconcile',
      'a2:commit',
      'a2:reconcile',
    ]);
  });

  it('coalesces an ordinary sync and schedules one trailing sync for concurrent force requests', async () => {
    const { coordinator, captureLease } = makeCoordinator();
    const account = coordinator.forAccount('account-a');
    const firstStarted = deferred<void>();
    const releaseFirst = deferred<void>();
    let runs = 0;
    const task = vi.fn(async (
      context: VaultSyncTaskContext<string, TestLease, TestSyncReason>,
    ): Promise<string> => {
      runs += 1;
      const run = runs;
      if (run === 1) {
        firstStarted.resolve(undefined);
        await releaseFirst.promise;
      }
      return `${context.reason}:${run}`;
    });

    const first = account.requestSync('startup', 'coalesce', task);
    await firstStarted.promise;
    const joined = account.requestSync('automatic', 'coalesce', task);
    const forced = account.requestSync('manual', 'force', task);
    const joinedForce = account.requestSync('manual', 'force', task);

    expect(joined).toBe(first);
    expect(forced).not.toBe(first);
    expect(joinedForce).toBe(forced);
    expect(task).toHaveBeenCalledOnce();
    expect(captureLease).toHaveBeenCalledTimes(4);

    releaseFirst.resolve(undefined);
    await expect(first).resolves.toBe('startup:1');
    await expect(forced).resolves.toBe('manual:2');
    expect(task).toHaveBeenCalledTimes(2);
  });

  it('appends one forced sync after an ordinary tail sync and joins later force requests', async () => {
    const { coordinator } = makeCoordinator();
    const account = coordinator.forAccount('account-a');
    const mutationStarted = deferred<void>();
    const releaseMutation = deferred<void>();
    const events: string[] = [];
    const mutation = account.runMutation('update', {
      commit: async () => {
        events.push('mutation:commit');
        mutationStarted.resolve(undefined);
        await releaseMutation.promise;
        return 'receipt';
      },
      reconcile: async () => {
        events.push('mutation:reconcile');
        return 'updated';
      },
    });
    await mutationStarted.promise;

    const ordinary = account.requestSync('automatic', 'coalesce', async (context) => {
      events.push(`sync:${context.policy}`);
      return 'ordinary';
    });
    const forced = account.requestSync('manual', 'force', async (context) => {
      events.push(`sync:${context.policy}`);
      return 'forced';
    });
    const joinedForce = account.requestSync('manual', 'force', async () => 'must-not-run');

    expect(forced).not.toBe(ordinary);
    expect(joinedForce).toBe(forced);
    releaseMutation.resolve(undefined);
    await Promise.all([mutation, ordinary, forced]);
    expect(events).toEqual([
      'mutation:commit',
      'mutation:reconcile',
      'sync:coalesce',
      'sync:force',
    ]);
  });

  it('does not coalesce a sync across an intervening mutation', async () => {
    const { coordinator } = makeCoordinator();
    const account = coordinator.forAccount('account-a');
    const firstStarted = deferred<void>();
    const releaseFirst = deferred<void>();
    const events: string[] = [];
    let syncRun = 0;
    const syncTask = async (): Promise<string> => {
      syncRun += 1;
      events.push(`sync-${syncRun}`);
      if (syncRun === 1) {
        firstStarted.resolve(undefined);
        await releaseFirst.promise;
      }
      return `sync-${syncRun}`;
    };

    const firstSync = account.requestSync('startup', 'coalesce', syncTask);
    await firstStarted.promise;
    const mutation = account.runMutation('update', {
      commit: async () => {
        events.push('mutation:commit');
        return 'receipt';
      },
      reconcile: async () => {
        events.push('mutation:reconcile');
        return 'updated';
      },
    });
    const laterSync = account.requestSync('automatic', 'coalesce', syncTask);

    expect(laterSync).not.toBe(firstSync);
    releaseFirst.resolve(undefined);
    await Promise.all([firstSync, mutation, laterSync]);
    expect(events).toEqual([
      'sync-1',
      'mutation:commit',
      'mutation:reconcile',
      'sync-2',
    ]);
  });

  it('captures a lease before queueing and refuses stale queued work before commit', async () => {
    const { coordinator, captureLease, assertLease, setGeneration } = makeCoordinator();
    const account = coordinator.forAccount('account-a');
    const firstStarted = deferred<void>();
    const releaseFirst = deferred<void>();
    const first = account.runMutation('create', {
      commit: async () => {
        firstStarted.resolve(undefined);
        await releaseFirst.promise;
        return 'first-receipt';
      },
      reconcile: async () => 'first-reconciled',
    });
    await firstStarted.promise;

    const staleCommit = vi.fn(async () => 'stale-receipt');
    const stale = account.runMutation('update', {
      commit: staleCommit,
      reconcile: async () => 'must-not-run',
    });
    expect(captureLease).toHaveBeenCalledTimes(2);
    expect(captureLease.mock.results[1]?.value).toEqual({ generation: 0 });

    setGeneration('account-a', 1);
    releaseFirst.resolve(undefined);

    await expect(first).resolves.toMatchObject({ status: 'committed_unsynced' });
    await expect(stale).resolves.toMatchObject({ status: 'not_committed' });
    expect(staleCommit).not.toHaveBeenCalled();
    expect(assertLease).toHaveBeenCalled();
  });

  it.each([
    'not_committed',
    'conflict',
    'outcome_unknown',
  ] as const)('returns the explicit %s commit failure without retrying', async (status) => {
    const { coordinator } = makeCoordinator();
    const commit = vi.fn(async () => {
      throw new VaultMutationCommitError(status, `classified as ${status}`);
    });
    const reconcile = vi.fn(async () => 'must-not-run');

    const outcome = await coordinator.forAccount('account-a').runMutation('update', {
      commit,
      reconcile,
    });

    expect(outcome).toMatchObject({ status });
    expect(commit).toHaveBeenCalledOnce();
    expect(reconcile).not.toHaveBeenCalled();
    await expect(coordinator.requiresReconcile('account-a'))
      .resolves.toBe(status !== 'not_committed');
  });

  it('uses the injected classifier and conservatively treats unknown commit failures as outcome_unknown', async () => {
    const conflict = new Error('revision conflict');
    const classifier = vi.fn((error: unknown) => (
      error === conflict ? 'conflict' as const : undefined
    ));
    const { coordinator } = makeCoordinator({ classifyCommitError: classifier });
    const conflictAccount = coordinator.forAccount('account-a');
    const unknownAccount = coordinator.forAccount('account-b');

    const classified = await conflictAccount.runMutation('update', {
      commit: async () => { throw conflict; },
      reconcile: async () => 'must-not-run',
    });
    const unknown = await unknownAccount.runMutation('delete', {
      commit: async () => { throw new Error('connection closed'); },
      reconcile: async () => 'must-not-run',
    });

    expect(classified).toEqual({ status: 'conflict', error: conflict });
    expect(unknown).toMatchObject({ status: 'outcome_unknown' });
    expect(classifier).toHaveBeenCalledTimes(2);
    await expect(coordinator.requiresReconcile('account-a')).resolves.toBe(true);
    await expect(coordinator.requiresReconcile('account-b')).resolves.toBe(true);
  });

  it('reports a known commit with failed reconciliation and blocks another mutation until sync succeeds', async () => {
    const { coordinator } = makeCoordinator();
    const account = coordinator.forAccount('account-a');
    const refreshError = new Error('sync failed');
    const firstCommit = vi.fn(async () => 'server-receipt');

    const first = await account.runMutation('create', {
      commit: firstCommit,
      reconcile: async () => { throw refreshError; },
    });

    expect(first).toEqual({
      status: 'committed_unsynced',
      commitResult: 'server-receipt',
      error: refreshError,
    });
    expect(firstCommit).toHaveBeenCalledOnce();
    await expect(coordinator.requiresReconcile('account-a')).resolves.toBe(true);

    const blockedCommit = vi.fn(async () => 'must-not-commit');
    const blocked = await account.runMutation('update', {
      commit: blockedCommit,
      reconcile: async () => 'must-not-run',
    });
    expect(blocked).toMatchObject({
      status: 'not_committed',
      error: { code: 'reconcile_required' },
    });
    expect(blockedCommit).not.toHaveBeenCalled();

    await expect(account.requestSync('automatic', 'coalesce', async () => 'synced'))
      .resolves.toBe('synced');
    await expect(coordinator.requiresReconcile('account-a')).resolves.toBe(false);
    await expect(account.runMutation('update', {
      commit: async () => 'second-receipt',
      reconcile: async () => 'updated',
    })).resolves.toEqual({ status: 'committed', value: 'updated' });
  });

  it('durably marks dirty before commit and clears only after successful reconciliation', async () => {
    const events: string[] = [];
    let dirty = false;
    const adapter: VaultMutationDirtyAdapter<string> = {
      readDirty: async () => {
        events.push('read');
        return dirty;
      },
      markDirty: async () => {
        events.push('mark');
        dirty = true;
      },
      clearDirty: async () => {
        events.push('clear');
        dirty = false;
      },
    };
    const { coordinator } = makeCoordinator({ dirtyAdapter: adapter });

    const outcome = await coordinator.forAccount('account-a').runMutation('create', {
      commit: async () => {
        events.push('commit');
        expect(dirty).toBe(true);
        return 'receipt';
      },
      reconcile: async () => {
        events.push('reconcile');
        expect(dirty).toBe(true);
        return 'reconciled';
      },
    });

    expect(outcome).toEqual({ status: 'committed', value: 'reconciled' });
    expect(events).toEqual(['read', 'mark', 'commit', 'reconcile', 'clear']);
    expect(dirty).toBe(false);
  });

  it('clears a durable marker after a known not_committed failure', async () => {
    const { adapter, dirty, markDirty, clearDirty } = memoryDirtyAdapter();
    const { coordinator } = makeCoordinator({ dirtyAdapter: adapter });
    const failure = new VaultMutationCommitError('not_committed', 'server rejected request');

    const outcome = await coordinator.forAccount('account-a').runMutation('create', {
      commit: async () => { throw failure; },
      reconcile: async () => 'must-not-run',
    });

    expect(outcome).toEqual({ status: 'not_committed', error: failure });
    expect(markDirty).toHaveBeenCalledOnce();
    expect(clearDirty).toHaveBeenCalledOnce();
    expect(dirty.has('account-a')).toBe(false);
    await expect(coordinator.requiresReconcile('account-a')).resolves.toBe(false);
  });

  it('loads a durable dirty marker in a new coordinator and blocks writes until sync', async () => {
    const { adapter, dirty, markDirty, clearDirty } = memoryDirtyAdapter();
    const firstCoordinator = makeCoordinator({ dirtyAdapter: adapter }).coordinator;
    const conflict = new VaultMutationCommitError('conflict', 'revision conflict');

    await expect(firstCoordinator.forAccount('account-a').runMutation('update', {
      commit: async () => { throw conflict; },
      reconcile: async () => 'must-not-run',
    })).resolves.toEqual({ status: 'conflict', error: conflict });
    expect(dirty.has('account-a')).toBe(true);
    expect(clearDirty).not.toHaveBeenCalled();

    const secondCoordinator = makeCoordinator({ dirtyAdapter: adapter }).coordinator;
    const blockedCommit = vi.fn(async () => 'must-not-commit');
    await expect(secondCoordinator.forAccount('account-a').runMutation('update', {
      commit: blockedCommit,
      reconcile: async () => 'must-not-run',
    })).resolves.toMatchObject({
      status: 'not_committed',
      error: { code: 'reconcile_required' },
    });
    expect(blockedCommit).not.toHaveBeenCalled();
    expect(markDirty).toHaveBeenCalledOnce();
    await expect(secondCoordinator.requiresReconcile('account-a')).resolves.toBe(true);

    await expect(secondCoordinator.forAccount('account-a').requestSync(
      'automatic',
      'coalesce',
      async () => 'synced',
    )).resolves.toBe('synced');
    expect(clearDirty).toHaveBeenCalledOnce();
    expect(dirty.has('account-a')).toBe(false);
  });

  it('does not start commit when durable dirty marking fails', async () => {
    const markError = new Error('dirty storage unavailable');
    const commit = vi.fn(async () => 'must-not-commit');
    const clearDirty = vi.fn(async () => {});
    const adapter: VaultMutationDirtyAdapter<string> = {
      readDirty: async () => false,
      markDirty: async () => { throw markError; },
      clearDirty,
    };
    const { coordinator } = makeCoordinator({ dirtyAdapter: adapter });

    await expect(coordinator.forAccount('account-a').runMutation('create', {
      commit,
      reconcile: async () => 'must-not-run',
    })).resolves.toEqual({ status: 'not_committed', error: markError });
    expect(commit).not.toHaveBeenCalled();
    expect(clearDirty).not.toHaveBeenCalled();
  });

  it('keeps committed_unsynced when durable dirty clearing fails after reconciliation', async () => {
    const { adapter: baseAdapter, dirty } = memoryDirtyAdapter();
    const clearError = new Error('dirty clear failed');
    const adapter: VaultMutationDirtyAdapter<string> = {
      ...baseAdapter,
      clearDirty: async () => { throw clearError; },
    };
    const { coordinator } = makeCoordinator({ dirtyAdapter: adapter });

    const outcome = await coordinator.forAccount('account-a').runMutation('create', {
      commit: async () => 'receipt',
      reconcile: async () => 'reconciled',
    });

    expect(outcome).toEqual({
      status: 'committed_unsynced',
      commitResult: 'receipt',
      error: clearError,
    });
    expect(dirty.has('account-a')).toBe(true);
    await expect(coordinator.requiresReconcile('account-a')).resolves.toBe(true);
  });

  it('cancels queued work, suspends admission, and resumes fresh work behind the active task', async () => {
    const { coordinator } = makeCoordinator();
    const account = coordinator.forAccount('account-a');
    const activeStarted = deferred<void>();
    const releaseActive = deferred<void>();
    const freshSyncStarted = deferred<void>();
    const active = account.runMutation('create', {
      commit: async () => {
        activeStarted.resolve(undefined);
        await releaseActive.promise;
        return 'active-receipt';
      },
      reconcile: async () => 'active-reconciled',
    });
    await activeStarted.promise;

    const queuedSyncTask = vi.fn(async () => 'obsolete-sync');
    const queuedSync = account.requestSync('automatic', 'coalesce', queuedSyncTask);
    const observedSyncError = queuedSync.catch((error: unknown) => error);
    const queuedCommit = vi.fn(async () => 'obsolete-receipt');
    const queuedMutation = account.runMutation('update', {
      commit: queuedCommit,
      reconcile: async () => 'obsolete-reconciled',
    });

    expect(coordinator.invalidateAccount('account-a')).toBe(2);
    const freshSyncTask = vi.fn(async () => {
      freshSyncStarted.resolve(undefined);
      return 'fresh-sync';
    });
    await expect(account.requestSync('startup', 'coalesce', freshSyncTask))
      .rejects.toMatchObject({ code: 'account_suspended' });
    const suspendedCommit = vi.fn(async () => 'must-not-commit');
    await expect(account.runMutation('create', {
      commit: suspendedCommit,
      reconcile: async () => 'must-not-run',
    })).resolves.toMatchObject({
      status: 'not_committed',
      error: { code: 'account_suspended' },
    });
    expect(suspendedCommit).not.toHaveBeenCalled();
    expect(coordinator.resumeAccount('account-a')).toBe(true);
    expect(coordinator.resumeAccount('account-a')).toBe(false);
    const freshSync = account.requestSync('startup', 'coalesce', freshSyncTask);
    expect(freshSyncTask).not.toHaveBeenCalled();

    await expect(observedSyncError).resolves.toMatchObject({ code: 'account_invalidated' });
    await expect(queuedMutation).resolves.toMatchObject({
      status: 'not_committed',
      error: { code: 'account_invalidated' },
    });
    expect(queuedSyncTask).not.toHaveBeenCalled();
    expect(queuedCommit).not.toHaveBeenCalled();

    releaseActive.resolve(undefined);
    await expect(active).resolves.toMatchObject({ status: 'committed_unsynced' });
    await freshSyncStarted.promise;
    await expect(freshSync).resolves.toBe('fresh-sync');
    await expect(coordinator.requiresReconcile('account-a')).resolves.toBe(false);
  });

  it('runs a terminal barrier in FIFO order and cancels every ordinary task queued behind it', async () => {
    const { coordinator, setGeneration } = makeCoordinator();
    const account = coordinator.forAccount('account-a');
    const activeStarted = deferred<void>();
    const releaseActive = deferred<void>();
    const terminalStarted = deferred<void>();
    const releasePreflight = deferred<void>();
    const events: string[] = [];
    const active = account.runMutation('create', {
      commit: async () => {
        events.push('active');
        activeStarted.resolve(undefined);
        await releaseActive.promise;
        return 'receipt';
      },
      reconcile: async () => 'done',
    });
    await activeStarted.promise;
    const terminal = account.runTerminal(async (context) => {
      events.push('terminal-preflight');
      terminalStarted.resolve(undefined);
      await releasePreflight.promise;
      events.push('terminal-commit');
      expect(context.commitTerminal()).toBe(2);
      expect(coordinator.resumeAccount('account-a')).toBe(false);
      expect(coordinator.resetTerminatedAccount('account-a')).toBe(false);
      coordinator.invalidateAccount('account-a', 'logout inside terminal task');
      events.push('terminal-cleanup');
      return 'terminal-done';
    });
    const queuedCommit = vi.fn(async () => 'must-not-commit');
    const queuedMutation = account.runMutation('update', {
      commit: queuedCommit,
      reconcile: async () => 'must-not-run',
    });
    const queuedSyncTask = vi.fn(async () => 'must-not-sync');
    const queuedSync = account.requestSync('automatic', 'coalesce', queuedSyncTask);
    const observedSyncError = queuedSync.catch((error: unknown) => error);

    expect(events).toEqual(['active']);
    releaseActive.resolve(undefined);
    await terminalStarted.promise;
    expect(events).toEqual(['active', 'terminal-preflight']);
    releasePreflight.resolve(undefined);

    await expect(active).resolves.toEqual({ status: 'committed', value: 'done' });
    await expect(terminal).resolves.toBe('terminal-done');
    await expect(queuedMutation).resolves.toMatchObject({
      status: 'not_committed',
      error: { code: 'account_invalidated' },
    });
    await expect(observedSyncError).resolves.toMatchObject({ code: 'account_invalidated' });
    expect(queuedCommit).not.toHaveBeenCalled();
    expect(queuedSyncTask).not.toHaveBeenCalled();
    expect(events).toEqual([
      'active', 'terminal-preflight', 'terminal-commit', 'terminal-cleanup',
    ]);
    await expect(account.runMutation('delete', {
      commit: async () => 'must-not-run',
      reconcile: async () => 'must-not-run',
    })).resolves.toMatchObject({
      status: 'not_committed',
      error: { code: 'account_suspended' },
    });
    expect(coordinator.resumeAccount('account-a')).toBe(false);
    expect(coordinator.resetTerminatedAccount('account-a')).toBe(false);
    setGeneration('account-a', 1);
    expect(coordinator.resetTerminatedAccount('account-a')).toBe(true);
    await expect(account.runMutation('delete', {
      commit: async () => 'receipt',
      reconcile: async () => 'deleted',
    })).resolves.toEqual({ status: 'committed', value: 'deleted' });
  });

  it('keeps a committed terminal lane sealed when its callback rejects', async () => {
    const { coordinator, captureLease, setGeneration } = makeCoordinator();
    const account = coordinator.forAccount('account-a');
    const failure = new Error('terminal cleanup failed');

    await expect(account.runTerminal(async (context) => {
      context.commitTerminal();
      coordinator.invalidateAccount('account-a', 'nested terminal cleanup invalidation');
      expect(coordinator.resumeAccount('account-a')).toBe(false);
      throw failure;
    })).rejects.toBe(failure);

    expect(coordinator.trackedAccountCount).toBe(1);
    expect(coordinator.resumeAccount('account-a')).toBe(false);
    await expect(account.requestSync('startup', 'coalesce', async () => 'must-not-run'))
      .rejects.toMatchObject({ code: 'account_suspended' });
    await expect(account.runMutation('update', {
      commit: async () => 'must-not-run',
      reconcile: async () => 'must-not-run',
    })).resolves.toMatchObject({
      status: 'not_committed',
      error: { code: 'account_suspended' },
    });
    // Only the terminal preflight captured a lease. Terminal admission failures are rejected before
    // an ordinary caller can capture credentials from the still-ambiguous account.
    expect(captureLease).toHaveBeenCalledOnce();
    expect(coordinator.resetTerminatedAccount('account-a')).toBe(false);
    setGeneration('account-a', 1);
    expect(coordinator.resetTerminatedAccount('account-a')).toBe(true);
    expect(coordinator.trackedAccountCount).toBe(0);
  });

  it('rejects a leaked terminal context after settlement without invalidating a fresh lane', async () => {
    const { coordinator } = makeCoordinator();
    const account = coordinator.forAccount('account-a');
    let leaked!: VaultTerminalTaskContext<string, TestLease>;
    const preflightFailure = new Error('preflight failed');

    await expect(account.runTerminal(async (context) => {
      leaked = context;
      throw preflightFailure;
    })).rejects.toBe(preflightFailure);

    const freshStarted = deferred<void>();
    const releaseFresh = deferred<void>();
    const fresh = account.runMutation('create', {
      commit: async () => {
        freshStarted.resolve(undefined);
        await releaseFresh.promise;
        return 'receipt';
      },
      reconcile: async () => 'created',
    });
    await freshStarted.promise;

    expect(() => leaked.commitTerminal()).toThrowError(
      expect.objectContaining({ code: 'terminal_not_committed' }),
    );
    expect(() => leaked.assertCurrent()).toThrowError(
      expect.objectContaining({ code: 'account_invalidated' }),
    );
    releaseFresh.resolve(undefined);
    await expect(fresh).resolves.toEqual({ status: 'committed', value: 'created' });
  });

  it('retires an active terminal lane only after settlement and releases account capacity', async () => {
    const { coordinator, setGeneration, setLeaseAvailable } = makeCoordinator({ maxAccounts: 1 });
    const account = coordinator.forAccount('account-a');
    const committed = deferred<void>();
    const releaseTerminal = deferred<void>();
    let leaked!: VaultTerminalTaskContext<string, TestLease>;
    const terminal = account.runTerminal(async (context) => {
      leaked = context;
      context.commitTerminal();
      committed.resolve(undefined);
      await releaseTerminal.promise;
      return 'retired';
    });
    await committed.promise;

    expect(coordinator.retireTerminatedAccount('account-a')).toBe(false);
    setGeneration('account-a', 1);
    expect(coordinator.retireTerminatedAccount('account-a')).toBe(false);
    setLeaseAvailable('account-a', false);
    expect(coordinator.retireTerminatedAccount('account-a')).toBe(true);
    expect(coordinator.trackedAccountCount).toBe(1);
    expect(coordinator.resetTerminatedAccount('account-a')).toBe(false);
    await expect(coordinator.forAccount('account-b').requestSync(
      'startup',
      'coalesce',
      async () => 'must-not-run',
    )).rejects.toMatchObject({ code: 'account_capacity' });

    releaseTerminal.resolve(undefined);
    await expect(terminal).resolves.toBe('retired');
    expect(coordinator.trackedAccountCount).toBe(0);
    expect(coordinator.retireTerminatedAccount('account-a')).toBe(false);
    await expect(coordinator.forAccount('account-b').requestSync(
      'startup',
      'coalesce',
      async () => 'other-synced',
    )).resolves.toBe('other-synced');

    setLeaseAvailable('account-a', true);
    const freshStarted = deferred<void>();
    const releaseFresh = deferred<void>();
    const fresh = account.runMutation('create', {
      commit: async () => {
        freshStarted.resolve(undefined);
        await releaseFresh.promise;
        return 'receipt';
      },
      reconcile: async () => 'created',
    });
    await freshStarted.promise;
    expect(() => leaked.commitTerminal()).toThrowError(
      expect.objectContaining({ code: 'terminal_not_committed' }),
    );
    expect(() => leaked.assertCurrent()).toThrowError(
      expect.objectContaining({ code: 'account_invalidated' }),
    );
    releaseFresh.resolve(undefined);
    await expect(fresh).resolves.toEqual({ status: 'committed', value: 'created' });
  });

  it('keeps the lane usable when terminal preflight fails before commitTerminal', async () => {
    const { coordinator } = makeCoordinator();
    const account = coordinator.forAccount('account-a');
    const preflightFailure = new Error('rotation self-check failed');
    const terminal = account.runTerminal(async () => {
      throw preflightFailure;
    });
    const ordinaryCommit = vi.fn(async () => 'receipt');
    const ordinary = account.runMutation('update', {
      commit: ordinaryCommit,
      reconcile: async () => 'updated',
    });

    await expect(terminal).rejects.toBe(preflightFailure);
    await expect(ordinary).resolves.toEqual({ status: 'committed', value: 'updated' });
    expect(ordinaryCommit).toHaveBeenCalledOnce();
    await expect(account.requestSync('automatic', 'coalesce', async () => 'synced'))
      .resolves.toBe('synced');
  });

  it('rejects a terminal task that returns without committing and leaves admission open', async () => {
    const { coordinator } = makeCoordinator();
    const account = coordinator.forAccount('account-a');

    await expect(account.runTerminal(async () => 'forgot-to-commit'))
      .rejects.toMatchObject({ code: 'terminal_not_committed' });
    await expect(account.runMutation('create', {
      commit: async () => 'receipt',
      reconcile: async () => 'created',
    })).resolves.toEqual({ status: 'committed', value: 'created' });
  });

  it('does not retain an in-memory tombstone when an account has no lane', async () => {
    const { coordinator, captureLease } = makeCoordinator({ maxAccounts: 1 });
    const account = coordinator.forAccount('account-a');

    expect(coordinator.invalidateAccount('account-a')).toBe(0);
    expect(coordinator.trackedAccountCount).toBe(0);
    expect(coordinator.resumeAccount('account-a')).toBe(false);
    await expect(account.requestSync('startup', 'coalesce', async () => 'synced'))
      .resolves.toBe('synced');
    expect(captureLease).toHaveBeenCalledOnce();
    expect(coordinator.trackedAccountCount).toBe(0);
  });

  it('reclaims an invalidated non-terminal lane after its active task settles', async () => {
    const { coordinator } = makeCoordinator({ maxAccounts: 1 });
    const account = coordinator.forAccount('account-a');
    const activeStarted = deferred<void>();
    const releaseActive = deferred<void>();
    const active = account.runMutation('create', {
      commit: async () => {
        activeStarted.resolve(undefined);
        await releaseActive.promise;
        return 'receipt';
      },
      reconcile: async () => 'must-not-reconcile',
    });
    await activeStarted.promise;

    expect(coordinator.invalidateAccount('account-a')).toBe(0);
    expect(coordinator.trackedAccountCount).toBe(1);
    await expect(account.requestSync('startup', 'coalesce', async () => 'must-not-run'))
      .rejects.toMatchObject({ code: 'account_suspended' });

    releaseActive.resolve(undefined);
    await expect(active).resolves.toMatchObject({ status: 'committed_unsynced' });
    expect(coordinator.trackedAccountCount).toBe(0);

    await expect(coordinator.forAccount('account-b').requestSync(
      'startup',
      'coalesce',
      async () => 'other-synced',
    )).resolves.toBe('other-synced');
  });

  it('does not join an active sync whose external lease is no longer current', async () => {
    const { coordinator, setGeneration } = makeCoordinator();
    const account = coordinator.forAccount('account-a');
    const firstStarted = deferred<void>();
    const releaseFirst = deferred<void>();
    let calls = 0;
    const task = vi.fn(async () => {
      calls += 1;
      if (calls === 1) {
        firstStarted.resolve(undefined);
        await releaseFirst.promise;
      }
      return `sync-${calls}`;
    });

    const obsolete = account.requestSync('startup', 'coalesce', task);
    const observedObsoleteError = obsolete.catch((error: unknown) => error);
    await firstStarted.promise;
    setGeneration('account-a', 1);
    const fresh = account.requestSync('automatic', 'coalesce', task);

    expect(fresh).not.toBe(obsolete);
    releaseFirst.resolve(undefined);
    await expect(observedObsoleteError).resolves.toMatchObject({ message: 'stale lease' });
    await expect(fresh).resolves.toBe('sync-2');
    expect(task).toHaveBeenCalledTimes(2);
  });

  it('continues with a trailing forced sync after the active sync fails', async () => {
    const { coordinator } = makeCoordinator();
    const account = coordinator.forAccount('account-a');
    const firstStarted = deferred<void>();
    const releaseFirst = deferred<void>();
    const failure = new Error('first sync failed');
    let calls = 0;
    const task = vi.fn(async () => {
      calls += 1;
      if (calls === 1) {
        firstStarted.resolve(undefined);
        await releaseFirst.promise;
        throw failure;
      }
      return 'recovered';
    });

    const first = account.requestSync('startup', 'coalesce', task);
    const observedFailure = first.catch((error: unknown) => error);
    await firstStarted.promise;
    const forced = account.requestSync('manual', 'force', task);
    releaseFirst.resolve(undefined);

    await expect(observedFailure).resolves.toBe(failure);
    await expect(forced).resolves.toBe('recovered');
    expect(task).toHaveBeenCalledTimes(2);
  });

  it('bounds tracked accounts and pending work, then releases capacity after completion', async () => {
    const { coordinator } = makeCoordinator({ maxAccounts: 1, maxPendingPerAccount: 1 });
    const accountA = coordinator.forAccount('account-a');
    const accountB = coordinator.forAccount('account-b');
    const firstStarted = deferred<void>();
    const releaseFirst = deferred<void>();
    const first = accountA.runMutation('create', {
      commit: async () => {
        firstStarted.resolve(undefined);
        await releaseFirst.promise;
        return 'first';
      },
      reconcile: async () => 'first-done',
    });
    await firstStarted.promise;

    const queued = accountA.runMutation('update', {
      commit: async () => 'second',
      reconcile: async () => 'second-done',
    });
    const overflow = accountA.runMutation('delete', {
      commit: async () => 'third',
      reconcile: async () => 'third-done',
    });
    const otherAccount = accountB.runMutation('create', {
      commit: async () => 'other',
      reconcile: async () => 'other-done',
    });

    await expect(overflow).resolves.toMatchObject({
      status: 'not_committed',
      error: { code: 'queue_capacity' },
    });
    await expect(otherAccount).resolves.toMatchObject({
      status: 'not_committed',
      error: { code: 'account_capacity' },
    });

    releaseFirst.resolve(undefined);
    await expect(first).resolves.toMatchObject({ status: 'committed' });
    await expect(queued).resolves.toMatchObject({ status: 'committed' });
    expect(coordinator.trackedAccountCount).toBe(0);

    await expect(accountB.runMutation('create', {
      commit: async () => 'other',
      reconcile: async () => 'other-done',
    })).resolves.toEqual({ status: 'committed', value: 'other-done' });
  });

  it('releases account capacity before the final sync promise settles', async () => {
    const { coordinator } = makeCoordinator({ maxAccounts: 1 });

    await expect(coordinator.forAccount('account-a').requestSync(
      'startup',
      'coalesce',
      async () => 'a-synced',
    )).resolves.toBe('a-synced');
    expect(coordinator.trackedAccountCount).toBe(0);

    await expect(coordinator.forAccount('account-b').requestSync(
      'startup',
      'coalesce',
      async () => 'b-synced',
    )).resolves.toBe('b-synced');
  });

  it('types promise-valued generics as their resolved values', async () => {
    const coordinator = new VaultMutationCoordinator<
      string,
      TestLease,
      Promise<string>,
      TestSyncReason,
      TestMutationKind
    >({
      captureLease: () => ({ generation: 0 }),
      assertLease: () => {},
    });
    const account = coordinator.forAccount('account-a');
    const sync: Promise<string> = account.requestSync(
      'startup',
      'coalesce',
      () => Promise.resolve('synced'),
    );
    expectTypeOf(sync).toEqualTypeOf<Promise<string>>();
    await expect(sync).resolves.toBe('synced');

    const mutation = account.runMutation<Promise<string>, Promise<string>>('create', {
      commit: () => Promise.resolve('receipt'),
      reconcile: (receipt) => Promise.resolve(`${receipt}:reconciled`),
    });
    expectTypeOf(mutation).toEqualTypeOf<Promise<MutationOutcome<string, string>>>();
    type PromiseOutcome = MutationOutcome<Promise<string>, Promise<number>>;
    expectTypeOf<Extract<PromiseOutcome, { status: 'committed' }>['value']>()
      .toEqualTypeOf<string>();
    expectTypeOf<Extract<PromiseOutcome, { status: 'committed_unsynced' }>['commitResult']>()
      .toEqualTypeOf<number>();
    await expect(mutation).resolves.toEqual({
      status: 'committed',
      value: 'receipt:reconciled',
    });

    const inferred = makeCoordinator().coordinator.forAccount('account-a').runMutation('create', {
      commit: async () => 'inferred-receipt',
      reconcile: async (receipt) => `${receipt}:done`,
    });
    expectTypeOf(inferred).toEqualTypeOf<Promise<MutationOutcome<string, string>>>();
    await expect(inferred).resolves.toEqual({
      status: 'committed',
      value: 'inferred-receipt:done',
    });
  });

  it('keeps callback parameters contravariant under strictFunctionTypes', () => {
    const narrowTask = {
      commit: (
        _context: VaultMutationTaskContext<'account-a', TestLease, 'create'>,
      ) => 'receipt',
      reconcile: (
        _receipt: string,
        _context: VaultMutationTaskContext<'account-a', TestLease, 'create'>,
      ) => 'done',
    };
    // @ts-expect-error A task restricted to one account and kind cannot implement the broad contract.
    const invalidTask: VaultMutationTask<
      string,
      TestLease,
      TestMutationKind,
      string,
      string
    > = narrowTask;
    expect(invalidTask).toBe(narrowTask);

    const narrowOptions = {
      captureLease: (_account: 'account-a'): TestLease => ({ generation: 0 }),
      assertLease: (_account: 'account-a', _lease: TestLease): void => {},
    };
    // @ts-expect-error Narrow account callbacks cannot implement coordinator-wide dependencies.
    const invalidOptions: VaultMutationCoordinatorOptions<
      string,
      TestLease,
      TestMutationKind
    > = narrowOptions;
    expect(invalidOptions).toBe(narrowOptions);
  });

  it('validates configured bounds', () => {
    expect(() => makeCoordinator({ maxAccounts: 0 })).toThrow(RangeError);
    expect(() => makeCoordinator({ maxPendingPerAccount: 1.5 })).toThrow(RangeError);
  });
});
