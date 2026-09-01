export const VAULT_SYNC_ALARM = 'vault-sync';
export const VAULT_SYNC_ALARM_PERIOD_MINUTES = 5;
export const DEFAULT_VAULT_SYNC_STALE_MS = VAULT_SYNC_ALARM_PERIOD_MINUTES * 60_000;
export const DEFAULT_POPUP_SYNC_STALE_MS = 45_000;
export const DEFAULT_NOTIFICATION_BURST_MS = 250;
export const DEFAULT_MAX_SYNC_IDENTITIES = 32;
export const VAULT_SYNC_METADATA_KEY = 'vaultSyncSchedulerMetadata';

const METADATA_SCHEMA_VERSION = 1 as const;

export type VaultSyncReason =
  | 'alarm'
  | 'login'
  | 'unlock'
  | 'startup'
  | 'popup'
  | 'manual'
  | 'mutation'
  | 'notification';

export type VaultSyncPolicy = 'coalesce' | 'force';
export type VaultSyncSessionState = 'loggedOut' | 'locked' | 'restricted' | 'unlocked';

export interface VaultSyncSessionContext {
  readonly state: VaultSyncSessionState;
  readonly identity?: string;
}

export interface VaultSyncSessionSettlement {
  readonly reason: string;
  readonly state: VaultSyncSessionState;
  readonly succeeded: boolean;
}

export interface VaultSyncIdentityMetadata {
  readonly lastAttempt: number;
  readonly lastSuccess?: number;
}

export interface VaultSyncStatus {
  readonly identity?: string;
  readonly lastSuccessfulSyncAt?: number;
  readonly dirty: boolean;
  readonly syncing: boolean;
}

export interface VaultSyncMetadata {
  readonly schemaVersion: typeof METADATA_SCHEMA_VERSION;
  readonly identities: Readonly<Record<string, VaultSyncIdentityMetadata>>;
}

export interface VaultSyncMetadataStore {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
}

export interface VaultSyncAlarmScheduler {
  get(name: string): Promise<{ name: string } | undefined>;
  create(name: string, options: { periodInMinutes: number }): void | PromiseLike<void>;
}

export interface VaultSyncTimers {
  setTimeout(callback: () => void, delayMs: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface VaultSyncSchedulerDeps {
  getSessionContext(): PromiseLike<VaultSyncSessionContext | undefined>;
  requestSync(reason: VaultSyncReason, policy: VaultSyncPolicy): PromiseLike<unknown>;
  rebuildCache(identity: string): PromiseLike<unknown>;
  isDirty(identity: string): PromiseLike<boolean>;
  metadataStore: VaultSyncMetadataStore;
  alarms: VaultSyncAlarmScheduler;
  now?: () => number;
  timers?: VaultSyncTimers;
  onBackgroundError?: (error: unknown) => void;
}

export interface VaultSyncSchedulerOptions {
  staleMs?: number;
  popupStaleMs?: number;
  notificationBurstMs?: number;
  maxTrackedIdentities?: number;
  metadataKey?: string;
}

/** Idempotently restore the periodic alarm after installation, browser restart, or worker eviction. */
export async function ensureVaultSyncAlarm(alarms: VaultSyncAlarmScheduler): Promise<void> {
  if (await alarms.get(VAULT_SYNC_ALARM)) return;
  await alarms.create(VAULT_SYNC_ALARM, { periodInMinutes: VAULT_SYNC_ALARM_PERIOD_MINUTES });
}

/**
 * Decides when sync should be requested while leaving account-level serialization and coalescing to
 * the injected coordinator. Persistent freshness data is scoped to an opaque account identity so a
 * newly selected account can never inherit another account's successful-sync timestamp.
 */
export class VaultSyncScheduler {
  private readonly staleMs: number;
  private readonly popupStaleMs: number;
  private readonly notificationBurstMs: number;
  private readonly maxTrackedIdentities: number;
  private readonly metadataKey: string;
  private readonly now: () => number;
  private readonly timers: VaultSyncTimers;
  private metadataTail: Promise<void> = Promise.resolve();
  private activeSyncs = 0;
  private notificationTimer: unknown;

  constructor(
    private readonly deps: VaultSyncSchedulerDeps,
    options: VaultSyncSchedulerOptions = {},
  ) {
    this.staleMs = nonNegativeFinite(options.staleMs ?? DEFAULT_VAULT_SYNC_STALE_MS, 'staleMs');
    this.popupStaleMs = nonNegativeFinite(
      options.popupStaleMs ?? DEFAULT_POPUP_SYNC_STALE_MS,
      'popupStaleMs',
    );
    this.notificationBurstMs = nonNegativeFinite(
      options.notificationBurstMs ?? DEFAULT_NOTIFICATION_BURST_MS,
      'notificationBurstMs',
    );
    this.maxTrackedIdentities = positiveInteger(
      options.maxTrackedIdentities ?? DEFAULT_MAX_SYNC_IDENTITIES,
      'maxTrackedIdentities',
    );
    this.metadataKey = options.metadataKey ?? VAULT_SYNC_METADATA_KEY;
    this.now = deps.now ?? (() => Date.now());
    this.timers = deps.timers ?? {
      setTimeout: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
      clearTimeout: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
    };
  }

  async ensureAlarm(): Promise<void> {
    await ensureVaultSyncAlarm(this.deps.alarms);
  }

  async handleAlarm(alarm: string | { name: string }): Promise<void> {
    const name = typeof alarm === 'string' ? alarm : alarm.name;
    if (name !== VAULT_SYNC_ALARM) return;
    const identity = await this.getAccountIdentity();
    if (!identity) return;
    await this.requestIfDirtyOrStale(identity, 'alarm', this.staleMs);
  }

  async startup(): Promise<void> {
    try {
      await this.ensureAlarm();
    } catch (error) {
      this.reportBackgroundError(error);
    }

    const identity = await this.getAccountIdentity();
    if (!identity) return;

    let dirty = true;
    try {
      dirty = await this.deps.isDirty(identity);
    } catch (error) {
      // An unreadable dirty marker is conservatively reconciled with a forced sync.
      this.reportBackgroundError(error);
    }
    if (!(await this.isCurrentUnlockedIdentity(identity))) return;
    if (dirty) {
      await this.trackSync(identity, 'startup', 'force');
      return;
    }
    await this.requestIfDirtyOrStale(identity, 'startup', this.staleMs);
  }

  async sessionSettled(event: VaultSyncSessionSettlement): Promise<void> {
    if (!event.succeeded || event.state !== 'unlocked') return;
    if (event.reason !== 'login' && event.reason !== 'unlock' && event.reason !== 'pinUnlock') return;

    const identity = await this.getUnlockedIdentity();
    if (!identity) return;
    if (event.reason === 'login') {
      await this.trackSync(identity, 'login', 'force');
      return;
    }

    let cacheReady = true;
    try {
      await this.deps.rebuildCache(identity);
    } catch (error) {
      cacheReady = false;
      this.reportBackgroundError(error);
    }
    if (!(await this.isCurrentUnlockedIdentity(identity))) return;
    if (!cacheReady) {
      await this.trackSync(identity, 'unlock', 'coalesce');
      return;
    }
    await this.requestIfDirtyOrStale(identity, 'unlock', this.staleMs);
  }

  /** Start a stale refresh after the caller has rendered its cache; network completion is detached. */
  async popupOpened(): Promise<void> {
    const identity = await this.getUnlockedIdentity();
    if (!identity) return;
    let dirty = true;
    try {
      dirty = await this.deps.isDirty(identity);
    } catch (error) {
      this.reportBackgroundError(error);
    }
    if (!(await this.isCurrentUnlockedIdentity(identity))) return;
    if (dirty) {
      this.observe(this.trackSync(identity, 'popup', 'force'));
      return;
    }
    if (await this.isStale(identity, this.popupStaleMs)) {
      this.observe(this.trackSync(identity, 'popup', 'coalesce'));
    }
  }

  async manual(): Promise<void> {
    const identity = await this.getAccountIdentity();
    if (!identity) return;
    await this.trackSync(identity, 'manual', 'force');
  }

  /** Queue reconciliation after a mutation outcome that cannot safely be treated as fully synced. */
  mutation(): void {
    this.observe(this.requestMutationSync());
  }

  /** Record a sync completed inside a mutation lane without issuing a redundant second request. */
  async recordSuccessfulSync(identity: string): Promise<void> {
    const now = this.now();
    await this.updateIdentity(identity, now, now);
  }

  async getLastSuccess(): Promise<number | undefined> {
    return (await this.getSyncStatus()).lastSuccessfulSyncAt;
  }

  async getSyncStatus(): Promise<VaultSyncStatus> {
    const identity = await this.getAccountIdentity();
    if (!identity) return { dirty: false, syncing: this.activeSyncs > 0 };
    await this.metadataTail;
    const [stored, dirty] = await Promise.all([
      this.deps.metadataStore.get<unknown>(this.metadataKey),
      Promise.resolve(this.deps.isDirty(identity)).catch(() => true),
    ]);
    const lastSuccessfulSyncAt = normalizeMetadata(stored).identities[identity]?.lastSuccess;
    return {
      identity,
      ...(lastSuccessfulSyncAt === undefined ? {} : { lastSuccessfulSyncAt }),
      dirty,
      syncing: this.activeSyncs > 0,
    };
  }

  /** Collapse a burst of server notifications into one trailing coordinator request. */
  notification(): void {
    if (this.notificationTimer !== undefined) this.timers.clearTimeout(this.notificationTimer);
    this.notificationTimer = this.timers.setTimeout(() => {
      this.notificationTimer = undefined;
      this.observe(this.requestNotificationSync());
    }, this.notificationBurstMs);
  }

  dispose(): void {
    if (this.notificationTimer === undefined) return;
    this.timers.clearTimeout(this.notificationTimer);
    this.notificationTimer = undefined;
  }

  private async requestNotificationSync(): Promise<void> {
    const identity = await this.getAccountIdentity();
    if (!identity) return;
    await this.trackSync(identity, 'notification', 'coalesce');
  }

  private async requestMutationSync(): Promise<void> {
    const identity = await this.getAccountIdentity();
    if (!identity) return;
    await this.trackSync(identity, 'mutation', 'force');
  }

  private async requestIfStale(
    identity: string,
    reason: VaultSyncReason,
    staleMs: number,
  ): Promise<void> {
    if (!(await this.isStale(identity, staleMs))) return;
    if (!(await this.isCurrentAccountIdentity(identity))) return;
    await this.trackSync(identity, reason, 'coalesce');
  }

  private async requestIfDirtyOrStale(
    identity: string,
    reason: VaultSyncReason,
    staleMs: number,
  ): Promise<void> {
    let dirty = true;
    try {
      dirty = await this.deps.isDirty(identity);
    } catch (error) {
      this.reportBackgroundError(error);
    }
    if (!(await this.isCurrentAccountIdentity(identity))) return;
    if (dirty) {
      await this.trackSync(identity, reason, 'force');
      return;
    }
    await this.requestIfStale(identity, reason, staleMs);
  }

  private async isStale(identity: string, staleMs: number): Promise<boolean> {
    let entry: VaultSyncIdentityMetadata | undefined;
    try {
      await this.metadataTail;
      const stored = await this.deps.metadataStore.get<unknown>(this.metadataKey);
      entry = normalizeMetadata(stored).identities[identity];
    } catch (error) {
      // Storage failure must not suppress a refresh. A successful request can repair the metadata.
      this.reportBackgroundError(error);
      return true;
    }
    return entry?.lastSuccess === undefined || this.now() - entry.lastSuccess >= staleMs;
  }

  private trackSync(
    identity: string,
    reason: VaultSyncReason,
    policy: VaultSyncPolicy,
  ): Promise<void> {
    this.activeSyncs++;
    const attemptedAt = this.now();
    const attemptWrite = this.updateIdentity(identity, attemptedAt).catch((error: unknown) => {
      this.reportBackgroundError(error);
    });

    let outcome: Promise<{ ok: true } | { ok: false; error: unknown }>;
    try {
      outcome = Promise.resolve(this.deps.requestSync(reason, policy)).then(
        () => ({ ok: true as const }),
        (error: unknown) => ({ ok: false as const, error }),
      );
    } catch (error) {
      outcome = Promise.resolve({ ok: false as const, error });
    }

    return (async () => {
      try {
        await attemptWrite;
        const result = await outcome;
        if (!result.ok) throw result.error;
        const succeededAt = this.now();
        try {
          await this.updateIdentity(identity, attemptedAt, succeededAt);
        } catch (error) {
          this.reportBackgroundError(error);
        }
      } finally {
        this.activeSyncs--;
      }
    })();
  }

  private updateIdentity(identity: string, attemptedAt: number, succeededAt?: number): Promise<void> {
    const operation = this.metadataTail.then(async () => {
      const stored = await this.deps.metadataStore.get<unknown>(this.metadataKey);
      const metadata = normalizeMetadata(stored);
      const current = metadata.identities[identity];
      const lastSuccess = succeededAt === undefined
        ? current?.lastSuccess
        : Math.max(succeededAt, (current?.lastSuccess ?? -1) + 1);
      const entry: VaultSyncIdentityMetadata = {
        lastAttempt: Math.max(current?.lastAttempt ?? attemptedAt, attemptedAt),
        ...(lastSuccess === undefined ? {} : { lastSuccess }),
      };
      const entries: Array<[string, VaultSyncIdentityMetadata]> = [
        ...Object.entries(metadata.identities).filter(([key]) => key !== identity),
        [identity, entry],
      ];
      const identities = Object.fromEntries(entries
        .sort(([identityA, entryA], [identityB, entryB]) => (
          entryB.lastAttempt - entryA.lastAttempt || identityA.localeCompare(identityB)
        ))
        .slice(0, this.maxTrackedIdentities));
      const next: VaultSyncMetadata = {
        schemaVersion: METADATA_SCHEMA_VERSION,
        identities,
      };
      await this.deps.metadataStore.set(this.metadataKey, next);
    });
    this.metadataTail = operation.catch(() => undefined);
    return operation;
  }

  private async getUnlockedIdentity(): Promise<string | undefined> {
    const context = await this.deps.getSessionContext();
    if (context?.state !== 'unlocked') return undefined;
    const identity = context.identity;
    return identity && identity.trim().length > 0 ? identity : undefined;
  }

  private async getAccountIdentity(): Promise<string | undefined> {
    const context = await this.deps.getSessionContext();
    if (!context || context.state === 'loggedOut' || context.state === 'restricted') return undefined;
    const identity = context.identity;
    return identity && identity.trim().length > 0 ? identity : undefined;
  }

  private async isCurrentUnlockedIdentity(identity: string): Promise<boolean> {
    return (await this.getUnlockedIdentity()) === identity;
  }

  private async isCurrentAccountIdentity(identity: string): Promise<boolean> {
    return (await this.getAccountIdentity()) === identity;
  }

  private observe(operation: Promise<void>): void {
    void operation.catch((error: unknown) => {
      this.reportBackgroundError(error);
    });
  }

  private reportBackgroundError(error: unknown): void {
    try {
      this.deps.onBackgroundError?.(error);
    } catch {
      // Error reporting cannot be allowed to break scheduler recovery paths.
    }
  }
}

export function createVaultSyncScheduler(
  deps: VaultSyncSchedulerDeps,
  options?: VaultSyncSchedulerOptions,
): VaultSyncScheduler {
  return new VaultSyncScheduler(deps, options);
}

function normalizeMetadata(value: unknown): VaultSyncMetadata {
  const identities: Record<string, VaultSyncIdentityMetadata> = Object.create(null) as Record<
    string,
    VaultSyncIdentityMetadata
  >;
  if (
    !isRecord(value)
    || value.schemaVersion !== METADATA_SCHEMA_VERSION
    || !isRecord(value.identities)
  ) {
    return { schemaVersion: METADATA_SCHEMA_VERSION, identities };
  }
  for (const [identity, candidate] of Object.entries(value.identities)) {
    if (!identity || !isRecord(candidate) || !isTimestamp(candidate.lastAttempt)) continue;
    if (candidate.lastSuccess !== undefined && !isTimestamp(candidate.lastSuccess)) continue;
    identities[identity] = {
      lastAttempt: candidate.lastAttempt,
      ...(candidate.lastSuccess === undefined ? {} : { lastSuccess: candidate.lastSuccess }),
    };
  }
  return { schemaVersion: METADATA_SCHEMA_VERSION, identities };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isTimestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function nonNegativeFinite(value: number, name: string): number {
  if (!Number.isFinite(value) || value < 0) throw new RangeError(`${name} must be non-negative`);
  return value;
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new RangeError(`${name} must be a positive integer`);
  return value;
}
