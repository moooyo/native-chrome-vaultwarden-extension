import type { KeyValueStore } from '../../platform/store.js';

export const ROTATION_PENDING_STORE_KEY = 'rotationPending';
export const ROTATION_PENDING_SCHEMA_VERSION = 1 as const;

const MAX_SERVER_URL_LENGTH = 4_096;
const MAX_ACCOUNT_ID_LENGTH = 1_024;

export interface RotationPendingIdentity {
  readonly serverUrl: string;
  /** Canonical stable account identifier. The current caller supplies a normalized email address. */
  readonly accountId: string;
}

export interface RotationPendingMarker extends RotationPendingIdentity {
  readonly schemaVersion: typeof ROTATION_PENDING_SCHEMA_VERSION;
  readonly startedAt: number;
}

export type RotationPendingStartupInspection =
  | { readonly kind: 'none'; readonly requiresAccountReset: false }
  | {
      readonly kind: 'pending';
      readonly requiresAccountReset: true;
      readonly marker: RotationPendingMarker;
    }
  | {
      readonly kind: 'invalid';
      readonly requiresAccountReset: true;
      readonly reason: 'corrupt_state' | 'unsupported_schema';
    };

export type RotationPendingStoreErrorCode =
  | 'pending_exists'
  | 'corrupt_state'
  | 'unsupported_schema';

export class RotationPendingStoreError extends Error {
  constructor(
    readonly code: RotationPendingStoreErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'RotationPendingStoreError';
  }
}

export interface RotationPendingStoreOptions {
  readonly storageKey?: string;
  readonly now?: () => number;
}

export interface RotationPendingStartupCleanup {
  readonly resetAllAccounts: () => Promise<void>;
  readonly clearVaultCache: () => Promise<void>;
  readonly clearGeneratorHistoryForServer?: (serverUrl: string) => Promise<void>;
  readonly clearClientEvents?: (identity: RotationPendingIdentity) => Promise<void>;
}

type ParsedMarker =
  | { readonly kind: 'none' }
  | { readonly kind: 'pending'; readonly marker: RotationPendingMarker }
  | { readonly kind: 'corrupt' }
  | { readonly kind: 'unsupported' };

/**
 * Durable write-ahead marker for an account-key rotation. The single slot is intentionally not
 * replaceable: an unresolved rotation must be reconciled by startup cleanup before another POST is
 * allowed. Every operation is linearized so concurrent mark/check/clear calls preserve call order.
 */
export class RotationPendingStore {
  private readonly storageKey: string;
  private readonly now: () => number;
  private operationTail: Promise<void> = Promise.resolve();

  constructor(
    private readonly store: KeyValueStore,
    options: RotationPendingStoreOptions = {},
  ) {
    this.storageKey = options.storageKey ?? ROTATION_PENDING_STORE_KEY;
    this.now = options.now ?? (() => Date.now());
    if (!this.storageKey.trim()) throw new TypeError('storageKey must not be empty');
  }

  /**
   * Persist and await the marker before issuing the irreversible rotation POST. Callers must not
   * send the request when this method rejects, including an ambiguous storage write failure.
   */
  async markBeforeRotation(identity: RotationPendingIdentity): Promise<RotationPendingMarker> {
    const canonical = canonicalizeIdentity(identity);
    return this.serialize(async () => {
      const parsed = parseMarker(await this.store.get<unknown>(this.storageKey));
      if (parsed.kind === 'pending') {
        throw new RotationPendingStoreError(
          'pending_exists',
          'An account-key rotation is already pending reconciliation',
        );
      }
      if (parsed.kind === 'unsupported') {
        throw new RotationPendingStoreError(
          'unsupported_schema',
          'The rotation marker uses an unsupported schema version',
        );
      }
      if (parsed.kind === 'corrupt') {
        throw new RotationPendingStoreError('corrupt_state', 'The rotation marker is corrupt');
      }

      const startedAt = this.now();
      if (!isTimestamp(startedAt)) {
        throw new RangeError('now must return a non-negative safe integer');
      }
      const marker: RotationPendingMarker = {
        schemaVersion: ROTATION_PENDING_SCHEMA_VERSION,
        serverUrl: canonical.serverUrl,
        accountId: canonical.accountId,
        startedAt,
      };
      await this.store.set(this.storageKey, marker);
      return marker;
    });
  }

  /**
   * Inspect durable state during startup. Any result other than `none` requires the caller to clear
   * the active session and account registry before explicitly clearing this marker.
   */
  inspectForStartup(): Promise<RotationPendingStartupInspection> {
    return this.serialize(async () => {
      const parsed = parseMarker(await this.store.get<unknown>(this.storageKey));
      if (parsed.kind === 'none') return { kind: 'none', requiresAccountReset: false };
      if (parsed.kind === 'pending') {
        return { kind: 'pending', requiresAccountReset: true, marker: parsed.marker };
      }
      return {
        kind: 'invalid',
        requiresAccountReset: true,
        reason: parsed.kind === 'unsupported' ? 'unsupported_schema' : 'corrupt_state',
      };
    });
  }

  /** Explicitly clear the slot after the caller has reconciled or reset account state. */
  async clear(): Promise<void> {
    await this.serialize(() => this.store.remove(this.storageKey));
  }

  private serialize<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.operationTail.then(operation, operation);
    this.operationTail = result.then(() => undefined, () => undefined);
    return result;
  }
}

export function createRotationPendingStore(
  store: KeyValueStore,
  options?: RotationPendingStoreOptions,
): RotationPendingStore {
  return new RotationPendingStore(store, options);
}

/**
 * Resolve any durable rotation marker before session initialization. Every configured cleanup is
 * attempted; the marker is cleared only when all succeed, so failures leave startup fail-closed.
 */
export async function recoverPendingRotationOnStartup(
  pending: Pick<RotationPendingStore, 'inspectForStartup' | 'clear'>,
  cleanup: RotationPendingStartupCleanup,
): Promise<boolean> {
  const inspection = await pending.inspectForStartup();
  if (!inspection.requiresAccountReset) return false;

  const failures: unknown[] = [];
  try {
    await cleanup.resetAllAccounts();
  } catch (error) {
    failures.push(error);
  }
  try {
    await cleanup.clearVaultCache();
  } catch (error) {
    failures.push(error);
  }
  if (inspection.kind === 'pending' && cleanup.clearGeneratorHistoryForServer) {
    try {
      await cleanup.clearGeneratorHistoryForServer(inspection.marker.serverUrl);
    } catch (error) {
      failures.push(error);
    }
  }
  if (inspection.kind === 'pending' && cleanup.clearClientEvents) {
    try {
      await cleanup.clearClientEvents(inspection.marker);
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) {
    throw new AggregateError(failures, 'Pending rotation startup cleanup failed');
  }
  await pending.clear();
  return true;
}

/**
 * Keep privileged startup initialization behind durable rotation recovery. A recovery read, reset,
 * cache purge, or marker-clear failure prevents `initialize` from running, so callers cannot publish
 * session gates or accept requests from an account whose remote key-rotation outcome is uncertain.
 */
export async function initializeAfterPendingRotationRecovery<Result>(
  pending: Pick<RotationPendingStore, 'inspectForStartup' | 'clear'>,
  cleanup: RotationPendingStartupCleanup,
  initialize: () => Promise<Result>,
): Promise<Result> {
  await recoverPendingRotationOnStartup(pending, cleanup);
  return initialize();
}

function parseMarker(value: unknown): ParsedMarker {
  if (value === undefined) return { kind: 'none' };
  if (!isRecord(value)) return { kind: 'corrupt' };
  if (isFutureSchemaVersion(value.schemaVersion)) return { kind: 'unsupported' };
  if (
    value.schemaVersion !== ROTATION_PENDING_SCHEMA_VERSION
    || !hasExactMarkerFields(value)
    || typeof value.serverUrl !== 'string'
    || typeof value.accountId !== 'string'
    || !isTimestamp(value.startedAt)
  ) {
    return { kind: 'corrupt' };
  }

  let canonical: RotationPendingIdentity;
  try {
    canonical = canonicalizeIdentity({
      serverUrl: value.serverUrl,
      accountId: value.accountId,
    });
  } catch {
    return { kind: 'corrupt' };
  }
  if (canonical.serverUrl !== value.serverUrl || canonical.accountId !== value.accountId) {
    return { kind: 'corrupt' };
  }
  return {
    kind: 'pending',
    marker: {
      schemaVersion: ROTATION_PENDING_SCHEMA_VERSION,
      serverUrl: canonical.serverUrl,
      accountId: canonical.accountId,
      startedAt: value.startedAt,
    },
  };
}

function canonicalizeIdentity(identity: RotationPendingIdentity): RotationPendingIdentity {
  if (typeof identity.serverUrl !== 'string' || typeof identity.accountId !== 'string') {
    throw new TypeError('Rotation identity fields must be strings');
  }
  const rawServerUrl = identity.serverUrl.trim();
  if (!rawServerUrl || rawServerUrl.length > MAX_SERVER_URL_LENGTH) {
    throw new TypeError('serverUrl must be a non-empty bounded URL');
  }
  const url = new URL(rawServerUrl);
  if (
    (url.protocol !== 'https:' && url.protocol !== 'http:')
    || url.username
    || url.password
    || url.search
    || url.hash
  ) {
    throw new TypeError('serverUrl must be an HTTP(S) URL without credentials, query, or fragment');
  }
  const serverUrl = url.toString();
  if (serverUrl.length > MAX_SERVER_URL_LENGTH) {
    throw new TypeError('serverUrl exceeds the supported length');
  }

  const accountId = identity.accountId.trim().toLowerCase();
  if (!accountId || accountId.length > MAX_ACCOUNT_ID_LENGTH) {
    throw new TypeError('accountId must be non-empty and bounded');
  }
  return { serverUrl, accountId };
}

function hasExactMarkerFields(value: Record<string, unknown>): boolean {
  const fields = Object.keys(value).sort();
  return fields.length === 4
    && fields[0] === 'accountId'
    && fields[1] === 'schemaVersion'
    && fields[2] === 'serverUrl'
    && fields[3] === 'startedAt';
}

function isFutureSchemaVersion(value: unknown): boolean {
  return Number.isSafeInteger(value) && (value as number) > ROTATION_PENDING_SCHEMA_VERSION;
}

function isTimestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}
