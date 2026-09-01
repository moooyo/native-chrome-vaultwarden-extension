import { AppError } from '../core/errors.js';
import {
  canonicalizeServerCapabilityUrl,
  createServerCapabilityScope,
  evaluateServerCapabilities,
  normalizeServerEnvironmentUrl,
  scopeServerObservation,
  type ClientCapabilityDeclaration,
  type ServerCapabilities,
} from '../core/api/server-capabilities.js';

const CAPABILITY_LEASE_OWNER: unique symbol = Symbol('serverCapabilityLeaseOwner');
const DEFAULT_TTL_MS = 5 * 60_000;
const DEFAULT_UNAVAILABLE_TTL_MS = 30_000;
const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1_024;
const MIN_TTL_MS = 1;
const MAX_TTL_MS = 24 * 60 * 60_000;
const MIN_RESPONSE_BYTES = 1_024;
const MAX_RESPONSE_BYTES = 1024 * 1_024;
const MAX_ACCOUNT_IDENTITY_LENGTH = 512;
const MAX_TOP_LEVEL_PROPERTIES = 128;
const MAX_SERVER_PROPERTIES = 32;
const MAX_ENVIRONMENT_PROPERTIES = 32;
const MAX_FEATURE_STATES = 512;
const MAX_FEATURE_KEY_LENGTH = 256;
const MAX_FEATURE_STRING_LENGTH = 4_096;
const MAX_VERSION_LENGTH = 128;
const MAX_SERVER_NAME_LENGTH = 256;

const ENVIRONMENT_URL_KEYS = [
  'vault',
  'api',
  'identity',
  'notifications',
  'sso',
] as const;

export interface ServerCapabilityIdentity {
  readonly serverUrl: string;
  /** A caller-owned canonical account identity. Omit it for anonymous server capabilities. */
  readonly accountIdentity?: string;
}

export interface ServerCapabilityIdentityCapture<IdentityLease extends object> {
  readonly identity: ServerCapabilityIdentity;
  /** An opaque, non-secret lease that detects server/account transitions, including ABA. */
  readonly lease: IdentityLease;
}

export interface ServerConfigFetchRequest {
  readonly serverUrl: string;
  readonly configUrl: string;
  readonly maxResponseBytes: number;
  readonly credentials: 'omit';
}

export interface ServerConfigFetchResponse {
  readonly body: unknown;
  /** UTF-8 response size measured before JSON parsing. */
  readonly responseBytes: number;
}

export type ServerCapabilityUnavailableReason = 'fetch_failed' | 'invalid_response';

interface ServerCapabilitySnapshotBase {
  readonly identity: Readonly<ServerCapabilityIdentity>;
  readonly generation: number;
  readonly fetchedAt: number;
  readonly expiresAt: number;
  readonly capabilities: ServerCapabilities;
}

export interface AvailableServerCapabilitySnapshot extends ServerCapabilitySnapshotBase {
  readonly availability: 'available';
}

export interface UnavailableServerCapabilitySnapshot extends ServerCapabilitySnapshotBase {
  readonly availability: 'unavailable';
  readonly reason: ServerCapabilityUnavailableReason;
}

export type ServerCapabilitySnapshot =
  | AvailableServerCapabilitySnapshot
  | UnavailableServerCapabilitySnapshot;

export interface ServerCapabilityLease {
  readonly generation: number;
  readonly serverUrl: string;
  readonly accountIdentity?: string;
}

/** Opaque authorization for one type-5 write operation. */
export interface SshCipherType5WriteAuthorization {
  /** Revalidate the account and capability generations immediately before the network write. */
  assertCurrent(): void;
}

/** Opaque authorization for one cipher archive operation. */
export interface CipherArchiveAuthorization {
  /** Revalidate the account and capability generations immediately before the network write. */
  assertCurrent(): void;
}

export interface OrganizationDataOwnershipTransportAuthorization {
  readonly serverKind: 'bitwarden' | 'vaultwarden';
  assertCurrent(): void;
}

/** Trusted Web Vault destination for the current server capability generation. */
export interface TwoFactorRecoveryAuthorization {
  readonly url: string;
  assertCurrent(): void;
}

/** Opaque authorization for Bitwarden's association-preserving collection name update. */
export interface CollectionNameOnlyUpdateAuthorization {
  assertCurrent(): void;
}

interface OwnedServerCapabilityLease extends ServerCapabilityLease {
  readonly [CAPABILITY_LEASE_OWNER]: symbol;
}

export interface ServerCapabilityManagerDeps<IdentityLease extends object> {
  /** Capture the current canonical identity and a revocable lease for that exact transition. */
  captureIdentity():
    | ServerCapabilityIdentityCapture<IdentityLease>
    | PromiseLike<ServerCapabilityIdentityCapture<IdentityLease>>;
  assertIdentityCurrent(lease: IdentityLease): void;
  /** Fetch and parse /api/config without credentials, respecting maxResponseBytes. */
  fetchConfig(request: Readonly<ServerConfigFetchRequest>): PromiseLike<ServerConfigFetchResponse>;
  clientDeclaration?: ClientCapabilityDeclaration;
  now?: () => number;
  ttlMs?: number;
  unavailableTtlMs?: number;
  maxResponseBytes?: number;
}

interface CanonicalIdentityCapture<IdentityLease extends object> {
  readonly identity: Readonly<ServerCapabilityIdentity>;
  readonly key: string;
  readonly lease: IdentityLease;
}

interface CachedSnapshot<IdentityLease extends object> {
  readonly snapshot: ServerCapabilitySnapshot;
  readonly identityCapture: CanonicalIdentityCapture<IdentityLease>;
}

interface ActiveContext<IdentityLease extends object>
  extends CanonicalIdentityCapture<IdentityLease> {
  readonly epoch: number;
}

interface CapabilityFlight<IdentityLease extends object> {
  readonly key: string;
  readonly epoch: number;
  readonly identityCapture: CanonicalIdentityCapture<IdentityLease>;
  readonly promise: Promise<ServerCapabilitySnapshot>;
}

export interface ResolveServerCapabilitiesOptions {
  readonly forceRefresh?: boolean;
}

/**
 * Keeps fail-closed /api/config decisions inside one server/account generation. Identity leases are
 * retained only in memory and are revalidated before cache reuse and immediately before publish.
 */
export class ServerCapabilityManager<IdentityLease extends object> {
  readonly #owner = Symbol('serverCapabilityManager');
  readonly #issuedLeases = new WeakSet<object>();
  readonly #cache = new Map<string, CachedSnapshot<IdentityLease>>();
  readonly #flights = new Map<string, CapabilityFlight<IdentityLease>>();
  readonly #now: () => number;
  readonly #ttlMs: number;
  readonly #unavailableTtlMs: number;
  readonly #maxResponseBytes: number;
  #generation = 0;
  #epoch = 0;
  #activeContext: ActiveContext<IdentityLease> | undefined;
  #currentEntry: CachedSnapshot<IdentityLease> | undefined;

  constructor(private readonly deps: ServerCapabilityManagerDeps<IdentityLease>) {
    this.#now = deps.now ?? (() => Date.now());
    this.#ttlMs = boundedInteger(deps.ttlMs ?? DEFAULT_TTL_MS, MIN_TTL_MS, MAX_TTL_MS, 'ttlMs');
    this.#unavailableTtlMs = boundedInteger(
      deps.unavailableTtlMs ?? DEFAULT_UNAVAILABLE_TTL_MS,
      MIN_TTL_MS,
      MAX_TTL_MS,
      'unavailableTtlMs',
    );
    this.#maxResponseBytes = boundedInteger(
      deps.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
      MIN_RESPONSE_BYTES,
      MAX_RESPONSE_BYTES,
      'maxResponseBytes',
    );
    this.readNow();
  }

  async resolve(
    options: ResolveServerCapabilitiesOptions = {},
  ): Promise<ServerCapabilitySnapshot> {
    const callerCapture = await this.captureCanonicalIdentity();
    this.assertExternalIdentity(callerCapture);
    this.reconcileIdentity(callerCapture);

    const context = this.#activeContext;
    if (!context || context.key !== callerCapture.key) throw transitionError();

    const existingFlight = this.#flights.get(context.key);
    if (existingFlight && existingFlight.epoch === context.epoch) {
      if (this.isExternalIdentityCurrent(existingFlight.identityCapture)) {
        return this.awaitForCaller(existingFlight.promise, callerCapture);
      }
      if (this.#flights.get(context.key) === existingFlight) this.#flights.delete(context.key);
    }

    if (!options.forceRefresh) {
      const cached = this.#cache.get(context.key);
      if (cached && this.isCacheEntryCurrent(cached, context)) return cached.snapshot;
      if (cached) this.#cache.delete(context.key);
    }

    const refreshContext = this.beginRefresh(callerCapture);
    const promise = this.fetchAndPublish(refreshContext);
    const flight: CapabilityFlight<IdentityLease> = Object.freeze({
      key: refreshContext.key,
      epoch: refreshContext.epoch,
      identityCapture: callerCapture,
      promise,
    });
    const cleanup = (): void => {
      if (this.#flights.get(refreshContext.key) === flight) {
        this.#flights.delete(refreshContext.key);
      }
    };
    this.#flights.set(refreshContext.key, flight);
    void promise.then(cleanup, cleanup);
    return this.awaitForCaller(promise, callerCapture);
  }

  current(): ServerCapabilitySnapshot | undefined {
    const entry = this.#currentEntry;
    const context = this.#activeContext;
    if (!entry || !context || !this.isCacheEntryCurrent(entry, context)) {
      if (entry) this.revokeCurrent();
      return undefined;
    }
    return entry.snapshot;
  }

  capture(): ServerCapabilityLease {
    const snapshot = this.current();
    if (!snapshot) {
      throw new AppError('sync_required', 'Server capability state is unavailable.');
    }
    const lease: OwnedServerCapabilityLease = Object.freeze({
      generation: snapshot.generation,
      serverUrl: snapshot.identity.serverUrl,
      ...(snapshot.identity.accountIdentity === undefined
        ? {}
        : { accountIdentity: snapshot.identity.accountIdentity }),
      [CAPABILITY_LEASE_OWNER]: this.#owner,
    });
    this.#issuedLeases.add(lease);
    return lease;
  }

  assert(lease: ServerCapabilityLease): ServerCapabilitySnapshot {
    const owned = lease as Partial<OwnedServerCapabilityLease>;
    const current = this.current();
    if (
      !isObject(lease)
      || !this.#issuedLeases.has(lease)
      || owned[CAPABILITY_LEASE_OWNER] !== this.#owner
      || !current
      || lease.generation !== this.#generation
      || lease.generation !== current.generation
      || lease.serverUrl !== current.identity.serverUrl
      || lease.accountIdentity !== current.identity.accountIdentity
    ) {
      throw new AppError('denied', 'Server capability state changed during the operation.');
    }
    return current;
  }

  /** Revoke all leases, cached observations, and pending publications. */
  invalidate(): void {
    this.#epoch += 1;
    this.#generation += 1;
    this.#activeContext = undefined;
    this.#currentEntry = undefined;
    this.#cache.clear();
    this.#flights.clear();
  }

  private async captureCanonicalIdentity(): Promise<CanonicalIdentityCapture<IdentityLease>> {
    const captured = await this.deps.captureIdentity();
    if (!isObject(captured) || !isObject(captured.identity) || !isObject(captured.lease)) {
      throw new AppError('denied', 'Server capability identity is invalid.');
    }
    const serverUrl = canonicalizeServerCapabilityUrl(captured.identity.serverUrl);
    const accountIdentity = canonicalAccountIdentity(captured.identity.accountIdentity);
    const identity = Object.freeze({
      serverUrl,
      ...(accountIdentity === undefined ? {} : { accountIdentity }),
    });
    return Object.freeze({
      identity,
      key: identityKey(identity),
      lease: captured.lease,
    });
  }

  private reconcileIdentity(capture: CanonicalIdentityCapture<IdentityLease>): void {
    const active = this.#activeContext;
    if (
      active
      && active.key === capture.key
      && this.isExternalIdentityCurrent(active)
    ) return;

    this.#epoch += 1;
    this.#generation += 1;
    this.#currentEntry = undefined;
    // A prior identity lease cannot become valid again after a transition, even for an ABA key.
    this.#cache.clear();
    this.#flights.clear();
    this.#activeContext = Object.freeze({ ...capture, epoch: this.#epoch });
  }

  private beginRefresh(
    capture: CanonicalIdentityCapture<IdentityLease>,
  ): ActiveContext<IdentityLease> {
    this.#epoch += 1;
    this.#generation += 1;
    this.#currentEntry = undefined;
    this.#cache.clear();
    this.#flights.clear();
    const context = Object.freeze({ ...capture, epoch: this.#epoch });
    this.#activeContext = context;
    return context;
  }

  private async fetchAndPublish(
    context: ActiveContext<IdentityLease>,
  ): Promise<ServerCapabilitySnapshot> {
    const request = Object.freeze({
      serverUrl: context.identity.serverUrl,
      configUrl: new URL('api/config', context.identity.serverUrl).toString(),
      maxResponseBytes: this.#maxResponseBytes,
      credentials: 'omit' as const,
    });

    let response: ServerConfigFetchResponse;
    try {
      this.assertAttempt(context);
      response = await this.deps.fetchConfig(request);
      this.assertAttempt(context);
    } catch {
      if (!this.isAttemptCurrent(context)) throw transitionError();
      this.assertAttempt(context);
      return this.publish(context, undefined, 'fetch_failed');
    }

    const projectedConfig = projectConfigResponse(response, this.#maxResponseBytes);
    this.assertAttempt(context);
    return this.publish(
      context,
      projectedConfig,
      projectedConfig ? undefined : 'invalid_response',
    );
  }

  private publish(
    context: ActiveContext<IdentityLease>,
    projectedConfig: Record<string, unknown> | undefined,
    unavailableReason: ServerCapabilityUnavailableReason | undefined,
  ): ServerCapabilitySnapshot {
    this.assertAttempt(context);
    const fetchedAt = this.readNow();
    const generation = ++this.#generation;
    const scope = createServerCapabilityScope(context.identity.serverUrl, generation);
    const capabilities = evaluateServerCapabilities(
      scope,
      projectedConfig
        ? { config: scopeServerObservation(scope, projectedConfig) }
        : {},
      this.deps.clientDeclaration,
    );
    const ttl = unavailableReason ? this.#unavailableTtlMs : this.#ttlMs;
    const base = {
      identity: context.identity,
      generation,
      fetchedAt,
      expiresAt: safeExpiry(fetchedAt, ttl),
      capabilities,
    };
    const snapshot: ServerCapabilitySnapshot = Object.freeze(unavailableReason
      ? { ...base, availability: 'unavailable' as const, reason: unavailableReason }
      : { ...base, availability: 'available' as const });
    const entry: CachedSnapshot<IdentityLease> = Object.freeze({
      snapshot,
      identityCapture: context,
    });
    this.#cache.set(context.key, entry);
    this.#currentEntry = entry;
    return snapshot;
  }

  private async awaitForCaller(
    promise: Promise<ServerCapabilitySnapshot>,
    callerCapture: CanonicalIdentityCapture<IdentityLease>,
  ): Promise<ServerCapabilitySnapshot> {
    const snapshot = await promise;
    this.assertExternalIdentity(callerCapture);
    const current = this.#currentEntry;
    if (
      !current
      || current.snapshot !== snapshot
      || current.identityCapture.key !== callerCapture.key
      || snapshot.generation !== this.#generation
    ) throw transitionError();
    return snapshot;
  }

  private isCacheEntryCurrent(
    entry: CachedSnapshot<IdentityLease>,
    context: ActiveContext<IdentityLease>,
  ): boolean {
    if (
      entry.identityCapture.key !== context.key
      || entry.snapshot.generation !== this.#generation
      || this.readNow() >= entry.snapshot.expiresAt
    ) return false;
    return this.isExternalIdentityCurrent(entry.identityCapture);
  }

  private assertAttempt(context: ActiveContext<IdentityLease>): void {
    if (
      this.#epoch !== context.epoch
      || this.#activeContext !== context
    ) throw transitionError();
    this.assertExternalIdentity(context);
  }

  private isAttemptCurrent(context: ActiveContext<IdentityLease>): boolean {
    if (this.#epoch !== context.epoch || this.#activeContext !== context) return false;
    return this.isExternalIdentityCurrent(context);
  }

  private assertExternalIdentity(capture: CanonicalIdentityCapture<IdentityLease>): void {
    try {
      this.deps.assertIdentityCurrent(capture.lease);
    } catch {
      throw transitionError();
    }
  }

  private isExternalIdentityCurrent(
    capture: CanonicalIdentityCapture<IdentityLease>,
  ): boolean {
    try {
      this.deps.assertIdentityCurrent(capture.lease);
      return true;
    } catch {
      return false;
    }
  }

  private revokeCurrent(): void {
    this.#generation += 1;
    this.#currentEntry = undefined;
  }

  private readNow(): number {
    const value = this.#now();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new RangeError('now must return a non-negative safe integer');
    }
    return value;
  }
}

/**
 * Resolve the authoritative server config and bind a type-5 write to that exact capability
 * generation. The underlying lease stays private so callers cannot accidentally cache or forge it.
 */
export async function authorizeSshCipherType5Write<IdentityLease extends object>(
  manager: ServerCapabilityManager<IdentityLease>,
): Promise<SshCipherType5WriteAuthorization> {
  await manager.resolve();
  const lease = manager.capture();
  assertSshCipherType5WriteAvailable(manager.assert(lease));
  return Object.freeze({
    assertCurrent(): void {
      assertSshCipherType5WriteAvailable(manager.assert(lease));
    },
  });
}

/** Resolve and bind archive support to the current account and capability generations. */
export async function authorizeCipherArchive<IdentityLease extends object>(
  manager: ServerCapabilityManager<IdentityLease>,
): Promise<CipherArchiveAuthorization> {
  let lease: ServerCapabilityLease;
  try {
    await manager.resolve();
    lease = manager.capture();
  } catch {
    throw cipherArchiveUnavailable();
  }
  assertCipherArchiveCurrent(manager, lease);
  return Object.freeze({
    assertCurrent(): void {
      assertCipherArchiveCurrent(manager, lease);
    },
  });
}

/** Bind ODO transport selection to one exact server/account capability generation. */
export async function authorizeOrganizationDataOwnershipTransport<IdentityLease extends object>(
  manager: ServerCapabilityManager<IdentityLease>,
): Promise<OrganizationDataOwnershipTransportAuthorization> {
  await manager.resolve();
  const lease = manager.capture();
  const initial = requireKnownServerKind(manager.assert(lease));
  return Object.freeze({
    serverKind: initial,
    assertCurrent(): void {
      if (requireKnownServerKind(manager.assert(lease)) !== initial) {
        throw new AppError('denied', 'Organization data ownership transport changed.');
      }
    },
  });
}

/** Vaultwarden requires full access arrays and therefore cannot safely perform a name-only update. */
export async function authorizeCollectionNameOnlyUpdate<IdentityLease extends object>(
  manager: ServerCapabilityManager<IdentityLease>,
): Promise<CollectionNameOnlyUpdateAuthorization> {
  await manager.resolve();
  const lease = manager.capture();
  assertCollectionNameOnlyUpdateAvailable(manager.assert(lease));
  return Object.freeze({
    assertCurrent(): void {
      assertCollectionNameOnlyUpdateAvailable(manager.assert(lease));
    },
  });
}

/** Resolve the current server's verified Web Vault and bind its recovery route to one lease. */
export async function authorizeTwoFactorRecovery<IdentityLease extends object>(
  manager: ServerCapabilityManager<IdentityLease>,
): Promise<TwoFactorRecoveryAuthorization> {
  let lease: ServerCapabilityLease;
  let url: string;
  try {
    await manager.resolve();
    lease = manager.capture();
    url = twoFactorRecoveryUrl(manager.assert(lease));
  } catch {
    throw twoFactorRecoveryUnavailable();
  }
  return Object.freeze({
    url,
    assertCurrent(): void {
      try {
        if (twoFactorRecoveryUrl(manager.assert(lease)) === url) return;
      } catch {
        // Every failed authorization has one non-disclosing public result.
      }
      throw twoFactorRecoveryUnavailable();
    },
  });
}

function requireKnownServerKind(
  snapshot: ServerCapabilitySnapshot,
): 'bitwarden' | 'vaultwarden' {
  const kind = snapshot.capabilities.config.serverKind;
  if (snapshot.availability !== 'available') {
    throw new AppError('denied', 'Organization data ownership transport is unavailable.');
  }
  if (kind === 'bitwarden' || kind === 'vaultwarden') return kind;
  // Official Bitwarden config responses expose a protocol version and an empty `server` object.
  // Vaultwarden identifies itself by name. Keep named unknown implementations denied while allowing
  // the nameless official shape needed for backend-specific transport selection.
  if (snapshot.capabilities.config.serverName === undefined
      && snapshot.capabilities.config.protocolVersion !== undefined) return 'bitwarden';
  throw new AppError('denied', 'Organization data ownership transport is unavailable.');
}

function assertCollectionNameOnlyUpdateAvailable(snapshot: ServerCapabilitySnapshot): void {
  let kind: 'bitwarden' | 'vaultwarden';
  try {
    kind = requireKnownServerKind(snapshot);
  } catch {
    throw new AppError('denied', 'Safe collection renaming is unavailable for this server.');
  }
  if (kind !== 'bitwarden') {
    throw new AppError('denied', 'Safe collection renaming is unavailable for this server.');
  }
}

function assertSshCipherType5WriteAvailable(snapshot: ServerCapabilitySnapshot): void {
  if (
    snapshot.availability !== 'available'
    || snapshot.capabilities.features.sshCipherType5 !== 'available'
  ) {
    throw new AppError('denied', 'SSH key writes are unavailable for this server and client.');
  }
}

function assertCipherArchiveCurrent<IdentityLease extends object>(
  manager: ServerCapabilityManager<IdentityLease>,
  lease: ServerCapabilityLease,
): void {
  try {
    const snapshot = manager.assert(lease);
    if (
      snapshot.availability === 'available'
      && snapshot.capabilities.features.archive === 'available'
    ) return;
  } catch {
    // Every failed authorization has one non-disclosing public result.
  }
  throw cipherArchiveUnavailable();
}

function cipherArchiveUnavailable(): AppError {
  return new AppError('denied', 'Cipher archiving is unavailable.');
}

function twoFactorRecoveryUrl(snapshot: ServerCapabilitySnapshot): string {
  const vault = snapshot.capabilities.config.environment.vault;
  if (snapshot.availability !== 'available' || !vault) throw twoFactorRecoveryUnavailable();
  const url = new URL(vault);
  url.hash = '/recover-2fa';
  return url.toString();
}

function twoFactorRecoveryUnavailable(): AppError {
  return new AppError('denied', 'Two-step recovery is unavailable for this server.');
}

function projectConfigResponse(
  response: ServerConfigFetchResponse,
  maxResponseBytes: number,
): Record<string, unknown> | undefined {
  if (
    !isObject(response)
    || !Number.isSafeInteger(response.responseBytes)
    || response.responseBytes < 0
    || response.responseBytes > maxResponseBytes
    || !isPlainRecord(response.body)
  ) return undefined;

  try {
    if (Object.keys(response.body).length > MAX_TOP_LEVEL_PROPERTIES) return undefined;
    const projected: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    const version = ownDataProperty(response.body, 'version');
    if (typeof version === 'string' && version.length <= MAX_VERSION_LENGTH) {
      projected.version = version;
    }

    const server = ownDataProperty(response.body, 'server');
    if (isPlainRecord(server) && Object.keys(server).length <= MAX_SERVER_PROPERTIES) {
      const name = ownDataProperty(server, 'name');
      if (typeof name === 'string' && name.length <= MAX_SERVER_NAME_LENGTH) {
        projected.server = { name };
      }
    }

    const environment = ownDataProperty(response.body, 'environment');
    if (
      isPlainRecord(environment)
      && Object.keys(environment).length <= MAX_ENVIRONMENT_PROPERTIES
    ) {
      const boundedEnvironment = Object.create(null) as Record<string, string>;
      for (const key of ENVIRONMENT_URL_KEYS) {
        const url = normalizeServerEnvironmentUrl(ownDataProperty(environment, key));
        if (url) boundedEnvironment[key] = url;
      }
      projected.environment = boundedEnvironment;
    }

    const featureStates = ownDataProperty(response.body, 'featureStates');
    if (isPlainRecord(featureStates)) {
      const entries = Object.entries(featureStates);
      if (entries.length <= MAX_FEATURE_STATES) {
        const boundedStates = Object.create(null) as Record<string, boolean | number | string>;
        for (const [key, value] of entries) {
          if (!key || key.length > MAX_FEATURE_KEY_LENGTH) continue;
          if (typeof value === 'boolean') boundedStates[key] = value;
          if (typeof value === 'number' && Number.isFinite(value)) boundedStates[key] = value;
          if (typeof value === 'string' && value.length <= MAX_FEATURE_STRING_LENGTH) {
            boundedStates[key] = value;
          }
        }
        projected.featureStates = boundedStates;
      }
    }
    return projected;
  } catch {
    return undefined;
  }
}

function ownDataProperty(value: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

function canonicalAccountIdentity(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const normalized = value.trim();
  if (
    !normalized
    || normalized.length > MAX_ACCOUNT_IDENTITY_LENGTH
    || hasAsciiControlCharacter(normalized)
  ) throw new AppError('denied', 'Server capability account identity is invalid.');
  return normalized;
}

function hasAsciiControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function identityKey(identity: Readonly<ServerCapabilityIdentity>): string {
  const accountIdentity = identity.accountIdentity ?? '';
  return `${identity.serverUrl.length}:${identity.serverUrl}${accountIdentity.length}:${accountIdentity}`;
}

function safeExpiry(now: number, ttlMs: number): number {
  const expiry = now + ttlMs;
  return Number.isSafeInteger(expiry) ? expiry : Number.MAX_SAFE_INTEGER;
}

function boundedInteger(value: number, minimum: number, maximum: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(`${field} is outside its supported range`);
  }
  return value;
}

function transitionError(): AppError {
  return new AppError('denied', 'Server capability identity changed during the operation.');
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (!isObject(value) || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}
