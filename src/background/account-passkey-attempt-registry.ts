import type { KeyValueStore } from '../platform/store.js';
import {
  parseAccountPasskeyAssertionOptions,
  type AccountPasskeyAssertionOptions,
} from '../core/api/account-passkey.js';
import { canonicalizeServerCapabilityUrl } from '../core/api/server-capabilities.js';
import {
  ACCOUNT_PASSKEY_ATTEMPT_MAX_TTL_MS,
  parseAccountPasskeyConnectorContext,
  type AccountPasskeyConnectorContext,
} from '../core/session/account-passkey.js';

export const ACCOUNT_PASSKEY_ATTEMPT_STORAGE_KEY = 'accountPasskeyAttempt';
export const ACCOUNT_PASSKEY_ATTEMPT_ENVELOPE_VERSION = 1 as const;
export const ACCOUNT_PASSKEY_ATTEMPT_MAX_UTF8_BYTES = 1024 * 1024;
export const ACCOUNT_PASSKEY_OUTCOME_UNKNOWN_TTL_MS = 5 * 60 * 1000;

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export interface AccountPasskeyAttemptOwner {
  readonly generation: number;
  readonly attemptId: string;
  readonly serverUrl: string;
}

export interface WaitingAccountPasskeyAttempt {
  readonly status: 'waiting';
  readonly owner: AccountPasskeyAttemptOwner;
  readonly connector: AccountPasskeyConnectorContext;
  readonly assertionOptions: AccountPasskeyAssertionOptions;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface ClaimedAccountPasskeyAttempt {
  readonly status: 'claimed';
  readonly owner: AccountPasskeyAttemptOwner;
  readonly connector: AccountPasskeyConnectorContext;
  readonly assertionOptions: AccountPasskeyAssertionOptions;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly workerId: string;
  readonly claimedAt: number;
}

export interface UnknownAccountPasskeyAttempt {
  readonly status: 'outcome_unknown';
  readonly owner: AccountPasskeyAttemptOwner;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly terminalAt: number;
}

export type AccountPasskeyAttempt =
  | WaitingAccountPasskeyAttempt
  | ClaimedAccountPasskeyAttempt
  | UnknownAccountPasskeyAttempt;

export interface AccountPasskeyAttemptRegistryOptions {
  readonly storageKey?: string;
  readonly now?: () => number;
  readonly workerId?: string;
}

interface WaitingEnvelope {
  readonly schemaVersion: typeof ACCOUNT_PASSKEY_ATTEMPT_ENVELOPE_VERSION;
  readonly generation: number;
  readonly status: 'waiting';
  readonly attemptId: string;
  readonly serverUrl: string;
  readonly connector: AccountPasskeyConnectorContext;
  readonly assertionOptions: AccountPasskeyAssertionOptions;
  readonly createdAt: number;
  readonly expiresAt: number;
}

interface ClaimedEnvelope extends Omit<WaitingEnvelope, 'status'> {
  readonly status: 'claimed';
  readonly workerId: string;
  readonly claimedAt: number;
}

interface UnknownEnvelope {
  readonly schemaVersion: typeof ACCOUNT_PASSKEY_ATTEMPT_ENVELOPE_VERSION;
  readonly generation: number;
  readonly status: 'outcome_unknown';
  readonly attemptId: string;
  readonly serverUrl: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly terminalAt: number;
}

type Envelope = WaitingEnvelope | ClaimedEnvelope | UnknownEnvelope;
interface SharedCoordinator { highWaterGeneration: number; readonly queue: OperationQueue }
interface OperationQueue { tail: Promise<void> }

const COORDINATORS = new WeakMap<KeyValueStore, Map<string, SharedCoordinator>>();

/** Persisted one-shot ownership for the single account-passkey assertion attempt. */
export class AccountPasskeyAttemptRegistry {
  readonly #storageKey: string;
  readonly #now: () => number;
  readonly #workerId: string;
  readonly #coordinator: SharedCoordinator;

  constructor(
    private readonly sessionStore: KeyValueStore,
    options: AccountPasskeyAttemptRegistryOptions = {},
  ) {
    this.#storageKey = options.storageKey ?? ACCOUNT_PASSKEY_ATTEMPT_STORAGE_KEY;
    if (!this.#storageKey || this.#storageKey.length > 256) throw new Error('Invalid account passkey storage key');
    this.#now = options.now ?? Date.now;
    this.#workerId = requireWorkerId(options.workerId ?? crypto.randomUUID());
    this.#coordinator = sharedCoordinator(sessionStore, this.#storageKey);
  }

  read(): Promise<AccountPasskeyAttempt | undefined> {
    return this.#serialize(async () => snapshot(await this.#readEnvelope()));
  }

  create(input: {
    readonly attemptId: string;
    readonly serverUrl: string;
    readonly connector: AccountPasskeyConnectorContext;
    readonly assertionOptions: AccountPasskeyAssertionOptions;
    readonly createdAt: number;
    readonly expiresAt: number;
  }): Promise<WaitingAccountPasskeyAttempt> {
    return this.#serialize(async () => {
      if (await this.#readEnvelope()) throw new Error('An account passkey attempt is already active');
      const serverUrl = canonicalizeServerCapabilityUrl(input.serverUrl);
      const envelope: WaitingEnvelope = {
        schemaVersion: ACCOUNT_PASSKEY_ATTEMPT_ENVELOPE_VERSION,
        generation: this.#nextGeneration(),
        status: 'waiting',
        attemptId: requireAttemptId(input.attemptId),
        serverUrl,
        connector: reparseConnector(input.connector, serverUrl),
        assertionOptions: reparseAssertionOptions(input.assertionOptions),
        createdAt: requireTimestamp(input.createdAt, 'createdAt'),
        expiresAt: requireTimestamp(input.expiresAt, 'expiresAt'),
      };
      assertLifetime(envelope, this.#currentTime());
      await this.#writeEnvelope(envelope);
      return snapshot(envelope) as WaitingAccountPasskeyAttempt;
    });
  }

  claim(owner: AccountPasskeyAttemptOwner): Promise<ClaimedAccountPasskeyAttempt | undefined> {
    const expected = parseOwner(owner);
    return this.#serialize(async () => {
      const current = await this.#readEnvelope();
      if (!current || current.status !== 'waiting' || !sameOwner(current, expected)) return undefined;
      const claimedAt = this.#currentTime();
      if (claimedAt >= current.expiresAt) {
        await this.#erase();
        return undefined;
      }
      const envelope: ClaimedEnvelope = {
        ...current,
        generation: this.#nextGeneration(),
        status: 'claimed',
        workerId: this.#workerId,
        claimedAt,
      };
      await this.#writeEnvelope(envelope);
      return snapshot(envelope) as ClaimedAccountPasskeyAttempt;
    });
  }

  markOutcomeUnknown(
    owner: AccountPasskeyAttemptOwner,
  ): Promise<UnknownAccountPasskeyAttempt | undefined> {
    const expected = parseOwner(owner);
    return this.#serialize(async () => {
      const current = await this.#readEnvelope();
      if (!current || current.status !== 'claimed' || !sameOwner(current, expected)) return undefined;
      const terminalAt = this.#currentTime();
      const expiresAt = terminalAt + ACCOUNT_PASSKEY_OUTCOME_UNKNOWN_TTL_MS;
      if (!Number.isSafeInteger(expiresAt)) {
        await this.#erase();
        throw new Error('Account passkey outcome lifetime is invalid');
      }
      const envelope: UnknownEnvelope = {
        schemaVersion: ACCOUNT_PASSKEY_ATTEMPT_ENVELOPE_VERSION,
        generation: this.#nextGeneration(),
        status: 'outcome_unknown',
        attemptId: current.attemptId,
        serverUrl: current.serverUrl,
        createdAt: current.createdAt,
        expiresAt,
        terminalAt,
      };
      await this.#writeEnvelope(envelope);
      return snapshot(envelope) as UnknownAccountPasskeyAttempt;
    });
  }

  clear(owner: AccountPasskeyAttemptOwner): Promise<boolean> {
    const expected = parseOwner(owner);
    return this.#serialize(async () => {
      const current = await this.#readEnvelope();
      if (!current || !sameOwner(current, expected)) return false;
      await this.#erase();
      return true;
    });
  }

  #currentTime(): number {
    return requireTimestamp(this.#now(), 'current time');
  }

  async #readEnvelope(): Promise<Envelope | undefined> {
    const raw = await this.sessionStore.get<unknown>(this.#storageKey);
    if (raw === undefined) return undefined;
    const rawGeneration = isRecord(raw) && Number.isSafeInteger(raw.generation)
      ? raw.generation as number
      : undefined;
    if (rawGeneration !== undefined) {
      this.#coordinator.highWaterGeneration = Math.max(
        this.#coordinator.highWaterGeneration,
        rawGeneration,
      );
    }
    try {
      if (!hasBoundedSize(this.#storageKey, raw)) throw new Error('Stored attempt is oversized');
      const envelope = parseEnvelope(raw);
      this.#coordinator.highWaterGeneration = Math.max(
        this.#coordinator.highWaterGeneration,
        envelope.generation,
      );
      const now = this.#currentTime();
      assertLifetime(envelope, now, true);
      if (now >= envelope.expiresAt) {
        await this.#erase();
        return undefined;
      }
      return envelope;
    } catch {
      await this.#erase();
      return undefined;
    }
  }

  async #writeEnvelope(envelope: Envelope): Promise<void> {
    if (!hasBoundedSize(this.#storageKey, envelope)) {
      throw new Error('Account passkey attempt exceeds the storage limit');
    }
    await this.sessionStore.set(this.#storageKey, envelope);
  }

  #nextGeneration(): number {
    if (this.#coordinator.highWaterGeneration >= Number.MAX_SAFE_INTEGER) {
      void this.sessionStore.remove(this.#storageKey).catch(() => undefined);
      throw new Error('Account passkey attempt generation is exhausted');
    }
    return ++this.#coordinator.highWaterGeneration;
  }

  #erase(): Promise<void> {
    return this.sessionStore.remove(this.#storageKey);
  }

  #serialize<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.#coordinator.queue.tail.then(operation, operation);
    this.#coordinator.queue.tail = run.then(() => undefined, () => undefined);
    return run;
  }
}

function parseEnvelope(input: unknown): Envelope {
  const record = requireRecord(input, 'account passkey attempt');
  if (record.schemaVersion !== ACCOUNT_PASSKEY_ATTEMPT_ENVELOPE_VERSION) {
    throw new Error('Unsupported account passkey attempt schema');
  }
  const generation = requireGeneration(record.generation);
  const status = record.status;
  const serverUrl = canonicalizeServerCapabilityUrl(requireString(record.serverUrl, 'serverUrl', 2048));
  const attemptId = requireAttemptId(record.attemptId);
  const createdAt = requireTimestamp(record.createdAt, 'createdAt');
  const expiresAt = requireTimestamp(record.expiresAt, 'expiresAt');
  if (status === 'outcome_unknown') {
    requireExactKeys(record, [
      'schemaVersion', 'generation', 'status', 'attemptId', 'serverUrl',
      'createdAt', 'expiresAt', 'terminalAt',
    ]);
    return Object.freeze({
      schemaVersion: ACCOUNT_PASSKEY_ATTEMPT_ENVELOPE_VERSION,
      generation,
      status,
      attemptId,
      serverUrl,
      createdAt,
      expiresAt,
      terminalAt: requireTimestamp(record.terminalAt, 'terminalAt'),
    });
  }
  if (status !== 'waiting' && status !== 'claimed') {
    throw new Error('Invalid account passkey attempt status');
  }
  requireExactKeys(record, [
    'schemaVersion', 'generation', 'status', 'attemptId', 'serverUrl', 'connector',
    'assertionOptions', 'createdAt', 'expiresAt',
    ...(status === 'claimed' ? ['workerId', 'claimedAt'] : []),
  ]);
  const connectorRecord = requireRecord(record.connector, 'account passkey connector');
  requireExactKeys(connectorRecord, ['tabId', 'frameId', 'documentId', 'url', 'origin']);
  const connector = parseAccountPasskeyConnectorContext({
    tabId: connectorRecord.tabId,
    frameId: connectorRecord.frameId,
    documentId: connectorRecord.documentId,
    url: connectorRecord.url,
  }, serverUrl);
  if (connectorRecord.origin !== connector.origin) throw new Error('Stored connector origin changed');
  const common = {
    schemaVersion: ACCOUNT_PASSKEY_ATTEMPT_ENVELOPE_VERSION,
    generation,
    attemptId,
    serverUrl,
    connector,
    assertionOptions: reparseAssertionOptions(record.assertionOptions),
    createdAt,
    expiresAt,
  } as const;
  return status === 'waiting'
    ? Object.freeze({ ...common, status })
    : Object.freeze({
        ...common,
        status,
        workerId: requireWorkerId(record.workerId),
        claimedAt: requireTimestamp(record.claimedAt, 'claimedAt'),
      });
}

function reparseAssertionOptions(input: AccountPasskeyAssertionOptions | unknown) {
  const value = requireRecord(input, 'stored account passkey options');
  return parseAccountPasskeyAssertionOptions({
    options: value.options,
    token: value.token,
  });
}

function reparseConnector(input: AccountPasskeyConnectorContext, serverUrl: string) {
  return parseAccountPasskeyConnectorContext({
    tabId: input.tabId,
    frameId: input.frameId,
    documentId: input.documentId,
    url: input.url,
  }, serverUrl);
}

function assertLifetime(envelope: Envelope, now: number, restoring = false): void {
  if (
    envelope.createdAt > now
    || envelope.expiresAt <= envelope.createdAt
    || (!restoring && now >= envelope.expiresAt)
  ) {
    throw new Error('Account passkey attempt lifetime is invalid');
  }
  if (envelope.status !== 'outcome_unknown'
      && envelope.expiresAt - envelope.createdAt > ACCOUNT_PASSKEY_ATTEMPT_MAX_TTL_MS) {
    throw new Error('Account passkey attempt lifetime is invalid');
  }
  if (envelope.status === 'claimed'
      && (envelope.claimedAt < envelope.createdAt || envelope.claimedAt > now)) {
    throw new Error('Account passkey claim time is invalid');
  }
  if (envelope.status === 'outcome_unknown'
      && (
        envelope.terminalAt < envelope.createdAt
        || envelope.terminalAt > now
        || envelope.expiresAt <= envelope.terminalAt
        || envelope.expiresAt - envelope.terminalAt > ACCOUNT_PASSKEY_OUTCOME_UNKNOWN_TTL_MS
      )) {
    throw new Error('Account passkey terminal time is invalid');
  }
}

function snapshot(envelope: Envelope | undefined): AccountPasskeyAttempt | undefined {
  if (!envelope) return undefined;
  const owner = Object.freeze({
    generation: envelope.generation,
    attemptId: envelope.attemptId,
    serverUrl: envelope.serverUrl,
  });
  if (envelope.status === 'outcome_unknown') {
    return Object.freeze({
      status: envelope.status,
      owner,
      createdAt: envelope.createdAt,
      expiresAt: envelope.expiresAt,
      terminalAt: envelope.terminalAt,
    });
  }
  return Object.freeze({
    status: envelope.status,
    owner,
    connector: envelope.connector,
    assertionOptions: envelope.assertionOptions,
    createdAt: envelope.createdAt,
    expiresAt: envelope.expiresAt,
    ...(envelope.status === 'claimed'
      ? { workerId: envelope.workerId, claimedAt: envelope.claimedAt }
      : {}),
  }) as WaitingAccountPasskeyAttempt | ClaimedAccountPasskeyAttempt;
}

function parseOwner(input: AccountPasskeyAttemptOwner): AccountPasskeyAttemptOwner {
  if (!isRecord(input)) throw new Error('Invalid account passkey attempt owner');
  return Object.freeze({
    generation: requireGeneration(input.generation),
    attemptId: requireAttemptId(input.attemptId),
    serverUrl: canonicalizeServerCapabilityUrl(requireString(input.serverUrl, 'serverUrl', 2048)),
  });
}

function sameOwner(envelope: Envelope, owner: AccountPasskeyAttemptOwner): boolean {
  return envelope.generation === owner.generation
    && envelope.attemptId === owner.attemptId
    && envelope.serverUrl === owner.serverUrl;
}

function sharedCoordinator(store: KeyValueStore, storageKey: string): SharedCoordinator {
  let stores = COORDINATORS.get(store);
  if (!stores) {
    stores = new Map();
    COORDINATORS.set(store, stores);
  }
  let coordinator = stores.get(storageKey);
  if (!coordinator) {
    coordinator = { highWaterGeneration: 0, queue: { tail: Promise.resolve() } };
    stores.set(storageKey, coordinator);
  }
  return coordinator;
}

function hasBoundedSize(storageKey: string, value: unknown): boolean {
  try {
    return new TextEncoder().encode(JSON.stringify({ [storageKey]: value })).byteLength
      <= ACCOUNT_PASSKEY_ATTEMPT_MAX_UTF8_BYTES;
  } catch {
    return false;
  }
}

function requireAttemptId(input: unknown): string {
  const value = requireString(input, 'attemptId', 36).toLowerCase();
  if (value.length !== 36 || !UUID_PATTERN.test(value)) {
    throw new Error('Account passkey attempt id must be a UUID');
  }
  return value;
}

function requireWorkerId(input: unknown): string {
  return requireString(input, 'workerId', 256);
}

function requireGeneration(input: unknown): number {
  if (!Number.isSafeInteger(input) || (input as number) <= 0) {
    throw new Error('Account passkey attempt generation is invalid');
  }
  return input as number;
}

function requireTimestamp(input: unknown, name: string): number {
  if (!Number.isSafeInteger(input) || (input as number) < 0) {
    throw new Error(`Account passkey ${name} is invalid`);
  }
  return input as number;
}

function requireString(input: unknown, name: string, maximumLength: number): string {
  if (
    typeof input !== 'string'
    || input.length === 0
    || input.length > maximumLength
    || input.trim() !== input
    || containsAsciiControl(input)
  ) {
    throw new Error(`Account passkey ${name} is invalid`);
  }
  return input;
}

function containsAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function requireExactKeys(record: Record<string, unknown>, keys: readonly string[]): void {
  if (Object.keys(record).length !== keys.length
      || Object.keys(record).some((key) => !keys.includes(key))
      || Object.getOwnPropertySymbols(record).length > 0) {
    throw new Error('Stored account passkey attempt contains unsupported fields');
  }
}

function requireRecord(input: unknown, name: string): Record<string, unknown> {
  if (!isRecord(input)) throw new Error(`${name} must be an object`);
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${name} must be a plain object`);
  }
  return input;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
