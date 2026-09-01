import type { KeyValueStore } from '../platform/store.js';
import {
  canonicalizeWebsitePasskeyRequest,
  serializeCanonicalWebsitePasskeyRequest,
  type CanonicalWebsitePasskeyRequest,
  type WebsitePasskeyUnsupportedReason,
} from '../messaging/website-passkey-port.js';
import type { WebsitePasskeyDocumentContext } from './website-passkey-coordinator.js';

export const WEBSITE_PASSKEY_LOCKED_CONTINUATION_STORAGE_KEY =
  'passkey.websiteLockedContinuation.v1';
export const WEBSITE_PASSKEY_LOCKED_CONTINUATION_SCHEMA_VERSION = 1 as const;
export const DEFAULT_WEBSITE_PASSKEY_LOCKED_CONTINUATION_RETIRE_MS = 120_000;
export const WEBSITE_PASSKEY_LOCKED_CONTINUATION_BYTE_BUDGET = 512 * 1_024;

const MAX_RETIRE_MS = 600_000;
const MAX_REQUEST_LIFETIME_MS = 600_000;
const MAX_RETIRED = 16;
const MAX_DOCUMENT_ID_LENGTH = 4_096;
const MAX_URL_LENGTH = 16_384;
const MAX_TEXT_LENGTH = 4_096;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const storageLanes = new WeakMap<object, Promise<void>>();

export type WebsitePasskeyLockedContinuationTerminalReason =
  | 'authorization_changed'
  | 'cancelled'
  | 'context_changed'
  | 'expired'
  | 'open_failed'
  | 'resumed';

export interface WebsitePasskeyLockedContinuationEnvelope {
  readonly schemaVersion: typeof WEBSITE_PASSKEY_LOCKED_CONTINUATION_SCHEMA_VERSION;
  readonly continuationId: string;
  readonly workerInstanceId: string;
  readonly workerGeneration: number;
  readonly document: WebsitePasskeyDocumentContext;
  readonly request: CanonicalWebsitePasskeyRequest;
  readonly operation: CanonicalWebsitePasskeyRequest['kind'];
  readonly unsupportedReason?: WebsitePasskeyUnsupportedReason;
  readonly accountIdentity: string;
  readonly serverUrl: string;
  readonly policyGeneration: number;
  readonly createdAt: number;
  readonly deadlineAt: number;
  readonly windowId?: number;
  readonly popupDocumentId?: string;
}

export interface WebsitePasskeyLockedContinuationInput {
  readonly document: WebsitePasskeyDocumentContext;
  readonly request: CanonicalWebsitePasskeyRequest;
  readonly unsupportedReason?: WebsitePasskeyUnsupportedReason;
  readonly accountIdentity: string;
  readonly serverUrl: string;
  readonly policyGeneration: number;
  readonly deadlineAt: number;
}

export interface WebsitePasskeyLockedContinuationRetired {
  readonly envelope: WebsitePasskeyLockedContinuationEnvelope;
  readonly reason: WebsitePasskeyLockedContinuationTerminalReason;
  readonly retiredAt: number;
  readonly retireAt: number;
}

export type WebsitePasskeyLockedContinuationLookup =
  | Readonly<{ state: 'pending'; envelope: WebsitePasskeyLockedContinuationEnvelope }>
  | Readonly<{ state: 'retired'; terminal: WebsitePasskeyLockedContinuationRetired }>;

export type WebsitePasskeyLockedContinuationStageResult =
  | Readonly<{
      status: 'created' | 'existing';
      envelope: WebsitePasskeyLockedContinuationEnvelope;
    }>
  | Readonly<{ status: 'busy' }>;

interface StoredState {
  readonly schemaVersion: typeof WEBSITE_PASSKEY_LOCKED_CONTINUATION_SCHEMA_VERSION;
  readonly workerInstanceId: string;
  readonly workerGeneration: number;
  readonly pending?: WebsitePasskeyLockedContinuationEnvelope;
  readonly retired: readonly WebsitePasskeyLockedContinuationRetired[];
}

export interface WebsitePasskeyLockedContinuationStoreOptions {
  readonly store: Pick<KeyValueStore, 'get' | 'set' | 'remove'>;
  readonly workerInstanceId?: string;
  readonly createId?: () => string;
  readonly now?: () => number;
  readonly retireMs?: number;
}

/** One durable, secret-free locked request with bounded replay tombstones. */
export class WebsitePasskeyLockedContinuationStore {
  readonly #store: WebsitePasskeyLockedContinuationStoreOptions['store'];
  readonly #workerInstanceId: string;
  readonly #createId: () => string;
  readonly #now: () => number;
  readonly #retireMs: number;
  readonly #laneKey: object;
  #recovery: Promise<number> | undefined;
  #workerGeneration: number | undefined;

  constructor(options: WebsitePasskeyLockedContinuationStoreOptions) {
    if (!options?.store || typeof options.store.get !== 'function'
        || typeof options.store.set !== 'function' || typeof options.store.remove !== 'function') {
      throw new TypeError('Website passkey locked continuation storage is required');
    }
    this.#store = options.store;
    this.#laneKey = options.store as object;
    this.#workerInstanceId = uuid(
      options.workerInstanceId ?? crypto.randomUUID(),
      'workerInstanceId',
    );
    this.#createId = options.createId ?? (() => crypto.randomUUID());
    this.#now = options.now ?? Date.now;
    this.#retireMs = positiveInteger(
      options.retireMs ?? DEFAULT_WEBSITE_PASSKEY_LOCKED_CONTINUATION_RETIRE_MS,
      MAX_RETIRE_MS,
      'retireMs',
    );
  }

  /** Adopt a surviving request and advance its worker generation before any action can run. */
  recoverWorker(): Promise<number> {
    this.#recovery ??= this.#run(async () => {
      const now = this.#time();
      const current = await this.#read(now, true);
      const workerGeneration = increment(current?.workerGeneration ?? 0, 'workerGeneration');
      const pending = current?.pending
        ? freezeEnvelope({
            ...current.pending,
            workerInstanceId: this.#workerInstanceId,
            workerGeneration,
          }, now, this.#retireMs)
        : undefined;
      const next = state({
        schemaVersion: WEBSITE_PASSKEY_LOCKED_CONTINUATION_SCHEMA_VERSION,
        workerInstanceId: this.#workerInstanceId,
        workerGeneration,
        ...(pending ? { pending } : {}),
        retired: current?.retired ?? Object.freeze([]),
      });
      await this.#write(next);
      this.#workerGeneration = workerGeneration;
      return workerGeneration;
    });
    return this.#recovery;
  }

  async stage(
    input: WebsitePasskeyLockedContinuationInput,
  ): Promise<WebsitePasskeyLockedContinuationStageResult> {
    await this.recoverWorker();
    return this.#run(async () => {
      const now = this.#time();
      const current = await this.#currentState(now);
      const canonical = canonicalInput(input, now);
      if (current.pending) {
        return sameInput(current.pending, canonical)
          ? Object.freeze({ status: 'existing' as const, envelope: cloneEnvelope(current.pending) })
          : Object.freeze({ status: 'busy' as const });
      }
      const continuationId = this.#freshId(current);
      const envelope = freezeEnvelope({
        schemaVersion: WEBSITE_PASSKEY_LOCKED_CONTINUATION_SCHEMA_VERSION,
        continuationId,
        workerInstanceId: this.#workerInstanceId,
        workerGeneration: current.workerGeneration,
        ...canonical,
        operation: canonical.request.kind,
        createdAt: now,
      }, now, this.#retireMs);
      await this.#write(state({ ...current, pending: envelope }));
      return Object.freeze({ status: 'created' as const, envelope: cloneEnvelope(envelope) });
    });
  }

  async find(
    document: WebsitePasskeyDocumentContext,
    request: CanonicalWebsitePasskeyRequest,
  ): Promise<WebsitePasskeyLockedContinuationLookup | undefined> {
    await this.recoverWorker();
    return this.#run(async () => {
      const current = await this.#currentState(this.#time());
      const canonicalDocument = documentContext(document);
      const serialized = serializeCanonicalWebsitePasskeyRequest(
        canonicalizeWebsitePasskeyRequest(request),
      );
      if (current.pending
          && sameDocument(current.pending.document, canonicalDocument)
          && serializeCanonicalWebsitePasskeyRequest(current.pending.request) === serialized) {
        return Object.freeze({ state: 'pending' as const, envelope: cloneEnvelope(current.pending) });
      }
      const terminal = current.retired.find((entry) => (
        sameDocument(entry.envelope.document, canonicalDocument)
        && serializeCanonicalWebsitePasskeyRequest(entry.envelope.request) === serialized
      ));
      return terminal
        ? Object.freeze({ state: 'retired' as const, terminal: cloneRetired(terminal) })
        : undefined;
    });
  }

  async readPending(): Promise<WebsitePasskeyLockedContinuationEnvelope | undefined> {
    await this.recoverWorker();
    return this.#run(async () => {
      const current = await this.#currentState(this.#time());
      return current.pending ? cloneEnvelope(current.pending) : undefined;
    });
  }

  async attachWindow(
    continuationId: string,
    workerGeneration: number,
    windowId: number,
  ): Promise<WebsitePasskeyLockedContinuationEnvelope | undefined> {
    await this.recoverWorker();
    return this.#run(async () => {
      const now = this.#time();
      const current = await this.#currentState(now);
      const id = uuid(continuationId, 'continuationId');
      const generation = nonNegativeInteger(workerGeneration, 'workerGeneration');
      const canonicalWindowId = nonNegativeInteger(windowId, 'windowId');
      const pending = current.pending;
      if (!pending || pending.continuationId !== id
          || pending.workerGeneration !== generation) return undefined;
      if (pending.windowId !== undefined && pending.windowId !== canonicalWindowId) return undefined;
      const updated = freezeEnvelope({ ...pending, windowId: canonicalWindowId }, now, this.#retireMs);
      await this.#write(state({ ...current, pending: updated }));
      return cloneEnvelope(updated);
    });
  }

  async claimPopup(
    continuationId: string,
    popupDocumentId: string,
  ): Promise<WebsitePasskeyLockedContinuationEnvelope | undefined> {
    await this.recoverWorker();
    return this.#run(async () => {
      const now = this.#time();
      const current = await this.#currentState(now);
      const id = uuid(continuationId, 'continuationId');
      const documentId = opaqueText(popupDocumentId, 'popupDocumentId', MAX_DOCUMENT_ID_LENGTH);
      const pending = current.pending;
      if (!pending || pending.continuationId !== id) return undefined;
      if (pending.popupDocumentId !== undefined && pending.popupDocumentId !== documentId) return undefined;
      if (pending.popupDocumentId === documentId) return cloneEnvelope(pending);
      const updated = freezeEnvelope({ ...pending, popupDocumentId: documentId }, now, this.#retireMs);
      await this.#write(state({ ...current, pending: updated }));
      return cloneEnvelope(updated);
    });
  }

  /** Tombstone first, then validate the caller binding so failed claims cannot be replayed. */
  async consume(input: {
    readonly continuationId: string;
    readonly workerGeneration: number;
    readonly reason: WebsitePasskeyLockedContinuationTerminalReason;
    readonly document?: WebsitePasskeyDocumentContext;
    readonly bridgeRequestId?: string;
    readonly popupDocumentId?: string;
    readonly windowId?: number;
  }): Promise<WebsitePasskeyLockedContinuationEnvelope | undefined> {
    await this.recoverWorker();
    return this.#run(async () => {
      const now = this.#time();
      const current = await this.#currentState(now);
      const id = uuid(input.continuationId, 'continuationId');
      const pending = current.pending;
      if (!pending || pending.continuationId !== id) return undefined;
      const reason = terminalReason(input.reason);
      const retired = retire(pending, reason, now, this.#retireMs);
      const { pending: _pending, ...withoutPending } = current;
      await this.#write(state({
        ...withoutPending,
        retired: trimRetired([...current.retired, retired]),
      }));

      let matches = pending.workerInstanceId === this.#workerInstanceId
        && pending.workerGeneration === nonNegativeInteger(input.workerGeneration, 'workerGeneration');
      if (input.document !== undefined) matches &&= sameDocument(
        pending.document,
        documentContext(input.document),
      );
      if (input.bridgeRequestId !== undefined) {
        matches &&= pending.request.bridgeRequestId === uuid(
          input.bridgeRequestId,
          'bridgeRequestId',
        );
      }
      if (input.popupDocumentId !== undefined) {
        matches &&= pending.popupDocumentId === opaqueText(
          input.popupDocumentId,
          'popupDocumentId',
          MAX_DOCUMENT_ID_LENGTH,
        );
      }
      if (input.windowId !== undefined) {
        matches &&= pending.windowId === nonNegativeInteger(input.windowId, 'windowId');
      }
      return matches ? cloneEnvelope(pending) : undefined;
    });
  }

  #freshId(current: StoredState): string {
    for (let attempt = 0; attempt < (MAX_RETIRED + 2); attempt += 1) {
      let id: string;
      try { id = uuid(this.#createId(), 'continuationId'); }
      catch { throw new Error('Website passkey locked continuation id generation failed'); }
      if (current.pending?.continuationId === id) continue;
      if (current.retired.some((entry) => entry.envelope.continuationId === id)) continue;
      return id;
    }
    throw new Error('Website passkey locked continuation id collision');
  }

  async #currentState(now: number): Promise<StoredState> {
    const current = await this.#read(now, false);
    if (!current
        || current.workerInstanceId !== this.#workerInstanceId
        || current.workerGeneration !== this.#workerGeneration) {
      throw new Error('Website passkey locked continuation worker is stale');
    }
    const normalized = normalizeState(current, now, this.#retireMs);
    if (JSON.stringify(normalized) !== JSON.stringify(current)) await this.#write(normalized);
    return normalized;
  }

  async #read(now: number, allowMissing: boolean): Promise<StoredState | undefined> {
    let raw: unknown;
    try { raw = await this.#store.get<unknown>(WEBSITE_PASSKEY_LOCKED_CONTINUATION_STORAGE_KEY); }
    catch { throw new Error('Website passkey locked continuation could not be read'); }
    if (raw === undefined) {
      if (allowMissing) return undefined;
      throw new Error('Website passkey locked continuation state is unavailable');
    }
    try { return normalizeState(parseState(raw, now, this.#retireMs), now, this.#retireMs); }
    catch (error) {
      await this.#store.remove(WEBSITE_PASSKEY_LOCKED_CONTINUATION_STORAGE_KEY).catch(() => undefined);
      throw error;
    }
  }

  async #write(value: StoredState): Promise<void> {
    const canonical = state(value);
    const serialized = JSON.stringify({
      [WEBSITE_PASSKEY_LOCKED_CONTINUATION_STORAGE_KEY]: canonical,
    });
    if (new TextEncoder().encode(serialized).byteLength
        > WEBSITE_PASSKEY_LOCKED_CONTINUATION_BYTE_BUDGET) {
      throw new Error('Website passkey locked continuation storage budget exceeded');
    }
    try { await this.#store.set(WEBSITE_PASSKEY_LOCKED_CONTINUATION_STORAGE_KEY, canonical); }
    catch {
      const current = await this.#store.get<unknown>(
        WEBSITE_PASSKEY_LOCKED_CONTINUATION_STORAGE_KEY,
      ).catch(() => undefined);
      if (JSON.stringify(current) === JSON.stringify(canonical)) return;
      throw new Error('Website passkey locked continuation could not be persisted');
    }
  }

  #time(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0 || Object.is(now, -0)) {
      throw new Error('Website passkey locked continuation clock is invalid');
    }
    return now;
  }

  async #run<Result>(operation: () => Promise<Result>): Promise<Result> {
    const previous = storageLanes.get(this.#laneKey) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((resolve) => { release = resolve; });
    storageLanes.set(this.#laneKey, previous.catch(() => undefined).then(() => next));
    await previous.catch(() => undefined);
    try { return await operation(); }
    finally { release(); }
  }
}

function canonicalInput(
  value: WebsitePasskeyLockedContinuationInput,
  now: number,
): Omit<WebsitePasskeyLockedContinuationEnvelope,
  'schemaVersion' | 'continuationId' | 'workerInstanceId' | 'workerGeneration'
  | 'operation' | 'createdAt' | 'windowId' | 'popupDocumentId'> {
  if (!plainRecord(value)) throw new TypeError('Website passkey locked continuation input is invalid');
  const expected = [
    'accountIdentity', 'deadlineAt', 'document', 'policyGeneration', 'request', 'serverUrl',
  ];
  if (value.unsupportedReason !== undefined) expected.push('unsupportedReason');
  exactKeys(value, expected);
  const request = canonicalizeWebsitePasskeyRequest(dataValue(value, 'request'));
  const deadlineAt = positiveInteger(
    dataValue(value, 'deadlineAt'),
    Number.MAX_SAFE_INTEGER,
    'deadlineAt',
  );
  if (deadlineAt <= now || deadlineAt - now > MAX_REQUEST_LIFETIME_MS) {
    throw new TypeError('Website passkey locked continuation deadline is invalid');
  }
  const unsupportedReason = optionalUnsupportedReason(dataValue(value, 'unsupportedReason'));
  return Object.freeze({
    document: documentContext(dataValue(value, 'document')),
    request,
    ...(unsupportedReason === undefined ? {} : { unsupportedReason }),
    accountIdentity: canonicalIdentity(dataValue(value, 'accountIdentity')),
    serverUrl: secureUrl(dataValue(value, 'serverUrl'), 'serverUrl'),
    policyGeneration: nonNegativeInteger(dataValue(value, 'policyGeneration'), 'policyGeneration'),
    deadlineAt,
  });
}

function parseState(value: unknown, now: number, retireMs: number): StoredState {
  if (!plainRecord(value)) throw new TypeError('Stored website passkey locked continuation is invalid');
  exactKeys(value, ['retired', 'schemaVersion', 'workerGeneration', 'workerInstanceId'], ['pending']);
  if (dataValue(value, 'schemaVersion') !== WEBSITE_PASSKEY_LOCKED_CONTINUATION_SCHEMA_VERSION) {
    throw new TypeError('Stored website passkey locked continuation schema is invalid');
  }
  const rawRetired = dataValue(value, 'retired');
  if (!Array.isArray(rawRetired) || rawRetired.length > MAX_RETIRED) {
    throw new TypeError('Stored website passkey locked continuation tombstones are invalid');
  }
  const workerInstanceId = uuid(dataValue(value, 'workerInstanceId'), 'workerInstanceId');
  const workerGeneration = positiveInteger(
    dataValue(value, 'workerGeneration'),
    Number.MAX_SAFE_INTEGER,
    'workerGeneration',
  );
  const pendingValue = dataValue(value, 'pending');
  const pending = pendingValue === undefined
    ? undefined
    : freezeEnvelope(pendingValue, now, retireMs);
  if (pending && (pending.workerInstanceId !== workerInstanceId
      || pending.workerGeneration !== workerGeneration)) {
    throw new TypeError('Stored website passkey locked continuation worker binding is invalid');
  }
  return state({
    schemaVersion: WEBSITE_PASSKEY_LOCKED_CONTINUATION_SCHEMA_VERSION,
    workerInstanceId,
    workerGeneration,
    ...(pending ? { pending } : {}),
    retired: Object.freeze(rawRetired.map((entry) => parseRetired(entry, now, retireMs))),
  });
}

function normalizeState(value: StoredState, now: number, retireMs: number): StoredState {
  let pending = value.pending;
  const retired = value.retired.filter((entry) => entry.retireAt > now);
  if (pending && pending.deadlineAt <= now) {
    retired.push(retire(pending, 'expired', now, retireMs));
    pending = undefined;
  }
  const { pending: _pending, ...withoutPending } = value;
  return state(pending
    ? { ...withoutPending, pending, retired: trimRetired(retired) }
    : { ...withoutPending, retired: trimRetired(retired) });
}

function freezeEnvelope(
  value: unknown,
  now: number,
  _retireMs: number,
): WebsitePasskeyLockedContinuationEnvelope {
  if (!plainRecord(value)) throw new TypeError('Website passkey locked continuation is invalid');
  const required = [
    'accountIdentity', 'continuationId', 'createdAt', 'deadlineAt', 'document', 'operation',
    'policyGeneration', 'request', 'schemaVersion', 'serverUrl', 'workerGeneration',
    'workerInstanceId',
  ];
  exactKeys(value, required, ['popupDocumentId', 'unsupportedReason', 'windowId']);
  if (dataValue(value, 'schemaVersion') !== WEBSITE_PASSKEY_LOCKED_CONTINUATION_SCHEMA_VERSION) {
    throw new TypeError('Website passkey locked continuation schema is invalid');
  }
  const request = canonicalizeWebsitePasskeyRequest(dataValue(value, 'request'));
  const operation = dataValue(value, 'operation');
  if ((operation !== 'get' && operation !== 'create') || operation !== request.kind) {
    throw new TypeError('Website passkey locked continuation operation is invalid');
  }
  const createdAt = nonNegativeInteger(dataValue(value, 'createdAt'), 'createdAt');
  const deadlineAt = positiveInteger(
    dataValue(value, 'deadlineAt'),
    Number.MAX_SAFE_INTEGER,
    'deadlineAt',
  );
  if (createdAt > now || deadlineAt <= createdAt
      || deadlineAt - createdAt > MAX_REQUEST_LIFETIME_MS) {
    throw new TypeError('Website passkey locked continuation lifetime is invalid');
  }
  const unsupportedReason = optionalUnsupportedReason(dataValue(value, 'unsupportedReason'));
  const windowId = dataValue(value, 'windowId');
  const popupDocumentId = dataValue(value, 'popupDocumentId');
  return Object.freeze({
    schemaVersion: WEBSITE_PASSKEY_LOCKED_CONTINUATION_SCHEMA_VERSION,
    continuationId: uuid(dataValue(value, 'continuationId'), 'continuationId'),
    workerInstanceId: uuid(dataValue(value, 'workerInstanceId'), 'workerInstanceId'),
    workerGeneration: positiveInteger(
      dataValue(value, 'workerGeneration'),
      Number.MAX_SAFE_INTEGER,
      'workerGeneration',
    ),
    document: documentContext(dataValue(value, 'document')),
    request,
    operation,
    ...(unsupportedReason === undefined ? {} : { unsupportedReason }),
    accountIdentity: canonicalIdentity(dataValue(value, 'accountIdentity')),
    serverUrl: secureUrl(dataValue(value, 'serverUrl'), 'serverUrl'),
    policyGeneration: nonNegativeInteger(dataValue(value, 'policyGeneration'), 'policyGeneration'),
    createdAt,
    deadlineAt,
    ...(windowId === undefined ? {} : { windowId: nonNegativeInteger(windowId, 'windowId') }),
    ...(popupDocumentId === undefined
      ? {}
      : { popupDocumentId: opaqueText(popupDocumentId, 'popupDocumentId', MAX_DOCUMENT_ID_LENGTH) }),
  });
}

function parseRetired(
  value: unknown,
  now: number,
  retireMs: number,
): WebsitePasskeyLockedContinuationRetired {
  if (!plainRecord(value)) throw new TypeError('Website passkey locked continuation tombstone is invalid');
  exactKeys(value, ['envelope', 'reason', 'retireAt', 'retiredAt']);
  const envelope = freezeEnvelope(dataValue(value, 'envelope'), now, retireMs);
  const retiredAt = nonNegativeInteger(dataValue(value, 'retiredAt'), 'retiredAt');
  const retireAt = positiveInteger(dataValue(value, 'retireAt'), Number.MAX_SAFE_INTEGER, 'retireAt');
  if (retiredAt < envelope.createdAt || retireAt <= retiredAt || retireAt - retiredAt > retireMs) {
    throw new TypeError('Website passkey locked continuation tombstone lifetime is invalid');
  }
  return Object.freeze({
    envelope,
    reason: terminalReason(dataValue(value, 'reason')),
    retiredAt,
    retireAt,
  });
}

function retire(
  envelope: WebsitePasskeyLockedContinuationEnvelope,
  reason: WebsitePasskeyLockedContinuationTerminalReason,
  now: number,
  retireMs: number,
): WebsitePasskeyLockedContinuationRetired {
  return Object.freeze({
    envelope,
    reason,
    retiredAt: now,
    retireAt: safeAdd(now, retireMs),
  });
}

function state(value: StoredState): StoredState {
  return Object.freeze({
    schemaVersion: WEBSITE_PASSKEY_LOCKED_CONTINUATION_SCHEMA_VERSION,
    workerInstanceId: value.workerInstanceId,
    workerGeneration: value.workerGeneration,
    ...(value.pending ? { pending: value.pending } : {}),
    retired: Object.freeze([...value.retired]),
  });
}

function trimRetired(
  entries: readonly WebsitePasskeyLockedContinuationRetired[],
): readonly WebsitePasskeyLockedContinuationRetired[] {
  return Object.freeze(entries.slice(-MAX_RETIRED));
}

function sameInput(
  envelope: WebsitePasskeyLockedContinuationEnvelope,
  input: ReturnType<typeof canonicalInput>,
): boolean {
  return sameDocument(envelope.document, input.document)
    && serializeCanonicalWebsitePasskeyRequest(envelope.request)
      === serializeCanonicalWebsitePasskeyRequest(input.request)
    && envelope.unsupportedReason === input.unsupportedReason
    && envelope.accountIdentity === input.accountIdentity
    && envelope.serverUrl === input.serverUrl
    && envelope.policyGeneration === input.policyGeneration
    && envelope.deadlineAt === input.deadlineAt;
}

function sameDocument(
  left: WebsitePasskeyDocumentContext,
  right: WebsitePasskeyDocumentContext,
): boolean {
  return left.tabId === right.tabId
    && left.frameId === right.frameId
    && left.documentId === right.documentId
    && left.url === right.url
    && left.origin === right.origin;
}

function documentContext(value: unknown): WebsitePasskeyDocumentContext {
  if (!plainRecord(value)) throw new TypeError('Website passkey locked document is invalid');
  exactKeys(value, ['documentId', 'frameId', 'origin', 'tabId', 'url']);
  const url = secureUrl(dataValue(value, 'url'), 'url');
  const origin = secureOrigin(dataValue(value, 'origin'));
  if (new URL(url).origin !== origin) throw new TypeError('Website passkey locked document origin changed');
  return Object.freeze({
    tabId: nonNegativeInteger(dataValue(value, 'tabId'), 'tabId'),
    frameId: nonNegativeInteger(dataValue(value, 'frameId'), 'frameId'),
    documentId: opaqueText(dataValue(value, 'documentId'), 'documentId', MAX_DOCUMENT_ID_LENGTH),
    url,
    origin,
  });
}

function cloneEnvelope(
  value: WebsitePasskeyLockedContinuationEnvelope,
): WebsitePasskeyLockedContinuationEnvelope {
  return Object.freeze({
    ...value,
    document: Object.freeze({ ...value.document }),
    request: canonicalizeWebsitePasskeyRequest(structuredClone(value.request)),
  });
}

function cloneRetired(
  value: WebsitePasskeyLockedContinuationRetired,
): WebsitePasskeyLockedContinuationRetired {
  return Object.freeze({ ...value, envelope: cloneEnvelope(value.envelope) });
}

function optionalUnsupportedReason(value: unknown): WebsitePasskeyUnsupportedReason | undefined {
  if (value === undefined) return undefined;
  if (value === 'silent_mediation' || value === 'required_user_verification'
      || value === 'unsupported_algorithm' || value === 'unsupported_attachment') return value;
  throw new TypeError('Website passkey locked unsupported reason is invalid');
}

function terminalReason(value: unknown): WebsitePasskeyLockedContinuationTerminalReason {
  if (value === 'authorization_changed' || value === 'cancelled'
      || value === 'context_changed' || value === 'expired'
      || value === 'open_failed' || value === 'resumed') return value;
  throw new TypeError('Website passkey locked continuation terminal reason is invalid');
}

function canonicalIdentity(value: unknown): string {
  const identity = opaqueText(value, 'accountIdentity', MAX_TEXT_LENGTH).toLowerCase();
  if (identity !== value) throw new TypeError('Website passkey locked account identity is invalid');
  return identity;
}

function secureOrigin(value: unknown): string {
  if (typeof value !== 'string' || !value || value.length > MAX_URL_LENGTH
      || value.trim() !== value || containsControl(value)) {
    throw new TypeError('Website passkey locked origin is invalid');
  }
  let url: URL;
  try { url = new URL(value); } catch {
    throw new TypeError('Website passkey locked origin is invalid');
  }
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1'
    || url.hostname === '[::1]';
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))
      || url.username || url.password || url.origin !== value
      || url.pathname !== '/' || url.search || url.hash) {
    throw new TypeError('Website passkey locked origin is invalid');
  }
  return url.origin;
}

function secureUrl(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value || value.length > MAX_URL_LENGTH
      || value.trim() !== value || containsControl(value)) throw new TypeError(`${field} is invalid`);
  let url: URL;
  try { url = new URL(value); } catch { throw new TypeError(`${field} is invalid`); }
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1'
    || url.hostname === '[::1]';
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))
      || url.username || url.password || url.href !== value) throw new TypeError(`${field} is invalid`);
  return url.href;
}

function opaqueText(value: unknown, field: string, maximum: number): string {
  if (typeof value !== 'string' || !value || value.length > maximum
      || value.trim() !== value || containsControl(value)) throw new TypeError(`${field} is invalid`);
  return value;
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  const keys = Reflect.ownKeys(value);
  const expected = new Set([...required, ...optional]);
  if (keys.some((key) => typeof key !== 'string' || !expected.has(key))
      || required.some((key) => !keys.includes(key))) {
    throw new TypeError('Website passkey locked continuation fields are invalid');
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      throw new TypeError('Website passkey locked continuation fields are invalid');
    }
  }
}

function dataValue(value: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor?.enumerable && 'value' in descriptor ? descriptor.value : undefined;
}

function uuid(value: unknown, field: string): string {
  if (typeof value !== 'string' || !UUID_V4.test(value)) throw new TypeError(`${field} is invalid`);
  return value;
}

function nonNegativeInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || Object.is(value, -0)) {
    throw new TypeError(`${field} is invalid`);
  }
  return value as number;
}

function positiveInteger(value: unknown, maximum: number, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > maximum) {
    throw new TypeError(`${field} is invalid`);
  }
  return value as number;
}

function increment(value: number, field: string): number {
  return positiveInteger(safeAdd(value, 1), Number.MAX_SAFE_INTEGER, field);
}

function safeAdd(left: number, right: number): number {
  const result = left + right;
  if (!Number.isSafeInteger(result)) throw new TypeError('Website passkey locked lifetime is invalid');
  return result;
}

function containsControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}
