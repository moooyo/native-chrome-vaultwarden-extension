import type { KeyValueStore } from '../platform/store.js';
import {
  createDuoChallengeOwner,
  parseDuoCallback,
  sameDuoChallengeOwner,
  type DuoAuthorization,
  type DuoCallbackResult,
  type DuoChallengeOwner,
} from '../core/session/duo-two-factor.js';

export const DUO_ATTEMPT_STORAGE_KEY = 'duoTwoFactorAttempt';
export const DUO_ATTEMPT_TTL_MS = 5 * 60_000;

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export interface DuoAttemptOwner {
  readonly generation: number;
  readonly attemptId: string;
  readonly challenge: DuoChallengeOwner;
}

export interface DuoSourceDocument {
  readonly tabId: number;
  readonly windowId: number;
  readonly documentId: string;
  readonly url: string;
}

export interface DuoSourceContext {
  readonly windowId: number;
  readonly document?: DuoSourceDocument;
}

interface ActiveBinding {
  readonly tabId: number;
  readonly authUrl: string;
  readonly redirectUri: string;
  readonly state: string;
  readonly remember: boolean;
  readonly source: DuoSourceContext;
}

export interface WaitingDuoAttempt extends ActiveBinding {
  readonly status: 'waiting';
  readonly owner: DuoAttemptOwner;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface ClaimedDuoAttempt extends ActiveBinding {
  readonly status: 'claimed';
  readonly owner: DuoAttemptOwner;
  readonly documentId: string;
  readonly workerId: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface SubmittingDuoAttempt extends ActiveBinding {
  readonly status: 'submitting';
  readonly owner: DuoAttemptOwner;
  readonly documentId: string;
  readonly workerId: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface UnknownDuoAttempt {
  readonly status: 'outcome_unknown';
  readonly owner: DuoAttemptOwner;
  readonly tabId: number;
  readonly source: DuoSourceContext;
  readonly documentId: string;
  readonly redirectUri: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly terminalAt: number;
}

export type DuoAttempt = WaitingDuoAttempt | ClaimedDuoAttempt | SubmittingDuoAttempt | UnknownDuoAttempt;

export interface ClaimedDuoCallback {
  readonly attempt: ClaimedDuoAttempt;
  readonly callback: DuoCallbackResult;
}

interface EnvelopeBase {
  readonly schemaVersion: 1;
  readonly generation: number;
  readonly attemptId: string;
  readonly challenge: DuoChallengeOwner;
  readonly createdAt: number;
  readonly expiresAt: number;
}

type Envelope =
  | EnvelopeBase & ActiveBinding & { readonly status: 'waiting' }
  | EnvelopeBase & ActiveBinding & {
      readonly status: 'claimed' | 'submitting';
      readonly documentId: string;
      readonly workerId: string;
    }
  | EnvelopeBase & {
      readonly status: 'outcome_unknown';
      readonly tabId: number;
      readonly source: DuoSourceContext;
      readonly documentId: string;
      readonly redirectUri: string;
      readonly terminalAt: number;
    };

interface Coordinator { generation: number; tail: Promise<void> }
const COORDINATORS = new WeakMap<KeyValueStore, Coordinator>();

export class DuoAttemptWriteUncertainError extends Error {
  override readonly name = 'DuoAttemptWriteUncertainError';

  constructor(
    public readonly owner: DuoAttemptOwner,
    cause: unknown,
    public readonly relatedTabIds: readonly number[] = Object.freeze([]),
  ) {
    super('A Duo attempt write could not be retired.', { cause });
  }
}

export class DuoAttemptStore {
  readonly #now: () => number;
  readonly #workerId: string;
  readonly #createId: () => string;
  readonly #coordinator: Coordinator;

  constructor(
    private readonly store: KeyValueStore,
    options: {
      readonly now?: () => number;
      readonly workerId?: string;
      readonly createAttemptId?: () => string;
    } = {},
  ) {
    this.#now = options.now ?? Date.now;
    this.#workerId = uuid(options.workerId ?? crypto.randomUUID(), 'worker id');
    this.#createId = options.createAttemptId ?? (() => crypto.randomUUID());
    this.#coordinator = COORDINATORS.get(store) ?? { generation: 0, tail: Promise.resolve() };
    COORDINATORS.set(store, this.#coordinator);
  }

  read(): Promise<DuoAttempt | undefined> {
    return this.#serialize(async () => {
      let current = await this.#read();
      if (current?.status === 'submitting' && current.workerId !== this.#workerId) {
        current = await this.#markUnknown(current);
      }
      return current ? snapshot(current) : undefined;
    });
  }

  /** Expose an expired binding only for restart-time scrub/close cleanup, never for grant replay. */
  claimExpiredRestartCleanup(): Promise<DuoAttempt | undefined> {
    return this.#serialize(async () => {
      const now = timestamp(this.#now());
      const current = await this.#readForCleanup(now);
      return current && now >= current.expiresAt ? snapshot(current) : undefined;
    });
  }

  clearExpiredRestartCleanup(expectedOwner: DuoAttemptOwner): Promise<boolean> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const current = await this.#readForCleanup(timestamp(this.#now()));
      if (!current || !sameOwner(current, owner)) return false;
      await this.store.remove(DUO_ATTEMPT_STORAGE_KEY);
      return true;
    });
  }

  /** Transfer a pre-grant callback claim to this worker for scrub-only recovery. */
  claimRestartCleanup(): Promise<ClaimedDuoAttempt | undefined> {
    return this.#serialize(async () => {
      const current = await this.#read();
      if (!current) return undefined;
      if (current.status === 'submitting' && current.workerId !== this.#workerId) {
        await this.#markUnknown(current);
        return undefined;
      }
      if (current.status !== 'claimed' || current.workerId === this.#workerId) return undefined;
      return snapshot(current) as ClaimedDuoAttempt;
    });
  }

  create(input: {
    readonly challenge: DuoChallengeOwner;
    readonly authorization: DuoAuthorization;
    readonly tabId: number;
    readonly remember: boolean;
    readonly source: DuoSourceContext;
  }): Promise<WaitingDuoAttempt> {
    return this.#serialize(async () => {
      if (await this.#read()) throw new Error('A Duo attempt is already active');
      const challenge = createDuoChallengeOwner(input.challenge);
      if (challenge.provider !== input.authorization.provider) {
        throw new TypeError('Duo provider binding changed');
      }
      assertTabId(input.tabId);
      if (typeof input.remember !== 'boolean') throw new TypeError('Duo remember is invalid');
      const source = parseSourceContext(input.source);
      const now = timestamp(this.#now());
      const envelope: Envelope = {
        schemaVersion: 1,
        generation: this.#nextGeneration(),
        attemptId: uuid(this.#createId(), 'attempt id'),
        status: 'waiting',
        challenge,
        tabId: input.tabId,
        authUrl: input.authorization.authUrl,
        redirectUri: input.authorization.redirectUri,
        state: input.authorization.state,
        remember: input.remember,
        source,
        createdAt: now,
        expiresAt: safeAdd(now, DUO_ATTEMPT_TTL_MS),
      };
      await this.#writePreGrant(envelope);
      return snapshot(envelope) as WaitingDuoAttempt;
    });
  }

  createOrReplaceWaiting(input: {
    readonly challenge: DuoChallengeOwner;
    readonly authorization: DuoAuthorization;
    readonly tabId: number;
    readonly remember: boolean;
    readonly source: DuoSourceContext;
  }): Promise<{
    readonly attempt: WaitingDuoAttempt;
    readonly replaced?: WaitingDuoAttempt;
  }> {
    return this.#serialize(async () => {
      const current = await this.#read();
      const challenge = createDuoChallengeOwner(input.challenge);
      if (current && (
        current.status !== 'waiting'
        || !sameDuoChallengeOwner(current.challenge, challenge)
      )) throw new Error('A different Duo attempt is already active');
      if (challenge.provider !== input.authorization.provider) {
        throw new TypeError('Duo provider binding changed');
      }
      assertTabId(input.tabId);
      if (typeof input.remember !== 'boolean') throw new TypeError('Duo remember is invalid');
      const source = parseSourceContext(input.source);
      const now = timestamp(this.#now());
      const envelope: Envelope = {
        schemaVersion: 1,
        generation: this.#nextGeneration(),
        attemptId: uuid(this.#createId(), 'attempt id'),
        status: 'waiting',
        challenge,
        tabId: input.tabId,
        authUrl: input.authorization.authUrl,
        redirectUri: input.authorization.redirectUri,
        state: input.authorization.state,
        remember: input.remember,
        source,
        createdAt: now,
        expiresAt: safeAdd(now, DUO_ATTEMPT_TTL_MS),
      };
      await this.#writeReplacement(envelope, current);
      return Object.freeze({
        attempt: snapshot(envelope) as WaitingDuoAttempt,
        ...(current ? { replaced: snapshot(current) as WaitingDuoAttempt } : {}),
      });
    });
  }

  claimCallback(
    expectedOwner: DuoAttemptOwner,
    input: { readonly tabId: number; readonly documentId: string; readonly callbackUrl: string },
  ): Promise<ClaimedDuoCallback | undefined> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const current = await this.#read();
      if (!current || current.status !== 'waiting' || !sameOwner(current, owner)
          || current.tabId !== input.tabId) return undefined;
      const documentId = boundedString(input.documentId, 512, 'document id');
      const callback = parseDuoCallback(input.callbackUrl, current);
      const claimed: Envelope = {
        ...current,
        generation: this.#nextGeneration(),
        status: 'claimed',
        documentId,
        workerId: this.#workerId,
      };
      await this.#writeReplacement(claimed, current);
      return Object.freeze({ attempt: snapshot(claimed) as ClaimedDuoAttempt, callback });
    });
  }

  startSubmission(expectedOwner: DuoAttemptOwner): Promise<SubmittingDuoAttempt | undefined> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const current = await this.#read();
      if (!current || current.status !== 'claimed' || !sameOwner(current, owner)
          || current.workerId !== this.#workerId) return undefined;
      const submitting: Envelope = {
        ...current,
        generation: this.#nextGeneration(),
        status: 'submitting',
      };
      await this.#writeReplacement(submitting, current);
      return snapshot(submitting) as SubmittingDuoAttempt;
    });
  }

  markOutcomeUnknown(expectedOwner: DuoAttemptOwner): Promise<UnknownDuoAttempt | undefined> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const current = await this.#read();
      if (!current || (current.status !== 'claimed' && current.status !== 'submitting')
          || !sameOwner(current, owner)) return undefined;
      return snapshot(await this.#markUnknown(current)) as UnknownDuoAttempt;
    });
  }

  cancelWaiting(expectedOwner: DuoAttemptOwner): Promise<boolean> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const current = await this.#read();
      if (!current || current.status !== 'waiting' || !sameOwner(current, owner)) return false;
      await this.store.remove(DUO_ATTEMPT_STORAGE_KEY);
      return true;
    });
  }

  clear(expectedOwner: DuoAttemptOwner): Promise<boolean> {
    const owner = parseOwner(expectedOwner);
    return this.#serialize(async () => {
      const current = await this.#read();
      if (!current || !sameOwner(current, owner)) return false;
      await this.store.remove(DUO_ATTEMPT_STORAGE_KEY);
      return true;
    });
  }

  async #read(): Promise<Envelope | undefined> {
    const now = timestamp(this.#now());
    const envelope = await this.#readForCleanup(now);
    if (!envelope) return undefined;
    if (now >= envelope.expiresAt) {
      await this.store.remove(DUO_ATTEMPT_STORAGE_KEY);
      return undefined;
    }
    return envelope;
  }

  async #readForCleanup(now: number): Promise<Envelope | undefined> {
    const raw = await this.store.get<unknown>(DUO_ATTEMPT_STORAGE_KEY);
    if (raw === undefined) return undefined;
    let envelope: Envelope;
    try { envelope = parseEnvelope(raw, now); } catch {
      await this.store.remove(DUO_ATTEMPT_STORAGE_KEY);
      return undefined;
    }
    this.#coordinator.generation = Math.max(this.#coordinator.generation, envelope.generation);
    return envelope;
  }

  async #markUnknown(
    current: Extract<Envelope, { status: 'claimed' | 'submitting' }>,
  ): Promise<Envelope> {
    const now = timestamp(this.#now());
    const unknown: Envelope = {
      schemaVersion: 1,
      generation: this.#nextGeneration(),
      attemptId: current.attemptId,
      status: 'outcome_unknown',
      challenge: current.challenge,
      tabId: current.tabId,
      source: current.source,
      documentId: current.documentId,
      redirectUri: current.redirectUri,
      createdAt: current.createdAt,
      expiresAt: safeAdd(now, DUO_ATTEMPT_TTL_MS),
      terminalAt: now,
    };
    await this.store.set(DUO_ATTEMPT_STORAGE_KEY, unknown);
    return unknown;
  }

  async #writePreGrant(envelope: Envelope): Promise<void> {
    try {
      await this.store.set(DUO_ATTEMPT_STORAGE_KEY, envelope);
    } catch (error) {
      try {
        await this.store.remove(DUO_ATTEMPT_STORAGE_KEY);
      } catch (cleanupError) {
        throw new DuoAttemptWriteUncertainError(ownerSnapshot(envelope), new AggregateError(
          [error, cleanupError],
          'Duo attempt write failed and could not be retired.',
          { cause: cleanupError },
        ));
      }
      throw error;
    }
  }

  async #writeReplacement(
    envelope: Envelope,
    previous: Envelope | undefined,
  ): Promise<void> {
    if (!previous) {
      await this.#writePreGrant(envelope);
      return;
    }
    try {
      await this.store.set(DUO_ATTEMPT_STORAGE_KEY, envelope);
      return;
    } catch (error) {
      let observed: Envelope | undefined;
      try {
        observed = await this.#read();
      } catch (readError) {
        throw new DuoAttemptWriteUncertainError(ownerSnapshot(envelope), new AggregateError(
          [error, readError],
          'Duo replacement write could not be inspected.',
          { cause: readError },
        ), [previous.tabId]);
      }
      if (observed && sameOwner(observed, previous)) throw error;
      if (!observed || !sameOwner(observed, envelope)) {
        throw new DuoAttemptWriteUncertainError(ownerSnapshot(envelope), error, [previous.tabId]);
      }
      try {
        await this.store.set(DUO_ATTEMPT_STORAGE_KEY, previous);
      } catch (rollbackError) {
        let rolledBack: Envelope | undefined;
        try { rolledBack = await this.#read(); } catch {
          throw new DuoAttemptWriteUncertainError(
            ownerSnapshot(envelope), rollbackError, [previous.tabId],
          );
        }
        if (rolledBack && sameOwner(rolledBack, previous)) throw error;
        throw new DuoAttemptWriteUncertainError(
          ownerSnapshot(envelope), rollbackError, [previous.tabId],
        );
      }
      const rolledBack = await this.#read();
      if (!rolledBack || !sameOwner(rolledBack, previous)) {
        throw new DuoAttemptWriteUncertainError(ownerSnapshot(envelope), error, [previous.tabId]);
      }
      throw error;
    }
  }

  #nextGeneration(): number {
    if (this.#coordinator.generation >= Number.MAX_SAFE_INTEGER) throw new Error('Duo generation exhausted');
    return ++this.#coordinator.generation;
  }

  #serialize<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.#coordinator.tail.then(operation, operation);
    this.#coordinator.tail = run.then(() => undefined, () => undefined);
    return run;
  }
}

function parseEnvelope(input: unknown, now: number): Envelope {
  const record = exactRecord(input, undefined, 'Duo attempt');
  const status = record.status;
  const active = status === 'waiting' || status === 'claimed' || status === 'submitting';
  const expected = active
    ? [
        'schemaVersion', 'generation', 'attemptId', 'status', 'challenge', 'tabId', 'authUrl',
        'redirectUri', 'state', 'remember', 'source', 'createdAt', 'expiresAt',
        ...(status === 'claimed' || status === 'submitting' ? ['documentId', 'workerId'] : []),
      ]
    : status === 'outcome_unknown'
      ? [
          'schemaVersion', 'generation', 'attemptId', 'status', 'challenge', 'tabId', 'source',
          'documentId', 'redirectUri',
          'createdAt', 'expiresAt', 'terminalAt',
        ]
      : [];
  exactRecord(record, expected, 'Duo attempt');
  if (record.schemaVersion !== 1) throw new TypeError('Duo schema is invalid');
  const common = {
    schemaVersion: 1 as const,
    generation: positiveInteger(record.generation, 'generation'),
    attemptId: uuid(record.attemptId, 'attempt id'),
    challenge: createDuoChallengeOwner(record.challenge as DuoChallengeOwner),
    createdAt: timestamp(record.createdAt),
    expiresAt: timestamp(record.expiresAt),
  };
  if (common.createdAt > now || common.expiresAt <= common.createdAt) throw new TypeError('Duo lifetime is invalid');
  if (!active) {
    const terminalAt = timestamp(record.terminalAt);
    if (terminalAt < common.createdAt || terminalAt > now) throw new TypeError('Duo terminal time is invalid');
    return {
      ...common,
      status: 'outcome_unknown',
      tabId: nonNegativeInteger(record.tabId, 'tab id'),
      source: parseSourceContext(record.source),
      documentId: boundedString(record.documentId, 512, 'document id'),
      redirectUri: boundedString(record.redirectUri, 16 * 1024, 'redirect URI'),
      terminalAt,
    };
  }
  const binding = {
    tabId: nonNegativeInteger(record.tabId, 'tab id'),
    authUrl: boundedString(record.authUrl, 16 * 1024, 'authorization URL'),
    redirectUri: boundedString(record.redirectUri, 16 * 1024, 'redirect URI'),
    state: boundedString(record.state, 16 * 1024, 'state'),
    remember: booleanValue(record.remember, 'remember'),
    source: parseSourceContext(record.source),
  };
  if (status === 'waiting') return { ...common, ...binding, status };
  return {
    ...common,
    ...binding,
    status,
    documentId: boundedString(record.documentId, 512, 'document id'),
    workerId: uuid(record.workerId, 'worker id'),
  };
}

function snapshot(envelope: Envelope): DuoAttempt {
  const owner = ownerSnapshot(envelope);
  const common = {
    owner,
    createdAt: envelope.createdAt,
    expiresAt: envelope.expiresAt,
  };
  if (envelope.status === 'outcome_unknown') {
    return Object.freeze({
      ...common,
      status: envelope.status,
      tabId: envelope.tabId,
      source: envelope.source,
      documentId: envelope.documentId,
      redirectUri: envelope.redirectUri,
      terminalAt: envelope.terminalAt,
    });
  }
  if (envelope.status === 'waiting') {
    return Object.freeze({
      ...common,
      status: envelope.status,
      tabId: envelope.tabId,
      authUrl: envelope.authUrl,
      redirectUri: envelope.redirectUri,
      state: envelope.state,
      remember: envelope.remember,
      source: envelope.source,
    });
  }
  return Object.freeze({
    ...common,
    status: envelope.status,
    tabId: envelope.tabId,
    authUrl: envelope.authUrl,
    redirectUri: envelope.redirectUri,
    state: envelope.state,
    remember: envelope.remember,
    source: envelope.source,
    documentId: envelope.documentId,
    workerId: envelope.workerId,
  });
}

function ownerSnapshot(envelope: Envelope): DuoAttemptOwner {
  return Object.freeze({
    generation: envelope.generation,
    attemptId: envelope.attemptId,
    challenge: envelope.challenge,
  });
}

function parseOwner(input: DuoAttemptOwner): DuoAttemptOwner {
  const record = exactRecord(input, ['generation', 'attemptId', 'challenge'], 'Duo owner');
  return Object.freeze({
    generation: positiveInteger(record.generation, 'generation'),
    attemptId: uuid(record.attemptId, 'attempt id'),
    challenge: createDuoChallengeOwner(record.challenge as DuoChallengeOwner),
  });
}

function sameOwner(envelope: Envelope, owner: DuoAttemptOwner): boolean {
  return envelope.generation === owner.generation
    && envelope.attemptId === owner.attemptId
    && sameDuoChallengeOwner(envelope.challenge, owner.challenge);
}

function exactRecord(input: unknown, expected: readonly string[] | undefined, name: string): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) throw new TypeError(`${name} is invalid`);
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError(`${name} is invalid`);
  const keys = Reflect.ownKeys(input);
  if (keys.some((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    return typeof key !== 'string' || !descriptor?.enumerable || !('value' in descriptor);
  })) throw new TypeError(`${name} is invalid`);
  if (expected && (keys.length !== expected.length || keys.some((key) => !expected.includes(key as string)))) {
    throw new TypeError(`${name} is invalid`);
  }
  return input as Record<string, unknown>;
}

function uuid(input: unknown, name: string): string {
  if (typeof input !== 'string' || !UUID_V4.test(input)) throw new TypeError(`Duo ${name} is invalid`);
  return input;
}

function boundedString(input: unknown, max: number, name: string): string {
  if (typeof input !== 'string' || input.length === 0 || input.length > max || input.trim() !== input) {
    throw new TypeError(`Duo ${name} is invalid`);
  }
  for (let index = 0; index < input.length; index += 1) {
    const code = input.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) throw new TypeError(`Duo ${name} is invalid`);
  }
  return input;
}

function parseSourceDocument(input: unknown): DuoSourceDocument {
  const record = exactRecord(
    input,
    ['tabId', 'windowId', 'documentId', 'url'],
    'Duo source document',
  );
  const urlValue = boundedString(record.url, 16 * 1024, 'source URL');
  let url: URL;
  try { url = new URL(urlValue); } catch { throw new TypeError('Duo source URL is invalid'); }
  if (
    (url.protocol !== 'https:' && url.protocol !== 'http:')
    || url.username
    || url.password
    || url.toString() !== urlValue
  ) throw new TypeError('Duo source URL is invalid');
  return Object.freeze({
    tabId: nonNegativeInteger(record.tabId, 'source tab id'),
    windowId: nonNegativeInteger(record.windowId, 'source window id'),
    documentId: boundedString(record.documentId, 512, 'source document id'),
    url: urlValue,
  });
}

function parseSourceContext(input: unknown): DuoSourceContext {
  const record = exactRecord(input, undefined, 'Duo source context');
  const hasDocument = Object.hasOwn(record, 'document');
  exactRecord(
    record,
    hasDocument ? ['windowId', 'document'] : ['windowId'],
    'Duo source context',
  );
  const windowId = nonNegativeInteger(record.windowId, 'source window id');
  const document = hasDocument ? parseSourceDocument(record.document) : undefined;
  if (document && document.windowId !== windowId) {
    throw new TypeError('Duo source window binding is invalid');
  }
  return Object.freeze({ windowId, ...(document ? { document } : {}) });
}

function timestamp(input: unknown): number {
  return nonNegativeInteger(input, 'timestamp');
}

function positiveInteger(input: unknown, name: string): number {
  if (!Number.isSafeInteger(input) || (input as number) <= 0) throw new TypeError(`Duo ${name} is invalid`);
  return input as number;
}

function nonNegativeInteger(input: unknown, name: string): number {
  if (!Number.isSafeInteger(input) || (input as number) < 0) throw new TypeError(`Duo ${name} is invalid`);
  return input as number;
}

function booleanValue(input: unknown, name: string): boolean {
  if (typeof input !== 'boolean') throw new TypeError(`Duo ${name} is invalid`);
  return input;
}

function assertTabId(value: number): void { nonNegativeInteger(value, 'tab id'); }

function safeAdd(value: number, delta: number): number {
  const result = value + delta;
  if (!Number.isSafeInteger(result)) throw new TypeError('Duo lifetime is invalid');
  return result;
}
