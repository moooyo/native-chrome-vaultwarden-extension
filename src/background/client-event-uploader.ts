import {
  serializeClientEventBatch,
  toClientEventWire,
  type ClientEventWire,
} from '../core/events/client-event.js';
import {
  createClientEventQueueScope,
  type ClientEventQueue,
  type ClientEventQueueScope,
  type ClientEventRetryState,
} from './client-event-queue.js';

export type ClientEventTransportResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly status: number; readonly retryAfter?: string };

export interface ClientEventTransport {
  upload(
    scope: ClientEventQueueScope,
    events: readonly ClientEventWire[],
  ): PromiseLike<ClientEventTransportResult>;
}

export type ClientEventUploadResult =
  | { readonly kind: 'idle' }
  | { readonly kind: 'busy'; readonly retryAt: number }
  | { readonly kind: 'deferred'; readonly retryAt: number }
  | { readonly kind: 'uploaded'; readonly count: number }
  | {
      readonly kind: 'retry_scheduled';
      readonly count: number;
      readonly retry: ClientEventRetryState;
      readonly status?: number;
    }
  | { readonly kind: 'superseded'; readonly count: number };

export interface ClientEventUploaderOptions {
  readonly onTransportError?: (error: unknown) => void;
}

/** One-lane-per-account upload coordinator over the durable claim/settlement queue. */
export class ClientEventUploader {
  readonly #scopeTails = new Map<string, Promise<void>>();
  readonly #onTransportError: ((error: unknown) => void) | undefined;

  constructor(
    private readonly queue: Pick<ClientEventQueue, 'claim' | 'acknowledge' | 'release'>,
    private readonly transport: ClientEventTransport,
    options: ClientEventUploaderOptions = {},
  ) {
    if (!queue || typeof queue.claim !== 'function'
      || typeof queue.acknowledge !== 'function' || typeof queue.release !== 'function') {
      throw new TypeError('Client event uploader requires a durable queue');
    }
    if (!transport || typeof transport.upload !== 'function') {
      throw new TypeError('Client event uploader requires a transport');
    }
    if (options.onTransportError !== undefined && typeof options.onTransportError !== 'function') {
      throw new TypeError('Client event uploader error observer is invalid');
    }
    this.#onTransportError = options.onTransportError;
  }

  flush(scopeInput: ClientEventQueueScope): Promise<ClientEventUploadResult> {
    const scope = createClientEventQueueScope(scopeInput.serverUrl, scopeInput.accountId);
    const key = JSON.stringify([scope.serverUrl, scope.accountId]);
    const previous = this.#scopeTails.get(key) ?? Promise.resolve();
    const operation = previous.then(
      () => this.#flushOne(scope),
      () => this.#flushOne(scope),
    );
    const tail = operation.then(() => undefined, () => undefined);
    this.#scopeTails.set(key, tail);
    void tail.finally(() => {
      if (this.#scopeTails.get(key) === tail) this.#scopeTails.delete(key);
    });
    return operation;
  }

  async #flushOne(scope: ClientEventQueueScope): Promise<ClientEventUploadResult> {
    const result = await this.queue.claim(scope);
    if (result.kind === 'empty') return Object.freeze({ kind: 'idle' });
    if (result.kind === 'busy') {
      return Object.freeze({ kind: 'busy', retryAt: result.retryAt });
    }
    if (result.kind === 'deferred') {
      return Object.freeze({ kind: 'deferred', retryAt: result.retryAt });
    }

    const { claim } = result;
    const events = Object.freeze(claim.entries.map((entry) => toClientEventWire(entry.event)));
    serializeClientEventBatch(events);

    let transportResult: ClientEventTransportResult;
    try {
      transportResult = parseTransportResult(await this.transport.upload(scope, events));
    } catch (error) {
      this.#reportTransportError(error);
      const retry = await this.#releaseOrAggregate(claim, { kind: 'network' }, error);
      if (!retry) return Object.freeze({ kind: 'superseded', count: events.length });
      return Object.freeze({
        kind: 'retry_scheduled',
        count: events.length,
        retry,
      });
    }

    if (transportResult.ok) {
      const removed = await this.queue.acknowledge(claim);
      return Object.freeze({ kind: 'uploaded', count: removed });
    }
    const retry = await this.queue.release(claim, {
      kind: 'http',
      status: transportResult.status,
      ...(transportResult.retryAfter === undefined
        ? {}
        : { retryAfter: transportResult.retryAfter }),
    });
    if (!retry) return Object.freeze({ kind: 'superseded', count: events.length });
    return Object.freeze({
      kind: 'retry_scheduled',
      count: events.length,
      retry,
      status: transportResult.status,
    });
  }

  async #releaseOrAggregate(
    claim: Parameters<ClientEventQueue['release']>[0],
    failure: Parameters<ClientEventQueue['release']>[1],
    transportError: unknown,
  ): Promise<ClientEventRetryState | undefined> {
    try {
      return await this.queue.release(claim, failure);
    } catch (releaseError) {
      throw new AggregateError(
        [transportError, releaseError],
        'Client event upload failed and its durable claim could not be released',
        { cause: releaseError },
      );
    }
  }

  #reportTransportError(error: unknown): void {
    try {
      this.#onTransportError?.(error);
    } catch {
      // Diagnostics must never interfere with durable claim settlement.
    }
  }
}

function parseTransportResult(value: unknown): ClientEventTransportResult {
  if (!isPlainRecord(value)) throw new TypeError('Client event transport result is invalid');
  if (value.ok === true) {
    requireExactDataKeys(value, ['ok']);
    return Object.freeze({ ok: true });
  }
  if (value.ok !== false) throw new TypeError('Client event transport result is invalid');
  const retryAfter = value.retryAfter;
  requireExactDataKeys(value, retryAfter === undefined ? ['ok', 'status'] : ['ok', 'status', 'retryAfter']);
  if (!Number.isSafeInteger(value.status) || (value.status as number) < 100
    || (value.status as number) > 599) {
    throw new TypeError('Client event transport status is invalid');
  }
  if (retryAfter !== undefined && typeof retryAfter !== 'string') {
    throw new TypeError('Client event transport Retry-After value is invalid');
  }
  return Object.freeze({
    ok: false,
    status: value.status as number,
    ...(retryAfter === undefined ? {} : { retryAfter }),
  });
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function requireExactDataKeys(record: Record<string, unknown>, expected: readonly string[]): void {
  const keys = Reflect.ownKeys(record);
  const expectedSet = new Set(expected);
  if (keys.length !== expected.length
    || keys.some((key) => typeof key !== 'string' || !expectedSet.has(key))) {
    throw new TypeError('Client event transport result has unexpected fields');
  }
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) {
      throw new TypeError('Client event transport result has invalid properties');
    }
  }
}
