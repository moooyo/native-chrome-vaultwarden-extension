import { ClientEventType } from '../core/events/client-event.js';
import type { ClientEventReceipt, ClientEventService } from './client-event-service.js';
import { bestEffortClientEvent } from './client-event-best-effort.js';

type ClientEventMethods = Pick<ClientEventService, 'prepare' | 'commit'>;

/**
 * Keeps a worker-only event receipt attached to one secret payload by object identity. This allows
 * direct background fills to commit only after their exact content-script acknowledgement without
 * adding authority metadata to the browser message.
 */
export class ClientEventFillRecorder {
  readonly #receipts = new WeakMap<object, ClientEventReceipt>();

  constructor(private readonly events: ClientEventMethods) {
    if (!events || typeof events.prepare !== 'function' || typeof events.commit !== 'function') {
      throw new TypeError('Client event fill recorder dependencies are invalid');
    }
  }

  async prepare(cipherId: string, payload: object): Promise<void> {
    const receipt = await bestEffortClientEvent(() => this.events.prepare({
        type: ClientEventType.Cipher_ClientAutofilled,
        cipherId,
    }));
    if (receipt) this.#receipts.set(payload, receipt);
  }

  async settle(payload: unknown, response: unknown): Promise<void> {
    if (!isObject(payload)) return;
    const receipt = this.#receipts.get(payload);
    if (!receipt) return;
    // Consume before validating or awaiting so duplicate browser responses cannot replay an event.
    this.#receipts.delete(payload);
    if (!isExactFilledResponse(response)) return;
    await bestEffortClientEvent(() => this.events.commit(receipt));
  }
}

function isExactFilledResponse(value: unknown): boolean {
  if (!isObject(value) || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 1 || keys[0] !== 'status') return false;
  const status = Object.getOwnPropertyDescriptor(value, 'status');
  return status?.enumerable === true && 'value' in status && status.value === 'filled';
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null;
}
