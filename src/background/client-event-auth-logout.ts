import type { SessionTransitionEvent } from '../core/session/auth-service.js';
import { bestEffortClientEvent } from './client-event-best-effort.js';
import type {
  ClientEventConfirmedLogoutReceipt,
  ClientEventLogoutReceipt,
  ClientEventProductionRuntime,
} from './client-event-production.js';

type LogoutRuntime = Pick<
  ClientEventProductionRuntime<never>,
  | 'captureLogout'
  | 'flushBeforeLogout'
  | 'confirmLogout'
  | 'discardConfirmedLogout'
  | 'completeLogout'
>;

interface PendingLogout {
  readonly receipt: Promise<ClientEventLogoutReceipt | undefined>;
}

/** Bind event collection cleanup to AuthService's authoritative logout transition result. */
export class ClientEventAuthLogoutLifecycle {
  readonly #pending = new Map<number, PendingLogout>();

  constructor(private readonly runtime: LogoutRuntime) {
    if (!runtime
      || typeof runtime.captureLogout !== 'function'
      || typeof runtime.flushBeforeLogout !== 'function'
      || typeof runtime.completeLogout !== 'function') {
      throw new TypeError('Client event logout lifecycle dependencies are invalid');
    }
  }

  async handle(event: SessionTransitionEvent): Promise<void> {
    if (event.reason !== 'logout') return;
    if (event.phase === 'start') {
      if (this.#pending.has(event.transitionId)) return;
      const receipt = Promise.resolve()
        .then(() => this.runtime.captureLogout())
        .catch(() => undefined);
      this.#pending.set(event.transitionId, Object.freeze({ receipt }));
      const captured = await bestEffortClientEvent(() => receipt);
      if (!captured) {
        throw new Error('Client event logout cleanup intent could not be persisted');
      }
      // Only network upload is best-effort. A durable cleanup intent is mandatory before logout.
      await bestEffortClientEvent(() => this.runtime.flushBeforeLogout(captured));
      return;
    }

    const pending = this.#pending.get(event.transitionId);
    if (!pending) return;
    this.#pending.delete(event.transitionId);
    if (!event.succeeded) {
      // A failed logout preserves data. Marker cleanup is recoverable from the account registry.
      await bestEffortClientEvent(async () => {
        const receipt = await pending.receipt;
        if (receipt) await this.runtime.completeLogout(receipt, false);
      });
      return;
    }

    const receipt = await pending.receipt;
    if (!receipt) throw new Error('Client event logout cleanup intent is unavailable');
    // Success promotion is mandatory and unbounded by the network budget. AuthService must not
    // release its transition until the durable phase proves startup can finish privacy cleanup.
    const confirmed: ClientEventConfirmedLogoutReceipt | undefined =
      await this.runtime.confirmLogout(receipt);
    if (!confirmed) throw new Error('Client event logout success could not be confirmed');
    // Only the queue/directory deletion is best-effort. Its late continuation remains observed.
    await bestEffortClientEvent(() => this.runtime.discardConfirmedLogout(confirmed));
  }
}
