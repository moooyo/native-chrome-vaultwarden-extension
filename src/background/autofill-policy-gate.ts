import { AppError } from '../core/errors.js';

const POLICY_LEASE_OWNER: unique symbol = Symbol('autofillPolicyLeaseOwner');

export interface AutofillPolicyLease {
  readonly generation: number;
}

interface OwnedAutofillPolicyLease extends AutofillPolicyLease {
  readonly [POLICY_LEASE_OWNER]: symbol;
}

/** In-memory revocation fence for settings that authorize content-facing autofill operations. */
export class AutofillPolicyGate {
  readonly #owner = Symbol('autofillPolicyGate');
  readonly #issued = new WeakSet<object>();
  #generation = 0;

  capture(): AutofillPolicyLease {
    const lease = Object.freeze({ generation: this.#generation, [POLICY_LEASE_OWNER]: this.#owner });
    this.#issued.add(lease);
    return lease;
  }

  assert(lease: AutofillPolicyLease): void {
    const owned = lease as Partial<OwnedAutofillPolicyLease>;
    if (
      typeof lease !== 'object'
      || lease === null
      || !this.#issued.has(lease)
      || owned[POLICY_LEASE_OWNER] !== this.#owner
      || lease.generation !== this.#generation
    ) {
      throw new AppError('denied', 'Autofill policy changed during operation');
    }
  }

  /** Revoke every outstanding policy lease before a setting or identity transition can continue. */
  invalidate(): void {
    this.#generation += 1;
  }
}
