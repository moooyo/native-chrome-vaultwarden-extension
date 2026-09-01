import { AppError } from '../core/errors.js';
import type { SessionLease } from '../core/session/session-manager.js';
import type { SessionGate } from './session-gate.js';
import type {
  VaultTimeoutController,
  VaultTimeoutReleaseLease,
  VaultTimeoutReleaseProof,
} from './vault-timeout-controller.js';

const LEASE_OWNER: unique symbol = Symbol('vaultReleaseLeaseOwner');
const PROOF_OWNER: unique symbol = Symbol('vaultReleaseProofOwner');

export interface VaultReleaseLease {
  readonly sessionLease: SessionLease;
  readonly timeoutLease: VaultTimeoutReleaseLease;
}

export interface VaultReleaseProof {
  readonly sessionLease: SessionLease;
  readonly timeoutProof: VaultTimeoutReleaseProof;
}

interface OwnedLease extends VaultReleaseLease { readonly [LEASE_OWNER]: symbol }
interface OwnedProof extends VaultReleaseProof { readonly [PROOF_OWNER]: symbol }

/** Durable observation plus a no-clock-sampling final fence for one secret release. */
export class VaultReleaseGate {
  private readonly owner = Symbol('vaultReleaseGate');
  private readonly leases = new WeakSet<object>();
  private readonly proofs = new WeakSet<object>();
  private readonly authorizedProofs = new WeakSet<object>();

  constructor(
    private readonly timeout: Pick<
      VaultTimeoutController,
      'captureRelease' | 'checkpointRelease' | 'assertRelease'
    > & Partial<Pick<VaultTimeoutController, 'settlePendingAction'>>,
    private readonly session: Pick<
      SessionGate,
      'capture' | 'assert' | 'assertWithoutPreflight' | 'runReleaseAssertions'
    >,
  ) {}

  async settlePendingAction(): Promise<void> {
    await this.timeout.settlePendingAction?.();
  }

  capture(sessionLease?: SessionLease): VaultReleaseLease {
    const boundSessionLease = sessionLease ?? this.session.capture();
    if (sessionLease) this.session.assert(sessionLease);
    const lease: OwnedLease = Object.freeze({
      sessionLease: boundSessionLease,
      timeoutLease: this.timeout.captureRelease(),
      [LEASE_OWNER]: this.owner,
    });
    this.leases.add(lease);
    return lease;
  }

  async checkpoint(lease: VaultReleaseLease): Promise<VaultReleaseProof> {
    const owned = lease as Partial<OwnedLease>;
    if (owned[LEASE_OWNER] !== this.owner || !this.leases.delete(lease as object)) {
      throw new AppError('locked', 'Vault release lease is invalid');
    }
    const timeoutProof = await this.timeout.checkpointRelease(lease.timeoutLease);
    this.session.assertWithoutPreflight(lease.sessionLease);
    const proof: OwnedProof = Object.freeze({
      sessionLease: lease.sessionLease,
      timeoutProof,
      [PROOF_OWNER]: this.owner,
    });
    this.proofs.add(proof);
    return proof;
  }

  assertAuthorities(proof: VaultReleaseProof, assertions: () => void): void {
    const owned = proof as Partial<OwnedProof>;
    if (owned[PROOF_OWNER] !== this.owner
        || !this.proofs.has(proof as object)
        || this.authorizedProofs.has(proof as object)) {
      throw new AppError('locked', 'Vault release proof is invalid');
    }
    try {
      this.session.runReleaseAssertions(() => {
        assertions();
        this.session.assertWithoutPreflight(proof.sessionLease);
      });
    } catch (error) {
      this.proofs.delete(proof as object);
      throw error;
    }
    this.authorizedProofs.add(proof);
  }

  assert(proof: VaultReleaseProof): void {
    const owned = proof as Partial<OwnedProof>;
    if (owned[PROOF_OWNER] !== this.owner
        || !this.authorizedProofs.delete(proof as object)
        || !this.proofs.delete(proof as object)) {
      throw new AppError('locked', 'Vault release proof is invalid');
    }
    this.timeout.assertRelease(proof.timeoutProof);
    this.session.assertWithoutPreflight(proof.sessionLease);
  }

}
