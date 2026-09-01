import { AppError } from '../core/errors.js';
import type { SessionTransitionEvent } from '../core/session/auth-service.js';
import type { SessionLease, SessionLeaseGate, SessionState } from '../core/session/session-manager.js';

const LEASE_OWNER: unique symbol = Symbol('sessionLeaseOwner');

interface OwnedSessionLease extends SessionLease {
  readonly [LEASE_OWNER]: symbol;
}

type GateState = SessionState | 'unknown' | 'transitioning';
const FAIL_CLOSED_FAILURE_REASONS = new Set<SessionTransitionEvent['reason']>([
  'login', 'unlock', 'pinUnlock', 'keyRotation',
]);

/**
 * In-memory authorization fence for operations that release decrypted data. A transition start
 * invalidates every outstanding lease before session storage changes; only the latest transition's
 * settled event can make the gate available again.
 */
export class SessionGate implements SessionLeaseGate {
  private readonly owner = Symbol('sessionGate');
  private generation = 0;
  private latestTransitionId = 0;
  private state: GateState;
  private terminalTransitionId: number | undefined;
  private preflight: (() => void) | undefined;
  private releaseAssertionDepth = 0;

  constructor(initialState: SessionState | 'unknown' = 'unknown') {
    this.state = initialState;
  }

  /** Initialize a fail-closed gate after reading the session state during worker startup. */
  initialize(state: SessionState): void {
    // A transition may have started while the initial storage read was in flight. Its newer state wins.
    if (this.state !== 'unknown') return;
    this.state = state;
  }

  /** Install the hydrated synchronous timeout guard before privileged requests are admitted. */
  setPreflight(preflight: () => void): void {
    this.preflight = preflight;
  }

  readonly handleTransition = (event: SessionTransitionEvent): void => {
    if (event.phase === 'start') {
      if (this.terminalTransitionId !== undefined) return;
      if (event.transitionId <= this.latestTransitionId) return;
      this.latestTransitionId = event.transitionId;
      this.generation++;
      this.state = 'transitioning';
      if (event.reason === 'keyRotation') this.terminalTransitionId = event.transitionId;
      return;
    }
    if (this.terminalTransitionId !== undefined) {
      if (event.transitionId !== this.terminalTransitionId || !event.succeeded) return;
      this.terminalTransitionId = undefined;
      this.state = event.state;
      return;
    }
    if (event.transitionId !== this.latestTransitionId) return;
    // A superseded activation may have completed a non-atomic storage write before noticing it was
    // stale. Never authorize that partially committed session; a later successful transition must
    // explicitly establish the next usable generation.
    if (!event.succeeded && FAIL_CLOSED_FAILURE_REASONS.has(event.reason)) return;
    this.state = event.state;
  };

  capture(): SessionLease {
    this.preflight?.();
    if (this.state !== 'unlocked') throw new AppError('locked', 'Vault is locked');
    return Object.freeze({ generation: this.generation, [LEASE_OWNER]: this.owner });
  }

  assert(lease: SessionLease): void {
    if (this.releaseAssertionDepth === 0) this.preflight?.();
    this.assertWithoutPreflight(lease);
  }

  /** Run synchronous post-checkpoint assertions without observing a newer, non-durable clock. */
  runReleaseAssertions(assertions: () => void): void {
    this.releaseAssertionDepth += 1;
    try {
      assertions();
    } finally {
      this.releaseAssertionDepth -= 1;
    }
  }

  /** Final release fence used only after a durable timeout observation checkpoint. */
  assertWithoutPreflight(lease: SessionLease): void {
    const owned = lease as Partial<OwnedSessionLease>;
    if (
      this.state !== 'unlocked'
      || owned[LEASE_OWNER] !== this.owner
      || lease.generation !== this.generation
    ) {
      throw new AppError('locked', 'Vault session changed during operation');
    }
  }
}
