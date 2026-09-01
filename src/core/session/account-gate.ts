import { AppError } from '../errors.js';

export interface AccountLeaseSnapshot {
  /** Canonical server URL. Values are compared verbatim; this gate does not normalize identities. */
  readonly serverUrl: string;
  /** Canonical stable account identifier, such as a normalized email address. */
  readonly accountIdentity?: string;
}

/** Proof that work still belongs to the same configured server. */
export interface ServerLease {
  readonly serverGeneration: number;
  readonly serverUrl: string;
}

/** Proof that ciphertext work still belongs to the same server and active account. */
export interface AccountLease extends AccountLeaseSnapshot {
  readonly accountIdentity: string;
  readonly serverGeneration: number;
  readonly accountGeneration: number;
}

const SERVER_TRANSITION_TOKEN: unique symbol = Symbol('serverTransitionToken');
const ACCOUNT_TRANSITION_TOKEN: unique symbol = Symbol('accountTransitionToken');

export interface ServerTransitionToken {
  readonly [SERVER_TRANSITION_TOKEN]: true;
}

export interface AccountTransitionToken {
  readonly [ACCOUNT_TRANSITION_TOKEN]: true;
}

type TransitionKind = 'server' | 'account';
type TransitionToken = ServerTransitionToken | AccountTransitionToken;
type LeaseErrorCode = 'session_expired' | 'denied';

type TransitionRecord =
  | { readonly kind: 'server'; readonly sequence: number }
  | {
      readonly kind: 'account';
      readonly sequence: number;
      readonly serverGeneration: number;
      readonly serverUrl: string;
    };

/**
 * In-memory identity fence for encrypted account work. Unlike SessionGate, this gate intentionally
 * remains usable while the vault is locked. Identity transitions invalidate leases immediately and
 * keep capture fail-closed until the matching transition token publishes an authoritative context.
 * Callers must serialize transition commit bodies so the latest settlement also reflects storage.
 */
export class AccountLeaseGate {
  private readonly issuedAccountLeases = new WeakSet<object>();
  private readonly issuedServerLeases = new WeakSet<object>();
  private readonly transitions = new WeakMap<object, TransitionRecord>();
  private serverGeneration = 0;
  private accountGeneration = 0;
  private transitionSequence = 0;
  private initialized = false;
  private snapshot: Readonly<AccountLeaseSnapshot> | undefined;
  private activeTransition: TransitionToken | undefined;

  /** Initialize once from storage. A transition that started during the read remains authoritative. */
  initialize(current: AccountLeaseSnapshot): void {
    if (this.initialized || this.activeTransition) return;
    this.snapshot = freezeSnapshot(current);
    this.initialized = true;
  }

  /** Return the settled server/account snapshot, or undefined before initialization or in transition. */
  current(): Readonly<AccountLeaseSnapshot> | undefined {
    if (!this.initialized || this.activeTransition) return undefined;
    return this.snapshot;
  }

  captureServer(): ServerLease {
    const current = this.current();
    if (!current) {
      throw new AppError('session_expired', 'No configured server is available for this operation.');
    }
    const lease: ServerLease = Object.freeze({
      serverGeneration: this.serverGeneration,
      serverUrl: current.serverUrl,
    });
    this.issuedServerLeases.add(lease);
    return lease;
  }

  assertServer(lease: ServerLease, errorCode: LeaseErrorCode = 'session_expired'): void {
    if (!isObject(lease) || !this.issuedServerLeases.has(lease)) {
      throw new AppError('denied', 'The server lease is not valid for this gate.');
    }
    const current = this.current();
    if (
      !current
      || lease.serverGeneration !== this.serverGeneration
      || lease.serverUrl !== current.serverUrl
    ) {
      throw new AppError(errorCode, 'The configured server changed during the operation.');
    }
  }

  capture(): AccountLease {
    const current = this.current();
    if (!current?.accountIdentity) {
      throw new AppError('session_expired', 'No active account is available for this operation.');
    }
    const lease: AccountLease = Object.freeze({
      serverGeneration: this.serverGeneration,
      accountGeneration: this.accountGeneration,
      serverUrl: current.serverUrl,
      accountIdentity: current.accountIdentity,
    });
    this.issuedAccountLeases.add(lease);
    return lease;
  }

  assert(lease: AccountLease, errorCode: LeaseErrorCode = 'session_expired'): void {
    if (!isObject(lease) || !this.issuedAccountLeases.has(lease)) {
      throw new AppError('denied', 'The account lease is not valid for this gate.');
    }
    const current = this.current();
    if (
      !current
      || !current.accountIdentity
      || lease.serverGeneration !== this.serverGeneration
      || lease.accountGeneration !== this.accountGeneration
      || lease.serverUrl !== current.serverUrl
      || lease.accountIdentity !== current.accountIdentity
    ) {
      throw new AppError(errorCode, 'The active account changed during the operation.');
    }
  }

  beginServerTransition(): ServerTransitionToken {
    this.assertNoActiveTransition();
    this.serverGeneration++;
    const token = Object.freeze({ [SERVER_TRANSITION_TOKEN]: true as const });
    this.activateTransition(token, { kind: 'server', sequence: ++this.transitionSequence });
    return token;
  }

  endServerTransition(token: ServerTransitionToken, current: AccountLeaseSnapshot): void {
    this.endTransition(token, 'server', current);
  }

  /** Settle a failed first-server transition when storage still has no configured server. */
  abortServerTransition(token: ServerTransitionToken): void {
    const record = isObject(token) ? this.transitions.get(token) : undefined;
    if (
      token !== this.activeTransition
      || record?.kind !== 'server'
      || record.sequence !== this.transitionSequence
    ) {
      throw new AppError('denied', 'The account transition token is no longer current.');
    }
    this.activeTransition = undefined;
  }

  /**
   * Recover an abandoned transition from a freshly read authoritative snapshot. Callers use this
   * only after the serialized transition that owned `token` has finished without settling its gate.
   * An absent snapshot keeps capture closed until a later server transition establishes one.
   */
  recoverTransition(token: TransitionToken, current?: AccountLeaseSnapshot): void {
    const record = isObject(token) ? this.transitions.get(token) : undefined;
    if (
      token !== this.activeTransition
      || !record
      || record.sequence !== this.transitionSequence
    ) {
      throw new AppError('denied', 'The account transition token is no longer current.');
    }
    if (current) {
      this.snapshot = freezeSnapshot(current);
      this.initialized = true;
    } else {
      this.snapshot = undefined;
      this.initialized = false;
    }
    this.activeTransition = undefined;
  }

  beginAccountTransition(): AccountTransitionToken {
    this.assertNoActiveTransition();
    if (!this.initialized || !this.snapshot) {
      throw new AppError('session_expired', 'No authoritative server is available for this transition.');
    }
    this.accountGeneration++;
    const token = Object.freeze({ [ACCOUNT_TRANSITION_TOKEN]: true as const });
    this.activateTransition(token, {
      kind: 'account',
      sequence: ++this.transitionSequence,
      serverGeneration: this.serverGeneration,
      serverUrl: this.snapshot.serverUrl,
    });
    return token;
  }

  endAccountTransition(token: AccountTransitionToken, current: AccountLeaseSnapshot): void {
    this.endTransition(token, 'account', current);
  }

  private activateTransition(token: TransitionToken, record: TransitionRecord): void {
    this.transitions.set(token, record);
    this.activeTransition = token;
  }

  private assertNoActiveTransition(): void {
    if (this.activeTransition) {
      throw new AppError('denied', 'An account or server transition is already in progress.');
    }
  }

  private endTransition(
    token: TransitionToken,
    kind: TransitionKind,
    current: AccountLeaseSnapshot,
  ): void {
    const record = isObject(token) ? this.transitions.get(token) : undefined;
    if (
      token !== this.activeTransition
      || record?.kind !== kind
      || record.sequence !== this.transitionSequence
    ) {
      throw new AppError('denied', 'The account transition token is no longer current.');
    }

    const next = freezeSnapshot(current);
    if (
      record.kind === 'account'
      && (
        next.serverUrl !== record.serverUrl
        || this.serverGeneration !== record.serverGeneration
      )
    ) {
      throw new AppError('denied', 'An account transition cannot change the active server.');
    }

    this.snapshot = next;
    this.initialized = true;
    this.activeTransition = undefined;
  }
}

function freezeSnapshot(snapshot: AccountLeaseSnapshot): Readonly<AccountLeaseSnapshot> {
  if (!snapshot.serverUrl.trim()) {
    throw new AppError('denied', 'An account lease snapshot requires a server.');
  }
  if (snapshot.accountIdentity !== undefined && !snapshot.accountIdentity.trim()) {
    throw new AppError('denied', 'An account identity cannot be blank.');
  }
  return Object.freeze({
    serverUrl: snapshot.serverUrl,
    ...(snapshot.accountIdentity === undefined
      ? {}
      : { accountIdentity: snapshot.accountIdentity }),
  });
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null;
}
