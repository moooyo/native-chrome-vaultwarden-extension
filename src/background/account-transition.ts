import type { SessionTransitionEvent, SessionTransitionReason } from '../core/session/auth-service.js';
import {
  AccountLeaseGate,
  type AccountLeaseSnapshot,
  type AccountTransitionToken,
  type ServerTransitionToken,
} from '../core/session/account-gate.js';

type TransitionKind = 'account' | 'server';

export interface VaultAccountAdmission {
  readonly resumeAccount: (account: string) => boolean;
  readonly resetTerminatedAccount: (account: string) => boolean;
  readonly retireTerminatedAccount: (account: string) => boolean;
}

type ActiveTransition =
  | {
      readonly transitionId: number;
      readonly kind: 'account';
      readonly token: AccountTransitionToken;
      readonly terminal: boolean;
    }
  | {
      readonly transitionId: number;
      readonly kind: 'server';
      readonly token: ServerTransitionToken;
      readonly terminal: false;
    };

function transitionKind(reason: SessionTransitionReason): TransitionKind | undefined {
  if (reason === 'serverChange') return 'server';
  if (
    reason === 'login'
    || reason === 'switchAccount'
    || reason === 'logout'
    || reason === 'removeAccount'
    || reason === 'keyRotation'
  ) {
    return 'account';
  }
  return undefined;
}

/**
 * Serial lifecycle adapter between AuthService transitions and AccountLeaseGate. A failed storage
 * read leaves capture closed, while the next serialized transition may recover the abandoned token
 * from a fresh authoritative snapshot before starting its own lifecycle.
 */
export class AccountTransitionCoordinator {
  private active: ActiveTransition | undefined;

  constructor(
    private readonly gate: AccountLeaseGate,
    private readonly readCurrent: () => Promise<AccountLeaseSnapshot | undefined>,
  ) {}

  readonly handle = async (event: SessionTransitionEvent): Promise<void> => {
    const kind = transitionKind(event.reason);
    if (event.phase === 'start') {
      await this.recoverAbandonedTransition(event.transitionId);
      if (!kind) return;
      this.active = kind === 'server'
        ? {
            transitionId: event.transitionId,
            kind,
            token: this.gate.beginServerTransition(),
            terminal: false,
          }
        : {
            transitionId: event.transitionId,
            kind,
            token: this.gate.beginAccountTransition(),
            terminal: event.reason === 'keyRotation',
          };
      return;
    }

    if (!kind) return;
    const active = this.active;
    if (!active || active.transitionId !== event.transitionId || active.kind !== kind) {
      throw new Error('Account lease transition settlement is out of order');
    }
    if (active.terminal && !event.succeeded) {
      throw new Error('Account key rotation requires startup recovery');
    }

    const current = await this.readCurrent();
    if (!current) {
      this.gate.recoverTransition(active.token);
      this.active = undefined;
      if (active.kind === 'account') {
        throw new Error('Account transition lost its configured server');
      }
      return;
    }

    if (active.kind === 'server') {
      this.gate.endServerTransition(active.token, current);
    } else {
      this.gate.endAccountTransition(active.token, current);
    }
    this.active = undefined;
  };

  private async recoverAbandonedTransition(nextTransitionId: number): Promise<void> {
    const active = this.active;
    if (!active) return;
    if (active.terminal) throw new Error('Account key rotation requires startup recovery');
    if (nextTransitionId <= active.transitionId) {
      throw new Error('Account lease transition start is out of order');
    }
    const current = await this.readCurrent();
    this.gate.recoverTransition(active.token, current);
    this.active = undefined;
  }
}

/**
 * Reopen vault admission only after a successful unlocked settlement. A completed key rotation
 * retires its old terminal lane without reopening it; a later fresh login can reset a retained lane.
 */
export function settleVaultAccountAdmission(
  event: SessionTransitionEvent,
  current: AccountLeaseSnapshot | undefined,
  admission: VaultAccountAdmission,
  transitionedAccount?: string,
): void {
  if (event.phase !== 'settled' || !event.succeeded) return;
  if (event.reason === 'keyRotation') {
    if (event.state === 'loggedOut' && transitionedAccount) {
      admission.retireTerminatedAccount(transitionedAccount);
    }
    return;
  }
  if (event.state !== 'unlocked' || !current?.accountIdentity) return;
  const account = `${current.serverUrl}\n${current.accountIdentity}`;
  if (event.reason === 'login' && admission.resetTerminatedAccount(account)) return;
  admission.resumeAccount(account);
}
