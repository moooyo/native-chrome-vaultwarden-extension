import { describe, expect, it, vi } from 'vitest';
import {
  AccountLeaseGate,
  type AccountLeaseSnapshot,
  type AccountTransitionToken,
} from './account-gate.js';
import {
  AccountTransitionCoordinator,
  settleVaultAccountAdmission,
} from '../../background/account-transition.js';

const SERVER_A = 'https://a.example/';
const SERVER_B = 'https://b.example/';
const ALICE = 'alice@example.com';
const BOB = 'bob@example.com';

function snapshot(
  serverUrl = SERVER_A,
  accountIdentity = ALICE,
): AccountLeaseSnapshot {
  return { serverUrl, accountIdentity };
}

function serverOnly(serverUrl = SERVER_A): AccountLeaseSnapshot {
  return { serverUrl };
}

describe('AccountLeaseGate', () => {
  it('retains the configured server when initialized without an active account', () => {
    const gate = new AccountLeaseGate();

    expect(gate.current()).toBeUndefined();
    expect(() => gate.capture()).toThrowError(expect.objectContaining({ code: 'session_expired' }));

    gate.initialize(serverOnly());
    expect(gate.current()).toEqual({ serverUrl: SERVER_A });
    expect(() => gate.capture()).toThrowError(expect.objectContaining({ code: 'session_expired' }));
    const serverLease = gate.captureServer();
    expect(Object.isFrozen(serverLease)).toBe(true);
    expect(() => gate.assertServer(serverLease)).not.toThrow();
  });

  it('captures an immutable lease that does not depend on the vault lock state', () => {
    const gate = new AccountLeaseGate();
    const initial = { serverUrl: SERVER_A, accountIdentity: ALICE };
    gate.initialize(initial);

    const lease = gate.capture();
    initial.accountIdentity = BOB;

    expect(Object.isFrozen(lease)).toBe(true);
    expect(lease).toEqual({
      serverGeneration: 0,
      accountGeneration: 0,
      serverUrl: SERVER_A,
      accountIdentity: ALICE,
    });
    expect(() => gate.assert(lease)).not.toThrow();
  });

  it('fails capture closed throughout a transition and ignores a late startup read', () => {
    const gate = new AccountLeaseGate();
    const transition = gate.beginServerTransition();

    gate.initialize(snapshot());

    expect(gate.current()).toBeUndefined();
    expect(() => gate.capture()).toThrowError(expect.objectContaining({ code: 'session_expired' }));
    expect(() => gate.captureServer()).toThrowError(
      expect.objectContaining({ code: 'session_expired' }),
    );

    gate.endServerTransition(transition, snapshot(SERVER_B, BOB));
    expect(gate.capture().accountIdentity).toBe(BOB);
  });

  it('invalidates account leases across an A-B-A account sequence', () => {
    const gate = new AccountLeaseGate();
    gate.initialize(snapshot());
    const originalAliceLease = gate.capture();

    const toBob = gate.beginAccountTransition();
    gate.endAccountTransition(toBob, snapshot(SERVER_A, BOB));
    const bobLease = gate.capture();

    const backToAlice = gate.beginAccountTransition();
    gate.endAccountTransition(backToAlice, snapshot());

    expect(() => gate.assert(originalAliceLease)).toThrowError(
      expect.objectContaining({ code: 'session_expired' }),
    );
    expect(() => gate.assert(bobLease)).toThrowError(
      expect.objectContaining({ code: 'session_expired' }),
    );
    expect(gate.capture()).toMatchObject({ accountGeneration: 2, accountIdentity: ALICE });
  });

  it('invalidates account leases across an A-B-A server sequence', () => {
    const gate = new AccountLeaseGate();
    gate.initialize(snapshot());
    const originalServerLease = gate.capture();

    const toServerB = gate.beginServerTransition();
    gate.endServerTransition(toServerB, snapshot(SERVER_B));

    const backToServerA = gate.beginServerTransition();
    gate.endServerTransition(backToServerA, snapshot());

    expect(() => gate.assert(originalServerLease)).toThrowError(
      expect.objectContaining({ code: 'session_expired' }),
    );
    expect(gate.capture()).toMatchObject({ serverGeneration: 2, serverUrl: SERVER_A });
  });

  it('retains the authoritative server after logout and a logged-out server change', () => {
    const gate = new AccountLeaseGate();
    gate.initialize(snapshot());

    const logout = gate.beginAccountTransition();
    gate.endAccountTransition(logout, serverOnly());

    expect(gate.current()).toEqual({ serverUrl: SERVER_A });
    expect(gate.captureServer()).toMatchObject({ serverGeneration: 0, serverUrl: SERVER_A });
    expect(() => gate.capture()).toThrowError(expect.objectContaining({ code: 'session_expired' }));

    const serverChange = gate.beginServerTransition();
    gate.endServerTransition(serverChange, serverOnly(SERVER_B));

    expect(gate.current()).toEqual({ serverUrl: SERVER_B });
    expect(gate.captureServer()).toMatchObject({ serverGeneration: 1, serverUrl: SERVER_B });
    expect(() => gate.capture()).toThrowError(expect.objectContaining({ code: 'session_expired' }));
  });

  it('rejects a late login result captured from the previous server', () => {
    const gate = new AccountLeaseGate();
    gate.initialize(serverOnly());
    const loginServer = gate.captureServer();

    const serverChange = gate.beginServerTransition();
    gate.endServerTransition(serverChange, serverOnly(SERVER_B));

    expect(() => gate.assertServer(loginServer)).toThrowError(
      expect.objectContaining({ code: 'session_expired' }),
    );
    expect(gate.current()).toEqual({ serverUrl: SERVER_B });
  });

  it('restores a failed server transition without reviving its prior leases', () => {
    const gate = new AccountLeaseGate();
    gate.initialize(snapshot());
    const accountLease = gate.capture();
    const serverLease = gate.captureServer();

    const failedChange = gate.beginServerTransition();
    gate.endServerTransition(failedChange, snapshot());

    expect(gate.current()).toEqual(snapshot());
    expect(() => gate.assert(accountLease)).toThrowError(
      expect.objectContaining({ code: 'session_expired' }),
    );
    expect(() => gate.assertServer(serverLease)).toThrowError(
      expect.objectContaining({ code: 'session_expired' }),
    );
    expect(gate.capture()).toMatchObject({ serverGeneration: 1, accountIdentity: ALICE });
  });

  it('can abort a failed first-server transition and retry without opening capture', () => {
    const gate = new AccountLeaseGate();
    const failed = gate.beginServerTransition();

    gate.abortServerTransition(failed);

    expect(gate.current()).toBeUndefined();
    expect(() => gate.captureServer()).toThrowError(
      expect.objectContaining({ code: 'session_expired' }),
    );
    const retry = gate.beginServerTransition();
    gate.endServerTransition(retry, serverOnly(SERVER_A));
    expect(gate.captureServer()).toMatchObject({ serverGeneration: 2, serverUrl: SERVER_A });
  });

  it('recovers an abandoned transition from an authoritative snapshot without reviving old leases', () => {
    const gate = new AccountLeaseGate();
    gate.initialize(snapshot());
    const oldLease = gate.capture();
    const abandoned = gate.beginAccountTransition();

    gate.recoverTransition(abandoned, snapshot(SERVER_B, BOB));

    expect(gate.current()).toEqual(snapshot(SERVER_B, BOB));
    expect(() => gate.assert(oldLease)).toThrowError(
      expect.objectContaining({ code: 'session_expired' }),
    );
    expect(gate.capture()).toMatchObject({ accountGeneration: 1, accountIdentity: BOB });
  });

  it('does not let an account transition change the server while logged out', () => {
    const gate = new AccountLeaseGate();
    gate.initialize(serverOnly());
    const login = gate.beginAccountTransition();

    expect(() => gate.endAccountTransition(login, snapshot(SERVER_B, ALICE))).toThrowError(
      expect.objectContaining({ code: 'denied' }),
    );
    expect(gate.current()).toBeUndefined();
    expect(() => gate.captureServer()).toThrowError(
      expect.objectContaining({ code: 'session_expired' }),
    );

    gate.endAccountTransition(login, snapshot(SERVER_A, ALICE));
    expect(gate.capture()).toMatchObject({ serverUrl: SERVER_A, accountIdentity: ALICE });
  });

  it('reopens after a failed transition without reviving the prior lease', () => {
    const gate = new AccountLeaseGate();
    const original = snapshot();
    gate.initialize(original);
    const oldLease = gate.capture();

    const failedSwitch = gate.beginAccountTransition();
    expect(() => gate.assert(oldLease)).toThrowError(
      expect.objectContaining({ code: 'session_expired' }),
    );
    gate.endAccountTransition(failedSwitch, original);

    expect(() => gate.assert(oldLease)).toThrowError(
      expect.objectContaining({ code: 'session_expired' }),
    );
    expect(() => gate.assert(gate.capture())).not.toThrow();
  });

  it('rejects an overlapping account transition without superseding the active token', () => {
    const gate = new AccountLeaseGate();
    gate.initialize(snapshot());
    const first = gate.beginAccountTransition();

    expect(() => gate.beginAccountTransition()).toThrowError(
      expect.objectContaining({ code: 'denied' }),
    );
    expect(() => gate.capture()).toThrowError(expect.objectContaining({ code: 'session_expired' }));

    gate.endAccountTransition(first, snapshot(SERVER_A, BOB));
    expect(gate.capture()).toMatchObject({ accountGeneration: 1, accountIdentity: BOB });
  });

  it('rejects account begin during a server transition and keeps the server token current', () => {
    const gate = new AccountLeaseGate();
    gate.initialize(snapshot());
    const serverTransition = gate.beginServerTransition();

    expect(() => gate.beginAccountTransition()).toThrowError(
      expect.objectContaining({ code: 'denied' }),
    );
    expect(() => gate.captureServer()).toThrowError(
      expect.objectContaining({ code: 'session_expired' }),
    );

    gate.endServerTransition(serverTransition, serverOnly(SERVER_B));
    expect(gate.current()).toEqual({ serverUrl: SERVER_B });
    expect(gate.captureServer()).toMatchObject({ serverGeneration: 1, serverUrl: SERVER_B });
  });

  it('rejects server begin during an account transition and keeps the account token current', () => {
    const gate = new AccountLeaseGate();
    gate.initialize(snapshot());
    const accountTransition = gate.beginAccountTransition();

    expect(() => gate.beginServerTransition()).toThrowError(
      expect.objectContaining({ code: 'denied' }),
    );
    expect(() => gate.capture()).toThrowError(expect.objectContaining({ code: 'session_expired' }));

    gate.endAccountTransition(accountTransition, snapshot(SERVER_A, BOB));
    expect(gate.capture()).toMatchObject({
      serverGeneration: 0,
      accountGeneration: 1,
      accountIdentity: BOB,
    });
  });

  it('stays closed after a wrong-kind or invalid settlement and allows the valid token to retry', () => {
    const gate = new AccountLeaseGate();
    gate.initialize(snapshot());
    const serverTransition = gate.beginServerTransition();

    expect(() => gate.endAccountTransition(
      serverTransition as unknown as AccountTransitionToken,
      snapshot(SERVER_B),
    )).toThrowError(expect.objectContaining({ code: 'denied' }));
    expect(() => gate.capture()).toThrowError(expect.objectContaining({ code: 'session_expired' }));

    gate.endServerTransition(serverTransition, snapshot(SERVER_B));
    const accountTransition = gate.beginAccountTransition();
    expect(() => gate.endAccountTransition(accountTransition, snapshot(SERVER_A, BOB))).toThrowError(
      expect.objectContaining({ code: 'denied' }),
    );
    expect(() => gate.capture()).toThrowError(expect.objectContaining({ code: 'session_expired' }));
    expect(() => gate.endAccountTransition(accountTransition, {
      serverUrl: SERVER_B,
      accountIdentity: '   ',
    })).toThrowError(expect.objectContaining({ code: 'denied' }));
    expect(() => gate.capture()).toThrowError(expect.objectContaining({ code: 'session_expired' }));

    gate.endAccountTransition(accountTransition, snapshot(SERVER_B, BOB));
    expect(gate.capture()).toMatchObject({ serverUrl: SERVER_B, accountIdentity: BOB });
    expect(() => gate.endAccountTransition(accountTransition, snapshot(SERVER_B, ALICE))).toThrowError(
      expect.objectContaining({ code: 'denied' }),
    );
    expect(gate.current()).toEqual(snapshot(SERVER_B, BOB));
  });

  it('rejects a transition token issued by another gate without consuming the current token', () => {
    const gate = new AccountLeaseGate();
    const other = new AccountLeaseGate();
    gate.initialize(snapshot());
    other.initialize(snapshot());
    const current = gate.beginAccountTransition();
    const foreign = other.beginAccountTransition();

    expect(() => gate.endAccountTransition(foreign, snapshot(SERVER_A, BOB))).toThrowError(
      expect.objectContaining({ code: 'denied' }),
    );
    expect(() => gate.capture()).toThrowError(expect.objectContaining({ code: 'session_expired' }));

    gate.endAccountTransition(current, snapshot(SERVER_A, BOB));
    expect(gate.current()).toEqual(snapshot(SERVER_A, BOB));
  });

  it('invalidates a lease when the active account is removed or logged out', () => {
    for (const settle of [serverOnly(), snapshot(SERVER_A, BOB)]) {
      const gate = new AccountLeaseGate();
      gate.initialize(snapshot());
      const lease = gate.capture();

      const transition = gate.beginAccountTransition();
      gate.endAccountTransition(transition, settle);

      expect(() => gate.assert(lease)).toThrowError(
        expect.objectContaining({ code: 'session_expired' }),
      );
      if (settle.accountIdentity === undefined) {
        expect(gate.current()).toEqual({ serverUrl: SERVER_A });
        expect(() => gate.capture()).toThrowError(
          expect.objectContaining({ code: 'session_expired' }),
        );
      }
    }
  });

  it('requires startup recovery after a failed terminal key-rotation transition', async () => {
    const gate = new AccountLeaseGate();
    gate.initialize(snapshot());
    const coordinator = new AccountTransitionCoordinator(gate, async () => snapshot());
    await coordinator.handle({
      phase: 'start', transitionId: 1, reason: 'keyRotation', identityChanged: true,
    });

    await expect(coordinator.handle({
      phase: 'settled', transitionId: 1, reason: 'keyRotation', identityChanged: true,
      state: 'unlocked', succeeded: false,
    })).rejects.toThrow(/startup recovery/i);
    await expect(coordinator.handle({
      phase: 'start', transitionId: 2, reason: 'logout', identityChanged: true,
    })).rejects.toThrow(/startup recovery/i);
    expect(gate.current()).toBeUndefined();
    expect(() => gate.capture()).toThrowError(expect.objectContaining({ code: 'session_expired' }));
  });

  it('keeps a lease current when the caller refreshes only tokens without opening a transition', () => {
    const gate = new AccountLeaseGate();
    let auth = {
      ...snapshot(),
      accessToken: 'old-access-token',
      refreshToken: 'old-refresh-token',
    };
    gate.initialize(auth);
    const lease = gate.capture();

    auth = {
      ...auth,
      accessToken: 'refreshed-access-token',
      refreshToken: 'refreshed-refresh-token',
    };

    expect(auth.accountIdentity).toBe(lease.accountIdentity);
    expect(gate.current()).toEqual(snapshot());
    expect(() => gate.assert(lease)).not.toThrow();
    expect(gate.capture()).toMatchObject({ serverGeneration: 0, accountGeneration: 0 });
  });

  it('rejects forged, cross-gate, and caller-denied stale leases', () => {
    const first = new AccountLeaseGate();
    const second = new AccountLeaseGate();
    first.initialize(snapshot());
    second.initialize(snapshot());
    const lease = first.capture();

    expect(() => second.assert(lease)).toThrowError(expect.objectContaining({ code: 'denied' }));
    expect(() => first.assert({ ...lease })).toThrowError(expect.objectContaining({ code: 'denied' }));

    const transition = first.beginAccountTransition();
    first.endAccountTransition(transition, snapshot(SERVER_A, BOB));
    expect(() => first.assert(lease, 'denied')).toThrowError(
      expect.objectContaining({ code: 'denied' }),
    );
  });
});

describe('vault admission settlement', () => {
  function admission() {
    return {
      resumeAccount: vi.fn(() => true),
      resetTerminatedAccount: vi.fn(() => true),
      retireTerminatedAccount: vi.fn(() => true),
    };
  }

  it('allows only a successful fresh login to clear a terminal lane', () => {
    const vault = admission();
    settleVaultAccountAdmission({
      phase: 'settled', transitionId: 1, reason: 'login', identityChanged: true,
      state: 'unlocked', succeeded: true,
    }, snapshot(), vault);

    expect(vault.resetTerminatedAccount).toHaveBeenCalledWith(`${SERVER_A}\n${ALICE}`);
    expect(vault.resumeAccount).not.toHaveBeenCalled();
  });

  it('uses ordinary resume for unlock and never clears terminal ownership', () => {
    const vault = admission();
    settleVaultAccountAdmission({
      phase: 'settled', transitionId: 1, reason: 'unlock', identityChanged: false,
      state: 'unlocked', succeeded: true,
    }, snapshot(), vault);

    expect(vault.resetTerminatedAccount).not.toHaveBeenCalled();
    expect(vault.resumeAccount).toHaveBeenCalledWith(`${SERVER_A}\n${ALICE}`);
  });

  it('keeps admission closed after a failed settlement even if the old state reads unlocked', () => {
    const vault = admission();
    settleVaultAccountAdmission({
      phase: 'settled', transitionId: 1, reason: 'login', identityChanged: true,
      state: 'unlocked', succeeded: false,
    }, snapshot(), vault);

    expect(vault.resetTerminatedAccount).not.toHaveBeenCalled();
    expect(vault.resumeAccount).not.toHaveBeenCalled();
  });

  it('falls back to reversible resume when a fresh login has no terminal tombstone', () => {
    const vault = admission();
    vault.resetTerminatedAccount.mockReturnValue(false);
    settleVaultAccountAdmission({
      phase: 'settled', transitionId: 1, reason: 'login', identityChanged: true,
      state: 'unlocked', succeeded: true,
    }, snapshot(), vault);

    expect(vault.resumeAccount).toHaveBeenCalledWith(`${SERVER_A}\n${ALICE}`);
  });

  it('retires the previous terminal lane after successful key-rotation cleanup', () => {
    const vault = admission();
    const previousAccount = `${SERVER_A}\n${ALICE}`;
    settleVaultAccountAdmission({
      phase: 'settled', transitionId: 1, reason: 'keyRotation', identityChanged: true,
      state: 'loggedOut', succeeded: true,
    }, serverOnly(), vault, previousAccount);

    expect(vault.retireTerminatedAccount).toHaveBeenCalledWith(previousAccount);
    expect(vault.resetTerminatedAccount).not.toHaveBeenCalled();
    expect(vault.resumeAccount).not.toHaveBeenCalled();
  });

  it('does not retire a terminal lane when key-rotation cleanup did not settle successfully', () => {
    const vault = admission();
    settleVaultAccountAdmission({
      phase: 'settled', transitionId: 1, reason: 'keyRotation', identityChanged: true,
      state: 'unlocked', succeeded: false,
    }, snapshot(), vault, `${SERVER_A}\n${ALICE}`);

    expect(vault.retireTerminatedAccount).not.toHaveBeenCalled();
    expect(vault.resetTerminatedAccount).not.toHaveBeenCalled();
    expect(vault.resumeAccount).not.toHaveBeenCalled();
  });
});
