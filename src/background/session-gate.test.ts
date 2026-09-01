import { describe, expect, it } from 'vitest';
import { SessionGate } from './session-gate.js';
import type { SessionTransitionEvent } from '../core/session/auth-service.js';

function start(transitionId: number, reason: 'lock' | 'unlock' = 'lock'): SessionTransitionEvent {
  return { phase: 'start', transitionId, reason, identityChanged: false };
}

function settled(
  transitionId: number,
  state: 'loggedOut' | 'locked' | 'unlocked',
  reason: 'lock' | 'unlock' = 'lock',
  succeeded = true,
): SessionTransitionEvent {
  return { phase: 'settled', transitionId, reason, identityChanged: false, state, succeeded };
}

describe('SessionGate', () => {
  it('fails closed until initialized and while locked', () => {
    const gate = new SessionGate();
    expect(() => gate.capture()).toThrow('Vault is locked');
    gate.initialize('locked');
    expect(() => gate.capture()).toThrow('Vault is locked');
  });

  it('never issues a secret lease for a restricted authenticated account', () => {
    const gate = new SessionGate('restricted');
    expect(() => gate.capture()).toThrow('Vault is locked');
  });

  it('invalidates a lease as soon as a transition starts', () => {
    const gate = new SessionGate('unlocked');
    const lease = gate.capture();

    gate.handleTransition(start(1));

    expect(() => gate.assert(lease)).toThrow('Vault session changed during operation');
    expect(() => gate.capture()).toThrow('Vault is locked');
  });

  it('does not let a late startup read overwrite an in-flight transition', () => {
    const gate = new SessionGate();
    gate.handleTransition(start(1, 'unlock'));

    gate.initialize('unlocked');

    expect(() => gate.capture()).toThrow('Vault is locked');
    gate.handleTransition(settled(1, 'unlocked', 'unlock'));
    expect(() => gate.assert(gate.capture())).not.toThrow();
  });

  it('establishes a fresh lease after a successful unlock settles', () => {
    const gate = new SessionGate('locked');
    gate.handleTransition(start(1, 'unlock'));
    gate.handleTransition(settled(1, 'unlocked', 'unlock'));

    const lease = gate.capture();
    expect(() => gate.assert(lease)).not.toThrow();
  });

  it('ignores a stale settled event after a newer transition has started', () => {
    const gate = new SessionGate('unlocked');
    gate.handleTransition(start(1));
    gate.handleTransition(start(2, 'unlock'));

    gate.handleTransition(settled(1, 'unlocked'));
    expect(() => gate.capture()).toThrow('Vault is locked');

    gate.handleTransition(settled(2, 'unlocked', 'unlock'));
    expect(() => gate.assert(gate.capture())).not.toThrow();
  });

  it('does not authorize storage left unlocked by a failed activation commit', () => {
    const gate = new SessionGate('locked');
    gate.handleTransition({ phase: 'start', transitionId: 1, reason: 'login', identityChanged: true });
    gate.handleTransition({
      phase: 'settled', transitionId: 1, reason: 'login', identityChanged: true,
      state: 'unlocked', succeeded: false,
    });

    expect(() => gate.capture()).toThrow('Vault is locked');
  });

  it('does not let later transitions reopen a failed terminal key rotation', () => {
    const gate = new SessionGate('unlocked');
    gate.handleTransition({
      phase: 'start', transitionId: 1, reason: 'keyRotation', identityChanged: true,
    });
    gate.handleTransition({
      phase: 'settled', transitionId: 1, reason: 'keyRotation', identityChanged: true,
      state: 'unlocked', succeeded: false,
    });
    gate.handleTransition(start(2, 'lock'));
    gate.handleTransition(settled(2, 'locked', 'lock'));

    expect(() => gate.capture()).toThrow('Vault is locked');
  });

  it('publishes loggedOut after a successful terminal key rotation cleanup', () => {
    const gate = new SessionGate('unlocked');
    gate.handleTransition({
      phase: 'start', transitionId: 1, reason: 'keyRotation', identityChanged: true,
    });
    gate.handleTransition({
      phase: 'settled', transitionId: 1, reason: 'keyRotation', identityChanged: true,
      state: 'loggedOut', succeeded: true,
    });

    expect(() => gate.capture()).toThrow('Vault is locked');
  });

  it('rejects a lease captured from another gate', () => {
    const first = new SessionGate('unlocked');
    const second = new SessionGate('unlocked');
    expect(() => second.assert(first.capture())).toThrow('Vault session changed during operation');
  });

  it('runs a hydrated timeout preflight before capture and assert', () => {
    const gate = new SessionGate('unlocked');
    const lease = gate.capture();
    gate.setPreflight(() => { throw new Error('deadline reached'); });

    expect(() => gate.capture()).toThrow('deadline reached');
    expect(() => gate.assert(lease)).toThrow('deadline reached');
  });

  it('supports a no-preflight assertion only for a post-checkpoint release fence', () => {
    const gate = new SessionGate('unlocked');
    const lease = gate.capture();
    let calls = 0;
    gate.setPreflight(() => { calls += 1; });

    gate.assertWithoutPreflight(lease);

    expect(calls).toBe(0);
    gate.assert(lease);
    expect(calls).toBe(1);
  });
});
