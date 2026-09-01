import { describe, expect, it, vi } from 'vitest';
import { SessionGate } from './session-gate.js';
import { VaultReleaseGate } from './vault-release-gate.js';

describe('VaultReleaseGate', () => {
  it('does not sample timeout preflight after the durable checkpoint', async () => {
    const session = new SessionGate('unlocked');
    const preflight = vi.fn();
    session.setPreflight(preflight);
    const timeout = {
      captureRelease: vi.fn(() => ({
        generation: 1,
        accountKey: 'account-a',
        sessionBindingId: 'binding-a',
      })),
      checkpointRelease: vi.fn(async () => ({
        generation: 1,
        accountKey: 'account-a',
        sessionBindingId: 'binding-a',
        issuedMonotonicAt: 1,
        monotonicDeadlineAt: 10,
      })),
      assertRelease: vi.fn(),
    };
    const gate = new VaultReleaseGate(timeout, session);
    const sessionLease = session.capture();
    const lease = gate.capture(sessionLease);
    const proof = await gate.checkpoint(lease);
    const preflightsAfterCheckpoint = preflight.mock.calls.length;

    gate.assertAuthorities(proof, () => session.assert(sessionLease));
    gate.assert(proof);

    expect(preflight).toHaveBeenCalledTimes(preflightsAfterCheckpoint);
    expect(timeout.assertRelease).toHaveBeenCalledOnce();
  });

  it('rejects a session transition after checkpoint without reusing the proof', async () => {
    const session = new SessionGate('unlocked');
    const timeout = {
      captureRelease: vi.fn(() => ({ generation: 1, accountKey: 'a', sessionBindingId: 'b' })),
      checkpointRelease: vi.fn(async () => ({
        generation: 1,
        accountKey: 'a',
        sessionBindingId: 'b',
        issuedMonotonicAt: 1,
        monotonicDeadlineAt: 10,
      })),
      assertRelease: vi.fn(),
    };
    const gate = new VaultReleaseGate(timeout, session);
    const proof = await gate.checkpoint(gate.capture());
    session.handleTransition({
      phase: 'start', transitionId: 1, reason: 'lock', identityChanged: false,
    });

    expect(() => gate.assertAuthorities(proof, () => {}))
      .toThrow('Vault session changed during operation');
    expect(() => gate.assert(proof)).toThrow('Vault release proof is invalid');
  });

});
