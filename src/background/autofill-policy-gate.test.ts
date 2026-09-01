import { describe, expect, it } from 'vitest';
import { AutofillPolicyGate } from './autofill-policy-gate.js';

describe('AutofillPolicyGate', () => {
  it('accepts a current lease and revokes it synchronously', () => {
    const gate = new AutofillPolicyGate();
    const lease = gate.capture();
    expect(() => gate.assert(lease)).not.toThrow();
    gate.invalidate();
    expect(() => gate.assert(lease)).toThrow(/policy changed/i);
    expect(() => gate.assert(gate.capture())).not.toThrow();
  });

  it('rejects leases from another gate and forged snapshots', () => {
    const first = new AutofillPolicyGate();
    const second = new AutofillPolicyGate();
    expect(() => second.assert(first.capture())).toThrow();
    expect(() => first.assert({ generation: 0 })).toThrow();
  });
});
