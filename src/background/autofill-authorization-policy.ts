import type {
  AutofillPolicyGate,
  AutofillPolicyLease,
} from './autofill-policy-gate.js';
import type {
  EffectiveEnterprisePolicySnapshot,
  EnterprisePolicyGate,
  PolicyLease,
} from '../core/policy/effective-enterprise-policy.js';
import {
  resolveEnterpriseUriMatchDefault,
  type EffectiveEnterpriseUriMatchDefault,
} from '../core/policy/enterprise-uri-match-default.js';
import type { UriMatchStrategySetting } from '../core/vault/uri-match.js';
import {
  createGeneratorPolicySnapshot,
  type GeneratorPolicySnapshot,
} from '../core/generator/enterprise-password-policy.js';

export interface AutofillAuthorizationPolicyLease {
  readonly autofill: AutofillPolicyLease;
  readonly enterprise: PolicyLease;
}

export interface AutofillAuthorizationPolicyGates {
  readonly autofill: Pick<AutofillPolicyGate, 'capture' | 'assert'>;
  readonly enterprise: Pick<EnterprisePolicyGate, 'capture' | 'assert'>;
}

/** Capture one authorization fence spanning local settings and the raw-sync policy generation. */
export function captureAutofillAuthorizationPolicy(
  gates: AutofillAuthorizationPolicyGates,
): AutofillAuthorizationPolicyLease {
  const lease = Object.freeze({
    autofill: gates.autofill.capture(),
    enterprise: gates.enterprise.capture(),
  });
  assertAutofillAuthorizationPolicy(gates, lease);
  return lease;
}

export function assertAutofillAuthorizationPolicy(
  gates: AutofillAuthorizationPolicyGates,
  lease: AutofillAuthorizationPolicyLease,
): EffectiveEnterprisePolicySnapshot {
  assertLeaseShape(lease);
  gates.autofill.assert(lease.autofill);
  return gates.enterprise.assert(lease.enterprise);
}

export function isAutofillAuthorizationPolicyCurrent(
  gates: AutofillAuthorizationPolicyGates,
  lease: AutofillAuthorizationPolicyLease,
): boolean {
  try {
    assertAutofillAuthorizationPolicy(gates, lease);
    return true;
  } catch {
    return false;
  }
}

export function resolveAutofillAuthorizationUriMatchDefault(
  gates: AutofillAuthorizationPolicyGates,
  lease: AutofillAuthorizationPolicyLease,
  userValue: UriMatchStrategySetting,
): EffectiveEnterpriseUriMatchDefault {
  const snapshot = assertAutofillAuthorizationPolicy(gates, lease);
  const resolved = resolveEnterpriseUriMatchDefault(userValue, snapshot);
  assertAutofillAuthorizationPolicy(gates, lease);
  return resolved;
}

export function resolveAutofillAuthorizationGeneratorPolicy(
  gates: AutofillAuthorizationPolicyGates,
  lease: AutofillAuthorizationPolicyLease,
): GeneratorPolicySnapshot {
  const snapshot = assertAutofillAuthorizationPolicy(gates, lease);
  const resolved = createGeneratorPolicySnapshot(
    snapshot.passwordGeneratorPolicy,
    lease.enterprise.generation,
  );
  assertAutofillAuthorizationPolicy(gates, lease);
  return resolved;
}

function assertLeaseShape(
  lease: AutofillAuthorizationPolicyLease,
): asserts lease is AutofillAuthorizationPolicyLease {
  if (
    typeof lease !== 'object'
    || lease === null
    || typeof lease.autofill !== 'object'
    || lease.autofill === null
    || typeof lease.enterprise !== 'object'
    || lease.enterprise === null
  ) {
    throw new TypeError('Autofill authorization policy lease is invalid');
  }
}
