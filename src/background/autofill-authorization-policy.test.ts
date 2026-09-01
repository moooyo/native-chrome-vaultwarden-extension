import { describe, expect, it } from 'vitest';

import {
  assertAutofillAuthorizationPolicy,
  captureAutofillAuthorizationPolicy,
  isAutofillAuthorizationPolicyCurrent,
  resolveAutofillAuthorizationUriMatchDefault,
} from './autofill-authorization-policy.js';
import { AutofillPolicyGate } from './autofill-policy-gate.js';
import {
  EnterprisePolicyGate,
  EnterprisePolicyType,
  type DeriveEnterprisePolicyInput,
} from '../core/policy/effective-enterprise-policy.js';
import type { SyncResponse } from '../core/api/types.js';
import type { AccountLease } from '../core/session/account-gate.js';
import { UriMatchStrategy } from '../core/vault/uri-match.js';

const ACCOUNT: AccountLease = Object.freeze({
  serverGeneration: 1,
  accountGeneration: 2,
  serverUrl: 'https://vault.example.test/',
  accountIdentity: 'user@example.test',
});

function policyInput(rawGeneration: string, value: number): DeriveEnterprisePolicyInput {
  const response: SyncResponse = {
    profile: {
      id: 'user-id',
      email: ACCOUNT.accountIdentity,
      organizationsNew: [{ id: 'org-id', status: 2, type: 2, enabled: true, usePolicies: true }],
    },
    ciphers: [],
    policiesNew: [{
      id: 'uri-policy',
      organizationId: 'org-id',
      type: EnterprisePolicyType.UriMatchDefaults,
      enabled: true,
      data: { uriMatchDetection: value },
    }],
  };
  return { response, accountLease: ACCOUNT, rawGeneration };
}

describe('autofill authorization policy lease', () => {
  it('resolves Domain zero from the captured enterprise generation', () => {
    const autofill = new AutofillPolicyGate();
    const enterprise = new EnterprisePolicyGate();
    enterprise.replace(policyInput('raw-a', UriMatchStrategy.Domain));
    const gates = { autofill, enterprise };
    const lease = captureAutofillAuthorizationPolicy(gates);

    expect(resolveAutofillAuthorizationUriMatchDefault(
      gates,
      lease,
      UriMatchStrategy.Never,
    )).toEqual({ value: UriMatchStrategy.Domain, managed: true, malformed: false });
  });

  it('does not revive an old lease after an enterprise policy A-B-A transition', () => {
    const autofill = new AutofillPolicyGate();
    const enterprise = new EnterprisePolicyGate();
    const gates = { autofill, enterprise };
    enterprise.replace(policyInput('raw-a', UriMatchStrategy.Host));
    const stale = captureAutofillAuthorizationPolicy(gates);

    enterprise.replace(policyInput('raw-b', UriMatchStrategy.Exact));
    enterprise.replace(policyInput('raw-c', UriMatchStrategy.Host));

    expect(isAutofillAuthorizationPolicyCurrent(gates, stale)).toBe(false);
    expect(() => assertAutofillAuthorizationPolicy(gates, stale)).toThrow();
    const current = captureAutofillAuthorizationPolicy(gates);
    expect(resolveAutofillAuthorizationUriMatchDefault(
      gates,
      current,
      UriMatchStrategy.Domain,
    ).value).toBe(UriMatchStrategy.Host);
  });

  it('revokes the bundle when local autofill settings change', () => {
    const autofill = new AutofillPolicyGate();
    const enterprise = new EnterprisePolicyGate();
    enterprise.replace(policyInput('raw-a', UriMatchStrategy.Exact));
    const gates = { autofill, enterprise };
    const lease = captureAutofillAuthorizationPolicy(gates);

    autofill.invalidate();

    expect(isAutofillAuthorizationPolicyCurrent(gates, lease)).toBe(false);
  });
});
