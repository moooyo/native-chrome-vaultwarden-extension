import { describe, expect, it } from 'vitest';
import type { OrganizationResponse, PolicyResponse, SyncResponse } from '../api/types.js';
import { AppError } from '../errors.js';
import type { AccountLease } from '../session/account-gate.js';
import {
  EnterprisePolicyGate,
  EnterprisePolicyType,
  deriveEffectiveEnterprisePolicy,
  enterprisePolicyAllows,
  enterprisePolicyAllowsSend,
  isEnterpriseItemRestricted,
  type DeriveEnterprisePolicyInput,
  type EnterprisePolicyCapability,
  type SupportedEnterprisePolicyType,
} from './effective-enterprise-policy.js';

const ACCOUNT: AccountLease = Object.freeze({
  serverGeneration: 2,
  accountGeneration: 7,
  serverUrl: 'https://vault.example.test',
  accountIdentity: 'user@example.test',
});

function organization(overrides: Partial<OrganizationResponse> = {}): OrganizationResponse {
  return {
    id: 'org-a',
    key: '4.encrypted-key',
    status: 2,
    type: 2,
    enabled: true,
    usePolicies: true,
    ...overrides,
  };
}

function policy(
  type: number,
  overrides: Partial<PolicyResponse> = {},
): PolicyResponse {
  return {
    id: `policy-${type}`,
    organizationId: 'org-a',
    type,
    enabled: true,
    ...overrides,
  };
}

function sync(overrides: Partial<SyncResponse> = {}): SyncResponse {
  return {
    profile: {
      id: 'user-id',
      email: ACCOUNT.accountIdentity,
      organizationsNew: [organization()],
    },
    ciphers: [],
    policiesNew: [],
    ...overrides,
  };
}

function derive(
  policies: PolicyResponse[],
  overrides: Partial<DeriveEnterprisePolicyInput> = {},
) {
  return deriveEffectiveEnterprisePolicy({
    response: sync({ policiesNew: policies }),
    accountLease: ACCOUNT,
    rawGeneration: 'raw-11',
    ...overrides,
  });
}

describe('effective enterprise policy source selection', () => {
  it('uses a non-empty policiesNew collection without merging legacy policies', () => {
    const snapshot = deriveEffectiveEnterprisePolicy({
      response: sync({
        policies: [policy(EnterprisePolicyType.DisableSend)],
        policiesNew: [policy(EnterprisePolicyType.DisablePersonalVaultExport)],
      }),
      accountLease: ACCOUNT,
      rawGeneration: 'raw-a',
    });

    expect(snapshot.policySource).toBe('policiesNew');
    expect(snapshot.personalVaultExportDisabled).toBe(true);
    expect(snapshot.sendControls.disabled).toBe(false);
  });

  const fallbackCases: Array<readonly [string, PolicyResponse[] | null | undefined]> = [
    ['empty', []],
    ['null', null],
    ['absent', undefined],
  ];

  it.each(fallbackCases)('falls back to legacy policies when policiesNew is %s', (_label, policiesNew) => {
    const profile = { id: 'user-id', email: ACCOUNT.accountIdentity, organizations: [organization()] };
    const response: SyncResponse = {
      profile,
      ciphers: [],
      policies: [policy(EnterprisePolicyType.DisableSend)],
      ...(policiesNew === undefined ? {} : { policiesNew }),
    };
    const snapshot = deriveEffectiveEnterprisePolicy({ response, accountLease: ACCOUNT, rawGeneration: 'raw' });

    expect(snapshot.policySource).toBe('policies');
    expect(snapshot.sendControls.disabled).toBe(true);
  });

  it('preserves unknown policy types as diagnostics without enforcing them', () => {
    const snapshot = derive([policy(88), policy(88, { id: 'duplicate' }), policy(89, { enabled: false })]);

    expect(snapshot.unknownPolicyTypes).toEqual([88, 89]);
    expect(snapshot.activePolicyTypes).toEqual([]);
    expect(snapshot.sendControls.disabled).toBe(false);
  });

  it('diagnoses a known policy whose enabled flag is malformed', () => {
    const malformedEnabled = policy(EnterprisePolicyType.DisableSend) as unknown as Record<string, unknown>;
    malformedEnabled.enabled = 'true';
    const snapshot = derive([malformedEnabled as unknown as PolicyResponse]);

    expect(snapshot.sendControls.disabled).toBe(false);
    expect(snapshot.malformedPolicyTypes).toContain(EnterprisePolicyType.DisableSend);
  });

  it('rejects a present non-array authoritative policy envelope', () => {
    const response = sync({ policiesNew: { forged: true } as never });

    expect(() => deriveEffectiveEnterprisePolicy({
      response,
      accountLease: ACCOUNT,
      rawGeneration: 'raw-invalid-envelope',
    })).toThrow(/policy collection/i);
  });
});

describe('master password policy', () => {
  it('combines every applicable policy by maximum numeric and boolean OR rules', () => {
    const snapshot = derive([
      policy(EnterprisePolicyType.MasterPassword, {
        id: 'mp-a',
        data: { minLength: 14, requireUpper: true, enforceOnLogin: false },
      }),
      policy(EnterprisePolicyType.MasterPassword, {
        id: 'mp-b',
        data: { minLength: 20, minComplexity: 3, requireNumbers: true, enforceOnLogin: true },
      }),
    ]);
    expect(snapshot.masterPasswordPolicy).toMatchObject({
      minLength: 20,
      minComplexity: 3,
      requireUpper: true,
      requireNumbers: true,
      enforceOnLogin: true,
    });
    expect(snapshot.masterPasswordPolicyMalformed).toBe(false);
  });

  it('marks malformed active policy data without producing a permissive policy', () => {
    const snapshot = derive([policy(EnterprisePolicyType.MasterPassword, {
      data: { minLength: '20', enforceOnLogin: true },
    })]);
    expect(snapshot.masterPasswordPolicy).toBeNull();
    expect(snapshot.masterPasswordPolicyMalformed).toBe(true);
    expect(snapshot.malformedPolicyTypes).toContain(EnterprisePolicyType.MasterPassword);
  });
});

describe('password generator policy', () => {
  it('combines every applicable policy by numeric maximum and boolean OR rules', () => {
    const snapshot = derive([
      policy(EnterprisePolicyType.PasswordGenerator, {
        id: 'generator-a',
        data: {
          overridePasswordType: 'passphrase',
          minLength: 18,
          useUpper: true,
          minNumbers: 2,
          minNumberWords: 6,
          capitalize: true,
        },
      }),
      policy(EnterprisePolicyType.PasswordGenerator, {
        id: 'generator-b',
        data: {
          overridePasswordType: 'password',
          minLength: 24,
          useLower: true,
          useNumbers: true,
          minNumbers: 4,
          useSpecial: true,
          minSpecial: 3,
          includeNumber: true,
        },
      }),
    ]);

    expect(snapshot.passwordGeneratorPolicy).toEqual({
      malformed: false,
      data: {
        overridePasswordType: 'password',
        minLength: 24,
        useUpper: true,
        useLower: true,
        useNumbers: true,
        minNumbers: 4,
        useSpecial: true,
        minSpecial: 3,
        minNumberWords: 6,
        capitalize: true,
        includeNumber: true,
      },
    });
    expect(snapshot.malformedPolicyTypes).not.toContain(EnterprisePolicyType.PasswordGenerator);
  });

  it('marks the combined policy malformed when any applicable entry is malformed', () => {
    const snapshot = derive([
      policy(EnterprisePolicyType.PasswordGenerator, {
        id: 'valid-generator',
        data: { minLength: 20, useNumbers: true },
      }),
      policy(EnterprisePolicyType.PasswordGenerator, {
        id: 'malformed-generator',
        data: { minNumbers: '4' },
      }),
    ]);

    expect(snapshot.passwordGeneratorPolicy).toMatchObject({
      malformed: true,
      data: { minLength: 20, useNumbers: true },
    });
    expect(snapshot.malformedPolicyTypes).toContain(EnterprisePolicyType.PasswordGenerator);
  });

  it('does not let an exempt provider policy contaminate an applicable direct policy', () => {
    const snapshot = deriveEffectiveEnterprisePolicy({
      response: sync({
        profile: {
          id: 'user-id',
          email: ACCOUNT.accountIdentity,
          organizationsNew: [organization({ id: 'direct-org', type: 2 })],
          providerOrganizations: [organization({ id: 'provider-org', type: 2 })],
        },
        policiesNew: [
          policy(EnterprisePolicyType.PasswordGenerator, {
            id: 'provider-generator',
            organizationId: 'provider-org',
            data: { overridePasswordType: 'password', minLength: 100 },
          }),
          policy(EnterprisePolicyType.PasswordGenerator, {
            id: 'direct-generator',
            organizationId: 'direct-org',
            data: { overridePasswordType: 'passphrase', minNumberWords: 7 },
          }),
        ],
      }),
      accountLease: ACCOUNT,
      rawGeneration: 'raw-generator',
    });

    expect(snapshot.passwordGeneratorPolicy).toMatchObject({
      malformed: false,
      data: {
        overridePasswordType: 'passphrase',
        minLength: 0,
        minNumberWords: 7,
      },
    });
  });
});

describe('activate autofill policy', () => {
  it('projects the presence of any applicable enabled type-11 policy without interpreting data', () => {
    const snapshot = derive([policy(EnterprisePolicyType.ActivateAutofill, {
      data: { ignoredByPresencePolicy: true },
    })]);

    expect(snapshot.activateAutofillRequired).toBe(true);
    expect(snapshot.malformedPolicyTypes).not.toContain(EnterprisePolicyType.ActivateAutofill);
  });

  it('does not activate autofill for a disabled type-11 policy', () => {
    const snapshot = derive([policy(EnterprisePolicyType.ActivateAutofill, { enabled: false })]);

    expect(snapshot.activateAutofillRequired).toBe(false);
  });
});

describe('Require SSO policy', () => {
  it.each([
    ['missing data', undefined],
    ['null data', null],
  ])('enforces an applicable enabled type-4 policy with %s', (_label, data) => {
    const snapshot = derive([policy(EnterprisePolicyType.RequireSso, { data })]);

    expect(snapshot.requireSso).toBe(true);
    expect(snapshot.activePolicyTypes).toContain(EnterprisePolicyType.RequireSso);
    expect(snapshot.malformedPolicyTypes).not.toContain(EnterprisePolicyType.RequireSso);
  });

  it('does not enforce a disabled type-4 policy', () => {
    const snapshot = derive([policy(EnterprisePolicyType.RequireSso, {
      enabled: false,
      data: { ignoredBecauseDisabled: true },
    })]);

    expect(snapshot.requireSso).toBe(false);
    expect(snapshot.activePolicyTypes).not.toContain(EnterprisePolicyType.RequireSso);
    expect(snapshot.malformedPolicyTypes).not.toContain(EnterprisePolicyType.RequireSso);
  });

  it.each([
    ['empty object', {}],
    ['array', []],
    ['boolean', false],
    ['string', 'unexpected'],
  ])('fails closed for unexpected %s policy data', (_label, data) => {
    const snapshot = derive([policy(EnterprisePolicyType.RequireSso, { data })]);

    expect(snapshot.requireSso).toBe(true);
    expect(snapshot.activePolicyTypes).toContain(EnterprisePolicyType.RequireSso);
    expect(snapshot.malformedPolicyTypes).toContain(EnterprisePolicyType.RequireSso);
  });

  it('fails closed without invoking accessor properties in an otherwise applicable envelope', () => {
    let reads = 0;
    const raw = policy(EnterprisePolicyType.RequireSso) as unknown as Record<string, unknown>;
    Object.defineProperty(raw, 'data', {
      configurable: true,
      enumerable: true,
      get: () => {
        reads += 1;
        return undefined;
      },
    });

    const snapshot = derive([raw as unknown as PolicyResponse]);

    expect(reads).toBe(0);
    expect(snapshot.requireSso).toBe(true);
    expect(snapshot.malformedPolicyTypes).toContain(EnterprisePolicyType.RequireSso);
  });

  it('fails closed for a custom-prototype policy envelope', () => {
    const raw = Object.assign(
      Object.create({ inherited: 'untrusted' }) as Record<string, unknown>,
      policy(EnterprisePolicyType.RequireSso),
    );

    const snapshot = derive([raw as unknown as PolicyResponse]);

    expect(snapshot.requireSso).toBe(true);
    expect(snapshot.activePolicyTypes).not.toContain(EnterprisePolicyType.RequireSso);
    expect(snapshot.malformedPolicyTypes).toContain(EnterprisePolicyType.RequireSso);
  });

  it('still honors disabled, role, and provider exemptions for malformed records', () => {
    const disabledEnvelope = Object.assign(
      Object.create({ inherited: 'untrusted' }) as Record<string, unknown>,
      policy(EnterprisePolicyType.RequireSso, { enabled: false }),
    );
    const disabled = derive([disabledEnvelope as unknown as PolicyResponse]);
    expect(disabled.requireSso).toBe(false);

    for (const response of [
      sync({
        profile: {
          id: 'user-id',
          email: ACCOUNT.accountIdentity,
          organizationsNew: [organization({ type: 0 })],
        },
        policiesNew: [policy(EnterprisePolicyType.RequireSso, { data: { unexpected: true } })],
      }),
      sync({
        profile: {
          id: 'user-id',
          email: ACCOUNT.accountIdentity,
          organizationsNew: [],
          providerOrganizations: [organization()],
        },
        policiesNew: [policy(EnterprisePolicyType.RequireSso, { data: { unexpected: true } })],
      }),
    ]) {
      const snapshot = deriveEffectiveEnterprisePolicy({
        response,
        accountLease: ACCOUNT,
        rawGeneration: 'raw-exempt-sso',
      });
      expect(snapshot.requireSso).toBe(false);
      expect(snapshot.malformedPolicyTypes).not.toContain(EnterprisePolicyType.RequireSso);
    }
  });

  it('fails closed when the enabled flag is not a boolean', () => {
    const raw = policy(EnterprisePolicyType.RequireSso) as unknown as Record<string, unknown>;
    raw.enabled = 'true';

    const snapshot = derive([raw as unknown as PolicyResponse]);

    expect(snapshot.requireSso).toBe(true);
    expect(snapshot.malformedPolicyTypes).toContain(EnterprisePolicyType.RequireSso);
  });
});

describe('URI match defaults policy', () => {
  it.each([
    ['Domain', 0],
    ['Host', 1],
    ['StartsWith', 2],
    ['Exact', 3],
    ['RegularExpression', 4],
    ['Never', 5],
  ] as const)('accepts the official %s value without treating zero as absent', (_label, value) => {
    const snapshot = derive([policy(EnterprisePolicyType.UriMatchDefaults, {
      data: { uriMatchDetection: value },
    })]);

    expect(snapshot.uriMatchDefaultsPolicy).toEqual({
      organizationId: 'org-a',
      malformed: false,
      value,
    });
    expect(snapshot.malformedPolicyTypes).not.toContain(EnterprisePolicyType.UriMatchDefaults);
  });

  it.each([
    ['missing data', undefined],
    ['null data', null],
    ['array data', []],
    ['missing value', {}],
    ['string value', { uriMatchDetection: '0' }],
    ['negative value', { uriMatchDetection: -1 }],
    ['future value', { uriMatchDetection: 6 }],
    ['fractional value', { uriMatchDetection: 1.5 }],
  ])('fails closed to Never for %s', (_label, data) => {
    const snapshot = derive([policy(EnterprisePolicyType.UriMatchDefaults, { data })]);

    expect(snapshot.uriMatchDefaultsPolicy).toEqual({
      organizationId: 'org-a',
      malformed: true,
      value: 5,
    });
    expect(snapshot.malformedPolicyTypes).toContain(EnterprisePolicyType.UriMatchDefaults);
  });

  it('uses the first applicable policy in source order', () => {
    const snapshot = deriveEffectiveEnterprisePolicy({
      response: sync({
        profile: {
          id: 'user-id',
          email: ACCOUNT.accountIdentity,
          organizationsNew: [
            organization({ type: 0 }),
            organization({ id: 'org-b', type: 2 }),
            organization({ id: 'org-c', type: 2 }),
          ],
        },
        policiesNew: [
          policy(EnterprisePolicyType.UriMatchDefaults, {
            id: 'exempt-owner',
            data: { uriMatchDetection: 5 },
          }),
          policy(EnterprisePolicyType.UriMatchDefaults, {
            id: 'first-applicable',
            organizationId: 'org-b',
            data: { uriMatchDetection: 1 },
          }),
          policy(EnterprisePolicyType.UriMatchDefaults, {
            id: 'second-applicable',
            organizationId: 'org-c',
            data: { uriMatchDetection: 3 },
          }),
        ],
      }),
      accountLease: ACCOUNT,
      rawGeneration: 'raw-uri',
    });

    expect(snapshot.uriMatchDefaultsPolicy).toEqual({
      organizationId: 'org-b',
      malformed: false,
      value: 1,
    });
  });
});

describe('organization membership context', () => {
  it('uses organizationsNew when present, including an empty collection', () => {
    const response = sync({
      profile: {
        id: 'user-id',
        email: ACCOUNT.accountIdentity,
        organizations: [organization({ type: 0 })],
        organizationsNew: [],
      },
      policiesNew: [policy(EnterprisePolicyType.DisableSend)],
    });
    const snapshot = deriveEffectiveEnterprisePolicy({ response, accountLease: ACCOUNT, rawGeneration: 'raw' });

    expect(snapshot.organizationContextSource).toBe('organizationsNew');
    expect(snapshot.sendControls.disabled).toBe(true);
  });

  it('falls back to organizations when organizationsNew is null', () => {
    const response = sync({
      profile: {
        id: 'user-id',
        email: ACCOUNT.accountIdentity,
        organizations: [organization({ type: 0 })],
        organizationsNew: null,
      },
      policiesNew: [policy(EnterprisePolicyType.DisableSend)],
    });
    const snapshot = deriveEffectiveEnterprisePolicy({ response, accountLease: ACCOUNT, rawGeneration: 'raw' });

    expect(snapshot.organizationContextSource).toBe('organizations');
    expect(snapshot.sendControls.disabled).toBe(false);
  });

  it('adds provider-only organizations and applies the provider exemption', () => {
    const response = sync({
      profile: {
        id: 'user-id',
        email: ACCOUNT.accountIdentity,
        organizationsNew: [],
        providerOrganizations: [organization({ id: 'provider-org' })],
      },
      policiesNew: [policy(EnterprisePolicyType.DisableSend, { organizationId: 'provider-org' })],
    });
    const snapshot = deriveEffectiveEnterprisePolicy({ response, accountLease: ACCOUNT, rawGeneration: 'raw' });

    expect(snapshot.sendControls.disabled).toBe(false);
  });

  it('marks a direct membership as a provider user when both lists contain the organization', () => {
    const response = sync({
      profile: {
        id: 'user-id',
        email: ACCOUNT.accountIdentity,
        organizationsNew: [organization({ type: 2 })],
        providerOrganizations: [organization({ type: 2 })],
      },
      policiesNew: [policy(EnterprisePolicyType.RemoveUnlockWithPin)],
    });
    const snapshot = deriveEffectiveEnterprisePolicy({ response, accountLease: ACCOUNT, rawGeneration: 'raw' });

    expect(snapshot.unlockWithPinRemoved).toBe(false);
  });

  it.each([
    ['disabled organization', organization({ enabled: false }), false],
    ['no policy entitlement', organization({ usePolicies: false }), false],
    ['revoked', organization({ status: -1 }), false],
    ['invited', organization({ status: 0 }), false],
    ['staged', organization({ status: 3 }), false],
    ['accepted', organization({ status: 1 }), true],
    ['confirmed', organization({ status: 2 }), true],
  ])('%s membership enforcement is %s', (_label, member, expected) => {
    const snapshot = deriveEffectiveEnterprisePolicy({
      response: sync({
        profile: { id: 'user-id', email: ACCOUNT.accountIdentity, organizationsNew: [member] },
        policiesNew: [policy(EnterprisePolicyType.RemoveUnlockWithPin)],
      }),
      accountLease: ACCOUNT,
      rawGeneration: 'raw',
    });
    expect(snapshot.unlockWithPinRemoved).toBe(expected);
  });

  it.each([
    ['missing context', []],
    ['missing enabled', [{ ...organization(), enabled: undefined } as unknown as OrganizationResponse]],
    ['unknown status', [organization({ status: 99 })]],
    ['unknown role', [organization({ type: 99 })]],
  ])('enforces fail-closed for %s', (_label, organizationsNew) => {
    const snapshot = deriveEffectiveEnterprisePolicy({
      response: sync({
        profile: { id: 'user-id', email: ACCOUNT.accountIdentity, organizationsNew },
        policiesNew: [policy(EnterprisePolicyType.DisableSend)],
      }),
      accountLease: ACCOUNT,
      rawGeneration: 'raw',
    });
    expect(snapshot.sendControls.disabled).toBe(true);
  });

  it('treats missing legacy entitlement flags as implicit true without bypassing role exemptions', () => {
    const sparseOwner = {
      id: 'org-a',
      key: '4.encrypted-key',
      status: 2,
      type: 0,
    } satisfies OrganizationResponse;
    const snapshot = deriveEffectiveEnterprisePolicy({
      response: sync({
        profile: { id: 'user-id', email: ACCOUNT.accountIdentity, organizations: [sparseOwner] },
        policiesNew: [
          policy(EnterprisePolicyType.DisableSend),
          policy(EnterprisePolicyType.RemoveUnlockWithPin, { id: 'pin-policy' }),
        ],
      }),
      accountLease: ACCOUNT,
      rawGeneration: 'raw',
    });

    expect(snapshot.sendControls.disabled).toBe(false);
    expect(snapshot.unlockWithPinRemoved).toBe(true);
  });

  it('keeps explicit disabled or no-policy-entitlement flags authoritative in sparse contexts', () => {
    for (const member of [
      { ...organization(), enabled: false, usePolicies: undefined },
      { ...organization(), enabled: undefined, usePolicies: false },
    ] as unknown as OrganizationResponse[]) {
      const snapshot = deriveEffectiveEnterprisePolicy({
        response: sync({
          profile: { id: 'user-id', email: ACCOUNT.accountIdentity, organizations: [member] },
          policiesNew: [policy(EnterprisePolicyType.RemoveUnlockWithPin)],
        }),
        accountLease: ACCOUNT,
        rawGeneration: 'raw',
      });
      expect(snapshot.unlockWithPinRemoved).toBe(false);
    }
  });
});

describe('policy-specific role exemptions', () => {
  const cases: ReadonlyArray<{
    type: SupportedEnterprisePolicyType;
    owner: boolean;
    admin: boolean;
    user: boolean;
    custom: boolean;
  }> = [
    { type: EnterprisePolicyType.RequireSso, owner: false, admin: false, user: true, custom: true },
    { type: EnterprisePolicyType.OrganizationDataOwnership, owner: false, admin: false, user: true, custom: true },
    { type: EnterprisePolicyType.PasswordGenerator, owner: true, admin: true, user: true, custom: true },
    { type: EnterprisePolicyType.DisableSend, owner: false, admin: false, user: true, custom: true },
    { type: EnterprisePolicyType.SendOptions, owner: false, admin: false, user: true, custom: true },
    { type: EnterprisePolicyType.MaximumVaultTimeout, owner: false, admin: true, user: true, custom: true },
    { type: EnterprisePolicyType.DisablePersonalVaultExport, owner: false, admin: false, user: true, custom: true },
    { type: EnterprisePolicyType.ActivateAutofill, owner: false, admin: false, user: true, custom: true },
    { type: EnterprisePolicyType.RemoveUnlockWithPin, owner: true, admin: true, user: true, custom: true },
    { type: EnterprisePolicyType.RestrictedItemTypes, owner: true, admin: true, user: true, custom: true },
    { type: EnterprisePolicyType.UriMatchDefaults, owner: false, admin: false, user: true, custom: true },
    { type: EnterprisePolicyType.SendControls, owner: false, admin: false, user: true, custom: true },
  ];

  it.each(cases)('applies type $type to the official roles', ({ type, owner, admin, user, custom }) => {
    const results = [0, 1, 2, 4].map((role) => {
      const data = type === EnterprisePolicyType.MaximumVaultTimeout
        ? { minutes: 5, type: 'custom', action: 'lock' }
        : type === EnterprisePolicyType.PasswordGenerator
          ? {}
        : type === EnterprisePolicyType.RestrictedItemTypes
          ? [3]
          : type === EnterprisePolicyType.UriMatchDefaults
            ? { uriMatchDetection: 1 }
          : type === EnterprisePolicyType.SendControls
            ? { disableSend: true }
            : undefined;
      const snapshot = deriveEffectiveEnterprisePolicy({
        response: sync({
          profile: {
            id: 'user-id',
            email: ACCOUNT.accountIdentity,
            organizationsNew: [organization({ type: role })],
          },
          policiesNew: [policy(type, { data })],
        }),
        accountLease: ACCOUNT,
        rawGeneration: 'raw',
      });
      return snapshot.activePolicyTypes.includes(type);
    });

    expect(results).toEqual([owner, admin, user, custom]);
  });

  it.each(Object.values(EnterprisePolicyType))('exempts Provider users from type %s', (type) => {
    const data = type === EnterprisePolicyType.MaximumVaultTimeout
      ? { minutes: 5 }
      : type === EnterprisePolicyType.PasswordGenerator
        ? {}
      : type === EnterprisePolicyType.RestrictedItemTypes
        ? [3]
        : type === EnterprisePolicyType.UriMatchDefaults
          ? { uriMatchDetection: 1 }
        : type === EnterprisePolicyType.SendControls
          ? { disableSend: true }
          : undefined;
    const response = sync({
      profile: {
        id: 'user-id',
        email: ACCOUNT.accountIdentity,
        organizationsNew: [],
        providerOrganizations: [organization()],
      },
      policiesNew: [policy(type, { data })],
    });
    const snapshot = deriveEffectiveEnterprisePolicy({ response, accountLease: ACCOUNT, rawGeneration: 'raw' });

    expect(snapshot.activePolicyTypes).not.toContain(type);
  });
});

describe('capability decisions', () => {
  it('exposes narrow deny decisions for ownership, export, PIN, and Send', () => {
    const snapshot = derive([
      policy(EnterprisePolicyType.OrganizationDataOwnership),
      policy(EnterprisePolicyType.DisablePersonalVaultExport),
      policy(EnterprisePolicyType.RemoveUnlockWithPin),
      policy(EnterprisePolicyType.DisableSend),
    ]);
    const capabilities: EnterprisePolicyCapability[] = [
      'createPersonalVaultItem', 'exportPersonalVault', 'unlockWithPin', 'createOrEditSend',
    ];

    expect(capabilities.map((capability) => enterprisePolicyAllows(snapshot, capability)))
      .toEqual([false, false, false, false]);
  });

  it('allows capabilities when no applicable policy exists', () => {
    const snapshot = derive([]);
    expect(enterprisePolicyAllows(snapshot, 'createPersonalVaultItem')).toBe(true);
    expect(enterprisePolicyAllows(snapshot, 'exportPersonalVault')).toBe(true);
    expect(enterprisePolicyAllows(snapshot, 'unlockWithPin')).toBe(true);
    expect(enterprisePolicyAllows(snapshot, 'createOrEditSend')).toBe(true);
  });

  it('denies personal export whenever data ownership applies', () => {
    const snapshot = derive([policy(EnterprisePolicyType.OrganizationDataOwnership)]);

    expect(snapshot.personalVaultExportDisabled).toBe(false);
    expect(enterprisePolicyAllows(snapshot, 'exportPersonalVault')).toBe(false);
  });
});

describe('organization data ownership transfer policy', () => {
  const revision = '2026-08-30T10:20:30.1234567Z';

  it('keeps creation denied without inventing a transfer for an ordinary ODO policy', () => {
    const snapshot = derive([policy(EnterprisePolicyType.OrganizationDataOwnership)]);

    expect(snapshot.organizationDataOwnershipRequired).toBe(true);
    expect(snapshot.organizationDataOwnershipTransferPolicy).toBeNull();
    expect(snapshot.organizationDataOwnershipOrganizationIds).toEqual([]);
    expect(enterprisePolicyAllows(snapshot, 'createPersonalVaultItem')).toBe(false);
    expect(snapshot.malformedPolicyTypes).not.toContain(EnterprisePolicyType.OrganizationDataOwnership);
  });

  it('projects and freezes one strictly valid transfer policy', () => {
    const snapshot = derive([policy(EnterprisePolicyType.OrganizationDataOwnership, {
      data: { enableIndividualItemsTransfer: true },
      revisionDate: revision,
    })]);

    expect(snapshot.organizationDataOwnershipTransferPolicy).toEqual({
      organizationId: 'org-a',
      revisionDate: revision,
    });
    expect(snapshot.organizationDataOwnershipOrganizationIds).toEqual(['org-a']);
    expect(Object.isFrozen(snapshot.organizationDataOwnershipTransferPolicy)).toBe(true);
    expect(Object.isFrozen(snapshot.organizationDataOwnershipOrganizationIds)).toBe(true);
  });

  it('accepts one explicit null revision for Vaultwarden compatibility', () => {
    const snapshot = derive([policy(EnterprisePolicyType.OrganizationDataOwnership, {
      data: { enableIndividualItemsTransfer: true },
      revisionDate: null,
    })]);

    expect(snapshot.organizationDataOwnershipTransferPolicy).toEqual({
      organizationId: 'org-a',
      revisionDate: null,
    });
    expect(snapshot.malformedPolicyTypes).not.toContain(EnterprisePolicyType.OrganizationDataOwnership);
  });

  it.each([
    ['explicit false', { data: { enableIndividualItemsTransfer: false }, revisionDate: revision }, false],
    ['null data', { data: null, revisionDate: revision }, false],
    ['missing flag', { data: {}, revisionDate: revision }, true],
    ['forged flag', { data: { enableIndividualItemsTransfer: 'true' }, revisionDate: revision }, true],
    ['extra field', {
      data: { enableIndividualItemsTransfer: true, future: false },
      revisionDate: revision,
    }, true],
    ['non-object data', { data: [true], revisionDate: revision }, true],
    ['missing revision', { data: { enableIndividualItemsTransfer: true } }, true],
    ['invalid calendar revision', {
      data: { enableIndividualItemsTransfer: true },
      revisionDate: '2026-02-30T10:20:30.000Z',
    }, true],
    ['invalid organization id', {
      organizationId: ' org-a ',
      data: { enableIndividualItemsTransfer: true },
      revisionDate: revision,
    }, true],
    ['unknown organization id', {
      organizationId: 'org-unknown',
      data: { enableIndividualItemsTransfer: true },
      revisionDate: revision,
    }, true],
  ] as const)('does not create a transfer candidate for %s', (_label, overrides, malformed) => {
    const snapshot = derive([policy(EnterprisePolicyType.OrganizationDataOwnership, overrides)]);

    expect(snapshot.organizationDataOwnershipRequired).toBe(true);
    expect(snapshot.organizationDataOwnershipTransferPolicy).toBeNull();
    expect(snapshot.organizationDataOwnershipOrganizationIds).toEqual([]);
    expect(snapshot.malformedPolicyTypes.includes(EnterprisePolicyType.OrganizationDataOwnership))
      .toBe(malformed);
  });

  it('selects the earliest revision and breaks equal-time ties by organization id', () => {
    const organizationsNew = [
      organization({ id: 'org-c' }),
      organization({ id: 'org-b' }),
      organization({ id: 'org-a' }),
    ];
    const candidates = [
      policy(EnterprisePolicyType.OrganizationDataOwnership, {
        id: 'policy-c',
        organizationId: 'org-c',
        data: { enableIndividualItemsTransfer: true },
        revisionDate: '2026-08-31T00:00:00.000Z',
      }),
      policy(EnterprisePolicyType.OrganizationDataOwnership, {
        id: 'policy-b',
        organizationId: 'org-b',
        data: { enableIndividualItemsTransfer: true },
        revisionDate: revision,
      }),
      policy(EnterprisePolicyType.OrganizationDataOwnership, {
        id: 'policy-a',
        organizationId: 'org-a',
        data: { enableIndividualItemsTransfer: true },
        revisionDate: revision,
      }),
    ];
    const deriveCandidates = (policiesNew: PolicyResponse[]) => deriveEffectiveEnterprisePolicy({
      response: sync({
        profile: { id: 'user-id', email: ACCOUNT.accountIdentity, organizationsNew },
        policiesNew,
      }),
      accountLease: ACCOUNT,
      rawGeneration: 'raw-transfer',
    });

    for (const snapshot of [deriveCandidates(candidates), deriveCandidates([...candidates].reverse())]) {
      expect(snapshot.organizationDataOwnershipTransferPolicy).toEqual({
        organizationId: 'org-a',
        revisionDate: revision,
      });
      expect(snapshot.organizationDataOwnershipOrganizationIds).toEqual(['org-a']);
    }
  });

  it('fails closed when an undated transfer competes with another candidate', () => {
    const snapshot = deriveEffectiveEnterprisePolicy({
      response: sync({
        profile: {
          id: 'user-id',
          email: ACCOUNT.accountIdentity,
          organizationsNew: [organization({ id: 'org-a' }), organization({ id: 'org-b' })],
        },
        policiesNew: [
          policy(EnterprisePolicyType.OrganizationDataOwnership, {
            organizationId: 'org-a',
            data: { enableIndividualItemsTransfer: true },
            revisionDate: null,
          }),
          policy(EnterprisePolicyType.OrganizationDataOwnership, {
            organizationId: 'org-b',
            data: { enableIndividualItemsTransfer: true },
            revisionDate: revision,
          }),
        ],
      }),
      accountLease: ACCOUNT,
      rawGeneration: 'raw-undated-transfer',
    });

    expect(snapshot.organizationDataOwnershipTransferPolicy).toBeNull();
    expect(snapshot.malformedPolicyTypes).toContain(EnterprisePolicyType.OrganizationDataOwnership);
  });

  it('does not select a valid target while another active transfer record is malformed', () => {
    const snapshot = deriveEffectiveEnterprisePolicy({
      response: sync({
        profile: {
          id: 'user-id',
          email: ACCOUNT.accountIdentity,
          organizationsNew: [organization({ id: 'org-a' }), organization({ id: 'org-b' })],
        },
        policiesNew: [
          policy(EnterprisePolicyType.OrganizationDataOwnership, {
            organizationId: 'org-a',
            data: { enableIndividualItemsTransfer: true },
            revisionDate: revision,
          }),
          policy(EnterprisePolicyType.OrganizationDataOwnership, {
            organizationId: 'org-b',
            data: { enableIndividualItemsTransfer: 'true' },
            revisionDate: '2026-08-31T00:00:00.000Z',
          }),
        ],
      }),
      accountLease: ACCOUNT,
      rawGeneration: 'raw-mixed-transfer',
    });

    expect(snapshot.organizationDataOwnershipTransferPolicy).toBeNull();
    expect(snapshot.malformedPolicyTypes).toContain(EnterprisePolicyType.OrganizationDataOwnership);
  });
});

describe('maximum vault timeout policy', () => {
  it('normalizes valid policy data without losing scope', () => {
    const snapshot = derive([policy(EnterprisePolicyType.MaximumVaultTimeout, {
      data: { type: 'custom', minutes: 15, action: 'lock', future: 'preserved-in-raw' },
    })]);

    expect(snapshot.maximumVaultTimeoutPolicy).toEqual({
      organizationId: 'org-a',
      malformed: false,
      data: { type: 'custom', minutes: 15, action: 'lock' },
    });
    expect(snapshot.malformedPolicyTypes).toEqual([]);
  });

  it.each([
    ['missing data', undefined],
    ['array', []],
    ['missing minutes', { type: 'custom', action: 'lock' }],
    ['negative minutes', { type: 'custom', minutes: -1, action: 'lock' }],
    ['fractional minutes', { type: 'custom', minutes: 1.5, action: 'lock' }],
    ['unknown type', { type: 'later', minutes: 5, action: 'lock' }],
    ['unknown action', { type: 'custom', minutes: 5, action: 'erase' }],
  ])('fails closed for %s', (_label, data) => {
    const snapshot = derive([policy(EnterprisePolicyType.MaximumVaultTimeout, { data })]);

    expect(snapshot.maximumVaultTimeoutPolicy).toEqual({
      organizationId: 'org-a',
      malformed: true,
      data: { type: 'immediately', minutes: 0, action: 'logOut' },
    });
    expect(snapshot.malformedPolicyTypes).toContain(EnterprisePolicyType.MaximumVaultTimeout);
  });

  it('uses the first applicable timeout policy in source order', () => {
    const snapshot = derive([
      policy(EnterprisePolicyType.MaximumVaultTimeout, { data: { minutes: 15 } }),
      policy(EnterprisePolicyType.MaximumVaultTimeout, {
        id: 'second', organizationId: 'org-b', data: { minutes: 'bad' },
      }),
    ]);

    expect(snapshot.maximumVaultTimeoutPolicy?.data.minutes).toBe(15);
    expect(snapshot.malformedPolicyTypes).not.toContain(EnterprisePolicyType.MaximumVaultTimeout);
  });
});

describe('restricted item types', () => {
  it('defaults an enabled data-less policy to Card', () => {
    const snapshot = derive([policy(EnterprisePolicyType.RestrictedItemTypes)]);

    expect(snapshot.restrictedItemTypes).toEqual([3]);
    expect(isEnterpriseItemRestricted(snapshot, { type: 3 })).toBe(true);
    expect(isEnterpriseItemRestricted(snapshot, { type: 1 })).toBe(false);
  });

  it('unions personal restrictions but evaluates organization items against their own organization', () => {
    const snapshot = deriveEffectiveEnterprisePolicy({
      response: sync({
        profile: {
          id: 'user-id',
          email: ACCOUNT.accountIdentity,
          organizationsNew: [organization(), organization({ id: 'org-b' })],
        },
        policiesNew: [
          policy(EnterprisePolicyType.RestrictedItemTypes, { data: [2, 3] }),
          policy(EnterprisePolicyType.RestrictedItemTypes, {
            id: 'policy-b', organizationId: 'org-b', data: [4, 3],
          }),
        ],
      }),
      accountLease: ACCOUNT,
      rawGeneration: 'raw',
    });

    expect(snapshot.restrictedItemTypes).toEqual([2, 3, 4]);
    expect(isEnterpriseItemRestricted(snapshot, { type: 4 })).toBe(true);
    expect(isEnterpriseItemRestricted(snapshot, { type: 4, organizationId: 'org-a' })).toBe(false);
    expect(isEnterpriseItemRestricted(snapshot, { type: 4, organizationId: 'org-b' })).toBe(true);
    expect(isEnterpriseItemRestricted(snapshot, { type: 3, organizationId: 'org-a' })).toBe(true);
    expect(isEnterpriseItemRestricted(snapshot, { type: 3, organizationId: 'org-c' })).toBe(true);
  });

  it('allows a known organization without a policy while denying an unknown organization', () => {
    const snapshot = deriveEffectiveEnterprisePolicy({
      response: sync({
        profile: {
          id: 'user-id',
          email: ACCOUNT.accountIdentity,
          organizationsNew: [organization(), organization({ id: 'org-b' })],
        },
        policiesNew: [policy(EnterprisePolicyType.RestrictedItemTypes, { data: [3] })],
      }),
      accountLease: ACCOUNT,
      rawGeneration: 'raw',
    });

    expect(isEnterpriseItemRestricted(snapshot, { type: 3, organizationId: 'org-b' })).toBe(false);
    expect(isEnterpriseItemRestricted(snapshot, { type: 3, organizationId: 'unknown-org' })).toBe(true);
  });

  it.each([
    ['object data', { restrictedItemTypes: [3] }],
    ['string element', [3, '4']],
    ['zero cipher type', [0]],
  ])('restricts every item type when %s is malformed', (_label, data) => {
    const snapshot = derive([policy(EnterprisePolicyType.RestrictedItemTypes, { data })]);

    expect(isEnterpriseItemRestricted(snapshot, { type: 1 })).toBe(true);
    expect(isEnterpriseItemRestricted(snapshot, { type: 999 })).toBe(true);
    expect(snapshot.malformedPolicyTypes).toContain(EnterprisePolicyType.RestrictedItemTypes);
  });

  it('rejects a malformed cipher subject even without a policy', () => {
    const snapshot = derive([]);
    expect(isEnterpriseItemRestricted(snapshot, { type: 0 })).toBe(true);
    expect(isEnterpriseItemRestricted(snapshot, { type: Number.NaN })).toBe(true);
  });
});

describe('Send controls', () => {
  it('combines current and legacy controls using official field semantics', () => {
    const snapshot = derive([
      policy(EnterprisePolicyType.SendControls, {
        id: 'send-a',
        data: {
          disableSend: false,
          disableHideEmail: true,
          whoCanAccess: 2,
          allowedDomains: ' Example.com, Sub.Example.com ',
          deletionHours: 72,
          allowedSendTypes: [0],
        },
      }),
      policy(EnterprisePolicyType.SendControls, {
        id: 'send-b',
        organizationId: 'org-b',
        data: { whoCanAccess: 1, deletionHours: 24, allowedSendTypes: [1] },
      }),
    ]);

    expect(snapshot.sendControls).toEqual({
      disabled: false,
      disableHideEmail: true,
      whoCanAccess: 2,
      allowedDomains: ['example.com', 'sub.example.com'],
      deletionHours: 72,
      allowedSendTypes: [0, 1],
      malformed: false,
    });
    expect(enterprisePolicyAllowsSend(snapshot, { type: 0, hideEmail: false })).toBe(true);
    expect(enterprisePolicyAllowsSend(snapshot, { type: 0, hideEmail: true })).toBe(false);
  });

  it('defaults a data-less SendControls policy to permissive Send defaults', () => {
    const snapshot = derive([policy(EnterprisePolicyType.SendControls)]);

    expect(snapshot.sendControls).toMatchObject({
      disabled: false,
      disableHideEmail: false,
      whoCanAccess: 0,
      allowedDomains: null,
      deletionHours: null,
      allowedSendTypes: [0, 1],
      malformed: false,
    });
  });

  it('combines legacy DisableSend with SendControls', () => {
    const snapshot = derive([
      policy(EnterprisePolicyType.DisableSend),
      policy(EnterprisePolicyType.SendControls, { data: { disableSend: false } }),
    ]);
    expect(snapshot.sendControls.disabled).toBe(true);
    expect(enterprisePolicyAllowsSend(snapshot, { type: 0 })).toBe(false);
  });

  it('combines legacy SendOptions disableHideEmail without disabling Send creation', () => {
    const snapshot = derive([
      policy(EnterprisePolicyType.SendOptions, { data: { disableHideEmail: true } }),
    ]);

    expect(snapshot.sendControls).toMatchObject({
      disabled: false,
      disableHideEmail: true,
      malformed: false,
    });
    expect(enterprisePolicyAllowsSend(snapshot, { type: 0 })).toBe(true);
    expect(enterprisePolicyAllowsSend(snapshot, { type: 0, hideEmail: true })).toBe(false);
  });

  it('fails closed only for hidden email when legacy SendOptions data is malformed', () => {
    const snapshot = derive([
      policy(EnterprisePolicyType.SendOptions, { data: { disableHideEmail: 'yes' } }),
    ]);

    expect(snapshot.sendControls).toMatchObject({
      disabled: false,
      disableHideEmail: true,
      malformed: true,
    });
    expect(snapshot.malformedPolicyTypes).toContain(EnterprisePolicyType.SendOptions);
  });

  it.each([
    ['non-object payload', 'bad'],
    ['invalid disableSend', { disableSend: 1 }],
    ['invalid access mode', { whoCanAccess: 3 }],
    ['invalid domain type', { allowedDomains: ['example.com'] }],
    ['invalid deletion duration', { deletionHours: 0 }],
    ['empty send types', { allowedSendTypes: [] }],
    ['unknown send type', { allowedSendTypes: [2] }],
  ])('fails closed for %s', (_label, data) => {
    const snapshot = derive([policy(EnterprisePolicyType.SendControls, { data })]);

    expect(snapshot.sendControls).toMatchObject({
      disabled: true,
      disableHideEmail: true,
      allowedSendTypes: [],
      malformed: true,
    });
    expect(snapshot.malformedPolicyTypes).toContain(EnterprisePolicyType.SendControls);
    expect(enterprisePolicyAllowsSend(snapshot, { type: 0 })).toBe(false);
  });

  it('rejects invalid Send subjects', () => {
    const snapshot = derive([]);
    expect(enterprisePolicyAllowsSend(snapshot, { type: 2 })).toBe(false);
  });
});

describe('EnterprisePolicyGate', () => {
  function input(rawGeneration = 'raw-a'): DeriveEnterprisePolicyInput {
    return {
      response: sync({ policiesNew: [policy(EnterprisePolicyType.DisablePersonalVaultExport)] }),
      accountLease: ACCOUNT,
      rawGeneration,
    };
  }

  it('binds leases to the account and raw generation', () => {
    const gate = new EnterprisePolicyGate();
    gate.replace(input());
    const lease = gate.capture();

    expect(lease).toMatchObject({ ...ACCOUNT, rawGeneration: 'raw-a', generation: 1 });
    expect(gate.isCurrent(lease)).toBe(true);
    expect(gate.allows(lease, 'exportPersonalVault')).toBe(false);
    expect(Object.isFrozen(lease)).toBe(true);
    expect(Object.isFrozen(gate.inspect(lease))).toBe(true);
  });

  it('revokes old leases on raw replacement and explicit invalidation', () => {
    const gate = new EnterprisePolicyGate();
    gate.replace(input('raw-a'));
    const first = gate.capture();
    gate.replace(input('raw-b'));
    const second = gate.capture();

    expect(gate.isCurrent(first)).toBe(false);
    expect(() => gate.assert(first)).toThrow(AppError);
    expect(gate.isCurrent(second)).toBe(true);
    gate.invalidate();
    expect(gate.isCurrent(second)).toBe(false);
    expect(() => gate.capture()).toThrowError(/unavailable/i);
  });

  it('rejects forged and cross-gate leases', () => {
    const first = new EnterprisePolicyGate();
    const second = new EnterprisePolicyGate();
    first.replace(input());
    second.replace(input());
    const lease = first.capture();

    expect(() => second.assert(lease)).toThrowError(/changed/i);
    expect(() => first.assert({ ...lease })).toThrowError(/changed/i);
  });

  it('revokes the old snapshot before a replacement derivation failure', () => {
    const gate = new EnterprisePolicyGate();
    gate.replace(input());
    const lease = gate.capture();
    const invalidAccount = { ...ACCOUNT, accountIdentity: '' } as AccountLease;

    expect(() => gate.replace({ ...input('raw-b'), accountLease: invalidAccount })).toThrow(RangeError);
    expect(gate.isCurrent(lease)).toBe(false);
    expect(() => gate.capture()).toThrowError(/unavailable/i);
  });

  it('provides lease-checked item, Send, and assert gates', () => {
    const gate = new EnterprisePolicyGate();
    gate.replace({
      response: sync({ policiesNew: [
        policy(EnterprisePolicyType.RestrictedItemTypes, { data: [3] }),
        policy(EnterprisePolicyType.PasswordGenerator, { data: { minLength: 20 } }),
        policy(EnterprisePolicyType.ActivateAutofill),
        policy(EnterprisePolicyType.UriMatchDefaults, { data: { uriMatchDetection: 3 } }),
        policy(EnterprisePolicyType.SendControls, { data: { allowedSendTypes: [0] } }),
        policy(EnterprisePolicyType.DisablePersonalVaultExport),
        policy(EnterprisePolicyType.OrganizationDataOwnership, {
          data: { enableIndividualItemsTransfer: true },
          revisionDate: '2026-08-30T10:20:30.000Z',
        }),
      ] }),
      accountLease: ACCOUNT,
      rawGeneration: 'raw',
    });
    const lease = gate.capture();

    expect(gate.isItemRestricted(lease, { type: 3 })).toBe(true);
    expect(gate.allowsSend(lease, { type: 0 })).toBe(true);
    expect(gate.allowsSend(lease, { type: 1 })).toBe(false);
    expect(gate.getRestrictedItemTypes(lease)).toEqual([3]);
    expect(gate.getSendControls(lease).allowedSendTypes).toEqual([0]);
    expect(gate.getMaximumVaultTimeoutPolicy(lease)).toBeNull();
    expect(gate.getPasswordGeneratorPolicy(lease)?.data.minLength).toBe(20);
    expect(gate.getActivateAutofillRequired(lease)).toBe(true);
    expect(gate.getRequireSso(lease)).toBe(false);
    expect(gate.getUriMatchDefaultsPolicy(lease)?.value).toBe(3);
    expect(gate.getOrganizationDataOwnershipTransferPolicy(lease)).toEqual({
      organizationId: 'org-a',
      revisionDate: '2026-08-30T10:20:30.000Z',
    });
    expect(() => gate.assertAllowed(lease, 'exportPersonalVault')).toThrowError(/denies/i);
  });
});
