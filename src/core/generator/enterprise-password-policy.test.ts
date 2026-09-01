import { describe, expect, it } from 'vitest';
import type { EffectivePasswordGeneratorPolicy } from '../policy/effective-enterprise-policy.js';
import {
  EMPTY_PASSWORD_GENERATOR_POLICY,
  type PasswordGeneratorPolicyData,
} from '../policy/password-generator-policy.js';
import { DEFAULT_PASSPHRASE_OPTIONS } from './passphrase.js';
import { DEFAULT_PASSWORD_OPTIONS, MAX_PASSWORD_LENGTH } from './password.js';
import {
  applyGeneratorPolicySnapshot,
  applyPasswordGeneratorPolicy,
  createGeneratorPolicySnapshot,
  parseGeneratorPolicySnapshot,
  sanitizePasswordGeneratorOptions,
  UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
  type PasswordGeneratorOptions,
} from './enterprise-password-policy.js';

const OPTIONS: PasswordGeneratorOptions = {
  mode: 'password',
  password: { ...DEFAULT_PASSWORD_OPTIONS },
  passphrase: { ...DEFAULT_PASSPHRASE_OPTIONS },
};

function policy(
  data: Partial<PasswordGeneratorPolicyData>,
  malformed = false,
): EffectivePasswordGeneratorPolicy {
  return {
    malformed,
    data: { ...EMPTY_PASSWORD_GENERATOR_POLICY, ...data },
  };
}

describe('sanitizePasswordGeneratorOptions', () => {
  it('canonicalizes lengths, separators, and user minimum cascades', () => {
    const result = sanitizePasswordGeneratorOptions({
      mode: 'password',
      password: {
        ...DEFAULT_PASSWORD_OPTIONS,
        length: MAX_PASSWORD_LENGTH + 50,
        numbers: false,
        minNumbers: 3.9,
        special: true,
        minSpecial: 0,
      },
      passphrase: {
        ...DEFAULT_PASSPHRASE_OPTIONS,
        numWords: 2.8,
        separator: '::',
      },
    });

    expect(result).toEqual({
      mode: 'password',
      password: {
        ...DEFAULT_PASSWORD_OPTIONS,
        length: MAX_PASSWORD_LENGTH,
        numbers: true,
        minNumbers: 3,
        special: true,
        minSpecial: 1,
      },
      passphrase: {
        ...DEFAULT_PASSPHRASE_OPTIONS,
        numWords: 3,
        separator: ':',
      },
    });
  });

  it.each([
    ['invalid mode', { ...OPTIONS, mode: 'pin' }],
    ['missing branch', { mode: 'password', password: OPTIONS.password }],
    ['non-finite length', { ...OPTIONS, password: { ...OPTIONS.password, length: Number.NaN } }],
    ['forged boolean', { ...OPTIONS, password: { ...OPTIONS.password, uppercase: 1 } }],
  ])('rejects %s', (_label, input) => {
    expect(sanitizePasswordGeneratorOptions(input)).toBeNull();
  });
});

describe('applyPasswordGeneratorPolicy', () => {
  it('returns sanitized options without a managed policy', () => {
    const result = applyPasswordGeneratorPolicy(OPTIONS, null);

    expect(result).toMatchObject({ allowed: true, managed: false, policyInEffect: false });
    expect(result.options?.mode).toBe('password');
  });

  it('rejects an empty password alphabet when no policy can make it valid', () => {
    const result = applyPasswordGeneratorPolicy({
      ...OPTIONS,
      password: {
        ...OPTIONS.password,
        lowercase: false,
        uppercase: false,
        numbers: false,
        special: false,
        minNumbers: 0,
        minSpecial: 0,
      },
    }, null);

    expect(result).toMatchObject({ allowed: false, managed: false, reason: 'invalid-options' });
  });

  it('applies policy before consistency checks so a required class can repair an empty alphabet', () => {
    const result = applyPasswordGeneratorPolicy({
      ...OPTIONS,
      password: {
        ...OPTIONS.password,
        lowercase: false,
        uppercase: false,
        numbers: false,
        special: false,
        minNumbers: 0,
        minSpecial: 0,
      },
    }, policy({ useUpper: true }));

    expect(result).toMatchObject({ allowed: true, managed: true });
    expect(result.options?.password).toMatchObject({ uppercase: true, length: 14 });
  });

  it('cascades numeric requirements to classes and expands length to every required character', () => {
    const result = applyPasswordGeneratorPolicy({
      ...OPTIONS,
      password: {
        ...OPTIONS.password,
        length: 5,
        uppercase: false,
        numbers: false,
        minNumbers: 0,
        special: false,
        minSpecial: 0,
      },
    }, policy({
      useUpper: true,
      minNumbers: 3,
      minSpecial: 4,
    }));

    expect(result).toMatchObject({ allowed: true, managed: true, policyInEffect: true });
    expect(result.options?.password).toMatchObject({
      length: 9,
      lowercase: true,
      uppercase: true,
      numbers: true,
      minNumbers: 3,
      special: true,
      minSpecial: 4,
    });
  });

  it('turns useNumbers and useSpecial into minimums of one', () => {
    const result = applyPasswordGeneratorPolicy({
      ...OPTIONS,
      password: {
        ...OPTIONS.password,
        numbers: false,
        special: false,
        minNumbers: 0,
        minSpecial: 0,
      },
    }, policy({ useNumbers: true, useSpecial: true }));

    expect(result.options?.password).toMatchObject({
      numbers: true,
      minNumbers: 1,
      special: true,
      minSpecial: 1,
    });
  });

  it('applies passphrase-only requirements without applying password length', () => {
    const result = applyPasswordGeneratorPolicy({ ...OPTIONS, mode: 'passphrase' }, policy({
      minLength: 100,
      minNumberWords: 8,
      capitalize: true,
      includeNumber: true,
    }));

    expect(result).toMatchObject({ allowed: true, managed: true, policyInEffect: true });
    expect(result.options?.mode).toBe('passphrase');
    expect(result.options?.passphrase).toMatchObject({
      numWords: 8,
      capitalize: true,
      includeNumber: true,
    });
  });

  it.each([
    ['password', 'passphrase'],
    ['passphrase', 'password'],
  ] as const)('forces a %s override over a requested %s mode', (forced, requested) => {
    const result = applyPasswordGeneratorPolicy({ ...OPTIONS, mode: requested }, policy({
      overridePasswordType: forced,
    }));

    expect(result.options?.mode).toBe(forced);
  });

  it('keeps a neutral enabled policy managed without claiming active constraints', () => {
    expect(applyPasswordGeneratorPolicy(OPTIONS, policy({}))).toMatchObject({
      allowed: true,
      managed: true,
      policyInEffect: false,
    });
  });

  it('fails a malformed enabled policy closed', () => {
    expect(applyPasswordGeneratorPolicy(OPTIONS, policy({}, true))).toEqual({
      allowed: false,
      managed: true,
      policyInEffect: true,
      reason: 'malformed-policy',
      options: null,
    });
  });

  it('rejects a forged effective policy even when the malformed marker is false', () => {
    const forged = policy({}) as unknown as {
      malformed: false;
      data: Record<string, unknown>;
    };
    forged.data.useUpper = 'true';

    expect(applyPasswordGeneratorPolicy(OPTIONS, forged as unknown as EffectivePasswordGeneratorPolicy))
      .toMatchObject({ allowed: false, reason: 'malformed-policy' });
  });

  it.each([
    ['password length', policy({ overridePasswordType: 'password', minLength: MAX_PASSWORD_LENGTH + 1 })],
    ['password minimum sum', policy({ overridePasswordType: 'password', minNumbers: MAX_PASSWORD_LENGTH })],
    ['passphrase words', policy({ overridePasswordType: 'passphrase', minNumberWords: 21 })],
  ])('disables generation for an unsatisfiable %s policy', (_label, constraint) => {
    expect(applyPasswordGeneratorPolicy(OPTIONS, constraint)).toMatchObject({
      allowed: false,
      managed: true,
      reason: 'unsatisfiable-policy',
      options: null,
    });
  });
});

describe('generator policy snapshots', () => {
  it('projects only bounded effective constraints and preserves the lease revision', () => {
    const snapshot = createGeneratorPolicySnapshot(policy({
      overridePasswordType: 'password',
      minLength: MAX_PASSWORD_LENGTH + 10_000,
      minNumbers: MAX_PASSWORD_LENGTH + 20_000,
      useSpecial: true,
      minNumberWords: 10_000,
      capitalize: true,
    }), 42);

    expect(snapshot).toEqual({
      revision: 42,
      managed: true,
      malformed: false,
      policyInEffect: true,
      forcedMode: 'password',
      password: {
        allowed: false,
        minLength: MAX_PASSWORD_LENGTH,
        uppercase: false,
        lowercase: false,
        numbers: true,
        minNumbers: MAX_PASSWORD_LENGTH,
        special: true,
        minSpecial: 1,
      },
      passphrase: {
        allowed: false,
        minWords: 20,
        capitalize: true,
        includeNumber: false,
      },
    });
    expect(Object.keys(snapshot)).toEqual([
      'revision', 'managed', 'malformed', 'policyInEffect', 'forcedMode', 'password', 'passphrase',
    ]);
    expect(JSON.stringify(snapshot)).not.toContain('overridePasswordType');
  });

  it('keeps an enabled but empty policy neutral and parseable', () => {
    const snapshot = createGeneratorPolicySnapshot(policy({}), 7);

    expect(snapshot).toMatchObject({
      revision: 7,
      managed: true,
      malformed: false,
      policyInEffect: false,
      forcedMode: null,
      password: { allowed: true },
      passphrase: { allowed: true },
    });
    expect(parseGeneratorPolicySnapshot(snapshot)).toEqual(snapshot);
    expect(applyGeneratorPolicySnapshot(OPTIONS, snapshot)).toMatchObject({
      allowed: true,
      managed: true,
      policyInEffect: false,
    });
  });

  it('projects malformed policy and invalid revisions to the fail-closed capability', () => {
    expect(createGeneratorPolicySnapshot(policy({}, true), 9)).toEqual({
      ...UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
      revision: 9,
    });
    expect(createGeneratorPolicySnapshot(null, -1)).toBe(UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT);
  });

  it.each([
    ['extra top-level field', { ...createGeneratorPolicySnapshot(null, 1), organizationId: 'org' }],
    ['extra nested field', {
      ...createGeneratorPolicySnapshot(null, 1),
      password: { ...createGeneratorPolicySnapshot(null, 1).password, rawPolicy: true },
    }],
    ['oversized password minimum', {
      ...createGeneratorPolicySnapshot(null, 1),
      password: { ...createGeneratorPolicySnapshot(null, 1).password, minNumbers: MAX_PASSWORD_LENGTH + 1 },
    }],
    ['oversized passphrase minimum', {
      ...createGeneratorPolicySnapshot(null, 1),
      passphrase: { ...createGeneratorPolicySnapshot(null, 1).passphrase, minWords: 21 },
    }],
    ['unsafe revision', { ...createGeneratorPolicySnapshot(null, 1), revision: Number.MAX_SAFE_INTEGER + 1 }],
    ['contradictory policy-in-effect marker', {
      ...createGeneratorPolicySnapshot(null, 1),
      managed: true,
      forcedMode: 'password',
    }],
    ['hidden numeric constraint', {
      ...createGeneratorPolicySnapshot(null, 1),
      managed: true,
      policyInEffect: true,
      password: { ...createGeneratorPolicySnapshot(null, 1).password, minNumbers: 2 },
    }],
    ['non-canonical malformed capability', {
      ...UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
      password: { ...UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT.password, allowed: true },
    }],
  ])('rejects a non-canonical snapshot with %s', (_label, snapshot) => {
    expect(parseGeneratorPolicySnapshot(snapshot)).toBeNull();
  });
});
