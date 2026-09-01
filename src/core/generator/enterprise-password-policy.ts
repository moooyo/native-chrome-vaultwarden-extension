import type { EffectivePasswordGeneratorPolicy } from '../policy/effective-enterprise-policy.js';
import {
  EMPTY_PASSWORD_GENERATOR_POLICY,
  parsePasswordGeneratorPolicyData,
  passwordGeneratorPolicyInEffect,
  type PasswordGeneratorPolicyData,
} from '../policy/password-generator-policy.js';
import {
  MAX_PASSWORD_LENGTH,
  type PasswordGenOptions,
} from './password.js';
import type { PassphraseGenOptions } from './passphrase.js';

export type PasswordGeneratorMode = 'password' | 'passphrase';

/** Complete generator state shared by popup and content-script generation surfaces. */
export interface PasswordGeneratorOptions {
  readonly mode: PasswordGeneratorMode;
  readonly password: Readonly<PasswordGenOptions>;
  readonly passphrase: Readonly<PassphraseGenOptions>;
}

export type PasswordGeneratorPolicyFailure =
  | 'invalid-options'
  | 'malformed-policy'
  | 'unsatisfiable-policy';

export type PasswordGeneratorPolicyEvaluation =
  | {
      readonly allowed: true;
      readonly managed: boolean;
      readonly policyInEffect: boolean;
      readonly reason: null;
      readonly options: PasswordGeneratorOptions;
    }
  | {
      readonly allowed: false;
      readonly managed: boolean;
      readonly policyInEffect: boolean;
      readonly reason: PasswordGeneratorPolicyFailure;
      readonly options: null;
    };

export interface GeneratorPolicySnapshot {
  readonly revision: number;
  readonly managed: boolean;
  readonly malformed: boolean;
  readonly policyInEffect: boolean;
  readonly forcedMode: PasswordGeneratorMode | null;
  readonly password: {
    readonly allowed: boolean;
    readonly minLength: number;
    readonly uppercase: boolean;
    readonly lowercase: boolean;
    readonly numbers: boolean;
    readonly minNumbers: number;
    readonly special: boolean;
    readonly minSpecial: number;
  };
  readonly passphrase: {
    readonly allowed: boolean;
    readonly minWords: number;
    readonly capitalize: boolean;
    readonly includeNumber: boolean;
  };
}

const MIN_PASSWORD_LENGTH = 1;
const MIN_PASSPHRASE_WORDS = 3;
const MAX_PASSPHRASE_WORDS = 20;

const EMPTY_PASSWORD_CONSTRAINTS = Object.freeze({
  allowed: true,
  minLength: 0,
  uppercase: false,
  lowercase: false,
  numbers: false,
  minNumbers: 0,
  special: false,
  minSpecial: 0,
});
const EMPTY_PASSPHRASE_CONSTRAINTS = Object.freeze({
  allowed: true,
  minWords: 0,
  capitalize: false,
  includeNumber: false,
});

export const UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT: GeneratorPolicySnapshot = Object.freeze({
  revision: 0,
  managed: true,
  malformed: true,
  policyInEffect: true,
  forcedMode: null,
  password: Object.freeze({ ...EMPTY_PASSWORD_CONSTRAINTS, allowed: false }),
  passphrase: Object.freeze({ ...EMPTY_PASSPHRASE_CONSTRAINTS, allowed: false }),
});

/** Canonicalize a generator request without mutating caller-owned preferences. */
export function sanitizePasswordGeneratorOptions(input: unknown): PasswordGeneratorOptions | null {
  if (!isRecord(input) || (input.mode !== 'password' && input.mode !== 'passphrase')) return null;
  const password = sanitizePasswordOptions(input.password);
  const passphrase = sanitizePassphraseOptions(input.passphrase);
  if (password === null || passphrase === null) return null;
  return Object.freeze({ mode: input.mode, password, passphrase });
}

/** Project raw effective policy into a bounded, non-secret UI capability snapshot. */
export function createGeneratorPolicySnapshot(
  policy: EffectivePasswordGeneratorPolicy | null,
  revision: number,
): GeneratorPolicySnapshot {
  if (!Number.isSafeInteger(revision) || revision < 0) return UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT;
  if (policy === null) {
    return Object.freeze({
      revision,
      managed: false,
      malformed: false,
      policyInEffect: false,
      forcedMode: null,
      password: EMPTY_PASSWORD_CONSTRAINTS,
      passphrase: EMPTY_PASSPHRASE_CONSTRAINTS,
    });
  }
  if (!isRecord(policy) || typeof policy.malformed !== 'boolean' || policy.malformed) {
    return unavailableSnapshot(revision);
  }
  const data = parsePasswordGeneratorPolicyData(policy.data);
  if (data === null) return unavailableSnapshot(revision);

  const numbers = data.useNumbers || data.minNumbers > 0;
  const special = data.useSpecial || data.minSpecial > 0;
  const minNumbers = numbers ? Math.max(data.minNumbers, 1) : 0;
  const minSpecial = special ? Math.max(data.minSpecial, 1) : 0;
  const requiredLength = requiredPasswordLength({
    lowercase: data.useLower,
    uppercase: data.useUpper,
    numbers,
    minNumbers,
    special,
    minSpecial,
  });
  const passwordAllowed = Math.max(data.minLength, requiredLength) <= MAX_PASSWORD_LENGTH;
  const passphraseAllowed = data.minNumberWords <= MAX_PASSPHRASE_WORDS;
  const forcedMode = data.overridePasswordType || null;
  const password = Object.freeze({
    allowed: passwordAllowed && forcedMode !== 'passphrase',
    minLength: clampInteger(Math.max(data.minLength, requiredLength), 0, MAX_PASSWORD_LENGTH),
    uppercase: data.useUpper,
    lowercase: data.useLower,
    numbers,
    minNumbers: clampInteger(minNumbers, 0, MAX_PASSWORD_LENGTH),
    special,
    minSpecial: clampInteger(minSpecial, 0, MAX_PASSWORD_LENGTH),
  });
  const passphrase = Object.freeze({
    allowed: passphraseAllowed && forcedMode !== 'password',
    minWords: clampInteger(data.minNumberWords, 0, MAX_PASSPHRASE_WORDS),
    capitalize: data.capitalize,
    includeNumber: data.includeNumber,
  });
  return Object.freeze({
    revision,
    managed: true,
    malformed: false,
    policyInEffect: passwordGeneratorPolicyInEffect(data),
    forcedMode,
    password,
    passphrase,
  });
}

/** Strictly parse an untrusted worker projection before a UI uses it to generate credentials. */
export function parseGeneratorPolicySnapshot(value: unknown): GeneratorPolicySnapshot | null {
  if (!isRecord(value) || !hasExactKeys(value, [
    'revision', 'managed', 'malformed', 'policyInEffect', 'forcedMode', 'password', 'passphrase',
  ])) return null;
  if (
    !isBoundedInteger(value.revision, 0, Number.MAX_SAFE_INTEGER)
    || typeof value.managed !== 'boolean'
    || typeof value.malformed !== 'boolean'
    || typeof value.policyInEffect !== 'boolean'
    || (value.forcedMode !== null && value.forcedMode !== 'password' && value.forcedMode !== 'passphrase')
    || !isPasswordConstraints(value.password)
    || !isPassphraseConstraints(value.passphrase)
  ) return null;
  const candidate = value as unknown as GeneratorPolicySnapshot;
  if (
    (candidate.malformed && !isCanonicalUnavailableSnapshot(candidate))
    || (!candidate.malformed && !isCanonicalAvailableSnapshot(candidate))
  ) return null;
  return Object.freeze({
    revision: candidate.revision,
    managed: candidate.managed,
    malformed: candidate.malformed,
    policyInEffect: candidate.policyInEffect,
    forcedMode: candidate.forcedMode,
    password: Object.freeze({ ...candidate.password }),
    passphrase: Object.freeze({ ...candidate.passphrase }),
  });
}

function isCanonicalUnavailableSnapshot(value: GeneratorPolicySnapshot): boolean {
  return value.managed
    && value.policyInEffect
    && value.forcedMode === null
    && !value.password.allowed
    && value.password.minLength === 0
    && !value.password.uppercase
    && !value.password.lowercase
    && !value.password.numbers
    && value.password.minNumbers === 0
    && !value.password.special
    && value.password.minSpecial === 0
    && !value.passphrase.allowed
    && value.passphrase.minWords === 0
    && !value.passphrase.capitalize
    && !value.passphrase.includeNumber;
}

function isCanonicalAvailableSnapshot(value: GeneratorPolicySnapshot): boolean {
  const requiredLength = requiredPasswordLength({
    lowercase: value.password.lowercase,
    uppercase: value.password.uppercase,
    numbers: value.password.numbers,
    minNumbers: value.password.minNumbers,
    special: value.password.special,
    minSpecial: value.password.minSpecial,
  });
  const policyInEffect = value.forcedMode !== null
    || value.password.minLength > 0
    || value.password.uppercase
    || value.password.lowercase
    || value.password.numbers
    || value.password.minNumbers > 0
    || value.password.special
    || value.password.minSpecial > 0
    || value.passphrase.minWords > 0
    || value.passphrase.capitalize
    || value.passphrase.includeNumber;
  if (
    value.policyInEffect !== policyInEffect
    || (!value.managed && policyInEffect)
    || value.password.numbers !== (value.password.minNumbers > 0)
    || value.password.special !== (value.password.minSpecial > 0)
    || value.password.minLength < requiredLength
    || (value.forcedMode === 'password' && value.passphrase.allowed)
    || (value.forcedMode === 'passphrase' && value.password.allowed)
  ) return false;
  if (!policyInEffect) {
    return value.forcedMode === null
      && value.password.allowed
      && value.passphrase.allowed;
  }
  if (value.password.allowed && requiredLength > MAX_PASSWORD_LENGTH) {
    return false;
  }
  return true;
}

/** Apply one already generation-bound effective type-2 policy to a generator request. */
export function applyPasswordGeneratorPolicy(
  input: unknown,
  policy: EffectivePasswordGeneratorPolicy | null,
): PasswordGeneratorPolicyEvaluation {
  return applyGeneratorPolicySnapshot(input, createGeneratorPolicySnapshot(policy, 0));
}

export function applyGeneratorPolicySnapshot(
  input: unknown,
  rawSnapshot: unknown,
): PasswordGeneratorPolicyEvaluation {
  const snapshot = parseGeneratorPolicySnapshot(rawSnapshot);
  if (snapshot === null || snapshot.malformed) return denied(true, true, 'malformed-policy');

  const options = sanitizePasswordGeneratorOptions(input);
  if (options === null) return denied(snapshot.managed, snapshot.policyInEffect, 'invalid-options');
  const mode = snapshot.forcedMode ?? options.mode;
  const parsedPolicy: PasswordGeneratorPolicyData = {
    ...EMPTY_PASSWORD_GENERATOR_POLICY,
    overridePasswordType: snapshot.forcedMode ?? '',
    minLength: snapshot.password.minLength,
    useUpper: snapshot.password.uppercase,
    useLower: snapshot.password.lowercase,
    useNumbers: snapshot.password.numbers,
    minNumbers: snapshot.password.minNumbers,
    useSpecial: snapshot.password.special,
    minSpecial: snapshot.password.minSpecial,
    minNumberWords: snapshot.passphrase.minWords,
    capitalize: snapshot.passphrase.capitalize,
    includeNumber: snapshot.passphrase.includeNumber,
  };

  if (mode === 'password') {
    if (!snapshot.password.allowed) {
      return denied(snapshot.managed, snapshot.policyInEffect, 'unsatisfiable-policy');
    }
    const password = applyPasswordPolicy(options.password, parsedPolicy);
    if (password === null) {
      return denied(
        snapshot.managed,
        snapshot.policyInEffect,
        snapshot.policyInEffect ? 'unsatisfiable-policy' : 'invalid-options',
      );
    }
    return allowed(
      Object.freeze({ ...options, mode, password }),
      snapshot.managed,
      snapshot.policyInEffect,
    );
  }

  if (!snapshot.passphrase.allowed) {
    return denied(snapshot.managed, snapshot.policyInEffect, 'unsatisfiable-policy');
  }
  const passphrase = applyPassphrasePolicy(options.passphrase, parsedPolicy);
  if (passphrase === null) {
    return denied(
      snapshot.managed,
      snapshot.policyInEffect,
      snapshot.policyInEffect ? 'unsatisfiable-policy' : 'invalid-options',
    );
  }
  return allowed(
    Object.freeze({ ...options, mode, passphrase }),
    snapshot.managed,
    snapshot.policyInEffect,
  );
}

function sanitizePasswordOptions(input: unknown): Readonly<PasswordGenOptions> | null {
  if (!isRecord(input)) return null;
  if (
    !isFiniteNumber(input.length)
    || !isFiniteNumber(input.minNumbers)
    || !isFiniteNumber(input.minSpecial)
    || typeof input.lowercase !== 'boolean'
    || typeof input.uppercase !== 'boolean'
    || typeof input.numbers !== 'boolean'
    || typeof input.special !== 'boolean'
    || typeof input.avoidAmbiguous !== 'boolean'
  ) return null;

  const minNumbers = clampInteger(input.minNumbers, 0, MAX_PASSWORD_LENGTH);
  const minSpecial = clampInteger(input.minSpecial, 0, MAX_PASSWORD_LENGTH);
  const numbers = input.numbers || minNumbers > 0;
  const special = input.special || minSpecial > 0;
  const normalizedMinNumbers = numbers ? Math.max(1, minNumbers) : 0;
  const normalizedMinSpecial = special ? Math.max(1, minSpecial) : 0;
  const requiredLength = requiredPasswordLength({
    lowercase: input.lowercase,
    uppercase: input.uppercase,
    numbers,
    minNumbers: normalizedMinNumbers,
    special,
    minSpecial: normalizedMinSpecial,
  });
  if (requiredLength > MAX_PASSWORD_LENGTH) return null;

  return Object.freeze({
    length: Math.max(
      clampInteger(input.length, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH),
      requiredLength,
    ),
    lowercase: input.lowercase,
    uppercase: input.uppercase,
    numbers,
    special,
    minNumbers: normalizedMinNumbers,
    minSpecial: normalizedMinSpecial,
    avoidAmbiguous: input.avoidAmbiguous,
  });
}

function sanitizePassphraseOptions(input: unknown): Readonly<PassphraseGenOptions> | null {
  if (
    !isRecord(input)
    || !isFiniteNumber(input.numWords)
    || typeof input.separator !== 'string'
    || typeof input.capitalize !== 'boolean'
    || typeof input.includeNumber !== 'boolean'
  ) return null;

  return Object.freeze({
    numWords: clampInteger(input.numWords, MIN_PASSPHRASE_WORDS, MAX_PASSPHRASE_WORDS),
    separator: input.separator === '' ? '' : (input.separator[0] ?? '-'),
    capitalize: input.capitalize,
    includeNumber: input.includeNumber,
  });
}

function applyPasswordPolicy(
  options: Readonly<PasswordGenOptions>,
  policy: PasswordGeneratorPolicyData,
): Readonly<PasswordGenOptions> | null {
  const lowercase = options.lowercase || policy.useLower;
  const uppercase = options.uppercase || policy.useUpper;
  const numbers = options.numbers || policy.useNumbers || policy.minNumbers > 0;
  const special = options.special || policy.useSpecial || policy.minSpecial > 0;
  const minNumbers = numbers
    ? Math.max(options.minNumbers, policy.minNumbers, policy.useNumbers ? 1 : 0, 1)
    : 0;
  const minSpecial = special
    ? Math.max(options.minSpecial, policy.minSpecial, policy.useSpecial ? 1 : 0, 1)
    : 0;
  const requiredLength = requiredPasswordLength({
    lowercase,
    uppercase,
    numbers,
    minNumbers,
    special,
    minSpecial,
  });
  const length = Math.max(options.length, policy.minLength, requiredLength);
  if (requiredLength === 0 || length > MAX_PASSWORD_LENGTH) return null;

  return Object.freeze({
    ...options,
    length,
    lowercase,
    uppercase,
    numbers,
    special,
    minNumbers,
    minSpecial,
  });
}

function applyPassphrasePolicy(
  options: Readonly<PassphraseGenOptions>,
  policy: PasswordGeneratorPolicyData,
): Readonly<PassphraseGenOptions> | null {
  const numWords = Math.max(options.numWords, policy.minNumberWords);
  if (numWords > MAX_PASSPHRASE_WORDS) return null;
  return Object.freeze({
    ...options,
    numWords,
    capitalize: options.capitalize || policy.capitalize,
    includeNumber: options.includeNumber || policy.includeNumber,
  });
}

function requiredPasswordLength(options: {
  readonly lowercase: boolean;
  readonly uppercase: boolean;
  readonly numbers: boolean;
  readonly minNumbers: number;
  readonly special: boolean;
  readonly minSpecial: number;
}): number {
  return (options.lowercase ? 1 : 0)
    + (options.uppercase ? 1 : 0)
    + (options.numbers ? Math.max(options.minNumbers, 1) : 0)
    + (options.special ? Math.max(options.minSpecial, 1) : 0);
}

function allowed(
  options: PasswordGeneratorOptions,
  managed: boolean,
  policyInEffect: boolean,
): PasswordGeneratorPolicyEvaluation {
  return Object.freeze({ allowed: true, managed, policyInEffect, reason: null, options });
}

function denied(
  managed: boolean,
  policyInEffect: boolean,
  reason: PasswordGeneratorPolicyFailure,
): PasswordGeneratorPolicyEvaluation {
  return Object.freeze({ allowed: false, managed, policyInEffect, reason, options: null });
}

function clampInteger(value: number, min: number, max: number): number {
  return Math.min(Math.max(Math.trunc(value), min), max);
}

function unavailableSnapshot(revision: number): GeneratorPolicySnapshot {
  return Object.freeze({
    ...UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
    revision,
  });
}

function isPasswordConstraints(value: unknown): value is GeneratorPolicySnapshot['password'] {
  if (!isRecord(value) || !hasExactKeys(value, [
    'allowed', 'minLength', 'uppercase', 'lowercase', 'numbers', 'minNumbers', 'special', 'minSpecial',
  ])) return false;
  return typeof value.allowed === 'boolean'
    && isBoundedInteger(value.minLength, 0, MAX_PASSWORD_LENGTH)
    && typeof value.uppercase === 'boolean'
    && typeof value.lowercase === 'boolean'
    && typeof value.numbers === 'boolean'
    && isBoundedInteger(value.minNumbers, 0, MAX_PASSWORD_LENGTH)
    && typeof value.special === 'boolean'
    && isBoundedInteger(value.minSpecial, 0, MAX_PASSWORD_LENGTH);
}

function isPassphraseConstraints(value: unknown): value is GeneratorPolicySnapshot['passphrase'] {
  if (!isRecord(value) || !hasExactKeys(value, [
    'allowed', 'minWords', 'capitalize', 'includeNumber',
  ])) return false;
  return typeof value.allowed === 'boolean'
    && isBoundedInteger(value.minWords, 0, MAX_PASSPHRASE_WORDS)
    && typeof value.capitalize === 'boolean'
    && typeof value.includeNumber === 'boolean';
}

function isBoundedInteger(value: unknown, min: number, max: number): value is number {
  return Number.isSafeInteger(value) && (value as number) >= min && (value as number) <= max;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
