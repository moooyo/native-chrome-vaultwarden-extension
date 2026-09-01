export type PasswordGeneratorTypeOverride = '' | 'password' | 'passphrase';

export interface PasswordGeneratorPolicyData {
  readonly overridePasswordType: PasswordGeneratorTypeOverride;
  readonly minLength: number;
  readonly useUpper: boolean;
  readonly useLower: boolean;
  readonly useNumbers: boolean;
  readonly minNumbers: number;
  readonly useSpecial: boolean;
  readonly minSpecial: number;
  readonly minNumberWords: number;
  readonly capitalize: boolean;
  readonly includeNumber: boolean;
}

export const EMPTY_PASSWORD_GENERATOR_POLICY = Object.freeze<PasswordGeneratorPolicyData>({
  overridePasswordType: '',
  minLength: 0,
  useUpper: false,
  useLower: false,
  useNumbers: false,
  minNumbers: 0,
  useSpecial: false,
  minSpecial: 0,
  minNumberWords: 0,
  capitalize: false,
  includeNumber: false,
});

const NUMBER_FIELDS = Object.freeze([
  'minLength',
  'minNumbers',
  'minSpecial',
  'minNumberWords',
] as const);

const BOOLEAN_FIELDS = Object.freeze([
  'useUpper',
  'useLower',
  'useNumbers',
  'useSpecial',
  'capitalize',
  'includeNumber',
] as const);

/** Parse one raw type-2 policy without coercing forged values. Nullish fields are neutral. */
export function parsePasswordGeneratorPolicyData(data: unknown): PasswordGeneratorPolicyData | null {
  if (!isRecord(data)) return null;
  const parsed = { ...EMPTY_PASSWORD_GENERATOR_POLICY };

  const override = data.overridePasswordType;
  if (override !== null && override !== undefined) {
    if (override !== '' && override !== 'password' && override !== 'passphrase') return null;
    parsed.overridePasswordType = override;
  }

  for (const field of NUMBER_FIELDS) {
    const value = data[field];
    if (value === null || value === undefined) continue;
    if (!Number.isSafeInteger(value) || (value as number) < 0) return null;
    parsed[field] = value as number;
  }

  for (const field of BOOLEAN_FIELDS) {
    const value = data[field];
    if (value === null || value === undefined) continue;
    if (typeof value !== 'boolean') return null;
    parsed[field] = value;
  }

  return Object.freeze(parsed);
}

/** Reduce applicable type-2 policies using Bitwarden's least-privilege rules. */
export function combinePasswordGeneratorPolicyData(
  policies: readonly PasswordGeneratorPolicyData[],
): PasswordGeneratorPolicyData {
  let overridePasswordType: PasswordGeneratorTypeOverride = '';
  let minLength = 0;
  let useUpper = false;
  let useLower = false;
  let useNumbers = false;
  let minNumbers = 0;
  let useSpecial = false;
  let minSpecial = 0;
  let minNumberWords = 0;
  let capitalize = false;
  let includeNumber = false;

  for (const policy of policies) {
    if (policy.overridePasswordType === 'password') {
      overridePasswordType = 'password';
    } else if (policy.overridePasswordType === 'passphrase' && overridePasswordType === '') {
      overridePasswordType = 'passphrase';
    }
    minLength = Math.max(minLength, policy.minLength);
    useUpper ||= policy.useUpper;
    useLower ||= policy.useLower;
    useNumbers ||= policy.useNumbers;
    minNumbers = Math.max(minNumbers, policy.minNumbers);
    useSpecial ||= policy.useSpecial;
    minSpecial = Math.max(minSpecial, policy.minSpecial);
    minNumberWords = Math.max(minNumberWords, policy.minNumberWords);
    capitalize ||= policy.capitalize;
    includeNumber ||= policy.includeNumber;
  }

  return Object.freeze({
    overridePasswordType,
    minLength,
    useUpper,
    useLower,
    useNumbers,
    minNumbers,
    useSpecial,
    minSpecial,
    minNumberWords,
    capitalize,
    includeNumber,
  });
}

export function passwordGeneratorPolicyInEffect(policy: PasswordGeneratorPolicyData): boolean {
  return policy.overridePasswordType !== ''
    || policy.minLength > 0
    || policy.useUpper
    || policy.useLower
    || policy.useNumbers
    || policy.minNumbers > 0
    || policy.useSpecial
    || policy.minSpecial > 0
    || policy.minNumberWords > 0
    || policy.capitalize
    || policy.includeNumber;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
