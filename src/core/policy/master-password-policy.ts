import zxcvbn from 'zxcvbn';

export const DEFAULT_MASTER_PASSWORD_MIN_LENGTH = 12;
export const MASTER_PASSWORD_POLICY_MAX_LENGTH = 1_024;
export const MASTER_PASSWORD_STRENGTH_INPUT_MAX_LENGTH = 256;
export const MASTER_PASSWORD_HINT_MAX_LENGTH = 50;
export const PASSWORD_CHANGE_REQUIREMENT_SCHEMA_VERSION = 1 as const;
export const MASTER_PASSWORD_EVIDENCE_SCHEMA_VERSION = 1 as const;

export interface MasterPasswordPolicy {
  readonly minComplexity: number;
  readonly minLength: number;
  readonly requireUpper: boolean;
  readonly requireLower: boolean;
  readonly requireNumbers: boolean;
  readonly requireSpecial: boolean;
  readonly enforceOnLogin: boolean;
}

/** Secret-free facts sufficient to re-evaluate every supported master-password policy control. */
export interface MasterPasswordEvidence {
  readonly schemaVersion: typeof MASTER_PASSWORD_EVIDENCE_SCHEMA_VERSION;
  /** Saturated at the largest server policy length so the persisted value reveals no extra detail. */
  readonly length: number;
  readonly hasUpper: boolean;
  readonly hasLower: boolean;
  readonly hasNumbers: boolean;
  readonly hasSpecial: boolean;
  readonly zxcvbnScore: 0 | 1 | 2 | 3 | 4;
}

export type ForceSetPasswordReason = 'adminForcePasswordReset' | 'weakMasterPassword';

export interface PasswordChangeRequirement {
  readonly schemaVersion: typeof PASSWORD_CHANGE_REQUIREMENT_SCHEMA_VERSION;
  readonly reason: ForceSetPasswordReason;
  readonly policy?: MasterPasswordPolicy;
}

export type MasterPasswordHintValidationError = 'invalid' | 'tooLong' | 'matchesPassword';

/** Official clients compare the raw, case-sensitive values; whitespace is intentionally retained. */
export function masterPasswordHintValidationError(
  hint: unknown,
  newPassword?: string,
): MasterPasswordHintValidationError | undefined {
  if (typeof hint !== 'string') return 'invalid';
  if (hint.length > MASTER_PASSWORD_HINT_MAX_LENGTH) return 'tooLong';
  if (newPassword !== undefined && hint !== '' && hint === newPassword) return 'matchesPassword';
  return undefined;
}

export function requireMasterPasswordHint(hint: unknown, newPassword?: string): string {
  const error = masterPasswordHintValidationError(hint, newPassword);
  if (error === 'invalid') throw new TypeError('Master password hint must be a string');
  if (error === 'tooLong') {
    throw new TypeError(`Master password hint cannot exceed ${MASTER_PASSWORD_HINT_MAX_LENGTH} characters`);
  }
  if (error === 'matchesPassword') {
    throw new TypeError('Master password hint cannot be the same as the master password');
  }
  return hint as string;
}

/** Minimum for creating or replacing a master password. Existing-password verification is separate. */
export function newMasterPasswordMinimumLength(
  policy?: Pick<MasterPasswordPolicy, 'minLength'>,
): number {
  return Math.max(DEFAULT_MASTER_PASSWORD_MIN_LENGTH, policy?.minLength ?? 0);
}

export function isNewMasterPasswordLengthAllowed(
  password: unknown,
  policy?: Pick<MasterPasswordPolicy, 'minLength'>,
): password is string {
  return typeof password === 'string'
    && password.length >= newMasterPasswordMinimumLength(policy)
    && password.length <= MASTER_PASSWORD_POLICY_MAX_LENGTH;
}

const EMPTY_POLICY: MasterPasswordPolicy = Object.freeze({
  minComplexity: 0,
  minLength: 0,
  requireUpper: false,
  requireLower: false,
  requireNumbers: false,
  requireSpecial: false,
  enforceOnLogin: false,
});

/** Strictly parse the policy projection returned by Identity. Missing/null means no policy. */
export function parseMasterPasswordPolicy(input: unknown): MasterPasswordPolicy | undefined {
  if (input === undefined || input === null) return undefined;
  const record = requirePlainDataRecord(input, 'master password policy');
  const allowedFields = new Set([
    'object', 'Object',
    'minComplexity', 'MinComplexity',
    'minLength', 'MinLength',
    'requireUpper', 'RequireUpper',
    'requireLower', 'RequireLower',
    'requireNumbers', 'RequireNumbers',
    'requireSpecial', 'RequireSpecial',
    'enforceOnLogin', 'EnforceOnLogin',
  ]);
  if (Object.keys(record).some((field) => !allowedFields.has(field))) {
    throw new TypeError('master password policy contains unsupported fields');
  }
  const objectDiscriminator = readAliased(record, 'object', 'Object');
  if (objectDiscriminator !== undefined && objectDiscriminator !== 'masterPasswordPolicy') {
    throw new TypeError('master password policy has an invalid object discriminator');
  }
  return Object.freeze({
    minComplexity: readInteger(record, 'minComplexity', 'MinComplexity', 0, 4),
    minLength: readInteger(record, 'minLength', 'MinLength', 0, MASTER_PASSWORD_POLICY_MAX_LENGTH),
    requireUpper: readBoolean(record, 'requireUpper', 'RequireUpper'),
    requireLower: readBoolean(record, 'requireLower', 'RequireLower'),
    requireNumbers: readBoolean(record, 'requireNumbers', 'RequireNumbers'),
    requireSpecial: readBoolean(record, 'requireSpecial', 'RequireSpecial'),
    enforceOnLogin: readBoolean(record, 'enforceOnLogin', 'EnforceOnLogin'),
  });
}

/** Parse the per-account durable restriction. Invalid state must never be silently downgraded. */
export function parsePasswordChangeRequirement(input: unknown): PasswordChangeRequirement {
  const record = requirePlainDataRecord(input, 'password change requirement');
  const keys = Object.keys(record).sort();
  const hasPolicy = Object.hasOwn(record, 'policy');
  const expected = hasPolicy
    ? ['policy', 'reason', 'schemaVersion']
    : ['reason', 'schemaVersion'];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new TypeError('password change requirement contains unsupported fields');
  }
  if (record.schemaVersion !== PASSWORD_CHANGE_REQUIREMENT_SCHEMA_VERSION) {
    throw new TypeError('password change requirement has an unsupported schema version');
  }
  if (record.reason !== 'adminForcePasswordReset' && record.reason !== 'weakMasterPassword') {
    throw new TypeError('password change requirement has an invalid reason');
  }
  const policy = hasPolicy ? parseMasterPasswordPolicy(record.policy) : undefined;
  if (hasPolicy && !policy) throw new TypeError('password change requirement has no policy');
  if (record.reason === 'weakMasterPassword' && !policy) {
    throw new TypeError('weak password requirement must retain its policy');
  }
  return Object.freeze({
    schemaVersion: PASSWORD_CHANGE_REQUIREMENT_SCHEMA_VERSION,
    reason: record.reason,
    ...(policy ? { policy } : {}),
  });
}

export function passwordChangeRequirement(
  reason: ForceSetPasswordReason,
  policy?: MasterPasswordPolicy,
): PasswordChangeRequirement {
  return parsePasswordChangeRequirement({
    schemaVersion: PASSWORD_CHANGE_REQUIREMENT_SCHEMA_VERSION,
    reason,
    ...(policy ? { policy } : {}),
  });
}

/** Combine security controls monotonically across Identity grant stages. */
export function combineMasterPasswordPolicies(
  current: MasterPasswordPolicy | undefined,
  next: MasterPasswordPolicy | undefined,
): MasterPasswordPolicy | undefined {
  if (!current) return next;
  if (!next) return current;
  return Object.freeze({
    minComplexity: Math.max(current.minComplexity, next.minComplexity),
    minLength: Math.max(current.minLength, next.minLength),
    requireUpper: current.requireUpper || next.requireUpper,
    requireLower: current.requireLower || next.requireLower,
    requireNumbers: current.requireNumbers || next.requireNumbers,
    requireSpecial: current.requireSpecial || next.requireSpecial,
    enforceOnLogin: current.enforceOnLogin || next.enforceOnLogin,
  });
}

/** Admin recovery is authoritative and may replace any client-side weak-password result. */
export function mergePasswordChangeRequirement(
  current: PasswordChangeRequirement | undefined,
  forcePasswordReset: boolean,
  policy?: MasterPasswordPolicy,
): PasswordChangeRequirement | undefined {
  const combinedPolicy = combineMasterPasswordPolicies(current?.policy, policy);
  if (forcePasswordReset || current?.reason === 'adminForcePasswordReset') {
    return passwordChangeRequirement('adminForcePasswordReset', combinedPolicy);
  }
  return current
    ? passwordChangeRequirement(current.reason, combinedPolicy)
    : undefined;
}

/** Capture the minimum non-secret password facts before plaintext leaves the login call scope. */
export function captureMasterPasswordEvidence(
  password: string,
  email: string,
): MasterPasswordEvidence {
  const scored = password.length > MASTER_PASSWORD_STRENGTH_INPUT_MAX_LENGTH
    ? password.substring(0, MASTER_PASSWORD_STRENGTH_INPUT_MAX_LENGTH)
    : password;
  const localPart = email.includes('@') ? email.slice(0, email.indexOf('@')) : '';
  const userInputs = Array.from(new Set([
    'bitwarden',
    'bit',
    'warden',
    ...localPart.trim().toLowerCase().split(/[^A-Za-z0-9]/u).filter(Boolean),
  ]));
  return Object.freeze({
    schemaVersion: MASTER_PASSWORD_EVIDENCE_SCHEMA_VERSION,
    length: Math.min(password.length, MASTER_PASSWORD_POLICY_MAX_LENGTH),
    hasUpper: password.toLocaleLowerCase() !== password,
    hasLower: password.toLocaleUpperCase() !== password,
    hasNumbers: /[0-9]/u.test(password),
    hasSpecial: /[!@#$%^&*]/u.test(password),
    zxcvbnScore: zxcvbn(scored, userInputs).score,
  });
}

/** Strictly restore secret-free evidence from an MV3 continuation. */
export function parseMasterPasswordEvidence(input: unknown): MasterPasswordEvidence {
  const record = requirePlainDataRecord(input, 'master password evidence');
  const expected = [
    'hasLower', 'hasNumbers', 'hasSpecial', 'hasUpper', 'length', 'schemaVersion', 'zxcvbnScore',
  ];
  const keys = Object.keys(record).sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new TypeError('master password evidence contains unsupported fields');
  }
  if (record.schemaVersion !== MASTER_PASSWORD_EVIDENCE_SCHEMA_VERSION) {
    throw new TypeError('master password evidence has an unsupported schema version');
  }
  if (!Number.isSafeInteger(record.length)
      || (record.length as number) < 0
      || (record.length as number) > MASTER_PASSWORD_POLICY_MAX_LENGTH) {
    throw new TypeError('master password evidence length is invalid');
  }
  for (const name of ['hasUpper', 'hasLower', 'hasNumbers', 'hasSpecial'] as const) {
    if (typeof record[name] !== 'boolean') {
      throw new TypeError(`master password evidence ${name} is invalid`);
    }
  }
  if (!Number.isSafeInteger(record.zxcvbnScore)
      || (record.zxcvbnScore as number) < 0
      || (record.zxcvbnScore as number) > 4) {
    throw new TypeError('master password evidence zxcvbnScore is invalid');
  }
  return Object.freeze({
    schemaVersion: MASTER_PASSWORD_EVIDENCE_SCHEMA_VERSION,
    length: record.length as number,
    hasUpper: record.hasUpper as boolean,
    hasLower: record.hasLower as boolean,
    hasNumbers: record.hasNumbers as boolean,
    hasSpecial: record.hasSpecial as boolean,
    zxcvbnScore: record.zxcvbnScore as 0 | 1 | 2 | 3 | 4,
  });
}

export function evaluateMasterPasswordEvidence(
  evidence: MasterPasswordEvidence,
  policy: MasterPasswordPolicy | undefined,
): boolean {
  if (!policy) return true;
  if (policy.minLength > evidence.length) return false;
  if (policy.requireUpper && !evidence.hasUpper) return false;
  if (policy.requireLower && !evidence.hasLower) return false;
  if (policy.requireNumbers && !evidence.hasNumbers) return false;
  if (policy.requireSpecial && !evidence.hasSpecial) return false;
  return policy.minComplexity <= evidence.zxcvbnScore;
}

export function evaluateMasterPasswordPolicy(
  password: string,
  email: string,
  policy: MasterPasswordPolicy | undefined,
): boolean {
  return evaluateMasterPasswordEvidence(captureMasterPasswordEvidence(password, email), policy);
}

export function weakPasswordRequirement(
  password: string,
  email: string,
  policy: MasterPasswordPolicy | undefined,
): PasswordChangeRequirement | undefined {
  if (!policy?.enforceOnLogin) return undefined;
  return evaluateMasterPasswordEvidence(captureMasterPasswordEvidence(password, email), policy)
    ? undefined
    : passwordChangeRequirement('weakMasterPassword', policy);
}

export function emptyMasterPasswordPolicy(): MasterPasswordPolicy {
  return EMPTY_POLICY;
}

export function samePasswordChangeRequirement(
  left: PasswordChangeRequirement | undefined,
  right: PasswordChangeRequirement | undefined,
): boolean {
  if (!left || !right) return left === right;
  if (left.schemaVersion !== right.schemaVersion || left.reason !== right.reason) return false;
  if (!left.policy || !right.policy) return left.policy === right.policy;
  return left.policy.minComplexity === right.policy.minComplexity
    && left.policy.minLength === right.policy.minLength
    && left.policy.requireUpper === right.policy.requireUpper
    && left.policy.requireLower === right.policy.requireLower
    && left.policy.requireNumbers === right.policy.requireNumbers
    && left.policy.requireSpecial === right.policy.requireSpecial
    && left.policy.enforceOnLogin === right.policy.enforceOnLogin;
}

function readInteger(
  record: Record<string, unknown>,
  camelName: string,
  pascalName: string,
  minimum: number,
  maximum: number,
): number {
  const value = readAliased(record, camelName, pascalName);
  if (value === undefined || value === null) return 0;
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new TypeError(`master password policy ${camelName} is invalid`);
  }
  return value as number;
}

function readBoolean(
  record: Record<string, unknown>,
  camelName: string,
  pascalName: string,
): boolean {
  const value = readAliased(record, camelName, pascalName);
  if (value === undefined || value === null) return false;
  if (typeof value !== 'boolean') {
    throw new TypeError(`master password policy ${camelName} is invalid`);
  }
  return value;
}

function readAliased(
  record: Record<string, unknown>,
  camelName: string,
  pascalName: string,
): unknown {
  const hasCamel = Object.hasOwn(record, camelName);
  const hasPascal = Object.hasOwn(record, pascalName);
  if (hasCamel && hasPascal) {
    throw new TypeError(`master password policy contains duplicate ${camelName} fields`);
  }
  return hasCamel ? record[camelName] : hasPascal ? record[pascalName] : undefined;
}

function requirePlainDataRecord(input: unknown, label: string): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new TypeError(`${label} must be a JSON object`);
  }
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${label} must be a plain JSON object`);
  }
  for (const key of Reflect.ownKeys(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (typeof key !== 'string' || !descriptor?.enumerable || !('value' in descriptor)) {
      throw new TypeError(`${label} must contain only enumerable data properties`);
    }
  }
  return input as Record<string, unknown>;
}
