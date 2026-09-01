export const LOGIN_CUSTOM_PLAN_VERSION = 2 as const;
export const MAX_LOGIN_CUSTOM_TARGETS = 32;
export const MAX_LOGIN_CUSTOM_HINTS_PER_TARGET = 8;
export const MAX_LOGIN_CUSTOM_FIELD_ID_LENGTH = 128;
export const MAX_LOGIN_CUSTOM_HINT_LENGTH = 256;
export const MAX_LOGIN_CUSTOM_PLAN_BYTES = 32 * 1024;
export const MAX_LOGIN_CUSTOM_ASSIGNMENT_LENGTH = 16 * 1024;
export const MAX_LOGIN_CUSTOM_ASSIGNMENT_BYTES = 128 * 1024;

export type LoginCustomControlType =
  | 'text'
  | 'email'
  | 'tel'
  | 'url'
  | 'search'
  | 'number'
  | 'checkbox'
  | 'select'
  | 'textarea';

export type LoginCustomTargetHint = Readonly<{
  kind: 'name' | 'id' | 'label' | 'placeholder';
  value: string;
}>;

export interface LoginCustomTarget {
  readonly fieldId: string;
  readonly controlType: LoginCustomControlType;
  readonly hints: readonly LoginCustomTargetHint[];
}

/** Metadata-only description of eligible custom fields in one detected login scope. */
export interface LoginCustomTargetPlan {
  readonly version: typeof LOGIN_CUSTOM_PLAN_VERSION;
  readonly generation: number;
  readonly targets: readonly LoginCustomTarget[];
}

/** Canonical no-custom-fields fixture used by strict callers and protocol tests. */
export const EMPTY_LOGIN_CUSTOM_PLAN: LoginCustomTargetPlan = Object.freeze({
  version: LOGIN_CUSTOM_PLAN_VERSION,
  generation: 1,
  targets: Object.freeze([]),
});
export const EMPTY_LOGIN_CUSTOM_PLAN_DIGEST = 'bafa16db11e4dc46cb70be92aa26c8de47ab98da57ed3b1b915f233ed5360935';

export type LoginCustomAssignment =
  | Readonly<{ fieldId: string; value: string }>
  | Readonly<{ fieldId: string; checked: boolean }>;

const CONTROL_TYPES = new Set<LoginCustomControlType>([
  'text', 'email', 'tel', 'url', 'search', 'number', 'checkbox', 'select', 'textarea',
]);
const HINT_KINDS = new Set<LoginCustomTargetHint['kind']>(['name', 'id', 'label', 'placeholder']);

/** Strictly canonicalize untrusted content metadata. Unknown keys and partial targets fail closed. */
export function parseLoginCustomTargetPlan(value: unknown): LoginCustomTargetPlan | undefined {
  if (!isRecord(value) || !hasOnlyKeys(value, ['version', 'generation', 'targets'])) return undefined;
  if (value.version !== LOGIN_CUSTOM_PLAN_VERSION
      || !Number.isSafeInteger(value.generation)
      || Number(value.generation) <= 0
      || !isDenseDataArray(value.targets)
      || value.targets.length > MAX_LOGIN_CUSTOM_TARGETS) return undefined;

  const fieldIds = new Set<string>();
  let totalBytes = 0;
  const targets: LoginCustomTarget[] = [];
  for (const candidate of value.targets) {
    if (!isRecord(candidate) || !hasOnlyKeys(candidate, ['fieldId', 'controlType', 'hints'])) return undefined;
    if (!isBoundedToken(candidate.fieldId, MAX_LOGIN_CUSTOM_FIELD_ID_LENGTH)
        || typeof candidate.controlType !== 'string'
        || !CONTROL_TYPES.has(candidate.controlType as LoginCustomControlType)
        || !isDenseDataArray(candidate.hints)
        || candidate.hints.length === 0
        || candidate.hints.length > MAX_LOGIN_CUSTOM_HINTS_PER_TARGET
        || fieldIds.has(candidate.fieldId)) return undefined;
    fieldIds.add(candidate.fieldId);
    totalBytes += utf8Length(candidate.fieldId);
    const hintKeys = new Set<string>();
    const hints: LoginCustomTargetHint[] = [];
    for (const hint of candidate.hints) {
      if (!isRecord(hint)
          || !hasOnlyKeys(hint, ['kind', 'value'])
          || typeof hint.kind !== 'string'
          || !HINT_KINDS.has(hint.kind as LoginCustomTargetHint['kind'])
          || !isCanonicalHint(hint.value)) return undefined;
      const key = `${hint.kind}\0${hint.value}`;
      if (hintKeys.has(key)) return undefined;
      hintKeys.add(key);
      totalBytes += utf8Length(hint.value);
      if (totalBytes > MAX_LOGIN_CUSTOM_PLAN_BYTES) return undefined;
      hints.push(Object.freeze({
        kind: hint.kind as LoginCustomTargetHint['kind'],
        value: hint.value,
      }));
    }
    targets.push(Object.freeze({
      fieldId: candidate.fieldId,
      controlType: candidate.controlType as LoginCustomControlType,
      hints: Object.freeze(hints),
    }));
  }

  const canonical = Object.freeze({
    version: LOGIN_CUSTOM_PLAN_VERSION,
    generation: Number(value.generation),
    targets: Object.freeze(targets),
  });
  return utf8Length(JSON.stringify(canonical)) <= MAX_LOGIN_CUSTOM_PLAN_BYTES ? canonical : undefined;
}

/** Digest the canonical plan so its complete structural shape can be bound to an intent. */
export async function digestLoginCustomTargetPlan(plan: LoginCustomTargetPlan): Promise<string> {
  const canonical = parseLoginCustomTargetPlan(plan);
  if (!canonical) throw new TypeError('Login custom target plan is invalid');
  const bytes = new TextEncoder().encode(JSON.stringify(canonical));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function isLoginCustomPlanDigest(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

export function equalLoginCustomPlanDigest(first: string, second: string): boolean {
  if (!isLoginCustomPlanDigest(first) || !isLoginCustomPlanDigest(second)) return false;
  let difference = 0;
  for (let index = 0; index < first.length; index += 1) {
    difference |= first.charCodeAt(index) ^ second.charCodeAt(index);
  }
  return difference === 0;
}

export function parseLoginCustomAssignments(value: unknown): LoginCustomAssignment[] | undefined {
  if (!isDenseDataArray(value) || value.length > MAX_LOGIN_CUSTOM_TARGETS) return undefined;
  const fieldIds = new Set<string>();
  let totalBytes = 0;
  const assignments: LoginCustomAssignment[] = [];
  for (const candidate of value) {
    if (!isRecord(candidate) || !isBoundedToken(candidate.fieldId, MAX_LOGIN_CUSTOM_FIELD_ID_LENGTH)) return undefined;
    if (fieldIds.has(candidate.fieldId)) return undefined;
    fieldIds.add(candidate.fieldId);
    if (hasOnlyKeys(candidate, ['fieldId', 'value'])
        && typeof candidate.value === 'string'
        && candidate.value.length <= MAX_LOGIN_CUSTOM_ASSIGNMENT_LENGTH) {
      totalBytes += new TextEncoder().encode(candidate.value).byteLength;
      if (totalBytes > MAX_LOGIN_CUSTOM_ASSIGNMENT_BYTES) return undefined;
      assignments.push(Object.freeze({ fieldId: candidate.fieldId, value: candidate.value }));
      continue;
    }
    if (hasOnlyKeys(candidate, ['fieldId', 'checked']) && typeof candidate.checked === 'boolean') {
      assignments.push(Object.freeze({ fieldId: candidate.fieldId, checked: candidate.checked }));
      continue;
    }
    return undefined;
  }
  return assignments;
}

function isCanonicalHint(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= MAX_LOGIN_CUSTOM_HINT_LENGTH
    && value.trim() === value
    && value.normalize('NFKC') === value;
}

function isBoundedToken(value: unknown, maximum: number): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= maximum
    && value.trim() === value;
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = new Set(allowed);
  return Object.keys(value).every((key) => keys.has(key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && 'value' in descriptor;
  });
}

function isDenseDataArray(value: unknown): value is unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes('length')) return false;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !('value' in descriptor)) return false;
  }
  return keys.every((key) => key === 'length' || (typeof key === 'string' && /^(0|[1-9]\d*)$/.test(key)));
}
