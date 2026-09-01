import { describe, expect, it } from 'vitest';
import {
  LOGIN_CUSTOM_PLAN_VERSION,
  EMPTY_LOGIN_CUSTOM_PLAN,
  EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
  MAX_LOGIN_CUSTOM_ASSIGNMENT_LENGTH,
  MAX_LOGIN_CUSTOM_HINTS_PER_TARGET,
  MAX_LOGIN_CUSTOM_PLAN_BYTES,
  MAX_LOGIN_CUSTOM_TARGETS,
  digestLoginCustomTargetPlan,
  equalLoginCustomPlanDigest,
  parseLoginCustomAssignments,
  parseLoginCustomTargetPlan,
  type LoginCustomTargetPlan,
} from './login-custom-fields.js';

function plan(overrides: Partial<LoginCustomTargetPlan> = {}): LoginCustomTargetPlan {
  return {
    version: LOGIN_CUSTOM_PLAN_VERSION,
    generation: 1,
    targets: [{ fieldId: 'private-1', controlType: 'text', hints: [{ kind: 'name', value: 'department' }] }],
    ...overrides,
  };
}

describe('login custom target plan', () => {
  it('canonicalizes a bounded metadata-only plan and rejects unknown fields', () => {
    expect(parseLoginCustomTargetPlan(plan())).toEqual(plan());
    expect(parseLoginCustomTargetPlan({ ...plan(), version: 1 })).toBeUndefined();
    expect(parseLoginCustomTargetPlan({ ...plan(), leakedValue: 'secret' })).toBeUndefined();
    expect(parseLoginCustomTargetPlan({
      ...plan(),
      targets: [{ ...plan().targets[0], selector: '#department' }],
    })).toBeUndefined();
  });

  it('rejects accessors, custom prototypes, sparse arrays, and array side channels', () => {
    const accessor = plan() as unknown as Record<string, unknown>;
    Object.defineProperty(accessor, 'generation', { get: () => 1, enumerable: true });
    expect(parseLoginCustomTargetPlan(accessor)).toBeUndefined();

    const customPrototype = plan() as unknown as Record<string, unknown>;
    Object.setPrototypeOf(customPrototype, { inherited: true });
    expect(parseLoginCustomTargetPlan(customPrototype)).toBeUndefined();

    const sparse = new Array<unknown>(1);
    expect(parseLoginCustomTargetPlan({ ...plan(), targets: sparse })).toBeUndefined();
    const extra = [...plan().targets];
    Object.defineProperty(extra, 'secret', { value: 'side-channel', enumerable: true });
    expect(parseLoginCustomTargetPlan({ ...plan(), targets: extra })).toBeUndefined();
  });

  it('rejects duplicate ids, non-canonical hints, and oversized plans', () => {
    const target = plan().targets[0]!;
    expect(parseLoginCustomTargetPlan(plan({ targets: [target, target] }))).toBeUndefined();
    expect(parseLoginCustomTargetPlan(plan({
      targets: [{ ...target, hints: [{ kind: 'name', value: ' department ' }] }],
    }))).toBeUndefined();
    expect(parseLoginCustomTargetPlan(plan({
      targets: [{ ...target, hints: Array.from({ length: MAX_LOGIN_CUSTOM_HINTS_PER_TARGET + 1 }, (_, index) => ({
        kind: 'label' as const,
        value: `label-${index}`,
      })) }],
    }))).toBeUndefined();
    expect(parseLoginCustomTargetPlan(plan({
      targets: [{ ...target, hints: [{ kind: 'name', value: 'same' }, { kind: 'name', value: 'same' }] }],
    }))).toBeUndefined();
    expect(parseLoginCustomTargetPlan(plan({
      targets: Array.from({ length: MAX_LOGIN_CUSTOM_TARGETS + 1 }, (_, index) => ({
        ...target,
        fieldId: `field-${index}`,
      })),
    }))).toBeUndefined();
  });

  it('rejects plans whose bounded hints exceed the aggregate UTF-8 budget', () => {
    const target = plan().targets[0]!;
    expect(parseLoginCustomTargetPlan(plan({
      targets: Array.from({ length: MAX_LOGIN_CUSTOM_TARGETS }, (_, index) => ({
        ...target,
        fieldId: `field-${index}`,
        hints: Array.from({ length: MAX_LOGIN_CUSTOM_HINTS_PER_TARGET }, () => ({
          kind: 'label' as const,
          value: '界'.repeat(Math.ceil(MAX_LOGIN_CUSTOM_PLAN_BYTES / MAX_LOGIN_CUSTOM_TARGETS / MAX_LOGIN_CUSTOM_HINTS_PER_TARGET / 3)),
        })).map((hint, hintIndex) => ({ ...hint, value: `${hint.value}${hintIndex}` })),
      })),
    }))).toBeUndefined();
  });

  it('binds every canonical plan field into a stable SHA-256 digest', async () => {
    const first = await digestLoginCustomTargetPlan(plan());
    const second = await digestLoginCustomTargetPlan(plan());
    const changed = await digestLoginCustomTargetPlan(plan({ generation: 2 }));
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(equalLoginCustomPlanDigest(first, second)).toBe(true);
    expect(equalLoginCustomPlanDigest(first, changed)).toBe(false);
    expect(await digestLoginCustomTargetPlan(EMPTY_LOGIN_CUSTOM_PLAN)).toBe(EMPTY_LOGIN_CUSTOM_PLAN_DIGEST);
  });

  it('accepts only minimal bounded assignments', () => {
    expect(parseLoginCustomAssignments([
      { fieldId: 'private-1', value: 'engineering' },
      { fieldId: 'private-2', checked: true },
    ])).toEqual([
      { fieldId: 'private-1', value: 'engineering' },
      { fieldId: 'private-2', checked: true },
    ]);
    expect(parseLoginCustomAssignments([{ fieldId: 'private-1', value: 'x', name: 'department' }])).toBeUndefined();
    expect(parseLoginCustomAssignments([{ fieldId: 'private-1', value: 'x'.repeat(MAX_LOGIN_CUSTOM_ASSIGNMENT_LENGTH + 1) }])).toBeUndefined();
    expect(parseLoginCustomAssignments([{ fieldId: 'same', value: 'x' }, { fieldId: 'same', value: 'y' }])).toBeUndefined();
    const accessor = [{ fieldId: 'private-1', value: 'safe' }] as Array<Record<string, unknown>>;
    Object.defineProperty(accessor[0], 'value', { get: () => 'unsafe', enumerable: true });
    expect(parseLoginCustomAssignments(accessor)).toBeUndefined();
  });
});
