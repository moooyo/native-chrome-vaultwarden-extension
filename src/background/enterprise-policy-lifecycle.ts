import type { SessionTransitionEvent } from '../core/session/auth-service.js';

const INVALIDATING_REASONS: ReadonlySet<SessionTransitionEvent['reason']> = new Set([
  'login',
  'switchAccount',
  'logout',
  'removeAccount',
  'serverChange',
  'keyRotation',
]);

/** Identity-changing transitions revoke account/raw-scoped policy state; lock transitions do not. */
export function invalidatesEnterprisePolicy(reason: SessionTransitionEvent['reason']): boolean {
  return INVALIDATING_REASONS.has(reason);
}

export type EnterprisePolicySideEffect =
  | 'invalidateAutofill'
  | 'clearPendingSaves'
  | 'clearUsernameStages'
  | 'enforceSessionPolicy'
  | 'refreshIdleDetection'
  | 'refreshAutofill'
  | 'refreshContextMenu';

/** Apply the timeout policy first; secondary cleanup failures cannot suppress that security boundary. */
export async function applyEnterprisePolicySideEffects(deps: {
  readonly applyVaultTimeout: () => Promise<void>;
  readonly invalidateAutofill: () => void | Promise<void>;
  readonly clearPendingSaves: () => Promise<void>;
  readonly clearUsernameStages: () => Promise<void>;
  readonly enforceSessionPolicy: () => Promise<void>;
  readonly refreshIdleDetection: () => Promise<void>;
  readonly refreshAutofill: () => Promise<void>;
  readonly refreshContextMenu: () => Promise<void>;
  readonly warn: (effect: EnterprisePolicySideEffect, error: unknown) => void;
}): Promise<void> {
  await deps.applyVaultTimeout();
  const effects: ReadonlyArray<readonly [EnterprisePolicySideEffect, () => void | Promise<void>]> = [
    ['invalidateAutofill', deps.invalidateAutofill],
    ['clearPendingSaves', deps.clearPendingSaves],
    ['clearUsernameStages', deps.clearUsernameStages],
    ['enforceSessionPolicy', deps.enforceSessionPolicy],
    ['refreshIdleDetection', deps.refreshIdleDetection],
    ['refreshAutofill', deps.refreshAutofill],
    ['refreshContextMenu', deps.refreshContextMenu],
  ];
  const settled = await Promise.allSettled(effects.map(([, operation]) => Promise.resolve().then(operation)));
  settled.forEach((result, index) => {
    if (result.status === 'rejected') deps.warn(effects[index]![0], result.reason);
  });
}
