import type { EffectiveMaximumVaultTimeoutPolicy } from '../core/policy/effective-enterprise-policy.js';
import {
  MAX_LOCK_TIMEOUT_MINUTES,
  isCanonicalLockTimeoutMinutes,
  isLockTimeoutSetting,
  isOnIdleAction,
  lockTimeoutToIdleMs,
  type LockTimeoutSetting,
  type OnIdleAction,
} from './settings.js';
import type { VaultTimeoutCloseLogoutProvenance } from './vault-timeout-state.js';

export type MaximumVaultTimeoutPolicyState =
  | { readonly kind: 'available'; readonly policy: EffectiveMaximumVaultTimeoutPolicy | null }
  | { readonly kind: 'unavailable' };

export type EffectiveVaultTimeoutMode = 'local' | 'systemLock' | 'immediate';

export interface EffectiveVaultTimeoutSettings {
  readonly lockTimeout: LockTimeoutSetting;
  readonly onIdleAction: OnIdleAction;
  readonly idleSeconds: number | null;
  readonly lockOnSystemLock: boolean;
  readonly logoutOnBrowserClose: boolean;
  readonly closeLogoutActionProvenance: VaultTimeoutCloseLogoutProvenance | null;
  readonly closeLogoutTimeoutProvenance: VaultTimeoutCloseLogoutProvenance | null;
  readonly mode: EffectiveVaultTimeoutMode;
  readonly managed: boolean;
  readonly failClosed: boolean;
}

export function isLocalCloseLogoutEnabled(
  lockTimeout: LockTimeoutSetting,
  onIdleAction: OnIdleAction,
): boolean {
  return onIdleAction === 'logout' && lockTimeout !== 'never';
}

export type LocalVaultTimeoutSettings = readonly [LockTimeoutSetting, OnIdleAction];

export function didLocalVaultTimeoutSettingsChange(
  before: LocalVaultTimeoutSettings,
  after: LocalVaultTimeoutSettings,
): boolean {
  return before[0] !== after[0] || before[1] !== after[1];
}

export function localCloseLogoutOwnerClear(
  before: LocalVaultTimeoutSettings,
  after: LocalVaultTimeoutSettings,
): { readonly action: boolean; readonly timeout: boolean } {
  return Object.freeze({
    action: before[1] === 'logout' && after[1] !== 'logout',
    timeout: before[0] !== 'never' && after[0] === 'never',
  });
}

const FAIL_CLOSED: EffectiveVaultTimeoutSettings = Object.freeze({
  lockTimeout: '1',
  onIdleAction: 'logout',
  idleSeconds: 0,
  lockOnSystemLock: true,
  logoutOnBrowserClose: true,
  closeLogoutActionProvenance: 'fail_closed',
  closeLogoutTimeoutProvenance: 'fail_closed',
  mode: 'immediate',
  managed: true,
  failClosed: true,
});

/** Resolve persisted preferences against one policy generation without exposing policy metadata. */
export function resolveEffectiveVaultTimeout(
  lockTimeout: LockTimeoutSetting,
  onIdleAction: OnIdleAction,
  state: MaximumVaultTimeoutPolicyState,
): EffectiveVaultTimeoutSettings {
  if (!isLockTimeoutSetting(lockTimeout) || !isOnIdleAction(onIdleAction)) return FAIL_CLOSED;
  if (state.kind === 'unavailable') return FAIL_CLOSED;
  const policy = state.policy;
  if (policy === null) {
    const behavior = localTimeoutBehavior(lockTimeout);
    return Object.freeze({
      lockTimeout,
      onIdleAction,
      idleSeconds: behavior.idleSeconds,
      lockOnSystemLock: behavior.lockOnSystemLock,
      logoutOnBrowserClose: isLocalCloseLogoutEnabled(lockTimeout, onIdleAction),
      closeLogoutActionProvenance: isLocalCloseLogoutEnabled(lockTimeout, onIdleAction) ? 'local' : null,
      closeLogoutTimeoutProvenance: isLocalCloseLogoutEnabled(lockTimeout, onIdleAction) ? 'local' : null,
      mode: behavior.mode,
      managed: false,
      failClosed: false,
    });
  }
  if (!isValidPolicy(policy) || policy.malformed) return FAIL_CLOSED;

  const action = policy.data.action === null
    ? onIdleAction
    : policy.data.action === 'logOut' ? 'logout' : 'lock';
  let effectiveTimeout = lockTimeout;
  let immediate = lockTimeout === 'immediate';
  let systemLockOnly = lockTimeout === 'onLocked';

  switch (policy.data.type) {
    case 'never':
      break;
    case 'immediately':
      immediate = true;
      systemLockOnly = false;
      effectiveTimeout = 'immediate';
      break;
    case 'onAppRestart':
      if (lockTimeout === 'never') {
        effectiveTimeout = 'onClose';
        immediate = false;
        systemLockOnly = false;
      }
      break;
    case 'onSystemLock':
      // A numeric deadline is already stricter in Bitwarden's timeout ordering. Browser idle
      // events are reserved for the explicit system-lock mode and never drive numeric timeouts.
      if (!immediate && !isNumericTimeout(effectiveTimeout)) systemLockOnly = true;
      break;
    case 'custom':
    case null:
      if (policy.data.minutes === 0) {
        immediate = true;
        systemLockOnly = false;
        effectiveTimeout = 'immediate';
      } else if (!immediate
          && (!isNumericTimeout(lockTimeout) || Number(lockTimeout) > policy.data.minutes)) {
        effectiveTimeout = String(policy.data.minutes) as `${number}`;
        immediate = false;
        systemLockOnly = false;
      }
      break;
  }

  const logoutOnBrowserClose = action === 'logout'
    && (effectiveTimeout !== 'never' || systemLockOnly || immediate);
  const policyOwnsTimeout = policy.data.type !== 'never';
  return Object.freeze({
    lockTimeout: effectiveTimeout,
    onIdleAction: action,
    idleSeconds: immediate ? 0 : systemLockOnly ? null : toIdleSeconds(effectiveTimeout),
    lockOnSystemLock: immediate || systemLockOnly,
    logoutOnBrowserClose,
    closeLogoutActionProvenance: logoutOnBrowserClose
      ? policy.data.action === 'logOut' ? 'policy' : 'local'
      : null,
    closeLogoutTimeoutProvenance: logoutOnBrowserClose
      ? policyOwnsTimeout ? 'policy' : 'local'
      : null,
    mode: immediate ? 'immediate' : systemLockOnly ? 'systemLock' : 'local',
    managed: policy.data.type !== 'never' || policy.data.action !== null,
    failClosed: false,
  });
}

/** Reject a persisted choice when policy resolution would have to make it stricter. */
export function isVaultTimeoutSelectionAllowed(
  lockTimeout: LockTimeoutSetting,
  onIdleAction: OnIdleAction,
  state: MaximumVaultTimeoutPolicyState,
): boolean {
  const effective = resolveEffectiveVaultTimeout(lockTimeout, onIdleAction, state);
  const local = localTimeoutBehavior(lockTimeout);
  return !effective.failClosed
    && effective.lockTimeout === lockTimeout
    && effective.onIdleAction === onIdleAction
    && effective.idleSeconds === local.idleSeconds
    && effective.lockOnSystemLock === local.lockOnSystemLock
    && effective.mode === local.mode;
}

/** Validate only the timeout field when the action is not part of the write. */
export function isVaultTimeoutValueAllowed(
  lockTimeout: LockTimeoutSetting,
  state: MaximumVaultTimeoutPolicyState,
): boolean {
  const effective = resolveEffectiveVaultTimeout(lockTimeout, 'lock', state);
  const local = localTimeoutBehavior(lockTimeout);
  return !effective.failClosed
    && effective.lockTimeout === lockTimeout
    && effective.idleSeconds === local.idleSeconds
    && effective.lockOnSystemLock === local.lockOnSystemLock
    && effective.mode === local.mode;
}

/** Validate only the action field when the timeout is not part of the write. */
export function isVaultTimeoutActionAllowed(
  onIdleAction: OnIdleAction,
  state: MaximumVaultTimeoutPolicyState,
): boolean {
  const effective = resolveEffectiveVaultTimeout('1', onIdleAction, state);
  return !effective.failClosed && effective.onIdleAction === onIdleAction;
}

function isNumericTimeout(value: LockTimeoutSetting): value is Extract<LockTimeoutSetting, `${number}`> {
  return isCanonicalLockTimeoutMinutes(value);
}

function toIdleSeconds(value: LockTimeoutSetting): number | null {
  const milliseconds = lockTimeoutToIdleMs(value);
  return milliseconds === null ? null : milliseconds / 1_000;
}

function localTimeoutBehavior(lockTimeout: LockTimeoutSetting): Readonly<{
  idleSeconds: number | null;
  lockOnSystemLock: boolean;
  mode: EffectiveVaultTimeoutMode;
}> {
  if (lockTimeout === 'immediate') {
    return Object.freeze({ idleSeconds: 0, lockOnSystemLock: true, mode: 'immediate' });
  }
  if (lockTimeout === 'onLocked') {
    return Object.freeze({ idleSeconds: null, lockOnSystemLock: true, mode: 'systemLock' });
  }
  return Object.freeze({
    idleSeconds: toIdleSeconds(lockTimeout),
    lockOnSystemLock: false,
    mode: 'local',
  });
}

function isValidPolicy(policy: EffectiveMaximumVaultTimeoutPolicy): boolean {
  const data = policy.data;
  return typeof policy.malformed === 'boolean'
    && data !== null
    && typeof data === 'object'
    && Number.isSafeInteger(data.minutes)
    && data.minutes >= 0
    && data.minutes <= MAX_LOCK_TIMEOUT_MINUTES
    && (data.type === null
      || data.type === 'never'
      || data.type === 'onAppRestart'
      || data.type === 'onSystemLock'
      || data.type === 'immediately'
      || data.type === 'custom')
    && (data.action === null || data.action === 'lock' || data.action === 'logOut');
}
