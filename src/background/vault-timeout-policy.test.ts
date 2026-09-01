import { describe, expect, it } from 'vitest';
import type { EffectiveMaximumVaultTimeoutPolicy } from '../core/policy/effective-enterprise-policy.js';
import {
  didLocalVaultTimeoutSettingsChange,
  isVaultTimeoutActionAllowed,
  isLocalCloseLogoutEnabled,
  isVaultTimeoutSelectionAllowed,
  isVaultTimeoutValueAllowed,
  localCloseLogoutOwnerClear,
  resolveEffectiveVaultTimeout,
  type MaximumVaultTimeoutPolicyState,
} from './vault-timeout-policy.js';

function available(
  type: EffectiveMaximumVaultTimeoutPolicy['data']['type'],
  minutes: number,
  action: EffectiveMaximumVaultTimeoutPolicy['data']['action'] = null,
): MaximumVaultTimeoutPolicyState {
  return {
    kind: 'available',
    policy: { organizationId: 'org', malformed: false, data: { type, minutes, action } },
  };
}

describe('resolveEffectiveVaultTimeout', () => {
  it('preserves local settings when no policy applies', () => {
    expect(resolveEffectiveVaultTimeout('never', 'lock', { kind: 'available', policy: null }))
      .toEqual({ lockTimeout: 'never', onIdleAction: 'lock', idleSeconds: null, lockOnSystemLock: false, logoutOnBrowserClose: false, closeLogoutActionProvenance: null, closeLogoutTimeoutProvenance: null, mode: 'local', managed: false, failClosed: false });
    expect(resolveEffectiveVaultTimeout('15', 'lock', { kind: 'available', policy: null }))
      .toMatchObject({ idleSeconds: 900, lockOnSystemLock: false, mode: 'local' });
    expect(resolveEffectiveVaultTimeout('15', 'logout', { kind: 'available', policy: null }))
      .toMatchObject({ logoutOnBrowserClose: true, closeLogoutActionProvenance: 'local', closeLogoutTimeoutProvenance: 'local' });
    expect(resolveEffectiveVaultTimeout('immediate', 'lock', { kind: 'available', policy: null }))
      .toMatchObject({ lockTimeout: 'immediate', idleSeconds: 0, lockOnSystemLock: true, mode: 'immediate' });
    expect(resolveEffectiveVaultTimeout('onLocked', 'lock', { kind: 'available', policy: null }))
      .toMatchObject({ lockTimeout: 'onLocked', idleSeconds: null, lockOnSystemLock: true, mode: 'systemLock' });
    expect(resolveEffectiveVaultTimeout('37', 'lock', { kind: 'available', policy: null }))
      .toMatchObject({ lockTimeout: '37', idleSeconds: 2_220, lockOnSystemLock: false, mode: 'local' });
  });

  it('clamps custom limits to the exact policy minute instead of a nearby preset', () => {
    expect(resolveEffectiveVaultTimeout('30', 'lock', available('custom', 10)))
      .toEqual({ lockTimeout: '10', onIdleAction: 'lock', idleSeconds: 600, lockOnSystemLock: false, logoutOnBrowserClose: false, closeLogoutActionProvenance: null, closeLogoutTimeoutProvenance: null, mode: 'local', managed: true, failClosed: false });
    expect(resolveEffectiveVaultTimeout('1', 'lock', available('custom', 10)).lockTimeout).toBe('1');
    expect(resolveEffectiveVaultTimeout('7', 'lock', available('custom', 10)).lockTimeout).toBe('7');
    expect(resolveEffectiveVaultTimeout('11', 'lock', available('custom', 10)).lockTimeout).toBe('10');
  });

  it.each(['onClose', 'onLocked', 'never'] as const)(
    'clamps %s to the exact custom policy minute',
    (local) => {
      expect(resolveEffectiveVaultTimeout(local, 'lock', available('custom', 17))).toMatchObject({
        lockTimeout: '17',
        idleSeconds: 1_020,
        lockOnSystemLock: false,
        mode: 'local',
      });
    },
  );

  it('keeps an immediate or stricter numeric local value under a wider custom policy', () => {
    expect(resolveEffectiveVaultTimeout('immediate', 'lock', available('custom', 30)))
      .toMatchObject({ lockTimeout: 'immediate', idleSeconds: 0, mode: 'immediate' });
    expect(resolveEffectiveVaultTimeout('5', 'lock', available('custom', 30)))
      .toMatchObject({ lockTimeout: '5', idleSeconds: 300, mode: 'local' });
  });

  it('maps a zero-minute custom policy to the explicit immediate mode', () => {
    expect(resolveEffectiveVaultTimeout('onClose', 'lock', available('custom', 0))).toMatchObject({
      lockTimeout: 'immediate',
      idleSeconds: 0,
      lockOnSystemLock: true,
      mode: 'immediate',
    });
  });

  it('forces the policy action exactly', () => {
    expect(resolveEffectiveVaultTimeout('5', 'logout', available('custom', 15, 'lock')).onIdleAction).toBe('lock');
    expect(resolveEffectiveVaultTimeout('5', 'lock', available('custom', 15, 'logOut')).onIdleAction).toBe('logout');
  });

  it('represents restart and system-lock policies without inventing an idle duration', () => {
    expect(resolveEffectiveVaultTimeout('never', 'lock', available('onAppRestart', 0)))
      .toMatchObject({ lockTimeout: 'onClose', idleSeconds: null, lockOnSystemLock: false, mode: 'local' });
    expect(resolveEffectiveVaultTimeout('onClose', 'lock', available('onSystemLock', 0)))
      .toMatchObject({ lockTimeout: 'onClose', idleSeconds: null, lockOnSystemLock: true, mode: 'systemLock' });
    expect(resolveEffectiveVaultTimeout('onLocked', 'lock', available('onSystemLock', 0)))
      .toMatchObject({ lockTimeout: 'onLocked', idleSeconds: null, lockOnSystemLock: true, mode: 'systemLock' });
    expect(resolveEffectiveVaultTimeout('15', 'lock', available('onSystemLock', 0)))
      .toMatchObject({ lockTimeout: '15', idleSeconds: 900, lockOnSystemLock: false, mode: 'local' });
    expect(resolveEffectiveVaultTimeout('15', 'lock', available('onAppRestart', 0, 'logOut')))
      .toMatchObject({ lockTimeout: '15', onIdleAction: 'logout', logoutOnBrowserClose: true, closeLogoutActionProvenance: 'policy', closeLogoutTimeoutProvenance: 'policy' });
  });

  it.each([
    ['onAppRestart', 0],
    ['onSystemLock', 0],
    ['custom', 30],
    [null, 30],
  ] as const)('retains the latent %s policy timeout provenance while local numeric is stricter', (type, minutes) => {
    expect(resolveEffectiveVaultTimeout('1', 'logout', available(type, minutes))).toMatchObject({
      logoutOnBrowserClose: true,
      closeLogoutActionProvenance: 'local',
      closeLogoutTimeoutProvenance: 'policy',
    });
  });

  it('keeps policy restart ownership when local timeout changes to never', () => {
    expect(resolveEffectiveVaultTimeout('never', 'logout', available('onAppRestart', 0))).toMatchObject({
      lockTimeout: 'onClose',
      logoutOnBrowserClose: true,
      closeLogoutActionProvenance: 'local',
      closeLogoutTimeoutProvenance: 'policy',
    });
  });

  it('treats never as no timeout restriction while retaining a forced action', () => {
    expect(resolveEffectiveVaultTimeout('never', 'lock', available('never', 0, 'logOut')))
      .toEqual({ lockTimeout: 'never', onIdleAction: 'logout', idleSeconds: null, lockOnSystemLock: false, logoutOnBrowserClose: false, closeLogoutActionProvenance: null, closeLogoutTimeoutProvenance: null, mode: 'local', managed: true, failClosed: false });
    expect(resolveEffectiveVaultTimeout('never', 'lock', available('never', 0)))
      .toEqual({ lockTimeout: 'never', onIdleAction: 'lock', idleSeconds: null, lockOnSystemLock: false, logoutOnBrowserClose: false, closeLogoutActionProvenance: null, closeLogoutTimeoutProvenance: null, mode: 'local', managed: false, failClosed: false });
  });

  it('fails closed to immediate logout for malformed or unavailable policy state', () => {
    expect(resolveEffectiveVaultTimeout('never', 'lock', { kind: 'unavailable' }))
      .toEqual({ lockTimeout: '1', onIdleAction: 'logout', idleSeconds: 0, lockOnSystemLock: true, logoutOnBrowserClose: true, closeLogoutActionProvenance: 'fail_closed', closeLogoutTimeoutProvenance: 'fail_closed', mode: 'immediate', managed: true, failClosed: true });
    const malformed = available('custom', 15) as { kind: 'available'; policy: EffectiveMaximumVaultTimeoutPolicy };
    malformed.policy = { ...malformed.policy, malformed: true };
    expect(resolveEffectiveVaultTimeout('never', 'lock', malformed).failClosed).toBe(true);
  });

  it('fails closed for a forged policy shape even when TypeScript types are bypassed', () => {
    const forged = { kind: 'available', policy: { malformed: false, data: { type: 'custom', minutes: Number.NaN, action: 'lock' } } };
    expect(resolveEffectiveVaultTimeout('15', 'lock', forged as never).failClosed).toBe(true);
    expect(resolveEffectiveVaultTimeout('15', 'lock', available('custom', 43_201)).failClosed).toBe(true);
    expect(resolveEffectiveVaultTimeout('bogus' as never, 'lock', { kind: 'available', policy: null }).failClosed)
      .toBe(true);
  });
});

describe('isVaultTimeoutSelectionAllowed', () => {
  it('accepts equal or stricter numeric choices and rejects wider or special choices', () => {
    const policy = available('custom', 10, 'lock');
    expect(isVaultTimeoutSelectionAllowed('5', 'lock', policy)).toBe(true);
    expect(isVaultTimeoutSelectionAllowed('15', 'lock', policy)).toBe(false);
    expect(isVaultTimeoutSelectionAllowed('never', 'lock', policy)).toBe(false);
    expect(isVaultTimeoutSelectionAllowed('immediate', 'lock', policy)).toBe(true);
    expect(isVaultTimeoutSelectionAllowed('onLocked', 'lock', policy)).toBe(false);
  });

  it('accepts local immediate, system-lock, and custom modes when no policy changes their behavior', () => {
    const none = { kind: 'available', policy: null } as const;
    expect(isVaultTimeoutSelectionAllowed('immediate', 'lock', none)).toBe(true);
    expect(isVaultTimeoutSelectionAllowed('onLocked', 'logout', none)).toBe(true);
    expect(isVaultTimeoutSelectionAllowed('37', 'lock', none)).toBe(true);
    expect(isVaultTimeoutValueAllowed('immediate', none)).toBe(true);
    expect(isVaultTimeoutValueAllowed('onLocked', none)).toBe(true);
  });

  it('compares full special-mode behavior when a system-lock policy applies', () => {
    const policy = available('onSystemLock', 0);
    expect(isVaultTimeoutSelectionAllowed('immediate', 'lock', policy)).toBe(true);
    expect(isVaultTimeoutSelectionAllowed('5', 'lock', policy)).toBe(true);
    expect(isVaultTimeoutSelectionAllowed('onLocked', 'lock', policy)).toBe(true);
    expect(isVaultTimeoutSelectionAllowed('onClose', 'lock', policy)).toBe(false);
    expect(isVaultTimeoutValueAllowed('onLocked', policy)).toBe(true);
    expect(isVaultTimeoutValueAllowed('onClose', policy)).toBe(false);
  });

  it('rejects the wrong action and every choice under fail-closed state', () => {
    expect(isVaultTimeoutSelectionAllowed('5', 'lock', available('custom', 10, 'logOut'))).toBe(false);
    expect(isVaultTimeoutSelectionAllowed('1', 'logout', { kind: 'unavailable' })).toBe(false);
  });

  it('validates independently written timeout and action fields without coupling stale local values', () => {
    const policy = available('custom', 10, 'logOut');
    expect(isVaultTimeoutValueAllowed('5', policy)).toBe(true);
    expect(isVaultTimeoutValueAllowed('10', policy)).toBe(true);
    expect(isVaultTimeoutValueAllowed('11', policy)).toBe(false);
    expect(isVaultTimeoutValueAllowed('15', policy)).toBe(false);
    expect(isVaultTimeoutActionAllowed('logout', policy)).toBe(true);
    expect(isVaultTimeoutActionAllowed('lock', policy)).toBe(false);
  });
});

describe('isLocalCloseLogoutEnabled', () => {
  it('tracks only the persisted local close/logout preference', () => {
    expect(isLocalCloseLogoutEnabled('15', 'logout')).toBe(true);
    expect(isLocalCloseLogoutEnabled('onClose', 'logout')).toBe(true);
    expect(isLocalCloseLogoutEnabled('onLocked', 'logout')).toBe(true);
    expect(isLocalCloseLogoutEnabled('immediate', 'logout')).toBe(true);
    expect(isLocalCloseLogoutEnabled('never', 'logout')).toBe(false);
    expect(isLocalCloseLogoutEnabled('15', 'lock')).toBe(false);
  });

  it('detects an actually persisted partial security write without treating clipboard-only writes as timeout changes', () => {
    const before = ['15', 'logout'] as const;
    const clipboardOnly = ['15', 'logout'] as const;
    const actionCommittedBeforeClipboardFailure = ['15', 'lock'] as const;
    const timeoutCommitted = ['never', 'logout'] as const;

    expect(didLocalVaultTimeoutSettingsChange(before, clipboardOnly)).toBe(false);
    expect(localCloseLogoutOwnerClear(before, clipboardOnly)).toEqual({ action: false, timeout: false });
    expect(didLocalVaultTimeoutSettingsChange(before, actionCommittedBeforeClipboardFailure)).toBe(true);
    expect(localCloseLogoutOwnerClear(before, actionCommittedBeforeClipboardFailure))
      .toEqual({ action: true, timeout: false });
    expect(localCloseLogoutOwnerClear(before, timeoutCommitted))
      .toEqual({ action: false, timeout: true });
  });
});
