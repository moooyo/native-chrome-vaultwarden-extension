import { describe, expect, it, vi } from 'vitest';
import type { SessionTransitionEvent } from '../core/session/auth-service.js';
import {
  applyEnterprisePolicySideEffects,
  invalidatesEnterprisePolicy,
} from './enterprise-policy-lifecycle.js';

describe('enterprise policy transition lifecycle', () => {
  it.each([
    'login',
    'switchAccount',
    'logout',
    'removeAccount',
    'serverChange',
    'keyRotation',
  ] satisfies SessionTransitionEvent['reason'][])(
    'revokes policy state before a %s identity transition',
    (reason) => expect(invalidatesEnterprisePolicy(reason)).toBe(true),
  );

  it.each([
    'lock',
    'unlock',
    'pinUnlock',
  ] satisfies SessionTransitionEvent['reason'][])(
    'retains raw policy state across a %s session-only transition',
    (reason) => expect(invalidatesEnterprisePolicy(reason)).toBe(false),
  );

  it('applies vault timeout before isolating every secondary cleanup failure', async () => {
    const events: string[] = [];
    const warn = vi.fn();
    await applyEnterprisePolicySideEffects({
      applyVaultTimeout: async () => { events.push('timeout'); },
      invalidateAutofill: () => { events.push('invalidate'); },
      clearPendingSaves: async () => { events.push('pending'); throw new Error('pending failed'); },
      clearUsernameStages: async () => { events.push('username'); },
      enforceSessionPolicy: async () => { events.push('session'); throw new Error('PIN cleanup failed'); },
      refreshIdleDetection: async () => { events.push('idle'); },
      refreshAutofill: async () => { events.push('autofill'); },
      refreshContextMenu: async () => { events.push('menu'); },
      warn,
    });

    expect(events[0]).toBe('timeout');
    expect(events).toEqual(expect.arrayContaining([
      'invalidate', 'pending', 'username', 'session', 'idle', 'autofill', 'menu',
    ]));
    expect(warn).toHaveBeenCalledWith('clearPendingSaves', expect.any(Error));
    expect(warn).toHaveBeenCalledWith('enforceSessionPolicy', expect.any(Error));
  });

  it('does not run secondary effects when the timeout policy cannot be applied', async () => {
    const secondary = vi.fn();
    await expect(applyEnterprisePolicySideEffects({
      applyVaultTimeout: async () => { throw new Error('timeout failed'); },
      invalidateAutofill: secondary,
      clearPendingSaves: secondary,
      clearUsernameStages: secondary,
      enforceSessionPolicy: secondary,
      refreshIdleDetection: secondary,
      refreshAutofill: secondary,
      refreshContextMenu: secondary,
      warn: vi.fn(),
    })).rejects.toThrow('timeout failed');
    expect(secondary).not.toHaveBeenCalled();
  });
});
