import { describe, expect, it, vi } from 'vitest';
import {
  TOOLBAR_BADGE_COLORS,
  TOOLBAR_ICON_PATHS,
  ToolbarStateController,
  composeToolbarState,
  reduceToolbarAuthTransition,
  type ToolbarAuthTransitionState,
  type ToolbarActionApi,
} from './toolbar-state.js';

const COPY = Object.freeze({
  unlocked: 'MiYu',
  locked: 'MiYu - Locked',
  signedOut: 'MiYu - Signed out',
  pendingApprovals: (count: number) => `${count} pending device approvals`,
  matchingLogins: (count: number) => `${count} matching logins`,
});

function compose(input: Omit<Parameters<typeof composeToolbarState>[0], 'copy'>) {
  return composeToolbarState({ ...input, copy: COPY });
}

function state(input: Omit<Parameters<ToolbarStateController['apply']>[0], 'copy'>) {
  return { ...input, copy: COPY };
}

function actionApi(overrides: Partial<ToolbarActionApi> = {}): ToolbarActionApi {
  return {
    setIcon: vi.fn(async () => undefined),
    setBadgeText: vi.fn(async () => undefined),
    setBadgeBackgroundColor: vi.fn(async () => undefined),
    setTitle: vi.fn(async () => undefined),
    ...overrides,
  };
}

describe('composeToolbarState', () => {
  it('uses active-account auth state for the icon', () => {
    expect(compose({ authState: 'loggedOut' }).iconKind).toBe('neutral');
    expect(compose({ authState: 'locked' }).iconKind).toBe('locked');
    expect(compose({ authState: 'restricted' }).iconKind).toBe('locked');
    expect(compose({ authState: 'unlocked' }).iconKind).toBe('unlocked');
  });

  it('shows approvals while locked and gives them priority over matching logins', () => {
    expect(compose({
      authState: 'locked',
      pendingApprovalCount: 2,
      matchingLoginCount: 8,
      showMatchingLoginCount: true,
    })).toEqual({
      iconKind: 'locked',
      icon: TOOLBAR_ICON_PATHS.locked,
      badgeText: '2',
      badgeBackgroundColor: TOOLBAR_BADGE_COLORS.approvals,
      title: 'MiYu - Locked - 2 pending device approvals',
    });
    expect(compose({
      authState: 'unlocked',
      pendingApprovalCount: 3,
      matchingLoginCount: 7,
      showMatchingLoginCount: true,
    }).badgeText).toBe('3');
  });

  it('shows matching logins only while unlocked and caps their text at 9+', () => {
    expect(compose({
      authState: 'unlocked',
      matchingLoginCount: 12,
      showMatchingLoginCount: true,
    })).toMatchObject({
      badgeText: '9+',
      badgeBackgroundColor: TOOLBAR_BADGE_COLORS.matches,
      title: 'MiYu - 12 matching logins',
    });
    expect(compose({
      authState: 'locked', matchingLoginCount: 4, showMatchingLoginCount: true,
    }).badgeText).toBe('');
    expect(compose({
      authState: 'unlocked', matchingLoginCount: 4, showMatchingLoginCount: false,
    }).badgeText).toBe('');
  });

  it('suppresses every contribution without an active account and caps approvals at 99+', () => {
    expect(compose({ authState: 'loggedOut', pendingApprovalCount: 8 })).toMatchObject({
      badgeText: '',
      title: 'MiYu - Signed out',
    });
    expect(compose({ authState: 'locked', pendingApprovalCount: 120 }).badgeText)
      .toBe('99+');
    expect(compose({ authState: 'restricted', pendingApprovalCount: 2 }).badgeText).toBe('');
  });
});

describe('ToolbarStateController', () => {
  it('is the single four-field writer and targets an exact tab', async () => {
    const action = actionApi();
    const controller = new ToolbarStateController({ action });
    await controller.apply(state({
      authState: 'unlocked', matchingLoginCount: 2, showMatchingLoginCount: true,
    }), 7);

    expect(action.setIcon).toHaveBeenCalledWith({ path: TOOLBAR_ICON_PATHS.unlocked, tabId: 7 });
    expect(action.setBadgeText).toHaveBeenCalledWith({ text: '2', tabId: 7 });
    expect(action.setBadgeBackgroundColor).toHaveBeenCalledWith({
      color: TOOLBAR_BADGE_COLORS.matches,
      tabId: 7,
    });
    expect(action.setTitle).toHaveBeenCalledWith({ title: 'MiYu - 2 matching logins', tabId: 7 });
  });

  it('deduplicates an already committed state', async () => {
    const action = actionApi();
    const controller = new ToolbarStateController({ action });
    const input = state({ authState: 'locked' as const, pendingApprovalCount: 1 });
    await controller.apply(input);
    await controller.apply(input);
    expect(action.setIcon).toHaveBeenCalledOnce();
    expect(action.setBadgeText).toHaveBeenCalledOnce();
  });

  it('serializes an A to B to A race so the final write is the newest A', async () => {
    let release!: () => void;
    const first = new Promise<void>((resolve) => { release = resolve; });
    const badgeWrites: string[] = [];
    const action = actionApi({
      setIcon: vi.fn()
        .mockImplementationOnce(() => first)
        .mockResolvedValue(undefined),
      setBadgeText: vi.fn(async ({ text }) => { badgeWrites.push(text); }),
    });
    const controller = new ToolbarStateController({ action });
    const a1 = controller.apply(state({ authState: 'locked', pendingApprovalCount: 1 }));
    await vi.waitFor(() => expect(action.setIcon).toHaveBeenCalledOnce());
    const b = controller.apply(state({ authState: 'unlocked', matchingLoginCount: 2, showMatchingLoginCount: true }));
    const a2 = controller.apply(state({ authState: 'locked', pendingApprovalCount: 1 }));
    release();
    await Promise.all([a1, b, a2]);

    expect(badgeWrites.at(-1)).toBe('1');
    expect(action.setBadgeText).toHaveBeenLastCalledWith({ text: '1' });
  });

  it('forgets queued writes for a removed tab', async () => {
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    const action = actionApi({ setIcon: vi.fn(() => blocked) });
    const controller = new ToolbarStateController({ action });
    const global = controller.apply(state({ authState: 'unlocked' }));
    await vi.waitFor(() => expect(action.setIcon).toHaveBeenCalledOnce());
    const tab = controller.apply(state({ authState: 'unlocked', matchingLoginCount: 2, showMatchingLoginCount: true }), 9);
    controller.forgetTab(9);
    release();
    await Promise.all([global, tab]);

    expect(action.setBadgeText).toHaveBeenCalledOnce();
  });

  it('waits for every failed field before retrying and reports a fixed diagnostic', async () => {
    const logger = { warn: vi.fn() };
    const action = actionApi({
      setTitle: vi.fn().mockRejectedValueOnce(new Error('private browser error')).mockResolvedValue(undefined),
    });
    const controller = new ToolbarStateController({ action, logger });
    const input = state({ authState: 'locked' as const });
    await controller.apply(input);
    await controller.apply(input);

    expect(logger.warn).toHaveBeenCalledWith('toolbar_state_write_failed');
    expect(action.setTitle).toHaveBeenCalledTimes(2);
  });
});

describe('reduceToolbarAuthTransition', () => {
  it('rejects a late A settlement across an A to B to A transition sequence', () => {
    let current: ToolbarAuthTransitionState = { transitionId: 0, authState: 'unlocked' };
    const first = reduceToolbarAuthTransition(current, {
      phase: 'start', transitionId: 1, reason: 'lock', identityChanged: false,
    });
    expect(first).toMatchObject({ accepted: true, authState: 'locked', clearMatches: true });
    current = first;
    const second = reduceToolbarAuthTransition(current, {
      phase: 'start', transitionId: 2, reason: 'switchAccount', identityChanged: true,
    });
    expect(second).toMatchObject({ accepted: true, authState: 'loggedOut', clearApprovals: true });
    current = second;

    const staleFirstSettlement = reduceToolbarAuthTransition(current, {
      phase: 'settled', transitionId: 1, reason: 'lock', identityChanged: false,
      state: 'locked', succeeded: true,
    });
    expect(staleFirstSettlement.accepted).toBe(false);
    expect(staleFirstSettlement.transitionId).toBe(2);

    const currentSettlement = reduceToolbarAuthTransition(current, {
      phase: 'settled', transitionId: 2, reason: 'switchAccount', identityChanged: true,
      state: 'unlocked', succeeded: true,
    });
    expect(currentSettlement).toMatchObject({
      accepted: true,
      transitionId: 2,
      authState: 'unlocked',
      refreshMatches: true,
    });
  });
});
