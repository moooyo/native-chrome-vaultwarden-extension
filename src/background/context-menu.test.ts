import { describe, it, expect, vi } from 'vitest';
import {
  createContextMenu,
  parseContextMenuPlatformAction,
  shouldRefreshMenu,
} from './context-menu.js';
import type {
  ContextMenuActionCapabilities,
  ContextMenuFrame,
  ContextMenuPlatformActions,
} from './context-menu.js';
import type {
  FillItemCandidate,
  FillCommand,
  FillErrorCommand,
  HoldFillTargetCommand,
  CancelHeldFillTargetCommand,
  ReserveFillTargetCommand,
  CancelFillTargetCommand,
  ClaimContextLoginTargetCommand,
  ContextLoginTargetClaimResult,
  TabAutofillSuggestion,
  TabSuggestionTarget,
} from '../messaging/protocol.js';

const CLICKED_FRAME_URL = 'https://shop.example/checkout';
const CLICK_TIME = 1_000;
type ContextMenuMessage =
  | FillCommand
  | FillErrorCommand
  | ReserveFillTargetCommand
  | CancelFillTargetCommand
  | HoldFillTargetCommand
  | CancelHeldFillTargetCommand
  | ClaimContextLoginTargetCommand;
type LoginSuggestion = Extract<TabAutofillSuggestion, { kind: 'login' }>;

function loginSuggestion(id: string): LoginSuggestion {
  return {
    kind: 'login',
    id,
    name: id,
    matchedUri: CLICKED_FRAME_URL,
    matchType: 0,
    favorite: false,
    target: {
      kind: 'login',
      frameId: 0,
      documentId: 'doc-A',
      formId: 'login-form',
      generation: 1,
      customPlanDigest: '0'.repeat(64),
    },
  };
}

function deferred<Value>() {
  let resolve!: (value: Value) => void;
  const promise = new Promise<Value>((done) => { resolve = done; });
  return { promise, resolve };
}

function reservationRoles(command: ReserveFillTargetCommand) {
  if (command.scope === 'field') return command.kind === 'card' ? ['number'] : ['email'];
  return command.kind === 'card'
    ? ['number', 'exp', 'code']
    : ['firstName', 'lastName', 'address1'];
}

function makeDeps(
  state: 'loggedOut' | 'locked' | 'unlocked',
  cards: FillItemCandidate[] = [],
  identities: FillItemCandidate[] = [],
  logins: LoginSuggestion[] = [],
) {
  const created: Record<string, unknown>[] = [];
  const sent: Array<{
    id: number;
    msg: ContextMenuMessage;
    opts: { frameId?: number; documentId?: string } | undefined;
  }> = [];
  const session = { epoch: 1, accountEpoch: 1 };
  const vaultTimeout = {
    captureActivity: vi.fn(() => ({ generation: 1 })),
    recordActivity: vi.fn(async () => undefined),
  };
  const vaultReleaseGate = {
    capture: vi.fn((_sessionLease: number) => ({})),
    checkpoint: vi.fn(async (_lease: object) => ({})),
    assertAuthorities: vi.fn((_proof: object, assertCurrent: () => void) => assertCurrent()),
    assert: vi.fn((_proof: object) => undefined),
    settlePendingAction: vi.fn(async () => undefined),
  };
  const deps = {
    getState: vi.fn(async () => state),
    getActiveTabId: vi.fn(async () => 7),
    getTabSuggestions: vi.fn(async () => ({ status: 'ready' as const, suggestions: logins })),
    fillTabSuggestion: vi.fn(async (
      _tabId: number,
      _cipherId: string,
      _target: TabSuggestionTarget,
      _assertCurrent: () => void,
    ) => ({ status: 'filled' as const })),
    findFillItems: vi.fn(async (kind: 'card' | 'identity') => (kind === 'card' ? cards : identities)),
    getFillData: vi.fn(async (
      _cipherId: string,
      _kind: 'card' | 'identity',
      _roles: readonly string[],
      bindFinalAuthority?: (assertCurrent: () => void) => void,
    ) => {
      bindFinalAuthority?.(() => {});
      return { number: '4111' };
    }),
    authorizeFrame: vi.fn(async () => ({ assertCurrent: () => {}, defaultStrategy: 0 as const })),
    getFrame: vi.fn(async (_tabId: number, frameId: number): Promise<ContextMenuFrame | undefined> => ({
      frameId,
      url: CLICKED_FRAME_URL,
      documentId: 'doc-A',
    })),
    continuation: {
      stageLockedContext: vi.fn(async () => undefined),
      stageContextLoginReprompt: vi.fn(async () => undefined),
      stageContextStructuredReprompt: vi.fn(async () => undefined),
    },
    captureSessionLease: vi.fn(async () => session.epoch),
    isSessionLeaseCurrent: vi.fn(async (lease: number) => lease === session.epoch),
    assertSessionLease: vi.fn((lease: number) => {
      if (lease !== session.epoch) throw new Error('session changed');
    }),
    captureAccountLease: vi.fn(async () => session.accountEpoch),
    isAccountLeaseCurrent: vi.fn(async (lease: number) => lease === session.accountEpoch),
    assertAccountLease: vi.fn((lease: number) => {
      if (lease !== session.accountEpoch) throw new Error('account changed');
    }),
    vaultTimeout,
    vaultReleaseGate,
    menus: { removeAll: vi.fn(async () => {}), create: vi.fn((p: Record<string, unknown>) => { created.push(p); }) },
    tabs: {
      sendMessage: vi.fn(async (
        id: number,
        msg: ContextMenuMessage,
        opts?: { frameId?: number; documentId?: string },
      ): Promise<unknown> => {
        sent.push({ id, msg, opts });
        if (msg.type === 'autofill.reserveFillTarget') {
          return { status: 'reserved', roles: reservationRoles(msg) };
        }
        if (msg.type === 'autofill.holdFillTarget') return { status: 'held' };
        if (msg.type === 'autofill.claimContextLoginTarget') {
          const target = logins.find((login) => login.target)?.target;
          return {
            status: 'claimed',
            formId: target?.formId ?? 'login-form',
            generation: target?.generation ?? 1,
            customPlanDigest: target?.kind === 'login' ? target.customPlanDigest : '0'.repeat(64),
          } satisfies ContextLoginTargetClaimResult;
        }
        return msg.type === 'autofill.fill' ? { status: 'filled' } : undefined;
      }),
    },
  };
  return { deps, created, sent, session, vaultTimeout, vaultReleaseGate };
}

function attachPlatformActions(
  deps: ReturnType<typeof makeDeps>['deps'],
  capabilities: ContextMenuActionCapabilities,
  overrides: Partial<ContextMenuPlatformActions> = {},
) {
  const actions: ContextMenuPlatformActions = {
    getCapabilities: vi.fn(async () => capabilities),
    readLoginCopyValue: vi.fn(async (
      _cipherId,
      _field,
      bindFinalAuthority,
    ) => {
      bindFinalAuthority(() => undefined);
      return 'copied-value';
    }),
    generatePasswordAndTrack: vi.fn(async (bindFinalAuthority) => {
      bindFinalAuthority(() => undefined);
      return { value: 'Generated-42!' };
    }),
    clipboard: {
      writeSecretAndScheduleClear: vi.fn(async (_value, assertCurrent) => {
        assertCurrent();
        return true;
      }),
      writeTotpAndScheduleClear: vi.fn(async (_value, assertCurrent) => {
        assertCurrent();
        return true;
      }),
    },
    createCipher: vi.fn(async (_kind, _source, assertCurrent) => assertCurrent()),
    ...overrides,
  };
  Object.assign(deps, { actions });
  return actions;
}

describe('context menu', () => {
  it('parses only canonical platform action ids', () => {
    expect(parseContextMenuPlatformAction('vw-action|copy|password|cipher-1')).toEqual({
      kind: 'copy', field: 'password', cipherId: 'cipher-1',
    });
    expect(parseContextMenuPlatformAction('vw-action|generate-password')).toEqual({
      kind: 'generate-password',
    });
    expect(parseContextMenuPlatformAction('vw-action|create|identity')).toEqual({
      kind: 'create', cipherKind: 'identity',
    });
    expect(parseContextMenuPlatformAction('vw-action|copy|seed|cipher-1')).toBeUndefined();
    expect(parseContextMenuPlatformAction('vw-action|copy|password|cipher|extra')).toBeUndefined();
    expect(parseContextMenuPlatformAction('vw-action|create|folder')).toBeUndefined();
  });

  it('clears derived titles without reading gates, vault data, or rebuilding entries', async () => {
    const { deps, created } = makeDeps(
      'unlocked',
      [{ id: 'c1', name: 'Sensitive card title', favorite: false }],
    );

    await createContextMenu(deps).clearDerivedState();

    expect(deps.menus.removeAll).toHaveBeenCalledOnce();
    expect(deps.menus.create).not.toHaveBeenCalled();
    expect(deps.getState).not.toHaveBeenCalled();
    expect(deps.captureSessionLease).not.toHaveBeenCalled();
    expect(deps.captureAccountLease).not.toHaveBeenCalled();
    expect(deps.findFillItems).not.toHaveBeenCalled();
    expect(deps.getTabSuggestions).not.toHaveBeenCalled();
    expect(created).toHaveLength(0);
  });

  it('builds all-context copy, generate, and create actions behind capabilities', async () => {
    const login: LoginSuggestion = {
      ...loginSuggestion('login-1'),
      username: 'alice@example.com',
      hasTotp: true,
    };
    const fixture = makeDeps('unlocked', [], [], [login]);
    attachPlatformActions(fixture.deps, {
      copyUsername: true,
      copyPassword: true,
      copyTotp: true,
      generatePassword: true,
      createLogin: true,
      createCard: true,
      createIdentity: true,
    });

    await createContextMenu(fixture.deps).refresh(7);

    expect(fixture.created.find((item) => item.id === 'vw-root')?.contexts).toEqual(['all']);
    expect(fixture.created.find((item) => item.id === 'vw-login-form')?.contexts).toEqual(['editable']);
    expect(fixture.created.map((item) => item.id)).toEqual(expect.arrayContaining([
      'vw-copy-username',
      'vw-action|copy|username|login-1',
      'vw-copy-password',
      'vw-action|copy|password|login-1',
      'vw-copy-totp',
      'vw-action|copy|totp|login-1',
      'vw-action|generate-password',
      'vw-action|create|login',
      'vw-action|create|card',
      'vw-action|create|identity',
    ]));
  });

  it('builds only a generic unlock action when locked without reading vault names', async () => {
    const { deps, created } = makeDeps('locked', [{ id: 'c1', name: 'Visa', favorite: false }]);
    await createContextMenu(deps).refresh();
    expect(deps.menus.removeAll).toHaveBeenCalled();
    expect(created).toEqual([{ id: 'vw-unlock', title: 'Unlock MiYu', contexts: ['editable'] }]);
    expect(deps.findFillItems).not.toHaveBeenCalled();
    expect(deps.getTabSuggestions).not.toHaveBeenCalled();
  });

  it('stages the generic locked action from browser-owned documents without touching vault leases', async () => {
    const { deps } = makeDeps('locked', [{ id: 'secret', name: 'Do not expose', favorite: false }]);

    await createContextMenu(deps).handleClick(
      'vw-unlock',
      { id: 7, windowId: 3 },
      0,
      CLICKED_FRAME_URL,
      CLICK_TIME,
    );

    expect(deps.continuation.stageLockedContext).toHaveBeenCalledOnce();
    expect(deps.captureSessionLease).not.toHaveBeenCalled();
    expect(deps.findFillItems).not.toHaveBeenCalled();
  });

  it('builds root + form/field groups with one item per card/identity when unlocked', async () => {
    const { deps, created } = makeDeps('unlocked', [{ id: 'c1', name: 'Visa', favorite: false }], [{ id: 'i1', name: 'Ada', favorite: false }]);
    await createContextMenu(deps).refresh();
    const ids = created.map((c) => c.id);
    expect(ids).toContain('vw-root');
    // each card appears under a form-scope and a field-scope group:
    expect(ids).toContain('vw-fill|form|card|c1');
    expect(ids).toContain('vw-fill|field|card|c1');
    expect(ids).toContain('vw-fill|form|identity|i1');
    expect(ids).toContain('vw-fill|field|identity|i1');
  });

  it('builds a current-tab login group from metadata-only tab suggestions', async () => {
    const login: LoginSuggestion = {
      kind: 'login',
      id: 'l1',
      name: 'Acme account',
      username: 'alice',
      matchedUri: CLICKED_FRAME_URL,
      matchType: 0,
      favorite: false,
      target: {
        kind: 'login',
        frameId: 3,
        documentId: 'doc-A',
        formId: 'login-form',
        generation: 4,
        customPlanDigest: '0'.repeat(64),
      },
    };
    const { deps, created } = makeDeps('unlocked', [], [], [login]);

    await createContextMenu(deps).refresh(7);

    expect(created.map((item) => item.id)).toEqual([
      'vw-root',
      'vw-login-form',
      'vw-login|l1',
    ]);
    expect(deps.getTabSuggestions).toHaveBeenCalledWith(7);
  });

  it('escapes ampersands in browser context-menu item titles', async () => {
    const login: LoginSuggestion = {
      kind: 'login',
      id: 'l1',
      name: 'Research & Development',
      matchedUri: CLICKED_FRAME_URL,
      matchType: 0,
      favorite: false,
      target: {
        kind: 'login', frameId: 0, documentId: 'doc-A', formId: 'login-form',
        generation: 1, customPlanDigest: '0'.repeat(64),
      },
    };
    const { deps, created } = makeDeps(
      'unlocked',
      [{ id: 'c1', name: 'Cards & Billing', favorite: false }],
      [],
      [login],
    );

    await createContextMenu(deps).refresh(7);

    expect(created.find((item) => item.id === 'vw-login|l1')?.title)
      .toBe('Research && Development');
    expect(created.find((item) => item.id === 'vw-fill|form|card|c1')?.title)
      .toBe('Cards && Billing');
  });

  it('claims the trusted right-click target then delegates login fill to TabAutofill', async () => {
    const login: LoginSuggestion = {
      kind: 'login',
      id: 'l1',
      name: 'Acme account',
      matchedUri: CLICKED_FRAME_URL,
      matchType: 0,
      favorite: false,
      target: {
        kind: 'login',
        frameId: 3,
        documentId: 'doc-A',
        formId: 'login-form',
        generation: 4,
        customPlanDigest: '0'.repeat(64),
      },
    };
    const { deps, sent } = makeDeps('unlocked', [], [], [login]);

    await createContextMenu(deps).handleClick(
      'vw-login|l1',
      { id: 7 },
      3,
      CLICKED_FRAME_URL,
      CLICK_TIME,
    );

    expect(sent[0]).toEqual({
      id: 7,
      msg: {
        type: 'autofill.claimContextLoginTarget',
        expectedFrameUrl: CLICKED_FRAME_URL,
        contextMenuClickTime: CLICK_TIME,
      },
      opts: { frameId: 3, documentId: 'doc-A' },
    });
    expect(deps.fillTabSuggestion).toHaveBeenCalledWith(
      7,
      'l1',
      login.target,
      expect.any(Function),
    );
    expect(deps.getFillData).not.toHaveBeenCalled();
  });

  it('does not fill a login when the refreshed target belongs to another browser document', async () => {
    const login: LoginSuggestion = {
      kind: 'login',
      id: 'l1',
      name: 'Acme account',
      matchedUri: CLICKED_FRAME_URL,
      matchType: 0,
      favorite: false,
      target: {
        kind: 'login',
        frameId: 3,
        documentId: 'doc-B',
        formId: 'login-form',
        generation: 4,
        customPlanDigest: '0'.repeat(64),
      },
    };
    const { deps } = makeDeps('unlocked', [], [], [login]);

    await createContextMenu(deps).handleClick(
      'vw-login|l1',
      { id: 7 },
      3,
      CLICKED_FRAME_URL,
      CLICK_TIME,
    );

    expect(deps.fillTabSuggestion).not.toHaveBeenCalled();
    expect(deps.getFillData).not.toHaveBeenCalled();
  });

  it('does not retarget a login after the claimed form is deleted', async () => {
    const login: LoginSuggestion = {
      kind: 'login',
      id: 'l1',
      name: 'Acme account',
      matchedUri: CLICKED_FRAME_URL,
      matchType: 0,
      favorite: false,
    };
    const { deps } = makeDeps('unlocked', [], [], [login]);
    deps.tabs.sendMessage.mockImplementation(async (_id, message) => (
      message.type === 'autofill.claimContextLoginTarget'
        ? {
            status: 'claimed',
            formId: 'deleted-form',
            generation: 4,
            customPlanDigest: '0'.repeat(64),
          }
        : undefined
    ));

    await createContextMenu(deps).handleClick(
      'vw-login|l1',
      { id: 7 },
      3,
      CLICKED_FRAME_URL,
      CLICK_TIME,
    );

    expect(deps.fillTabSuggestion).not.toHaveBeenCalled();
    expect(deps.continuation.stageContextLoginReprompt).not.toHaveBeenCalled();
  });

  it('does not retarget a login when focus moves from claimed form A to suggestion form B', async () => {
    const login: LoginSuggestion = {
      kind: 'login',
      id: 'l1',
      name: 'Acme account',
      matchedUri: CLICKED_FRAME_URL,
      matchType: 0,
      favorite: false,
      target: {
        kind: 'login',
        frameId: 3,
        documentId: 'doc-A',
        formId: 'form-b',
        generation: 5,
        customPlanDigest: '1'.repeat(64),
      },
    };
    const { deps } = makeDeps('unlocked', [], [], [login]);
    deps.tabs.sendMessage.mockImplementation(async (_id, message) => (
      message.type === 'autofill.claimContextLoginTarget'
        ? {
            status: 'claimed',
            formId: 'form-a',
            generation: 4,
            customPlanDigest: '0'.repeat(64),
          }
        : undefined
    ));

    await createContextMenu(deps).handleClick(
      'vw-login|l1',
      { id: 7 },
      3,
      CLICKED_FRAME_URL,
      CLICK_TIME,
    );

    expect(deps.fillTabSuggestion).not.toHaveBeenCalled();
    expect(deps.continuation.stageContextLoginReprompt).not.toHaveBeenCalled();
  });

  it('marks reprompt items with a lock and omits empty kinds', async () => {
    const { deps, created } = makeDeps('unlocked', [{ id: 'c1', name: 'Amex', favorite: false, reprompt: true }], []);
    await createContextMenu(deps).refresh();
    const item = created.find((c) => c.id === 'vw-fill|form|card|c1');
    expect(item!.title).toContain('Amex');
    expect(item!.title).toContain('🔒');
    // no identity group when there are no identities
    expect(created.some((c) => c.id === 'vw-identity-form')).toBe(false);
  });

  it.each([
    ['session', (session: { epoch: number; accountEpoch: number }) => { session.epoch += 1; }],
    ['account', (session: { epoch: number; accountEpoch: number }) => { session.accountEpoch += 1; }],
  ] as const)('does not rebuild stale item names when the %s changes during candidate loading', async (_label, invalidate) => {
    const { deps, created, session } = makeDeps(
      'unlocked',
      [{ id: 'c1', name: 'Old account card', favorite: false }],
    );
    deps.findFillItems.mockImplementation(async (kind: 'card' | 'identity') => {
      if (kind === 'card') invalidate(session);
      return kind === 'card' ? [{ id: 'c1', name: 'Old account card', favorite: false }] : [];
    });

    await createContextMenu(deps).refresh();

    expect(deps.menus.removeAll).toHaveBeenCalledOnce();
    expect(created).toHaveLength(0);
  });

  it('settles a timeout action when a refresh preflight lease is no longer current', async () => {
    const { deps, vaultReleaseGate } = makeDeps('unlocked');
    deps.isSessionLeaseCurrent.mockResolvedValue(false);

    await createContextMenu(deps).refresh();

    expect(vaultReleaseGate.settlePendingAction).toHaveBeenCalledOnce();
  });

  it('settles a timeout action when a click document preflight returns early', async () => {
    const { deps, vaultReleaseGate } = makeDeps('unlocked');
    deps.isSessionLeaseCurrent.mockResolvedValue(false);

    await createContextMenu(deps).handleClick(
      'vw-fill|field|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME,
    );

    expect(vaultReleaseGate.settlePendingAction).toHaveBeenCalledOnce();
  });

  it('copies a login value only through the owned-clear clipboard boundary', async () => {
    const fixture = makeDeps('unlocked', [], [], [{
      ...loginSuggestion('login-1'), username: 'alice@example.com',
    }]);
    const itemAuthority = vi.fn();
    const actions = attachPlatformActions(fixture.deps, { copyUsername: true }, {
      readLoginCopyValue: vi.fn(async (_cipherId, _field, bindFinalAuthority) => {
        bindFinalAuthority(itemAuthority);
        return 'alice@example.com';
      }),
    });

    await createContextMenu(fixture.deps).handleClick(
      'vw-action|copy|username|login-1',
      { id: 7, windowId: 4 },
      0,
      CLICKED_FRAME_URL,
      CLICK_TIME,
    );

    expect(actions.readLoginCopyValue).toHaveBeenCalledWith(
      'login-1',
      'username',
      expect.any(Function),
    );
    expect(actions.clipboard.writeSecretAndScheduleClear).toHaveBeenCalledWith(
      'alice@example.com',
      expect.any(Function),
    );
    expect(itemAuthority).toHaveBeenCalled();
    expect(fixture.vaultTimeout.recordActivity).toHaveBeenCalledOnce();
  });

  it('keeps TOTP copy on the dedicated constrained clipboard channel', async () => {
    const fixture = makeDeps('unlocked', [], [], [{
      ...loginSuggestion('login-1'), hasTotp: true,
    }]);
    const actions = attachPlatformActions(fixture.deps, { copyTotp: true }, {
      readLoginCopyValue: vi.fn(async (_cipherId, _field, bindFinalAuthority) => {
        bindFinalAuthority(() => undefined);
        return '123456';
      }),
    });

    await createContextMenu(fixture.deps).handleClick(
      'vw-action|copy|totp|login-1',
      { id: 7, windowId: 4 },
      0,
      CLICKED_FRAME_URL,
      CLICK_TIME,
    );

    expect(actions.clipboard.writeTotpAndScheduleClear).toHaveBeenCalledWith(
      '123456',
      expect.any(Function),
    );
    expect(actions.clipboard.writeSecretAndScheduleClear).not.toHaveBeenCalled();
  });

  it('rechecks the capability at click time before reading a copy value', async () => {
    const fixture = makeDeps('unlocked');
    const actions = attachPlatformActions(fixture.deps, { copyPassword: false });

    await createContextMenu(fixture.deps).handleClick(
      'vw-action|copy|password|login-1',
      { id: 7, windowId: 4 },
      0,
      CLICKED_FRAME_URL,
      CLICK_TIME,
    );

    expect(actions.readLoginCopyValue).not.toHaveBeenCalled();
    expect(actions.clipboard.writeSecretAndScheduleClear).not.toHaveBeenCalled();
    expect(actions.clipboard.writeTotpAndScheduleClear).not.toHaveBeenCalled();
  });

  it('does not copy a stale cipher that no longer matches the clicked page', async () => {
    const fixture = makeDeps('unlocked', [], [], [loginSuggestion('login-1')]);
    const actions = attachPlatformActions(fixture.deps, { copyPassword: true });
    fixture.deps.getTabSuggestions.mockResolvedValueOnce({ status: 'ready', suggestions: [] });

    await createContextMenu(fixture.deps).handleClick(
      'vw-action|copy|password|login-1',
      { id: 7, windowId: 4 },
      0,
      CLICKED_FRAME_URL,
      CLICK_TIME,
    );

    expect(actions.readLoginCopyValue).not.toHaveBeenCalled();
    expect(actions.clipboard.writeSecretAndScheduleClear).not.toHaveBeenCalled();
  });

  it('stages password-copy reprompt without writing a secret', async () => {
    const fixture = makeDeps('unlocked', [], [], [loginSuggestion('login-1')]);
    const actions = attachPlatformActions(fixture.deps, { copyPassword: true }, {
      readLoginCopyValue: vi.fn(async () => {
        throw Object.assign(new Error('reprompt'), { code: 'reprompt_required' });
      }),
    });
    const stageContextCopyReprompt = vi.fn(async () => undefined);
    Object.assign(fixture.deps.continuation, { stageContextCopyReprompt });

    await createContextMenu(fixture.deps).handleClick(
      'vw-action|copy|password|login-1',
      { id: 7, windowId: 4 },
      0,
      CLICKED_FRAME_URL,
      CLICK_TIME,
    );

    expect(actions.clipboard.writeSecretAndScheduleClear).not.toHaveBeenCalled();
    expect(actions.clipboard.writeTotpAndScheduleClear).not.toHaveBeenCalled();
    expect(stageContextCopyReprompt).toHaveBeenCalledWith(
      expect.objectContaining({
        tabId: 7,
        windowId: 4,
        frameId: 0,
        frameDocumentId: 'doc-A',
        frameUrl: CLICKED_FRAME_URL,
      }),
      'login-1',
      'password',
    );
  });

  it('generates through the shared adapter before owned-clear copy', async () => {
    const fixture = makeDeps('unlocked');
    const actions = attachPlatformActions(fixture.deps, { generatePassword: true });

    await createContextMenu(fixture.deps).handleClick(
      'vw-action|generate-password',
      { id: 7, windowId: 4 },
      0,
      CLICKED_FRAME_URL,
      CLICK_TIME,
    );

    expect(actions.generatePasswordAndTrack).toHaveBeenCalledOnce();
    expect(actions.clipboard.writeSecretAndScheduleClear).toHaveBeenCalledWith(
      'Generated-42!',
      expect.any(Function),
    );
  });

  it('delegates create actions with the browser-owned source and authority callback', async () => {
    const fixture = makeDeps('unlocked');
    const actions = attachPlatformActions(fixture.deps, { createIdentity: true });

    await createContextMenu(fixture.deps).handleClick(
      'vw-action|create|identity',
      { id: 7, windowId: 4 },
      0,
      CLICKED_FRAME_URL,
      CLICK_TIME,
    );

    expect(actions.createCipher).toHaveBeenCalledWith(
      'identity',
      expect.objectContaining({ tabId: 7, windowId: 4, frameDocumentId: 'doc-A' }),
      expect.any(Function),
    );
  });

  it('on click: fetches fill data and sends a fill command to the clicked frame', async () => {
    const { deps, sent } = makeDeps('unlocked', [{ id: 'c1', name: 'Visa', favorite: false }]);
    await createContextMenu(deps).handleClick('vw-fill|field|card|c1', { id: 7 }, 3, CLICKED_FRAME_URL, CLICK_TIME);
    expect(deps.getFillData).toHaveBeenCalledWith('c1', 'card', ['number'], expect.any(Function));
    expect(deps.getFrame).toHaveBeenNthCalledWith(1, 7, 3);
    expect(deps.getFrame).toHaveBeenNthCalledWith(2, 7, 3);
    expect(deps.getFrame).toHaveBeenNthCalledWith(3, 7, 3);
    const reserve = sent[0]!.msg;
    const fill = sent[1]!.msg;
    expect(reserve).toEqual({
      type: 'autofill.reserveFillTarget',
      reservationId: expect.any(String),
      scope: 'field',
      kind: 'card',
      expectedFrameUrl: CLICKED_FRAME_URL,
      contextMenuClickTime: CLICK_TIME,
    });
    if (reserve.type !== 'autofill.reserveFillTarget') throw new Error('expected reserve command');
    expect(sent[1]).toEqual({
      id: 7,
      msg: {
        type: 'autofill.fill',
        reservationId: reserve.reservationId,
        scope: 'field',
        kind: 'card',
        roles: ['number'],
        data: { number: '4111' },
        expectedFrameUrl: CLICKED_FRAME_URL,
      },
      opts: { frameId: 3, documentId: 'doc-A' },
    });
    expect(fill.type).toBe('autofill.fill');
  });

  it('waits for a successful target reservation before reading fill data', async () => {
    const { deps } = makeDeps('unlocked');
    let resolveReservation!: (value: { status: 'reserved'; roles: ['number'] }) => void;
    const reservationGate = new Promise<{ status: 'reserved'; roles: ['number'] }>((resolve) => { resolveReservation = resolve; });
    deps.tabs.sendMessage.mockImplementation(async (_id: number, message: ContextMenuMessage) => {
      if (message.type === 'autofill.reserveFillTarget') return reservationGate;
      return undefined;
    });

    const pending = createContextMenu(deps)
      .handleClick('vw-fill|field|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);
    await vi.waitFor(() => expect(deps.tabs.sendMessage).toHaveBeenCalledOnce());
    expect(deps.getFillData).not.toHaveBeenCalled();

    resolveReservation({ status: 'reserved', roles: ['number'] });
    await pending;
    expect(deps.getFillData).toHaveBeenCalledOnce();
  });

  it('canonicalizes the reserved form roles before reading or delivering secrets', async () => {
    const { deps } = makeDeps('unlocked');
    deps.tabs.sendMessage.mockResolvedValueOnce({
      status: 'reserved',
      roles: ['code', 'number', 'code', 'exp'],
    });

    await createContextMenu(deps)
      .handleClick('vw-fill|form|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);

    expect(deps.getFillData).toHaveBeenCalledWith(
      'c1', 'card', ['number', 'exp', 'code'], expect.any(Function),
    );
    const fill = deps.tabs.sendMessage.mock.calls
      .map((call) => call[1] as ContextMenuMessage)
      .find((message) => message.type === 'autofill.fill');
    expect(fill).toMatchObject({
      type: 'autofill.fill',
      kind: 'card',
      scope: 'form',
      roles: ['number', 'exp', 'code'],
    });
  });

  it.each([
    ['missing roles', { status: 'reserved' }],
    ['empty roles', { status: 'reserved', roles: [] }],
    ['non-array roles', { status: 'reserved', roles: 'number' }],
    ['wrong-kind roles', { status: 'reserved', roles: ['email'] }],
    ['unknown roles', { status: 'reserved', roles: ['cardSecret'] }],
    ['too many raw roles', { status: 'reserved', roles: Array.from({ length: 17 }, () => 'number') }],
    ['more than one field role', { status: 'reserved', roles: ['number', 'code'] }],
  ])('rejects a forged field reservation with %s before reading secrets', async (_label, response) => {
    const { deps } = makeDeps('unlocked');
    deps.tabs.sendMessage.mockResolvedValueOnce(response);

    await createContextMenu(deps)
      .handleClick('vw-fill|field|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);

    expect(deps.getFillData).not.toHaveBeenCalled();
    expect(deps.authorizeFrame).not.toHaveBeenCalled();
    expect(deps.tabs.sendMessage.mock.calls.map((call) => (call[1] as ContextMenuMessage).type))
      .toEqual(['autofill.reserveFillTarget', 'autofill.cancelFillTarget']);
  });

  it('cancels a refused reservation without reading fill data', async () => {
    const { deps } = makeDeps('unlocked');
    deps.tabs.sendMessage.mockResolvedValueOnce({ status: 'no_target' });

    await createContextMenu(deps)
      .handleClick('vw-fill|field|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);

    expect(deps.getFillData).not.toHaveBeenCalled();
    expect(deps.tabs.sendMessage.mock.calls.map((call) => (call[1] as ContextMenuMessage).type))
      .toEqual(['autofill.reserveFillTarget', 'autofill.cancelFillTarget']);
  });

  it('records activity only when the content frame confirms a structured fill', async () => {
    const { deps, vaultTimeout } = makeDeps(
      'unlocked',
      [{ id: 'c1', name: 'Card', favorite: false }],
    );
    await createContextMenu(deps)
      .handleClick('vw-fill|field|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);
    expect(vaultTimeout.recordActivity).toHaveBeenCalledOnce();

    vaultTimeout.recordActivity.mockClear();
    deps.tabs.sendMessage
      .mockResolvedValueOnce({ status: 'reserved', roles: ['number'] })
      .mockResolvedValueOnce({ status: 'target_changed' });
    await createContextMenu(deps)
      .handleClick('vw-fill|field|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);
    expect(vaultTimeout.recordActivity).not.toHaveBeenCalled();
  });

  it('asserts the original session lease synchronously before sending structured secrets', async () => {
    const { deps, sent, vaultTimeout } = makeDeps('unlocked');
    let expired = false;
    deps.getFillData.mockImplementationOnce(async () => {
      expired = true;
      return { number: '4111' };
    });
    deps.assertSessionLease.mockImplementation((lease: number) => {
      if (expired || lease !== 1) throw new Error('session timed out');
    });

    await createContextMenu(deps)
      .handleClick('vw-fill|field|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);

    expect(sent.map(({ msg }) => msg.type)).toEqual([
      'autofill.reserveFillTarget',
      'autofill.cancelFillTarget',
    ]);
    expect(vaultTimeout.recordActivity).not.toHaveBeenCalled();
  });

  it('withholds structured secrets when the durable release checkpoint fails', async () => {
    const { deps, sent, vaultReleaseGate } = makeDeps('unlocked');
    vaultReleaseGate.checkpoint.mockRejectedValueOnce(new Error('checkpoint unavailable'));

    await createContextMenu(deps)
      .handleClick('vw-fill|field|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);

    expect(sent.map(({ msg }) => msg.type)).toEqual([
      'autofill.reserveFillTarget',
      'autofill.cancelFillTarget',
    ]);
    expect(vaultReleaseGate.assert).not.toHaveBeenCalled();
    expect(vaultReleaseGate.settlePendingAction).toHaveBeenCalledOnce();
  });

  it('rechecks original document and enterprise item authority after the checkpoint await', async () => {
    const { deps, sent, vaultReleaseGate } = makeDeps('unlocked');
    let itemAuthorized = true;
    deps.getFillData.mockImplementationOnce(async (
      _cipherId: string,
      _kind: 'card' | 'identity',
      _roles: readonly string[],
      bindFinalAuthority?: (assertCurrent: () => void) => void,
    ) => {
      bindFinalAuthority?.(() => {
        if (!itemAuthorized) throw new Error('item policy changed');
      });
      return { number: '4111' };
    });
    const pending = deferred<object>();
    vaultReleaseGate.checkpoint.mockImplementationOnce(() => pending.promise);
    const fill = createContextMenu(deps)
      .handleClick('vw-fill|field|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);
    await vi.waitFor(() => expect(vaultReleaseGate.checkpoint).toHaveBeenCalledOnce());
    itemAuthorized = false;
    pending.resolve({});
    await fill;

    expect(vaultReleaseGate.assertAuthorities).toHaveBeenCalledOnce();
    expect(vaultReleaseGate.assert).not.toHaveBeenCalled();
    expect(sent.map(({ msg }) => msg.type)).toEqual([
      'autofill.reserveFillTarget',
      'autofill.cancelFillTarget',
    ]);
  });

  it('asserts the original session lease in the final login fill callback', async () => {
    const login: LoginSuggestion = {
      kind: 'login',
      id: 'l1',
      name: 'Acme account',
      matchedUri: CLICKED_FRAME_URL,
      matchType: 0,
      favorite: false,
      target: {
        kind: 'login',
        frameId: 3,
        documentId: 'doc-A',
        formId: 'login-form',
        generation: 4,
        customPlanDigest: '0'.repeat(64),
      },
    };
    const { deps, vaultTimeout } = makeDeps('unlocked', [], [], [login]);
    let expired = false;
    deps.assertSessionLease.mockImplementation(() => {
      if (expired) throw new Error('session timed out');
    });
    deps.fillTabSuggestion.mockImplementationOnce(async (_tabId, _cipherId, _target, assertCurrent) => {
      expired = true;
      assertCurrent();
      return { status: 'filled' as const };
    });

    await createContextMenu(deps).handleClick(
      'vw-login|l1',
      { id: 7 },
      3,
      CLICKED_FRAME_URL,
      CLICK_TIME,
    );

    expect(vaultTimeout.recordActivity).not.toHaveBeenCalled();
  });

  it('does not release fill data when the clicked document no longer exists', async () => {
    const { deps, sent } = makeDeps('unlocked');
    deps.getFrame.mockResolvedValueOnce(undefined);

    await createContextMenu(deps).handleClick('vw-fill|form|card|c1', { id: 7 }, 2, CLICKED_FRAME_URL, CLICK_TIME);

    expect(deps.getFillData).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });

  it('does not release fill data when the session lease is already stale', async () => {
    const { deps, sent } = makeDeps('unlocked');
    deps.isSessionLeaseCurrent.mockResolvedValueOnce(false);

    await createContextMenu(deps).handleClick('vw-fill|form|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);

    expect(deps.getFillData).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });

  it('does not release fill data when the account lease is already stale', async () => {
    const { deps, sent } = makeDeps('unlocked');
    deps.isAccountLeaseCurrent.mockResolvedValueOnce(false);

    await createContextMenu(deps).handleClick('vw-fill|form|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);

    expect(deps.getFillData).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });

  it('rechecks the account lease immediately before reading fill data', async () => {
    const { deps, sent, session } = makeDeps('unlocked');
    deps.authorizeFrame.mockImplementationOnce(async () => {
      session.accountEpoch += 1;
      return { assertCurrent: () => {}, defaultStrategy: 0 as const };
    });

    await createContextMenu(deps).handleClick('vw-fill|form|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);

    expect(deps.getFillData).not.toHaveBeenCalled();
    expect(sent.map(({ msg }) => msg.type)).toEqual(['autofill.reserveFillTarget', 'autofill.cancelFillTarget']);
  });

  it.each([
    ['URL', { frameId: 1, url: 'https://shop.example/complete', documentId: 'doc-A' }],
    ['documentId', { frameId: 1, url: 'https://shop.example/checkout', documentId: 'doc-B' }],
  ])('drops decrypted data when the target %s changes', async (_label, changedFrame) => {
    const { deps, sent } = makeDeps('unlocked');
    deps.getFrame
      .mockResolvedValueOnce({ frameId: 1, url: CLICKED_FRAME_URL, documentId: 'doc-A' })
      .mockResolvedValueOnce({ frameId: 1, url: CLICKED_FRAME_URL, documentId: 'doc-A' })
      .mockResolvedValueOnce({ frameId: 1, url: CLICKED_FRAME_URL, documentId: 'doc-A' })
      .mockResolvedValueOnce(changedFrame);

    await createContextMenu(deps).handleClick('vw-fill|form|identity|i1', { id: 7 }, 1, CLICKED_FRAME_URL, CLICK_TIME);

    expect(deps.getFillData).toHaveBeenCalledWith(
      'i1',
      'identity',
      ['firstName', 'lastName', 'address1'],
      expect.any(Function),
    );
    expect(sent.map(({ msg }) => msg.type)).toEqual(['autofill.reserveFillTarget', 'autofill.cancelFillTarget']);
  });

  it('drops decrypted data when the unlocked session changes during retrieval', async () => {
    const { deps, sent } = makeDeps('unlocked');
    deps.isSessionLeaseCurrent
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(false);

    await createContextMenu(deps).handleClick('vw-fill|form|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);

    expect(deps.getFillData).toHaveBeenCalledOnce();
    expect(sent.map(({ msg }) => msg.type)).toEqual(['autofill.reserveFillTarget', 'autofill.cancelFillTarget']);
  });

  it('drops decrypted data when the active account changes during retrieval', async () => {
    const { deps, sent, session } = makeDeps('unlocked');
    deps.getFillData.mockImplementationOnce(async () => {
      session.accountEpoch += 1;
      return { number: '4111' };
    });

    await createContextMenu(deps).handleClick('vw-fill|form|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);

    expect(deps.getFillData).toHaveBeenCalledOnce();
    expect(sent.map(({ msg }) => msg.type)).toEqual(['autofill.reserveFillTarget', 'autofill.cancelFillTarget']);
  });

  it('rechecks the session after a pending post-decryption frame lookup', async () => {
    const { deps, sent, session } = makeDeps('unlocked');
    let frameReadCount = 0;
    let signalFinalRead!: () => void;
    let releaseFinalRead!: () => void;
    const finalReadStarted = new Promise<void>((resolve) => { signalFinalRead = resolve; });
    const finalReadGate = new Promise<void>((resolve) => { releaseFinalRead = resolve; });
    deps.getFrame.mockImplementation(async (_tabId: number, frameId: number) => {
      frameReadCount += 1;
      if (frameReadCount === 4) {
        signalFinalRead();
        await finalReadGate;
      }
      return { frameId, url: CLICKED_FRAME_URL, documentId: 'doc-A' };
    });

    const pending = createContextMenu(deps)
      .handleClick('vw-fill|form|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);
    await finalReadStarted;
    session.epoch += 1;
    releaseFinalRead();
    await pending;

    expect(sent.map(({ msg }) => msg.type)).toEqual(['autofill.reserveFillTarget', 'autofill.cancelFillTarget']);
  });

  it('fails closed when the browser omits documentId', async () => {
    const { deps, sent } = makeDeps('unlocked');
    deps.getFrame.mockImplementation(async (_tabId: number, frameId: number) => ({
      frameId,
      url: CLICKED_FRAME_URL,
    }));

    await createContextMenu(deps).handleClick('vw-fill|field|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);

    expect(deps.getFrame).toHaveBeenCalledWith(7, 0);
    expect(deps.getFillData).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });

  it('fails closed when the browser omits the clicked frame id', async () => {
    const { deps, sent } = makeDeps('unlocked');

    await createContextMenu(deps).handleClick('vw-fill|field|card|c1', { id: 7 }, undefined, CLICKED_FRAME_URL, CLICK_TIME);

    expect(deps.getFrame).not.toHaveBeenCalled();
    expect(deps.getFillData).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });

  it('fails before decryption when navigation wins the race with the first frame read', async () => {
    const { deps, sent } = makeDeps('unlocked');
    deps.getFrame.mockResolvedValueOnce({
      frameId: 0,
      url: 'https://shop.example/complete',
      documentId: 'doc-B',
    });

    await createContextMenu(deps).handleClick('vw-fill|form|card|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);

    expect(deps.getFillData).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);
  });

  it('on click of a reprompt item: holds the exact target and opens the continuation', async () => {
    const { deps, sent } = makeDeps('unlocked');
    deps.getFillData = vi.fn(async () => { throw Object.assign(new Error('x'), { code: 'reprompt_required' }); });
    await createContextMenu(deps).handleClick(
      'vw-fill|form|card|c9',
      { id: 7, windowId: 3 },
      0,
      CLICKED_FRAME_URL,
      CLICK_TIME,
    );
    const reserve = sent[0]!.msg;
    if (reserve.type !== 'autofill.reserveFillTarget') throw new Error('expected reserve command');
    expect(sent.map(({ msg }) => msg.type).slice(0, 2)).toEqual([
      'autofill.reserveFillTarget',
      'autofill.holdFillTarget',
    ]);
    expect(deps.continuation.stageContextStructuredReprompt).toHaveBeenCalledOnce();
  });

  it('ignores clicks with no tab id or unrecognized menu id', async () => {
    const { deps, sent } = makeDeps('unlocked');
    await createContextMenu(deps).handleClick('vw-fill|form|card|c1', undefined, 0, CLICKED_FRAME_URL, CLICK_TIME);
    await createContextMenu(deps).handleClick('something-else', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);
    await createContextMenu(deps).handleClick('vw-fill|bogus|nope|c1', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);
    expect(sent).toHaveLength(0);
    expect(deps.getFillData).not.toHaveBeenCalled();
  });

  it('builds nothing when logged out, even with items', async () => {
    const { deps, created } = makeDeps('loggedOut', [{ id: 'c1', name: 'Visa', favorite: false }]);
    await createContextMenu(deps).refresh();
    expect(created).toHaveLength(0);
  });

  it('serializes overlapping refreshes and coalesces them to a single trailing rebuild', async () => {
    const { deps } = makeDeps('unlocked', [{ id: 'c1', name: 'Visa', favorite: false }]);
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    let removeAllCount = 0;
    deps.menus.removeAll = vi.fn(async () => {
      removeAllCount += 1;
      if (removeAllCount === 1) await gate; // hold the first rebuild open while more refreshes queue
    });
    const menu = createContextMenu(deps);
    const p1 = menu.refresh();
    const p2 = menu.refresh();
    const p3 = menu.refresh();
    release();
    await Promise.all([p1, p2, p3]);
    // Without serialization all three rebuilds interleave (3 removeAlls, duplicate create ids);
    // newest-wins single-flight collapses them to the in-flight run plus one coalesced trailing run.
    expect(removeAllCount).toBe(2);
  });

  it('logs an unexpected fill error instead of silently swallowing it', async () => {
    const { deps, sent } = makeDeps('unlocked');
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    deps.getFillData = vi.fn(async () => { throw new Error('decrypt exploded'); });
    await createContextMenu(deps).handleClick('vw-fill|form|card|c9', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);
    expect(spy).toHaveBeenCalled();
    expect(sent.map(({ msg }) => msg.type)).toEqual(['autofill.reserveFillTarget', 'autofill.cancelFillTarget']);
    spy.mockRestore();
  });

  it('silently drops delivery when the leased document disappears before sendMessage', async () => {
    const { deps } = makeDeps('unlocked');
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    deps.tabs.sendMessage = vi.fn(async (_id: number, message: ContextMenuMessage) => {
      if (message.type === 'autofill.reserveFillTarget') {
        return { status: 'reserved', roles: reservationRoles(message) };
      }
      throw new Error('Could not establish connection. Receiving end does not exist.');
    });

    await createContextMenu(deps).handleClick(
      'vw-fill|form|card|c1',
      { id: 7 },
      0,
      CLICKED_FRAME_URL,
      CLICK_TIME,
    );

    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('stays silent (no log, no message) for expected credential-release refusals', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    for (const code of ['denied', 'locked', 'sync_required'] as const) {
      const { deps, sent } = makeDeps('unlocked');
      deps.getFillData = vi.fn(async () => { throw Object.assign(new Error('x'), { code }); });
      await createContextMenu(deps).handleClick('vw-fill|form|card|c9', { id: 7 }, 0, CLICKED_FRAME_URL, CLICK_TIME);
      expect(sent.map(({ msg }) => msg.type)).toEqual(['autofill.reserveFillTarget', 'autofill.cancelFillTarget']);
    }
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('shouldRefreshMenu fires for sync/auth/cipher mutations, not for reads', () => {
    expect(shouldRefreshMenu('vault.sync')).toBe(true);
    expect(shouldRefreshMenu('auth.lock')).toBe(true);
    expect(shouldRefreshMenu('auth.register')).toBe(true);
    expect(shouldRefreshMenu('auth.submitTwoFactor')).toBe(true);
    expect(shouldRefreshMenu('auth.completeFido2')).toBe(true);
    expect(shouldRefreshMenu('auth.rotateAccountKey')).toBe(true);
    expect(shouldRefreshMenu('vault.createCipher')).toBe(true);
    expect(shouldRefreshMenu('auth.unlockWithPin')).toBe(true);
    expect(shouldRefreshMenu('vault.import')).toBe(false);
    expect(shouldRefreshMenu('vault.export')).toBe(false);
    expect(shouldRefreshMenu('settings.save')).toBe(true);
    expect(shouldRefreshMenu('vault.getField')).toBe(false);
    expect(shouldRefreshMenu('autofill.findFillItems')).toBe(false);
  });
});
