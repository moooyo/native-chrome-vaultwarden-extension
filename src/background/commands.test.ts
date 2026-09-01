import { describe, expect, it, vi } from 'vitest';
import {
  CommandCoordinator,
  EXTENSION_COMMANDS,
  handleFocusedFillCommand,
  FOCUSED_FILL_COMMAND,
  type CommandCoordinatorDeps,
} from './commands.js';
import type { TabAutofillSuggestion, TabFillOutcome, TabSuggestionTarget } from '../messaging/protocol.js';

const TOP_RUNTIME_INCARNATION = '11111111-2222-4abc-8def-000000000001';
const NEXT_TOP_RUNTIME_INCARNATION = '11111111-2222-4abc-8def-000000000002';
const FRAME_RUNTIME_INCARNATION = '33333333-4444-4abc-8def-000000000001';
const NEXT_FRAME_RUNTIME_INCARNATION = '33333333-4444-4abc-8def-000000000002';

function deps() {
  return {
    tabs: { sendMessage: vi.fn().mockResolvedValue(undefined) },
    getTopDocument: vi.fn<
      (tabId: number) => Promise<{
        documentId: string;
        url: string;
        runtimeIncarnation?: string;
      } | undefined>
    >(
      async () => ({
        documentId: 'top-doc',
        url: 'https://example.com/',
        runtimeIncarnation: TOP_RUNTIME_INCARNATION,
      }),
    ),
    getState: vi.fn<() => Promise<'loggedOut' | 'locked' | 'restricted' | 'unlocked'>>(
      async () => 'unlocked',
    ),
    captureSessionLease: vi.fn(() => 1),
    assertSessionLease: vi.fn(),
    beginLocked: vi.fn(async () => undefined),
    keyboardGrants: {
      issueCommand: vi.fn(() => '00000000-0000-4000-8000-000000000001'),
    },
  };
}

function loginSuggestion(
  id: string,
  formId = 'login-form',
  target: {
    readonly frameId?: number;
    readonly documentId?: string;
    readonly runtimeIncarnation?: string;
  } = {},
): TabAutofillSuggestion {
  return {
    kind: 'login',
    id,
    name: id,
    matchedUri: 'https://example.com/',
    matchType: 0,
    favorite: false,
    target: {
      kind: 'login',
      frameId: target.frameId ?? 0,
      documentId: target.documentId ?? 'top-doc',
      runtimeIncarnation: target.runtimeIncarnation ?? TOP_RUNTIME_INCARNATION,
      formId,
      generation: 1,
      customPlanDigest: '0'.repeat(64),
    },
  };
}

function cardSuggestion(id: string): TabAutofillSuggestion {
  return {
    kind: 'card',
    id,
    name: id,
    favorite: false,
    target: {
      kind: 'card',
      frameId: 0,
      documentId: 'top-doc',
      runtimeIncarnation: TOP_RUNTIME_INCARNATION,
      formId: 'card-form',
      generation: 1,
      roles: ['number'],
    },
  };
}

function coordinatorFixture(initialSuggestions: TabAutofillSuggestion[] = []) {
  const authority = { session: 1, account: 1, policy: 1 };
  let state: 'loggedOut' | 'locked' | 'restricted' | 'unlocked' = 'unlocked';
  const suggestions = [...initialSuggestions];
  const assertEqual = (actual: number, expected: number) => {
    if (actual !== expected) throw new Error('authority changed');
  };
  const fillTabSuggestion = vi.fn(async (
    _tabId: number,
    _cipherId: string,
    _target: TabSuggestionTarget,
    assertCurrent: () => void,
  ): Promise<TabFillOutcome> => {
    assertCurrent();
    return { status: 'filled' };
  });
  const deps = {
    tabs: { sendMessage: vi.fn(async () => undefined) },
    getTopDocument: vi.fn(async () => ({
      documentId: 'top-doc',
      url: 'https://example.com/',
      runtimeIncarnation: TOP_RUNTIME_INCARNATION,
    })),
    getState: vi.fn(async () => state),
    captureSessionLease: vi.fn(() => authority.session),
    assertSessionLease: vi.fn((lease: number) => assertEqual(lease, authority.session)),
    beginLocked: vi.fn(async () => undefined),
    keyboardGrants: { issueCommand: vi.fn(() => '00000000-0000-4000-8000-000000000001') },
    captureAccountLease: vi.fn(() => authority.account),
    assertAccountLease: vi.fn((lease: number) => assertEqual(lease, authority.account)),
    capturePolicyLease: vi.fn(() => authority.policy),
    assertPolicyLease: vi.fn((lease: number) => assertEqual(lease, authority.policy)),
    authorizeFrame: vi.fn(async () => ({ assertCurrent: vi.fn() })),
    getTabSuggestions: vi.fn(async () => ({ status: 'ready' as const, suggestions })),
    fillTabSuggestion,
    generatePasswordAndTrack: vi.fn(async (bind: (assertCurrent: () => void) => void) => {
      bind(() => undefined);
      return { value: 'Generated-Password-42!' };
    }),
    clipboard: {
      writeSecretAndScheduleClear: vi.fn(async (_value: string, assertCurrent: () => void) => {
        assertCurrent();
        return true;
      }),
    },
    lockVault: vi.fn(async () => undefined),
    openPopup: vi.fn(async () => undefined),
    continuation: {
      stageLockedCommand: vi.fn(async () => undefined),
      stageRepromptCommand: vi.fn(async () => undefined),
    },
    vaultReleaseGate: {
      capture: vi.fn(() => ({})),
      checkpoint: vi.fn(async () => ({})),
      assertAuthorities: vi.fn((_proof: object, assertCurrent: () => void) => assertCurrent()),
      assert: vi.fn(),
      settlePendingAction: vi.fn(async () => undefined),
    },
    recordActivity: vi.fn(async () => undefined),
  } satisfies CommandCoordinatorDeps<number, number, number>;
  return {
    authority,
    deps,
    suggestions,
    coordinator: new CommandCoordinator(deps),
    setState(next: typeof state) { state = next; },
  };
}

describe('handleFocusedFillCommand', () => {
  it('relays the focused-fill command to the active tab', async () => {
    const d = deps();
    await handleFocusedFillCommand(FOCUSED_FILL_COMMAND, { id: 7 }, d);
    expect(d.keyboardGrants.issueCommand).toHaveBeenCalledWith({
      tabId: 7,
      topDocumentId: 'top-doc',
      topFrameUrl: 'https://example.com/',
      sessionLease: 1,
    });
    expect(d.tabs.sendMessage).toHaveBeenCalledWith(7, {
      type: 'autofill.focusedFill',
      commandToken: '00000000-0000-4000-8000-000000000001',
    });
  });

  it('ignores other command names', async () => {
    const d = deps();
    await handleFocusedFillCommand('something-else', { id: 7 }, d);
    expect(d.tabs.sendMessage).not.toHaveBeenCalled();
    expect(d.getTopDocument).not.toHaveBeenCalled();
  });

  it('ignores calls without a valid tab id', async () => {
    const d = deps();
    await handleFocusedFillCommand(FOCUSED_FILL_COMMAND, undefined, d);
    await handleFocusedFillCommand(FOCUSED_FILL_COMMAND, {}, d);
    expect(d.tabs.sendMessage).not.toHaveBeenCalled();
    expect(d.getTopDocument).not.toHaveBeenCalled();
  });

  it('does not issue a command token without a browser-owned top document', async () => {
    const d = deps();
    d.getTopDocument.mockResolvedValueOnce(undefined);

    await handleFocusedFillCommand(FOCUSED_FILL_COMMAND, { id: 7 }, d);

    expect(d.keyboardGrants.issueCommand).not.toHaveBeenCalled();
    expect(d.tabs.sendMessage).not.toHaveBeenCalled();
  });

  it('does not require a runtime incarnation before content claims the command token', async () => {
    const d = deps();
    d.getTopDocument.mockResolvedValue({
      documentId: 'top-doc',
      url: 'https://example.com/',
    });

    await handleFocusedFillCommand(FOCUSED_FILL_COMMAND, { id: 7, windowId: 3 }, d);

    expect(d.keyboardGrants.issueCommand).toHaveBeenCalledOnce();
    expect(d.tabs.sendMessage).toHaveBeenCalledOnce();
  });

  it('stages a locked action without minting or sending a command token', async () => {
    const d = deps();
    d.getState.mockResolvedValueOnce('locked');

    await handleFocusedFillCommand(FOCUSED_FILL_COMMAND, { id: 7, windowId: 3 }, d);

    expect(d.beginLocked).toHaveBeenCalledWith({
      tabId: 7,
      windowId: 3,
      topDocumentId: 'top-doc',
      topFrameUrl: 'https://example.com/',
    });
    expect(d.keyboardGrants.issueCommand).not.toHaveBeenCalled();
    expect(d.tabs.sendMessage).not.toHaveBeenCalled();
  });

  it('checks auth state before reading a document or touching command capabilities', async () => {
    const d = deps();
    d.getState.mockResolvedValueOnce('loggedOut');

    await handleFocusedFillCommand(FOCUSED_FILL_COMMAND, { id: 7, windowId: 3 }, d);

    expect(d.getTopDocument).not.toHaveBeenCalled();
    expect(d.keyboardGrants.issueCommand).not.toHaveBeenCalled();
  });
});

describe('CommandCoordinator', () => {
  const tab = { id: 7, windowId: 3 };

  it('opens the popup without consulting vault state', async () => {
    const fixture = coordinatorFixture();
    fixture.setState('loggedOut');

    await fixture.coordinator.handle(EXTENSION_COMMANDS.OpenPopup, undefined);

    expect(fixture.deps.openPopup).toHaveBeenCalledOnce();
    expect(fixture.deps.getState).not.toHaveBeenCalled();
    expect(fixture.deps.captureSessionLease).not.toHaveBeenCalled();
  });

  it('locks only an unlocked vault', async () => {
    const fixture = coordinatorFixture();
    await fixture.coordinator.handle(EXTENSION_COMMANDS.LockVault, undefined);
    expect(fixture.deps.lockVault).toHaveBeenCalledOnce();

    fixture.setState('locked');
    await fixture.coordinator.handle(EXTENSION_COMMANDS.LockVault, undefined);
    expect(fixture.deps.lockVault).toHaveBeenCalledOnce();
  });

  it('stages the exact secret command while locked', async () => {
    const fixture = coordinatorFixture();
    fixture.setState('locked');

    await fixture.coordinator.handle(EXTENSION_COMMANDS.GeneratePassword, tab);

    expect(fixture.deps.continuation.stageLockedCommand).toHaveBeenCalledWith(
      EXTENSION_COMMANDS.GeneratePassword,
      {
        tabId: 7,
        windowId: 3,
        documentId: 'top-doc',
        url: 'https://example.com/',
        runtimeIncarnation: TOP_RUNTIME_INCARNATION,
      },
    );
    expect(fixture.deps.generatePasswordAndTrack).not.toHaveBeenCalled();
  });

  it('does not stage a locked command for a malformed top runtime incarnation', async () => {
    const fixture = coordinatorFixture();
    fixture.setState('locked');
    fixture.deps.getTopDocument.mockResolvedValue({
      documentId: 'top-doc',
      url: 'https://example.com/',
      runtimeIncarnation: TOP_RUNTIME_INCARNATION.toUpperCase(),
    });

    await fixture.coordinator.handle(EXTENSION_COMMANDS.GeneratePassword, tab);

    expect(fixture.deps.continuation.stageLockedCommand).not.toHaveBeenCalled();
  });

  it('generates through the shared adapter, then copies with owned clear', async () => {
    const fixture = coordinatorFixture();

    await fixture.coordinator.handle(EXTENSION_COMMANDS.GeneratePassword, undefined);

    expect(fixture.deps.generatePasswordAndTrack).toHaveBeenCalledOnce();
    expect(fixture.deps.clipboard.writeSecretAndScheduleClear).toHaveBeenCalledWith(
      'Generated-Password-42!',
      expect.any(Function),
    );
    expect(fixture.deps.vaultReleaseGate.checkpoint).toHaveBeenCalledOnce();
    expect(fixture.deps.recordActivity).toHaveBeenCalledOnce();
    expect(fixture.deps.getTopDocument).not.toHaveBeenCalled();
  });

  it('does not copy a generated password after authority changes', async () => {
    const fixture = coordinatorFixture();
    fixture.deps.generatePasswordAndTrack.mockImplementationOnce(async (bind) => {
      bind(() => undefined);
      fixture.authority.policy += 1;
      return { value: 'stale-secret' };
    });

    await expect(fixture.coordinator.handle(EXTENSION_COMMANDS.GeneratePassword, tab))
      .rejects.toThrow('authority changed');
    expect(fixture.deps.clipboard.writeSecretAndScheduleClear).not.toHaveBeenCalled();
  });

  it('does not resume a locked generator command into a replacement content runtime', async () => {
    const fixture = coordinatorFixture();
    fixture.deps.getTopDocument.mockResolvedValue({
      documentId: 'top-doc',
      url: 'https://example.com/',
      runtimeIncarnation: NEXT_TOP_RUNTIME_INCARNATION,
    });

    await fixture.coordinator.handle(
      EXTENSION_COMMANDS.GeneratePassword,
      tab,
      () => undefined,
      {
        documentId: 'top-doc',
        url: 'https://example.com/',
        runtimeIncarnation: TOP_RUNTIME_INCARNATION,
      },
    );

    expect(fixture.deps.generatePasswordAndTrack).not.toHaveBeenCalled();
  });

  it('fills and cycles matching logins without requiring a focused claim', async () => {
    const fixture = coordinatorFixture([loginSuggestion('login-a'), loginSuggestion('login-b')]);

    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);
    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);
    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);

    expect(fixture.deps.fillTabSuggestion.mock.calls.map((call) => call[1]))
      .toEqual(['login-a', 'login-b', 'login-a']);
    expect(fixture.deps.tabs.sendMessage).not.toHaveBeenCalled();
  });

  it('rejects stale or malformed top-frame target runtime incarnations', async () => {
    const fixture = coordinatorFixture([
      loginSuggestion('stale-runtime', 'login-form-a', {
        runtimeIncarnation: NEXT_TOP_RUNTIME_INCARNATION,
      }),
      loginSuggestion('malformed-runtime', 'login-form-b', {
        runtimeIncarnation: TOP_RUNTIME_INCARNATION.toUpperCase(),
      }),
    ]);

    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);

    expect(fixture.deps.fillTabSuggestion).not.toHaveBeenCalled();
  });

  it('propagates a distinct valid child-frame runtime incarnation', async () => {
    const suggestion = loginSuggestion('child-login', 'child-form', {
      frameId: 4,
      documentId: 'child-doc',
      runtimeIncarnation: FRAME_RUNTIME_INCARNATION,
    });
    const fixture = coordinatorFixture([suggestion]);

    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);

    expect(fixture.deps.fillTabSuggestion).toHaveBeenCalledWith(
      7,
      'child-login',
      suggestion.target,
      expect.any(Function),
    );
  });

  it('stops a direct fill when the top runtime changes during candidate discovery', async () => {
    const fixture = coordinatorFixture([loginSuggestion('login-a')]);
    fixture.deps.getTabSuggestions.mockImplementationOnce(async () => {
      fixture.deps.getTopDocument.mockResolvedValue({
        documentId: 'top-doc',
        url: 'https://example.com/',
        runtimeIncarnation: NEXT_TOP_RUNTIME_INCARNATION,
      });
      return { status: 'ready' as const, suggestions: fixture.suggestions };
    });

    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);

    expect(fixture.deps.fillTabSuggestion).not.toHaveBeenCalled();
  });

  it('restarts cycling when the top content runtime incarnation changes', async () => {
    const childTarget = {
      frameId: 4,
      documentId: 'child-doc',
      runtimeIncarnation: FRAME_RUNTIME_INCARNATION,
    } as const;
    const fixture = coordinatorFixture([
      loginSuggestion('login-a', 'login-form-a', childTarget),
      loginSuggestion('login-b', 'login-form-b', childTarget),
    ]);

    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);
    fixture.deps.getTopDocument.mockResolvedValue({
      documentId: 'top-doc',
      url: 'https://example.com/',
      runtimeIncarnation: NEXT_TOP_RUNTIME_INCARNATION,
    });
    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);

    expect(fixture.deps.fillTabSuggestion.mock.calls.map((call) => call[1]))
      .toEqual(['login-a', 'login-a']);
  });

  it('restarts cycling when a target runtime incarnation changes', async () => {
    const fixture = coordinatorFixture([
      loginSuggestion('login-a', 'login-form-a', {
        frameId: 4,
        documentId: 'child-doc',
        runtimeIncarnation: FRAME_RUNTIME_INCARNATION,
      }),
      loginSuggestion('login-b', 'login-form-b', {
        frameId: 4,
        documentId: 'child-doc',
        runtimeIncarnation: FRAME_RUNTIME_INCARNATION,
      }),
    ]);

    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);
    fixture.suggestions.splice(
      0,
      fixture.suggestions.length,
      loginSuggestion('login-a', 'login-form-a', {
        frameId: 4,
        documentId: 'child-doc',
        runtimeIncarnation: NEXT_FRAME_RUNTIME_INCARNATION,
      }),
      loginSuggestion('login-b', 'login-form-b', {
        frameId: 4,
        documentId: 'child-doc',
        runtimeIncarnation: NEXT_FRAME_RUNTIME_INCARNATION,
      }),
    );
    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);

    expect(fixture.deps.fillTabSuggestion.mock.calls.map((call) => call[1]))
      .toEqual(['login-a', 'login-a']);
  });

  it('restarts cycling after tab or account lifecycle revocation', async () => {
    const fixture = coordinatorFixture([loginSuggestion('login-a'), loginSuggestion('login-b')]);

    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);
    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);
    fixture.coordinator.revokeTab(7);
    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);
    fixture.authority.account += 1;
    fixture.coordinator.revokeAll();
    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);

    expect(fixture.deps.fillTabSuggestion.mock.calls.map((call) => call[1]))
      .toEqual(['login-a', 'login-b', 'login-a', 'login-a']);
  });

  it('bounds per-tab cycle state and evicts the oldest tab', async () => {
    const fixture = coordinatorFixture([loginSuggestion('login-a'), loginSuggestion('login-b')]);
    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);
    for (let tabId = 8; tabId < 8 + CommandCoordinator.MAX_CYCLE_ENTRIES; tabId += 1) {
      await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, { id: tabId, windowId: 3 });
    }
    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);

    const tabSevenCalls = fixture.deps.fillTabSuggestion.mock.calls
      .filter((call) => call[0] === 7)
      .map((call) => call[1]);
    expect(tabSevenCalls).toEqual(['login-a', 'login-a']);
  });

  it('selects only the item kind named by a direct fill command', async () => {
    const fixture = coordinatorFixture([loginSuggestion('login-a'), cardSuggestion('card-a')]);

    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillCard, tab);

    expect(fixture.deps.fillTabSuggestion).toHaveBeenCalledWith(
      7,
      'card-a',
      expect.objectContaining({ kind: 'card' }),
      expect.any(Function),
    );
  });

  it('stages a reprompt result without attempting another secret release', async () => {
    const suggestion = loginSuggestion('protected-login', 'child-form', {
      frameId: 4,
      documentId: 'child-doc',
      runtimeIncarnation: FRAME_RUNTIME_INCARNATION,
    });
    const fixture = coordinatorFixture([suggestion]);
    fixture.deps.fillTabSuggestion.mockResolvedValueOnce({ status: 'reprompt_required' });

    await fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab);

    expect(fixture.deps.continuation.stageRepromptCommand).toHaveBeenCalledWith({
      command: EXTENSION_COMMANDS.AutofillLogin,
      source: {
        tabId: 7,
        windowId: 3,
        documentId: 'top-doc',
        url: 'https://example.com/',
        runtimeIncarnation: TOP_RUNTIME_INCARNATION,
      },
      cipherId: 'protected-login',
      target: suggestion.target,
    });
  });

  it('does not stage a reprompt continuation after command authority changes', async () => {
    const suggestion = loginSuggestion('protected-login');
    const fixture = coordinatorFixture([suggestion]);
    fixture.deps.fillTabSuggestion.mockImplementationOnce(async () => {
      fixture.authority.account += 1;
      return { status: 'reprompt_required' };
    });

    await expect(fixture.coordinator.handle(EXTENSION_COMMANDS.AutofillLogin, tab))
      .rejects.toThrow('authority changed');

    expect(fixture.deps.continuation.stageRepromptCommand).not.toHaveBeenCalled();
  });
});
