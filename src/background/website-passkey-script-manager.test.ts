import { describe, expect, it, vi } from 'vitest';
import {
  WEBSITE_PASSKEY_BRIDGE_SCRIPT_ID,
  WEBSITE_PASSKEY_MAIN_SCRIPT_ID,
  WEBSITE_PASSKEY_SCRIPT_IDS,
  WEBSITE_PASSKEY_SCRIPT_MATCHES,
  WebsitePasskeyScriptManager,
  createDesiredWebsitePasskeyScripts,
  type WebsitePasskeyRegisteredScript,
  type WebsitePasskeyScriptState,
  type WebsitePasskeyScriptingAdapter,
} from './website-passkey-script-manager.js';

function cloneScript(script: WebsitePasskeyRegisteredScript): WebsitePasskeyRegisteredScript {
  return {
    ...script,
    ...(script.matches ? { matches: [...script.matches] } : {}),
    ...(script.js ? { js: [...script.js] } : {}),
    ...(script.css ? { css: [...script.css] } : {}),
    ...(script.excludeMatches ? { excludeMatches: [...script.excludeMatches] } : {}),
  };
}

function makeScripting(initial: readonly WebsitePasskeyRegisteredScript[] = [], ignoreFilter = false) {
  let registrations = initial.map(cloneScript);
  const adapter: WebsitePasskeyScriptingAdapter = {
    getRegisteredContentScripts: vi.fn(async ({ ids }) => (
      ignoreFilter ? registrations : registrations.filter((script) => ids.includes(script.id))
    ).map(cloneScript)),
    registerContentScripts: vi.fn(async (scripts) => {
      for (const script of scripts) {
        if (registrations.some((current) => current.id === script.id)) throw new Error('duplicate id');
      }
      registrations.push(...scripts.map(cloneScript));
    }),
    unregisterContentScripts: vi.fn(async ({ ids }) => {
      registrations = registrations.filter((script) => !ids.includes(script.id));
    }),
  };
  return { adapter, registrations: () => registrations.map(cloneScript) };
}

describe('website passkey dynamic script definitions', () => {
  it('defines exactly one MAIN shim and one isolated bridge at document_start in all frames', () => {
    const scripts = createDesiredWebsitePasskeyScripts();
    expect(scripts).toHaveLength(2);
    expect(scripts).toEqual([
      expect.objectContaining({
        id: WEBSITE_PASSKEY_MAIN_SCRIPT_ID,
        js: ['content/page-webauthn.js'],
        world: 'MAIN',
        runAt: 'document_start',
        allFrames: true,
      }),
      expect.objectContaining({
        id: WEBSITE_PASSKEY_BRIDGE_SCRIPT_ID,
        js: ['content/webauthn-bridge.js'],
        world: 'ISOLATED',
        runAt: 'document_start',
        allFrames: true,
      }),
    ]);
    expect(WEBSITE_PASSKEY_SCRIPT_MATCHES).toEqual([
      'https://*/*',
      'http://localhost/*',
      'http://127.0.0.1/*',
    ]);
    expect(WEBSITE_PASSKEY_SCRIPT_MATCHES).not.toContain('http://*/*');
    expect(scripts.every((script) => script.matchOriginAsFallback === false)).toBe(true);
    expect(Object.isFrozen(scripts)).toBe(true);
  });
});

describe('WebsitePasskeyScriptManager lifecycle', () => {
  it.each(['locked', 'unlocked'] as const)('registers both scripts when enabled and %s', async (sessionState) => {
    const scripting = makeScripting();
    const notifyOpenTopFrames = vi.fn(async () => {});
    const manager = new WebsitePasskeyScriptManager({ scripting: scripting.adapter, notifyOpenTopFrames });

    await manager.reconcile({ enabled: true, sessionState, policyGeneration: 1 });

    expect(scripting.registrations().map((script) => script.id)).toEqual([...WEBSITE_PASSKEY_SCRIPT_IDS]);
    expect(scripting.adapter.registerContentScripts).toHaveBeenCalledTimes(1);
    expect(notifyOpenTopFrames).toHaveBeenCalledTimes(1);
  });

  it.each([
    { enabled: false, sessionState: 'locked' as const },
    { enabled: false, sessionState: 'unlocked' as const },
    { enabled: true, sessionState: 'loggedOut' as const },
  ])('does not register while inactive: $enabled/$sessionState', async ({ enabled, sessionState }) => {
    const scripting = makeScripting();
    const manager = new WebsitePasskeyScriptManager({
      scripting: scripting.adapter,
      notifyOpenTopFrames: vi.fn(),
    });

    await manager.reconcile({ enabled, sessionState, policyGeneration: 1 });

    expect(scripting.adapter.registerContentScripts).not.toHaveBeenCalled();
    expect(scripting.adapter.unregisterContentScripts).not.toHaveBeenCalled();
  });

  it('is idempotent within one worker and across a reconstructed manager', async () => {
    const scripting = makeScripting();
    const notify = vi.fn(async () => {});
    const first = new WebsitePasskeyScriptManager({ scripting: scripting.adapter, notifyOpenTopFrames: notify });
    const state = { enabled: true, sessionState: 'unlocked' as const, policyGeneration: 4 };

    await first.reconcile(state);
    await first.reconcile(state);
    const second = new WebsitePasskeyScriptManager({ scripting: scripting.adapter, notifyOpenTopFrames: notify });
    await second.reconcile(state);

    expect(scripting.adapter.registerContentScripts).toHaveBeenCalledTimes(1);
    expect(scripting.adapter.unregisterContentScripts).not.toHaveBeenCalled();
    expect(notify).toHaveBeenCalledTimes(2);
  });

  it('accepts browser defaults while retaining the required all-frame registration', async () => {
    const registrations = createDesiredWebsitePasskeyScripts().map((script) => ({
      id: script.id,
      matches: [...(script.matches ?? [])],
      js: [...(script.js ?? [])],
      runAt: script.runAt ?? 'document_start',
      allFrames: true,
      ...(script.world === 'MAIN' ? { world: 'MAIN' as const } : {}),
    }));
    const scripting = makeScripting(registrations);
    const manager = new WebsitePasskeyScriptManager({
      scripting: scripting.adapter,
      notifyOpenTopFrames: vi.fn(),
    });

    await manager.reconcile({ enabled: true, sessionState: 'unlocked', policyGeneration: 1 });

    expect(scripting.adapter.registerContentScripts).not.toHaveBeenCalled();
    expect(scripting.adapter.unregisterContentScripts).not.toHaveBeenCalled();
  });

  it('replaces incomplete or stale owned registrations as one pair', async () => {
    const desired = createDesiredWebsitePasskeyScripts();
    const scripting = makeScripting([{
      ...desired[0]!,
      runAt: 'document_idle',
      allFrames: false,
    }]);
    const manager = new WebsitePasskeyScriptManager({
      scripting: scripting.adapter,
      notifyOpenTopFrames: vi.fn(),
    });

    await manager.reconcile({ enabled: true, sessionState: 'locked', policyGeneration: 1 });

    expect(scripting.adapter.unregisterContentScripts).toHaveBeenCalledWith({
      ids: [WEBSITE_PASSKEY_MAIN_SCRIPT_ID],
    });
    expect(scripting.registrations()).toEqual(desired);
  });

  it('unregisters only its own IDs and never removes unrelated dynamic scripts', async () => {
    const unrelated = { id: 'unrelated-script', matches: ['https://*/*'], js: ['other.js'] };
    const scripting = makeScripting([...createDesiredWebsitePasskeyScripts(), unrelated], true);
    const manager = new WebsitePasskeyScriptManager({
      scripting: scripting.adapter,
      notifyOpenTopFrames: vi.fn(),
    });

    await manager.reconcile({ enabled: false, sessionState: 'unlocked', policyGeneration: 2 });

    expect(scripting.adapter.unregisterContentScripts).toHaveBeenCalledWith({
      ids: [...WEBSITE_PASSKEY_SCRIPT_IDS],
    });
    expect(scripting.registrations()).toEqual([unrelated]);
  });

  it('unregisters on logout and re-registers after a locked account becomes active', async () => {
    const scripting = makeScripting();
    const notify = vi.fn(async () => {});
    const manager = new WebsitePasskeyScriptManager({ scripting: scripting.adapter, notifyOpenTopFrames: notify });

    await manager.reconcile({ enabled: true, sessionState: 'unlocked', policyGeneration: 1 });
    await manager.reconcile({ enabled: true, sessionState: 'loggedOut', policyGeneration: 2 });
    expect(scripting.registrations()).toEqual([]);
    await manager.reconcile({ enabled: true, sessionState: 'locked', policyGeneration: 3 });

    expect(scripting.registrations().map((script) => script.id)).toEqual([...WEBSITE_PASSKEY_SCRIPT_IDS]);
    expect(scripting.adapter.registerContentScripts).toHaveBeenCalledTimes(2);
    expect(scripting.adapter.unregisterContentScripts).toHaveBeenCalledTimes(1);
    expect(notify).toHaveBeenCalledTimes(3);
  });

  it('notifies once per policy generation even when registration is already correct', async () => {
    const scripting = makeScripting(createDesiredWebsitePasskeyScripts());
    const notify = vi.fn(async () => {});
    const manager = new WebsitePasskeyScriptManager({ scripting: scripting.adapter, notifyOpenTopFrames: notify });

    await manager.reconcile({ enabled: true, sessionState: 'unlocked', policyGeneration: 8 });
    await manager.reconcile({ enabled: true, sessionState: 'unlocked', policyGeneration: 8 });
    await manager.reconcile({ enabled: true, sessionState: 'unlocked', policyGeneration: 9 });

    expect(scripting.adapter.registerContentScripts).not.toHaveBeenCalled();
    expect(notify).toHaveBeenCalledTimes(2);
  });

  it('passes an immutable validated snapshot instead of the caller-owned state', async () => {
    const scripting = makeScripting(createDesiredWebsitePasskeyScripts());
    const observed: Readonly<WebsitePasskeyScriptState>[] = [];
    const notify = vi.fn(async (state: Readonly<WebsitePasskeyScriptState>) => {
      observed.push(state);
      expect(Object.isFrozen(state)).toBe(true);
      expect(() => {
        (state as { enabled: boolean }).enabled = false;
      }).toThrow(TypeError);
    });
    const manager = new WebsitePasskeyScriptManager({
      scripting: scripting.adapter,
      notifyOpenTopFrames: notify,
    });
    const callerState = {
      enabled: true,
      sessionState: 'unlocked' as const,
      policyGeneration: 8,
    };

    const reconciliation = manager.reconcile(callerState);
    callerState.enabled = false;
    callerState.policyGeneration = 99;
    await reconciliation;

    expect(observed).toEqual([{
      enabled: true,
      sessionState: 'unlocked',
      policyGeneration: 8,
    }]);
    expect(observed[0]).not.toBe(callerState);
  });

  it('serializes overlapping reconciliations and leaves the latest requested state installed', async () => {
    const scripting = makeScripting();
    const notified: Readonly<WebsitePasskeyScriptState>[] = [];
    let releaseFirst!: () => void;
    const firstRead = new Promise<void>((resolve) => { releaseFirst = resolve; });
    vi.mocked(scripting.adapter.getRegisteredContentScripts)
      .mockImplementationOnce(async () => {
        await firstRead;
        return [];
      });
    const manager = new WebsitePasskeyScriptManager({
      scripting: scripting.adapter,
      notifyOpenTopFrames: vi.fn((state: Readonly<WebsitePasskeyScriptState>) => {
        notified.push(state);
      }),
    });

    const enabling = manager.reconcile({ enabled: true, sessionState: 'unlocked', policyGeneration: 1 });
    const disabling = manager.reconcile({ enabled: false, sessionState: 'unlocked', policyGeneration: 2 });
    releaseFirst();
    await Promise.all([enabling, disabling]);

    expect(scripting.registrations()).toEqual([]);
    expect(scripting.adapter.registerContentScripts).toHaveBeenCalledTimes(1);
    expect(scripting.adapter.unregisterContentScripts).toHaveBeenCalledTimes(1);
    expect(notified).toEqual([
      { enabled: true, sessionState: 'unlocked', policyGeneration: 1 },
      { enabled: false, sessionState: 'unlocked', policyGeneration: 2 },
    ]);
    expect(notified.every(Object.isFrozen)).toBe(true);
  });

  it('notifies after registration for each serialized state', async () => {
    const calls: string[] = [];
    const scripting = makeScripting();
    vi.mocked(scripting.adapter.getRegisteredContentScripts).mockImplementation(async () => {
      calls.push('read');
      return [];
    });
    vi.mocked(scripting.adapter.registerContentScripts).mockImplementation(async () => {
      calls.push('register');
    });
    const manager = new WebsitePasskeyScriptManager({
      scripting: scripting.adapter,
      notifyOpenTopFrames: async (state) => {
        calls.push(`notify:${state.policyGeneration}`);
      },
    });

    await manager.reconcile({ enabled: true, sessionState: 'unlocked', policyGeneration: 4 });

    expect(calls).toEqual(['read', 'register', 'notify:4']);
  });

  it('retries a failed notification with a fresh immutable snapshot', async () => {
    const scripting = makeScripting(createDesiredWebsitePasskeyScripts());
    const snapshots: Readonly<WebsitePasskeyScriptState>[] = [];
    const notify = vi.fn(async (state: Readonly<WebsitePasskeyScriptState>) => {
      snapshots.push(state);
      if (snapshots.length === 1) throw new Error('notification failed');
    });
    const manager = new WebsitePasskeyScriptManager({
      scripting: scripting.adapter,
      notifyOpenTopFrames: notify,
    });
    const state = { enabled: true, sessionState: 'unlocked' as const, policyGeneration: 5 };

    await expect(manager.reconcile(state)).rejects.toThrow('notification failed');
    await expect(manager.reconcile(state)).resolves.toBeUndefined();

    expect(notify).toHaveBeenCalledTimes(2);
    expect(snapshots).toEqual([state, state]);
    expect(snapshots[0]).not.toBe(snapshots[1]);
    expect(snapshots.every(Object.isFrozen)).toBe(true);
  });

  it('still notifies open frames when the browser registration API fails', async () => {
    const scripting = makeScripting(createDesiredWebsitePasskeyScripts());
    vi.mocked(scripting.adapter.getRegisteredContentScripts).mockRejectedValueOnce(new Error('browser API failed'));
    const notify = vi.fn(async () => {});
    const manager = new WebsitePasskeyScriptManager({ scripting: scripting.adapter, notifyOpenTopFrames: notify });

    await expect(manager.reconcile({ enabled: false, sessionState: 'locked', policyGeneration: 1 }))
      .rejects.toThrow('browser API failed');
    expect(notify).toHaveBeenCalledTimes(1);

    await expect(manager.reconcile({ enabled: false, sessionState: 'locked', policyGeneration: 1 }))
      .resolves.toBeUndefined();
    expect(notify).toHaveBeenCalledTimes(1);
  });

  it('rejects malformed lifecycle state before calling browser APIs', () => {
    const scripting = makeScripting();
    const manager = new WebsitePasskeyScriptManager({
      scripting: scripting.adapter,
      notifyOpenTopFrames: vi.fn(),
    });

    expect(() => manager.reconcile({
      enabled: true,
      sessionState: 'unlocked',
      policyGeneration: -1,
    })).toThrow('Invalid website passkey script state');
    expect(scripting.adapter.getRegisteredContentScripts).not.toHaveBeenCalled();
  });
});
