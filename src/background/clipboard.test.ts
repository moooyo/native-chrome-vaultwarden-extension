import { describe, it, expect, vi } from 'vitest';
import { createClipboard, CLIPBOARD_CLEAR_ALARM, type ClipboardDeps } from './clipboard.js';

function testDigest(value: string): Uint8Array {
  return new Uint8Array(32).fill(value.charCodeAt(0) & 0xff);
}

function makeDeps(over: Partial<ClipboardDeps> = {}): ClipboardDeps {
  return {
    getClearSeconds: async () => 60,
    createAlarm: vi.fn(),
    clearAlarm: vi.fn(),
    now: () => 1_000,
    digestValue: vi.fn(async (value: string) => testDigest(value)),
    ensureOffscreen: vi.fn(async () => {}),
    sendOffscreen: vi.fn(async () => ({ ok: true, cleared: true })),
    writeOffscreen: vi.fn(async () => ({ ok: true, written: true })),
    closeOffscreen: vi.fn(async () => {}),
    ...over,
  };
}

describe('createClipboard', () => {
  it('precomputes ownership, writes a TOTP offscreen, then claims owned clear', async () => {
    const order: string[] = [];
    const deps = makeDeps({
      writeOffscreen: vi.fn(async () => { order.push('write'); return { ok: true, written: true }; }),
      digestValue: vi.fn(async () => { order.push('digest'); return testDigest('1'); }),
      createAlarm: vi.fn(() => { order.push('alarm'); }),
    });
    const clipboard = createClipboard(deps);

    await expect(clipboard.writeAndScheduleClear('123456')).resolves.toBe(true);
    expect(order).toEqual(['digest', 'write', 'alarm']);
    expect(deps.writeOffscreen).toHaveBeenCalledWith({
      type: 'offscreen.writeClipboard',
      value: '123456',
    });
  });

  it('does not claim clear ownership when the offscreen write fails', async () => {
    const deps = makeDeps({
      writeOffscreen: vi.fn(async () => ({ ok: false, error: 'denied' })),
    });
    const clipboard = createClipboard(deps);

    await expect(clipboard.writeAndScheduleClear('123456')).resolves.toBe(false);
    expect(deps.createAlarm).not.toHaveBeenCalled();
  });

  it('preserves the previous owned clear when a newer offscreen write fails', async () => {
    let sentSnapshot: Parameters<ClipboardDeps['sendOffscreen']>[0] | undefined;
    const deps = makeDeps({
      writeOffscreen: vi.fn(async () => ({ ok: false, error: 'denied' })),
      sendOffscreen: vi.fn(async (message) => {
        sentSnapshot = structuredClone(message);
        return { ok: true, cleared: true };
      }),
    });
    const clipboard = createClipboard(deps);
    await clipboard.scheduleClear('older');
    (deps.clearAlarm as ReturnType<typeof vi.fn>).mockClear();

    await expect(clipboard.writeAndScheduleClear('123456')).resolves.toBe(false);
    expect(deps.clearAlarm).not.toHaveBeenCalled();
    await clipboard.handleClipboardAlarm(61_000);
    expect(sentSnapshot).toEqual({
      type: 'offscreen.clearClipboardIfOwned',
      expectedDigest: Array(32).fill('o'.charCodeAt(0)),
    });
  });

  it('immediately clears a successful slow write when its authority becomes stale', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    let releaseWrite!: () => void;
    let signalWrite!: () => void;
    const writeStarted = new Promise<void>((resolve) => { signalWrite = resolve; });
    const writePending = new Promise<{ ok: true; written: true }>((resolve) => {
      releaseWrite = () => resolve({ ok: true, written: true });
    });
    let current = true;
    let sentSnapshot: Parameters<ClipboardDeps['sendOffscreen']>[0] | undefined;
    const assertCurrent = vi.fn(() => {
      if (!current) throw new Error('stale');
    });
    const deps = makeDeps({
      writeOffscreen: vi.fn(() => {
        signalWrite();
        return writePending;
      }),
      sendOffscreen: vi.fn(async (message) => {
        sentSnapshot = structuredClone(message);
        return { ok: true, cleared: true };
      }),
    });
    const clipboard = createClipboard(deps);

    const copy = clipboard.writeAndScheduleClear('123456', assertCurrent);
    await writeStarted;
    current = false;
    releaseWrite();

    await expect(copy).resolves.toBe(false);
    expect(assertCurrent).toHaveBeenCalledTimes(3);
    expect(deps.createAlarm).not.toHaveBeenCalled();
    expect(sentSnapshot).toEqual({
      type: 'offscreen.clearClipboardIfOwned',
      expectedDigest: Array(32).fill('1'.charCodeAt(0)),
    });
    warn.mockRestore();
  });

  it('accepts a valid Steam TOTP through the shared clipboard validator', async () => {
    const deps = makeDeps();
    const clipboard = createClipboard(deps);

    await expect(clipboard.writeAndScheduleClear('B2CDX')).resolves.toBe(true);
    expect(deps.writeOffscreen).toHaveBeenCalledWith({
      type: 'offscreen.writeClipboard',
      value: 'B2CDX',
    });
  });

  it('writes bounded non-TOTP secrets only through the worker-only message type', async () => {
    const deps = makeDeps();
    const clipboard = createClipboard(deps);

    await expect(clipboard.writeSecretAndScheduleClear('correct horse battery staple'))
      .resolves.toBe(true);
    expect(deps.writeOffscreen).toHaveBeenCalledWith({
      type: 'offscreen.writeSecretClipboard',
      value: 'correct horse battery staple',
    });
  });

  it('keeps the TOTP and generic secret routes semantically separate', async () => {
    const deps = makeDeps();
    const clipboard = createClipboard(deps);

    await expect(clipboard.writeTotpAndScheduleClear('ordinary-password')).resolves.toBe(false);
    await expect(clipboard.writeSecretAndScheduleClear('ordinary-password')).resolves.toBe(true);
    await expect(clipboard.writeSecretAndScheduleClear('x'.repeat(32 * 1_024 + 1))).resolves.toBe(false);
    expect(deps.writeOffscreen).toHaveBeenCalledTimes(1);
  });

  it('serializes an older clear before a newer background write', async () => {
    let release!: () => void;
    const clearPending = new Promise<unknown>((resolve) => {
      release = () => resolve({ ok: true, cleared: true });
    });
    const order: string[] = [];
    const deps = makeDeps({
      sendOffscreen: vi.fn(async () => { order.push('clear'); return clearPending; }),
      writeOffscreen: vi.fn(async () => { order.push('write'); return { ok: true, written: true }; }),
    });
    const clipboard = createClipboard(deps);
    await clipboard.scheduleClear('old-value');
    const clearing = clipboard.handleClipboardAlarm(61_000);
    await Promise.resolve();
    const writing = clipboard.writeAndScheduleClear('123456');
    await Promise.resolve();
    expect(order).toEqual(['clear']);

    release();
    await clearing;
    await expect(writing).resolves.toBe(true);
    expect(order).toEqual(['clear', 'write']);
  });

  it('clears any pending alarm when set to never', async () => {
    const deps = makeDeps({ getClearSeconds: async () => null });
    await createClipboard(deps).scheduleClear('secret');
    expect(deps.clearAlarm).toHaveBeenCalledWith(CLIPBOARD_CLEAR_ALARM);
    expect(deps.createAlarm).not.toHaveBeenCalled();
  });

  it('schedules an alarm at now + max(30, seconds)', async () => {
    const d60 = makeDeps({ getClearSeconds: async () => 60 });
    await createClipboard(d60).scheduleClear('first');
    expect(d60.createAlarm).toHaveBeenCalledWith(CLIPBOARD_CLEAR_ALARM, 61_000);
    const d30 = makeDeps({ getClearSeconds: async () => 30 });
    await createClipboard(d30).scheduleClear('second');
    expect(d30.createAlarm).toHaveBeenCalledWith(CLIPBOARD_CLEAR_ALARM, 31_000);
  });

  it('claims and conditionally clears a TOTP code without persisting its plaintext', async () => {
    let sentSnapshot: Parameters<ClipboardDeps['sendOffscreen']>[0] | undefined;
    const digest = new Uint8Array(32).fill(6);
    const deps = makeDeps({
      digestValue: vi.fn(async () => digest),
      sendOffscreen: vi.fn(async (message) => {
        sentSnapshot = structuredClone(message);
        return { ok: true, cleared: true };
      }),
    });
    const clipboard = createClipboard(deps);

    await clipboard.scheduleClear('123456');
    expect(deps.digestValue).toHaveBeenCalledWith('123456');
    expect(deps.createAlarm).toHaveBeenCalledWith(CLIPBOARD_CLEAR_ALARM, 61_000);
    await clipboard.handleClipboardAlarm(61_000);

    expect(sentSnapshot).toEqual({
      type: 'offscreen.clearClipboardIfOwned',
      expectedDigest: Array(32).fill(6),
    });
    expect(JSON.stringify(sentSnapshot)).not.toContain('123456');
    expect(digest.every((byte) => byte === 0)).toBe(true);
  });

  it('ensures offscreen, sends clear, then closes (close runs even if send throws)', async () => {
    const order: string[] = [];
    let sentSnapshot: Parameters<ClipboardDeps['sendOffscreen']>[0] | undefined;
    const deps = makeDeps({
      ensureOffscreen: vi.fn(async () => { order.push('ensure'); }),
      sendOffscreen: vi.fn(async (message) => {
        sentSnapshot = structuredClone(message);
        order.push('send');
        return { ok: true, cleared: true };
      }),
      closeOffscreen: vi.fn(async () => { order.push('close'); }),
    });
    const clipboard = createClipboard(deps);
    await clipboard.scheduleClear('owned-secret');
    await clipboard.handleClipboardAlarm(61_000);
    expect(order).toEqual(['ensure', 'send', 'close']);
    expect(sentSnapshot).toEqual({
      type: 'offscreen.clearClipboardIfOwned',
      expectedDigest: Array(32).fill('o'.charCodeAt(0)),
    });
    expect(JSON.stringify(sentSnapshot)).not.toContain('owned-secret');
    const liveMessage = (deps.sendOffscreen as ReturnType<typeof vi.fn>).mock.calls[0]![0] as { expectedDigest: number[] };
    expect(liveMessage.expectedDigest.every((byte) => byte === 0)).toBe(true);

    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const throwing = makeDeps({ sendOffscreen: vi.fn(async () => { throw new Error('boom'); }) });
    const throwingClipboard = createClipboard(throwing);
    await throwingClipboard.scheduleClear('owned-secret');
    await throwingClipboard.handleClipboardAlarm(61_000); // must not reject
    expect(throwing.closeOffscreen).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });

  it('logs a rejected offscreen overwrite and still closes the document', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const deps = makeDeps({ sendOffscreen: vi.fn(async () => ({ ok: false, error: 'not focused' })) });
    const clipboard = createClipboard(deps);
    await clipboard.scheduleClear('owned-secret');
    await clipboard.handleClipboardAlarm(61_000);
    expect(warn).toHaveBeenCalledWith('clipboard clear failed', expect.any(Error));
    expect(deps.closeOffscreen).toHaveBeenCalledOnce();
    warn.mockRestore();
  });

  it('does nothing when a restarted worker has no in-memory ownership', async () => {
    const deps = makeDeps();
    await createClipboard(deps).handleClipboardAlarm(61_000);
    expect(deps.ensureOffscreen).not.toHaveBeenCalled();
    expect(deps.sendOffscreen).not.toHaveBeenCalled();
    expect(deps.closeOffscreen).not.toHaveBeenCalled();
  });

  it('accepts a safe not-owned response without warning and consumes the alarm ownership', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const deps = makeDeps({ sendOffscreen: vi.fn(async () => ({ ok: true, cleared: false })) });
    const clipboard = createClipboard(deps);
    await clipboard.scheduleClear('old-secret');
    await clipboard.handleClipboardAlarm(61_000);
    await clipboard.handleClipboardAlarm(61_000);
    expect(deps.sendOffscreen).toHaveBeenCalledOnce();
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it('keeps the newest copy when an older settings lookup resolves late', async () => {
    let resolveFirst: ((seconds: number | null) => void) | undefined;
    let signalFirstLookup!: () => void;
    const firstLookupStarted = new Promise<void>((resolve) => { signalFirstLookup = resolve; });
    const getClearSeconds = vi.fn()
      .mockImplementationOnce(() => {
        signalFirstLookup();
        return new Promise<number | null>((resolve) => { resolveFirst = resolve; });
      })
      .mockResolvedValueOnce(120);
    let sentSnapshot: Parameters<ClipboardDeps['sendOffscreen']>[0] | undefined;
    const deps = makeDeps({
      getClearSeconds,
      sendOffscreen: vi.fn(async (message) => {
        sentSnapshot = structuredClone(message);
        return { ok: true, cleared: true };
      }),
    });
    const clipboard = createClipboard(deps);

    const older = clipboard.scheduleClear('older');
    await firstLookupStarted;
    await clipboard.scheduleClear('newest');
    resolveFirst?.(60);
    await older;

    expect(deps.createAlarm).toHaveBeenCalledOnce();
    expect(deps.createAlarm).toHaveBeenCalledWith(CLIPBOARD_CLEAR_ALARM, 121_000);
    await clipboard.handleClipboardAlarm(121_000);
    expect(sentSnapshot).toEqual({
      type: 'offscreen.clearClipboardIfOwned',
      expectedDigest: Array(32).fill('n'.charCodeAt(0)),
    });
  });

  it('clears ownership and the pending alarm when auto-clear is disabled', async () => {
    let enabled = true;
    const deps = makeDeps({ getClearSeconds: async () => enabled ? 60 : null });
    const clipboard = createClipboard(deps);
    await clipboard.scheduleClear('secret');
    enabled = false;
    await clipboard.scheduleClear('new-value');
    await clipboard.handleClipboardAlarm(61_000);
    expect(deps.clearAlarm).toHaveBeenCalledWith(CLIPBOARD_CLEAR_ALARM);
    expect(deps.sendOffscreen).not.toHaveBeenCalled();
  });

  it('conditionally clears the owned value immediately on a session transition', async () => {
    let sentSnapshot: Parameters<ClipboardDeps['sendOffscreen']>[0] | undefined;
    const digest = new Uint8Array(32).fill(7);
    const deps = makeDeps({
      digestValue: vi.fn(async () => digest),
      sendOffscreen: vi.fn(async (message) => {
        sentSnapshot = structuredClone(message);
        return { ok: true, cleared: true };
      }),
    });
    const clipboard = createClipboard(deps);
    await clipboard.scheduleClear('owned-secret');
    (deps.clearAlarm as ReturnType<typeof vi.fn>).mockClear();

    await clipboard.clearOwnedOnSessionTransition();

    expect(deps.clearAlarm).toHaveBeenCalledTimes(1);
    expect(deps.clearAlarm).toHaveBeenCalledWith(CLIPBOARD_CLEAR_ALARM);
    expect(sentSnapshot).toEqual({
      type: 'offscreen.clearClipboardIfOwned',
      expectedDigest: Array(32).fill(7),
    });
    expect(JSON.stringify(sentSnapshot)).not.toContain('owned-secret');
    expect(digest.every((byte) => byte === 0)).toBe(true);
    await clipboard.handleClipboardAlarm(61_000);
    expect(deps.sendOffscreen).toHaveBeenCalledOnce();
  });

  it('cancels ownership without clearing when the current setting is never', async () => {
    let enabled = true;
    const digest = new Uint8Array(32).fill(8);
    const deps = makeDeps({
      getClearSeconds: async () => enabled ? 60 : null,
      digestValue: vi.fn(async () => digest),
    });
    const clipboard = createClipboard(deps);
    await clipboard.scheduleClear('owned-secret');
    enabled = false;
    (deps.clearAlarm as ReturnType<typeof vi.fn>).mockClear();

    await clipboard.clearOwnedOnSessionTransition();

    expect(deps.clearAlarm).toHaveBeenCalledTimes(1);
    expect(deps.clearAlarm).toHaveBeenCalledWith(CLIPBOARD_CLEAR_ALARM);
    expect(deps.ensureOffscreen).not.toHaveBeenCalled();
    expect(deps.sendOffscreen).not.toHaveBeenCalled();
    expect(digest.every((byte) => byte === 0)).toBe(true);
    await clipboard.handleClipboardAlarm(61_000);
    expect(deps.sendOffscreen).not.toHaveBeenCalled();
  });

  it('preserves a new owner created while a transition clear is reading settings', async () => {
    let resolveTransitionSetting: ((seconds: number | null) => void) | undefined;
    const getClearSeconds = vi.fn()
      .mockResolvedValueOnce(60)
      .mockImplementationOnce(() => new Promise<number | null>((resolve) => {
        resolveTransitionSetting = resolve;
      }))
      .mockResolvedValueOnce(60);
    const sentDigestMarkers: number[] = [];
    const deps = makeDeps({
      getClearSeconds,
      sendOffscreen: vi.fn(async (message) => {
        sentDigestMarkers.push(message.expectedDigest[0]!);
        return { ok: true, cleared: true };
      }),
    });
    const clipboard = createClipboard(deps);
    await clipboard.scheduleClear('older');

    const transitionClear = clipboard.clearOwnedOnSessionTransition();
    await Promise.resolve();
    await clipboard.scheduleClear('newest');
    resolveTransitionSetting?.(60);
    await transitionClear;

    expect(deps.sendOffscreen).not.toHaveBeenCalled();
    await clipboard.handleClipboardAlarm(61_001);
    expect(sentDigestMarkers).toEqual(['n'.charCodeAt(0)]);
  });

  it('takes over an ownership claim still waiting on settings when a transition settles', async () => {
    let resolveSetting: ((seconds: number | null) => void) | undefined;
    let signalSettingLookup!: () => void;
    const settingLookupStarted = new Promise<void>((resolve) => { signalSettingLookup = resolve; });
    let sentSnapshot: Parameters<ClipboardDeps['sendOffscreen']>[0] | undefined;
    const getClearSeconds = vi.fn()
      .mockImplementationOnce(() => {
        signalSettingLookup();
        return new Promise<number | null>((resolve) => { resolveSetting = resolve; });
      })
      .mockResolvedValueOnce(60);
    const deps = makeDeps({
      getClearSeconds,
      sendOffscreen: vi.fn(async (message) => {
        sentSnapshot = structuredClone(message);
        return { ok: true, cleared: true };
      }),
    });
    const clipboard = createClipboard(deps);
    const pendingSchedule = clipboard.scheduleClear('pending-secret');
    await settingLookupStarted;

    const transitionClear = clipboard.clearOwnedOnSessionTransition();
    resolveSetting?.(60);
    await Promise.all([pendingSchedule, transitionClear]);

    expect(deps.createAlarm).not.toHaveBeenCalled();
    expect(deps.sendOffscreen).toHaveBeenCalledOnce();
    expect(sentSnapshot).toEqual({
      type: 'offscreen.clearClipboardIfOwned',
      expectedDigest: Array(32).fill('p'.charCodeAt(0)),
    });
  });

  it('takes over a clipboard claim while its digest is still being computed', async () => {
    let resolveDigest: ((digest: Uint8Array) => void) | undefined;
    let sentSnapshot: Parameters<ClipboardDeps['sendOffscreen']>[0] | undefined;
    const digest = new Uint8Array(32).fill(9);
    const deps = makeDeps({
      digestValue: vi.fn(() => new Promise<Uint8Array>((resolve) => {
        resolveDigest = resolve;
      })),
      sendOffscreen: vi.fn(async (message) => {
        sentSnapshot = structuredClone(message);
        return { ok: true, cleared: true };
      }),
    });
    const clipboard = createClipboard(deps);
    const pendingSchedule = clipboard.scheduleClear('pending-secret');

    const transitionClear = clipboard.clearOwnedOnSessionTransition();
    resolveDigest?.(digest);
    await Promise.all([pendingSchedule, transitionClear]);

    expect(deps.createAlarm).not.toHaveBeenCalled();
    expect(sentSnapshot).toEqual({
      type: 'offscreen.clearClipboardIfOwned',
      expectedDigest: Array(32).fill(9),
    });
    expect(digest.every((byte) => byte === 0)).toBe(true);
  });

  it('uses an established claim when the transition settings re-read fails', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const getClearSeconds = vi.fn()
      .mockResolvedValueOnce(60)
      .mockRejectedValueOnce(new Error('storage unavailable'));
    const deps = makeDeps({ getClearSeconds });
    const clipboard = createClipboard(deps);
    await clipboard.scheduleClear('owned-secret');

    await clipboard.clearOwnedOnSessionTransition();

    expect(warn).toHaveBeenCalledWith('clipboard clear setting read failed', expect.any(Error));
    expect(deps.sendOffscreen).toHaveBeenCalledOnce();
    warn.mockRestore();
  });

  it('preserves a new owner created while an older alarm is being handled', async () => {
    let releaseFirst: (() => void) | undefined;
    const sentDigestMarkers: number[] = [];
    const sendOffscreen = vi.fn()
      .mockImplementationOnce((message: { expectedDigest: number[] }) => new Promise<{ ok: true; cleared: false }>((resolve) => {
        sentDigestMarkers.push(message.expectedDigest[0]!);
        releaseFirst = () => resolve({ ok: true, cleared: false });
      }))
      .mockImplementationOnce((message: { expectedDigest: number[] }) => {
        sentDigestMarkers.push(message.expectedDigest[0]!);
        return Promise.resolve({ ok: true, cleared: true });
      });
    const deps = makeDeps({ sendOffscreen });
    const clipboard = createClipboard(deps);
    await clipboard.scheduleClear('older');
    const olderAlarm = clipboard.handleClipboardAlarm(61_000);
    await Promise.resolve();
    await clipboard.scheduleClear('newest');
    releaseFirst?.();
    await olderAlarm;
    await clipboard.handleClipboardAlarm(61_001);

    expect(sentDigestMarkers).toEqual(['o'.charCodeAt(0), 'n'.charCodeAt(0)]);
  });

  it('ignores an already-dispatched alarm after a newer copy replaces it', async () => {
    let sentSnapshot: Parameters<ClipboardDeps['sendOffscreen']>[0] | undefined;
    const deps = makeDeps({ sendOffscreen: vi.fn(async (message) => {
      sentSnapshot = structuredClone(message);
      return { ok: true, cleared: true };
    }) });
    const clipboard = createClipboard(deps);
    await clipboard.scheduleClear('older');
    await clipboard.scheduleClear('newest');

    await clipboard.handleClipboardAlarm(61_000);
    expect(deps.sendOffscreen).not.toHaveBeenCalled();
    await clipboard.handleClipboardAlarm(61_001);
    expect(sentSnapshot).toEqual({
      type: 'offscreen.clearClipboardIfOwned',
      expectedDigest: Array(32).fill('n'.charCodeAt(0)),
    });
  });

  it('zeroes digests on replacement, cancellation, and alarm completion', async () => {
    const digests = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)];
    const deps = makeDeps({ digestValue: vi.fn(async () => digests.shift()!) });
    const clipboard = createClipboard(deps);

    await clipboard.scheduleClear('first');
    const first = (deps.digestValue as ReturnType<typeof vi.fn>).mock.results[0]!.value as Promise<Uint8Array>;
    const firstDigest = await first;
    await clipboard.scheduleClear('second');
    expect(firstDigest.every((byte) => byte === 0)).toBe(true);

    const second = (deps.digestValue as ReturnType<typeof vi.fn>).mock.results[1]!.value as Promise<Uint8Array>;
    const secondDigest = await second;
    clipboard.cancelClear();
    expect(secondDigest.every((byte) => byte === 0)).toBe(true);

    const alarmDigest = new Uint8Array(32).fill(3);
    const alarmDeps = makeDeps({ digestValue: vi.fn(async () => alarmDigest) });
    const alarmClipboard = createClipboard(alarmDeps);
    await alarmClipboard.scheduleClear('third');
    await alarmClipboard.handleClipboardAlarm(61_000);
    expect(alarmDigest.every((byte) => byte === 0)).toBe(true);
  });
});
