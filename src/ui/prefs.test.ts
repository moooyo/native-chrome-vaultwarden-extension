// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';

const storage = vi.hoisted(() => ({
  value: undefined as unknown,
  listener: undefined as ((changes: Record<string, { newValue?: unknown }>, area: string) => void) | undefined,
  set: vi.fn(async () => {}),
}));

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: {
        get: vi.fn(async () => ({ 'miyu.prefs': storage.value })),
        set: storage.set,
      },
      onChanged: {
        addListener: vi.fn((listener: typeof storage.listener) => { storage.listener = listener; }),
      },
    },
  },
}));

import {
  DEFAULT_PREFS,
  MIYU_PREFS_SCHEMA_VERSION,
  getPrefs,
  initPrefs,
  sanitizePrefs,
  setPref,
  setPrefs,
  subscribePrefs,
} from './prefs.js';

describe('prefs', () => {
  beforeEach(async () => {
    storage.value = undefined;
    storage.set.mockClear();
    await initPrefs();
    storage.set.mockClear();
  });

  it('exposes versioned defaults for every non-secret generator choice', () => {
    expect(getPrefs()).toEqual({
      schemaVersion: MIYU_PREFS_SCHEMA_VERSION,
      genMode: 'random',
      genLength: 20,
      genLowercase: true,
      genNumbers: true,
      genSymbols: true,
      genUppercase: true,
      genMinNumbers: 1,
      genMinSpecial: 1,
      genAvoidAmbiguous: true,
      genPassphraseWords: 6,
      genPassphraseCapitalize: false,
      genPassphraseNumber: false,
      genPinLength: 14,
      genUsernameType: 'randomWord',
      genUsernameLength: 8,
      genUsernameCapitalize: false,
      genUsernameNumber: false,
    });
    expect(Object.isFrozen(getPrefs())).toBe(true);
  });

  it('migrates the legacy unversioned random-password fields without guessing newer choices', async () => {
    storage.value = {
      genLength: 32,
      genNumbers: false,
      genSymbols: false,
      genUppercase: false,
    };

    await initPrefs();

    expect(getPrefs()).toEqual({
      ...DEFAULT_PREFS,
      genLength: 32,
      genNumbers: false,
      genSymbols: false,
      genUppercase: false,
      genMinNumbers: 0,
      genMinSpecial: 0,
    });
    expect(storage.set).toHaveBeenCalledWith({ 'miyu.prefs': getPrefs() });
  });

  it('migrates version 2 preferences and preserves every existing choice', async () => {
    storage.value = {
      ...DEFAULT_PREFS,
      schemaVersion: 2,
      genMode: 'memorable',
      genLength: 40,
      genNumbers: false,
      genSymbols: true,
      genUppercase: false,
      genPassphraseWords: 9,
    };

    await initPrefs();

    expect(getPrefs()).toMatchObject({
      schemaVersion: MIYU_PREFS_SCHEMA_VERSION,
      genMode: 'memorable',
      genLength: 40,
      genLowercase: true,
      genNumbers: false,
      genMinNumbers: 0,
      genSymbols: true,
      genMinSpecial: 1,
      genUppercase: false,
      genAvoidAmbiguous: true,
      genPassphraseWords: 9,
    });
    expect(storage.set).toHaveBeenCalledWith({ 'miyu.prefs': getPrefs() });
  });

  it('strictly defaults forged fields and rejects unknown schema versions', () => {
    expect(sanitizePrefs({
      ...DEFAULT_PREFS,
      genMode: 'forged',
      genLength: 129,
      genMinNumbers: 10,
      genMinSpecial: Number.NaN,
      genPassphraseWords: Number.NaN,
      genPinLength: 41,
      genUsernameType: 'email',
      genUsernameLength: '12',
      genUsernameCapitalize: 'true',
    })).toEqual(DEFAULT_PREFS);
    expect(sanitizePrefs({ ...DEFAULT_PREFS, schemaVersion: 999, genLength: 30 })).toEqual(DEFAULT_PREFS);
    expect(sanitizePrefs([])).toEqual(DEFAULT_PREFS);
  });

  it('persists a complete current-schema object and notifies subscribers', () => {
    const listener = vi.fn();
    const unsubscribe = subscribePrefs(listener);

    setPref('genMode', 'memorable');
    setPref('genPassphraseWords', 10);

    expect(getPrefs().genMode).toBe('memorable');
    expect(getPrefs().genPassphraseWords).toBe(10);
    expect(listener).toHaveBeenCalledTimes(2);
    expect(storage.set).toHaveBeenLastCalledWith({
      'miyu.prefs': expect.objectContaining({
        schemaVersion: MIYU_PREFS_SCHEMA_VERSION,
        genMode: 'memorable',
        genPassphraseWords: 10,
        genLength: 20,
        genUsernameType: 'randomWord',
      }),
    });
    expect(JSON.stringify(storage.set.mock.calls.at(-1))).not.toContain('example.com');
    unsubscribe();
  });

  it('updates coupled character-class preferences atomically', () => {
    const listener = vi.fn();
    const unsubscribe = subscribePrefs(listener);

    setPrefs({ genNumbers: false, genMinNumbers: 0 });

    expect(getPrefs()).toMatchObject({ genNumbers: false, genMinNumbers: 0 });
    expect(listener).toHaveBeenCalledOnce();
    expect(storage.set).toHaveBeenCalledTimes(1);

    setPrefs({ genNumbers: true, genMinNumbers: 4 });
    expect(getPrefs()).toMatchObject({ genNumbers: true, genMinNumbers: 4 });
    expect(listener).toHaveBeenCalledTimes(2);
    expect(storage.set).toHaveBeenCalledTimes(2);
    unsubscribe();
  });

  it('ignores invalid and no-op writes', () => {
    const listener = vi.fn();
    const unsubscribe = subscribePrefs(listener);

    setPref('genLength', Number.NaN);
    setPref('genUsernameLength', 33);
    setPref('genNumbers', getPrefs().genNumbers);

    expect(getPrefs()).toEqual(DEFAULT_PREFS);
    expect(listener).not.toHaveBeenCalled();
    expect(storage.set).not.toHaveBeenCalled();
    unsubscribe();
  });

  it('applies a sanitized external local-storage change to subscribers', () => {
    const listener = vi.fn();
    const unsubscribe = subscribePrefs(listener);
    const external = {
      ...DEFAULT_PREFS,
      genMode: 'username' as const,
      genUsernameType: 'catchAll' as const,
      genUsernameLength: 16,
      genUsernameNumber: true,
    };

    storage.listener?.({ 'miyu.prefs': { newValue: external } }, 'local');

    expect(getPrefs()).toEqual(external);
    expect(listener).toHaveBeenCalledOnce();
    storage.listener?.({ 'miyu.prefs': { newValue: DEFAULT_PREFS } }, 'sync');
    expect(getPrefs()).toEqual(external);
    unsubscribe();
  });
});
