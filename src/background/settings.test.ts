import { describe, it, expect, vi } from 'vitest';
import { createSettingsService } from './settings.js';
import { createMemoryStore } from '../platform/store.js';
import { UriMatchStrategy } from '../core/vault/uri-match.js';
import { isOnIdleAction, isClipboardClearSetting, clipboardClearToSeconds, DEFAULT_ON_IDLE_ACTION, DEFAULT_CLIPBOARD_CLEAR } from './settings.js';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: {}, session: {} } },
}));

describe('settings service', () => {
  it('normalizes serverUrl and stores it', async () => {
    const settings = createSettingsService(createMemoryStore());
    await settings.saveServerUrl('https://vw.example.com/base/');
    expect(await settings.getServerUrl()).toBe('https://vw.example.com/base/');
  });

  it('rejects non-http URLs', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.saveServerUrl('file:///tmp/x')).rejects.toThrow('serverUrl must start with http:// or https://');
  });

  it('defaults URI match strategy to Domain', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.getDefaultUriMatchStrategy()).resolves.toBe(UriMatchStrategy.Domain);
  });

  it('persists a supported URI match strategy', async () => {
    const settings = createSettingsService(createMemoryStore());
    await settings.saveDefaultUriMatchStrategy(UriMatchStrategy.Host);
    await expect(settings.getDefaultUriMatchStrategy()).resolves.toBe(UriMatchStrategy.Host);
  });

  it('rejects unsupported URI match strategy values', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.saveDefaultUriMatchStrategy(6 as never)).rejects.toThrow('unsupported URI match strategy');
  });

  it('defaults lock timeout to 15 minutes', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.getLockTimeout()).resolves.toBe('15');
  });

  it('persists supported lock timeout values including onClose and never', async () => {
    const settings = createSettingsService(createMemoryStore());
    await settings.saveLockTimeout('5');
    await expect(settings.getLockTimeout()).resolves.toBe('5');
    await settings.saveLockTimeout('onClose');
    await expect(settings.getLockTimeout()).resolves.toBe('onClose');
    await settings.saveLockTimeout('never');
    await expect(settings.getLockTimeout()).resolves.toBe('never');
  });

  it('rejects unsupported lock timeout values', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.saveLockTimeout('99' as never)).rejects.toThrow('unsupported lock timeout');
    await expect(settings.saveLockTimeout(15 as never)).rejects.toThrow('unsupported lock timeout');
  });

  it('maps lock timeout to idle milliseconds, with null for onClose and never', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.getIdleMs()).resolves.toBe(15 * 60 * 1000); // default
    await settings.saveLockTimeout('1');
    await expect(settings.getIdleMs()).resolves.toBe(60 * 1000);
    await settings.saveLockTimeout('30');
    await expect(settings.getIdleMs()).resolves.toBe(30 * 60 * 1000);
    await settings.saveLockTimeout('onClose');
    await expect(settings.getIdleMs()).resolves.toBeNull();
    await settings.saveLockTimeout('never');
    await expect(settings.getIdleMs()).resolves.toBeNull();
  });
});

describe('onIdleAction setting', () => {
  it('defaults to lock and round-trips lock/logout', async () => {
    const s = createSettingsService(createMemoryStore());
    expect(await s.getOnIdleAction()).toBe(DEFAULT_ON_IDLE_ACTION);
    expect(DEFAULT_ON_IDLE_ACTION).toBe('lock');
    await s.saveOnIdleAction('logout');
    expect(await s.getOnIdleAction()).toBe('logout');
  });
  it('rejects an unknown action and falls back on a corrupt stored value', async () => {
    const s = createSettingsService(createMemoryStore());
    await expect(s.saveOnIdleAction('sleep' as never)).rejects.toThrow();
    expect(isOnIdleAction('lock')).toBe(true);
    expect(isOnIdleAction('nope')).toBe(false);
  });
});

describe('clipboardClearSeconds setting', () => {
  it('defaults to 60 and round-trips values', async () => {
    const s = createSettingsService(createMemoryStore());
    expect(await s.getClipboardClearSetting()).toBe(DEFAULT_CLIPBOARD_CLEAR);
    expect(DEFAULT_CLIPBOARD_CLEAR).toBe('60');
    await s.saveClipboardClearSetting('never');
    expect(await s.getClipboardClearSetting()).toBe('never');
    expect(await s.getClipboardClearSeconds()).toBeNull();
    await s.saveClipboardClearSetting('120');
    expect(await s.getClipboardClearSeconds()).toBe(120);
  });
  it('validates values and maps never to null', () => {
    expect(isClipboardClearSetting('30')).toBe(true);
    expect(isClipboardClearSetting('15')).toBe(false);
    expect(clipboardClearToSeconds('never')).toBeNull();
    expect(clipboardClearToSeconds('300')).toBe(300);
  });
});
