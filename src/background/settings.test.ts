import { describe, it, expect, vi } from 'vitest';
import { createSettingsService } from './settings.js';
import { createMemoryStore } from '../platform/store.js';
import { UriMatchStrategy } from '../core/vault/uri-match.js';

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
