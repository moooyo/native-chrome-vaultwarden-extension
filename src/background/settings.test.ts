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
});
