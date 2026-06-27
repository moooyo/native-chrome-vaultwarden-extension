import { describe, it, expect, vi } from 'vitest';
import { createSettingsService } from './settings.js';
import { createMemoryStore } from '../platform/store.js';

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
});
