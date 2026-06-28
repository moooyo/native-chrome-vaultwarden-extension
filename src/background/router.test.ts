import { describe, it, expect, vi } from 'vitest';
import type { SessionState } from '../core/session/session-manager.js';
import type { UriMatchStrategySetting } from '../core/vault/uri-match.js';
import { createRouter } from './router.js';

describe('router', () => {
  it('routes auth.getState', async () => {
    const router = createRouter({
      auth: { getState: vi.fn(async (): Promise<SessionState> => 'locked') },
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'auth.getState' })).resolves.toEqual({ ok: true, data: { state: 'locked' } });
  });

  it('turns thrown errors into ok:false responses', async () => {
    const router = createRouter({
      auth: { login: vi.fn(async () => { throw new Error('bad password'); }) },
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'auth.login', email: 'u', masterPassword: 'p' }))
      .resolves.toEqual({ ok: false, error: { code: 'error', message: 'bad password' } });
  });

  it('routes vault.getField', async () => {
    const router = createRouter({
      auth: {},
      vault: { getField: vi.fn(async () => 'secret') },
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'vault.getField', id: '1', field: 'password' }))
      .resolves.toEqual({ ok: true, data: { value: 'secret' } });
  });

  it('vault.getField omits value property when field is undefined', async () => {
    const router = createRouter({
      auth: {},
      vault: { getField: vi.fn(async () => undefined) },
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'vault.getField', id: 'missing', field: 'password' }))
      .resolves.toEqual({ ok: true, data: {} });
  });

  it('routes settings.get returning serverUrl', async () => {
    const router = createRouter({
      auth: {},
      vault: {},
      settings: {
        getServerUrl: vi.fn(async () => 'https://vault.example.com'),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'settings.get' }))
      .resolves.toEqual({ ok: true, data: { serverUrl: 'https://vault.example.com', defaultUriMatchStrategy: 0 } });
  });

  it('routes settings.get when serverUrl is undefined', async () => {
    const router = createRouter({
      auth: {},
      vault: {},
      settings: {
        getServerUrl: vi.fn(async () => undefined),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'settings.get' }))
      .resolves.toEqual({ ok: true, data: { defaultUriMatchStrategy: 0 } });
  });

  it('routes settings.save', async () => {
    const save = vi.fn(async () => {});
    const router = createRouter({
      auth: {},
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: save,
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'settings.save', serverUrl: 'https://vault.example.com' }))
      .resolves.toEqual({ ok: true, data: null });
    expect(save).toHaveBeenCalledWith('https://vault.example.com');
  });

  it('routes settings.get with default autofill strategy', async () => {
    const router = createRouter({
      auth: {},
      vault: {},
      settings: {
        getServerUrl: vi.fn(async () => 'https://vault.example.com'),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'settings.get' }))
      .resolves.toEqual({ ok: true, data: { serverUrl: 'https://vault.example.com', defaultUriMatchStrategy: 0 } });
  });

  it('routes settings.save with default autofill strategy', async () => {
    const saveServerUrl = vi.fn(async () => {});
    const saveDefaultUriMatchStrategy = vi.fn(async () => {});
    const router = createRouter({
      auth: {},
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl,
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy,
      },
    });
    await expect(router.handle({ type: 'settings.save', serverUrl: 'https://vault.example.com', defaultUriMatchStrategy: 1 }))
      .resolves.toEqual({ ok: true, data: null });
    expect(saveServerUrl).toHaveBeenCalledWith('https://vault.example.com');
    expect(saveDefaultUriMatchStrategy).toHaveBeenCalledWith(1);
  });

  it('routes auth.lock', async () => {
    const lock = vi.fn(async () => {});
    const router = createRouter({
      auth: { lock },
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'auth.lock' })).resolves.toEqual({ ok: true, data: null });
    expect(lock).toHaveBeenCalledTimes(1);
  });

  it('routes auth.logout', async () => {
    const logout = vi.fn(async () => {});
    const router = createRouter({
      auth: { logout },
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'auth.logout' })).resolves.toEqual({ ok: true, data: null });
    expect(logout).toHaveBeenCalledTimes(1);
  });

  it('routes vault.listItems', async () => {
    const items = [{ id: '1', name: 'item', uris: [], loginUris: [], type: 1 as const, favorite: false }];
    const router = createRouter({
      auth: {},
      vault: { listItems: vi.fn(async () => items) },
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'vault.listItems' }))
      .resolves.toEqual({ ok: true, data: items });
  });

  it('turns non-Error throws into ok:false with string message', async () => {
    const router = createRouter({
      auth: { lock: vi.fn(async () => { throw 'string error'; }) },
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'auth.lock' }))
      .resolves.toEqual({ ok: false, error: { code: 'error', message: 'string error' } });
  });

  it('auth.submitTwoFactor omits remember property when undefined', async () => {
    const submitTwoFactor = vi.fn(async () => ({ kind: 'unlocked' as const }));
    const router = createRouter({
      auth: { submitTwoFactor },
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'auth.submitTwoFactor', provider: 0, code: '123456' }))
      .resolves.toEqual({ ok: true, data: { kind: 'unlocked' } });
    expect(submitTwoFactor).toHaveBeenCalledWith({ provider: 0, code: '123456' });
    expect(submitTwoFactor).toHaveBeenCalledTimes(1);
  });

  it('auth.submitTwoFactor includes remember property when provided', async () => {
    const submitTwoFactor = vi.fn(async () => ({ kind: 'unlocked' as const }));
    const router = createRouter({
      auth: { submitTwoFactor },
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'auth.submitTwoFactor', provider: 0, code: '123456', remember: true }))
      .resolves.toEqual({ ok: true, data: { kind: 'unlocked' } });
    expect(submitTwoFactor).toHaveBeenCalledWith({ provider: 0, code: '123456', remember: true });
    expect(submitTwoFactor).toHaveBeenCalledTimes(1);
  });
});
