import { describe, it, expect, vi } from 'vitest';
import type { SessionState } from '../core/session/session-manager.js';
import type { UriMatchStrategySetting } from '../core/vault/uri-match.js';
import type { LockTimeoutSetting, OnIdleAction, ClipboardClearSetting } from './settings.js';
import { AppError } from '../core/errors.js';
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
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
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
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
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
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
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
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
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
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'settings.get' }))
      .resolves.toEqual({ ok: true, data: { serverUrl: 'https://vault.example.com', defaultUriMatchStrategy: 0, lockTimeout: '15', onIdleAction: 'lock', clipboardClearSeconds: '60' } });
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
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'settings.get' }))
      .resolves.toEqual({ ok: true, data: { defaultUriMatchStrategy: 0, lockTimeout: '15', onIdleAction: 'lock', clipboardClearSeconds: '60' } });
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
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
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
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'settings.get' }))
      .resolves.toEqual({ ok: true, data: { serverUrl: 'https://vault.example.com', defaultUriMatchStrategy: 0, lockTimeout: '15', onIdleAction: 'lock', clipboardClearSeconds: '60' } });
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
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'settings.save', serverUrl: 'https://vault.example.com', defaultUriMatchStrategy: 1 }))
      .resolves.toEqual({ ok: true, data: null });
    expect(saveServerUrl).toHaveBeenCalledWith('https://vault.example.com');
    expect(saveDefaultUriMatchStrategy).toHaveBeenCalledWith(1);
  });

  it('routes settings.save persisting lockTimeout when provided', async () => {
    const saveLockTimeout = vi.fn(async () => {});
    const router = createRouter({
      auth: {},
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout,
        getOnIdleAction: vi.fn(async () => 'lock' as const),
        saveOnIdleAction: vi.fn(),
        getClipboardClearSetting: vi.fn(async () => '60' as const),
        saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'settings.save', serverUrl: 'https://vault.example.com', lockTimeout: '30' }))
      .resolves.toEqual({ ok: true, data: null });
    expect(saveLockTimeout).toHaveBeenCalledWith('30');
  });

  it('routes settings.save without lockTimeout leaves it untouched', async () => {
    const saveLockTimeout = vi.fn(async () => {});
    const router = createRouter({
      auth: {},
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout,
        getOnIdleAction: vi.fn(async () => 'lock' as const),
        saveOnIdleAction: vi.fn(),
        getClipboardClearSetting: vi.fn(async () => '60' as const),
        saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'settings.save', serverUrl: 'https://vault.example.com' }))
      .resolves.toEqual({ ok: true, data: null });
    expect(saveLockTimeout).not.toHaveBeenCalled();
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
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
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
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'auth.logout' })).resolves.toEqual({ ok: true, data: null });
    expect(logout).toHaveBeenCalledTimes(1);
  });

  it('routes vault.listItems', async () => {
    const envelope = { items: [{ id: '1', name: 'item', uris: [], loginUris: [], type: 1 as const, favorite: false }], folders: [], collections: [], orgPermissions: [] };
    const router = createRouter({
      auth: {},
      vault: { listItems: vi.fn(async () => envelope) },
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'vault.listItems' }))
      .resolves.toEqual({ ok: true, data: envelope });
  });

  it('routes vault.getCipherDetail and vault.getSkippedOrgCount', async () => {
    const cipher = { id: 'card-1', name: 'Card', type: 3 as const, favorite: false, uris: [], loginUris: [], card: { brand: 'Visa' } };
    const router = createRouter({
      auth: {},
      vault: {
        getCipherDetail: vi.fn(async () => cipher),
        getSkippedOrgCount: vi.fn(async () => 2),
      },
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'vault.getCipherDetail', id: 'card-1' }))
      .resolves.toEqual({ ok: true, data: { cipher } });
    await expect(router.handle({ type: 'vault.getSkippedOrgCount' }))
      .resolves.toEqual({ ok: true, data: { count: 2 } });
  });

  it('routes vault.getTotp and maps an absent code to null', async () => {
    const getTotpCode = vi.fn(async (id: string) =>
      id === 'has' ? { code: '081804', period: 30, remaining: 1 } : undefined);
    const router = createRouter({
      auth: {},
      vault: { getTotpCode },
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'vault.getTotp', id: 'has' }))
      .resolves.toEqual({ ok: true, data: { totp: { code: '081804', period: 30, remaining: 1 } } });
    await expect(router.handle({ type: 'vault.getTotp', id: 'none' }))
      .resolves.toEqual({ ok: true, data: { totp: null } });
    expect(getTotpCode).toHaveBeenCalledWith('has', undefined);
  });

  it('routes vault folder mutations to the matching VaultService methods', async () => {
    const listing = { items: [], folders: [{ id: 'f1', name: 'Work' }], collections: [], orgPermissions: [] };
    const createFolder = vi.fn(async () => listing);
    const renameFolder = vi.fn(async () => listing);
    const deleteFolder = vi.fn(async () => listing);
    const router = createRouter({
      auth: {},
      vault: { createFolder, renameFolder, deleteFolder },
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'vault.createFolder', name: 'Work' })).resolves.toEqual({ ok: true, data: listing });
    expect(createFolder).toHaveBeenCalledWith('Work');
    await expect(router.handle({ type: 'vault.renameFolder', id: 'f1', name: 'Home' })).resolves.toEqual({ ok: true, data: listing });
    expect(renameFolder).toHaveBeenCalledWith('f1', 'Home');
    await expect(router.handle({ type: 'vault.deleteFolder', id: 'f1' })).resolves.toEqual({ ok: true, data: listing });
    expect(deleteFolder).toHaveBeenCalledWith('f1');
  });

  it('routes collection CRUD + membership to the vault service', async () => {
    const listing = { items: [], folders: [], collections: [], orgPermissions: [] };
    const createCollection = vi.fn(async () => listing);
    const renameCollection = vi.fn(async () => listing);
    const deleteCollection = vi.fn(async () => listing);
    const setCipherCollections = vi.fn(async () => listing);
    const router = createRouter({
      auth: {},
      vault: { createCollection, renameCollection, deleteCollection, setCipherCollections },
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'vault.createCollection', organizationId: 'o1', name: 'C' })).resolves.toEqual({ ok: true, data: listing });
    expect(createCollection).toHaveBeenCalledWith('o1', 'C');
    await expect(router.handle({ type: 'vault.renameCollection', organizationId: 'o1', id: 'c1', name: 'N' })).resolves.toEqual({ ok: true, data: listing });
    expect(renameCollection).toHaveBeenCalledWith('o1', 'c1', 'N');
    await expect(router.handle({ type: 'vault.deleteCollection', organizationId: 'o1', id: 'c1' })).resolves.toEqual({ ok: true, data: listing });
    expect(deleteCollection).toHaveBeenCalledWith('o1', 'c1');
    await expect(router.handle({ type: 'vault.setCipherCollections', id: 'ci1', collectionIds: ['c1'] })).resolves.toEqual({ ok: true, data: listing });
    expect(setCipherCollections).toHaveBeenCalledWith('ci1', ['c1']);
  });

  it('routes vault cipher mutations and getCipherInput', async () => {
    const listing = { items: [], folders: [], collections: [], orgPermissions: [] };
    const input = { type: 1 as const, name: 'GitHub', login: { username: 'octo' } };
    const createCipher = vi.fn(async () => listing);
    const updateCipher = vi.fn(async () => listing);
    const deleteCipher = vi.fn(async () => listing);
    const softDeleteCipher = vi.fn(async () => listing);
    const restoreCipher = vi.fn(async () => listing);
    const getCipherInput = vi.fn(async (id: string) => (id === 'c1' ? input : undefined));
    const router = createRouter({
      auth: {},
      vault: { createCipher, updateCipher, deleteCipher, softDeleteCipher, restoreCipher, getCipherInput },
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'vault.createCipher', input })).resolves.toEqual({ ok: true, data: listing });
    expect(createCipher).toHaveBeenCalledWith(input);
    await expect(router.handle({ type: 'vault.updateCipher', id: 'c1', input })).resolves.toEqual({ ok: true, data: listing });
    expect(updateCipher).toHaveBeenCalledWith('c1', input);
    await expect(router.handle({ type: 'vault.deleteCipher', id: 'c1' })).resolves.toEqual({ ok: true, data: listing });
    expect(deleteCipher).toHaveBeenCalledWith('c1');
    await expect(router.handle({ type: 'vault.softDeleteCipher', id: 'c1' })).resolves.toEqual({ ok: true, data: listing });
    expect(softDeleteCipher).toHaveBeenCalledWith('c1');
    await expect(router.handle({ type: 'vault.restoreCipher', id: 'c1' })).resolves.toEqual({ ok: true, data: listing });
    expect(restoreCipher).toHaveBeenCalledWith('c1');
    await expect(router.handle({ type: 'vault.getCipherInput', id: 'c1' })).resolves.toEqual({ ok: true, data: { input } });
    await expect(router.handle({ type: 'vault.getCipherInput', id: 'missing' })).resolves.toEqual({ ok: true, data: { input: null } });
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
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
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
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
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
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'auth.submitTwoFactor', provider: 0, code: '123456', remember: true }))
      .resolves.toEqual({ ok: true, data: { kind: 'unlocked' } });
    expect(submitTwoFactor).toHaveBeenCalledWith({ provider: 0, code: '123456', remember: true });
    expect(submitTwoFactor).toHaveBeenCalledTimes(1);
  });

  it('auth.isDeviceRemembered returns the remembered flag and forwards the email', async () => {
    const isDeviceRemembered = vi.fn(async () => true);
    const router = createRouter({
      auth: { isDeviceRemembered },
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'auth.isDeviceRemembered', email: 'u@x.com' }))
      .resolves.toEqual({ ok: true, data: { remembered: true } });
    expect(isDeviceRemembered).toHaveBeenCalledWith('u@x.com');
  });

  it('auth.forgetDevice forwards the email and returns null data', async () => {
    const forgetDevice = vi.fn(async () => {});
    const router = createRouter({
      auth: { forgetDevice },
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'auth.forgetDevice', email: 'u@x.com' }))
      .resolves.toEqual({ ok: true, data: null });
    expect(forgetDevice).toHaveBeenCalledWith('u@x.com');
  });

  it('preserves typed application error codes', async () => {
    const router = createRouter({
      auth: { lock: vi.fn(async () => { throw new AppError('locked', 'Vault is locked'); }) },
      vault: {},
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'auth.lock' }))
      .resolves.toEqual({ ok: false, error: { code: 'locked', message: 'Vault is locked' } });
  });

  it('routes autofill.findCandidates through settings default strategy', async () => {
    const findAutofillCandidates = vi.fn(async () => [{
      id: '1',
      name: 'Example',
      username: 'me@example.com',
      matchedUri: 'https://example.com',
      matchType: 0 as const,
      favorite: false,
    }]);
    const router = createRouter({
      auth: {},
      vault: { findAutofillCandidates },
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'autofill.findCandidates', frameUrl: 'https://example.com/login' }))
      .resolves.toEqual({ ok: true, data: [{
        id: '1',
        name: 'Example',
        username: 'me@example.com',
        matchedUri: 'https://example.com',
        matchType: 0,
        favorite: false,
      }] });
    expect(findAutofillCandidates).toHaveBeenCalledWith('https://example.com/login', 0);
  });

  it('routes autofill.getCredentials through settings default strategy', async () => {
    const getAutofillCredentials = vi.fn(async () => ({ username: 'me@example.com', password: 'secret' }));
    const router = createRouter({
      auth: {},
      vault: { getAutofillCredentials },
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 1),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    await expect(router.handle({ type: 'autofill.getCredentials', cipherId: '1', frameUrl: 'https://example.com/login' }))
      .resolves.toEqual({ ok: true, data: { username: 'me@example.com', password: 'secret' } });
    expect(getAutofillCredentials).toHaveBeenCalledWith('1', 'https://example.com/login', 1);
  });

  const settingsStub = {
    getServerUrl: vi.fn(),
    saveServerUrl: vi.fn(),
    getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
    saveDefaultUriMatchStrategy: vi.fn(),
    getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
    saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
  };

  it('routes autofill.findFillItems to vault.findFillItems', async () => {
    const findFillItems = vi.fn(async () => [{ id: 'c1', name: 'Visa', favorite: false }]);
    const router = createRouter({ auth: {}, vault: { findFillItems }, settings: settingsStub });
    const res = await router.handle({ type: 'autofill.findFillItems', kind: 'card' });
    expect(findFillItems).toHaveBeenCalledWith('card');
    expect(res).toEqual({ ok: true, data: [{ id: 'c1', name: 'Visa', favorite: false }] });
  });

  it('routes autofill.getFillData to vault.getFillData', async () => {
    const getFillData = vi.fn(async () => ({ number: '4111' }));
    const router = createRouter({ auth: {}, vault: { getFillData }, settings: settingsStub });
    const res = await router.handle({ type: 'autofill.getFillData', cipherId: 'c1', kind: 'card' });
    expect(getFillData).toHaveBeenCalledWith('c1', 'card');
    expect(res).toEqual({ ok: true, data: { number: '4111' } });
  });

  it('routes sends.createFile to vault.createFileSend with the server URL', async () => {
    const createFileSend = vi.fn(async () => ({ id: 's1', url: 'u', name: 'Doc', type: 1 }));
    const settings = { getServerUrl: vi.fn(async () => 'http://localhost:8080'), saveServerUrl: vi.fn(), getDefaultUriMatchStrategy: vi.fn(async () => 0), saveDefaultUriMatchStrategy: vi.fn(), getLockTimeout: vi.fn(async () => '15'), saveLockTimeout: vi.fn() };
    const router = createRouter({ auth: {}, vault: { createFileSend } as never, settings: settings as never });
    const res = await router.handle({ type: 'sends.createFile', input: { name: 'Doc', deletionDays: 7 } as never, dataB64: 'AQID', fileName: 'secret.pdf' });
    expect(createFileSend).toHaveBeenCalledWith({ name: 'Doc', deletionDays: 7 }, 'AQID', 'secret.pdf', 'http://localhost:8080');
    expect(res).toEqual({ ok: true, data: { send: { id: 's1', url: 'u', name: 'Doc', type: 1 } } });
  });

  it('routes sends.update to vault.updateSend with the server URL', async () => {
    const updateSend = vi.fn(async () => ({ id: 's1', url: 'u', name: 'New', type: 0 }));
    const settings = { getServerUrl: vi.fn(async () => 'http://localhost:8080'), saveServerUrl: vi.fn(), getDefaultUriMatchStrategy: vi.fn(async () => 0), saveDefaultUriMatchStrategy: vi.fn(), getLockTimeout: vi.fn(async () => '15'), saveLockTimeout: vi.fn() };
    const router = createRouter({ auth: {}, vault: { updateSend } as never, settings: settings as never });
    const res = await router.handle({ type: 'sends.update', id: 's1', input: { name: 'New' } as never });
    expect(updateSend).toHaveBeenCalledWith('s1', { name: 'New' }, 'http://localhost:8080');
    expect(res).toEqual({ ok: true, data: { send: { id: 's1', url: 'u', name: 'New', type: 0 } } });
  });

  it('routes vault.checkPwned to vault.getPwnedReport', async () => {
    const getPwnedReport = vi.fn(async () => [{ id: 'a', pwnedCount: 5 }]);
    const router = createRouter({ auth: {}, vault: { getPwnedReport } as never, settings: {
      getServerUrl: vi.fn(), saveServerUrl: vi.fn(), getDefaultUriMatchStrategy: vi.fn(async () => 0), saveDefaultUriMatchStrategy: vi.fn(), getLockTimeout: vi.fn(async () => '15'), saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
    } as never });
    const res = await router.handle({ type: 'vault.checkPwned' });
    expect(getPwnedReport).toHaveBeenCalled();
    expect(res).toEqual({ ok: true, data: { entries: [{ id: 'a', pwnedCount: 5 }] } });
  });

  it('vault.hasPasskey forwards origin and allowedCredentialIds', async () => {
    const hasMatchingPasskey = vi.fn(async () => true);
    const router = createRouter({ auth: {}, vault: { hasMatchingPasskey } as never, settings: {
      getServerUrl: vi.fn(), saveServerUrl: vi.fn(), getDefaultUriMatchStrategy: vi.fn(async () => 0), saveDefaultUriMatchStrategy: vi.fn(), getLockTimeout: vi.fn(async () => '15'), saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
    } as never });
    await expect(router.handle({ type: 'vault.hasPasskey', rpId: 'example.com', origin: 'https://example.com', allowedCredentialIds: ['a'] }))
      .resolves.toEqual({ ok: true, data: { matches: true } });
    expect(hasMatchingPasskey).toHaveBeenCalledWith({ rpId: 'example.com', origin: 'https://example.com', allowedCredentialIds: ['a'] });
  });

  it('saves security settings and schedules a clipboard clear', async () => {
    const settings = {
      getServerUrl: async () => 'https://x', getDefaultUriMatchStrategy: async () => 0,
      getLockTimeout: async () => '15', getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'),
      getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveOnIdleAction: vi.fn(async () => {}),
      saveClipboardClearSetting: vi.fn(async () => {}), saveServerUrl: vi.fn(), saveDefaultUriMatchStrategy: vi.fn(), saveLockTimeout: vi.fn(),
    };
    const clipboard = { scheduleClear: vi.fn(async () => {}) };
    const router = createRouter({ auth: {} as never, vault: {} as never, settings: settings as never, clipboard } as never);

    const got = await router.handle({ type: 'settings.get' } as never);
    expect(got).toMatchObject({ ok: true, data: { onIdleAction: 'lock', clipboardClearSeconds: '60' } });

    await router.handle({ type: 'settings.saveSecurity', onIdleAction: 'logout', clipboardClearSeconds: '120' } as never);
    expect(settings.saveOnIdleAction).toHaveBeenCalledWith('logout');
    expect(settings.saveClipboardClearSetting).toHaveBeenCalledWith('120');

    await router.handle({ type: 'clipboard.scheduleClear' } as never);
    expect(clipboard.scheduleClear).toHaveBeenCalledTimes(1);
  });

  it('clipboard.scheduleClear throws when clipboard dep is not wired', async () => {
    const router = createRouter({ auth: {}, vault: {}, settings: settingsStub });
    const res = await router.handle({ type: 'clipboard.scheduleClear' });
    expect(res).toEqual({ ok: false, error: { code: 'error', message: 'clipboard is not wired' } });
  });

  it('routes auth.rotateAccountKey', async () => {
    const auth = { rotateAccountKey: vi.fn(async () => {}) };
    const router = createRouter({ auth: auth as never, vault: {} as never, settings: {} as never } as never);
    expect(await router.handle({ type: 'auth.rotateAccountKey', masterPassword: 'pw' } as never)).toEqual({ ok: true, data: null });
    expect(auth.rotateAccountKey).toHaveBeenCalledWith('pw');
  });
});
