// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    runtime: {
      sendMessage: vi.fn(),
      getURL: vi.fn((path: string) => path),
      getManifest: vi.fn(() => ({ version: '1.3.0' })),
      openOptionsPage: vi.fn(),
      onMessage: { addListener: vi.fn(), removeListener: vi.fn() },
    },
    commands: { getAll: vi.fn(async () => []) },
    permissions: { request: vi.fn(async () => true) },
    tabs: { query: vi.fn(async () => []), create: vi.fn() },
    storage: { local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, onChanged: { addListener: vi.fn(), removeListener: vi.fn() } },
  },
}));

import './options-app.js';
import browser from 'webextension-polyfill';
import { t } from '../i18n/index.js';
import type { VwOptionsApp } from './options-app.js';
import {
  VaultTransferClientError,
  type VaultTransferDownloadArtifact,
} from './vault-transfer-client.js';
import type {
  LoadedSettings,
  OptionsDeps,
  OptionsRequest,
  OptionsVaultTransferClient,
} from './types.js';
import type {
  VaultTransferImportResultMessage,
  VaultTransferPortPreviewModel,
  VaultTransferRecoveryStatus,
} from '../../messaging/vault-transfer-port.js';
import { createGeneratorPolicySnapshot } from '../../core/generator/enterprise-password-policy.js';

type Req = Parameters<OptionsRequest>[0];
type Res = Awaited<ReturnType<OptionsRequest>>;
type BinaryUpload = NonNullable<OptionsDeps['uploadBinaryTransfer']>;
type BinaryUploadResult = Awaited<ReturnType<BinaryUpload>>;
type ReqHandler<K extends Req['type']> = (req: Extract<Req, { type: K }>) => Res | Promise<Res>;

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => { resolve = next; });
  return { promise, resolve };
}

async function nextTask(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

function fakeRequest(handlers: Partial<{ [K in Req['type']]: ReqHandler<K> }>): OptionsRequest {
  const dispatch = async (req: Req): Promise<Res> => {
    const handler = handlers[req.type] as ReqHandler<Req['type']> | undefined;
    if (handler) return handler(req);
    return { ok: true, data: null };
  };
  return dispatch as OptionsRequest;
}

const loadedSettings: LoadedSettings = {
  serverUrl: 'https://vault.example.com/',
  defaultUriMatchStrategy: 0,
  inlineSuggestions: true,
  pageLoadFill: false,
  pageLoadFillDefault: true,
  autoCopyTotp: true,
  showMatchingLoginCount: true,
  savePromptEnabled: true,
  updatePromptEnabled: false,
  savePromptExcludedDomains: ['never-save.example'],
  blockedDomains: ['blocked.example'],
  autofillPolicyValid: true,
  websitePasskeys: { enabled: false, excludedDomains: [], valid: true },
  httpAuth: { enabled: false, allowedOrigins: [], valid: true },
  lockTimeout: '15',
  onIdleAction: 'lock',
  clipboardClearSeconds: '60',
  enterprisePolicy: {
    pinUnlockAllowed: true,
    maximumVaultTimeoutManaged: false,
    maximumVaultTimeoutMode: 'local',
    uriMatchDefaultManaged: false,
    uriMatchDefaultMalformed: false,
    activateAutofillManaged: false,
  },
  generator: createGeneratorPolicySnapshot(null, 1),
};

const transferPreview: VaultTransferPortPreviewModel = {
  format: 'json',
  scope: 'personal',
  phase: 'previewed',
  counts: { folders: 1, collections: 2, items: 3, attachments: 0 },
  diagnostics: { errors: [], warnings: [], unsupported: [] },
  organizationTargetRequired: false,
  hasUnknownOutcome: false,
  canCommit: true,
};

const completedImportResult: VaultTransferImportResultMessage = {
  version: 1,
  type: 'import.result',
  transferId: '00000000-0000-4000-8000-000000000001',
  phase: 'completed',
  status: 'completed',
  counts: { committed: 4, rejected: 0, skipped: 0, outcomeUnknown: 0 },
  mustSyncBeforeRetry: false,
};

const emptyRecoveryStatus: VaultTransferRecoveryStatus = {
  count: 0,
  unresolvedUnknownCount: 0,
  reconcileRequiredCount: 0,
  omittedCount: 0,
  barriers: [],
};

const clearableRecoveryStatus: VaultTransferRecoveryStatus = {
  count: 1,
  unresolvedUnknownCount: 1,
  reconcileRequiredCount: 0,
  omittedCount: 0,
  barriers: [{
    transferId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    reason: 'outcome_unknown',
    reconciled: true,
    clearable: true,
  }],
};
const EXPORT_AUTHORIZATION_ID = '33333333-3333-4333-8333-333333333333';

function makeTransferClient(
  overrides: Partial<OptionsVaultTransferClient> = {},
): OptionsVaultTransferClient {
  const artifact: VaultTransferDownloadArtifact = {
    blob: new Blob(['{}'], { type: 'application/json' }),
    fileName: 'miyu-vault.json',
    format: 'json',
  };
  return {
    import: vi.fn(async () => transferPreview),
    confirm: vi.fn(async () => completedImportResult),
    export: vi.fn(async () => artifact),
    inspectRecovery: vi.fn(async () => emptyRecoveryStatus),
    clearRecovery: vi.fn(async () => ({
      version: 1 as const,
      type: 'recovery.cleared' as const,
      phase: 'completed' as const,
      cleared: 1,
    })),
    cancel: vi.fn(),
    dispose: vi.fn(),
    ...overrides,
  };
}

function makeDeps(
  handlers: Partial<{ [K in Req['type']]: ReqHandler<K> }> = {},
  calls: string[] = [],
  transferClient: OptionsVaultTransferClient = makeTransferClient(),
): OptionsDeps {
  const wrapped = fakeRequest({
    'auth.getState': async () => ({ ok: true, data: { state: 'unlocked' } }),
    'settings.get': async () => ({ ok: true, data: loadedSettings }),
    'auth.listAccounts': async () => ({ ok: true, data: { accounts: [{ email: 'me@x.dev', active: true }] } }),
    'sends.list': async () => ({ ok: true, data: { sends: [] } }),
    'vault.authorizeExport': async () => ({
      ok: true,
      data: { authorizationId: EXPORT_AUTHORIZATION_ID, expiresAt: 31_000 },
    }),
    ...handlers,
  });
  return {
    request: (req) => { calls.push(req.type); return wrapped(req); },
    uploadBinaryTransfer: vi.fn(async () => ({ ok: true as const, data: null })),
    requestOrigins: vi.fn(async () => true),
    createVaultTransferClient: vi.fn(() => transferClient),
    extensionVersion: () => '1.3.0',
    getCommands: vi.fn(async () => [{ name: 'autofill-focused', shortcut: 'Ctrl+Shift+F' }]),
    openShortcutSettings: vi.fn(async () => {}),
    subscribeSessionChanges: vi.fn(() => vi.fn()),
  };
}

async function mount(deps: OptionsDeps): Promise<VwOptionsApp> {
  const app = document.createElement('vw-options-app') as VwOptionsApp;
  app.deps = deps;
  document.body.append(app);
  await new Promise((r) => setTimeout(r, 0));
  await app.updateComplete;
  return app;
}

function shell(app: VwOptionsApp): Element {
  return app.shadowRoot!.querySelector('vw-options-shell')!;
}

beforeEach(() => {
  Object.defineProperty(window, 'confirm', { value: vi.fn(() => true), configurable: true, writable: true });
  Object.defineProperty(navigator, 'clipboard', { value: { writeText: vi.fn(async () => {}) }, configurable: true });
});
afterEach(() => document.body.replaceChildren());

describe('vw-options-app', () => {
  it('ignores token-only storage writes but reports an active-account identity change', () => {
    const app = document.createElement('vw-options-app') as VwOptionsApp;
    const listener = vi.fn();
    const unsubscribe = app.deps.subscribeSessionChanges(listener);
    const addListener = browser.storage.onChanged.addListener as unknown as ReturnType<typeof vi.fn>;
    const onChanged = addListener.mock.calls.at(-1)?.[0] as (
      changes: Record<string, unknown>,
      areaName: string,
    ) => void;

    onChanged({
      auth: {
        oldValue: { email: 'same@example.com', accessToken: 'old' },
        newValue: { email: 'same@example.com', accessToken: 'new' },
      },
      accounts: { oldValue: { one: 'old' }, newValue: { one: 'new' } },
    }, 'local');
    expect(listener).not.toHaveBeenCalled();

    onChanged({
      auth: {
        oldValue: { email: 'same@example.com' },
        newValue: { email: 'other@example.com' },
      },
    }, 'local');
    expect(listener).toHaveBeenCalledWith('account');

    unsubscribe();
    expect(browser.storage.onChanged.removeListener).toHaveBeenCalledWith(onChanged);
  });

  it('loads settings + account and defaults to the account section', async () => {
    const app = await mount(makeDeps());
    expect(app.selected).toBe('account');
    expect(app.accountEmail).toBe('me@x.dev');
    expect(app.shadowRoot!.querySelector('vw-connection-section')).not.toBeNull();
  });

  it('does not unlock transfers at startup until the active account identity is confirmed', async () => {
    const exportVault = vi.fn(async () => ({
      blob: new Blob(['{}']),
      fileName: 'miyu-vault.json',
      format: 'json' as const,
    }));
    const transfer = makeTransferClient({ export: exportVault });
    const app = await mount(makeDeps({
      'auth.listAccounts': async () => ({
        ok: false,
        error: { code: 'error', message: 'identity unavailable' },
      }),
    }, [], transfer));

    expect(app.locked).toBe(true);
    expect(app.accountEmail).toBe('');
    shell(app).dispatchEvent(new CustomEvent('vw-export', {
      detail: { format: 'json', masterPassword: 'master-secret' }, bubbles: true, composed: true,
    }));
    await nextTask();
    expect(exportVault).not.toHaveBeenCalled();
  });

  it('switches sections on nav-change', async () => {
    const app = await mount(makeDeps());
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', { detail: { id: 'appearance' }, bubbles: true, composed: true }));
    await app.updateComplete;
    expect(app.selected).toBe('appearance');
    expect(app.shadowRoot!.querySelector('vw-appearance-section')).not.toBeNull();
  });

  it('keeps a dirty Send draft when section navigation is canceled', async () => {
    const confirm = vi.mocked(window.confirm).mockReturnValue(false);
    const app = await mount(makeDeps());
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', { detail: { id: 'send' }, bubbles: true, composed: true }));
    await app.updateComplete;
    const sendSection = app.shadowRoot!.querySelector('vw-send-section')!;
    (sendSection.shadowRoot!.querySelector('.intro .btn-primary') as HTMLButtonElement).click();
    await sendSection.updateComplete;
    (sendSection.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value = 'keep me';

    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', { detail: { id: 'appearance' }, bubbles: true, composed: true }));
    await app.updateComplete;
    expect(app.selected).toBe('send');
    expect((sendSection.shadowRoot!.querySelector('[data-content]') as HTMLTextAreaElement).value).toBe('keep me');

    confirm.mockReturnValue(true);
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', { detail: { id: 'appearance' }, bubbles: true, composed: true }));
    await app.updateComplete;
    expect(app.selected).toBe('appearance');
    confirm.mockRestore();
  });

  it('loads the assigned browser command and opens shortcut settings on request', async () => {
    const deps = makeDeps();
    const app = await mount(deps);
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', { detail: { id: 'autofill' }, bubbles: true, composed: true }));
    await app.updateComplete;
    const section = app.shadowRoot!.querySelector('vw-autofill-section') as HTMLElement & {
      shortcut: string;
      inlineSuggestions: boolean;
      pageLoadFill: boolean;
      savePromptEnabled: boolean;
      updatePromptEnabled: boolean;
      savePromptExcludedDomains: string[];
      blockedDomains: string[];
      autofillPolicyValid: boolean;
    };
    expect(section.shortcut).toBe('Ctrl+Shift+F');
    expect(section.inlineSuggestions).toBe(true);
    expect(section.pageLoadFill).toBe(false);
    expect(section.savePromptEnabled).toBe(true);
    expect(section.updatePromptEnabled).toBe(false);
    expect(section.savePromptExcludedDomains).toEqual(['never-save.example']);
    expect(section.blockedDomains).toEqual(['blocked.example']);
    expect(section.autofillPolicyValid).toBe(true);
    section.dispatchEvent(new CustomEvent('vw-shortcut-change', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(deps.openShortcutSettings).toHaveBeenCalledTimes(1);
  });

  it('keeps autofill behavior fail-closed while policy settings are still loading', async () => {
    const settings = deferred<Res>();
    const app = await mount(makeDeps({ 'settings.get': () => settings.promise }));
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'autofill' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    const section = app.shadowRoot!.querySelector('vw-autofill-section') as HTMLElement & {
      inlineSuggestions: boolean;
      pageLoadFill: boolean;
      autofillPolicyValid: boolean;
    };
    expect(section.inlineSuggestions).toBe(false);
    expect(section.pageLoadFill).toBe(false);
    expect(section.autofillPolicyValid).toBe(false);

    settings.resolve({ ok: true, data: loadedSettings } as Res);
    await nextTask();
  });

  it('saves a complete autofill policy snapshot and publishes the accepted state', async () => {
    const requests: Req[] = [];
    let authoritative: LoadedSettings = loadedSettings;
    const app = await mount(makeDeps({
      'settings.get': async () => ({ ok: true, data: authoritative }),
      'settings.save': async (request) => {
        requests.push(request);
        authoritative = {
          ...authoritative,
          ...(request.defaultUriMatchStrategy === undefined
            ? {}
            : { defaultUriMatchStrategy: request.defaultUriMatchStrategy }),
          ...request.autofillSettings,
          savePromptExcludedDomains: [
            ...(request.autofillSettings?.savePromptExcludedDomains
              ?? authoritative.savePromptExcludedDomains),
          ],
          blockedDomains: [
            ...(request.autofillSettings?.blockedDomains ?? authoritative.blockedDomains),
          ],
          autofillPolicyValid: true,
        };
        return { ok: true, data: null };
      },
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'autofill' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;

    shell(app).dispatchEvent(new CustomEvent('vw-autofill-save', {
      detail: {
        defaultUriMatchStrategy: 1,
        inlineSuggestions: false,
        pageLoadFill: true,
        pageLoadFillDefault: false,
        autoCopyTotp: false,
        savePromptEnabled: false,
        updatePromptEnabled: true,
        savePromptExcludedDomains: ['never-save.example'],
        blockedDomains: ['login.example'],
      },
      bubbles: true,
      composed: true,
    }));
    await nextTask();

    expect(requests.at(-1) as unknown as Record<string, unknown>).toMatchObject({
      type: 'settings.save',
      serverUrl: 'https://vault.example.com/',
      defaultUriMatchStrategy: 1,
      autofillSettings: {
        inlineSuggestions: false,
        pageLoadFill: true,
        pageLoadFillDefault: false,
        autoCopyTotp: false,
        savePromptEnabled: false,
        updatePromptEnabled: true,
        savePromptExcludedDomains: ['never-save.example'],
        blockedDomains: ['login.example'],
      },
    });
    expect(app.settings).toMatchObject({
      defaultUriMatchStrategy: 1,
      inlineSuggestions: false,
      pageLoadFill: true,
      autoCopyTotp: false,
      savePromptEnabled: false,
      updatePromptEnabled: true,
      savePromptExcludedDomains: ['never-save.example'],
      blockedDomains: ['login.example'],
      autofillPolicyValid: true,
    });
    expect(app.autofillStatus?.tone).toBe('success');
  });

  it('saves the toolbar match counter independently from autofill policy', async () => {
    const requests: Array<Extract<Req, { type: 'settings.save' }>> = [];
    let authoritative = loadedSettings;
    const app = await mount(makeDeps({
      'settings.get': async () => ({ ok: true, data: authoritative }),
      'settings.save': async (request) => {
        requests.push(request);
        if (request.showMatchingLoginCount !== undefined) {
          authoritative = {
            ...authoritative,
            showMatchingLoginCount: request.showMatchingLoginCount,
          };
        }
        return { ok: true, data: null };
      },
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'autofill' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;

    shell(app).dispatchEvent(new CustomEvent('vw-toolbar-badge-save', {
      detail: { showMatchingLoginCount: false }, bubbles: true, composed: true,
    }));
    await nextTask();
    await app.updateComplete;

    expect(requests.at(-1)).toEqual({
      type: 'settings.save',
      showMatchingLoginCount: false,
    });
    expect(app.settings?.showMatchingLoginCount).toBe(false);
    const section = app.shadowRoot!.querySelector('vw-autofill-section') as HTMLElement & {
      showMatchingLoginCount: boolean;
    };
    expect(section.showMatchingLoginCount).toBe(false);
  });

  it('omits a managed URI default while saving and publishing other autofill settings', async () => {
    const requests: Array<Extract<Req, { type: 'settings.save' }>> = [];
    let managedSettings: LoadedSettings = {
      ...loadedSettings,
      defaultUriMatchStrategy: 3,
      enterprisePolicy: {
        ...loadedSettings.enterprisePolicy,
        uriMatchDefaultManaged: true,
      },
    };
    const app = await mount(makeDeps({
      'settings.get': async () => ({ ok: true, data: managedSettings }),
      'settings.save': async (request) => {
        requests.push(request);
        managedSettings = {
          ...managedSettings,
          ...request.autofillSettings,
          savePromptExcludedDomains: [
            ...(request.autofillSettings?.savePromptExcludedDomains
              ?? managedSettings.savePromptExcludedDomains),
          ],
          blockedDomains: [
            ...(request.autofillSettings?.blockedDomains ?? managedSettings.blockedDomains),
          ],
          autofillPolicyValid: true,
        };
        return { ok: true, data: null };
      },
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'autofill' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;

    const section = app.shadowRoot!.querySelector('vw-autofill-section') as HTMLElement & {
      uriMatchDefaultManaged: boolean;
      uriMatchDefaultMalformed: boolean;
    };
    expect(section.uriMatchDefaultManaged).toBe(true);
    expect(section.uriMatchDefaultMalformed).toBe(false);

    shell(app).dispatchEvent(new CustomEvent('vw-autofill-save', {
      detail: {
        defaultUriMatchStrategy: 0,
        inlineSuggestions: false,
        pageLoadFill: true,
        pageLoadFillDefault: false,
        autoCopyTotp: false,
        savePromptEnabled: false,
        updatePromptEnabled: true,
        savePromptExcludedDomains: ['keep.example'],
        blockedDomains: ['blocked.example'],
      },
      bubbles: true,
      composed: true,
    }));
    await nextTask();

    expect(requests).toHaveLength(1);
    expect(requests[0]).not.toHaveProperty('defaultUriMatchStrategy');
    expect(requests[0]?.autofillSettings).toEqual({
      inlineSuggestions: false,
      pageLoadFill: true,
      pageLoadFillDefault: false,
      autoCopyTotp: false,
      savePromptEnabled: false,
      updatePromptEnabled: true,
      savePromptExcludedDomains: ['keep.example'],
      blockedDomains: ['blocked.example'],
    });
    expect(app.settings).toMatchObject({
      defaultUriMatchStrategy: 3,
      inlineSuggestions: false,
      pageLoadFill: true,
    });
  });

  it('uses safe defaults and exposes repair when the worker reports an invalid autofill policy', async () => {
    const { serverUrl: _serverUrl, ...serverlessSettings } = loadedSettings;
    let response = {
      ...serverlessSettings,
      inlineSuggestions: false,
      pageLoadFill: true,
      blockedDomains: ['unsafe.example'],
      autofillPolicyValid: false,
    };
    const saved: Array<Extract<Req, { type: 'settings.save' }>> = [];
    const app = await mount(makeDeps({
      'settings.get': async () => ({ ok: true, data: response } as Res),
      'settings.save': async (request) => {
        saved.push(request);
        response = {
          ...response,
          ...request.autofillSettings,
          savePromptExcludedDomains: [
            ...(request.autofillSettings?.savePromptExcludedDomains
              ?? response.savePromptExcludedDomains),
          ],
          blockedDomains: [
            ...(request.autofillSettings?.blockedDomains ?? response.blockedDomains),
          ],
          autofillPolicyValid: true,
        };
        return { ok: true, data: null };
      },
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'autofill' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    const section = app.shadowRoot!.querySelector('vw-autofill-section') as HTMLElement & {
      inlineSuggestions: boolean;
      pageLoadFill: boolean;
      savePromptEnabled: boolean;
      updatePromptEnabled: boolean;
      savePromptExcludedDomains: string[];
      blockedDomains: string[];
      autofillPolicyValid: boolean;
    };

    expect(section.inlineSuggestions).toBe(false);
    expect(section.pageLoadFill).toBe(false);
    expect(section.savePromptEnabled).toBe(false);
    expect(section.updatePromptEnabled).toBe(false);
    expect(section.savePromptExcludedDomains).toEqual([]);
    expect(section.blockedDomains).toEqual([]);
    expect(section.autofillPolicyValid).toBe(false);

    section.shadowRoot!.querySelector<HTMLButtonElement>('[data-restore-policy]')!.click();
    await nextTask();
    await app.updateComplete;
    expect(saved.at(-1)?.autofillSettings).toEqual({
      inlineSuggestions: true,
      pageLoadFill: false,
      pageLoadFillDefault: true,
      autoCopyTotp: true,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: [],
      blockedDomains: [],
    });
    expect(saved.at(-1)).not.toHaveProperty('serverUrl');
    expect(app.settings?.autofillPolicyValid).toBe(true);
  });

  it('loads website passkey settings into the autofill section', async () => {
    const app = await mount(makeDeps({
      'settings.get': async () => ({
        ok: true,
        data: {
          ...loadedSettings,
          websitePasskeys: {
            enabled: true,
            excludedDomains: ['accounts.example.com'],
            valid: true,
          },
        },
      }),
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'autofill' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    const section = app.shadowRoot!.querySelector('vw-autofill-section') as HTMLElement & {
      websitePasskeyEnabled: boolean;
      websitePasskeyExcludedDomains: string[];
      websitePasskeyPolicyValid: boolean;
    };
    expect(section.websitePasskeyEnabled).toBe(true);
    expect(section.websitePasskeyExcludedDomains).toEqual(['accounts.example.com']);
    expect(section.websitePasskeyPolicyValid).toBe(true);
  });

  it('fails closed when loaded website passkey settings are missing or malformed', async () => {
    const { websitePasskeys: _websitePasskeys, ...legacySettings } = loadedSettings;
    const app = await mount(makeDeps({
      'settings.get': async () => ({ ok: true, data: legacySettings } as Res),
    }));
    expect(app.settings?.websitePasskeys).toEqual({
      enabled: false,
      excludedDomains: [],
      valid: false,
    });
  });

  it('loads HTTP auth settings into the autofill section and fails closed when missing', async () => {
    const app = await mount(makeDeps({
      'settings.get': async () => ({
        ok: true,
        data: {
          ...loadedSettings,
          httpAuth: {
            enabled: true,
            allowedOrigins: ['https://intranet.example'],
            valid: true,
          },
        },
      }),
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'autofill' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    const section = app.shadowRoot!.querySelector('vw-autofill-section') as HTMLElement & {
      httpAuthEnabled: boolean;
      httpAuthAllowedOrigins: string[];
      httpAuthPolicyValid: boolean;
    };
    expect(section.httpAuthEnabled).toBe(true);
    expect(section.httpAuthAllowedOrigins).toEqual(['https://intranet.example']);
    expect(section.httpAuthPolicyValid).toBe(true);

    const { httpAuth: _httpAuth, ...legacySettings } = loadedSettings;
    const legacy = await mount(makeDeps({
      'settings.get': async () => ({ ok: true, data: legacySettings } as Res),
    }));
    expect(legacy.settings?.httpAuth).toEqual({
      enabled: false,
      allowedOrigins: [],
      valid: false,
    });
  });

  it('requests the exact script origins as the first await before enabling website passkeys', async () => {
    const permission = deferred<boolean>();
    const requests: Req[] = [];
    const deps = makeDeps({
      'settings.saveWebsitePasskeys': async (request) => {
        requests.push(request);
        return { ok: true, data: null };
      },
    });
    deps.requestOrigins = vi.fn(() => permission.promise);
    const app = await mount(deps);

    shell(app).dispatchEvent(new CustomEvent('vw-website-passkey-save', {
      detail: { enabled: true, excludedDomains: [] }, bubbles: true, composed: true,
    }));
    expect(deps.requestOrigins).toHaveBeenCalledWith([
      'https://*/*',
      'http://localhost/*',
      'http://127.0.0.1/*',
    ]);
    expect(requests).toEqual([]);

    permission.resolve(true);
    await nextTask();
    expect(requests).toEqual([{
      type: 'settings.saveWebsitePasskeys',
      enabled: true,
      excludedDomains: [],
    }]);
    expect(app.settings?.websitePasskeys).toEqual({
      enabled: true,
      excludedDomains: [],
      valid: true,
    });
  });

  it.each(['denied', 'error'] as const)(
    'keeps website passkeys disabled when origin permission is %s',
    async (outcome) => {
      const requests: Req[] = [];
      const deps = makeDeps({
        'settings.saveWebsitePasskeys': async (request) => {
          requests.push(request);
          return { ok: true, data: null };
        },
      });
      deps.requestOrigins = outcome === 'denied'
        ? vi.fn(async () => false)
        : vi.fn(async () => { throw new Error('permission unavailable'); });
      const app = await mount(deps);

      shell(app).dispatchEvent(new CustomEvent('vw-website-passkey-save', {
        detail: { enabled: true, excludedDomains: [] }, bubbles: true, composed: true,
      }));
      await nextTask();

      expect(requests).toEqual([]);
      expect(app.settings?.websitePasskeys.enabled).toBe(false);
      expect(app.websitePasskeyPending).toBe(false);
      expect(app.autofillStatus?.tone).toBe('danger');
    },
  );

  it('does not request permissions when disabling or only saving exclusions', async () => {
    const requests: Req[] = [];
    const deps = makeDeps({
      'settings.get': async () => ({
        ok: true,
        data: {
          ...loadedSettings,
          websitePasskeys: { enabled: true, excludedDomains: [], valid: true },
        },
      }),
      'settings.saveWebsitePasskeys': async (request) => {
        requests.push(request);
        return { ok: true, data: null };
      },
    });
    const app = await mount(deps);

    shell(app).dispatchEvent(new CustomEvent('vw-website-passkey-save', {
      detail: { enabled: true, excludedDomains: ['login.example'] },
      bubbles: true,
      composed: true,
    }));
    await nextTask();
    shell(app).dispatchEvent(new CustomEvent('vw-website-passkey-save', {
      detail: { enabled: false, excludedDomains: ['login.example'] },
      bubbles: true,
      composed: true,
    }));
    await nextTask();

    expect(deps.requestOrigins).not.toHaveBeenCalled();
    expect(requests.map((request) => ({
      enabled: (request as Extract<Req, { type: 'settings.saveWebsitePasskeys' }>).enabled,
      excludedDomains: (request as Extract<Req, { type: 'settings.saveWebsitePasskeys' }>).excludedDomains,
    }))).toEqual([
      { enabled: true, excludedDomains: ['login.example'] },
      { enabled: false, excludedDomains: ['login.example'] },
    ]);
  });

  it('keeps the accepted snapshot on save failure and ignores obsolete failures', async () => {
    const first = deferred<Res>();
    const second = deferred<Res>();
    let saves = 0;
    const app = await mount(makeDeps({
      'settings.get': async () => ({
        ok: true,
        data: {
          ...loadedSettings,
          websitePasskeys: { enabled: true, excludedDomains: [], valid: true },
        },
      }),
      'settings.saveWebsitePasskeys': () => {
        saves += 1;
        return saves === 1 ? first.promise : second.promise;
      },
    }));

    shell(app).dispatchEvent(new CustomEvent('vw-website-passkey-save', {
      detail: { enabled: false, excludedDomains: [] }, bubbles: true, composed: true,
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-website-passkey-save', {
      detail: { enabled: true, excludedDomains: ['latest.example'] }, bubbles: true, composed: true,
    }));
    expect(saves).toBe(2);

    second.resolve({ ok: true, data: null });
    await nextTask();
    expect(app.settings?.websitePasskeys).toEqual({
      enabled: true,
      excludedDomains: ['latest.example'],
      valid: true,
    });
    first.resolve({ ok: false, error: { code: 'error', message: 'obsolete failure' } });
    await nextTask();
    expect(app.settings?.websitePasskeys.excludedDomains).toEqual(['latest.example']);
    expect(app.autofillStatus).toEqual(expect.objectContaining({ tone: 'success' }));
  });

  it('reports the latest website passkey save failure without publishing its draft', async () => {
    const app = await mount(makeDeps({
      'settings.get': async () => ({
        ok: true,
        data: {
          ...loadedSettings,
          websitePasskeys: { enabled: true, excludedDomains: [], valid: true },
        },
      }),
      'settings.saveWebsitePasskeys': async () => ({
        ok: false,
        error: { code: 'error', message: 'save rejected' },
      }),
    }));

    shell(app).dispatchEvent(new CustomEvent('vw-website-passkey-save', {
      detail: { enabled: false, excludedDomains: ['draft.example'] },
      bubbles: true,
      composed: true,
    }));
    await nextTask();

    expect(app.settings?.websitePasskeys).toEqual({ enabled: true, excludedDomains: [], valid: true });
    expect(app.autofillStatus).toEqual({ message: 'save rejected', tone: 'danger' });
    expect(app.websitePasskeyPending).toBe(false);
  });

  it('does not send a stale enable after a newer disable wins during permission prompt', async () => {
    const permission = deferred<boolean>();
    const requests: Array<Extract<Req, { type: 'settings.saveWebsitePasskeys' }>> = [];
    const deps = makeDeps({
      'settings.saveWebsitePasskeys': async (request) => {
        requests.push(request);
        return { ok: true, data: null };
      },
    });
    deps.requestOrigins = vi.fn(() => permission.promise);
    const app = await mount(deps);

    shell(app).dispatchEvent(new CustomEvent('vw-website-passkey-save', {
      detail: { enabled: true, excludedDomains: [] }, bubbles: true, composed: true,
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-website-passkey-save', {
      detail: { enabled: false, excludedDomains: ['newer.example'] }, bubbles: true, composed: true,
    }));
    await nextTask();
    permission.resolve(true);
    await nextTask();

    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({ enabled: false, excludedDomains: ['newer.example'] });
    expect(app.settings?.websitePasskeys).toEqual({
      enabled: false,
      excludedDomains: ['newer.example'],
      valid: true,
    });
  });

  it('requests exact host access before saving the HTTP auth authorization', async () => {
    const requests: Array<Extract<Req, { type: 'settings.saveHttpAuth' }>> = [];
    const deps = makeDeps({
      'settings.saveHttpAuth': async (request) => {
        requests.push(request);
        return { ok: true, data: null };
      },
    });
    const app = await mount(deps);
    shell(app).dispatchEvent(new CustomEvent('vw-http-auth-save', {
      detail: {
        enabled: true,
        allowedOrigins: ['https://intranet.example', 'http://127.0.0.1:8080'],
      },
      bubbles: true,
      composed: true,
    }));
    await nextTask();
    expect(deps.requestOrigins).toHaveBeenCalledWith([
      'https://intranet.example/*',
      'http://127.0.0.1:8080/*',
    ]);
    expect(requests).toEqual([{
      type: 'settings.saveHttpAuth',
      enabled: true,
      allowedOrigins: ['https://intranet.example', 'http://127.0.0.1:8080'],
    }]);
    expect(app.settings?.httpAuth).toEqual({
      enabled: true,
      allowedOrigins: ['https://intranet.example', 'http://127.0.0.1:8080'],
      valid: true,
    });
  });

  it('does not enable HTTP auth when exact host access is denied', async () => {
    const requests: Array<Extract<Req, { type: 'settings.saveHttpAuth' }>> = [];
    const deps = makeDeps({
      'settings.saveHttpAuth': async (request) => {
        requests.push(request);
        return { ok: true, data: null };
      },
    });
    deps.requestOrigins = vi.fn(async () => false);
    const app = await mount(deps);

    shell(app).dispatchEvent(new CustomEvent('vw-http-auth-save', {
      detail: { enabled: true, allowedOrigins: ['https://intranet.example'] },
      bubbles: true,
      composed: true,
    }));
    await nextTask();

    expect(requests).toHaveLength(0);
    expect(app.autofillStatus).toEqual({
      message: t('options.autofill.httpAuthPermissionDenied'),
      tone: 'danger',
    });
  });

  it('saves shrinking or disabling the HTTP auth authorization without browser permission APIs', async () => {
    const requests: Array<Extract<Req, { type: 'settings.saveHttpAuth' }>> = [];
    const deps = makeDeps({
      'settings.get': async () => ({
        ok: true,
        data: {
          ...loadedSettings,
          httpAuth: {
            enabled: true,
            allowedOrigins: ['https://one.example', 'https://two.example'],
            valid: true,
          },
        },
      }),
      'settings.saveHttpAuth': async (request) => {
        requests.push(request);
        return { ok: true, data: null };
      },
    });
    const app = await mount(deps);
    shell(app).dispatchEvent(new CustomEvent('vw-http-auth-save', {
      detail: { enabled: false, allowedOrigins: ['https://one.example'] },
      bubbles: true,
      composed: true,
    }));
    await nextTask();
    expect(deps.requestOrigins).not.toHaveBeenCalled();
    expect(requests).toEqual([{
      type: 'settings.saveHttpAuth',
      enabled: false,
      allowedOrigins: ['https://one.example'],
    }]);
  });

  it('renders all eight sections in turn', async () => {
    const app = await mount(makeDeps());
    const map: Record<string, string> = {
      account: 'vw-connection-section', security: 'vw-security-section', autofill: 'vw-autofill-section',
      generator: 'vw-generator-section', send: 'vw-send-section', appearance: 'vw-appearance-section',
      data: 'vw-data-section', about: 'vw-about-section',
    };
    for (const [id, tag] of Object.entries(map)) {
      shell(app).dispatchEvent(new CustomEvent('vw-nav-change', { detail: { id }, bubbles: true, composed: true }));
      await app.updateComplete;
      expect(app.shadowRoot!.querySelector(tag), tag).not.toBeNull();
    }
  });

  it('requests host permission then saves the server URL on connection-save', async () => {
    const calls: string[] = [];
    const deps = makeDeps({}, calls);
    const app = await mount(deps);
    shell(app).dispatchEvent(new CustomEvent('vw-connection-save', { detail: { serverUrl: 'https://vault.example.com/' }, bubbles: true, composed: true }));
    await new Promise((r) => setTimeout(r, 0));
    expect(deps.requestOrigins).toHaveBeenCalledWith(['https://vault.example.com/*']);
    expect(calls).toContain('settings.save');
  });

  it('syncs on vw-sync-now and records the time', async () => {
    const calls: string[] = [];
    const app = await mount(makeDeps({ 'vault.sync': async () => ({ ok: true, data: null }) }, calls));
    shell(app).dispatchEvent(new CustomEvent('vw-sync-now', { bubbles: true, composed: true }));
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toContain('vault.sync');
    expect(app.lastSync).toBeTypeOf('number');
  });

  it('changes the master password, then re-reads the remaining active account', async () => {
    const calls: string[] = [];
    const requests: Array<Extract<Req, { type: 'auth.changePassword' }>> = [];
    const getState = vi.fn()
      .mockResolvedValueOnce({ ok: true, data: { state: 'unlocked' } })
      .mockResolvedValueOnce({ ok: true, data: { state: 'locked' } });
    const listAccounts = vi.fn()
      .mockResolvedValueOnce({ ok: true, data: { accounts: [{ email: 'me@x.dev', active: true }] } })
      .mockResolvedValueOnce({ ok: true, data: { accounts: [{ email: 'other@x.dev', active: true }] } });
    const app = await mount(makeDeps({
      'auth.getState': getState,
      'auth.listAccounts': listAccounts,
      'auth.changePassword': async (request) => {
        requests.push(request);
        return { ok: true, data: null };
      },
    }, calls));
    shell(app).dispatchEvent(new CustomEvent('vw-change-password', {
      detail: { currentPassword: 'a', newPassword: 'bbbbbbbb', masterPasswordHint: '' },
      bubbles: true,
      composed: true,
    }));
    await nextTask();
    await nextTask();
    expect(calls).toContain('auth.changePassword');
    expect(requests).toEqual([{
      type: 'auth.changePassword',
      currentPassword: 'a',
      newPassword: 'bbbbbbbb',
      masterPasswordHint: '',
    }]);
    expect(getState).toHaveBeenCalledTimes(2);
    expect(app.locked).toBe(true);
    expect(app.accountEmail).toBe('other@x.dev');
  });

  it('serializes lock-timeout saves and preserves the latest selection', async () => {
    const first = deferred<Res>();
    const second = deferred<Res>();
    const requests: Array<Extract<Req, { type: 'settings.save' }>> = [];
    const app = await mount(makeDeps({
      'settings.save': (request) => {
        requests.push(request);
        return requests.length === 1 ? first.promise : second.promise;
      },
    }));

    shell(app).dispatchEvent(new CustomEvent('vw-lock-timeout-save', {
      detail: { lockTimeout: '30' },
      bubbles: true,
      composed: true,
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-lock-timeout-save', {
      detail: { lockTimeout: 'onClose' },
      bubbles: true,
      composed: true,
    }));

    expect(requests.map((request) => request.lockTimeout)).toEqual(['30']);
    expect(app.settings?.lockTimeout).toBe('onClose');

    first.resolve({ ok: true, data: null });
    await nextTask();
    expect(requests.map((request) => request.lockTimeout)).toEqual(['30', 'onClose']);
    expect(app.settings?.lockTimeout).toBe('onClose');
    expect(app.securityStatus).toBeUndefined();

    second.resolve({ ok: false, error: { code: 'error', message: 'latest timeout failed' } });
    await nextTask();
    expect(app.settings?.lockTimeout).toBe('onClose');
    expect(app.securityStatus).toEqual({ message: 'latest timeout failed', tone: 'danger' });
  });

  it('keeps the effective timeout after a failed save and updates it only after a successful retry', async () => {
    const first = deferred<Res>();
    const retry = deferred<Res>();
    let callCount = 0;
    const app = await mount(makeDeps({
      'settings.save': () => (++callCount === 1 ? first.promise : retry.promise),
    }));
    app.selected = 'security';
    await app.updateComplete;
    const section = app.shadowRoot!.querySelector('vw-security-section')!;
    await section.updateComplete;

    shell(app).dispatchEvent(new CustomEvent('vw-lock-timeout-save', {
      detail: { lockTimeout: '30' }, bubbles: true, composed: true,
    }));
    await app.updateComplete;
    await section.updateComplete;
    expect(app.securityFeedback.lockTimeout?.state).toBe('saving');
    expect(app.effectiveSecuritySettings?.lockTimeout).toBe('15');
    expect(section.shadowRoot!.querySelector('[data-save-field="lockTimeout"]')!.textContent)
      .toContain(t('options.save.effective', { value: t('options.lock.15m') }));

    first.resolve({ ok: false, error: { code: 'error', message: 'timeout save failed' } });
    await nextTask();
    await section.updateComplete;
    expect(app.settings?.lockTimeout).toBe('30');
    expect(app.effectiveSecuritySettings?.lockTimeout).toBe('15');
    expect(app.securityFeedback.lockTimeout).toEqual({ state: 'error', message: 'timeout save failed' });
    const retryButton = section.shadowRoot!.querySelector<HTMLButtonElement>('[data-retry-setting="lockTimeout"]')!;
    expect(retryButton).not.toBeNull();
    retryButton.click();
    expect(callCount).toBe(2);
    expect(app.securityFeedback.lockTimeout?.state).toBe('saving');
    expect(app.effectiveSecuritySettings?.lockTimeout).toBe('15');

    retry.resolve({ ok: true, data: null });
    await nextTask();
    await section.updateComplete;
    expect(app.effectiveSecuritySettings?.lockTimeout).toBe('30');
    expect(app.securityFeedback.lockTimeout?.state).toBe('saved');
    expect(section.shadowRoot!.querySelector('[data-retry-setting="lockTimeout"]')).toBeNull();
  });

  it('ignores a forged legacy never timeout while settings are locally managed', async () => {
    const requests: Array<Extract<Req, { type: 'settings.save' }>> = [];
    const app = await mount(makeDeps({
      'settings.save': async (request) => {
        requests.push(request);
        return { ok: true, data: null };
      },
    }));

    shell(app).dispatchEvent(new CustomEvent('vw-lock-timeout-save', {
      detail: { lockTimeout: 'never' },
      bubbles: true,
      composed: true,
    }));
    await nextTask();

    expect(requests).toEqual([]);
    expect(app.settings?.lockTimeout).toBe('15');
  });

  it('ignores forged wider timeout events while managed and still permits clipboard-only changes', async () => {
    const timeoutRequests: Array<Extract<Req, { type: 'settings.save' }>> = [];
    const securityRequests: Array<Extract<Req, { type: 'settings.saveSecurity' }>> = [];
    const app = await mount(makeDeps({
      'settings.save': async (request) => { timeoutRequests.push(request); return { ok: true, data: null }; },
      'settings.saveSecurity': async (request) => { securityRequests.push(request); return { ok: true, data: null }; },
    }));
    app.settings = {
      ...loadedSettings,
      lockTimeout: '5',
      onIdleAction: 'logout',
      enterprisePolicy: {
        pinUnlockAllowed: false,
        maximumVaultTimeoutManaged: true,
        maximumVaultTimeoutMode: 'local',
        uriMatchDefaultManaged: false,
        uriMatchDefaultMalformed: false,
        activateAutofillManaged: false,
      },
    };

    shell(app).dispatchEvent(new CustomEvent('vw-lock-timeout-save', {
      detail: { lockTimeout: 'never' }, bubbles: true, composed: true,
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-security-save', {
      detail: { onIdleAction: 'lock', clipboardClearSeconds: '120' }, bubbles: true, composed: true,
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-security-save', {
      detail: { onIdleAction: 'logout', clipboardClearSeconds: '120' }, bubbles: true, composed: true,
    }));
    await nextTask();

    expect(timeoutRequests).toEqual([]);
    expect(securityRequests).toHaveLength(1);
    expect(securityRequests[0]).toMatchObject({ onIdleAction: 'logout', clipboardClearSeconds: '120' });
  });

  it('coalesces security snapshots and ignores feedback from an obsolete request', async () => {
    const first = deferred<Res>();
    const second = deferred<Res>();
    const requests: Array<Extract<Req, { type: 'settings.saveSecurity' }>> = [];
    const app = await mount(makeDeps({
      'settings.saveSecurity': (request) => {
        requests.push(request);
        return requests.length === 1 ? first.promise : second.promise;
      },
    }));

    shell(app).dispatchEvent(new CustomEvent('vw-security-save', {
      detail: { onIdleAction: 'logout', clipboardClearSeconds: '60' },
      bubbles: true,
      composed: true,
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-security-save', {
      detail: { onIdleAction: 'logout', clipboardClearSeconds: '120' },
      bubbles: true,
      composed: true,
    }));

    expect(requests.map(({ onIdleAction, clipboardClearSeconds }) => ({ onIdleAction, clipboardClearSeconds })))
      .toEqual([{ onIdleAction: 'logout', clipboardClearSeconds: '60' }]);
    expect(app.settings).toMatchObject({ onIdleAction: 'logout', clipboardClearSeconds: '120' });
    expect(app.securityFeedback).toMatchObject({
      onIdleAction: { state: 'saving' }, clipboardClearSeconds: { state: 'saving' },
    });
    expect(app.effectiveSecuritySettings).toMatchObject({ onIdleAction: 'lock', clipboardClearSeconds: '60' });

    first.resolve({ ok: false, error: { code: 'error', message: 'obsolete failure' } });
    await nextTask();
    expect(requests.map(({ onIdleAction, clipboardClearSeconds }) => ({ onIdleAction, clipboardClearSeconds })))
      .toEqual([
        { onIdleAction: 'logout', clipboardClearSeconds: '60' },
        { onIdleAction: 'logout', clipboardClearSeconds: '120' },
      ]);
    expect(app.securityStatus).toBeUndefined();

    expect(app.securityFeedback).toMatchObject({
      onIdleAction: { state: 'saving' }, clipboardClearSeconds: { state: 'saving' },
    });
    expect(app.effectiveSecuritySettings).toMatchObject({ onIdleAction: 'lock', clipboardClearSeconds: '60' });

    second.resolve({ ok: true, data: null });
    await nextTask();
    expect(app.settings).toMatchObject({ onIdleAction: 'logout', clipboardClearSeconds: '120' });
    expect(app.securityStatus).toBeUndefined();
    expect(app.securityFeedback).toMatchObject({
      onIdleAction: { state: 'saved' }, clipboardClearSeconds: { state: 'saved' },
    });
    expect(app.effectiveSecuritySettings).toMatchObject({ onIdleAction: 'logout', clipboardClearSeconds: '120' });
  });

  it('reports only the latest security snapshot failure', async () => {
    const first = deferred<Res>();
    const second = deferred<Res>();
    let callCount = 0;
    const app = await mount(makeDeps({
      'settings.saveSecurity': () => (++callCount === 1 ? first.promise : second.promise),
    }));

    shell(app).dispatchEvent(new CustomEvent('vw-security-save', {
      detail: { onIdleAction: 'logout', clipboardClearSeconds: '60' },
      bubbles: true,
      composed: true,
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-security-save', {
      detail: { onIdleAction: 'lock', clipboardClearSeconds: '300' },
      bubbles: true,
      composed: true,
    }));
    first.resolve({ ok: true, data: null });
    await nextTask();
    second.resolve({ ok: false, error: { code: 'error', message: 'latest security failed' } });
    await nextTask();

    expect(app.settings).toMatchObject({ onIdleAction: 'lock', clipboardClearSeconds: '300' });
    expect(app.securityStatus).toEqual({ message: 'latest security failed', tone: 'danger' });
  });

  it('creates a Send and copies its link', async () => {
    const calls: string[] = [];
    const scheduleClear = vi.fn<ReqHandler<'clipboard.scheduleClear'>>(async () => ({ ok: true, data: null }));
    const app = await mount(makeDeps({
      'sends.createText': async () => ({ ok: true, data: { send: { id: 's1', accessId: 'a', type: 0, name: 'x', hidden: false, hideEmail: false, url: 'https://s', deletionDate: '', accessCount: 0, disabled: false, passwordProtected: false } } }),
      'clipboard.scheduleClear': scheduleClear,
    }, calls));
    shell(app).dispatchEvent(new CustomEvent('vw-send-create', { detail: { kind: 'text', input: { name: 'x', deletionDays: 7 } }, bubbles: true, composed: true }));
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toContain('sends.createText');
    expect((navigator.clipboard.writeText as ReturnType<typeof vi.fn>)).toHaveBeenCalledWith('https://s');
    expect(scheduleClear).toHaveBeenCalledWith({ type: 'clipboard.scheduleClear', value: 'https://s' });
  });

  it('creates a file Send through the binary transfer client without reading the whole file', async () => {
    const calls: string[] = [];
    const deps = makeDeps({}, calls);
    const upload = vi.fn<BinaryUpload>(async () => ({
      ok: true,
      data: { send: { url: 'https://file-send' } },
    }));
    deps.uploadBinaryTransfer = upload;
    const app = await mount(deps);
    const file = new File(['payload'], 'payload.bin');
    const readWholeFile = vi.fn(() => { throw new Error('The whole file must not be read'); });
    Object.defineProperty(file, 'arrayBuffer', { value: readWholeFile });
    const slice = vi.spyOn(file, 'slice');
    const input = { name: 'Payload', deletionHours: 168 };

    shell(app).dispatchEvent(new CustomEvent('vw-send-create', {
      detail: { kind: 'file', input, file, fileName: file.name },
      bubbles: true,
      composed: true,
    }));
    await nextTask();

    expect(upload).toHaveBeenCalledWith({
      type: 'sends.createFile', input, fileName: file.name, expectedBytes: file.size,
    }, file, { signal: expect.any(AbortSignal) });
    expect(upload.mock.calls[0]![2]?.signal?.aborted).toBe(false);
    expect(readWholeFile).not.toHaveBeenCalled();
    expect(slice).not.toHaveBeenCalled();
    expect(calls).not.toContain('sends.createFile');
    expect(calls.filter((type) => type === 'sends.list')).toHaveLength(2);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('https://file-send');
    expect(app.sendStatus?.tone).toBe('success');
    expect(app.pending).toBe(false);
  });

  it('reports file transfer failure and releases the pending state without copying a link', async () => {
    const calls: string[] = [];
    const deps = makeDeps({}, calls);
    const result = deferred<BinaryUploadResult>();
    deps.uploadBinaryTransfer = vi.fn(() => result.promise);
    const app = await mount(deps);
    const file = new File(['payload'], 'payload.bin');
    shell(app).dispatchEvent(new CustomEvent('vw-send-create', {
      detail: { kind: 'file', input: { name: 'Payload', deletionHours: 168 }, file, fileName: file.name },
      bubbles: true,
      composed: true,
    }));
    expect(app.pending).toBe(true);

    result.resolve({ ok: false, error: { code: 'file_read', message: 'File could not be read' } });
    await nextTask();
    expect(app.pending).toBe(false);
    expect(app.sendStatus).toEqual({ tone: 'danger', message: 'File could not be read' });
    expect(navigator.clipboard.writeText).not.toHaveBeenCalled();
    expect(calls.filter((type) => type === 'sends.list')).toHaveLength(1);
  });

  it.each(['keyMaterial', 'account', 'locked', 'disconnected'] as const)(
    'aborts file upload after %s invalidation and ignores a late result',
    async (reason) => {
      let state: 'unlocked' | 'locked' = 'unlocked';
      const result = deferred<BinaryUploadResult>();
      const upload = vi.fn<BinaryUpload>(() => result.promise);
      const deps = makeDeps({ 'auth.getState': async () => ({ ok: true, data: { state } }) });
      deps.uploadBinaryTransfer = upload;
      const app = await mount(deps);
      const file = new File(['payload'], 'payload.bin');
      shell(app).dispatchEvent(new CustomEvent('vw-send-create', {
        detail: { kind: 'file', input: { name: 'Payload', deletionHours: 168 }, file, fileName: file.name },
        bubbles: true,
        composed: true,
      }));
      const signal = upload.mock.calls[0]![2]!.signal!;
      expect(signal.aborted).toBe(false);
      expect(app.pending).toBe(true);

      state = 'locked';
      if (reason === 'locked') {
        app.locked = true;
        await app.updateComplete;
      } else if (reason === 'disconnected') {
        app.remove();
      } else {
        const listener = (deps.subscribeSessionChanges as ReturnType<typeof vi.fn>)
          .mock.calls[0]![0] as (kind: 'keyMaterial' | 'account') => void;
        listener(reason);
      }
      expect(signal.aborted).toBe(true);
      expect(app.pending).toBe(false);

      result.resolve({ ok: true, data: { send: { url: 'https://stale-file-send' } } });
      await nextTask();
      expect(app.sendStatus).toBeUndefined();
      expect(navigator.clipboard.writeText).not.toHaveBeenCalled();
    },
  );

  it('keeps a newer upload pending when an aborted upload resolves after an account change', async () => {
    const first = deferred<BinaryUploadResult>();
    const second = deferred<BinaryUploadResult>();
    const upload = vi.fn<BinaryUpload>()
      .mockImplementationOnce(() => first.promise)
      .mockImplementationOnce(() => second.promise);
    const deps = makeDeps();
    deps.uploadBinaryTransfer = upload;
    const app = await mount(deps);
    const file = new File(['payload'], 'payload.bin');
    const create = (): void => {
      shell(app).dispatchEvent(new CustomEvent('vw-send-create', {
        detail: { kind: 'file', input: { name: 'Payload', deletionHours: 168 }, file, fileName: file.name },
        bubbles: true,
        composed: true,
      }));
    };
    create();
    const listener = (deps.subscribeSessionChanges as ReturnType<typeof vi.fn>)
      .mock.calls[0]![0] as (kind: 'keyMaterial' | 'account') => void;
    listener('account');
    expect(upload.mock.calls[0]![2]?.signal?.aborted).toBe(true);
    await vi.waitFor(() => expect(app.locked).toBe(false));
    create();
    expect(upload).toHaveBeenCalledTimes(2);

    first.resolve({ ok: true, data: { send: { url: 'https://stale-file-send' } } });
    await nextTask();
    expect(app.pending).toBe(true);
    expect(app.sendStatus).toBeUndefined();
    expect(navigator.clipboard.writeText).not.toHaveBeenCalled();
    second.resolve({ ok: true, data: null });
    await nextTask();
    expect(app.pending).toBe(false);
    expect(app.sendStatus?.tone).toBe('success');
  });

  it('reports clipboard failure instead of claiming a Send link was copied', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: vi.fn(async () => { throw new Error('denied'); }) },
      configurable: true,
    });
    const app = await mount(makeDeps());
    shell(app).dispatchEvent(new CustomEvent('vw-copy', { detail: { value: 'https://s' }, bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(app.sendStatus?.tone).toBe('danger');
    expect(app.sendStatus?.message).not.toContain('已复制');
  });

  it('ignores clipboard feedback from before a newer Send mutation', async () => {
    let releaseFirst: (() => void) | undefined;
    const writeText = vi.fn()
      .mockImplementationOnce(() => new Promise<void>((resolve) => { releaseFirst = resolve; }))
      .mockResolvedValueOnce(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const app = await mount(makeDeps({
      'sends.createText': async () => ({ ok: true, data: { send: { id: 's1', accessId: 'a', type: 0, name: 'x', hidden: false, hideEmail: false, url: 'https://new', deletionDate: '', accessCount: 0, disabled: false, passwordProtected: false } } }),
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-copy', { detail: { value: 'https://old' }, bubbles: true, composed: true }));
    shell(app).dispatchEvent(new CustomEvent('vw-send-create', { detail: { kind: 'text', input: { name: 'x', deletionDays: 7 } }, bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const mutationMessage = app.sendStatus?.message;
    expect(mutationMessage).toContain('已创建');
    releaseFirst?.();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(app.sendStatus?.message).toBe(mutationMessage);
  });

  it('queries and displays lost-result recovery status when Data becomes active', async () => {
    const status: VaultTransferRecoveryStatus = {
      ...clearableRecoveryStatus,
      reconcileRequiredCount: 1,
      barriers: [{
        ...clearableRecoveryStatus.barriers[0]!,
        reconciled: false,
        clearable: false,
      }],
    };
    const inspectRecovery = vi.fn(async () => status);
    const transfer = makeTransferClient({ inspectRecovery });
    const app = await mount(makeDeps({}, [], transfer));

    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'data' }, bubbles: true, composed: true,
    }));
    await vi.waitFor(() => expect(inspectRecovery).toHaveBeenCalledOnce());
    await vi.waitFor(() => expect(app.transferRecoveryStatus).toEqual(status));
    await app.updateComplete;

    const section = app.shadowRoot!.querySelector('vw-data-section') as HTMLElement & {
      updateComplete: Promise<boolean>;
      shadowRoot: ShadowRoot;
    };
    await section.updateComplete;
    expect(section.shadowRoot.querySelector('[data-recovery-counts]')?.textContent)
      .toContain('结果未知 1');
    expect(section.shadowRoot.textContent).not.toContain(status.barriers[0]!.transferId);
  });

  it('fails closed for import when recovery status cannot be inspected', async () => {
    const importVault = vi.fn(async () => transferPreview);
    const transfer = makeTransferClient({
      import: importVault,
      inspectRecovery: vi.fn(async () => { throw new VaultTransferClientError('disconnected'); }),
    });
    const app = await mount(makeDeps({}, [], transfer));
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'data' }, bubbles: true, composed: true,
    }));
    await vi.waitFor(() => expect(app.transferRecoveryUnavailable).toBe(true));
    await app.updateComplete;
    const section = app.shadowRoot!.querySelector('vw-data-section') as HTMLElement & {
      updateComplete: Promise<boolean>;
      shadowRoot: ShadowRoot;
    };
    await section.updateComplete;

    expect(section.shadowRoot.querySelector<HTMLButtonElement>('[data-import]')!.disabled).toBe(true);
    shell(app).dispatchEvent(new CustomEvent('vw-import-file', {
      detail: { file: new File(['[]'], 'vault.json') }, bubbles: true, composed: true,
    }));
    await nextTask();
    expect(importVault).not.toHaveBeenCalled();
    expect(app.dataStatus?.message).toContain('请勿重新导入整个存档');
  });

  it('clears only after explicit UI confirmation and refreshes recovery status', async () => {
    window.confirm = vi.fn(() => true);
    const inspectRecovery = vi.fn()
      .mockResolvedValueOnce(clearableRecoveryStatus)
      .mockResolvedValueOnce(emptyRecoveryStatus);
    const clearRecovery = vi.fn(async () => ({
      version: 1 as const,
      type: 'recovery.cleared' as const,
      phase: 'completed' as const,
      cleared: 1,
    }));
    const transfer = makeTransferClient({ inspectRecovery, clearRecovery });
    const app = await mount(makeDeps({}, [], transfer));
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'data' }, bubbles: true, composed: true,
    }));
    await vi.waitFor(() => expect(app.transferRecoveryStatus).toEqual(clearableRecoveryStatus));
    await app.updateComplete;
    const section = app.shadowRoot!.querySelector('vw-data-section') as HTMLElement & {
      updateComplete: Promise<boolean>;
      shadowRoot: ShadowRoot;
    };
    await section.updateComplete;
    const clearButton = section.shadowRoot.querySelector<HTMLButtonElement>('[data-recovery-clear]')!;

    clearButton.click();
    expect(clearRecovery).not.toHaveBeenCalled();
    const confirmation = section.shadowRoot.querySelector<HTMLInputElement>('[data-recovery-confirm]')!;
    confirmation.checked = true;
    confirmation.dispatchEvent(new Event('change', { bubbles: true }));
    await section.updateComplete;
    section.shadowRoot.querySelector<HTMLButtonElement>('[data-recovery-clear]')!.click();

    await vi.waitFor(() => expect(clearRecovery).toHaveBeenCalledOnce());
    expect(clearRecovery).toHaveBeenCalledWith(clearableRecoveryStatus);
    await vi.waitFor(() => expect(inspectRecovery).toHaveBeenCalledTimes(2));
    await vi.waitFor(() => expect(app.transferRecoveryStatus).toEqual(emptyRecoveryStatus));
    expect(app.dataStatus?.tone).toBe('success');
    expect(app.dataStatus?.message).toContain('已清除 1 条恢复记录');
  });

  it('does not clear when the root-level final confirmation is cancelled', async () => {
    window.confirm = vi.fn(() => false);
    const clearRecovery = vi.fn(async () => ({
      version: 1 as const,
      type: 'recovery.cleared' as const,
      phase: 'completed' as const,
      cleared: 1,
    }));
    const transfer = makeTransferClient({
      inspectRecovery: vi.fn(async () => clearableRecoveryStatus),
      clearRecovery,
    });
    const app = await mount(makeDeps({}, [], transfer));
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'data' }, bubbles: true, composed: true,
    }));
    await vi.waitFor(() => expect(app.transferRecoveryStatus).toEqual(clearableRecoveryStatus));

    shell(app).dispatchEvent(new CustomEvent('vw-transfer-recovery-clear', {
      bubbles: true, composed: true,
    }));
    await nextTask();

    expect(window.confirm).toHaveBeenCalledOnce();
    expect(clearRecovery).not.toHaveBeenCalled();
    expect(app.transferRecoveryStatus).toEqual(clearableRecoveryStatus);
  });

  it('does not clear a retained status after leaving the Data section', async () => {
    window.confirm = vi.fn(() => true);
    const clearRecovery = vi.fn(async () => ({
      version: 1 as const,
      type: 'recovery.cleared' as const,
      phase: 'completed' as const,
      cleared: 1,
    }));
    const transfer = makeTransferClient({
      inspectRecovery: vi.fn(async () => clearableRecoveryStatus),
      clearRecovery,
    });
    const app = await mount(makeDeps({}, [], transfer));
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'data' }, bubbles: true, composed: true,
    }));
    await vi.waitFor(() => expect(app.transferRecoveryStatus).toEqual(clearableRecoveryStatus));
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'account' }, bubbles: true, composed: true,
    }));

    shell(app).dispatchEvent(new CustomEvent('vw-transfer-recovery-clear', {
      bubbles: true, composed: true,
    }));
    await nextTask();

    expect(window.confirm).not.toHaveBeenCalled();
    expect(clearRecovery).not.toHaveBeenCalled();
  });

  it('refreshes recovery state after a partial import result', async () => {
    const unresolved: VaultTransferRecoveryStatus = {
      ...clearableRecoveryStatus,
      reconcileRequiredCount: 1,
      barriers: [{
        ...clearableRecoveryStatus.barriers[0]!,
        reconciled: false,
        clearable: false,
      }],
    };
    const inspectRecovery = vi.fn()
      .mockResolvedValueOnce(emptyRecoveryStatus)
      .mockResolvedValueOnce(unresolved);
    const transfer = makeTransferClient({
      inspectRecovery,
      confirm: vi.fn(async () => ({
        ...completedImportResult,
        status: 'partial' as const,
        counts: { committed: 1, rejected: 1, skipped: 0, outcomeUnknown: 0 },
        mustSyncBeforeRetry: true,
      })),
    });
    const app = await mount(makeDeps({}, [], transfer));
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'data' }, bubbles: true, composed: true,
    }));
    await vi.waitFor(() => expect(inspectRecovery).toHaveBeenCalledOnce());

    shell(app).dispatchEvent(new CustomEvent('vw-import-file', {
      detail: { file: new File(['[]'], 'vault.json') }, bubbles: true, composed: true,
    }));
    await vi.waitFor(() => expect(app.importPreview).toBeDefined());
    shell(app).dispatchEvent(new CustomEvent('vw-import-preview-confirm', {
      bubbles: true, composed: true,
    }));

    await vi.waitFor(() => expect(inspectRecovery).toHaveBeenCalledTimes(2));
    await vi.waitFor(() => expect(app.transferRecoveryStatus).toEqual(unresolved));
  });

  it('disposes a recovery client and erases status on a session change', async () => {
    let state: 'unlocked' | 'locked' = 'unlocked';
    const pendingInspection = deferred<VaultTransferRecoveryStatus>();
    const inspectRecovery = vi.fn()
      .mockResolvedValueOnce(clearableRecoveryStatus)
      .mockImplementationOnce(() => pendingInspection.promise);
    const transfer = makeTransferClient({ inspectRecovery });
    const deps = makeDeps({
      'auth.getState': async () => ({ ok: true, data: { state } }),
    }, [], transfer);
    const app = await mount(deps);
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'data' }, bubbles: true, composed: true,
    }));
    await vi.waitFor(() => expect(app.transferRecoveryStatus).toEqual(clearableRecoveryStatus));
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'data' }, bubbles: true, composed: true,
    }));
    await vi.waitFor(() => expect(inspectRecovery).toHaveBeenCalledTimes(2));
    const disposeCount = (transfer.dispose as ReturnType<typeof vi.fn>).mock.calls.length;

    state = 'locked';
    const listener = (deps.subscribeSessionChanges as ReturnType<typeof vi.fn>)
      .mock.calls[0]![0] as (kind: 'keyMaterial' | 'account') => void;
    listener('keyMaterial');

    expect(app.transferRecoveryStatus).toBeUndefined();
    expect(app.transferRecoveryPending).toBe(false);
    expect((transfer.dispose as ReturnType<typeof vi.fn>).mock.calls.length)
      .toBeGreaterThan(disposeCount);
    pendingInspection.resolve(clearableRecoveryStatus);
    await nextTask();
    expect(app.locked).toBe(true);
    expect(app.transferRecoveryStatus).toBeUndefined();
  });

  it('imports through the Port client, previews, confirms, and never reads the whole file', async () => {
    const calls: string[] = [];
    const transfer = makeTransferClient();
    const app = await mount(makeDeps({}, calls, transfer));
    const file = new File(['{"encrypted":false}'], 'vault.json');
    const textSpy = vi.spyOn(file, 'text');

    shell(app).dispatchEvent(new CustomEvent('vw-import-file', {
      detail: { file }, bubbles: true, composed: true,
    }));
    await nextTask();

    expect(transfer.import).toHaveBeenCalledWith(file);
    expect(textSpy).not.toHaveBeenCalled();
    expect(app.importPreview).toMatchObject({
      counts: { folders: 1, collections: 2, items: 3, attachments: 0 },
      canCommit: true,
    });

    shell(app).dispatchEvent(new CustomEvent('vw-import-preview-confirm', {
      bubbles: true, composed: true,
    }));
    await nextTask();
    expect(transfer.confirm).toHaveBeenCalledTimes(1);
    expect(app.importPreview).toBeUndefined();
    expect(app.dataStatus).toEqual(expect.objectContaining({ tone: 'success' }));
    expect(app.dataStatus?.message).toContain('写入 4');
    expect(calls).not.toContain('vault.import');
    expect(calls).not.toContain('vault.export');
  });

  it('reuses the same File after the worker requests an encrypted-import password', async () => {
    const importVault = vi.fn()
      .mockRejectedValueOnce(new VaultTransferClientError('password_required'))
      .mockResolvedValueOnce(transferPreview);
    const transfer = makeTransferClient({ import: importVault });
    const app = await mount(makeDeps({}, [], transfer));
    const file = new File(['ciphertext'], 'vault.json');

    shell(app).dispatchEvent(new CustomEvent('vw-import-file', {
      detail: { file }, bubbles: true, composed: true,
    }));
    await nextTask();
    expect(app.awaitingImportPassword).toBe(true);
    expect(app.importPreview).toBeUndefined();

    const detail = { password: 'archive-password' };
    shell(app).dispatchEvent(new CustomEvent('vw-import-password', {
      detail, bubbles: true, composed: true,
    }));
    await nextTask();
    expect(importVault).toHaveBeenNthCalledWith(1, file);
    expect(importVault).toHaveBeenNthCalledWith(2, file, 'archive-password');
    expect(detail.password).toBe('archive-password');
    expect(app.awaitingImportPassword).toBe(false);
    expect(app.importPreview?.canCommit).toBe(true);
  });

  it('cancels and disposes a previewed import explicitly', async () => {
    const transfer = makeTransferClient();
    const app = await mount(makeDeps({}, [], transfer));
    shell(app).dispatchEvent(new CustomEvent('vw-import-file', {
      detail: { file: new File(['[]'], 'vault.json') }, bubbles: true, composed: true,
    }));
    await nextTask();

    shell(app).dispatchEvent(new CustomEvent('vw-import-preview-cancel', {
      bubbles: true, composed: true,
    }));
    expect(transfer.cancel).toHaveBeenCalledTimes(1);
    expect(transfer.dispose).toHaveBeenCalledTimes(1);
    expect(app.importPreview).toBeUndefined();
    expect(app.dataStatus).toEqual(expect.objectContaining({ tone: 'info' }));
  });

  it('preserves a previewed import when a forged export event arrives', async () => {
    const transfer = makeTransferClient();
    const app = await mount(makeDeps({}, [], transfer));
    shell(app).dispatchEvent(new CustomEvent('vw-import-file', {
      detail: { file: new File(['[]'], 'vault.json') }, bubbles: true, composed: true,
    }));
    await nextTask();
    const preview = app.importPreview;

    shell(app).dispatchEvent(new CustomEvent('vw-export', {
      detail: { format: 'json', masterPassword: 'master-secret' }, bubbles: true, composed: true,
    }));
    await nextTask();

    expect(transfer.export).not.toHaveBeenCalled();
    expect(transfer.dispose).not.toHaveBeenCalled();
    expect(app.importPreview).toBe(preview);
    shell(app).dispatchEvent(new CustomEvent('vw-import-preview-confirm', {
      bubbles: true, composed: true,
    }));
    await nextTask();
    expect(transfer.confirm).toHaveBeenCalledTimes(1);
  });

  it('reports partial imports using only aggregate counts and reconciliation guidance', async () => {
    const transfer = makeTransferClient({
      confirm: vi.fn(async (): Promise<VaultTransferImportResultMessage> => ({
        ...completedImportResult,
        status: 'partial',
        counts: { committed: 2, rejected: 1, skipped: 3, outcomeUnknown: 0 },
        mustSyncBeforeRetry: true,
      })),
    });
    const app = await mount(makeDeps({}, [], transfer));
    shell(app).dispatchEvent(new CustomEvent('vw-import-file', {
      detail: { file: new File(['[]'], 'vault.json') }, bubbles: true, composed: true,
    }));
    await nextTask();
    shell(app).dispatchEvent(new CustomEvent('vw-import-preview-confirm', {
      bubbles: true, composed: true,
    }));
    await nextTask();

    expect(app.dataStatus?.tone).toBe('warning');
    expect(app.dataStatus?.message).toContain('写入 2');
    expect(app.dataStatus?.message).toContain('拒绝 1');
    expect(app.dataStatus?.message).toContain('跳过 3');
    expect(app.dataStatus?.message).toContain('先同步并核对');
    expect(app.dataStatus?.message).not.toContain('vault.json');
  });

  it('treats an unknown import outcome as reconciliation-required', async () => {
    const transfer = makeTransferClient({
      confirm: vi.fn(async (): Promise<VaultTransferImportResultMessage> => ({
        ...completedImportResult,
        status: 'outcome_unknown',
        counts: { committed: 1, rejected: 0, skipped: 2, outcomeUnknown: 1 },
        mustSyncBeforeRetry: true,
      })),
    });
    const app = await mount(makeDeps({}, [], transfer));
    shell(app).dispatchEvent(new CustomEvent('vw-import-file', {
      detail: { file: new File(['[]'], 'vault.json') }, bubbles: true, composed: true,
    }));
    await nextTask();
    shell(app).dispatchEvent(new CustomEvent('vw-import-preview-confirm', {
      bubbles: true, composed: true,
    }));
    await nextTask();
    expect(app.dataStatus?.tone).toBe('danger');
    expect(app.dataStatus?.message).toContain('结果未知 1');
    expect(app.dataStatus?.message).toContain('不要重新导入整个存档');
    expect(app.dataStatus?.message).toContain('先同步并核对');
  });

  it.each(['disconnected', 'timeout'] as const)(
    'treats a missing authoritative commit result after %s as outcome-unknown',
    async (code) => {
      const transfer = makeTransferClient({
        confirm: vi.fn(async () => { throw new VaultTransferClientError(code); }),
      });
      const app = await mount(makeDeps({}, [], transfer));
      shell(app).dispatchEvent(new CustomEvent('vw-import-file', {
        detail: { file: new File(['[]'], 'vault.json') }, bubbles: true, composed: true,
      }));
      await nextTask();
      shell(app).dispatchEvent(new CustomEvent('vw-import-preview-confirm', {
        bubbles: true, composed: true,
      }));
      await nextTask();

      expect(app.dataStatus?.tone).toBe('danger');
      expect(app.dataStatus?.message).toContain('结果可能未知');
      expect(app.dataStatus?.message).toContain('不要重新导入整个存档');
      expect(app.dataStatus?.message).toContain('先同步并核对');
      expect(app.importPreview).toBeUndefined();
    },
  );

  it('exports both encrypted JSON modes and every data format exclusively through the Port client', async () => {
    const calls: string[] = [];
    const exportVault = vi.fn(async (
      format: 'json' | 'encrypted-json' | 'csv' | 'zip',
      _authorizationId: string,
      _filePassword?: string,
    ) => ({
      blob: new Blob(['x']),
      fileName: format === 'zip'
        ? 'miyu-vault.zip'
        : format === 'csv' ? 'miyu-vault.csv' : 'miyu-vault.json',
      format,
      ...(format === 'csv' ? {
        review: {
          exportedItemCount: 2,
          omittedItemCount: 1,
          warnings: [{ code: 'ssh_key_items_omitted' as const, count: 1 }],
        },
      } : {}),
    }));
    const transfer = makeTransferClient({ export: exportVault });
    const authorize = vi.fn(async (_request: Extract<Req, { type: 'vault.authorizeExport' }>) => ({
      ok: true as const,
      data: { authorizationId: EXPORT_AUTHORIZATION_ID, expiresAt: 31_000 },
    }));
    const deps = makeDeps({ 'vault.authorizeExport': authorize }, calls, transfer);
    const app = await mount(deps);

    for (const detail of [
      { format: 'json' as const, masterPassword: 'master-password' },
      {
        format: 'encrypted-json' as const,
        encryptionType: 'account' as const,
        masterPassword: 'master-password',
      },
      {
        format: 'encrypted-json' as const,
        encryptionType: 'file' as const,
        masterPassword: 'master-password',
        filePassword: 'export-password',
      },
      { format: 'zip' as const, masterPassword: 'master-password' },
      { format: 'csv' as const, masterPassword: 'master-password' },
    ]) {
      shell(app).dispatchEvent(new CustomEvent('vw-export', {
        detail, bubbles: true, composed: true,
      }));
      await nextTask();
    }

    expect(exportVault).toHaveBeenNthCalledWith(
      1, 'json', EXPORT_AUTHORIZATION_ID, undefined, { kind: 'personal' },
    );
    expect(exportVault).toHaveBeenNthCalledWith(
      2, 'encrypted-json', EXPORT_AUTHORIZATION_ID, undefined, { kind: 'personal' },
    );
    expect(exportVault).toHaveBeenNthCalledWith(
      3, 'encrypted-json', EXPORT_AUTHORIZATION_ID, 'export-password', { kind: 'personal' },
    );
    expect(exportVault).toHaveBeenNthCalledWith(
      4, 'zip', EXPORT_AUTHORIZATION_ID, undefined, { kind: 'personal' },
    );
    expect(exportVault).toHaveBeenNthCalledWith(
      5, 'csv', EXPORT_AUTHORIZATION_ID, undefined, { kind: 'personal' },
    );
    expect(authorize).toHaveBeenNthCalledWith(2, expect.objectContaining({
      format: 'encrypted-json', encryptionType: 'account',
    }));
    expect(authorize).toHaveBeenNthCalledWith(3, expect.objectContaining({
      format: 'encrypted-json', encryptionType: 'file',
    }));
    expect(authorize.mock.calls[0]?.[0]).not.toHaveProperty('encryptionType');
    expect(authorize.mock.calls[3]?.[0]).not.toHaveProperty('encryptionType');
    expect(authorize.mock.calls[4]?.[0]).not.toHaveProperty('encryptionType');
    expect(deps.createVaultTransferClient).toHaveBeenCalledTimes(5);
    expect(calls.filter((type) => type === 'vault.authorizeExport')).toHaveLength(5);
    expect(calls).not.toContain('vault.export');
    expect(calls).not.toContain('vault.import');
    expect(app.dataStatus).toEqual(expect.objectContaining({ tone: 'warning' }));
    expect(app.dataStatus?.message).toContain('1');
  });

  it('loads managed direct-member organizations and binds the selected export target end to end', async () => {
    const organizationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    const exportVault = vi.fn(async () => ({
      blob: new Blob(['{}']), fileName: 'miyu-organization-vault.json', format: 'json' as const,
    }));
    const transfer = makeTransferClient({ export: exportVault });
    const authorize = vi.fn(async () => ({
      ok: true as const,
      data: { authorizationId: EXPORT_AUTHORIZATION_ID, expiresAt: 31_000 },
    }));
    const app = await mount(makeDeps({
      'vault.listItems': async () => ({
        ok: true,
        data: {
          items: [],
          folders: [],
          collections: [{
            id: 'managed-collection', name: 'Managed', organizationId, manage: true,
          }],
          orgPermissions: [{
            id: organizationId,
            name: 'Managed organization',
            isMember: true,
            canCreateCollections: false,
            canEditCollections: false,
            canDeleteCollections: false,
            canManageCollections: false,
          }],
        },
      }),
      'vault.authorizeExport': authorize,
    }, [], transfer));
    shell(app).dispatchEvent(new CustomEvent('vw-nav-change', {
      detail: { id: 'data' }, bubbles: true, composed: true,
    }));
    await vi.waitFor(() => expect(app.exportOrganizations).toEqual([
      { id: organizationId, name: 'Managed organization' },
    ]));
    await app.updateComplete;
    const section = app.shadowRoot!.querySelector('vw-data-section') as HTMLElement & {
      updateComplete: Promise<boolean>;
      shadowRoot: ShadowRoot;
    };
    await section.updateComplete;
    const selector = section.shadowRoot.querySelector<HTMLSelectElement>('[data-export-target]')!;
    expect([...selector.options].map((option) => option.value)).toEqual(['personal', organizationId]);

    shell(app).dispatchEvent(new CustomEvent('vw-export', {
      detail: {
        format: 'json',
        masterPassword: 'master-password',
        target: { kind: 'organization', organizationId },
      },
      bubbles: true,
      composed: true,
    }));
    await vi.waitFor(() => expect(exportVault).toHaveBeenCalledOnce());
    expect(authorize).toHaveBeenCalledWith({
      type: 'vault.authorizeExport',
      format: 'json',
      target: { kind: 'organization', organizationId },
      masterPassword: 'master-password',
    });
    expect(exportVault).toHaveBeenCalledWith(
      'json',
      EXPORT_AUTHORIZATION_ID,
      undefined,
      { kind: 'organization', organizationId },
    );
  });

  it('reports a declined CSV review as cancellation instead of a completed backup', async () => {
    const transfer = makeTransferClient({
      export: vi.fn(async () => { throw new VaultTransferClientError('cancelled'); }),
    });
    const app = await mount(makeDeps({}, [], transfer));

    shell(app).dispatchEvent(new CustomEvent('vw-export', {
      detail: { format: 'csv', masterPassword: 'master-password' },
      bubbles: true,
      composed: true,
    }));
    await nextTask();

    expect(transfer.export).toHaveBeenCalledWith(
      'csv', EXPORT_AUTHORIZATION_ID, undefined, { kind: 'personal' },
    );
    expect(app.dataStatus).toEqual({ message: '已取消传输', tone: 'info' });
  });

  it('does not open the transfer Port when worker verification fails and clears submitted secrets', async () => {
    const transfer = makeTransferClient();
    const authorize = vi.fn(async () => ({
      ok: false as const,
      error: { code: 'denied' as const, message: 'verification failed' },
    }));
    const deps = makeDeps({ 'vault.authorizeExport': authorize }, [], transfer);
    const app = await mount(deps);
    const detail = {
      format: 'encrypted-json' as const,
      encryptionType: 'file' as const,
      masterPassword: 'master-secret',
      filePassword: 'file-secret',
    };

    shell(app).dispatchEvent(new CustomEvent('vw-export', {
      detail, bubbles: true, composed: true,
    }));
    await nextTask();

    expect(authorize).toHaveBeenCalledWith({
      type: 'vault.authorizeExport', format: 'encrypted-json', encryptionType: 'file',
      target: { kind: 'personal' },
      masterPassword: 'master-secret',
    });
    expect(detail).toEqual({
      format: 'encrypted-json', encryptionType: 'file', masterPassword: '', filePassword: '',
    });
    expect(deps.createVaultTransferClient).not.toHaveBeenCalled();
    expect(transfer.export).not.toHaveBeenCalled();
    expect(app.dataStatus?.tone).toBe('danger');
  });

  it('signs out on vw-delete-local (confirmed)', async () => {
    const calls: string[] = [];
    window.confirm = vi.fn(() => true);
    const app = await mount(makeDeps({ 'auth.logout': async () => ({ ok: true, data: null }) }, calls));
    shell(app).dispatchEvent(new CustomEvent('vw-delete-local', { bubbles: true, composed: true }));
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toContain('auth.logout');
    expect(app.locked).toBe(true);
  });

  it('keeps the unlocked state and reports an error when delete-local logout fails', async () => {
    window.confirm = vi.fn(() => true);
    const app = await mount(makeDeps({
      'auth.logout': async () => ({ ok: false, error: { code: 'error', message: 'logout failed' } }),
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-delete-local', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(app.locked).toBe(false);
    expect(app.dataStatus).toEqual({ message: 'logout failed', tone: 'danger' });
  });

  it('signs out on vw-logout', async () => {
    const calls: string[] = [];
    window.confirm = vi.fn(() => true);
    const app = await mount(makeDeps({ 'auth.logout': async () => ({ ok: true, data: null }) }, calls));
    shell(app).dispatchEvent(new CustomEvent('vw-logout', { bubbles: true, composed: true }));
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toContain('auth.logout');
    expect(app.locked).toBe(true);
  });

  it('does not claim logout succeeded when the worker rejects it', async () => {
    window.confirm = vi.fn(() => true);
    const app = await mount(makeDeps({
      'auth.logout': async () => ({ ok: false, error: { code: 'error', message: 'logout failed' } }),
    }));
    shell(app).dispatchEvent(new CustomEvent('vw-logout', { bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(app.locked).toBe(false);
    expect(app.accountEmail).toBe('me@x.dev');
    expect(app.connectionStatus).toEqual({ message: 'logout failed', tone: 'danger' });
  });

  it('does not sign out when the logout confirmation is cancelled', async () => {
    const calls: string[] = [];
    window.confirm = vi.fn(() => false);
    const app = await mount(makeDeps({ 'auth.logout': async () => ({ ok: true, data: null }) }, calls));
    shell(app).dispatchEvent(new CustomEvent('vw-logout', { bubbles: true, composed: true }));
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).not.toContain('auth.logout');
  });

  it('refreshes the active identity on account changes and ignores an older account response', async () => {
    const older = deferred<Res>();
    const latest = deferred<Res>();
    let listCall = 0;
    const deps = makeDeps({
      'auth.listAccounts': () => {
        listCall += 1;
        if (listCall === 1) {
          return { ok: true, data: { accounts: [{ email: 'first@example.com', active: true }] } };
        }
        return listCall === 2 ? older.promise : latest.promise;
      },
    });
    const app = await mount(deps);
    expect(app.accountEmail).toBe('first@example.com');
    app.accountName = 'Outdated name';

    const listener = (deps.subscribeSessionChanges as ReturnType<typeof vi.fn>).mock.calls[0]![0] as (kind: 'keyMaterial' | 'account') => void;
    listener('account');
    await nextTask();
    listener('account');
    await nextTask();
    expect(listCall).toBe(3);

    latest.resolve({ ok: true, data: { accounts: [{ email: 'latest@example.com', active: true }] } });
    await nextTask();
    expect(app.accountEmail).toBe('latest@example.com');
    expect(app.accountName).toBe('');

    older.resolve({ ok: true, data: { accounts: [{ email: 'older@example.com', active: true }] } });
    await nextTask();
    expect(app.accountEmail).toBe('latest@example.com');
    expect(app.accountName).toBe('');
  });

  it('keeps transfers locked when an account transition cannot refresh its identity', async () => {
    let accountReads = 0;
    const exportVault = vi.fn(async () => ({
      blob: new Blob(['{}']),
      fileName: 'miyu-vault.json',
      format: 'json' as const,
    }));
    const transfer = makeTransferClient({ export: exportVault });
    const deps = makeDeps({
      'auth.listAccounts': async () => {
        accountReads += 1;
        return accountReads === 1
          ? { ok: true, data: { accounts: [{ email: 'old@example.com', active: true }] } }
          : { ok: false, error: { code: 'error', message: 'identity unavailable' } };
      },
    }, [], transfer);
    const app = await mount(deps);
    expect(app.accountEmail).toBe('old@example.com');
    const listener = (deps.subscribeSessionChanges as ReturnType<typeof vi.fn>)
      .mock.calls[0]![0] as (kind: 'keyMaterial' | 'account') => void;

    listener('account');
    expect(app.locked).toBe(true);
    expect(app.accountEmail).toBe('');
    expect(app.transferRecoveryUnavailable).toBe(true);
    await vi.waitFor(() => expect(accountReads).toBe(2));
    expect(app.locked).toBe(true);

    shell(app).dispatchEvent(new CustomEvent('vw-export', {
      detail: { format: 'json', masterPassword: 'master-secret' }, bubbles: true, composed: true,
    }));
    await nextTask();
    expect(exportVault).not.toHaveBeenCalled();
  });

  it('does not restore identity when the initial account response arrives after logout', async () => {
    window.confirm = vi.fn(() => true);
    const accounts = deferred<Res>();
    const deps = makeDeps({
      'auth.listAccounts': () => accounts.promise,
      'auth.logout': async () => ({ ok: true, data: null }),
    });
    const app = await mount(deps);
    expect(app.locked).toBe(true);
    app.accountName = 'Current name';

    shell(app).dispatchEvent(new CustomEvent('vw-logout', { bubbles: true, composed: true }));
    await nextTask();
    expect(app.locked).toBe(true);
    expect(app.accountEmail).toBe('');
    expect(app.accountName).toBe('');

    accounts.resolve({ ok: true, data: { accounts: [{ email: 'stale@example.com', active: true }] } });
    await nextTask();
    expect(app.accountEmail).toBe('');
    expect(app.accountName).toBe('');
  });

  it('clears Sends and pending import data after a cross-context lock signal', async () => {
    let state: 'unlocked' | 'locked' | 'loggedOut' = 'unlocked';
    const transfer = makeTransferClient({
      import: vi.fn(async () => { throw new VaultTransferClientError('password_required'); }),
    });
    const deps = makeDeps({
      'auth.getState': async () => ({ ok: true, data: { state } }),
      'sends.list': async () => ({
        ok: true,
        data: { sends: [{ id: 's1', accessId: 'a', type: 0, name: 'secret', hidden: false, hideEmail: false, url: 'https://s', deletionDate: '', accessCount: 0, disabled: false, passwordProtected: false }] },
      }),
    }, [], transfer);
    const app = await mount(deps);
    shell(app).dispatchEvent(new CustomEvent('vw-import-file', { detail: { file: new File(['x'], 'vault.json') }, bubbles: true, composed: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(app.awaitingImportPassword).toBe(true);
    expect(app.sendsState.status).toBe('ready');

    state = 'locked';
    const listener = (deps.subscribeSessionChanges as ReturnType<typeof vi.fn>).mock.calls[0]![0] as (kind: 'keyMaterial' | 'account') => void;
    listener('keyMaterial');
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(app.locked).toBe(true);
    expect(app.awaitingImportPassword).toBe(false);
    expect(app.sendsState).toEqual({ status: 'idle' });
    expect(transfer.cancel).toHaveBeenCalledTimes(1);
    expect(transfer.dispose).toHaveBeenCalledTimes(1);

    state = 'loggedOut';
    listener('account');
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(app.accountEmail).toBe('');
  });

  it('invalidates a preview immediately when the active account changes', async () => {
    const transfer = makeTransferClient();
    const deps = makeDeps({}, [], transfer);
    const app = await mount(deps);
    shell(app).dispatchEvent(new CustomEvent('vw-import-file', {
      detail: { file: new File(['[]'], 'vault.json') }, bubbles: true, composed: true,
    }));
    await nextTask();
    expect(app.importPreview).toBeDefined();

    const listener = (
      deps.subscribeSessionChanges as ReturnType<typeof vi.fn>
    ).mock.calls[0]![0] as (kind: 'keyMaterial' | 'account') => void;
    listener('account');

    expect(app.importPreview).toBeUndefined();
    expect(transfer.cancel).toHaveBeenCalledTimes(1);
    expect(transfer.dispose).toHaveBeenCalledTimes(1);
  });

  it('ignores a late inspection result after account invalidation', async () => {
    const inspection = deferred<VaultTransferPortPreviewModel>();
    const transfer = makeTransferClient({ import: vi.fn(() => inspection.promise) });
    const deps = makeDeps({}, [], transfer);
    const app = await mount(deps);
    shell(app).dispatchEvent(new CustomEvent('vw-import-file', {
      detail: { file: new File(['[]'], 'vault.json') }, bubbles: true, composed: true,
    }));
    await nextTask();
    expect(app.pending).toBe(true);

    const listener = (
      deps.subscribeSessionChanges as ReturnType<typeof vi.fn>
    ).mock.calls[0]![0] as (kind: 'keyMaterial' | 'account') => void;
    listener('account');
    expect(app.pending).toBe(false);
    inspection.resolve(transferPreview);
    await nextTask();

    expect(app.importPreview).toBeUndefined();
    expect(app.dataStatus).toBeUndefined();
    expect(transfer.cancel).toHaveBeenCalledTimes(1);
    expect(transfer.dispose).toHaveBeenCalledTimes(1);
  });

  it('uses a fixed status when the transfer Port disconnects', async () => {
    const transfer = makeTransferClient({
      import: vi.fn(async () => { throw new VaultTransferClientError('disconnected'); }),
    });
    const app = await mount(makeDeps({}, [], transfer));
    shell(app).dispatchEvent(new CustomEvent('vw-import-file', {
      detail: { file: new File(['sensitive'], 'private-name.json') },
      bubbles: true,
      composed: true,
    }));
    await nextTask();

    expect(app.dataStatus?.tone).toBe('danger');
    expect(app.dataStatus?.message).toContain('传输连接已中断');
    expect(app.dataStatus?.message).not.toContain('private-name.json');
    expect(app.dataStatus?.message).not.toContain('sensitive');
  });

  it('clears sensitive state when session refresh fails and unsubscribes on disconnect', async () => {
    let fail = false;
    const unsubscribe = vi.fn();
    const deps = makeDeps({
      'auth.getState': async () => fail
        ? ({ ok: false, error: { code: 'error', message: 'offline' } })
        : ({ ok: true, data: { state: 'unlocked' } }),
    });
    deps.subscribeSessionChanges = vi.fn(() => unsubscribe);
    const app = await mount(deps);
    app.sendsState = { status: 'ready', data: [] };
    fail = true;
    const listener = (deps.subscribeSessionChanges as ReturnType<typeof vi.fn>).mock.calls[0]![0] as (kind: 'keyMaterial' | 'account') => void;
    listener('keyMaterial');
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(app.locked).toBe(true);
    expect(app.sendsState).toEqual({ status: 'idle' });
    app.remove();
    expect(unsubscribe).toHaveBeenCalledTimes(1);
  });

});
