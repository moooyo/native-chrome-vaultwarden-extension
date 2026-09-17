import { describe, it, expect, vi } from 'vitest';
import type { SessionState } from '../core/session/session-manager.js';
import { UriMatchStrategy, type UriMatchStrategySetting } from '../core/vault/uri-match.js';
import {
  AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
  WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION,
  type LockTimeoutSetting,
  type OnIdleAction,
  type ClipboardClearSetting,
  type AutofillSettings,
  type AutofillPolicySettings,
  type WebsitePasskeySettings,
} from './settings.js';
import type { RequestMessage } from '../messaging/protocol.js';
import { AppError } from '../core/errors.js';
import { ClientEventType } from '../core/events/client-event.js';
import { createRouter as createRouterWithContext } from './router.js';
import type { RouterDeps } from './router.js';
import type { RequestContext } from './sender-guard.js';
import { AutofillIntentRegistry } from './autofill-intent-registry.js';
import type { SessionLease } from '../core/session/session-manager.js';
import type { AccountLease } from '../core/session/account-gate.js';
import { AutofillPolicyGate } from './autofill-policy-gate.js';
import {
  assertAutofillAuthorizationPolicy,
  captureAutofillAuthorizationPolicy,
  type AutofillAuthorizationPolicyLease,
} from './autofill-authorization-policy.js';
import { AutofillPendingSaveStore } from './autofill-pending-save-store.js';
import { AutofillKeyboardGrantRegistry } from './autofill-keyboard-grant-registry.js';
import { AutofillUsernameStageStore } from './autofill-username-stage-store.js';
import { PageLoadFillDeduper } from './page-load-fill-deduper.js';
import { RepromptAutofillGrantRegistry } from './reprompt-autofill-grant-registry.js';
import type { SymmetricKey } from '../core/crypto/keys.js';
import { createUserKeyGeneratorHistoryCrypto } from '../core/generator/history-crypto.js';
import type { AtomicKeyValueStore } from '../platform/store.js';
import {
  EMPTY_LOGIN_CUSTOM_PLAN,
  EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
} from '../core/vault/login-custom-fields.js';
import type {
  EffectiveEnterprisePolicySnapshot,
  EffectiveMaximumVaultTimeoutPolicy,
  EffectivePasswordGeneratorPolicy,
  EffectiveUriMatchDefaultsPolicy,
  PolicyLease,
} from '../core/policy/effective-enterprise-policy.js';
import {
  createGeneratorPolicySnapshot,
  type PasswordGeneratorOptions,
  UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
} from '../core/generator/enterprise-password-policy.js';
import { EMPTY_PASSWORD_GENERATOR_POLICY } from '../core/policy/password-generator-policy.js';
import { MAX_PIN_UTF16_CODE_UNITS } from '../core/session/pin-constraints.js';
import {
  HTTP_AUTH_SETTINGS_SCHEMA_VERSION,
  type HttpAuthSettings,
} from './http-auth-settings.js';
import type {
  InteractiveTwoFactorBroker,
  InteractiveTwoFactorOwner,
} from '../core/session/interactive-two-factor.js';
import { CLIENT_EVENT_BEST_EFFORT_WAIT_MS } from './client-event-best-effort.js';
import { GeneratorHistoryProductionService } from './generator-history-production.js';

const EXTENSION_PAGE_CONTEXT = {
  kind: 'extensionPage',
  url: 'chrome-extension://test/ui/popup/popup.html',
  origin: 'chrome-extension://test',
  documentId: 'popup-doc-1',
} satisfies RequestContext;

const OPTIONS_PAGE_CONTEXT = {
  kind: 'extensionPage',
  url: 'chrome-extension://test/ui/options/options.html',
  origin: 'chrome-extension://test',
} satisfies RequestContext;

const CONTENT_CONTEXT = {
  kind: 'content',
  tabId: 7,
  frameId: 0,
  documentId: 'doc-1',
  url: 'https://sender.example/login',
  origin: 'https://sender.example',
} satisfies RequestContext;

const TEST_RUNTIME_INCARNATION = '10000000-0000-4000-8000-000000000001';
const PREVIOUS_RUNTIME_INCARNATION = '10000000-0000-4000-8000-000000000002';
const NEXT_RUNTIME_INCARNATION = '10000000-0000-4000-8000-000000000003';
const TEST_CAPTURE_ID = 'a0000000-0000-4000-8000-000000000004';
const TEST_PROMPT_ID = 'b0000000-0000-4000-8000-000000000005';

const RUNTIME_BOUND_AUTOFILL_REQUESTS = new Set<RequestMessage['type']>([
  'autofill.findCandidates',
  'autofill.findStructuredCandidates',
  'autofill.claimKeyboardGrant',
  'autofill.keyboard.findCandidates',
  'autofill.keyboard.issueIntent',
  'autofill.continuation.redeemKeyboardReprompt',
  'autofill.keyboard.redeemLoginIntent',
  'autofill.keyboard.redeemTotpIntent',
  'autofill.keyboard.redeemStructuredIntent',
  'autofill.issueIntent',
  'autofill.issueStructuredIntent',
  'autofill.redeemLoginIntent',
  'autofill.redeemTotpIntent',
  'autofill.redeemStructuredIntent',
  'autofill.getClientConfig',
  'autofill.authorizeGeneratorUse',
  'autofill.trackGeneratedValue',
  'autofill.issuePageLoadIntent',
  'autofill.redeemPageLoadIntent',
  'autofill.captureSubmission',
  'autofill.claimSavePrompt',
  'autofill.commitSavePrompt',
  'autofill.dismissSavePrompt',
]);

const PASSWORD_FIDO_OWNER = Object.freeze({
  flow: 'password',
  generation: 8,
  serverUrl: 'https://vault.example/',
  bindingId: 'c8882c32-17e1-4052-ac72-9b09f0bbb11d',
}) satisfies InteractiveTwoFactorOwner;

const DEVICE_FIDO_OWNER = Object.freeze({
  flow: 'deviceLogin',
  generation: 9,
  serverUrl: 'https://vault.example/',
  bindingId: 'device-request-9',
}) satisfies InteractiveTwoFactorOwner;

function interactiveTwoFactorBroker<Result = never>(
  overrides: Partial<InteractiveTwoFactorBroker<Result>> = {},
): InteractiveTwoFactorBroker<Result> {
  return {
    begin: vi.fn(async () => { throw new Error('unexpected interactive two-factor begin'); }),
    cancelLaunch: vi.fn(async () => false),
    bindTab: vi.fn(async () => {}),
    matchCaller: vi.fn(() => undefined),
    complete: vi.fn(async () => { throw new Error('unexpected interactive two-factor completion'); }),
    ...overrides,
  };
}

function loginIntentRequest(cipherId = '1') {
  return { type: 'autofill.issueIntent' as const, cipherId, purpose: 'login' as const, customPlan: EMPTY_LOGIN_CUSTOM_PLAN };
}

const STRUCTURED_TARGET = Object.freeze({
  kind: 'card' as const,
  runtimeIncarnation: TEST_RUNTIME_INCARNATION,
  formId: 'frame-form-1',
  generation: 4,
  roles: ['number', 'exp', 'code'] as const,
});

function loginTabTarget() {
  return {
    kind: 'login' as const,
    frameId: 0,
    formId: 'form-1',
    documentId: 'doc-0',
    runtimeIncarnation: TEST_RUNTIME_INCARNATION,
    generation: 1,
    customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
  };
}

const DEFAULT_AUTOFILL_SETTINGS = {
  inlineSuggestions: true,
  pageLoadFill: false,
  autoCopyTotp: true,
  savePromptEnabled: true,
  updatePromptEnabled: true,
  savePromptExcludedDomains: [],
  blockedDomains: [],
} satisfies AutofillSettings;

const DEFAULT_AUTOFILL_SETTINGS_VIEW = {
  ...DEFAULT_AUTOFILL_SETTINGS,
  showMatchingLoginCount: true,
  pageLoadFillDefault: true,
  autofillPolicyValid: true,
  websitePasskeys: {
    enabled: false,
    excludedDomains: [],
    valid: true,
  },
  httpAuth: {
    enabled: false,
    allowedOrigins: [],
    valid: true,
  },
  enterprisePolicy: {
    pinUnlockAllowed: true,
    maximumVaultTimeoutManaged: false,
    maximumVaultTimeoutMode: 'local',
    uriMatchDefaultManaged: false,
    uriMatchDefaultMalformed: false,
    activateAutofillManaged: false,
  },
  generator: createGeneratorPolicySnapshot(null, 0),
} as const;

const INLINE_GENERATOR_OPTIONS: PasswordGeneratorOptions = Object.freeze({
  mode: 'password',
  password: Object.freeze({
    length: 18,
    lowercase: true,
    uppercase: true,
    numbers: true,
    special: true,
    minNumbers: 1,
    minSpecial: 0,
    avoidAmbiguous: true,
  }),
  passphrase: Object.freeze({
    numWords: 5,
    separator: '-',
    capitalize: false,
    includeNumber: false,
  }),
});

function uriMatchDefaultsPolicy(
  value: UriMatchStrategySetting,
  malformed = false,
): EffectiveUriMatchDefaultsPolicy {
  return { organizationId: 'organization-id', malformed, value };
}

function generatorPolicy(
  data: Partial<typeof EMPTY_PASSWORD_GENERATOR_POLICY>,
  malformed = false,
): EffectivePasswordGeneratorPolicy {
  return {
    malformed,
    data: { ...EMPTY_PASSWORD_GENERATOR_POLICY, ...data },
  };
}

function enterprisePolicyControl(options: {
  pinAllowed?: boolean;
  timeout?: EffectiveMaximumVaultTimeoutPolicy | null;
  uriMatch?: EffectiveUriMatchDefaultsPolicy | null;
  generator?: EffectivePasswordGeneratorPolicy | null;
  activateAutofill?: boolean;
  available?: boolean;
} = {}) {
  let generation = 0;
  let available = options.available ?? true;
  let uriMatch = options.uriMatch ?? null;
  let generator = options.generator ?? null;
  let activateAutofill = options.activateAutofill ?? false;
  const gate: NonNullable<RouterDeps['enterprisePolicyGate']> = {
    capture: () => {
      if (!available) throw new AppError('sync_required', 'policy unavailable');
      return {
        generation,
        serverGeneration: 0,
        accountGeneration: 0,
        serverUrl: 'https://vault.example/',
        accountIdentity: 'user@example.com',
        rawGeneration: `raw-generation-${generation}`,
      } satisfies PolicyLease;
    },
    assert: (lease) => {
      if (!available || lease.generation !== generation) throw new AppError('denied', 'policy changed');
      return {
        scope: {
          serverGeneration: lease.serverGeneration,
          accountGeneration: lease.accountGeneration,
          serverUrl: lease.serverUrl,
          accountIdentity: lease.accountIdentity,
          rawGeneration: lease.rawGeneration,
        },
        unlockWithPinRemoved: options.pinAllowed === false,
        maximumVaultTimeoutPolicy: options.timeout ?? null,
        passwordGeneratorPolicy: generator,
        activateAutofillRequired: activateAutofill,
        uriMatchDefaultsPolicy: uriMatch,
      } as EffectiveEnterprisePolicySnapshot;
    },
  };
  return {
    gate,
    invalidate() { generation += 1; },
    replaceUriMatch(next: EffectiveUriMatchDefaultsPolicy | null) {
      uriMatch = next;
      generation += 1;
    },
    replaceGenerator(next: EffectivePasswordGeneratorPolicy | null) {
      generator = next;
      generation += 1;
    },
    replaceActivateAutofill(next: boolean) {
      activateAutofill = next;
      generation += 1;
    },
    makeUnavailable() { available = false; generation += 1; },
  };
}

type TestRouterDeps = Omit<RouterDeps,
  | 'sessionGate'
  | 'accountGate'
  | 'autofillPolicyGate'
  | 'enterprisePolicyGate'
  | 'autofillIntents'
  | 'keyboardGrants'
  | 'saveCaptureCoordinator'
  | 'getKeyboardTopDocument'
  | 'pageLoadFillDeduper'>
  & Partial<Pick<RouterDeps,
    | 'sessionGate'
    | 'accountGate'
    | 'autofillPolicyGate'
    | 'enterprisePolicyGate'
    | 'autofillIntents'
    | 'getKeyboardTopDocument'
    | 'pageLoadFillDeduper'>>
  & {
    keyboardGrants?: AutofillKeyboardGrantRegistry<SessionLease, AccountLease, AutofillAuthorizationPolicyLease>;
    saveCaptureCoordinator?: Partial<NonNullable<RouterDeps['saveCaptureCoordinator']>>;
  };

const ACTIVE_SESSION_GATE: RouterDeps['sessionGate'] = {
  capture: () => ({ generation: 0 }),
  assert: () => {},
};

const ACTIVE_ACCOUNT_GATE: RouterDeps['accountGate'] = {
  capture: () => ({
    serverGeneration: 0,
    accountGeneration: 0,
    serverUrl: 'https://vault.example/',
    accountIdentity: 'user@example.com',
  }),
  assert: () => {},
};

function createTestStore(): AtomicKeyValueStore {
  const values = new Map<string, unknown>();
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const value = values.get(key);
      return value === undefined ? undefined : structuredClone(value) as T;
    },
    async set(key: string, value: unknown): Promise<void> { values.set(key, structuredClone(value)); },
    async setMany(next: Readonly<Record<string, unknown>>): Promise<void> {
      for (const [key, value] of Object.entries(next)) values.set(key, structuredClone(value));
    },
    async remove(key: string): Promise<void> { values.delete(key); },
    async clear(): Promise<void> { values.clear(); },
  };
}

async function realReleaseBoundaryFixture() {
  const { SessionGate } = await import('./session-gate.js');
  const { VaultReleaseGate } = await import('./vault-release-gate.js');
  const { VaultTimeoutController } = await import('./vault-timeout-controller.js');
  const { VaultTimeoutStateStore } = await import('./vault-timeout-state.js');
  const { AutofillSaveCaptureCoordinator } = await import('./autofill-save-capture-coordinator.js');
  const { SessionManager } = await import('../core/session/session-manager.js');
  const { AuthService } = await import('../core/session/auth-service.js');
  const localStore = createTestStore();
  const sessionStore = createTestStore();
  const session = new SessionManager({ localStore, sessionStore });
  await session.saveUnlocked({
    email: 'user@example.com',
    accessToken: 'synthetic-access',
    refreshToken: 'synthetic-refresh',
    expiresAt: 999_999,
    protectedKey: 'synthetic-protected-key',
    kdf: 0,
    kdfIterations: 5_000,
    userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
  });
  const sessionGate = new SessionGate('unlocked');
  const networkStore = createTestStore();
  const pendingSaves = new AutofillPendingSaveStore({ store: networkStore });
  const coordinator = new AutofillSaveCaptureCoordinator({
    store: networkStore,
    captures: pendingSaves,
    loadUserKey: async () => undefined,
    now: () => 1_000,
  });
  expect(await coordinator.activateRuntime({
    tabId: CONTENT_CONTEXT.tabId,
    frameId: CONTENT_CONTEXT.frameId,
    documentId: CONTENT_CONTEXT.documentId,
    frameUrl: CONTENT_CONTEXT.url,
    runtimeIncarnation: TEST_RUNTIME_INCARNATION,
  })).toBe(true);
  const stateStore = new VaultTimeoutStateStore({ localStore, sessionStore });
  await stateStore.initializeBrowserSession();
  const transitionEvents: Array<{ phase: string; state?: string }> = [];
  const auth = new AuthService({
    api: {} as never,
    session,
    sessionGate,
    onSessionTransition: (event) => {
      transitionEvents.push(event);
      if (event.phase === 'start') timeout.transitionStarted();
      sessionGate.handleTransition(event);
    },
    onSerializedSessionTransition: async (event) => {
      if (event.phase === 'start') {
        await Promise.allSettled([pendingSaves.clear(), coordinator.clear()]);
      } else {
        await timeout.transitionSettled(event.succeeded, event.state);
      }
    },
  });
  const timeout: InstanceType<typeof VaultTimeoutController> = new VaultTimeoutController({
    state: stateStore,
    alarms: { create: async () => {}, clear: async () => true },
    getContext: async () => {
      const active = await session.getActiveAuth();
      return {
        state: await session.getState(),
        accountKey: 'https://vault.example/\nuser@example.com',
        email: 'user@example.com',
        ...(active?.sessionBindingId ? { sessionBindingId: active.sessionBindingId } : {}),
      };
    },
    getConfig: async () => ({
      lockTimeout: '1', onIdleAction: 'lock', idleSeconds: 60,
      lockOnSystemLock: true, logoutOnBrowserClose: false,
      closeLogoutActionProvenance: null, closeLogoutTimeoutProvenance: null,
      mode: 'local', managed: false, failClosed: false,
    }),
    applyAction: async (expected, action) => {
      const active = await session.getActiveAuth();
      if (active?.email !== expected.email || active.sessionBindingId !== expected.sessionBindingId) return;
      expect(action).toBe('lock');
      await auth.lock();
    },
    now: () => 1_000,
    monotonicNow: () => 1_000,
  });
  await timeout.initialize();
  sessionGate.setPreflight(() => timeout.preflight());
  const releaseGate = new VaultReleaseGate(timeout, sessionGate);
  const settings = intentSettings();
  settings.getAutofillSettings = vi.fn(async () => ({ ...DEFAULT_AUTOFILL_SETTINGS, pageLoadFill: true }));
  const vaultRead = vi.fn(async () => ({ username: 'user', password: 'synthetic-release-secret' }));
  const router = createRouter({
    auth: { getState: () => session.getState() },
    settings,
    sessionGate,
    vaultReleaseGate: releaseGate,
    vaultTimeout: timeout,
    getSessionBindingId: async () => (await session.getActiveAuth())?.sessionBindingId,
    saveCaptureCoordinator: {
      captureRuntimeAuthority: coordinator.captureRuntimeAuthority.bind(coordinator),
      isRuntimeCurrent: coordinator.isRuntimeCurrent.bind(coordinator),
    },
    vault: {
      findAutofillCandidates: vi.fn(async () => [{
        id: 'login-1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
      }]),
      getAutofillLoginData: vaultRead,
    },
  });
  const token = intentId(await router.handle({ type: 'autofill.issuePageLoadIntent' }, CONTENT_CONTEXT));
  return {
    router, token, auth, session, sessionStore, networkStore, coordinator, timeout,
    releaseGate, vaultRead, transitionEvents,
  };
}

function createRouter(deps: TestRouterDeps) {
  const sessionGate = deps.sessionGate ?? ACTIVE_SESSION_GATE;
  const accountGate = deps.accountGate ?? ACTIVE_ACCOUNT_GATE;
  const autofillPolicyGate = deps.autofillPolicyGate ?? new AutofillPolicyGate();
  const enterprisePolicyGate = deps.enterprisePolicyGate ?? enterprisePolicyControl().gate;
  const authorizationPolicyGates = {
    autofill: autofillPolicyGate,
    enterprise: enterprisePolicyGate,
  } as const;
  const isSessionLeaseCurrent = (lease: SessionLease): boolean => {
    try { sessionGate.assert(lease); return true; } catch { return false; }
  };
  const isAccountLeaseCurrent = (lease: AccountLease): boolean => {
    try { accountGate.assert(lease); return true; } catch { return false; }
  };
  const isPolicyLeaseCurrent = (lease: AutofillAuthorizationPolicyLease): boolean => {
    try { assertAutofillAuthorizationPolicy(authorizationPolicyGates, lease); return true; } catch { return false; }
  };
  const autofillIntents = deps.autofillIntents ?? new AutofillIntentRegistry<SessionLease, AccountLease, AutofillAuthorizationPolicyLease>({
    isSessionLeaseCurrent,
    isAccountLeaseCurrent,
    isPolicyLeaseCurrent,
  });
  const pendingStore = createTestStore();
  const loadUserKey = deps.loadPendingSaveUserKey ?? (async (): Promise<SymmetricKey> => ({
    encKey: new Uint8Array(32).fill(17),
    macKey: new Uint8Array(32).fill(29),
  }));
  const pendingSaves = deps.pendingSaves ?? new AutofillPendingSaveStore({ store: pendingStore });
  const usernameStages = deps.usernameStages ?? new AutofillUsernameStageStore({
    store: pendingStore,
    loadUserKey,
  });
  const saveCaptureCoordinator: NonNullable<RouterDeps['saveCaptureCoordinator']> = {
    activateRuntime: vi.fn(async () => true),
    isRuntimeCurrent: vi.fn(async (
      _tabId: number,
      _frameId: number,
      _documentId: string,
      runtimeIncarnation: string,
    ) => runtimeIncarnation === TEST_RUNTIME_INCARNATION),
    captureRuntimeAuthority: async (...args) => (
      await saveCaptureCoordinator.isRuntimeCurrent(...args)
        ? Object.freeze({ assertCurrent: () => {} })
        : undefined
    ),
    stage: async (
      input: Parameters<NonNullable<RouterDeps['saveCaptureCoordinator']>['stage']>[0],
      credentials: Parameters<NonNullable<RouterDeps['saveCaptureCoordinator']>['stage']>[1],
      ownedUserKey: Parameters<NonNullable<RouterDeps['saveCaptureCoordinator']>['stage']>[2],
    ) => {
      await pendingSaves.put(input, credentials, ownedUserKey);
      return undefined as never;
    },
    stageUsername: async (input) => usernameStages.stage(input),
    consumeUsername: async (context) => usernameStages.consume(context),
    claimPendingSave: async (context, ownedUserKey, evaluate, captureId) => (
      pendingSaves.claim(context, ownedUserKey, evaluate, captureId)
    ),
    takePendingSave: async (promptId, context, ownedUserKey) => (
      pendingSaves.take(promptId, context, ownedUserKey)
    ),
    dismissPendingSave: async (promptId, context) => pendingSaves.dismiss(promptId, context),
    ...deps.saveCaptureCoordinator,
  };
  const getSessionBindingId = deps.getSessionBindingId ?? (async () => 'session-binding');
  const keyboardGrants = deps.keyboardGrants ?? new AutofillKeyboardGrantRegistry<SessionLease, AccountLease, AutofillAuthorizationPolicyLease>({
    isSessionLeaseCurrent,
    isAccountLeaseCurrent,
    isPolicyLeaseCurrent,
  });
  const getKeyboardTopDocument = deps.getKeyboardTopDocument ?? (async () => ({
    documentId: CONTENT_CONTEXT.documentId,
    url: CONTENT_CONTEXT.url,
  }));
  const getContentDocument = deps.getContentDocument ?? (async () => ({
    documentId: CONTENT_CONTEXT.documentId,
    url: CONTENT_CONTEXT.url,
  }));
  const pageLoadFillDeduper = deps.pageLoadFillDeduper ?? new PageLoadFillDeduper();
  const repromptAutofillGrants = deps.repromptAutofillGrants
    ?? new RepromptAutofillGrantRegistry<SessionLease, AccountLease, AutofillAuthorizationPolicyLease>({
      isSessionLeaseCurrent,
      isAccountLeaseCurrent,
      isPolicyLeaseCurrent,
      now: () => Date.now(),
    });
  const auth = {
    resetForServerChange: async (commitServerUrl?: () => Promise<void>) => {
      await commitServerUrl?.();
    },
    ...deps.auth,
  };
  const settings = {
    getAutofillSettings: async () => DEFAULT_AUTOFILL_SETTINGS,
    saveAutofillSettings: async () => {},
    getAutofillPolicySettings: async () => {
      const [defaultUriMatchStrategy, autofill] = await Promise.all([
        deps.settings.getDefaultUriMatchStrategy(),
        deps.settings.getAutofillSettings?.()
          ?? Promise.resolve(DEFAULT_AUTOFILL_SETTINGS),
      ]);
      return {
        schemaVersion: AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
        defaultUriMatchStrategy,
        pageLoadFillDefault: true,
        ...autofill,
      };
    },
    saveAutofillPolicySettings: async (policy: AutofillPolicySettings) => {
      await deps.settings.saveDefaultUriMatchStrategy(policy.defaultUriMatchStrategy);
      await deps.settings.saveAutofillSettings?.(policy);
    },
    ...deps.settings,
  };
  const vault: RouterDeps['vault'] = {
    ...deps.vault,
    commitCapturedLogin: deps.vault.commitCapturedLogin ?? (async (
      frameUrl,
      submitted,
      defaultStrategy,
      expected,
      assertCurrent,
    ) => {
      const current = await deps.vault.checkSaveLogin?.(frameUrl, submitted, defaultStrategy);
      if (!current || JSON.stringify(current) !== JSON.stringify(expected)) {
        throw new AppError('denied', 'captured decision changed');
      }
      assertCurrent?.();
      if (current.action === 'save') {
        if (!deps.vault.saveLogin) throw new Error('saveLogin is not wired');
        return deps.vault.saveLogin(frameUrl, submitted.username, submitted.password, assertCurrent);
      }
      if (current.action === 'addUri') {
        if (!submitted.username || !deps.vault.addLoginUri) throw new Error('addLoginUri is not wired');
        return deps.vault.addLoginUri(
          current.cipherId,
          submitted.username,
          submitted.password,
          frameUrl,
          defaultStrategy,
          assertCurrent,
        );
      }
      if (current.action === 'update' && deps.vault.updateLoginPassword) {
        return deps.vault.updateLoginPassword(
          current.cipherId,
          submitted.password,
          frameUrl,
          defaultStrategy,
          assertCurrent,
        );
      }
      throw new Error('updateLoginPassword is not wired');
    }),
  };
  const router = createRouterWithContext({
    ...deps,
    auth,
    vault,
    settings,
    sessionGate,
    accountGate,
    autofillPolicyGate,
    enterprisePolicyGate,
    autofillIntents,
    pendingSaves,
    saveCaptureCoordinator,
    loadPendingSaveUserKey: loadUserKey,
    usernameStages,
    getSessionBindingId,
    keyboardGrants,
    getKeyboardTopDocument,
    getContentDocument,
    pageLoadFillDeduper,
    repromptAutofillGrants,
  });
  return {
    keyboardGrants,
    captureSessionLease: () => sessionGate.capture(),
    captureAccountLease: () => accountGate.capture(),
    repromptAutofillGrants,
    capturePolicyLease: () => captureAutofillAuthorizationPolicy(authorizationPolicyGates),
    handle(request: RequestMessage, context: RequestContext = EXTENSION_PAGE_CONTEXT) {
      return router.handle(bindTestRuntime(request, context), context);
    },
  };
}

function bindTestRuntime(request: RequestMessage, context: RequestContext): RequestMessage {
  if (context.kind !== 'content'
      || !RUNTIME_BOUND_AUTOFILL_REQUESTS.has(request.type)
      || Object.hasOwn(request, 'runtimeIncarnation')) return request;
  const bound = Object.create(
    Object.getPrototypeOf(request),
    Object.getOwnPropertyDescriptors(request),
  ) as RequestMessage;
  Object.defineProperty(bound, 'runtimeIncarnation', {
    configurable: true,
    enumerable: true,
    value: TEST_RUNTIME_INCARNATION,
    writable: true,
  });
  return bound;
}

function intentSettings(strategy: UriMatchStrategySetting = 0): RouterDeps['settings'] {
  return {
    getServerUrl: vi.fn(),
    saveServerUrl: vi.fn(),
    getDefaultUriMatchStrategy: vi.fn(async () => strategy),
    saveDefaultUriMatchStrategy: vi.fn(),
    getAutofillSettings: vi.fn(async () => DEFAULT_AUTOFILL_SETTINGS),
    saveAutofillSettings: vi.fn(),
    getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
    saveLockTimeout: vi.fn(),
    getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'),
    saveOnIdleAction: vi.fn(),
    getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'),
    saveClipboardClearSetting: vi.fn(),
  };
}

function clientEventsHarness(order: string[] = []) {
  const eventReceipt = Object.freeze({}) as never;
  const accountRemovalReceipt = Object.freeze({}) as never;
  const serverChangeReceipt = Object.freeze({}) as never;
  const clientEvents = {
    prepare: vi.fn(async () => { order.push('prepare'); return eventReceipt; }),
    commit: vi.fn(async () => { order.push('commit'); return { kind: 'enqueued' as const }; }),
    flushActive: vi.fn(async () => { order.push('flush'); }),
    captureAccountRemoval: vi.fn(async () => {
      order.push('capture-remove');
      return accountRemovalReceipt;
    }),
    completeAccountRemoval: vi.fn(async () => { order.push('complete-remove'); return true; }),
    captureServerChange: vi.fn(async () => {
      order.push('capture-server');
      return serverChangeReceipt;
    }),
    completeServerChange: vi.fn(async () => {
      order.push('complete-server');
      return { discarded: 1, failed: 0 };
    }),
  } satisfies NonNullable<RouterDeps['clientEvents']>;
  return { clientEvents, eventReceipt, accountRemovalReceipt, serverChangeReceipt };
}

function totpCopyHarness() {
  const ackId = '20000000-0000-4000-8000-000000000020';
  let assertCurrent: (() => void) | undefined;
  const autofillTotpCopies = {
    issueContent: vi.fn((_owner, _code: string, assertion: () => void) => {
      assertCurrent = assertion;
      return ackId;
    }),
    consumeContent: vi.fn(async () => ({ kind: 'copied' as const })),
    revokeAll: vi.fn(() => 0),
  } satisfies NonNullable<RouterDeps['autofillTotpCopies']>;
  return { ackId, autofillTotpCopies, getAssertCurrent: () => assertCurrent };
}

function intentId(response: Awaited<ReturnType<ReturnType<typeof createRouter>['handle']>>): string {
  const data = response.ok ? response.data : undefined;
  if (typeof data !== 'object' || data === null || !('intentId' in data) || typeof data.intentId !== 'string') {
    throw new Error('expected an autofill intent');
  }
  return data.intentId;
}

function keyboardGrantId(response: Awaited<ReturnType<ReturnType<typeof createRouter>['handle']>>): string {
  const data = response.ok ? response.data : undefined;
  if (typeof data !== 'object' || data === null
      || !('keyboardGrantId' in data) || typeof data.keyboardGrantId !== 'string') {
    throw new Error('expected a keyboard grant');
  }
  return data.keyboardGrantId;
}

function promptId(response: Awaited<ReturnType<ReturnType<typeof createRouter>['handle']>>): string {
  const data = response.ok ? response.data : undefined;
  if (typeof data !== 'object' || data === null || !('promptId' in data) || typeof data.promptId !== 'string') {
    throw new Error('expected an autofill save prompt');
  }
  return data.promptId;
}

const DEVICE_LOGIN_BINDING = Object.freeze({
  version: 1 as const,
  requestId: 'f4b47b53-a174-4a40-bbd6-08b2bb6f9d34',
  publicKeyDigest: 'A'.repeat(43),
  requestDeviceIdentifier: 'request-device',
  creationDate: '2026-08-30T08:00:00.000Z',
  requestDeviceTypeValue: 2,
  nonce: 'B'.repeat(22),
  proof: 'C'.repeat(43),
});

const DEVICE_LOGIN_APPROVAL = Object.freeze({
  view: Object.freeze({
    id: DEVICE_LOGIN_BINDING.requestId,
    fingerprint: 'one-two-three-four-five',
    requestDeviceType: 'Chrome',
    requestDeviceTypeValue: 2,
    requestDeviceIdentifier: 'request-device',
    creationDate: DEVICE_LOGIN_BINDING.creationDate,
    creationTime: Date.parse(DEVICE_LOGIN_BINDING.creationDate),
    expiresAt: Date.parse(DEVICE_LOGIN_BINDING.creationDate) + 900_000,
  }),
  decisionBinding: DEVICE_LOGIN_BINDING,
});

describe('router', () => {
  it('routes password hints only from an exact Popup document without session activity', async () => {
    const requestPasswordHint = vi.fn(async () => ({ status: 'sent' as const }));
    const captureActivity = vi.fn(() => ({} as never));
    const recordActivity = vi.fn(async () => {});
    const captureSession = vi.fn(() => ({ generation: 0 }));
    const router = createRouter({
      auth: { requestPasswordHint }, vault: {}, settings: intentSettings(),
      vaultTimeout: { captureActivity, recordActivity },
      sessionGate: { capture: captureSession, assert: vi.fn() },
    });
    const request = {
      type: 'auth.requestPasswordHint', email: '  USER@Example.COM  ',
    } satisfies RequestMessage;
    const withoutDocument: RequestContext = {
      kind: 'extensionPage', url: EXTENSION_PAGE_CONTEXT.url,
      origin: EXTENSION_PAGE_CONTEXT.origin,
    };

    for (const context of [OPTIONS_PAGE_CONTEXT, CONTENT_CONTEXT, withoutDocument]) {
      await expect(router.handle(request, context)).resolves.toEqual({
        ok: false, error: { code: 'denied', message: 'sender not permitted' },
      });
    }
    await expect(router.handle({
      ...request, accountExists: true,
    } as unknown as RequestMessage)).resolves.toMatchObject({
      ok: false, error: { code: 'denied' },
    });
    expect(requestPasswordHint).not.toHaveBeenCalled();

    await expect(router.handle(request)).resolves.toEqual({
      ok: true, data: { status: 'sent' },
    });
    expect(requestPasswordHint).toHaveBeenCalledWith('  USER@Example.COM  ');
    expect(captureActivity).not.toHaveBeenCalled();
    expect(recordActivity).not.toHaveBeenCalled();
    expect(captureSession).not.toHaveBeenCalled();
  });

  it('routes only an exact Popup favorite command and records successful vault activity', async () => {
    const listing = {
      items: [], folders: [], collections: [], orgPermissions: [], personalCreationAllowed: true,
    };
    const setCipherFavorite = vi.fn(async () => listing);
    const captureActivity = vi.fn(() => ({} as never));
    const recordActivity = vi.fn(async () => {});
    const router = createRouter({
      auth: {},
      vault: { setCipherFavorite },
      settings: intentSettings(),
      vaultTimeout: { captureActivity, recordActivity },
    });
    const request = {
      type: 'vault.setCipherFavorite', id: 'cipher-1', favorite: true,
    } satisfies RequestMessage;
    const withoutDocument: RequestContext = {
      kind: 'extensionPage', url: EXTENSION_PAGE_CONTEXT.url,
      origin: EXTENSION_PAGE_CONTEXT.origin,
    };

    for (const context of [OPTIONS_PAGE_CONTEXT, CONTENT_CONTEXT, withoutDocument]) {
      await expect(router.handle(request, context)).resolves.toEqual({
        ok: false, error: { code: 'denied', message: 'sender not permitted' },
      });
    }
    await expect(router.handle({
      ...request, folderId: 'must-not-cross-protocol',
    } as unknown as RequestMessage)).resolves.toEqual({
      ok: false, error: { code: 'denied', message: 'Invalid cipher favorite request.' },
    });
    expect(setCipherFavorite).not.toHaveBeenCalled();
    expect(captureActivity).not.toHaveBeenCalled();

    await expect(router.handle(request)).resolves.toEqual({ ok: true, data: listing });
    expect(setCipherFavorite).toHaveBeenCalledWith('cipher-1', true);
    expect(captureActivity).toHaveBeenCalledOnce();
    expect(recordActivity).toHaveBeenCalledOnce();
  });

  it('withholds a favorite response when its session lease becomes stale', async () => {
    const lease = { generation: 1 } as SessionLease;
    let current = true;
    const setCipherFavorite = vi.fn(async () => {
      current = false;
      return { items: [], folders: [], collections: [], orgPermissions: [] };
    });
    const router = createRouter({
      auth: {},
      vault: { setCipherFavorite },
      settings: intentSettings(),
      sessionGate: {
        capture: vi.fn(() => lease),
        assert: vi.fn(() => {
          if (!current) throw new AppError('locked', 'Favorite session is stale');
        }),
      },
    });

    await expect(router.handle({
      type: 'vault.setCipherFavorite', id: 'cipher-1', favorite: true,
    })).resolves.toEqual({
      ok: false, error: { code: 'locked', message: 'Favorite session is stale' },
    });
    expect(setCipherFavorite).toHaveBeenCalledOnce();
  });

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

  it('returns a structured error for an unknown message type instead of resolving undefined', async () => {
    const router = createRouter({
      auth: {}, vault: {},
      settings: {
        getServerUrl: vi.fn(), saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0), saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'), saveLockTimeout: vi.fn(),
        getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(),
        getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    const response = await router.handle({ type: 'bogus.unknown' } as never);
    expect(response).toEqual({ ok: false, error: { code: 'error', message: expect.stringContaining('unknown message type') } });
  });

  it('dispatches encrypted generator history through the real worker service and final release fence', async () => {
    const values = new Map<string, unknown>();
    const store: AtomicKeyValueStore = {
      async get<T>(key: string): Promise<T | undefined> {
        const value = values.get(key);
        return value === undefined ? undefined : structuredClone(value) as T;
      },
      async set(key, value) { values.set(key, structuredClone(value)); },
      async setMany(entries) {
        for (const [key, value] of Object.entries(entries)) values.set(key, structuredClone(value));
      },
      async remove(key) { values.delete(key); },
      async clear() { values.clear(); },
    };
    const userKey = {
      encKey: new Uint8Array(32).fill(17),
      macKey: new Uint8Array(32).fill(29),
    };
    let authorityGeneration = 1;
    const history = new GeneratorHistoryProductionService({
      store,
      withCurrentAuthority: async (operation) => {
        const captured = authorityGeneration;
        const assertCurrent = (): void => {
          if (captured !== authorityGeneration) throw new AppError('locked', 'history authority changed');
        };
        return operation(Object.freeze({
          serverUrl: 'https://vault.example/',
          accountIdentity: 'user@example.com',
          userId: '11111111-1111-4111-8111-111111111111',
          policyRevision: 7,
          crypto: createUserKeyGeneratorHistoryCrypto(userKey),
          assertCurrent,
        }));
      },
      createIndexRevision: (() => {
        let revision = 0;
        return () => `00000000-0000-4000-8000-${(++revision).toString(16).padStart(12, '0')}`;
      })(),
    });
    const checkpoint = vi.fn(async () => ({} as never));
    const release = {
      capture: vi.fn(() => ({} as never)),
      checkpoint,
      assertAuthorities: vi.fn((_proof, assertCurrent: () => void) => { assertCurrent(); }),
      assert: vi.fn(),
    } satisfies NonNullable<RouterDeps['vaultReleaseGate']>;
    const recordActivity = vi.fn(async () => {});
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      generatorHistory: history,
      vaultReleaseGate: release,
      vaultTimeout: {
        captureActivity: vi.fn(() => ({} as never)),
        recordActivity,
      },
    });
    const generated = 'secret-from-generator';

    await expect(router.handle({
      type: 'generator.history.track',
      entry: { value: generated, type: 'password', policyRevision: 7 },
    })).resolves.toEqual({ ok: true, data: { added: true } });
    expect(JSON.stringify([...values.values()])).not.toContain(generated);
    expect(recordActivity).not.toHaveBeenCalled();

    await expect(router.handle({ type: 'generator.history.list' })).resolves.toMatchObject({
      ok: true,
      data: { entries: [{ value: generated, type: 'password' }] },
    });
    expect(release.capture).toHaveBeenCalledOnce();
    expect(release.checkpoint).toHaveBeenCalledOnce();
    expect(release.assertAuthorities).toHaveBeenCalledOnce();
    expect(release.assert).toHaveBeenCalledOnce();
    expect(recordActivity).toHaveBeenCalledOnce();

    checkpoint.mockImplementationOnce(async () => {
      authorityGeneration += 1;
      return {} as never;
    });
    const withheld = await router.handle({ type: 'generator.history.list' });
    expect(withheld).toMatchObject({ ok: false, error: { code: 'locked' } });
    expect(JSON.stringify(withheld)).not.toContain(generated);

    await expect(router.handle({ type: 'generator.history.clear' })).resolves.toEqual({
      ok: true, data: { cleared: true },
    });
    await expect(router.handle({ type: 'generator.history.list' })).resolves.toEqual({
      ok: true, data: { entries: [] },
    });
  });

  it('admits exact generator history commands only from a Popup document', async () => {
    const list = vi.fn(async () => ({ entries: [] }));
    const track = vi.fn(async () => ({ added: true }));
    const clear = vi.fn(async () => ({ cleared: true }));
    const router = createRouter({
      auth: {}, vault: {}, settings: intentSettings(), generatorHistory: { list, track, clear },
    });
    const withoutDocument: RequestContext = {
      kind: 'extensionPage',
      url: EXTENSION_PAGE_CONTEXT.url,
      origin: EXTENSION_PAGE_CONTEXT.origin,
    };
    const requests = [
      { type: 'generator.history.list' },
      {
        type: 'generator.history.track',
        entry: { value: 'secret', type: 'pin', policyRevision: 7 },
      },
      { type: 'generator.history.clear' },
    ] satisfies RequestMessage[];

    for (const request of requests) {
      for (const context of [OPTIONS_PAGE_CONTEXT, CONTENT_CONTEXT, withoutDocument]) {
        await expect(router.handle(request, context)).resolves.toEqual({
          ok: false, error: { code: 'denied', message: 'sender not permitted' },
        });
      }
    }
    await expect(router.handle({
      type: 'generator.history.list', extra: true,
    } as unknown as RequestMessage)).resolves.toMatchObject({
      ok: false, error: { code: 'denied' },
    });
    expect(list).not.toHaveBeenCalled();
    expect(track).not.toHaveBeenCalled();
    expect(clear).not.toHaveBeenCalled();
  });

  it('centrally denies vault work while restricted but still allows logout', async () => {
    const requirement = {
      schemaVersion: 1 as const,
      reason: 'adminForcePasswordReset' as const,
    };
    const sync = vi.fn(async () => ({
      items: [],
      folders: [],
      collections: [],
      orgPermissions: [],
    }));
    const logout = vi.fn(async () => {});
    const router = createRouter({
      auth: {
        getState: vi.fn(async (): Promise<SessionState> => 'restricted'),
        getPasswordChangeRequirement: vi.fn(async () => requirement),
        logout,
      },
      vault: { sync },
      settings: intentSettings(),
    });

    await expect(router.handle({ type: 'auth.getState' })).resolves.toEqual({
      ok: true,
      data: { state: 'restricted', restriction: requirement },
    });
    await expect(router.handle({ type: 'vault.sync' })).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    expect(sync).not.toHaveBeenCalled();
    await expect(router.handle({ type: 'auth.logout' })).resolves.toEqual({
      ok: true,
      data: null,
    });
    expect(logout).toHaveBeenCalledOnce();
  });

  it.each(['vault.export', 'vault.import'])('has no ordinary-message route for legacy transfer verb %s', async (type) => {
    const router = createRouter({
      auth: {}, vault: {},
      settings: {
        getServerUrl: vi.fn(), saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0), saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'), saveLockTimeout: vi.fn(),
        getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(),
        getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });

    await expect(router.handle({ type } as never)).resolves.toEqual({
      ok: false,
      error: { code: 'error', message: `unknown message type: ${type}` },
    });
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
      .resolves.toEqual({ ok: true, data: { serverUrl: 'https://vault.example.com', defaultUriMatchStrategy: 0, lockTimeout: '15', onIdleAction: 'lock', clipboardClearSeconds: '60', ...DEFAULT_AUTOFILL_SETTINGS_VIEW } });
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
      .resolves.toEqual({ ok: true, data: { defaultUriMatchStrategy: 0, lockTimeout: '15', onIdleAction: 'lock', clipboardClearSeconds: '60', ...DEFAULT_AUTOFILL_SETTINGS_VIEW } });
  });

  it('reads settings.get storage values concurrently', async () => {
    let started = 0;
    let unblock!: () => void;
    const barrier = new Promise<void>((resolve) => { unblock = resolve; });
    // Each getter blocks on a shared barrier that only releases once all six have started. Sequential
    // awaits would deadlock (the first getter never resolves); a single Promise.all fires all six.
    const gated = <T>(value: T): (() => Promise<T>) => vi.fn(async () => {
      started += 1;
      if (started === 6) unblock();
      await barrier;
      return value;
    });
    const router = createRouter({
      auth: {},
      vault: {},
      settings: {
        getServerUrl: gated<string | undefined>('https://vault.example.com'),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: gated<UriMatchStrategySetting>(0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: gated<LockTimeoutSetting>('15'),
        saveLockTimeout: vi.fn(),
        getOnIdleAction: gated<OnIdleAction>('lock'),
        saveOnIdleAction: vi.fn(),
        getClipboardClearSetting: gated<ClipboardClearSetting>('60'),
        saveClipboardClearSetting: vi.fn(),
        getWebsitePasskeySettings: gated<WebsitePasskeySettings>({
          schemaVersion: WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION,
          enabled: false,
          excludedDomains: [],
        }),
      },
    });
    await expect(router.handle({ type: 'settings.get' })).resolves.toEqual({
      ok: true,
      data: { serverUrl: 'https://vault.example.com', defaultUriMatchStrategy: 0, lockTimeout: '15', onIdleAction: 'lock', clipboardClearSeconds: '60', ...DEFAULT_AUTOFILL_SETTINGS_VIEW },
    });
    expect(started).toBe(6);
  }, 2000);

  it('returns validated website passkey settings and fails closed on a corrupt record', async () => {
    const settings = intentSettings();
    settings.getWebsitePasskeySettings = vi.fn(async () => ({
      schemaVersion: WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION,
      enabled: true,
      excludedDomains: ['accounts.example.com'],
    }));
    const router = createRouter({ auth: {}, vault: {}, settings });

    await expect(router.handle({ type: 'settings.get' })).resolves.toMatchObject({
      ok: true,
      data: {
        websitePasskeys: {
          enabled: true,
          excludedDomains: ['accounts.example.com'],
          valid: true,
        },
      },
    });

    const corruptSettings = intentSettings();
    corruptSettings.getWebsitePasskeySettings = vi.fn(async () => {
      throw new Error('Invalid website passkey settings');
    });
    const corruptRouter = createRouter({ auth: {}, vault: {}, settings: corruptSettings });
    await expect(corruptRouter.handle({ type: 'settings.get' })).resolves.toMatchObject({
      ok: true,
      data: { websitePasskeys: { enabled: false, excludedDomains: [], valid: false } },
    });
  });

  it('keeps the runtime response pending while a synchronous timeout preflight action settles', async () => {
    let releaseAction!: () => void;
    const action = new Promise<void>((resolve) => { releaseAction = resolve; });
    const settlePendingAction = vi.fn(() => action);
    const suppressApprovalNotifications = vi.fn(async () => undefined);
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      vaultTimeout: {
        captureActivity: vi.fn(() => { throw new AppError('locked', 'Vault session timed out'); }),
        recordActivity: vi.fn(async () => undefined),
        settlePendingAction,
      },
      onDeviceLoginApprovalPopupOpened: suppressApprovalNotifications,
    });

    const response = router.handle({ type: 'vault.popupOpened' });
    expect(suppressApprovalNotifications).toHaveBeenCalledOnce();
    await vi.waitFor(() => expect(settlePendingAction).toHaveBeenCalledOnce());
    let completed = false;
    void response.finally(() => { completed = true; });
    await Promise.resolve();
    expect(completed).toBe(false);

    releaseAction();
    await expect(response).resolves.toEqual({
      ok: false,
      error: { code: 'locked', message: 'Vault session timed out' },
    });
  });

  it('saves one complete canonical website passkey policy from extension pages', async () => {
    const saveWebsitePasskeySettings = vi.fn(async () => {});
    const settings = intentSettings();
    settings.saveWebsitePasskeySettings = saveWebsitePasskeySettings;
    const router = createRouter({ auth: {}, vault: {}, settings });

    await expect(router.handle({
      type: 'settings.saveWebsitePasskeys',
      enabled: true,
      excludedDomains: ['EXAMPLE.com.', 'example.com', 'login.example.org'],
    })).resolves.toEqual({ ok: true, data: null });
    expect(saveWebsitePasskeySettings).toHaveBeenCalledWith({
      schemaVersion: WEBSITE_PASSKEY_SETTINGS_SCHEMA_VERSION,
      enabled: true,
      excludedDomains: ['example.com', 'login.example.org'],
    });
  });

  it('rejects content, partial, wider, and invalid website passkey setting writes', async () => {
    const saveWebsitePasskeySettings = vi.fn(async () => {});
    const settings = intentSettings();
    settings.saveWebsitePasskeySettings = saveWebsitePasskeySettings;
    const router = createRouter({ auth: {}, vault: {}, settings });
    const valid = {
      type: 'settings.saveWebsitePasskeys' as const,
      enabled: true,
      excludedDomains: ['example.com'],
    };

    await expect(router.handle(valid, CONTENT_CONTEXT)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied', message: 'sender not permitted' },
    });
    for (const request of [
      { type: 'settings.saveWebsitePasskeys', enabled: true },
      { ...valid, injected: true },
      { ...valid, excludedDomains: ['https://example.com/login'] },
    ]) {
      await expect(router.handle(request as never)).resolves.toEqual({
        ok: false,
        error: { code: 'error', message: 'Invalid website passkey settings' },
      });
    }
    expect(saveWebsitePasskeySettings).not.toHaveBeenCalled();
  });

  it('returns a fixed error when website passkey persistence is not wired', async () => {
    const router = createRouter({ auth: {}, vault: {}, settings: intentSettings() });
    await expect(router.handle({
      type: 'settings.saveWebsitePasskeys',
      enabled: false,
      excludedDomains: [],
    })).resolves.toEqual({
      ok: false,
      error: { code: 'error', message: 'settings.saveWebsitePasskeySettings is not wired' },
    });
  });

  it('returns the independent HTTP auth policy and fails closed on corrupt storage', async () => {
    const settings = intentSettings();
    const httpAuthSettings = {
      get: vi.fn(async () => ({
        valid: true,
        settings: {
          schemaVersion: HTTP_AUTH_SETTINGS_SCHEMA_VERSION,
          enabled: true,
          allowedOrigins: ['https://intranet.example'],
        },
      })),
      save: vi.fn(),
    };
    const router = createRouter({ auth: {}, vault: {}, settings, httpAuthSettings });
    await expect(router.handle({ type: 'settings.get' })).resolves.toMatchObject({
      ok: true,
      data: {
        httpAuth: {
          enabled: true,
          allowedOrigins: ['https://intranet.example'],
          valid: true,
        },
      },
    });

    httpAuthSettings.get.mockResolvedValueOnce({
      valid: false,
      settings: {
        schemaVersion: HTTP_AUTH_SETTINGS_SCHEMA_VERSION,
        enabled: false,
        allowedOrigins: [],
      },
    });
    await expect(router.handle({ type: 'settings.get' })).resolves.toMatchObject({
      ok: true,
      data: { httpAuth: { enabled: false, allowedOrigins: [], valid: false } },
    });
  });

  it('saves a canonical exact-origin HTTP auth authorization policy', async () => {
    const settings = intentSettings();
    const save = vi.fn(async () => undefined);
    const get = vi.fn(async () => ({
      valid: true,
      settings: {
        schemaVersion: HTTP_AUTH_SETTINGS_SCHEMA_VERSION,
        enabled: false,
        allowedOrigins: ['https://existing.example'],
      } satisfies HttpAuthSettings,
    }));
    const policyGate = new AutofillPolicyGate();
    const oldLease = policyGate.capture();
    const router = createRouter({
      auth: {},
      vault: {},
      settings,
      httpAuthSettings: { get, save },
      autofillPolicyGate: policyGate,
    });

    await expect(router.handle({
      type: 'settings.saveHttpAuth',
      enabled: true,
      allowedOrigins: [
        'HTTPS://NEW.example:443/',
        'https://existing.example',
        'https://new.example',
      ],
    })).resolves.toEqual({ ok: true, data: null });
    expect(save).toHaveBeenCalledWith({
      schemaVersion: HTTP_AUTH_SETTINGS_SCHEMA_VERSION,
      enabled: true,
      allowedOrigins: ['https://existing.example', 'https://new.example'],
    });
    expect(() => policyGate.assert(oldLease)).toThrow(/policy changed/i);
  });

  it('rejects content, partial, wider, and invalid HTTP auth setting writes', async () => {
    const save = vi.fn(async () => undefined);
    const router = createRouter({
      auth: {}, vault: {}, settings: intentSettings(),
      httpAuthSettings: {
        get: async () => ({
          valid: true,
          settings: {
            schemaVersion: HTTP_AUTH_SETTINGS_SCHEMA_VERSION,
            enabled: false,
            allowedOrigins: [],
          },
        }),
        save,
      },
    });
    const valid = {
      type: 'settings.saveHttpAuth' as const,
      enabled: true,
      allowedOrigins: ['https://intranet.example'],
    };
    await expect(router.handle(valid, CONTENT_CONTEXT)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    for (const request of [
      { type: 'settings.saveHttpAuth', enabled: true },
      { ...valid, injected: true },
      { ...valid, allowedOrigins: ['http://remote.example'] },
    ]) {
      await expect(router.handle(request as never)).resolves.toMatchObject({ ok: false });
    }
    expect(save).not.toHaveBeenCalled();
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

  it('saves the display-only toolbar match counter without rewriting autofill policy', async () => {
    const saveShowMatchingLoginCount = vi.fn(async () => undefined);
    const saveAutofillPolicySettings = vi.fn(async () => undefined);
    const router = createRouter({
      auth: {},
      vault: {},
      settings: {
        ...intentSettings(),
        saveShowMatchingLoginCount,
        saveAutofillPolicySettings,
      },
    });

    await expect(router.handle({
      type: 'settings.save',
      showMatchingLoginCount: false,
    })).resolves.toEqual({ ok: true, data: null });
    expect(saveShowMatchingLoginCount).toHaveBeenCalledWith(false);
    expect(saveAutofillPolicySettings).not.toHaveBeenCalled();
  });

  it('resets authentication before saving a different server URL', async () => {
    const calls: string[] = [];
    const resetForServerChange = vi.fn(async (commitServerUrl?: () => Promise<void>) => {
      calls.push('reset');
      await commitServerUrl?.();
    });
    const saveServerUrl = vi.fn(async () => { calls.push('save'); });
    const router = createRouter({
      auth: { resetForServerChange },
      vault: {},
      settings: {
        getServerUrl: vi.fn(async () => 'https://old.example/'),
        saveServerUrl,
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });

    await expect(router.handle({ type: 'settings.save', serverUrl: 'https://new.example' }))
      .resolves.toEqual({ ok: true, data: null });
    expect(resetForServerChange).toHaveBeenCalledTimes(1);
    expect(calls).toEqual(['reset', 'save']);
  });

  it('captures, flushes, and discards old-server events around a successful server reset', async () => {
    const order: string[] = [];
    const events = clientEventsHarness(order);
    const settings = intentSettings();
    settings.getServerUrl = vi.fn(async () => 'https://old.example/');
    settings.saveServerUrl = vi.fn(async () => { order.push('save'); });
    const resetForServerChange = vi.fn(async (commit?: () => Promise<void>) => {
      order.push('reset');
      await commit?.();
    });
    const router = createRouter({
      auth: { resetForServerChange }, vault: {}, settings, clientEvents: events.clientEvents,
    });

    await expect(router.handle({ type: 'settings.save', serverUrl: 'https://new.example/' }))
      .resolves.toEqual({ ok: true, data: null });
    expect(order).toEqual(['capture-server', 'flush', 'reset', 'save', 'complete-server']);
    expect(events.clientEvents.captureServerChange).toHaveBeenCalledWith('https://old.example/');
    expect(events.clientEvents.completeServerChange).toHaveBeenCalledWith(events.serverChangeReceipt);
  });

  it('retains old-server event state when the server reset fails', async () => {
    const events = clientEventsHarness();
    const settings = intentSettings();
    settings.getServerUrl = vi.fn(async () => 'https://old.example/');
    const router = createRouter({
      auth: { resetForServerChange: vi.fn(async () => { throw new Error('reset failed'); }) },
      vault: {}, settings, clientEvents: events.clientEvents,
    });

    await expect(router.handle({ type: 'settings.save', serverUrl: 'https://new.example/' }))
      .resolves.toMatchObject({ ok: false, error: { message: 'reset failed' } });
    expect(events.clientEvents.completeServerChange).not.toHaveBeenCalled();
  });

  it('keeps server reset successful when event lifecycle operations fail', async () => {
    const events = clientEventsHarness();
    events.clientEvents.captureServerChange.mockRejectedValue(new Error('directory unavailable'));
    events.clientEvents.flushActive.mockRejectedValue(new Error('upload unavailable'));
    const settings = intentSettings();
    settings.getServerUrl = vi.fn(async () => 'https://old.example/');
    const resetForServerChange = vi.fn(async (commit?: () => Promise<void>) => commit?.());
    const router = createRouter({
      auth: { resetForServerChange }, vault: {}, settings, clientEvents: events.clientEvents,
    });

    await expect(router.handle({ type: 'settings.save', serverUrl: 'https://new.example/' }))
      .resolves.toEqual({ ok: true, data: null });
    expect(resetForServerChange).toHaveBeenCalledOnce();
    expect(events.clientEvents.completeServerChange).not.toHaveBeenCalled();
  });

  it('does not change a committed server reset when old-scope cleanup fails', async () => {
    const events = clientEventsHarness();
    events.clientEvents.completeServerChange.mockRejectedValue(new Error('cleanup unavailable'));
    const settings = intentSettings();
    settings.getServerUrl = vi.fn(async () => 'https://old.example/');
    const resetForServerChange = vi.fn(async (commit?: () => Promise<void>) => commit?.());
    const router = createRouter({
      auth: { resetForServerChange }, vault: {}, settings, clientEvents: events.clientEvents,
    });

    await expect(router.handle({ type: 'settings.save', serverUrl: 'https://new.example/' }))
      .resolves.toEqual({ ok: true, data: null });
    expect(events.clientEvents.completeServerChange).toHaveBeenCalledWith(events.serverChangeReceipt);
  });

  it('completes a late old-server capture after the server reset succeeds', async () => {
    vi.useFakeTimers();
    try {
      const events = clientEventsHarness();
      let resolveCapture!: (receipt: typeof events.serverChangeReceipt) => void;
      const pendingCapture = new Promise<typeof events.serverChangeReceipt>((resolve) => {
        resolveCapture = resolve;
      });
      events.clientEvents.captureServerChange.mockImplementation(() => pendingCapture);
      const settings = intentSettings();
      settings.getServerUrl = vi.fn(async () => 'https://old.example/');
      const resetForServerChange = vi.fn(async (commit?: () => Promise<void>) => commit?.());
      const router = createRouter({
        auth: { resetForServerChange }, vault: {}, settings,
        clientEvents: events.clientEvents,
      });
      const response = router.handle({ type: 'settings.save', serverUrl: 'https://new.example/' });

      await vi.advanceTimersByTimeAsync(CLIENT_EVENT_BEST_EFFORT_WAIT_MS);
      await vi.waitFor(() => expect(resetForServerChange).toHaveBeenCalledOnce());
      resolveCapture(events.serverChangeReceipt);
      await vi.advanceTimersByTimeAsync(0);

      await expect(response).resolves.toEqual({ ok: true, data: null });
      expect(events.clientEvents.completeServerChange).toHaveBeenCalledWith(events.serverChangeReceipt);
    } finally {
      vi.useRealTimers();
    }
  });

  it('runs first-server configuration through the same transition callback', async () => {
    const resetForServerChange = vi.fn(async (commitServerUrl?: () => Promise<void>) => {
      await commitServerUrl?.();
    });
    const saveServerUrl = vi.fn(async () => {});
    const router = createRouter({
      auth: { resetForServerChange },
      vault: {},
      settings: {
        getServerUrl: vi.fn(async () => undefined),
        saveServerUrl,
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });

    await expect(router.handle({ type: 'settings.save', serverUrl: 'https://first.example' }))
      .resolves.toEqual({ ok: true, data: null });
    expect(resetForServerChange).toHaveBeenCalledOnce();
    expect(saveServerUrl).toHaveBeenCalledWith('https://first.example');
  });

  it('keeps server saving inside the transition and surfaces a failed save', async () => {
    const calls: string[] = [];
    const resetForServerChange = vi.fn(async (commitServerUrl?: () => Promise<void>) => {
      calls.push('reset-start');
      await commitServerUrl?.();
      calls.push('reset-settled');
    });
    const saveServerUrl = vi.fn(async () => {
      calls.push('save');
      throw new Error('save failed');
    });
    const router = createRouter({
      auth: { resetForServerChange },
      vault: {},
      settings: {
        getServerUrl: vi.fn(async () => 'https://old.example/'),
        saveServerUrl,
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });

    await expect(router.handle({ type: 'settings.save', serverUrl: 'https://new.example' }))
      .resolves.toEqual({ ok: false, error: { code: 'error', message: 'save failed' } });
    expect(calls).toEqual(['reset-start', 'save']);
  });

  it('keeps authentication when saving an equivalent normalized server URL', async () => {
    const resetForServerChange = vi.fn(async () => {});
    const saveServerUrl = vi.fn(async () => {});
    const router = createRouter({
      auth: { resetForServerChange },
      vault: {},
      settings: {
        getServerUrl: vi.fn(async () => 'https://vault.example/'),
        saveServerUrl,
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });

    await router.handle({ type: 'settings.save', serverUrl: 'https://vault.example' });
    expect(resetForServerChange).not.toHaveBeenCalled();
    expect(saveServerUrl).toHaveBeenCalledWith('https://vault.example');
  });

  it('rejects an invalid server URL before resetting authentication', async () => {
    const resetForServerChange = vi.fn(async () => {});
    const saveServerUrl = vi.fn(async () => {});
    const router = createRouter({
      auth: { resetForServerChange },
      vault: {},
      settings: {
        getServerUrl: vi.fn(async () => 'https://vault.example/'),
        saveServerUrl,
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });

    await expect(router.handle({ type: 'settings.save', serverUrl: 'file:///tmp/not-a-server' }))
      .resolves.toMatchObject({ ok: false });
    expect(resetForServerChange).not.toHaveBeenCalled();
    expect(saveServerUrl).not.toHaveBeenCalled();
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
      .resolves.toEqual({ ok: true, data: { serverUrl: 'https://vault.example.com', defaultUriMatchStrategy: 0, lockTimeout: '15', onIdleAction: 'lock', clipboardClearSeconds: '60', ...DEFAULT_AUTOFILL_SETTINGS_VIEW } });
  });

  it('returns only sanitized enterprise capabilities and clamped effective timeout settings', async () => {
    const policy = enterprisePolicyControl({
      pinAllowed: false,
      timeout: {
        organizationId: 'secret-org-id',
        malformed: false,
        data: { type: 'custom', minutes: 10, action: 'logOut' },
      },
    });
    const settings = intentSettings();
    settings.getLockTimeout = vi.fn(async (): Promise<LockTimeoutSetting> => '30');
    const router = createRouter({ auth: {}, vault: {}, settings, enterprisePolicyGate: policy.gate });

    const response = await router.handle({ type: 'settings.get' });
    expect(response).toMatchObject({
      ok: true,
      data: {
        lockTimeout: '10',
        onIdleAction: 'logout',
        enterprisePolicy: { pinUnlockAllowed: false, maximumVaultTimeoutManaged: true, maximumVaultTimeoutMode: 'local' },
      },
    });
    expect(JSON.stringify(response)).not.toContain('secret-org-id');
  });

  it.each([
    {
      label: 'unmanaged Domain zero',
      local: UriMatchStrategy.Domain,
      policy: null,
      effective: UriMatchStrategy.Domain,
      managed: false,
      malformed: false,
    },
    {
      label: 'managed Domain zero',
      local: UriMatchStrategy.Never,
      policy: uriMatchDefaultsPolicy(UriMatchStrategy.Domain),
      effective: UriMatchStrategy.Domain,
      managed: true,
      malformed: false,
    },
    {
      label: 'malformed managed policy',
      local: UriMatchStrategy.Host,
      policy: uriMatchDefaultsPolicy(UriMatchStrategy.Never, true),
      effective: UriMatchStrategy.Never,
      managed: true,
      malformed: true,
    },
  ])('returns the effective URI match settings for $label', async ({
    local,
    policy: uriMatch,
    effective,
    managed,
    malformed,
  }) => {
    const enterprise = enterprisePolicyControl({ uriMatch });
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(local),
      enterprisePolicyGate: enterprise.gate,
    });

    await expect(router.handle({ type: 'settings.get' })).resolves.toMatchObject({
      ok: true,
      data: {
        defaultUriMatchStrategy: effective,
        enterprisePolicy: {
          uriMatchDefaultManaged: managed,
          uriMatchDefaultMalformed: malformed,
        },
      },
    });
  });

  it('keeps a managed URI default out of local storage while saving other autofill settings', async () => {
    let stored: AutofillPolicySettings = {
      schemaVersion: AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
      defaultUriMatchStrategy: UriMatchStrategy.Domain,
      pageLoadFillDefault: true,
      ...DEFAULT_AUTOFILL_SETTINGS,
    };
    const saveAutofillPolicySettings = vi.fn(async (next: AutofillPolicySettings) => {
      stored = next;
    });
    const settings = intentSettings(UriMatchStrategy.Domain);
    settings.getAutofillPolicySettings = vi.fn(async () => stored);
    settings.saveAutofillPolicySettings = saveAutofillPolicySettings;
    const enterprise = enterprisePolicyControl({
      uriMatch: uriMatchDefaultsPolicy(UriMatchStrategy.Exact),
    });
    const router = createRouter({
      auth: {},
      vault: {},
      settings,
      enterprisePolicyGate: enterprise.gate,
    });

    await expect(router.handle({
      type: 'settings.save',
      defaultUriMatchStrategy: UriMatchStrategy.Exact,
    })).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(saveAutofillPolicySettings).not.toHaveBeenCalled();

    const nextAutofill = {
      ...DEFAULT_AUTOFILL_SETTINGS,
      pageLoadFillDefault: true,
      inlineSuggestions: false,
      pageLoadFill: true,
      blockedDomains: ['blocked.example'],
    };
    await expect(router.handle({
      type: 'settings.save',
      autofillSettings: nextAutofill,
    })).resolves.toEqual({ ok: true, data: null });
    expect(saveAutofillPolicySettings).toHaveBeenCalledWith({
      schemaVersion: AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
      defaultUriMatchStrategy: UriMatchStrategy.Domain,
      ...nextAutofill,
    }, expect.any(Function));
    expect(stored.defaultUriMatchStrategy).toBe(UriMatchStrategy.Domain);
  });

  it('forces page-load autofill while preserving the raw local toggle under type 11', async () => {
    let stored: AutofillPolicySettings = {
      schemaVersion: AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
      defaultUriMatchStrategy: UriMatchStrategy.Domain,
      pageLoadFillDefault: true,
      ...DEFAULT_AUTOFILL_SETTINGS,
      pageLoadFill: false,
    };
    const settings = intentSettings();
    settings.getAutofillPolicySettings = vi.fn(async () => stored);
    settings.saveAutofillPolicySettings = vi.fn(async (next, assertCurrent) => {
      assertCurrent?.();
      stored = next;
      assertCurrent?.();
    });
    const enterprise = enterprisePolicyControl({ activateAutofill: true });
    const router = createRouter({ auth: {}, vault: {}, settings, enterprisePolicyGate: enterprise.gate });

    await expect(router.handle({ type: 'autofill.getClientConfig' }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: true, data: { pageLoadFill: true } });
    await expect(router.handle({ type: 'settings.get' }, OPTIONS_PAGE_CONTEXT)).resolves.toMatchObject({
      ok: true,
      data: {
        pageLoadFill: false,
        pageLoadFillDefault: true,
        enterprisePolicy: { activateAutofillManaged: true },
      },
    });

    await expect(router.handle({
      type: 'settings.save',
      autofillSettings: {
        ...DEFAULT_AUTOFILL_SETTINGS,
        pageLoadFill: true,
        pageLoadFillDefault: false,
      },
    }, OPTIONS_PAGE_CONTEXT)).resolves.toEqual({ ok: true, data: null });
    expect(stored.pageLoadFill).toBe(false);
    expect(stored.pageLoadFillDefault).toBe(false);
  });

  it('rolls back a local page-load write when type 11 activates during the guarded save', async () => {
    let stored: AutofillPolicySettings = {
      schemaVersion: AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
      defaultUriMatchStrategy: UriMatchStrategy.Domain,
      pageLoadFillDefault: true,
      ...DEFAULT_AUTOFILL_SETTINGS,
      pageLoadFill: false,
    };
    const enterprise = enterprisePolicyControl({ activateAutofill: false });
    const settings = intentSettings();
    settings.getAutofillPolicySettings = vi.fn(async () => stored);
    settings.saveAutofillPolicySettings = vi.fn(async (next, assertCurrent) => {
      const previous = stored;
      assertCurrent?.();
      stored = next;
      enterprise.replaceActivateAutofill(true);
      try {
        assertCurrent?.();
      } catch (error) {
        stored = previous;
        throw error;
      }
    });
    const router = createRouter({ auth: {}, vault: {}, settings, enterprisePolicyGate: enterprise.gate });

    await expect(router.handle({
      type: 'settings.save',
      autofillSettings: {
        ...DEFAULT_AUTOFILL_SETTINGS,
        pageLoadFill: true,
        pageLoadFillDefault: false,
      },
    }, OPTIONS_PAGE_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(stored.pageLoadFill).toBe(false);
    expect(stored.pageLoadFillDefault).toBe(true);
  });

  it('authorizes generated-password use only for the current bounded policy revision', async () => {
    const enterprise = enterprisePolicyControl();
    const issue = vi.fn(() => '40000000-0000-4000-8000-000000000001');
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      enterprisePolicyGate: enterprise.gate,
      inlineGeneratorTracks: {
        issue,
        consume: vi.fn(async () => ({ kind: 'tracked', added: true } as const)),
        revokeAll: vi.fn(() => 0),
      },
    });

    await expect(router.handle({
      type: 'autofill.authorizeGeneratorUse',
      revision: 0,
      options: INLINE_GENERATOR_OPTIONS,
    }, CONTENT_CONTEXT)).resolves.toEqual({
      ok: true,
      data: { trackToken: '40000000-0000-4000-8000-000000000001' },
    });
    expect(issue).toHaveBeenLastCalledWith({
      tabId: CONTENT_CONTEXT.tabId,
      frameId: CONTENT_CONTEXT.frameId,
      documentId: CONTENT_CONTEXT.documentId,
      url: CONTENT_CONTEXT.url,
    }, createGeneratorPolicySnapshot(null, 0), INLINE_GENERATOR_OPTIONS, expect.any(Function));

    enterprise.replaceGenerator(generatorPolicy({ minLength: 24, useSpecial: true }));
    await expect(router.handle({
      type: 'autofill.authorizeGeneratorUse',
      revision: 0,
      options: INLINE_GENERATOR_OPTIONS,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({
      type: 'autofill.authorizeGeneratorUse',
      revision: 1,
      options: INLINE_GENERATOR_OPTIONS,
    }, CONTENT_CONTEXT)).resolves.toEqual({
      ok: true,
      data: { trackToken: '40000000-0000-4000-8000-000000000001' },
    });

    enterprise.replaceGenerator(generatorPolicy({}, true));
    await expect(router.handle({
      type: 'autofill.authorizeGeneratorUse',
      revision: 2,
      options: INLINE_GENERATOR_OPTIONS,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
  });

  it('consumes a generated-value token using only the exact content document owner', async () => {
    const consume = vi.fn(async () => ({ kind: 'tracked', added: true } as const));
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      inlineGeneratorTracks: {
        issue: vi.fn(() => '40000000-0000-4000-8000-000000000001'),
        consume,
        revokeAll: vi.fn(() => 0),
      },
    });

    await expect(router.handle({
      type: 'autofill.trackGeneratedValue',
      token: '40000000-0000-4000-8000-000000000001',
      value: 'Abcdef2!ghij',
    }, CONTENT_CONTEXT)).resolves.toEqual({ ok: true, data: { added: true } });
    expect(consume).toHaveBeenCalledWith(
      '40000000-0000-4000-8000-000000000001',
      {
        tabId: CONTENT_CONTEXT.tabId,
        frameId: CONTENT_CONTEXT.frameId,
        documentId: CONTENT_CONTEXT.documentId,
        url: CONTENT_CONTEXT.url,
      },
      'Abcdef2!ghij',
    );
  });

  it('uses immediate logout settings when the enterprise snapshot is unavailable', async () => {
    const policy = enterprisePolicyControl({ available: false });
    const settings = intentSettings();
    settings.getLockTimeout = vi.fn(async (): Promise<LockTimeoutSetting> => 'never');
    const router = createRouter({ auth: {}, vault: {}, settings, enterprisePolicyGate: policy.gate });

    await expect(router.handle({ type: 'settings.get' })).resolves.toMatchObject({
      ok: true,
      data: {
        lockTimeout: '1',
        onIdleAction: 'logout',
        enterprisePolicy: { pinUnlockAllowed: false, maximumVaultTimeoutManaged: true, maximumVaultTimeoutMode: 'immediate' },
      },
    });
  });

  it('reports system-lock-only mode without fabricating a numeric timeout', async () => {
    const policy = enterprisePolicyControl({
      timeout: { organizationId: null, malformed: false, data: { type: 'onSystemLock', minutes: 0, action: 'lock' } },
    });
    const settings = intentSettings();
    settings.getLockTimeout = vi.fn(async (): Promise<LockTimeoutSetting> => 'onClose');
    const router = createRouter({ auth: {}, vault: {}, settings, enterprisePolicyGate: policy.gate });

    await expect(router.handle({ type: 'settings.get' })).resolves.toMatchObject({
      ok: true,
      data: {
        lockTimeout: 'onClose',
        enterprisePolicy: { maximumVaultTimeoutManaged: true, maximumVaultTimeoutMode: 'systemLock' },
      },
    });
  });

  it('rejects a timeout wider than the enterprise maximum without persisting it', async () => {
    const policy = enterprisePolicyControl({
      timeout: { organizationId: null, malformed: false, data: { type: 'custom', minutes: 10, action: 'lock' } },
    });
    const settings = intentSettings();
    const router = createRouter({ auth: {}, vault: {}, settings, enterprisePolicyGate: policy.gate });

    await expect(router.handle({ type: 'settings.save', lockTimeout: '15' })).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    expect(settings.saveLockTimeout).not.toHaveBeenCalled();
  });

  it('rejects a weaker timeout action and a stale policy lease', async () => {
    const policy = enterprisePolicyControl({
      timeout: { organizationId: null, malformed: false, data: { type: 'custom', minutes: 30, action: 'logOut' } },
    });
    const settings = intentSettings();
    let staleOnRead = false;
    settings.getLockTimeout = vi.fn(async (): Promise<LockTimeoutSetting> => {
      if (staleOnRead) policy.invalidate();
      return '15';
    });
    settings.getOnIdleAction = vi.fn(async (): Promise<OnIdleAction> => {
      if (staleOnRead) policy.invalidate();
      return 'logout';
    });
    const router = createRouter({ auth: {}, vault: {}, settings, enterprisePolicyGate: policy.gate });

    await expect(router.handle({ type: 'settings.saveSecurity', onIdleAction: 'lock', clipboardClearSeconds: '60' }))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    staleOnRead = true;
    await expect(router.handle({ type: 'settings.save', lockTimeout: '5' }))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(settings.saveOnIdleAction).not.toHaveBeenCalled();
    expect(settings.saveLockTimeout).not.toHaveBeenCalled();
  });

  it('returns an atomic PIN status from AuthService', async () => {
    const router = createRouter({
      auth: { getPinStatus: vi.fn(async () => ({
        enabled: false,
        available: false,
        allowed: false,
        requireMasterPasswordOnRestart: true,
      })) },
      vault: {},
      settings: intentSettings(),
    });

    await expect(router.handle({ type: 'auth.pinStatus' })).resolves.toEqual({
      ok: true,
      data: {
        enabled: false,
        available: false,
        allowed: false,
        requireMasterPasswordOnRestart: true,
      },
    });
  });

  it('forwards the explicit browser-restart policy when setting a PIN', async () => {
    const setPin = vi.fn(async () => {});
    const router = createRouter({
      auth: { setPin },
      vault: {},
      settings: intentSettings(),
    });

    await expect(router.handle({
      type: 'auth.setPin',
      pin: 'word pin',
      requireMasterPasswordOnRestart: false,
    })).resolves.toEqual({ ok: true, data: null });
    expect(setPin).toHaveBeenCalledWith('word pin', false);
  });

  it.each([
    ['auth.setPin', 'abc'],
    ['auth.setPin', 'a'.repeat(MAX_PIN_UTF16_CODE_UNITS + 1)],
    ['auth.unlockWithPin', 'abc'],
    ['auth.unlockWithPin', 'a'.repeat(MAX_PIN_UTF16_CODE_UNITS + 1)],
  ] as const)('rejects invalid PIN input before invoking %s', async (type, pin) => {
    const setPin = vi.fn(async () => {});
    const unlockWithPin = vi.fn(async () => {});
    const router = createRouter({
      auth: { setPin, unlockWithPin },
      vault: {},
      settings: intentSettings(),
    });
    const request = type === 'auth.setPin'
      ? { type, pin, requireMasterPasswordOnRestart: true } as const
      : { type, pin } as const;

    await expect(router.handle(request)).resolves.toMatchObject({
      ok: false,
      error: { code: 'error' },
    });
    expect(setPin).not.toHaveBeenCalled();
    expect(unlockWithPin).not.toHaveBeenCalled();
  });

  it('issues an exact format-and-encryption-mode grant only after master-password verification', async () => {
    const verifyMasterPassword = vi.fn(async () => true);
    const issue = vi.fn(() => ({
      authorizationId: '33333333-3333-4333-8333-333333333333',
      expiresAt: 31_000,
    }));
    const policy = enterprisePolicyControl();
    const router = createRouter({
      auth: { verifyMasterPassword },
      vault: {},
      settings: intentSettings(),
      enterprisePolicyGate: policy.gate,
      exportGrants: { issue },
    });

    await expect(router.handle({
      type: 'vault.authorizeExport', format: 'encrypted-json', encryptionType: 'account',
      masterPassword: 'master-secret',
    }, OPTIONS_PAGE_CONTEXT)).resolves.toEqual({
      ok: true,
      data: {
        authorizationId: '33333333-3333-4333-8333-333333333333',
        expiresAt: 31_000,
      },
    });
    expect(verifyMasterPassword).toHaveBeenCalledWith('master-secret');
    expect(issue).toHaveBeenCalledWith(expect.objectContaining({
      format: 'encrypted-json', encryptionType: 'account', target: { kind: 'personal' },
    }));
  });

  it('binds an organization export grant to the canonical organization and rejects ZIP', async () => {
    const verifyMasterPassword = vi.fn(async () => true);
    const issue = vi.fn(() => ({
      authorizationId: '33333333-3333-4333-8333-333333333333',
      expiresAt: 31_000,
    }));
    const router = createRouter({
      auth: { verifyMasterPassword },
      vault: {},
      settings: intentSettings(),
      enterprisePolicyGate: enterprisePolicyControl().gate,
      exportGrants: { issue },
    });
    const organizationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

    await expect(router.handle({
      type: 'vault.authorizeExport',
      format: 'json',
      target: { kind: 'organization', organizationId: organizationId.toUpperCase() },
      masterPassword: 'master-secret',
    }, OPTIONS_PAGE_CONTEXT)).resolves.toMatchObject({ ok: true });
    expect(issue).toHaveBeenCalledWith(expect.objectContaining({
      format: 'json',
      target: { kind: 'organization', organizationId },
    }));

    issue.mockClear();
    verifyMasterPassword.mockClear();
    await expect(router.handle({
      type: 'vault.authorizeExport',
      format: 'zip',
      target: { kind: 'organization', organizationId },
      masterPassword: 'master-secret',
    }, OPTIONS_PAGE_CONTEXT)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    expect(verifyMasterPassword).not.toHaveBeenCalled();
    expect(issue).not.toHaveBeenCalled();
  });

  it('rejects missing or misplaced encrypted export modes before verification', async () => {
    const verifyMasterPassword = vi.fn(async () => true);
    const issue = vi.fn();
    const policy = enterprisePolicyControl();
    const router = createRouter({
      auth: { verifyMasterPassword },
      vault: {},
      settings: intentSettings(),
      enterprisePolicyGate: policy.gate,
      exportGrants: { issue },
    });

    await expect(router.handle({
      type: 'vault.authorizeExport', format: 'encrypted-json', masterPassword: 'secret',
    }, OPTIONS_PAGE_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({
      type: 'vault.authorizeExport', format: 'json', encryptionType: 'file', masterPassword: 'secret',
    }, OPTIONS_PAGE_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(verifyMasterPassword).not.toHaveBeenCalled();
    expect(issue).not.toHaveBeenCalled();
  });

  it('does not issue an export grant for a wrong password or a non-options sender', async () => {
    const verifyMasterPassword = vi.fn(async () => false);
    const issue = vi.fn();
    const policy = enterprisePolicyControl();
    const router = createRouter({
      auth: { verifyMasterPassword },
      vault: {},
      settings: intentSettings(),
      enterprisePolicyGate: policy.gate,
      exportGrants: { issue },
    });
    const request = {
      type: 'vault.authorizeExport' as const,
      format: 'json' as const,
      masterPassword: 'wrong-secret',
    };

    await expect(router.handle(request, OPTIONS_PAGE_CONTEXT)).resolves.toMatchObject({
      ok: false, error: { code: 'denied' },
    });
    await expect(router.handle(request, EXTENSION_PAGE_CONTEXT)).resolves.toMatchObject({
      ok: false, error: { code: 'denied' },
    });
    await expect(router.handle(request, CONTENT_CONTEXT)).resolves.toMatchObject({
      ok: false, error: { code: 'denied' },
    });
    expect(verifyMasterPassword).toHaveBeenCalledOnce();
    expect(issue).not.toHaveBeenCalled();
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

  it.each([
    {
      label: 'missing prompt controls',
      autofillSettings: {
        inlineSuggestions: true,
        pageLoadFill: false,
        blockedDomains: [],
      },
    },
    {
      label: 'unknown nested field',
      autofillSettings: {
        ...DEFAULT_AUTOFILL_SETTINGS,
        pageLoadFillDefault: true,
        unexpected: true,
      },
    },
  ])('rejects a runtime autofill snapshot with $label', async ({ autofillSettings }) => {
    const settings = intentSettings();
    const saveAutofillPolicySettings = vi.fn();
    settings.saveAutofillPolicySettings = saveAutofillPolicySettings;
    const router = createRouter({ auth: {}, vault: {}, settings });

    await expect(router.handle({
      type: 'settings.save',
      defaultUriMatchStrategy: 0,
      autofillSettings,
    } as unknown as RequestMessage)).resolves.toMatchObject({
      ok: false,
      error: { code: 'error', message: 'Invalid autofill settings' },
    });
    expect(saveAutofillPolicySettings).not.toHaveBeenCalled();
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

  it('flushes client events before logout and contains a failed flush', async () => {
    const order: string[] = [];
    const { clientEvents } = clientEventsHarness(order);
    clientEvents.flushActive.mockImplementation(async () => {
      order.push('flush');
      throw new Error('event upload failed');
    });
    const logout = vi.fn(async () => { order.push('logout'); });
    const router = createRouter({
      auth: { logout }, vault: {}, settings: intentSettings(), clientEvents,
    });

    await expect(router.handle({ type: 'auth.logout' })).resolves.toEqual({ ok: true, data: null });
    expect(order).toEqual(['flush', 'logout']);
  });

  it('does not enter a second logout transition when a repeated-401 flush already logged out', async () => {
    let state: SessionState = 'unlocked';
    const logout = vi.fn(async () => { state = 'loggedOut'; });
    const { clientEvents } = clientEventsHarness();
    clientEvents.flushActive.mockImplementation(async () => {
      state = 'loggedOut';
      throw new Error('second 401');
    });
    const router = createRouter({
      auth: { getState: vi.fn(async () => state), logout },
      vault: {}, settings: intentSettings(), clientEvents,
    });

    await expect(router.handle({ type: 'auth.logout' })).resolves.toEqual({ ok: true, data: null });
    expect(logout).not.toHaveBeenCalled();
  });

  it('does not let a hanging event flush block logout', async () => {
    vi.useFakeTimers();
    try {
      const { clientEvents } = clientEventsHarness();
      clientEvents.flushActive.mockImplementation(() => new Promise(() => {}));
      const logout = vi.fn(async () => {});
      const router = createRouter({
        auth: { logout }, vault: {}, settings: intentSettings(), clientEvents,
      });
      const response = router.handle({ type: 'auth.logout' });

      await vi.advanceTimersByTimeAsync(CLIENT_EVENT_BEST_EFFORT_WAIT_MS);
      await expect(response).resolves.toEqual({ ok: true, data: null });
      expect(logout).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });

  it('flushes before switching accounts without changing the switch result on event failure', async () => {
    const order: string[] = [];
    const { clientEvents } = clientEventsHarness(order);
    clientEvents.flushActive.mockImplementation(async () => {
      order.push('flush');
      throw new Error('event upload failed');
    });
    const switchAccount = vi.fn(async () => { order.push('switch'); });
    const router = createRouter({
      auth: { switchAccount }, vault: {}, settings: intentSettings(), clientEvents,
    });

    await expect(router.handle({ type: 'auth.switchAccount', email: 'next@example.com' }))
      .resolves.toEqual({ ok: true, data: null });
    expect(order).toEqual(['flush', 'switch']);
  });

  it('completes exact event cleanup only after account removal succeeds', async () => {
    const successOrder: string[] = [];
    const successEvents = clientEventsHarness(successOrder);
    const removeAccount = vi.fn(async () => { successOrder.push('remove'); });
    const success = createRouter({
      auth: { removeAccount }, vault: {}, settings: intentSettings(),
      clientEvents: successEvents.clientEvents,
    });

    await expect(success.handle({ type: 'auth.removeAccount', email: 'old@example.com' }))
      .resolves.toEqual({ ok: true, data: null });
    expect(successOrder).toEqual(['capture-remove', 'flush', 'remove', 'complete-remove']);
    expect(successEvents.clientEvents.captureAccountRemoval).toHaveBeenCalledWith('old@example.com');
    expect(successEvents.clientEvents.completeAccountRemoval)
      .toHaveBeenCalledWith(successEvents.accountRemovalReceipt);

    const failedEvents = clientEventsHarness();
    const failed = createRouter({
      auth: { removeAccount: vi.fn(async () => { throw new Error('remove failed'); }) },
      vault: {}, settings: intentSettings(), clientEvents: failedEvents.clientEvents,
    });
    await expect(failed.handle({ type: 'auth.removeAccount', email: 'old@example.com' }))
      .resolves.toMatchObject({ ok: false, error: { message: 'remove failed' } });
    expect(failedEvents.clientEvents.completeAccountRemoval).not.toHaveBeenCalled();
  });

  it('keeps account removal successful when event capture or cleanup fails', async () => {
    const captureFailure = clientEventsHarness();
    captureFailure.clientEvents.captureAccountRemoval.mockRejectedValue(
      new Error('directory unavailable'),
    );
    const firstRemove = vi.fn(async () => {});
    const first = createRouter({
      auth: { removeAccount: firstRemove }, vault: {}, settings: intentSettings(),
      clientEvents: captureFailure.clientEvents,
    });
    await expect(first.handle({ type: 'auth.removeAccount', email: 'old@example.com' }))
      .resolves.toEqual({ ok: true, data: null });
    expect(firstRemove).toHaveBeenCalledOnce();

    const cleanupFailure = clientEventsHarness();
    cleanupFailure.clientEvents.completeAccountRemoval.mockRejectedValue(
      new Error('cleanup unavailable'),
    );
    const secondRemove = vi.fn(async () => {});
    const second = createRouter({
      auth: { removeAccount: secondRemove }, vault: {}, settings: intentSettings(),
      clientEvents: cleanupFailure.clientEvents,
    });
    await expect(second.handle({ type: 'auth.removeAccount', email: 'old@example.com' }))
      .resolves.toEqual({ ok: true, data: null });
    expect(secondRemove).toHaveBeenCalledOnce();
  });

  it('completes a late account-removal capture after the owning removal succeeds', async () => {
    vi.useFakeTimers();
    try {
      const events = clientEventsHarness();
      let resolveCapture!: (receipt: typeof events.accountRemovalReceipt) => void;
      const pendingCapture = new Promise<typeof events.accountRemovalReceipt>((resolve) => {
        resolveCapture = resolve;
      });
      events.clientEvents.captureAccountRemoval.mockImplementation(() => pendingCapture);
      const removeAccount = vi.fn(async () => {});
      const router = createRouter({
        auth: { removeAccount }, vault: {}, settings: intentSettings(),
        clientEvents: events.clientEvents,
      });
      const response = router.handle({ type: 'auth.removeAccount', email: 'old@example.com' });

      await vi.advanceTimersByTimeAsync(CLIENT_EVENT_BEST_EFFORT_WAIT_MS);
      await vi.waitFor(() => expect(removeAccount).toHaveBeenCalledOnce());
      resolveCapture(events.accountRemovalReceipt);
      await vi.advanceTimersByTimeAsync(0);

      await expect(response).resolves.toEqual({ ok: true, data: null });
      expect(events.clientEvents.completeAccountRemoval)
        .toHaveBeenCalledWith(events.accountRemovalReceipt);
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not complete a late account-removal capture when removal fails', async () => {
    vi.useFakeTimers();
    try {
      const events = clientEventsHarness();
      let resolveCapture!: (receipt: typeof events.accountRemovalReceipt) => void;
      const pendingCapture = new Promise<typeof events.accountRemovalReceipt>((resolve) => {
        resolveCapture = resolve;
      });
      events.clientEvents.captureAccountRemoval.mockImplementation(() => pendingCapture);
      const router = createRouter({
        auth: { removeAccount: vi.fn(async () => { throw new Error('remove failed'); }) },
        vault: {}, settings: intentSettings(), clientEvents: events.clientEvents,
      });
      const response = router.handle({ type: 'auth.removeAccount', email: 'old@example.com' });

      await vi.advanceTimersByTimeAsync(CLIENT_EVENT_BEST_EFFORT_WAIT_MS);
      await expect(response).resolves.toMatchObject({ ok: false, error: { message: 'remove failed' } });
      resolveCapture(events.accountRemovalReceipt);
      await vi.advanceTimersByTimeAsync(0);
      expect(events.clientEvents.completeAccountRemoval).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
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
    expect(getTotpCode).toHaveBeenCalledWith('has', undefined, expect.any(Function));
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
    const archiveCipher = vi.fn(async () => listing);
    const unarchiveCipher = vi.fn(async () => listing);
    const upgradeLegacyAttachment = vi.fn(async () => listing);
    const deletePasskey = vi.fn(async () => listing);
    const getCipherInput = vi.fn(async (id: string) => (id === 'c1' ? input : undefined));
    const router = createRouter({
      auth: {},
      vault: {
        createCipher,
        updateCipher,
        deleteCipher,
        softDeleteCipher,
        restoreCipher,
        archiveCipher,
        unarchiveCipher,
        upgradeLegacyAttachment,
        deletePasskey,
        getCipherInput,
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
    const target = { kind: 'personal' as const };
    await expect(router.handle({ type: 'vault.createCipher', input, target })).resolves.toEqual({ ok: true, data: listing });
    expect(createCipher).toHaveBeenCalledWith(input, target);
    const organizationTarget = {
      kind: 'organization' as const,
      organizationId: 'org-1',
      collectionIds: ['collection-1'],
    };
    await expect(router.handle({
      type: 'vault.createCipher',
      input,
      target: organizationTarget,
    })).resolves.toEqual({ ok: true, data: listing });
    expect(createCipher).toHaveBeenLastCalledWith(input, organizationTarget);
    await expect(router.handle({ type: 'vault.updateCipher', id: 'c1', input })).resolves.toEqual({ ok: true, data: listing });
    expect(updateCipher).toHaveBeenCalledWith('c1', input);
    await expect(router.handle({ type: 'vault.deleteCipher', id: 'c1' })).resolves.toEqual({ ok: true, data: listing });
    expect(deleteCipher).toHaveBeenCalledWith('c1');
    await expect(router.handle({ type: 'vault.softDeleteCipher', id: 'c1' })).resolves.toEqual({ ok: true, data: listing });
    expect(softDeleteCipher).toHaveBeenCalledWith('c1');
    await expect(router.handle({ type: 'vault.restoreCipher', id: 'c1' })).resolves.toEqual({ ok: true, data: listing });
    expect(restoreCipher).toHaveBeenCalledWith('c1');
    await expect(router.handle({
      type: 'vault.archiveCipher',
      id: 'c1',
      masterPassword: 'master',
    })).resolves.toEqual({ ok: true, data: listing });
    expect(archiveCipher).toHaveBeenCalledWith('c1', 'master');
    await expect(router.handle({
      type: 'vault.unarchiveCipher',
      id: 'c1',
      masterPassword: 'master',
    })).resolves.toEqual({ ok: true, data: listing });
    expect(unarchiveCipher).toHaveBeenCalledWith('c1', 'master');
    await expect(router.handle({
      type: 'vault.upgradeLegacyAttachment',
      cipherId: 'c1',
      attachmentId: 'legacy-1',
      masterPassword: 'master',
    })).resolves.toEqual({ ok: true, data: listing });
    expect(upgradeLegacyAttachment).toHaveBeenCalledWith('c1', 'legacy-1', 'master');
    await expect(router.handle({
      type: 'vault.upgradeLegacyAttachment',
      cipherId: 'c1',
      attachmentId: 'legacy-1',
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({
      type: 'vault.deletePasskey',
      id: 'c1',
      credentialId: 'credential-1',
      masterPassword: 'master',
    })).resolves.toEqual({ ok: true, data: listing });
    expect(deletePasskey).toHaveBeenCalledWith('c1', 'credential-1', 'master');
    await expect(router.handle({ type: 'vault.getCipherInput', id: 'c1', cipherInputPurpose: 'edit' })).resolves.toEqual({ ok: true, data: { input } });
    await expect(router.handle({ type: 'vault.getCipherInput', id: 'missing', cipherInputPurpose: 'edit' })).resolves.toEqual({ ok: true, data: { input: null } });
  });

  it('requires an explicit exact cipher input purpose at the router boundary', async () => {
    const getCipherInput = vi.fn(async () => ({ type: 1 as const, name: 'Login' }));
    const router = createRouter({
      auth: {}, vault: { getCipherInput }, settings: intentSettings(),
    });
    const invalid = [
      { type: 'vault.getCipherInput', id: 'c1' },
      { type: 'vault.getCipherInput', id: 'c1', cipherInputPurpose: 'other' },
      { type: 'vault.getCipherInput', id: 'c1', cipherInputPurpose: 'clone', clientEventPurpose: 'editor' },
      { type: 'vault.getCipherInput', id: 'c1', cipherInputPurpose: 'edit', extra: true },
    ];
    for (const request of invalid) {
      await expect(router.handle(request as never)).resolves.toMatchObject({
        ok: false, error: { code: 'denied' },
      });
    }
    const accessor = Object.defineProperty({
      type: 'vault.getCipherInput', id: 'c1',
    }, 'cipherInputPurpose', { enumerable: true, get: () => 'clone' });
    await expect(router.handle(accessor as never)).resolves.toMatchObject({
      ok: false, error: { code: 'denied' },
    });
    expect(getCipherInput).not.toHaveBeenCalled();
  });

  it('routes the dedicated SSH key surface with public-only and explicit private responses', async () => {
    const listing = { items: [], folders: [], collections: [], orgPermissions: [] };
    const metadata = {
      name: 'Deploy key',
      notes: '',
      favorite: false,
      reprompt: true,
      folderId: null,
      fields: [],
    };
    const publicDetails = {
      publicKey: 'ssh-ed25519 AAAATEST',
      keyFingerprint: 'SHA256:test',
      hasPrivateKey: true,
    };
    const getSshKeyWriteAvailability = vi.fn(async () => ({ available: true }));
    const getSshKeyDetails = vi.fn(async (id: string) => (id === 'ssh-1' ? publicDetails : undefined));
    const revealSshPrivateKey = vi.fn(async (id: string) => (id === 'ssh-1' ? 'PRIVATE' : undefined));
    const createGeneratedSshKey = vi.fn(async () => listing);
    const importSshKey = vi.fn(async () => listing);
    const replaceSshKey = vi.fn(async () => listing);
    const updateSshKeyMetadata = vi.fn(async () => listing);
    const router = createRouter({
      auth: {},
      vault: {
        getSshKeyDetails,
        getSshKeyWriteAvailability,
        revealSshPrivateKey,
        createGeneratedSshKey,
        importSshKey,
        replaceSshKey,
        updateSshKeyMetadata,
      },
      settings: intentSettings(),
    });

    await expect(router.handle({ type: 'vault.getSshKeyWriteAvailability' }))
      .resolves.toEqual({ ok: true, data: { available: true } });
    expect(getSshKeyWriteAvailability).toHaveBeenCalledOnce();

    await expect(router.handle({ type: 'vault.getSshKeyDetails', id: 'ssh-1', masterPassword: 'proof' }))
      .resolves.toEqual({ ok: true, data: { sshKey: publicDetails } });
    expect(getSshKeyDetails).toHaveBeenCalledWith('ssh-1', 'proof', expect.any(Function));
    await expect(router.handle({ type: 'vault.getSshKeyDetails', id: 'missing' }))
      .resolves.toEqual({ ok: true, data: { sshKey: null } });

    await expect(router.handle({ type: 'vault.revealSshPrivateKey', id: 'ssh-1', masterPassword: 'proof' }))
      .resolves.toEqual({ ok: true, data: { privateKey: 'PRIVATE' } });
    expect(revealSshPrivateKey).toHaveBeenCalledWith('ssh-1', 'proof', expect.any(Function));
    await expect(router.handle({ type: 'vault.revealSshPrivateKey', id: 'missing' }))
      .resolves.toEqual({ ok: true, data: { privateKey: null } });

    const target = { kind: 'personal' as const };
    await expect(router.handle({ type: 'vault.createGeneratedSshKey', metadata, target }))
      .resolves.toEqual({ ok: true, data: listing });
    expect(createGeneratedSshKey).toHaveBeenCalledWith(metadata, target);
    await expect(router.handle({ type: 'vault.importSshKey', metadata, privateKey: 'IMPORTED', target }))
      .resolves.toEqual({ ok: true, data: listing });
    expect(importSshKey).toHaveBeenCalledWith(metadata, 'IMPORTED', target);
    await expect(router.handle({ type: 'vault.replaceSshKey', id: 'ssh-1', privateKey: 'REPLACEMENT', masterPassword: 'proof' }))
      .resolves.toEqual({ ok: true, data: listing });
    expect(replaceSshKey).toHaveBeenCalledWith('ssh-1', 'REPLACEMENT', 'proof');
    await expect(router.handle({ type: 'vault.updateSshKeyMetadata', id: 'ssh-1', metadata, masterPassword: 'proof' }))
      .resolves.toEqual({ ok: true, data: listing });
    expect(updateSshKeyMetadata).toHaveBeenCalledWith('ssh-1', metadata, 'proof');
  });

  it('rejects every dedicated SSH command from content scripts', async () => {
    const called = vi.fn();
    const listing = { items: [], folders: [], collections: [], orgPermissions: [] };
    const router = createRouter({
      auth: {},
      vault: {
        getSshKeyWriteAvailability: async () => { called(); return { available: true }; },
        getSshKeyDetails: async () => { called(); return undefined; },
        revealSshPrivateKey: async () => { called(); return undefined; },
        createGeneratedSshKey: async () => { called(); return listing; },
        importSshKey: async () => { called(); return listing; },
        replaceSshKey: async () => { called(); return listing; },
        updateSshKeyMetadata: async () => { called(); return listing; },
      },
      settings: intentSettings(),
    });
    const metadata = {
      name: 'Key', notes: '', favorite: false, reprompt: false, folderId: null, fields: [],
    };
    const requests: RequestMessage[] = [
      { type: 'vault.getSshKeyWriteAvailability' },
      { type: 'vault.getSshKeyDetails', id: 'ssh-1' },
      { type: 'vault.revealSshPrivateKey', id: 'ssh-1' },
      { type: 'vault.createGeneratedSshKey', metadata, target: { kind: 'personal' } },
      { type: 'vault.importSshKey', metadata, privateKey: 'PRIVATE', target: { kind: 'personal' } },
      { type: 'vault.replaceSshKey', id: 'ssh-1', privateKey: 'PRIVATE' },
      { type: 'vault.updateSshKeyMetadata', id: 'ssh-1', metadata },
    ];

    for (const request of requests) {
      await expect(router.handle(request, CONTENT_CONTEXT)).resolves.toEqual({
        ok: false,
        error: { code: 'denied', message: 'sender not permitted' },
      });
    }
    expect(called).not.toHaveBeenCalled();
  });

  it('blocks crafted type-5 inputs at the generic router boundary', async () => {
    const createCipher = vi.fn();
    const updateCipher = vi.fn();
    const router = createRouter({
      auth: {},
      vault: { createCipher, updateCipher },
      settings: intentSettings(),
    });
    const input = {
      type: 5,
      name: 'Bypass',
      sshKey: { privateKey: 'P', publicKey: 'U', keyFingerprint: 'F' },
    };

    await expect(router.handle({ type: 'vault.createCipher', input } as never)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    await expect(router.handle({ type: 'vault.updateCipher', id: 'ssh-1', input } as never)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    expect(createCipher).not.toHaveBeenCalled();
    expect(updateCipher).not.toHaveBeenCalled();
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

  it('auth.submitTwoFactor rejects provider 7 outside the fallback connector flow', async () => {
    const submitTwoFactor = vi.fn(async () => ({ kind: 'unlocked' as const }));
    const router = createRouter({
      auth: { submitTwoFactor },
      vault: {},
      settings: intentSettings(),
    });

    await expect(router.handle({ type: 'auth.submitTwoFactor', provider: 7, code: '{"id":"key"}' }))
      .resolves.toEqual({ ok: false, error: { code: 'denied', message: 'Use the security-key connector.' } });
    expect(submitTwoFactor).not.toHaveBeenCalled();
  });

  it('opens two-factor recovery only from the popup without cancelling pending login', async () => {
    const open = vi.fn(async () => undefined);
    const cancelPendingLogin = vi.fn(async () => true);
    const router = createRouter({
      auth: { cancelPendingLogin },
      vault: {},
      settings: intentSettings(),
      twoFactorRecovery: { open },
    });

    await expect(router.handle({ type: 'auth.openTwoFactorRecovery' }, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: null });
    expect(open).toHaveBeenCalledOnce();
    expect(cancelPendingLogin).not.toHaveBeenCalled();
  });

  it.each([CONTENT_CONTEXT, OPTIONS_PAGE_CONTEXT])(
    'denies two-factor recovery from a non-popup sender',
    async (context) => {
      const open = vi.fn(async () => undefined);
      const router = createRouter({
        auth: {}, vault: {}, settings: intentSettings(), twoFactorRecovery: { open },
      });

      await expect(router.handle({ type: 'auth.openTwoFactorRecovery' }, context))
        .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
      expect(open).not.toHaveBeenCalled();
    },
  );

  it('rejects a recovery command carrying a page-controlled URL', async () => {
    const open = vi.fn(async () => undefined);
    const router = createRouter({
      auth: {}, vault: {}, settings: intentSettings(), twoFactorRecovery: { open },
    });
    const forged = {
      type: 'auth.openTwoFactorRecovery',
      url: 'https://evil.example/recover',
    } as unknown as RequestMessage;

    await expect(router.handle(forged, EXTENSION_PAGE_CONTEXT)).resolves.toEqual({
      ok: false,
      error: { code: 'denied', message: 'Invalid two-step recovery request.' },
    });
    expect(open).not.toHaveBeenCalled();
  });

  it('routes new-device verification actions with only attempt-bound public input', async () => {
    const sendNewDeviceVerificationOtp = vi.fn(async () => undefined);
    const submitNewDeviceVerification = vi.fn(async () => ({ kind: 'unlocked' as const }));
    const cancelNewDeviceVerification = vi.fn(async () => true);
    const router = createRouter({
      auth: {
        sendNewDeviceVerificationOtp,
        submitNewDeviceVerification,
        cancelNewDeviceVerification,
      },
      vault: {},
      settings: intentSettings(),
    });

    await expect(router.handle({
      type: 'auth.newDeviceVerification.sendOtp', attemptId: 4,
    })).resolves.toEqual({ ok: true, data: null });
    await expect(router.handle({
      type: 'auth.newDeviceVerification.submit', attemptId: 4, code: '123456',
    })).resolves.toEqual({ ok: true, data: { kind: 'unlocked' } });
    await expect(router.handle({
      type: 'auth.newDeviceVerification.cancel', attemptId: 4,
    })).resolves.toEqual({ ok: true, data: { cancelled: true } });

    expect(sendNewDeviceVerificationOtp).toHaveBeenCalledWith({ attemptId: 4 });
    expect(submitNewDeviceVerification).toHaveBeenCalledWith({ attemptId: 4, code: '123456' });
    expect(cancelNewDeviceVerification).toHaveBeenCalledWith({ attemptId: 4 });
  });

  it('routes password-login continuation status and cancellation only from extension pages', async () => {
    const status = {
      status: 'twoFactor' as const,
      attemptId: 8,
      continuationId: 'c8882c32-17e1-4052-ac72-9b09f0bbb11d',
      providers: [0, 7],
      fido2: { owner: PASSWORD_FIDO_OWNER },
      expiresAt: Date.now() + 60_000,
    };
    const getPendingLoginStatus = vi.fn(async () => status);
    const cancelPendingLogin = vi.fn(async () => true);
    const router = createRouter({
      auth: { getPendingLoginStatus, cancelPendingLogin },
      vault: {},
      settings: intentSettings(),
    });

    await expect(router.handle({ type: 'auth.pendingLogin.status' }))
      .resolves.toEqual({ ok: true, data: status });
    await expect(router.handle({ type: 'auth.pendingLogin.cancel' }))
      .resolves.toEqual({ ok: true, data: { cancelled: true } });
    await expect(router.handle({ type: 'auth.pendingLogin.status' }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({ type: 'auth.pendingLogin.cancel' }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });

    expect(getPendingLoginStatus).toHaveBeenCalledTimes(1);
    expect(cancelPendingLogin).toHaveBeenCalledTimes(1);
  });

  it('denies new-device verification actions from content documents', async () => {
    const sendNewDeviceVerificationOtp = vi.fn(async () => undefined);
    const router = createRouter({
      auth: { sendNewDeviceVerificationOtp },
      vault: {},
      settings: intentSettings(),
    });

    await expect(router.handle({
      type: 'auth.newDeviceVerification.sendOtp', attemptId: 4,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(sendNewDeviceVerificationOtp).not.toHaveBeenCalled();
  });

  it('auth.beginFido2 opens and binds the exact fallback URL from an extension page', async () => {
    const url = 'https://vault.example/webauthn-fallback-connector.html?data=abc&parent=def&v=1&locale=en';
    const replace = Object.freeze({ tabId: 18, documentId: 'connector-old-doc', url });
    const begin = vi.fn(async () => ({ owner: PASSWORD_FIDO_OWNER, url, replace }));
    const bindTab = vi.fn(async () => {});
    const cancelLaunch = vi.fn(async () => false);
    const password = interactiveTwoFactorBroker({ begin, bindTab, cancelLaunch });
    const deviceLogin = interactiveTwoFactorBroker();
    const open = vi.fn(async () => ({
      tabId: 22,
      documentId: 'connector-doc-1',
      url,
    }));
    const close = vi.fn(async () => {});
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      interactiveTwoFactor: { password, deviceLogin },
      fido2Connector: { open, close, finish: vi.fn(async () => {}) },
    });

    await expect(router.handle({ type: 'auth.beginFido2', owner: PASSWORD_FIDO_OWNER, locale: 'en' }))
      .resolves.toEqual({ ok: true, data: null });
    expect(begin).toHaveBeenCalledWith({
      owner: PASSWORD_FIDO_OWNER,
      parentUrl: EXTENSION_PAGE_CONTEXT.url,
      locale: 'en',
    });
    expect(open).toHaveBeenCalledWith(url, replace);
    expect(bindTab).toHaveBeenCalledWith({
      owner: PASSWORD_FIDO_OWNER,
      url,
      tabId: 22,
      documentId: 'connector-doc-1',
    });
    expect(deviceLogin.begin).not.toHaveBeenCalled();
    expect(close).not.toHaveBeenCalled();
    expect(cancelLaunch).not.toHaveBeenCalled();
  });

  it('auth.beginFido2 releases its launch reservation when tab creation fails', async () => {
    const url = 'https://vault.example/webauthn-fallback-connector.html?data=abc';
    const cancelLaunch = vi.fn(async () => true);
    const password = interactiveTwoFactorBroker({
      begin: vi.fn(async () => ({ owner: PASSWORD_FIDO_OWNER, url })),
      cancelLaunch,
    });
    const deviceLogin = interactiveTwoFactorBroker();
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      interactiveTwoFactor: { password, deviceLogin },
      fido2Connector: {
        open: vi.fn(async () => { throw new Error('tab create failed'); }),
        close: vi.fn(async () => {}),
        finish: vi.fn(async () => {}),
      },
    });

    await expect(router.handle({ type: 'auth.beginFido2', owner: PASSWORD_FIDO_OWNER, locale: 'en' }))
      .resolves.toEqual({ ok: false, error: { code: 'error', message: 'tab create failed' } });
    expect(cancelLaunch).toHaveBeenCalledWith({ owner: PASSWORD_FIDO_OWNER, url });
    expect(deviceLogin.cancelLaunch).not.toHaveBeenCalled();
  });

  it('auth.beginFido2 releases a mismatched launch owner before allowing a retry', async () => {
    const url = 'https://vault.example/webauthn-fallback-connector.html?data=abc';
    const changedOwner = Object.freeze({ ...PASSWORD_FIDO_OWNER, generation: 9 });
    const begin = vi.fn()
      .mockResolvedValueOnce({ owner: changedOwner, url })
      .mockResolvedValueOnce({ owner: PASSWORD_FIDO_OWNER, url });
    const cancelLaunch = vi.fn(async () => true);
    const bindTab = vi.fn(async () => {});
    const password = interactiveTwoFactorBroker({ begin, cancelLaunch, bindTab });
    const open = vi.fn(async () => ({ tabId: 22, documentId: 'connector-doc-1', url }));
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      interactiveTwoFactor: { password, deviceLogin: interactiveTwoFactorBroker() },
      fido2Connector: { open, close: vi.fn(async () => {}), finish: vi.fn(async () => {}) },
    });
    const request = { type: 'auth.beginFido2', owner: PASSWORD_FIDO_OWNER, locale: 'en' } as const;

    await expect(router.handle(request)).resolves.toEqual({
      ok: false,
      error: { code: 'denied', message: 'Interactive two-factor owner changed during launch.' },
    });
    expect(cancelLaunch).toHaveBeenCalledWith({ owner: changedOwner, url });
    expect(open).not.toHaveBeenCalled();

    await expect(router.handle(request)).resolves.toEqual({ ok: true, data: null });
    expect(open).toHaveBeenCalledOnce();
    expect(bindTab).toHaveBeenCalledWith({
      owner: PASSWORD_FIDO_OWNER,
      url,
      tabId: 22,
      documentId: 'connector-doc-1',
    });
  });

  it.each(['unlocked', 'locked'] as const)(
    'auth.completeFido2 treats %s as success after validating the browser-owned top-frame URL/tab',
    async (kind) => {
      const connectorContext = {
        ...CONTENT_CONTEXT,
        tabId: 22,
        documentId: 'connector-doc-1',
        url: 'https://vault.example/webauthn-fallback-connector.html?data=abc',
        origin: 'https://vault.example',
      } satisfies RequestContext;
      const matchPasswordCaller = vi.fn(() => PASSWORD_FIDO_OWNER);
      const matchDeviceCaller = vi.fn(() => undefined);
      const complete = vi.fn(async () => ({ kind }));
      const password = interactiveTwoFactorBroker({
        matchCaller: matchPasswordCaller,
        complete,
      });
      const deviceLogin = interactiveTwoFactorBroker({ matchCaller: matchDeviceCaller });
      const finish = vi.fn(async () => {});
      const router = createRouter({
        auth: {},
        vault: {},
        settings: intentSettings(),
        interactiveTwoFactor: { password, deviceLogin },
        fido2Connector: {
          open: vi.fn(async () => ({
            tabId: connectorContext.tabId,
            documentId: connectorContext.documentId,
            url: connectorContext.url,
          })),
          close: vi.fn(async () => {}),
          finish,
        },
      });

      await expect(router.handle({
        type: 'auth.completeFido2', token: '{"id":"key"}', remember: true,
      }, connectorContext)).resolves.toEqual({ ok: true, data: { kind } });
      const callerBinding = {
        url: connectorContext.url,
        tabId: connectorContext.tabId,
        documentId: connectorContext.documentId,
      };
      expect(matchPasswordCaller).toHaveBeenCalledWith(callerBinding);
      expect(matchDeviceCaller).toHaveBeenCalledWith(callerBinding);
      expect(complete).toHaveBeenCalledWith({
        owner: PASSWORD_FIDO_OWNER,
        ...callerBinding,
        token: '{"id":"key"}',
        remember: true,
      });
      expect(deviceLogin.complete).not.toHaveBeenCalled();
      expect(finish).toHaveBeenCalledWith(callerBinding, 'success');
    },
  );

  it('atomically claims one connector document before concurrent callbacks can await', async () => {
    const connectorContext = {
      ...CONTENT_CONTEXT,
      tabId: 25,
      documentId: 'connector-concurrent-doc',
      url: 'https://vault.example/webauthn-fallback-connector.html?data=concurrent',
      origin: 'https://vault.example',
    } satisfies RequestContext;
    let resolveCompletion!: (value: { kind: 'unlocked' }) => void;
    const completion = new Promise<{ kind: 'unlocked' }>((resolve) => {
      resolveCompletion = resolve;
    });
    const complete = vi.fn(() => completion);
    const finish = vi.fn(async () => {});
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      interactiveTwoFactor: {
        password: interactiveTwoFactorBroker({
          matchCaller: vi.fn(() => PASSWORD_FIDO_OWNER),
          complete,
        }),
        deviceLogin: interactiveTwoFactorBroker(),
      },
      fido2Connector: {
        open: vi.fn(async () => connectorContext),
        close: vi.fn(async () => {}),
        finish,
      },
    });
    const request = { type: 'auth.completeFido2', token: '{}', remember: false } as const;

    const first = router.handle(request, connectorContext);
    await vi.waitFor(() => expect(complete).toHaveBeenCalledOnce());
    await expect(router.handle(request, connectorContext)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    expect(finish).not.toHaveBeenCalled();

    resolveCompletion({ kind: 'unlocked' });
    await expect(first).resolves.toEqual({ ok: true, data: { kind: 'unlocked' } });
    expect(complete).toHaveBeenCalledOnce();
    expect(finish).toHaveBeenCalledOnce();
  });

  it('auth.completeFido2 rejects a callback claimed by both interactive owners', async () => {
    const connectorContext = {
      ...CONTENT_CONTEXT,
      tabId: 22,
      documentId: 'connector-doc-1',
      url: 'https://vault.example/webauthn-fallback-connector.html?data=abc',
      origin: 'https://vault.example',
    } satisfies RequestContext;
    const passwordComplete = vi.fn();
    const deviceComplete = vi.fn();
    const password = interactiveTwoFactorBroker({
      matchCaller: vi.fn(() => PASSWORD_FIDO_OWNER),
      complete: passwordComplete,
    });
    const deviceLogin = interactiveTwoFactorBroker({
      matchCaller: vi.fn(() => DEVICE_FIDO_OWNER),
      complete: deviceComplete,
    });
    const finish = vi.fn(async () => {});
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      interactiveTwoFactor: { password, deviceLogin },
      fido2Connector: {
        open: vi.fn(async () => ({
          tabId: connectorContext.tabId,
          documentId: connectorContext.documentId,
          url: connectorContext.url,
        })),
        close: vi.fn(async () => {}),
        finish,
      },
    });

    await expect(router.handle({
      type: 'auth.completeFido2', token: '{}', remember: false,
    }, connectorContext)).resolves.toEqual({
      ok: false,
      error: { code: 'denied', message: 'sender not permitted' },
    });
    expect(passwordComplete).not.toHaveBeenCalled();
    expect(deviceComplete).not.toHaveBeenCalled();
    expect(finish).not.toHaveBeenCalled();
  });

  it('auth.completeFido2 rejects a callback claimed by neither interactive owner', async () => {
    const connectorContext = {
      ...CONTENT_CONTEXT,
      tabId: 22,
      documentId: 'connector-doc-1',
      url: 'https://vault.example/webauthn-fallback-connector.html?data=abc',
      origin: 'https://vault.example',
    } satisfies RequestContext;
    const passwordComplete = vi.fn();
    const deviceComplete = vi.fn();
    const finish = vi.fn(async () => {});
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      interactiveTwoFactor: {
        password: interactiveTwoFactorBroker({ complete: passwordComplete }),
        deviceLogin: interactiveTwoFactorBroker({ complete: deviceComplete }),
      },
      fido2Connector: {
        open: vi.fn(async () => ({
          tabId: connectorContext.tabId,
          documentId: connectorContext.documentId,
          url: connectorContext.url,
        })),
        close: vi.fn(async () => {}),
        finish,
      },
    });

    await expect(router.handle({
      type: 'auth.completeFido2', token: '{}', remember: false,
    }, connectorContext)).resolves.toEqual({
      ok: false,
      error: { code: 'denied', message: 'sender not permitted' },
    });
    expect(passwordComplete).not.toHaveBeenCalled();
    expect(deviceComplete).not.toHaveBeenCalled();
    expect(finish).not.toHaveBeenCalled();
  });

  it('auth.completeFido2 completes an exact device-login owner without touching password state', async () => {
    const connectorContext = {
      ...CONTENT_CONTEXT,
      tabId: 23,
      documentId: 'connector-device-doc-1',
      url: 'https://vault.example/webauthn-fallback-connector.html?data=device',
      origin: 'https://vault.example',
    } satisfies RequestContext;
    const passwordComplete = vi.fn();
    const deviceComplete = vi.fn(async () => ({ status: 'unlocked' as const }));
    const finish = vi.fn(async () => {});
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      interactiveTwoFactor: {
        password: interactiveTwoFactorBroker({ complete: passwordComplete }),
        deviceLogin: interactiveTwoFactorBroker({
          matchCaller: vi.fn(() => DEVICE_FIDO_OWNER),
          complete: deviceComplete,
        }),
      },
      fido2Connector: {
        open: vi.fn(async () => ({
          tabId: connectorContext.tabId,
          documentId: connectorContext.documentId,
          url: connectorContext.url,
        })),
        close: vi.fn(async () => {}),
        finish,
      },
    });

    await expect(router.handle({
      type: 'auth.completeFido2', token: '{"id":"device-key"}', remember: true,
    }, connectorContext)).resolves.toEqual({ ok: true, data: { status: 'unlocked' } });
    expect(passwordComplete).not.toHaveBeenCalled();
    expect(deviceComplete).toHaveBeenCalledWith({
      owner: DEVICE_FIDO_OWNER,
      url: connectorContext.url,
      tabId: connectorContext.tabId,
      documentId: connectorContext.documentId,
      token: '{"id":"device-key"}',
      remember: true,
    });
    expect(finish).toHaveBeenCalledWith({
      url: connectorContext.url,
      tabId: connectorContext.tabId,
      documentId: connectorContext.documentId,
    }, 'success');
  });

  it('does not downgrade a completed login when settled connector cleanup fails', async () => {
    const connectorContext = {
      ...CONTENT_CONTEXT,
      tabId: 24,
      documentId: 'connector-consumed-doc-1',
      url: 'https://vault.example/webauthn-fallback-connector.html?data=consumed',
      origin: 'https://vault.example',
    } satisfies RequestContext;
    let consumed = false;
    const complete = vi.fn(async () => {
      consumed = true;
      return { kind: 'unlocked' as const };
    });
    const password = interactiveTwoFactorBroker({
      matchCaller: vi.fn(() => consumed ? undefined : PASSWORD_FIDO_OWNER),
      complete,
    });
    const finish = vi.fn(async () => { throw new Error('tab cleanup failed'); });
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      interactiveTwoFactor: { password, deviceLogin: interactiveTwoFactorBroker() },
      fido2Connector: {
        open: vi.fn(async () => ({
          tabId: connectorContext.tabId,
          documentId: connectorContext.documentId,
          url: connectorContext.url,
        })),
        close: vi.fn(async () => {}),
        finish,
      },
    });
    const request = { type: 'auth.completeFido2', token: '{}', remember: false } as const;

    await expect(router.handle(request, connectorContext)).resolves.toEqual({
      ok: true,
      data: { kind: 'unlocked' },
    });
    await expect(router.handle(request, connectorContext)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    expect(complete).toHaveBeenCalledOnce();
    expect(finish).toHaveBeenCalledOnce();
  });

  it('rechecks page-load vault result authority after the release checkpoint await', async () => {
    const settings = intentSettings();
    settings.getAutofillSettings = vi.fn(async () => ({
      ...DEFAULT_AUTOFILL_SETTINGS,
      pageLoadFill: true,
    }));
    let current = true;
    let releaseCheckpoint!: (proof: object) => void;
    const checkpointPending = new Promise<object>((resolve) => { releaseCheckpoint = resolve; });
    const checkpoint = vi.fn(() => checkpointPending);
    const vaultReleaseGate: NonNullable<RouterDeps['vaultReleaseGate']> = {
      capture: vi.fn(() => ({ sessionLease: { generation: 0 }, timeoutLease: {} } as never)),
      checkpoint: checkpoint as never,
      assertAuthorities: vi.fn((_proof, assertCurrent) => assertCurrent()),
      assert: vi.fn(),
    };
    const router = createRouter({
      auth: {},
      settings,
      vaultReleaseGate,
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: 'login-1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
        }]),
        getAutofillLoginData: vi.fn(async (
          _id, _url, _strategy, _options, bindFinalAuthority,
        ) => {
          bindFinalAuthority?.(() => {
            if (!current) throw new AppError('denied', 'vault result changed');
          });
          return { username: 'user', password: 'secret' };
        }),
      },
    });
    const token = intentId(await router.handle({ type: 'autofill.issuePageLoadIntent' }, CONTENT_CONTEXT));
    const response = router.handle({
      type: 'autofill.redeemPageLoadIntent', intentId: token,
    }, CONTENT_CONTEXT);
    await vi.waitFor(() => expect(checkpoint).toHaveBeenCalledOnce());
    current = false;
    releaseCheckpoint({});

    await expect(response).resolves.toEqual({
      ok: false,
      error: { code: 'denied', message: 'vault result changed' },
    });
    expect(vaultReleaseGate.assert).not.toHaveBeenCalled();
  });

  it('withholds a revealed password when a pending timeout action locks the session', async () => {
    const { SessionGate } = await import('./session-gate.js');
    const { VaultReleaseGate } = await import('./vault-release-gate.js');
    const sessionGate = new SessionGate('unlocked');
    const releaseGate = new VaultReleaseGate({
      captureRelease: () => ({} as never),
      checkpointRelease: async () => ({} as never),
      assertRelease: () => {},
    }, sessionGate);
    let releaseAction!: () => void;
    const action = new Promise<void>((resolve) => { releaseAction = resolve; });
    const settlePendingAction = vi.fn(() => action);
    const router = createRouter({
      auth: {},
      settings: intentSettings(),
      sessionGate,
      vaultReleaseGate: releaseGate,
      vaultTimeout: {
        captureActivity: () => undefined,
        recordActivity: async () => {},
        settlePendingAction,
      },
      vault: { getField: async () => 'synthetic-secret' },
    });
    const response = router.handle({ type: 'vault.getField', id: 'cipher-1', field: 'password' });
    await vi.waitFor(() => expect(settlePendingAction).toHaveBeenCalledOnce());
    sessionGate.handleTransition({ phase: 'start', transitionId: 1, reason: 'lock', identityChanged: false });
    sessionGate.handleTransition({
      phase: 'settled', transitionId: 1, reason: 'lock', identityChanged: false,
      state: 'locked', succeeded: true,
    });
    releaseAction();
    await expect(response).resolves.toMatchObject({ ok: false, error: { code: 'locked' } });
  });

  it('rechecks the original runtime authority after the final durable checkpoint', async () => {
    let current = true;
    let releaseCheckpoint!: () => void;
    const checkpointPending = new Promise<void>((resolve) => { releaseCheckpoint = resolve; });
    const checkpoint = vi.fn(async () => { await checkpointPending; return {} as never; });
    const assert = vi.fn();
    const router = createRouter({
      auth: {}, settings: intentSettings(),
      vaultReleaseGate: {
        capture: () => ({} as never), checkpoint,
        assertAuthorities: (_proof, authorities) => authorities(), assert,
      },
      saveCaptureCoordinator: {
        captureRuntimeAuthority: async () => ({ assertCurrent: () => {
          if (!current) throw new AppError('denied', 'Runtime replaced');
        } }),
      },
      vault: {
        findAutofillCandidates: async () => [{
          id: '1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0, favorite: false,
        }],
        getInteractiveAutofillLoginData: async () => ({
          login: { username: 'user', password: 'synthetic-secret' }, customAssignments: [],
        }),
      },
    });
    const issued = await router.handle(loginIntentRequest(), CONTENT_CONTEXT);
    const response = router.handle({
      type: 'autofill.redeemLoginIntent', intentId: intentId(issued),
    }, CONTENT_CONTEXT);
    await vi.waitFor(() => expect(checkpoint).toHaveBeenCalledOnce());
    current = false;
    releaseCheckpoint();
    await expect(response).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(assert).not.toHaveBeenCalled();
  });

  it('releases real page-load data once without asynchronous runtime or timeout work after the final fence', async () => {
    const f = await realReleaseBoundaryFixture();
    let released = false;
    const lateOperations: string[] = [];
    const read = f.networkStore.get.bind(f.networkStore);
    const settle = f.timeout.settlePendingAction.bind(f.timeout);
    const finalAssert = f.releaseGate.assert.bind(f.releaseGate);
    vi.spyOn(f.networkStore, 'get').mockImplementation(async <T>(key: string): Promise<T | undefined> => {
      if (released) lateOperations.push('runtime storage read');
      return read<T>(key);
    });
    vi.spyOn(f.timeout, 'settlePendingAction').mockImplementation(async () => {
      if (released) lateOperations.push('timeout settlement');
      await settle();
    });
    const checkpoint = vi.spyOn(f.releaseGate, 'checkpoint');
    const assert = vi.spyOn(f.releaseGate, 'assert').mockImplementation((proof) => {
      finalAssert(proof);
      released = true;
    });

    await expect(f.router.handle({
      type: 'autofill.redeemPageLoadIntent', intentId: f.token,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({
      ok: true,
      data: { login: { username: 'user', password: 'synthetic-release-secret' } },
    });

    expect(checkpoint).toHaveBeenCalledOnce();
    expect(assert).toHaveBeenCalledOnce();
    expect(lateOperations).toEqual([]);
    expect(f.vaultRead).toHaveBeenCalledOnce();
    await expect(f.session.getState()).resolves.toBe('unlocked');
  });

  it('withholds page-load data when a real system lock overtakes the admitted runtime journal read', async () => {
    const f = await realReleaseBoundaryFixture();
    const { AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY } = await import('./autofill-save-capture-coordinator.js');
    let readEntered = false;
    let releaseRead!: () => void;
    const delayedRead = new Promise<void>((resolve) => { releaseRead = resolve; });
    const read = f.networkStore.get.bind(f.networkStore);
    vi.spyOn(f.networkStore, 'get').mockImplementation(async <T>(key: string): Promise<T | undefined> => {
      const value = await read<T>(key);
      if (key === AUTOFILL_SAVE_CAPTURE_NETWORK_STORAGE_KEY && !readEntered) {
        readEntered = true;
        await delayedRead;
      }
      return value;
    });
    const assert = vi.spyOn(f.releaseGate, 'assert');
    const response = f.router.handle({
      type: 'autofill.redeemPageLoadIntent', intentId: f.token,
    }, CONTENT_CONTEXT);
    let systemLock: Promise<void> | undefined;
    try {
      await vi.waitFor(() => expect(readEntered).toBe(true));
      systemLock = f.timeout.handleSystemLocked();
      await vi.waitFor(() => expect(f.transitionEvents).toContainEqual(expect.objectContaining({ phase: 'start' })));
    } finally {
      releaseRead();
    }

    await expect(response).resolves.toMatchObject({ ok: false });
    await systemLock;
    await expect(f.session.getState()).resolves.toBe('locked');
    expect(f.transitionEvents).toEqual([
      expect.objectContaining({ phase: 'start' }),
      expect.objectContaining({ phase: 'settled', state: 'locked' }),
    ]);
    expect(f.vaultRead).not.toHaveBeenCalled();
    expect(assert).not.toHaveBeenCalled();
  });

  it.each(['session lock', 'runtime replacement'] as const)(
    'withholds real page-load data when %s crosses the durable checkpoint storage write',
    async (revocation) => {
      const f = await realReleaseBoundaryFixture();
      let writeEntered = false;
      let releaseWrite!: () => void;
      const delayedWrite = new Promise<void>((resolve) => { releaseWrite = resolve; });
      const write = f.sessionStore.set.bind(f.sessionStore);
      vi.spyOn(f.sessionStore, 'set').mockImplementation(async (key, value) => {
        if (key === 'vaultTimeoutActivity' && !writeEntered) {
          writeEntered = true;
          await delayedWrite;
        }
        await write(key, value);
      });
      const assert = vi.spyOn(f.releaseGate, 'assert');
      const response = f.router.handle({
        type: 'autofill.redeemPageLoadIntent', intentId: f.token,
      }, CONTENT_CONTEXT);
      let locked: Promise<void> | undefined;
      try {
        await vi.waitFor(() => expect(writeEntered).toBe(true));
        expect(f.vaultRead).toHaveBeenCalledOnce();
        if (revocation === 'session lock') {
          locked = f.auth.lock();
          expect(f.transitionEvents).toContainEqual(expect.objectContaining({ phase: 'start' }));
        } else {
          await expect(f.coordinator.activateRuntime({
            tabId: CONTENT_CONTEXT.tabId,
            frameId: CONTENT_CONTEXT.frameId,
            documentId: CONTENT_CONTEXT.documentId,
            frameUrl: CONTENT_CONTEXT.url,
            runtimeIncarnation: NEXT_RUNTIME_INCARNATION,
            previousRuntimeIncarnation: TEST_RUNTIME_INCARNATION,
          })).resolves.toBe(true);
        }
      } finally {
        releaseWrite();
      }

      await expect(response).resolves.toMatchObject({
        ok: false,
        error: { code: revocation === 'session lock' ? 'locked' : 'denied' },
      });
      await locked;
      expect(assert).not.toHaveBeenCalled();
      await expect(f.session.getState()).resolves.toBe(revocation === 'session lock' ? 'locked' : 'unlocked');
    },
  );

  it('auth.completeFido2 rejects a child-frame relay before touching broker or browser state', async () => {
    const matchPasswordCaller = vi.fn(() => PASSWORD_FIDO_OWNER);
    const matchDeviceCaller = vi.fn(() => undefined);
    const password = interactiveTwoFactorBroker({ matchCaller: matchPasswordCaller });
    const deviceLogin = interactiveTwoFactorBroker({ matchCaller: matchDeviceCaller });
    const finish = vi.fn(async () => {});
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      interactiveTwoFactor: { password, deviceLogin },
      fido2Connector: {
        open: vi.fn(async () => ({
          tabId: 22,
          documentId: 'connector-doc-1',
          url: 'https://vault.example/webauthn-fallback-connector.html?data=abc',
        })),
        close: vi.fn(async () => {}),
        finish,
      },
    });

    await expect(router.handle({
      type: 'auth.completeFido2', token: '{}', remember: false,
    }, { ...CONTENT_CONTEXT, frameId: 2 })).resolves.toEqual({
      ok: false,
      error: { code: 'denied', message: 'sender not permitted' },
    });
    expect(matchPasswordCaller).not.toHaveBeenCalled();
    expect(matchDeviceCaller).not.toHaveBeenCalled();
    expect(finish).not.toHaveBeenCalled();
  });

  it('auth.completeFido2 closes the accepted connector and opens an error popup on verification failure', async () => {
    const connectorContext = {
      ...CONTENT_CONTEXT,
      tabId: 22,
      documentId: 'connector-doc-1',
      url: 'https://vault.example/webauthn-fallback-connector.html?data=abc',
      origin: 'https://vault.example',
    } satisfies RequestContext;
    const matchPasswordCaller = vi.fn(() => PASSWORD_FIDO_OWNER);
    const matchDeviceCaller = vi.fn(() => undefined);
    const complete = vi.fn(async () => {
      throw new AppError('session_expired', 'invalid assertion');
    });
    const password = interactiveTwoFactorBroker({ matchCaller: matchPasswordCaller, complete });
    const deviceLogin = interactiveTwoFactorBroker({ matchCaller: matchDeviceCaller });
    const finish = vi.fn(async () => {});
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      interactiveTwoFactor: { password, deviceLogin },
      fido2Connector: {
        open: vi.fn(async () => ({
          tabId: connectorContext.tabId,
          documentId: connectorContext.documentId,
          url: connectorContext.url,
        })),
        close: vi.fn(async () => {}),
        finish,
      },
    });

    await expect(router.handle({
      type: 'auth.completeFido2', token: '{}', remember: false,
    }, connectorContext)).resolves.toEqual({
      ok: false,
      error: { code: 'session_expired', message: 'invalid assertion' },
    });
    const callerBinding = {
      url: connectorContext.url,
      tabId: connectorContext.tabId,
      documentId: connectorContext.documentId,
    };
    expect(matchPasswordCaller).toHaveBeenCalledWith(callerBinding);
    expect(matchDeviceCaller).toHaveBeenCalledWith(callerBinding);
    expect(complete).toHaveBeenCalledWith({
      owner: PASSWORD_FIDO_OWNER,
      ...callerBinding,
      token: '{}',
      remember: false,
    });
    expect(finish).toHaveBeenCalledWith({
      url: connectorContext.url,
      tabId: connectorContext.tabId,
      documentId: connectorContext.documentId,
    }, 'error');
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

  it('uses the browser-owned content URL when routing autofill.findCandidates', async () => {
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
    await expect(router.handle(
      { type: 'autofill.findCandidates', purpose: 'login' },
      CONTENT_CONTEXT,
    ))
      .resolves.toEqual({ ok: true, data: [{
        id: '1',
        name: 'Example',
        username: 'me@example.com',
        matchedUri: 'https://example.com',
        matchType: 0,
        favorite: false,
      }] });
    expect(findAutofillCandidates).toHaveBeenCalledWith('https://sender.example/login', 0, 'login');
  });

  it('issues and redeems login data against the browser-owned document context', async () => {
    const findAutofillCandidates = vi.fn(async () => [{
      id: '1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
    }]);
    const getInteractiveAutofillLoginData = vi.fn(async () => ({
      login: { username: 'me@example.com', password: 'secret' },
      customAssignments: [],
    }));
    const router = createRouter({
      auth: {},
      vault: { findAutofillCandidates, getInteractiveAutofillLoginData },
      settings: {
        getServerUrl: vi.fn(),
        saveServerUrl: vi.fn(),
        getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 1),
        saveDefaultUriMatchStrategy: vi.fn(),
        getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
        saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
      },
    });
    const issued = await router.handle(loginIntentRequest(), CONTENT_CONTEXT);
    expect(issued.ok).toBe(true);
    const token = intentId(issued);

    await expect(router.handle(
      { type: 'autofill.redeemLoginIntent', intentId: token },
      CONTENT_CONTEXT,
    )).resolves.toEqual({
      ok: true,
      data: { login: { username: 'me@example.com', password: 'secret' }, customAssignments: [] },
    });
    expect(findAutofillCandidates).toHaveBeenCalledWith(CONTENT_CONTEXT.url, 1, 'login');
    expect(getInteractiveAutofillLoginData).toHaveBeenCalledWith(
      '1', CONTENT_CONTEXT.url, 1, EMPTY_LOGIN_CUSTOM_PLAN, undefined, expect.any(Function),
    );
  });

  it('issues an owner-bound TOTP copy ACK without returning the TOTP code', async () => {
    const copies = totpCopyHarness();
    let vaultCurrent = true;
    const getAutofillTotpData = vi.fn(async (
      _id, _url, _strategy, bindFinalAuthority?: (assertCurrent: () => void) => void,
    ) => {
      bindFinalAuthority?.(() => {
        if (!vaultCurrent) throw new AppError('denied', 'TOTP authority changed');
      });
      return { code: '654321', period: 30, remaining: 12 };
    });
    const router = createRouter({
      auth: {},
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: '1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
        }]),
        getInteractiveAutofillLoginData: vi.fn(async () => ({
          login: { username: 'me@example.com', password: 'secret' }, customAssignments: [],
        })),
        getAutofillTotpData,
      },
      settings: intentSettings(),
      autofillTotpCopies: copies.autofillTotpCopies,
    });
    const token = intentId(await router.handle(loginIntentRequest(), CONTENT_CONTEXT));

    const response = await router.handle({ type: 'autofill.redeemLoginIntent', intentId: token }, CONTENT_CONTEXT);

    expect(response).toMatchObject({ ok: true, data: { totpCopyAckId: copies.ackId } });
    expect(JSON.stringify(response)).not.toContain('654321');
    expect(copies.autofillTotpCopies.issueContent).toHaveBeenCalledWith(
      { tabId: 7, frameId: 0, documentId: 'doc-1' },
      '654321',
      expect.any(Function),
    );
    copies.getAssertCurrent()?.();
    vaultCurrent = false;
    expect(() => copies.getAssertCurrent()?.()).toThrow('TOTP authority changed');
  });

  it('issues the same opaque TOTP copy ACK for page-load login redemption', async () => {
    const copies = totpCopyHarness();
    const settings = intentSettings();
    settings.getAutofillSettings = vi.fn(async () => ({
      ...DEFAULT_AUTOFILL_SETTINGS, pageLoadFill: true,
    }));
    const router = createRouter({
      auth: {},
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: 'page-login', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
        }]),
        getAutofillLoginData: vi.fn(async () => ({ password: 'secret' })),
        getAutofillTotpData: vi.fn(async () => ({ code: 'B2CDX', period: 30, remaining: 12 })),
      },
      settings,
      autofillTotpCopies: copies.autofillTotpCopies,
    });
    const token = intentId(await router.handle({ type: 'autofill.issuePageLoadIntent' }, CONTENT_CONTEXT));

    const response = await router.handle({ type: 'autofill.redeemPageLoadIntent', intentId: token }, CONTENT_CONTEXT);

    expect(response).toMatchObject({ ok: true, data: { totpCopyAckId: copies.ackId } });
    expect(JSON.stringify(response)).not.toContain('B2CDX');
  });

  it('does not read or issue TOTP copy state when automatic copying is disabled', async () => {
    const copies = totpCopyHarness();
    const settings = intentSettings();
    settings.getAutofillSettings = vi.fn(async () => ({
      ...DEFAULT_AUTOFILL_SETTINGS, autoCopyTotp: false,
    }));
    const getAutofillTotpData = vi.fn(async () => ({ code: '654321', period: 30, remaining: 12 }));
    const router = createRouter({
      auth: {},
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: '1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
        }]),
        getInteractiveAutofillLoginData: vi.fn(async () => ({
          login: { password: 'secret' }, customAssignments: [],
        })),
        getAutofillTotpData,
      },
      settings,
      autofillTotpCopies: copies.autofillTotpCopies,
    });
    const token = intentId(await router.handle(loginIntentRequest(), CONTENT_CONTEXT));

    const response = await router.handle({ type: 'autofill.redeemLoginIntent', intentId: token }, CONTENT_CONTEXT);

    expect(response).toMatchObject({ ok: true });
    expect(response.ok && response.data).not.toHaveProperty('totpCopyAckId');
    expect(getAutofillTotpData).not.toHaveBeenCalled();
    expect(copies.autofillTotpCopies.issueContent).not.toHaveBeenCalled();
  });

  it('derives the TOTP copy ACK consumer owner only from the content RequestContext', async () => {
    const copies = totpCopyHarness();
    const router = createRouter({
      auth: {}, vault: {}, settings: intentSettings(),
      autofillTotpCopies: copies.autofillTotpCopies,
    });

    await expect(router.handle({
      type: 'autofill.ackTotpCopy', ackId: copies.ackId,
    }, CONTENT_CONTEXT)).resolves.toEqual({ ok: true, data: { copied: true } });
    expect(copies.autofillTotpCopies.consumeContent).toHaveBeenCalledWith(copies.ackId, {
      tabId: CONTENT_CONTEXT.tabId,
      frameId: CONTENT_CONTEXT.frameId,
      documentId: CONTENT_CONTEXT.documentId,
    });
  });

  it('revokes pending TOTP copy ACKs before changing autofill settings', async () => {
    const copies = totpCopyHarness();
    const settings = intentSettings();
    settings.saveAutofillPolicySettings = vi.fn(async () => {});
    const router = createRouter({
      auth: {}, vault: {}, settings,
      autofillTotpCopies: copies.autofillTotpCopies,
    });

    await expect(router.handle({
      type: 'settings.save',
      autofillSettings: {
        ...DEFAULT_AUTOFILL_SETTINGS,
        autoCopyTotp: false,
        pageLoadFillDefault: true,
      },
    }, OPTIONS_PAGE_CONTEXT)).resolves.toEqual({ ok: true, data: null });
    expect(copies.autofillTotpCopies.revokeAll).toHaveBeenCalledOnce();
  });

  it('uses the managed Host default for interactive intent issue and redemption', async () => {
    const findAutofillCandidates = vi.fn(async () => [{
      id: 'interactive-login',
      name: 'Interactive',
      matchedUri: CONTENT_CONTEXT.url,
      matchType: UriMatchStrategy.Host,
      favorite: false,
    }]);
    const getInteractiveAutofillLoginData = vi.fn(async () => ({
      login: { username: 'user', password: 'secret' },
      customAssignments: [],
    }));
    const enterprise = enterprisePolicyControl({
      uriMatch: uriMatchDefaultsPolicy(UriMatchStrategy.Host),
    });
    const router = createRouter({
      auth: {},
      vault: { findAutofillCandidates, getInteractiveAutofillLoginData },
      settings: intentSettings(UriMatchStrategy.Domain),
      enterprisePolicyGate: enterprise.gate,
    });

    const token = intentId(await router.handle(
      loginIntentRequest('interactive-login'),
      CONTENT_CONTEXT,
    ));
    await expect(router.handle({
      type: 'autofill.redeemLoginIntent',
      intentId: token,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: true });

    expect(findAutofillCandidates).toHaveBeenCalledWith(
      CONTENT_CONTEXT.url,
      UriMatchStrategy.Host,
      'login',
    );
    expect(getInteractiveAutofillLoginData).toHaveBeenCalledWith(
      'interactive-login',
      CONTENT_CONTEXT.url,
      UriMatchStrategy.Host,
      EMPTY_LOGIN_CUSTOM_PLAN,
      undefined,
      expect.any(Function),
    );
  });

  it('uses the managed Exact default throughout a keyboard grant and intent', async () => {
    const findAutofillCandidates = vi.fn(async () => [{
      id: 'keyboard-login',
      name: 'Keyboard',
      matchedUri: CONTENT_CONTEXT.url,
      matchType: UriMatchStrategy.Exact,
      favorite: false,
    }]);
    const getInteractiveAutofillLoginData = vi.fn(async () => ({
      login: { password: 'secret' }, customAssignments: [],
    }));
    const enterprise = enterprisePolicyControl({
      uriMatch: uriMatchDefaultsPolicy(UriMatchStrategy.Exact),
    });
    const router = createRouter({
      auth: {},
      vault: { findAutofillCandidates, getInteractiveAutofillLoginData },
      settings: intentSettings(UriMatchStrategy.Domain),
      enterprisePolicyGate: enterprise.gate,
    });
    const commandToken = router.keyboardGrants.issueCommand({
      tabId: CONTENT_CONTEXT.tabId,
      topDocumentId: CONTENT_CONTEXT.documentId,
      topFrameUrl: CONTENT_CONTEXT.url,
      sessionLease: router.captureSessionLease(),
    });
    const grant = keyboardGrantId(await router.handle({
      type: 'autofill.claimKeyboardGrant',
      commandToken,
      binding: { purpose: 'login', customPlan: EMPTY_LOGIN_CUSTOM_PLAN },
    }, CONTENT_CONTEXT));

    await expect(router.handle({
      type: 'autofill.keyboard.findCandidates',
      keyboardGrantId: grant,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: true });
    const token = intentId(await router.handle({
      type: 'autofill.keyboard.issueIntent',
      keyboardGrantId: grant,
      cipherId: 'keyboard-login',
    }, CONTENT_CONTEXT));
    await expect(router.handle({
      type: 'autofill.keyboard.redeemLoginIntent',
      intentId: token,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: true });

    expect(findAutofillCandidates).toHaveBeenCalledWith(
      CONTENT_CONTEXT.url,
      UriMatchStrategy.Exact,
      'login',
    );
    expect(getInteractiveAutofillLoginData).toHaveBeenCalledWith(
      'keyboard-login',
      CONTENT_CONTEXT.url,
      UriMatchStrategy.Exact,
      EMPTY_LOGIN_CUSTOM_PLAN,
      undefined,
      expect.any(Function),
    );
  });

  it('passes the managed Never default through page-load issue and uniqueness recheck', async () => {
    const findAutofillCandidates = vi.fn(async () => [{
      id: 'page-load-login',
      name: 'Page load',
      matchedUri: CONTENT_CONTEXT.url,
      matchType: UriMatchStrategy.Never,
      favorite: false,
    }]);
    const getAutofillLoginData = vi.fn(async () => ({ password: 'secret' }));
    const settings = intentSettings(UriMatchStrategy.Domain);
    settings.getAutofillSettings = vi.fn(async () => ({
      ...DEFAULT_AUTOFILL_SETTINGS,
      pageLoadFill: true,
    }));
    const enterprise = enterprisePolicyControl({
      uriMatch: uriMatchDefaultsPolicy(UriMatchStrategy.Never),
    });
    const router = createRouter({
      auth: {},
      vault: { findAutofillCandidates, getAutofillLoginData },
      settings,
      enterprisePolicyGate: enterprise.gate,
    });

    const token = intentId(await router.handle({
      type: 'autofill.issuePageLoadIntent',
    }, CONTENT_CONTEXT));
    await expect(router.handle({
      type: 'autofill.redeemPageLoadIntent',
      intentId: token,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: true });

    expect(findAutofillCandidates).toHaveBeenCalledTimes(2);
    expect(findAutofillCandidates).toHaveBeenNthCalledWith(
      1,
      CONTENT_CONTEXT.url,
      UriMatchStrategy.Never,
      'login',
      'page-load',
      true,
    );
    expect(findAutofillCandidates).toHaveBeenNthCalledWith(
      2,
      CONTENT_CONTEXT.url,
      UriMatchStrategy.Never,
      'login',
      'page-load',
      true,
    );
    expect(getAutofillLoginData).toHaveBeenCalledWith(
      'page-load-login',
      CONTENT_CONTEXT.url,
      UriMatchStrategy.Never,
      { requireUnique: true, channel: 'page-load', pageLoadFillDefault: true },
      expect.any(Function),
    );
  });

  it.each([
    {
      label: 'save',
      strategy: UriMatchStrategy.Host,
      decision: { action: 'save' as const, suggestedName: 'Example' },
    },
    {
      label: 'update',
      strategy: UriMatchStrategy.Exact,
      decision: { action: 'update' as const, cipherId: 'cipher-id', name: 'Example' },
    },
  ])('uses the managed $strategy default for $label prompt classification and commit', async ({
    strategy,
    decision,
  }) => {
    const credentials = { username: 'user', password: 'new-password' };
    const checkSaveLogin = vi.fn(async () => decision);
    const commitCapturedLogin = vi.fn(async (
      ...args: Parameters<NonNullable<RouterDeps['vault']['commitCapturedLogin']>>
    ) => {
      args[4]?.();
      return { items: [], folders: [], collections: [], orgPermissions: [] };
    });
    const enterprise = enterprisePolicyControl({
      uriMatch: uriMatchDefaultsPolicy(strategy),
    });
    const router = createRouter({
      auth: {},
      vault: { checkSaveLogin, commitCapturedLogin },
      settings: intentSettings(UriMatchStrategy.Domain),
      enterprisePolicyGate: enterprise.gate,
    });

    await expect(router.handle({
      type: 'autofill.captureSubmission',
      ...credentials,
    }, CONTENT_CONTEXT)).resolves.toEqual({ ok: true, data: null });
    const token = promptId(await router.handle(
      { type: 'autofill.claimSavePrompt' },
      CONTENT_CONTEXT,
    ));
    await expect(router.handle({
      type: 'autofill.commitSavePrompt',
      promptId: token,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: true });

    expect(checkSaveLogin).toHaveBeenCalledWith(CONTENT_CONTEXT.url, credentials, strategy);
    expect(commitCapturedLogin).toHaveBeenCalledWith(
      CONTENT_CONTEXT.url,
      credentials,
      strategy,
      decision,
      expect.any(Function),
    );
  });

  it('does not revive an old interactive intent after an enterprise Host-Exact-Host transition', async () => {
    const getInteractiveAutofillLoginData = vi.fn(async () => ({
      login: { password: 'secret' }, customAssignments: [],
    }));
    const enterprise = enterprisePolicyControl({
      uriMatch: uriMatchDefaultsPolicy(UriMatchStrategy.Host),
    });
    const router = createRouter({
      auth: {},
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: 'stale-login',
          name: 'Stale',
          matchedUri: CONTENT_CONTEXT.url,
          matchType: UriMatchStrategy.Host,
          favorite: false,
        }]),
        getInteractiveAutofillLoginData,
      },
      settings: intentSettings(UriMatchStrategy.Domain),
      enterprisePolicyGate: enterprise.gate,
    });
    const stale = intentId(await router.handle(
      loginIntentRequest('stale-login'),
      CONTENT_CONTEXT,
    ));

    enterprise.replaceUriMatch(uriMatchDefaultsPolicy(UriMatchStrategy.Exact));
    enterprise.replaceUriMatch(uriMatchDefaultsPolicy(UriMatchStrategy.Host));

    await expect(router.handle({
      type: 'autofill.redeemLoginIntent',
      intentId: stale,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(getInteractiveAutofillLoginData).not.toHaveBeenCalled();
  });

  it.each(['login', 'totp'] as const)(
    'uses a browser-command grant for %s while ordinary inline requests remain disabled',
    async (purpose) => {
      const settings = intentSettings();
      settings.getAutofillSettings = vi.fn(async () => ({
        ...DEFAULT_AUTOFILL_SETTINGS,
        inlineSuggestions: false,
        pageLoadFill: false,
      }));
      const findAutofillCandidates = vi.fn(async () => [{
        id: 'login-1',
        name: 'Example',
        matchedUri: CONTENT_CONTEXT.url,
        matchType: 0 as const,
        favorite: false,
        ...(purpose === 'totp' ? { hasTotp: true } : {}),
      }]);
      const router = createRouter({
        auth: {},
        vault: {
          findAutofillCandidates,
          getInteractiveAutofillLoginData: vi.fn(async () => ({
            login: { username: 'user', password: 'secret' }, customAssignments: [],
          })),
          getAutofillTotpData: vi.fn(async () => ({ code: '123456', period: 30, remaining: 10 })),
        },
        settings,
      });
      const commandToken = router.keyboardGrants.issueCommand({
        tabId: CONTENT_CONTEXT.tabId,
        topDocumentId: CONTENT_CONTEXT.documentId,
        topFrameUrl: CONTENT_CONTEXT.url,
        sessionLease: router.captureSessionLease(),
      });
      const grant = keyboardGrantId(await router.handle({
        type: 'autofill.claimKeyboardGrant',
        commandToken,
        binding: purpose === 'login'
          ? { purpose, customPlan: EMPTY_LOGIN_CUSTOM_PLAN }
          : { purpose },
      }, CONTENT_CONTEXT));

      await expect(router.handle({
        type: 'autofill.findCandidates', purpose,
      }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
      await expect(router.handle({
        type: 'autofill.keyboard.findCandidates', keyboardGrantId: grant,
      }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: true, data: [{ id: 'login-1' }] });
      const intent = intentId(await router.handle({
        type: 'autofill.keyboard.issueIntent', keyboardGrantId: grant, cipherId: 'login-1',
      }, CONTENT_CONTEXT));
      await expect(router.handle({
        type: 'autofill.keyboard.issueIntent', keyboardGrantId: grant, cipherId: 'login-1',
      }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });

      const redemption = purpose === 'login'
        ? await router.handle({ type: 'autofill.keyboard.redeemLoginIntent', intentId: intent }, CONTENT_CONTEXT)
        : await router.handle({ type: 'autofill.keyboard.redeemTotpIntent', intentId: intent }, CONTENT_CONTEXT);
      expect(redemption).toMatchObject(purpose === 'login'
        ? { ok: true, data: { login: { password: 'secret' } } }
        : { ok: true, data: { totp: { code: '123456' } } });
      expect(findAutofillCandidates).toHaveBeenCalledWith(CONTENT_CONTEXT.url, 0, purpose);
    },
  );

  it.each(['card', 'identity'] as const)(
    'uses a browser-command grant for %s with exact document and form metadata',
    async (purpose) => {
      const settings = intentSettings();
      settings.getAutofillSettings = vi.fn(async () => ({
        ...DEFAULT_AUTOFILL_SETTINGS,
        inlineSuggestions: false,
        pageLoadFill: false,
      }));
      const target = purpose === 'card'
        ? STRUCTURED_TARGET
        : {
            kind: 'identity' as const,
            runtimeIncarnation: TEST_RUNTIME_INCARNATION,
            formId: 'identity-form',
            generation: 8,
            roles: ['firstName', 'lastName', 'email'] as const,
          };
      const findFillItems = vi.fn(async () => [{ id: `${purpose}-1`, name: 'Item', favorite: false }]);
      const fill = vi.fn(async (
        _tabId: number,
        _cipherId: string,
        _target: unknown,
        assertExternalCurrent?: () => void,
      ) => {
        assertExternalCurrent?.();
        return { status: 'filled' as const };
      });
      const router = createRouter({
        auth: {},
        vault: { findFillItems },
        tabAutofill: { getSuggestions: vi.fn(), fill },
        settings,
      });
      const commandToken = router.keyboardGrants.issueCommand({
        tabId: CONTENT_CONTEXT.tabId,
        topDocumentId: CONTENT_CONTEXT.documentId,
        topFrameUrl: CONTENT_CONTEXT.url,
        sessionLease: router.captureSessionLease(),
      });
      const grant = keyboardGrantId(await router.handle({
        type: 'autofill.claimKeyboardGrant',
        commandToken,
        binding: { purpose, structuredTarget: target },
      }, CONTENT_CONTEXT));

      await expect(router.handle({
        type: 'autofill.findStructuredCandidates', kind: purpose,
      }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
      await expect(router.handle({
        type: 'autofill.keyboard.findCandidates', keyboardGrantId: grant,
      }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: true, data: [{ id: `${purpose}-1` }] });
      const intent = intentId(await router.handle({
        type: 'autofill.keyboard.issueIntent', keyboardGrantId: grant, cipherId: `${purpose}-1`,
      }, CONTENT_CONTEXT));
      await expect(router.handle({
        type: 'autofill.keyboard.redeemStructuredIntent', intentId: intent, target,
      }, CONTENT_CONTEXT)).resolves.toEqual({ ok: true, data: { outcome: { status: 'filled' } } });
      expect(fill).toHaveBeenCalledWith(CONTENT_CONTEXT.tabId, `${purpose}-1`, {
        ...target,
        frameId: CONTENT_CONTEXT.frameId,
        documentId: CONTENT_CONTEXT.documentId,
      }, expect.any(Function));
    },
  );

  it('consumes command and grant capabilities when the browser top document changes', async () => {
    let top = { documentId: CONTENT_CONTEXT.documentId, url: CONTENT_CONTEXT.url };
    const router = createRouter({
      auth: {},
      vault: { findAutofillCandidates: vi.fn(async () => []) },
      settings: intentSettings(),
      getKeyboardTopDocument: vi.fn(async () => top),
    });
    const issueCommand = () => router.keyboardGrants.issueCommand({
      tabId: CONTENT_CONTEXT.tabId,
      topDocumentId: CONTENT_CONTEXT.documentId,
      topFrameUrl: CONTENT_CONTEXT.url,
      sessionLease: router.captureSessionLease(),
    });
    const first = issueCommand();
    top = { documentId: 'new-top', url: 'https://sender.example/other' };
    await expect(router.handle({
      type: 'autofill.claimKeyboardGrant', commandToken: first, binding: { purpose: 'totp' },
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    top = { documentId: CONTENT_CONTEXT.documentId, url: CONTENT_CONTEXT.url };
    await expect(router.handle({
      type: 'autofill.claimKeyboardGrant', commandToken: first, binding: { purpose: 'totp' },
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });

    const second = issueCommand();
    const grant = keyboardGrantId(await router.handle({
      type: 'autofill.claimKeyboardGrant', commandToken: second, binding: { purpose: 'totp' },
    }, CONTENT_CONTEXT));
    top = { documentId: 'new-top', url: 'https://sender.example/other' };
    await expect(router.handle({
      type: 'autofill.keyboard.findCandidates', keyboardGrantId: grant,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    top = { documentId: CONTENT_CONTEXT.documentId, url: CONTENT_CONTEXT.url };
    await expect(router.handle({
      type: 'autofill.keyboard.findCandidates', keyboardGrantId: grant,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
  });

  it('consumes a keyboard grant when another runtime presents it', async () => {
    const router = createRouter({
      auth: {},
      vault: { findAutofillCandidates: vi.fn(async () => []) },
      settings: intentSettings(),
      saveCaptureCoordinator: { isRuntimeCurrent: vi.fn(async () => true) },
    });
    const commandToken = router.keyboardGrants.issueCommand({
      tabId: CONTENT_CONTEXT.tabId,
      topDocumentId: CONTENT_CONTEXT.documentId,
      topFrameUrl: CONTENT_CONTEXT.url,
      sessionLease: router.captureSessionLease(),
    });
    const grant = keyboardGrantId(await router.handle({
      type: 'autofill.claimKeyboardGrant',
      commandToken,
      binding: { purpose: 'totp' },
    }, CONTENT_CONTEXT));

    await expect(router.handle({
      type: 'autofill.keyboard.findCandidates',
      keyboardGrantId: grant,
      runtimeIncarnation: NEXT_RUNTIME_INCARNATION,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({
      type: 'autofill.keyboard.findCandidates', keyboardGrantId: grant,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
  });

  it('lists structured metadata and redeems a bound selection through the tab coordinator', async () => {
    const findFillItems = vi.fn(async () => [{
      id: 'card-1', name: 'Primary card', subtitle: 'Visa', favorite: true,
    }]);
    const fill = vi.fn(async (
      _tabId: number,
      _cipherId: string,
      _target: unknown,
      assertExternalCurrent?: () => void,
    ) => {
      assertExternalCurrent?.();
      return { status: 'filled' as const };
    });
    const router = createRouter({
      auth: {},
      vault: { findFillItems },
      tabAutofill: { getSuggestions: vi.fn(), fill },
      settings: intentSettings(),
    });

    await expect(router.handle(
      { type: 'autofill.findStructuredCandidates', kind: 'card' },
      CONTENT_CONTEXT,
    )).resolves.toEqual({
      ok: true,
      data: [{ id: 'card-1', name: 'Primary card', subtitle: 'Visa', favorite: true }],
    });
    const token = intentId(await router.handle({
      type: 'autofill.issueStructuredIntent',
      cipherId: 'card-1',
      target: STRUCTURED_TARGET,
    }, CONTENT_CONTEXT));

    await expect(router.handle({
      type: 'autofill.redeemStructuredIntent',
      intentId: token,
      target: STRUCTURED_TARGET,
    }, CONTENT_CONTEXT)).resolves.toEqual({ ok: true, data: { outcome: { status: 'filled' } } });
    expect(fill).toHaveBeenCalledWith(7, 'card-1', {
      ...STRUCTURED_TARGET,
      frameId: 0,
      documentId: 'doc-1',
    }, expect.any(Function));
  });

  it('consumes a structured intent when the form generation does not match', async () => {
    const fill = vi.fn(async () => ({ status: 'filled' as const }));
    const router = createRouter({
      auth: {},
      vault: { findFillItems: vi.fn(async () => [{ id: 'card-1', name: 'Card', favorite: false }]) },
      tabAutofill: { getSuggestions: vi.fn(), fill },
      settings: intentSettings(),
    });
    const token = intentId(await router.handle({
      type: 'autofill.issueStructuredIntent', cipherId: 'card-1', target: STRUCTURED_TARGET,
    }, CONTENT_CONTEXT));

    await expect(router.handle({
      type: 'autofill.redeemStructuredIntent',
      intentId: token,
      target: { ...STRUCTURED_TARGET, generation: STRUCTURED_TARGET.generation + 1 },
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({
      type: 'autofill.redeemStructuredIntent', intentId: token, target: STRUCTURED_TARGET,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(fill).not.toHaveBeenCalled();
  });

  it('preserves the explicit structured selection through issue and redemption', async () => {
    const fill = vi.fn(async () => ({ status: 'filled' as const }));
    const router = createRouter({
      auth: {},
      vault: { findFillItems: vi.fn(async () => [{ id: 'card-1', name: 'Card', favorite: false }]) },
      tabAutofill: { getSuggestions: vi.fn(), fill },
      settings: intentSettings(),
    });
    const target = { ...STRUCTURED_TARGET, selectedRoles: ['number'] as const };
    const token = intentId(await router.handle({
      type: 'autofill.issueStructuredIntent', cipherId: 'card-1', target,
    }, CONTENT_CONTEXT));

    await expect(router.handle({
      type: 'autofill.redeemStructuredIntent', intentId: token, target,
    }, CONTENT_CONTEXT)).resolves.toEqual({ ok: true, data: { outcome: { status: 'filled' } } });
    expect(fill).toHaveBeenCalledWith(7, 'card-1', {
      ...target, frameId: 0, documentId: 'doc-1',
    }, expect.any(Function));
  });

  it.each([
    ['empty', []],
    ['duplicate', ['number', 'number']],
    ['noncanonical', ['code', 'number']],
    ['outside the structure', ['cardholderName']],
    ['cross-kind', ['email']],
    ['explicit undefined', undefined],
  ])('refuses an invalid %s selection before reading candidate metadata', async (_label, selectedRoles) => {
    const findFillItems = vi.fn(async () => [{ id: 'card-1', name: 'Card', favorite: false }]);
    const router = createRouter({ auth: {}, vault: { findFillItems }, settings: intentSettings() });

    await expect(router.handle({
      type: 'autofill.issueStructuredIntent', cipherId: 'card-1',
      target: { ...STRUCTURED_TARGET, selectedRoles } as never,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(findFillItems).not.toHaveBeenCalled();
  });

  it('consumes a narrowed structured capability when redemption tries to restore all roles', async () => {
    const fill = vi.fn(async () => ({ status: 'filled' as const }));
    const router = createRouter({
      auth: {},
      vault: { findFillItems: vi.fn(async () => [{ id: 'card-1', name: 'Card', favorite: false }]) },
      tabAutofill: { getSuggestions: vi.fn(), fill },
      settings: intentSettings(),
    });
    const target = { ...STRUCTURED_TARGET, selectedRoles: ['number'] as const };
    const token = intentId(await router.handle({
      type: 'autofill.issueStructuredIntent', cipherId: 'card-1', target,
    }, CONTENT_CONTEXT));

    await expect(router.handle({
      type: 'autofill.redeemStructuredIntent', intentId: token, target: STRUCTURED_TARGET,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({
      type: 'autofill.redeemStructuredIntent', intentId: token, target,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(fill).not.toHaveBeenCalled();
  });

  it('rejects a malformed or reprompt-protected structured selection before issuing a capability', async () => {
    const findFillItems = vi.fn(async () => [{ id: 'card-1', name: 'Card', favorite: false, reprompt: true }]);
    const router = createRouter({ auth: {}, vault: { findFillItems }, settings: intentSettings() });

    await expect(router.handle({
      type: 'autofill.issueStructuredIntent',
      cipherId: 'card-1',
      target: { ...STRUCTURED_TARGET, roles: ['code', 'number'] } as never,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(findFillItems).not.toHaveBeenCalled();

    await expect(router.handle({
      type: 'autofill.issueStructuredIntent', cipherId: 'card-1', target: STRUCTURED_TARGET,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'reprompt_required' } });
  });

  it('consumes an intent on a cross-purpose redemption and rejects replay', async () => {
    const router = createRouter({
      auth: {},
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: '1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
        }]),
        getAutofillLoginData: vi.fn(async () => ({ password: 'secret' })),
        getAutofillTotpData: vi.fn(async () => ({ code: '123456', period: 30, remaining: 10 })),
      },
      settings: intentSettings(),
    });
    const token = intentId(await router.handle(
      loginIntentRequest(),
      CONTENT_CONTEXT,
    ));
    const denied = { ok: false, error: { code: 'denied', message: 'Autofill intent is invalid or expired' } };

    await expect(router.handle({ type: 'autofill.redeemTotpIntent', intentId: token }, CONTENT_CONTEXT))
      .resolves.toEqual(denied);
    await expect(router.handle({ type: 'autofill.redeemLoginIntent', intentId: token }, CONTENT_CONTEXT))
      .resolves.toEqual(denied);
  });

  it('consumes an intent on a cross-document redemption', async () => {
    const getAutofillLoginData = vi.fn(async () => ({ password: 'secret' }));
    const router = createRouter({
      auth: {},
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: '1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
        }]),
        getAutofillLoginData,
      },
      settings: intentSettings(),
    });
    const token = intentId(await router.handle(
      loginIntentRequest(),
      CONTENT_CONTEXT,
    ));
    const otherDocument = { ...CONTENT_CONTEXT, documentId: 'doc-2' } satisfies RequestContext;

    await expect(router.handle({ type: 'autofill.redeemLoginIntent', intentId: token }, otherDocument))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({ type: 'autofill.redeemLoginIntent', intentId: token }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(getAutofillLoginData).not.toHaveBeenCalled();
  });

  it('consumes an intent on a cross-runtime redemption', async () => {
    const getAutofillLoginData = vi.fn(async () => ({ password: 'secret' }));
    const router = createRouter({
      auth: {},
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: '1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
        }]),
        getAutofillLoginData,
      },
      settings: intentSettings(),
      saveCaptureCoordinator: { isRuntimeCurrent: vi.fn(async () => true) },
    });
    const token = intentId(await router.handle(loginIntentRequest(), CONTENT_CONTEXT));

    await expect(router.handle({
      type: 'autofill.redeemLoginIntent',
      intentId: token,
      runtimeIncarnation: NEXT_RUNTIME_INCARNATION,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({
      type: 'autofill.redeemLoginIntent', intentId: token,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(getAutofillLoginData).not.toHaveBeenCalled();
  });

  it('returns only current TOTP data through a TOTP intent', async () => {
    const getAutofillLoginData = vi.fn(async () => ({ password: 'must-not-read' }));
    const getAutofillTotpData = vi.fn(async () => ({ code: '654321', period: 30, remaining: 17 }));
    const router = createRouter({
      auth: {},
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: '1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false, hasTotp: true,
        }]),
        getAutofillLoginData,
        getAutofillTotpData,
      },
      settings: intentSettings(),
    });
    const token = intentId(await router.handle(
      { type: 'autofill.issueIntent', cipherId: '1', purpose: 'totp' },
      CONTENT_CONTEXT,
    ));

    await expect(router.handle({ type: 'autofill.redeemTotpIntent', intentId: token }, CONTENT_CONTEXT))
      .resolves.toEqual({ ok: true, data: { totp: { code: '654321', period: 30, remaining: 17 } } });
    expect(getAutofillTotpData).toHaveBeenCalledWith(
      '1', CONTENT_CONTEXT.url, 0, expect.any(Function),
    );
    expect(getAutofillLoginData).not.toHaveBeenCalled();
  });

  it('consumes an intent when its account lease becomes stale', async () => {
    let accountGeneration = 0;
    const accountGate: RouterDeps['accountGate'] = {
      capture: () => ({
        serverGeneration: 0,
        accountGeneration,
        serverUrl: 'https://vault.example',
        accountIdentity: accountGeneration === 0 ? 'a@example.com' : 'b@example.com',
      }),
      assert: (lease) => {
        if (lease.accountGeneration !== accountGeneration) throw new AppError('session_expired', 'account changed');
      },
    };
    const getAutofillLoginData = vi.fn(async () => ({ password: 'secret' }));
    const router = createRouter({
      auth: {},
      accountGate,
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: '1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
        }]),
        getAutofillLoginData,
      },
      settings: intentSettings(),
    });
    const token = intentId(await router.handle(
      loginIntentRequest(),
      CONTENT_CONTEXT,
    ));
    accountGeneration = 1;

    await expect(router.handle({ type: 'autofill.redeemLoginIntent', intentId: token }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(getAutofillLoginData).not.toHaveBeenCalled();
  });

  it('consumes a locked-session intent before the global session gate can reject it', async () => {
    let unlocked = true;
    const sessionGate: RouterDeps['sessionGate'] = {
      capture: () => {
        if (!unlocked) throw new AppError('locked', 'locked');
        return { generation: 0 };
      },
      assert: () => {
        if (!unlocked) throw new AppError('locked', 'locked');
      },
    };
    const getAutofillLoginData = vi.fn(async () => ({ password: 'secret' }));
    const router = createRouter({
      auth: {},
      sessionGate,
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: '1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
        }]),
        getAutofillLoginData,
      },
      settings: intentSettings(),
    });
    const token = intentId(await router.handle(
      loginIntentRequest(),
      CONTENT_CONTEXT,
    ));
    unlocked = false;
    await expect(router.handle({ type: 'autofill.redeemLoginIntent', intentId: token }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    unlocked = true;
    await expect(router.handle({ type: 'autofill.redeemLoginIntent', intentId: token }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(getAutofillLoginData).not.toHaveBeenCalled();
  });

  it('records activity before the final assertion of the original intent session lease', async () => {
    let expired = false;
    const captures: SessionLease[] = [];
    const sessionGate: RouterDeps['sessionGate'] = {
      capture: () => {
        const lease = { generation: captures.length + 1 };
        captures.push(lease);
        return lease;
      },
      assert: (lease) => {
        if (expired) throw new AppError('locked', 'Vault session timed out');
        if (lease !== captures[0]) throw new AppError('session_expired', 'wrong lease');
      },
    };
    const recordActivity = vi.fn(async () => { expired = true; });
    const router = createRouter({
      auth: {},
      sessionGate,
      vaultTimeout: {
        captureActivity: vi.fn(() => ({
          generation: 1,
          accountKey: 'https://vault.example/\nuser@example.com',
          sessionBindingId: 'binding-a',
        })),
        recordActivity,
      },
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: '1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
        }]),
        getInteractiveAutofillLoginData: vi.fn(async () => ({
          login: { username: 'alice', password: 'secret' },
          customAssignments: [],
        })),
      },
      settings: intentSettings(),
    });
    const token = intentId(await router.handle(loginIntentRequest(), CONTENT_CONTEXT));

    await expect(router.handle({
      type: 'autofill.redeemLoginIntent', intentId: token,
    }, CONTENT_CONTEXT)).resolves.toEqual({
      ok: false,
      error: { code: 'locked', message: 'Vault session timed out' },
    });

    expect(recordActivity).toHaveBeenCalledOnce();
    expect(captures).toHaveLength(1);
  });

  it('fails closed for blocked or malformed policy without exposing the blocklist to content', async () => {
    const findAutofillCandidates = vi.fn(async () => []);
    const settings = intentSettings();
    settings.getAutofillSettings = vi.fn(async () => ({
      ...DEFAULT_AUTOFILL_SETTINGS,
      inlineSuggestions: true,
      pageLoadFill: true,
      blockedDomains: ['sender.example'],
    }));
    const router = createRouter({ auth: {}, vault: { findAutofillCandidates }, settings });

    await expect(router.handle({ type: 'autofill.findCandidates', purpose: 'login' }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    const config = await router.handle({ type: 'autofill.getClientConfig' }, CONTENT_CONTEXT);
    expect(config).toEqual({
      ok: true,
      data: {
        inlineSuggestions: false,
        pageLoadFill: false,
        saveAllowed: false,
        updateAllowed: false,
        generatorAllowed: false,
        generator: createGeneratorPolicySnapshot(null, 0),
      },
    });
    expect(JSON.stringify(config)).not.toContain('sender.example');
    expect(findAutofillCandidates).not.toHaveBeenCalled();

    settings.getAutofillSettings = vi.fn(async () => { throw new Error('corrupt'); });
    await expect(router.handle({ type: 'autofill.getClientConfig' }, CONTENT_CONTEXT))
      .resolves.toEqual({
        ok: true,
        data: {
          inlineSuggestions: false,
          pageLoadFill: false,
          saveAllowed: false,
          updateAllowed: false,
          generatorAllowed: false,
          generator: UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
        },
      });
  });

  it('keeps autofill enabled while independently applying prompt toggles and save-only exclusions', async () => {
    let policy: AutofillPolicySettings = {
      schemaVersion: AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
      defaultUriMatchStrategy: 0,
      pageLoadFillDefault: true,
      ...DEFAULT_AUTOFILL_SETTINGS,
      pageLoadFill: true,
      savePromptEnabled: false,
      updatePromptEnabled: true,
    };
    const settings = intentSettings();
    settings.getAutofillPolicySettings = vi.fn(async () => policy);
    const findAutofillCandidates = vi.fn(async () => []);
    const router = createRouter({ auth: {}, vault: { findAutofillCandidates }, settings });

    await expect(router.handle({ type: 'autofill.getClientConfig' }, CONTENT_CONTEXT)).resolves.toEqual({
      ok: true,
      data: {
        inlineSuggestions: true,
        pageLoadFill: true,
        saveAllowed: false,
        updateAllowed: true,
        generatorAllowed: true,
        generator: createGeneratorPolicySnapshot(null, 0),
      },
    });
    await expect(router.handle(
      { type: 'autofill.findCandidates', purpose: 'login' },
      CONTENT_CONTEXT,
    )).resolves.toEqual({ ok: true, data: [] });

    policy = {
      ...policy,
      savePromptEnabled: true,
      updatePromptEnabled: true,
      savePromptExcludedDomains: ['sender.example'],
    };
    await expect(router.handle({ type: 'autofill.getClientConfig' }, CONTENT_CONTEXT)).resolves.toEqual({
      ok: true,
      data: {
        inlineSuggestions: true,
        pageLoadFill: true,
        saveAllowed: false,
        updateAllowed: false,
        generatorAllowed: true,
        generator: createGeneratorPolicySnapshot(null, 0),
      },
    });
    await expect(router.handle(
      { type: 'autofill.findCandidates', purpose: 'login' },
      CONTENT_CONTEXT,
    )).resolves.toEqual({ ok: true, data: [] });
    expect(findAutofillCandidates).toHaveBeenCalledTimes(2);
  });

  it.each([
    {
      label: 'save',
      settings: { savePromptEnabled: false, updatePromptEnabled: true },
      decision: { action: 'save' as const, suggestedName: 'Example' },
    },
    {
      label: 'update',
      settings: { savePromptEnabled: true, updatePromptEnabled: false },
      decision: { action: 'update' as const, cipherId: 'cipher-1', name: 'Example' },
    },
    {
      label: 'add URI',
      settings: { savePromptEnabled: true, updatePromptEnabled: false },
      decision: { action: 'addUri' as const, cipherId: 'cipher-1', name: 'Example' },
    },
  ])('drops a classified $label prompt when only the other prompt type is enabled', async ({ settings: flags, decision }) => {
    const settings = intentSettings();
    settings.getAutofillSettings = vi.fn(async () => ({
      ...DEFAULT_AUTOFILL_SETTINGS,
      ...flags,
    }));
    const checkSaveLogin = vi.fn(async () => decision);
    const router = createRouter({ auth: {}, vault: { checkSaveLogin }, settings });

    await expect(router.handle(
      { type: 'autofill.captureSubmission', password: 'password' },
      CONTENT_CONTEXT,
    )).resolves.toEqual({ ok: true, data: null });
    await expect(router.handle(
      { type: 'autofill.claimSavePrompt' },
      CONTENT_CONTEXT,
    )).resolves.toEqual({ ok: true, data: { action: 'none' } });
    await expect(router.handle(
      { type: 'autofill.claimSavePrompt' },
      CONTENT_CONTEXT,
    )).resolves.toEqual({ ok: true, data: { action: 'none' } });
    expect(checkSaveLogin).toHaveBeenCalledOnce();
  });

  it('blocks capture on a save-only excluded site without blocking ordinary autofill', async () => {
    const settings = intentSettings();
    settings.getAutofillSettings = vi.fn(async () => ({
      ...DEFAULT_AUTOFILL_SETTINGS,
      savePromptExcludedDomains: ['sender.example'],
    }));
    const findAutofillCandidates = vi.fn(async () => []);
    const checkSaveLogin = vi.fn();
    const router = createRouter({ auth: {}, vault: { findAutofillCandidates, checkSaveLogin }, settings });

    await expect(router.handle(
      { type: 'autofill.captureSubmission', password: 'password' },
      CONTENT_CONTEXT,
    )).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle(
      { type: 'autofill.findCandidates', purpose: 'login' },
      CONTENT_CONTEXT,
    )).resolves.toEqual({ ok: true, data: [] });
    expect(findAutofillCandidates).toHaveBeenCalledOnce();
    expect(checkSaveLogin).not.toHaveBeenCalled();
  });

  it('issues a top-frame-only page-load intent and rechecks uniqueness on redemption', async () => {
    const findAutofillCandidates = vi.fn(async () => [{
      id: 'login-1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
    }]);
    const getAutofillLoginData = vi.fn(async () => ({ username: 'user', password: 'secret' }));
    const settings = intentSettings();
    settings.getAutofillSettings = vi.fn(async () => ({
      ...DEFAULT_AUTOFILL_SETTINGS,
      inlineSuggestions: true,
      pageLoadFill: true,
    }));
    const vaultTimeout: NonNullable<RouterDeps['vaultTimeout']> = {
      captureActivity: vi.fn(() => ({
        generation: 1,
        accountKey: 'https://vault.example/\nuser@example.com',
        sessionBindingId: 'binding-a',
      })),
      recordActivity: vi.fn(async () => undefined),
    };
    const router = createRouter({
      auth: {},
      vault: { findAutofillCandidates, getAutofillLoginData },
      settings,
      vaultTimeout,
    });
    const token = intentId(await router.handle({ type: 'autofill.issuePageLoadIntent' }, CONTENT_CONTEXT));
    expect(findAutofillCandidates).toHaveBeenCalledWith(
      CONTENT_CONTEXT.url,
      0,
      'login',
      'page-load',
      true,
    );

    await expect(router.handle({ type: 'autofill.redeemPageLoadIntent', intentId: token }, CONTENT_CONTEXT))
      .resolves.toEqual({ ok: true, data: { login: { username: 'user', password: 'secret' } } });
    expect(getAutofillLoginData).toHaveBeenCalledWith(
      'login-1',
      CONTENT_CONTEXT.url,
      0,
      { requireUnique: true, channel: 'page-load', pageLoadFillDefault: true },
      expect.any(Function),
    );
    expect(vaultTimeout.captureActivity).not.toHaveBeenCalled();
    expect(vaultTimeout.recordActivity).not.toHaveBeenCalled();

    const iframe = { ...CONTENT_CONTEXT, frameId: 2, documentId: 'iframe-doc' } satisfies RequestContext;
    await expect(router.handle({ type: 'autofill.issuePageLoadIntent' }, iframe))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({ type: 'autofill.getClientConfig' }, iframe))
      .resolves.toMatchObject({ ok: true, data: { pageLoadFill: false } });
  });

  it('deduplicates page-load intents per exact browser document URL including URL ABA', async () => {
    const settings = intentSettings();
    settings.getAutofillSettings = vi.fn(async () => ({
      ...DEFAULT_AUTOFILL_SETTINGS,
      pageLoadFill: true,
    }));
    const router = createRouter({
      auth: {},
      settings,
      vault: {
        findAutofillCandidates: vi.fn(async (url) => [{
          id: url,
          name: 'Example',
          matchedUri: url,
          matchType: 0 as const,
          favorite: false,
        }]),
      },
    });
    const urlB = {
      ...CONTENT_CONTEXT,
      url: 'https://sender.example/account',
    } satisfies RequestContext;

    await expect(router.handle({ type: 'autofill.issuePageLoadIntent' }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: true });
    await expect(router.handle({ type: 'autofill.issuePageLoadIntent' }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({ type: 'autofill.issuePageLoadIntent' }, urlB))
      .resolves.toMatchObject({ ok: true });
    await expect(router.handle({ type: 'autofill.issuePageLoadIntent' }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
  });

  it('withholds page-load secrets when the durable release checkpoint fails', async () => {
    const settings = intentSettings();
    settings.getAutofillSettings = vi.fn(async () => ({
      ...DEFAULT_AUTOFILL_SETTINGS,
      pageLoadFill: true,
    }));
    const checkpoint = vi.fn(async () => { throw new AppError('locked', 'checkpoint failed'); });
    const vaultReleaseGate: NonNullable<RouterDeps['vaultReleaseGate']> = {
      capture: vi.fn(() => ({ sessionLease: { generation: 0 }, timeoutLease: {} } as never)),
      checkpoint,
      assertAuthorities: vi.fn((_proof, assertCurrent) => assertCurrent()),
      assert: vi.fn(),
    };
    const router = createRouter({
      auth: {},
      settings,
      vaultReleaseGate,
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: 'login-1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
        }]),
        getAutofillLoginData: vi.fn(async () => ({ username: 'user', password: 'secret' })),
      },
    });
    const token = intentId(await router.handle({ type: 'autofill.issuePageLoadIntent' }, CONTENT_CONTEXT));

    await expect(router.handle({
      type: 'autofill.redeemPageLoadIntent', intentId: token,
    }, CONTENT_CONTEXT)).resolves.toEqual({
      ok: false,
      error: { code: 'locked', message: 'checkpoint failed' },
    });
    expect(checkpoint).toHaveBeenCalledOnce();
    expect(vaultReleaseGate.assert).not.toHaveBeenCalled();
  });

  it.each([
    ['field', { type: 'vault.getField', id: 'c1', field: 'password' }, 'getField', 'secret'],
    ['custom field', { type: 'vault.getCustomField', id: 'c1', index: 0 }, 'getCustomField', 'secret'],
    ['cipher detail', { type: 'vault.getCipherDetail', id: 'c1' }, 'getCipherDetail', { id: 'c1', notes: 'secret' }],
    ['attachment', { type: 'vault.getAttachment', cipherId: 'c1', attachmentId: 'a1' }, 'getAttachment', { fileName: 'a.txt', dataB64: 'c2VjcmV0' }],
    ['SSH public material', { type: 'vault.getSshKeyDetails', id: 'c1' }, 'getSshKeyDetails', { publicKey: 'ssh-ed25519 AAAA', hasPrivateKey: true }],
    ['SSH private material', { type: 'vault.revealSshPrivateKey', id: 'c1' }, 'revealSshPrivateKey', 'PRIVATE'],
    ['password history', { type: 'vault.getPasswordHistory', id: 'c1' }, 'getPasswordHistory', [{ password: 'old' }]],
    ['TOTP', { type: 'vault.getTotp', id: 'c1' }, 'getTotpCode', { code: '123456', period: 30, remaining: 20 }],
    ['TOTP list', { type: 'vault.getTotpCodes' }, 'listTotpCodes', [{ id: 'c1', name: 'Login', code: '123456', period: 30, remaining: 20 }]],
    ['cipher input', { type: 'vault.getCipherInput', id: 'c1', cipherInputPurpose: 'edit' }, 'getCipherInput', { type: 1, name: 'Login', password: 'secret' }],
    ['Send plaintext', { type: 'sends.list' }, 'listSends', [{ id: 's1', name: 'Secret', text: 'secret' }]],
  ] as const)(
    'rechecks result-bound vault authority after the release checkpoint for %s',
    async (_label, request, method, result) => {
      let current = true;
      let releaseCheckpoint!: (proof: object) => void;
      const checkpointPending = new Promise<object>((resolve) => { releaseCheckpoint = resolve; });
      const read = vi.fn(async (...args: unknown[]) => {
        const bind = args.at(-1);
        if (typeof bind !== 'function') throw new Error('final authority binder is missing');
        bind(() => {
          if (!current) throw new AppError('denied', 'vault result changed');
        });
        return result;
      });
      const vaultReleaseGate: NonNullable<RouterDeps['vaultReleaseGate']> = {
        capture: vi.fn(() => ({ sessionLease: { generation: 0 }, timeoutLease: {} } as never)),
        checkpoint: vi.fn(() => checkpointPending as never),
        assertAuthorities: vi.fn((_proof, assertCurrent) => assertCurrent()),
        assert: vi.fn(),
      };
      const settings = intentSettings();
      settings.getServerUrl = vi.fn(async () => 'https://vault.example/');
      const router = createRouter({
        auth: {},
        settings,
        vaultReleaseGate,
        vault: { [method]: read } as unknown as RouterDeps['vault'],
      });

      const response = router.handle(request as RequestMessage);
      await vi.waitFor(() => expect(vaultReleaseGate.checkpoint).toHaveBeenCalledOnce());
      current = false;
      releaseCheckpoint({});

      await expect(response).resolves.toEqual({
        ok: false,
        error: { code: 'denied', message: 'vault result changed' },
      });
      expect(vaultReleaseGate.assert).not.toHaveBeenCalled();
    },
  );

  it('does not allow an interactive redeem verb to consume page-load data', async () => {
    const settings = intentSettings();
    settings.getAutofillSettings = vi.fn(async () => ({ ...DEFAULT_AUTOFILL_SETTINGS, pageLoadFill: true }));
    const router = createRouter({
      auth: {},
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: 'login-1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
        }]),
        getAutofillLoginData: vi.fn(async () => ({ password: 'secret' })),
      },
      settings,
    });
    const token = intentId(await router.handle({ type: 'autofill.issuePageLoadIntent' }, CONTENT_CONTEXT));

    await expect(router.handle({ type: 'autofill.redeemLoginIntent', intentId: token }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({ type: 'autofill.redeemPageLoadIntent', intentId: token }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
  });

  it('consumes a page-load intent when another runtime presents it', async () => {
    const settings = intentSettings();
    settings.getAutofillSettings = vi.fn(async () => ({ ...DEFAULT_AUTOFILL_SETTINGS, pageLoadFill: true }));
    const getAutofillLoginData = vi.fn(async () => ({ password: 'secret' }));
    const router = createRouter({
      auth: {},
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: 'login-1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
        }]),
        getAutofillLoginData,
      },
      settings,
      saveCaptureCoordinator: { isRuntimeCurrent: vi.fn(async () => true) },
    });
    const token = intentId(await router.handle({ type: 'autofill.issuePageLoadIntent' }, CONTENT_CONTEXT));

    await expect(router.handle({
      type: 'autofill.redeemPageLoadIntent',
      intentId: token,
      runtimeIncarnation: NEXT_RUNTIME_INCARNATION,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({
      type: 'autofill.redeemPageLoadIntent', intentId: token,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(getAutofillLoginData).not.toHaveBeenCalled();
  });

  it('stages password captures with an exact browser-correlation submission hint', async () => {
    const isRuntimeCurrent = vi.fn(async () => true);
    const stage = vi.fn(async (
      _input: Parameters<NonNullable<RouterDeps['saveCaptureCoordinator']>['stage']>[0],
      _credentials: Parameters<NonNullable<RouterDeps['saveCaptureCoordinator']>['stage']>[1],
      ownedUserKey: Parameters<NonNullable<RouterDeps['saveCaptureCoordinator']>['stage']>[2],
    ) => {
      ownedUserKey.encKey.fill(0);
      ownedUserKey.macKey.fill(0);
      return undefined as never;
    });
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      saveCaptureCoordinator: {
        isRuntimeCurrent,
        stage,
      },
    });

    await expect(router.handle({
      type: 'autofill.captureSubmission',
      username: 'user',
      password: 'password',
      submission: {
        kind: 'native',
        actionUrl: 'https://sender.example/session#not-sent',
        method: 'POST',
      },
    }, CONTENT_CONTEXT)).resolves.toEqual({ ok: true, data: null });

    expect(isRuntimeCurrent).toHaveBeenCalledWith(
      CONTENT_CONTEXT.tabId,
      CONTENT_CONTEXT.frameId,
      CONTENT_CONTEXT.documentId,
      TEST_RUNTIME_INCARNATION,
    );
    expect(stage).toHaveBeenCalledWith(
      expect.objectContaining({
        tabId: CONTENT_CONTEXT.tabId,
        frameId: CONTENT_CONTEXT.frameId,
        sourceDocumentId: CONTENT_CONTEXT.documentId,
        runtimeIncarnation: TEST_RUNTIME_INCARNATION,
        sourceUrl: CONTENT_CONTEXT.url,
      }),
      { username: 'user', password: 'password' },
      expect.objectContaining({ encKey: expect.any(Uint8Array), macKey: expect.any(Uint8Array) }),
      { kind: 'native', actionUrl: 'https://sender.example/session', method: 'POST' },
    );
  });

  it('routes exact runtime activation, preserves CAS ownership, and rejects stale or extra fields', async () => {
    const activateRuntime = vi.fn()
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(false);
    const getContentDocument = vi.fn(async () => ({
      documentId: CONTENT_CONTEXT.documentId,
      url: CONTENT_CONTEXT.url,
    }));
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      saveCaptureCoordinator: { activateRuntime },
      getContentDocument,
    });

    await expect(router.handle(
      { type: 'autofill.activateRuntime', runtimeIncarnation: TEST_RUNTIME_INCARNATION },
      CONTENT_CONTEXT,
    )).resolves.toEqual({ ok: true, data: { status: 'active' } });
    expect(activateRuntime).toHaveBeenNthCalledWith(1, {
      tabId: CONTENT_CONTEXT.tabId,
      frameId: CONTENT_CONTEXT.frameId,
      documentId: CONTENT_CONTEXT.documentId,
      frameUrl: CONTENT_CONTEXT.url,
      runtimeIncarnation: TEST_RUNTIME_INCARNATION,
    });

    await expect(router.handle({
      type: 'autofill.activateRuntime',
      runtimeIncarnation: NEXT_RUNTIME_INCARNATION,
      previousRuntimeIncarnation: TEST_RUNTIME_INCARNATION,
    }, CONTENT_CONTEXT)).resolves.toEqual({ ok: true, data: { status: 'active' } });
    expect(activateRuntime).toHaveBeenNthCalledWith(2, {
      tabId: CONTENT_CONTEXT.tabId,
      frameId: CONTENT_CONTEXT.frameId,
      documentId: CONTENT_CONTEXT.documentId,
      frameUrl: CONTENT_CONTEXT.url,
      runtimeIncarnation: NEXT_RUNTIME_INCARNATION,
      previousRuntimeIncarnation: TEST_RUNTIME_INCARNATION,
    });

    await expect(router.handle({
      type: 'autofill.activateRuntime',
      runtimeIncarnation: TEST_RUNTIME_INCARNATION,
      previousRuntimeIncarnation: PREVIOUS_RUNTIME_INCARNATION,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(activateRuntime).toHaveBeenNthCalledWith(3, {
      tabId: CONTENT_CONTEXT.tabId,
      frameId: CONTENT_CONTEXT.frameId,
      documentId: CONTENT_CONTEXT.documentId,
      frameUrl: CONTENT_CONTEXT.url,
      runtimeIncarnation: TEST_RUNTIME_INCARNATION,
      previousRuntimeIncarnation: PREVIOUS_RUNTIME_INCARNATION,
    });

    await expect(router.handle({
      type: 'autofill.activateRuntime',
      runtimeIncarnation: TEST_RUNTIME_INCARNATION,
      extra: true,
    } as unknown as RequestMessage, CONTENT_CONTEXT)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    expect(activateRuntime).toHaveBeenCalledTimes(3);
    expect(getContentDocument).toHaveBeenCalledTimes(3);
    expect(getContentDocument).toHaveBeenCalledWith(CONTENT_CONTEXT.tabId, CONTENT_CONTEXT.frameId);
  });

  it.each([
    {
      label: 'document identity',
      current: { documentId: 'replacement-document', url: CONTENT_CONTEXT.url },
    },
    {
      label: 'document URL',
      current: { documentId: CONTENT_CONTEXT.documentId, url: 'https://sender.example/replaced' },
    },
  ])('rejects runtime activation when the browser-owned $label changed', async ({ current }) => {
    const activateRuntime = vi.fn(async () => true);
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      saveCaptureCoordinator: { activateRuntime },
      getContentDocument: vi.fn(async () => current),
    });

    await expect(router.handle({
      type: 'autofill.activateRuntime',
      runtimeIncarnation: TEST_RUNTIME_INCARNATION,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(activateRuntime).not.toHaveBeenCalled();
  });

  it('passes an exact wake capture id to the runtime-fenced prompt claim', async () => {
    const claimPendingSave = vi.fn(async (
      _context: Parameters<NonNullable<RouterDeps['saveCaptureCoordinator']>['claimPendingSave']>[0],
      ownedUserKey: Parameters<NonNullable<RouterDeps['saveCaptureCoordinator']>['claimPendingSave']>[1],
      _evaluate: Parameters<NonNullable<RouterDeps['saveCaptureCoordinator']>['claimPendingSave']>[2],
      _captureId: Parameters<NonNullable<RouterDeps['saveCaptureCoordinator']>['claimPendingSave']>[3],
    ) => {
      ownedUserKey.encKey.fill(0);
      ownedUserKey.macKey.fill(0);
      return { action: 'none' as const };
    });
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      saveCaptureCoordinator: { claimPendingSave },
    });

    await expect(router.handle({
      type: 'autofill.claimSavePrompt',
      captureId: TEST_CAPTURE_ID,
    }, CONTENT_CONTEXT)).resolves.toEqual({ ok: true, data: { action: 'none' } });
    expect(claimPendingSave).toHaveBeenCalledWith(
      expect.objectContaining({
        tabId: CONTENT_CONTEXT.tabId,
        frameId: CONTENT_CONTEXT.frameId,
        documentId: CONTENT_CONTEXT.documentId,
        runtimeIncarnation: TEST_RUNTIME_INCARNATION,
        frameUrl: CONTENT_CONTEXT.url,
      }),
      expect.objectContaining({ encKey: expect.any(Uint8Array), macKey: expect.any(Uint8Array) }),
      expect.any(Function),
      TEST_CAPTURE_ID,
    );

    await expect(router.handle({
      type: 'autofill.claimSavePrompt',
      captureId: TEST_CAPTURE_ID.toUpperCase(),
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({
      type: 'autofill.claimSavePrompt',
      captureId: TEST_CAPTURE_ID,
      extra: true,
    } as unknown as RequestMessage, CONTENT_CONTEXT)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    expect(claimPendingSave).toHaveBeenCalledOnce();
  });

  it.each([
    {
      label: 'claim',
      method: 'claimPendingSave' as const,
      request: { type: 'autofill.claimSavePrompt', captureId: TEST_CAPTURE_ID } as RequestMessage,
    },
    {
      label: 'take',
      method: 'takePendingSave' as const,
      request: { type: 'autofill.commitSavePrompt', promptId: TEST_PROMPT_ID } as RequestMessage,
    },
    {
      label: 'dismiss',
      method: 'dismissPendingSave' as const,
      request: { type: 'autofill.dismissSavePrompt', promptId: TEST_PROMPT_ID } as RequestMessage,
    },
  ])('fails closed when A to B activation crosses a pending prompt $label', async ({ method, request }) => {
    type PendingSaveContext = Parameters<
      NonNullable<RouterDeps['saveCaptureCoordinator']>['claimPendingSave']
    >[0];
    let currentRuntimeIncarnation = TEST_RUNTIME_INCARNATION;
    let runtimeFence: object = {};
    let releaseOperation!: () => void;
    const pendingOperation = new Promise<void>((resolve) => { releaseOperation = resolve; });
    const storeMutation = vi.fn();
    const commitCapturedLogin = vi.fn();
    const crossFence = async (
      context: PendingSaveContext,
      ownedUserKey?: SymmetricKey,
    ): Promise<void> => {
      const admittedFence = runtimeFence;
      await pendingOperation;
      if (admittedFence !== runtimeFence
          || context.runtimeIncarnation !== currentRuntimeIncarnation) {
        ownedUserKey?.encKey.fill(0);
        ownedUserKey?.macKey.fill(0);
        throw new Error('Pending-save runtime fence changed');
      }
      storeMutation();
    };
    const claimPendingSave = vi.fn(async (context: PendingSaveContext, ownedUserKey: SymmetricKey) => {
      await crossFence(context, ownedUserKey);
      return { action: 'none' as const };
    });
    const takePendingSave = vi.fn(async (
      _promptId: string,
      context: PendingSaveContext,
      ownedUserKey: SymmetricKey,
    ) => {
      await crossFence(context, ownedUserKey);
      return {
        credentials: { password: 'password' },
        sourceUrl: CONTENT_CONTEXT.url,
        decision: { action: 'save' as const, suggestedName: 'Example' },
      };
    });
    const dismissPendingSave = vi.fn(async (_promptId: string, context: PendingSaveContext) => {
      await crossFence(context);
      return true;
    });
    const activateRuntime = vi.fn(async (
      activation: Parameters<NonNullable<RouterDeps['saveCaptureCoordinator']>['activateRuntime']>[0],
    ) => {
      if (activation.previousRuntimeIncarnation !== currentRuntimeIncarnation) return false;
      runtimeFence = {};
      currentRuntimeIncarnation = activation.runtimeIncarnation;
      return true;
    });
    const isRuntimeCurrent = vi.fn(async (
      _tabId: number,
      _frameId: number,
      _documentId: string,
      runtimeIncarnation: string,
    ) => runtimeIncarnation === currentRuntimeIncarnation);
    const router = createRouter({
      auth: {},
      vault: { commitCapturedLogin },
      settings: intentSettings(),
      saveCaptureCoordinator: {
        activateRuntime,
        isRuntimeCurrent,
        claimPendingSave,
        takePendingSave,
        dismissPendingSave,
      },
    });
    const pendingResponse = router.handle(request, CONTENT_CONTEXT);
    const pendingMethod = { claimPendingSave, takePendingSave, dismissPendingSave }[method];
    await vi.waitFor(() => expect(pendingMethod).toHaveBeenCalledOnce());

    await expect(router.handle({
      type: 'autofill.activateRuntime',
      runtimeIncarnation: NEXT_RUNTIME_INCARNATION,
      previousRuntimeIncarnation: TEST_RUNTIME_INCARNATION,
    }, CONTENT_CONTEXT)).resolves.toEqual({ ok: true, data: { status: 'active' } });
    releaseOperation();

    await expect(pendingResponse).resolves.toMatchObject({ ok: false });
    expect(storeMutation).not.toHaveBeenCalled();
    expect(commitCapturedLogin).not.toHaveBeenCalled();
  });

  it('rejects malformed native correlation hints without invoking accessors or staging', async () => {
    const stage = vi.fn(async () => undefined as never);
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      saveCaptureCoordinator: {
        stage,
      },
    });
    const readAction = vi.fn(() => 'https://sender.example/session');
    const submission = { kind: 'native', method: 'POST' } as Record<string, unknown>;
    Object.defineProperty(submission, 'actionUrl', { enumerable: true, get: readAction });

    await expect(router.handle({
      type: 'autofill.captureSubmission',
      password: 'password',
      submission,
    } as RequestMessage, CONTENT_CONTEXT)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    expect(readAction).not.toHaveBeenCalled();
    expect(stage).not.toHaveBeenCalled();
  });

  it('persists a capture and claims an opaque update prompt in the next document', async () => {
    const checkSaveLogin = vi.fn(async () => ({
      action: 'update' as const,
      cipherId: 'cipher-secret-id',
      name: 'Example',
    }));
    const router = createRouter({ auth: {}, vault: { checkSaveLogin }, settings: intentSettings() });
    const nextDocument = { ...CONTENT_CONTEXT, documentId: 'doc-2', url: 'https://sender.example/home' };

    await expect(router.handle({
      type: 'autofill.captureSubmission',
      username: 'user',
      password: 'new-password',
    }, CONTENT_CONTEXT)).resolves.toEqual({ ok: true, data: null });
    expect(checkSaveLogin).not.toHaveBeenCalled();

    const response = await router.handle({ type: 'autofill.claimSavePrompt' }, nextDocument);
    expect(response).toMatchObject({
      ok: true,
      data: { action: 'update', name: 'Example', promptId: expect.any(String) },
    });
    expect(JSON.stringify(response)).not.toContain('cipher-secret-id');
    expect(JSON.stringify(response)).not.toContain('new-password');
    expect(checkSaveLogin).toHaveBeenCalledWith(
      CONTENT_CONTEXT.url,
      { username: 'user', password: 'new-password' },
      0,
    );
  });

  it('commits addUri with only a document-bound prompt id and rejects replay', async () => {
    const addLoginUri = vi.fn(async (
      _cipherId: string,
      _username: string,
      _password: string,
      _url: string,
      _strategy: UriMatchStrategySetting,
      assertCurrent?: () => void,
    ) => {
      assertCurrent?.();
      return { items: [], folders: [], collections: [], orgPermissions: [] };
    });
    const router = createRouter({
      auth: {},
      vault: {
        checkSaveLogin: vi.fn(async () => ({
          action: 'addUri' as const,
          cipherId: 'private-target-id',
          name: 'Existing login',
        })),
        addLoginUri,
      },
      settings: intentSettings(1),
    });
    const document = { ...CONTENT_CONTEXT, documentId: 'doc-2', url: 'https://sender.example/home' };
    await router.handle({
      type: 'autofill.captureSubmission', username: 'user', password: 'password',
    }, CONTENT_CONTEXT);
    const claimed = await router.handle({ type: 'autofill.claimSavePrompt' }, document);
    const token = promptId(claimed);
    const commit: RequestMessage = { type: 'autofill.commitSavePrompt', promptId: token };

    expect(JSON.stringify(commit)).not.toContain('password');
    await expect(router.handle(commit, document)).resolves.toMatchObject({ ok: true });
    expect(addLoginUri).toHaveBeenCalledWith(
      'private-target-id',
      'user',
      'password',
      CONTENT_CONTEXT.url,
      1,
      expect.any(Function),
    );
    await expect(router.handle(commit, document))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(addLoginUri).toHaveBeenCalledOnce();
  });

  it('delegates the consumed claim to one atomic VaultService commit without branching in the router', async () => {
    const checkSaveLogin = vi.fn(async () => ({
      action: 'update' as const,
      cipherId: 'cipher-1',
      name: 'Example',
    }));
    const commitCapturedLogin = vi.fn(async () => ({
      items: [], folders: [], collections: [], orgPermissions: [],
    }));
    const saveLogin = vi.fn();
    const updateLoginPassword = vi.fn();
    const addLoginUri = vi.fn();
    const router = createRouter({
      auth: {},
      vault: {
        checkSaveLogin,
        commitCapturedLogin,
        saveLogin,
        updateLoginPassword,
        addLoginUri,
      },
      settings: intentSettings(1),
    });
    await router.handle({
      type: 'autofill.captureSubmission', username: 'user', password: 'new-password',
    }, CONTENT_CONTEXT);
    const token = promptId(await router.handle({ type: 'autofill.claimSavePrompt' }, CONTENT_CONTEXT));
    await expect(router.handle({
      type: 'autofill.commitSavePrompt', promptId: token,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: true });

    expect(checkSaveLogin).toHaveBeenCalledOnce();
    expect(commitCapturedLogin).toHaveBeenCalledWith(
      CONTENT_CONTEXT.url,
      { username: 'user', password: 'new-password' },
      1,
      { action: 'update', cipherId: 'cipher-1', name: 'Example' },
      expect.any(Function),
    );
    expect(saveLogin).not.toHaveBeenCalled();
    expect(updateLoginPassword).not.toHaveBeenCalled();
    expect(addLoginUri).not.toHaveBeenCalled();
  });

  it('does not let another document or runtime consume a live prompt', async () => {
    const updateLoginPassword = vi.fn(async () => ({ items: [], folders: [], collections: [], orgPermissions: [] }));
    const router = createRouter({
      auth: {},
      vault: {
        checkSaveLogin: vi.fn(async () => ({ action: 'update' as const, cipherId: 'cipher-1', name: 'Example' })),
        updateLoginPassword,
      },
      settings: intentSettings(),
      saveCaptureCoordinator: { isRuntimeCurrent: vi.fn(async () => true) },
    });
    const claimant = { ...CONTENT_CONTEXT, documentId: 'doc-2', url: 'https://sender.example/home' };
    await router.handle({ type: 'autofill.captureSubmission', password: 'new-password' }, CONTENT_CONTEXT);
    const token = promptId(await router.handle({ type: 'autofill.claimSavePrompt' }, claimant));

    await expect(router.handle({
      type: 'autofill.commitSavePrompt',
      promptId: token,
      runtimeIncarnation: NEXT_RUNTIME_INCARNATION,
    }, claimant)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle(
      { type: 'autofill.commitSavePrompt', promptId: token },
      { ...claimant, documentId: 'doc-3' },
    )).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle(
      { type: 'autofill.commitSavePrompt', promptId: token },
      claimant,
    )).resolves.toMatchObject({ ok: true });
    expect(updateLoginPassword).toHaveBeenCalledOnce();
  });

  it('encrypts a staged username and folds it into a later password capture', async () => {
    const saveLogin = vi.fn(async () => ({ items: [], folders: [], collections: [], orgPermissions: [] }));
    const checkSaveLogin = vi.fn(async () => ({ action: 'save' as const, suggestedName: 'Example' }));
    const router = createRouter({
      auth: {},
      vault: { checkSaveLogin, saveLogin },
      settings: intentSettings(),
    });
    const passwordDocument = { ...CONTENT_CONTEXT, documentId: 'doc-2', url: 'https://sender.example/password' };
    const resultDocument = { ...CONTENT_CONTEXT, documentId: 'doc-3', url: 'https://sender.example/home' };

    await router.handle({
      type: 'autofill.captureSubmission', username: 'alice@example.com',
    }, CONTENT_CONTEXT);
    await router.handle({
      type: 'autofill.captureSubmission', password: 'next-step-password',
    }, passwordDocument);
    const token = promptId(await router.handle({ type: 'autofill.claimSavePrompt' }, resultDocument));
    await expect(router.handle({ type: 'autofill.commitSavePrompt', promptId: token }, resultDocument))
      .resolves.toMatchObject({ ok: true });

    expect(checkSaveLogin).toHaveBeenCalledWith(
      passwordDocument.url,
      { username: 'alice@example.com', password: 'next-step-password' },
      0,
    );
    expect(saveLogin).toHaveBeenCalledWith(
      passwordDocument.url,
      'alice@example.com',
      'next-step-password',
      expect.any(Function),
    );
  });

  it('drains a stale username stage even when the password capture has its own username', async () => {
    const consume = vi.fn(async () => 'stale@example.com');
    const checkSaveLogin = vi.fn(async () => ({ action: 'save' as const, suggestedName: 'Example' }));
    const router = createRouter({
      auth: {},
      usernameStages: { stage: vi.fn(), consume },
      vault: { checkSaveLogin },
      settings: intentSettings(),
    });

    await router.handle({
      type: 'autofill.captureSubmission',
      username: 'current@example.com',
      password: 'password',
    }, CONTENT_CONTEXT);
    await router.handle({ type: 'autofill.claimSavePrompt' }, CONTENT_CONTEXT);

    expect(consume).toHaveBeenCalledWith(expect.objectContaining({
      tabId: CONTENT_CONTEXT.tabId,
      frameId: CONTENT_CONTEXT.frameId,
      documentId: CONTENT_CONTEXT.documentId,
      runtimeIncarnation: TEST_RUNTIME_INCARNATION,
    }));
    expect(checkSaveLogin).toHaveBeenCalledWith(
      CONTENT_CONTEXT.url,
      { username: 'current@example.com', password: 'password' },
      0,
    );
  });

  it('consumes without writing when the authoritative decision changes after claim', async () => {
    const addLoginUri = vi.fn();
    const updateLoginPassword = vi.fn();
    const checkSaveLogin = vi.fn()
      .mockResolvedValueOnce({ action: 'addUri' as const, cipherId: 'first', name: 'Existing' })
      .mockResolvedValueOnce({ action: 'update' as const, cipherId: 'second', name: 'Changed' });
    const router = createRouter({
      auth: {},
      vault: { checkSaveLogin, addLoginUri, updateLoginPassword },
      settings: intentSettings(),
    });
    await router.handle({
      type: 'autofill.captureSubmission', username: 'user', password: 'password',
    }, CONTENT_CONTEXT);
    const token = promptId(await router.handle({ type: 'autofill.claimSavePrompt' }, CONTENT_CONTEXT));

    await expect(router.handle({ type: 'autofill.commitSavePrompt', promptId: token }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({ type: 'autofill.commitSavePrompt', promptId: token }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(addLoginUri).not.toHaveBeenCalled();
    expect(updateLoginPassword).not.toHaveBeenCalled();
  });

  it('atomically consumes before a vault write with an unknown outcome', async () => {
    const saveLogin = vi.fn(async () => { throw new Error('transport outcome unknown'); });
    const router = createRouter({
      auth: {},
      vault: {
        checkSaveLogin: vi.fn(async () => ({ action: 'save' as const, suggestedName: 'Example' })),
        saveLogin,
      },
      settings: intentSettings(),
    });
    await router.handle({ type: 'autofill.captureSubmission', password: 'password' }, CONTENT_CONTEXT);
    const token = promptId(await router.handle({ type: 'autofill.claimSavePrompt' }, CONTENT_CONTEXT));

    await expect(router.handle({ type: 'autofill.commitSavePrompt', promptId: token }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false });
    await expect(router.handle({ type: 'autofill.commitSavePrompt', promptId: token }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(saveLogin).toHaveBeenCalledOnce();
  });

  it('dismisses by opaque prompt id and prevents later commit', async () => {
    const saveLogin = vi.fn();
    const router = createRouter({
      auth: {},
      vault: {
        checkSaveLogin: vi.fn(async () => ({ action: 'save' as const, suggestedName: 'Example' })),
        saveLogin,
      },
      settings: intentSettings(),
    });
    await router.handle({ type: 'autofill.captureSubmission', password: 'password' }, CONTENT_CONTEXT);
    const token = promptId(await router.handle({ type: 'autofill.claimSavePrompt' }, CONTENT_CONTEXT));
    const dismiss: RequestMessage = { type: 'autofill.dismissSavePrompt', promptId: token };

    expect(JSON.stringify(dismiss)).toBe(JSON.stringify({ type: 'autofill.dismissSavePrompt', promptId: token }));
    await expect(router.handle(dismiss, CONTENT_CONTEXT)).resolves.toEqual({ ok: true, data: null });
    await expect(router.handle({ type: 'autofill.commitSavePrompt', promptId: token }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(saveLogin).not.toHaveBeenCalled();
  });

  it('rejects malformed capture and prompt requests without persisting or writing', async () => {
    const checkSaveLogin = vi.fn();
    const saveLogin = vi.fn();
    const router = createRouter({ auth: {}, vault: { checkSaveLogin, saveLogin }, settings: intentSettings() });

    await expect(router.handle({
      type: 'autofill.captureSubmission',
      username: 'user',
      password: 'password',
      extra: true,
    } as unknown as RequestMessage, CONTENT_CONTEXT)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    await expect(router.handle({
      type: 'autofill.commitSavePrompt', promptId: 'not-a-prompt-id',
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(checkSaveLogin).not.toHaveBeenCalled();
    expect(saveLogin).not.toHaveBeenCalled();
  });

  it('revokes a claimed prompt when account or policy generations change', async () => {
    let accountGeneration = 0;
    const accountGate: RouterDeps['accountGate'] = {
      capture: () => ({
        serverGeneration: 0,
        accountGeneration,
        serverUrl: 'https://vault.example/',
        accountIdentity: accountGeneration === 0 ? 'a@example.com' : 'b@example.com',
      }),
      assert: (lease) => {
        if (lease.accountGeneration !== accountGeneration) throw new AppError('session_expired', 'account changed');
      },
    };
    const saveLogin = vi.fn();
    const router = createRouter({
      auth: {},
      accountGate,
      vault: {
        checkSaveLogin: vi.fn(async () => ({ action: 'save' as const, suggestedName: 'Example' })),
        saveLogin,
      },
      settings: intentSettings(),
    });
    await router.handle({ type: 'autofill.captureSubmission', password: 'password' }, CONTENT_CONTEXT);
    const token = promptId(await router.handle({ type: 'autofill.claimSavePrompt' }, CONTENT_CONTEXT));
    accountGeneration = 1;

    await expect(router.handle({ type: 'autofill.commitSavePrompt', promptId: token }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false });
    expect(saveLogin).not.toHaveBeenCalled();

    const policyGate = new AutofillPolicyGate();
    const policyRouter = createRouter({
      auth: {},
      autofillPolicyGate: policyGate,
      vault: {
        checkSaveLogin: vi.fn(async () => ({ action: 'save' as const, suggestedName: 'Example' })),
        saveLogin,
      },
      settings: intentSettings(),
    });
    await policyRouter.handle({ type: 'autofill.captureSubmission', password: 'password' }, CONTENT_CONTEXT);
    const policyToken = promptId(await policyRouter.handle({ type: 'autofill.claimSavePrompt' }, CONTENT_CONTEXT));
    policyGate.invalidate();
    await expect(policyRouter.handle({ type: 'autofill.commitSavePrompt', promptId: policyToken }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(saveLogin).not.toHaveBeenCalled();
  });

  it('rechecks the exact prompt action after consuming the claim and before any vault write', async () => {
    let policy: AutofillPolicySettings = {
      schemaVersion: AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
      defaultUriMatchStrategy: 0,
      pageLoadFillDefault: true,
      ...DEFAULT_AUTOFILL_SETTINGS,
    };
    const settings = intentSettings();
    settings.getAutofillPolicySettings = vi.fn(async () => policy);
    const commitCapturedLogin = vi.fn();
    const router = createRouter({
      auth: {},
      vault: {
        checkSaveLogin: vi.fn(async () => ({ action: 'save' as const, suggestedName: 'Example' })),
        commitCapturedLogin,
      },
      settings,
    });
    await router.handle({ type: 'autofill.captureSubmission', password: 'password' }, CONTENT_CONTEXT);
    const token = promptId(await router.handle({ type: 'autofill.claimSavePrompt' }, CONTENT_CONTEXT));
    policy = {
      ...policy,
      savePromptEnabled: false,
      updatePromptEnabled: true,
    };

    await expect(router.handle(
      { type: 'autofill.commitSavePrompt', promptId: token },
      CONTENT_CONTEXT,
    )).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle(
      { type: 'autofill.commitSavePrompt', promptId: token },
      CONTENT_CONTEXT,
    )).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(commitCapturedLogin).not.toHaveBeenCalled();
  });

  it('revokes login and save capabilities after one combined policy save', async () => {
    const policyGate = new AutofillPolicyGate();
    let policy: AutofillPolicySettings = {
      schemaVersion: AUTOFILL_POLICY_SETTINGS_SCHEMA_VERSION,
      defaultUriMatchStrategy: 0,
      pageLoadFillDefault: true,
      ...DEFAULT_AUTOFILL_SETTINGS,
    };
    const settings = intentSettings();
    settings.getAutofillPolicySettings = vi.fn(async () => policy);
    settings.saveAutofillPolicySettings = vi.fn(async (next) => { policy = next; });
    const getAutofillLoginData = vi.fn(async () => ({ password: 'secret' }));
    const saveLogin = vi.fn();
    const router = createRouter({
      auth: {},
      autofillPolicyGate: policyGate,
      vault: {
        findAutofillCandidates: vi.fn(async () => [{
          id: 'login-1', name: 'Example', matchedUri: CONTENT_CONTEXT.url, matchType: 0 as const, favorite: false,
        }]),
        getAutofillLoginData,
        checkSaveLogin: vi.fn(async () => ({ action: 'save' as const, suggestedName: 'Example' })),
        saveLogin,
      },
      settings,
    });
    const loginToken = intentId(await router.handle(loginIntentRequest('login-1'), CONTENT_CONTEXT));
    await router.handle({ type: 'autofill.captureSubmission', password: 'new-password' }, CONTENT_CONTEXT);
    const saveToken = promptId(await router.handle({ type: 'autofill.claimSavePrompt' }, CONTENT_CONTEXT));

    await expect(router.handle({
      type: 'settings.save',
      defaultUriMatchStrategy: 1,
      autofillSettings: {
        ...DEFAULT_AUTOFILL_SETTINGS,
        pageLoadFillDefault: true,
        inlineSuggestions: false,
        blockedDomains: ['blocked.example'],
      },
    })).resolves.toEqual({ ok: true, data: null });
    await expect(router.handle({ type: 'autofill.redeemLoginIntent', intentId: loginToken }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({ type: 'autofill.commitSavePrompt', promptId: saveToken }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(getAutofillLoginData).not.toHaveBeenCalled();
    expect(saveLogin).not.toHaveBeenCalled();
  });
  const settingsStub = {
    getServerUrl: vi.fn(),
    saveServerUrl: vi.fn(),
    getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
    saveDefaultUriMatchStrategy: vi.fn(),
    getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
    saveLockTimeout: vi.fn(), getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'), saveOnIdleAction: vi.fn(), getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveClipboardClearSetting: vi.fn(),
  };

  it('routes autofill.getTabSuggestions to tabAutofill.getSuggestions', async () => {
    const getSuggestions = vi.fn(async () => ({ status: 'ready' as const, suggestions: [] }));
    const router = createRouter({ auth: {}, vault: {}, settings: settingsStub, tabAutofill: { getSuggestions, fill: vi.fn() } });
    const res = await router.handle({ type: 'autofill.getTabSuggestions', tabId: 7 });
    expect(getSuggestions).toHaveBeenCalledWith(7);
    expect(res).toEqual({ ok: true, data: { outcome: { status: 'ready', suggestions: [] } } });
  });

  it('routes autofill.fillTabSuggestion to tabAutofill.fill', async () => {
    const fill = vi.fn(async () => ({ status: 'filled' as const }));
    const router = createRouter({ auth: {}, vault: {}, settings: settingsStub, tabAutofill: { getSuggestions: vi.fn(), fill } });
    const target = loginTabTarget();
    const res = await router.handle({ type: 'autofill.fillTabSuggestion', tabId: 7, cipherId: 'c1', target });
    expect(fill).toHaveBeenCalledWith(7, 'c1', target);
    expect(res).toEqual({ ok: true, data: { outcome: { status: 'filled' } } });
  });

  it('routes continuation ownership only through the exact Popup document and scrubs reprompt input', async () => {
    const status = vi.fn(async () => ({ status: 'none' as const }));
    const authorizeReprompt = vi.fn(async (_documentId: string, _id: string, password: string) => ({
      verified: password === 'right',
    }));
    const continuation = {
      status,
      cancel: vi.fn(async () => true),
      resumeUnlock: vi.fn(async () => ({ status: 'started' as const })),
      authorizeReprompt,
      stageKeyboardReprompt: vi.fn(async () => '11111111-1111-4111-8111-111111111111'),
      redeemKeyboardReprompt: vi.fn(async () => undefined),
    };
    const router = createRouter({
      auth: {}, vault: {}, settings: settingsStub, autofillContinuation: continuation,
    });

    await expect(router.handle({ type: 'autofill.continuation.status' }, OPTIONS_PAGE_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({ type: 'autofill.continuation.status' }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({ type: 'autofill.continuation.status' }, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: { status: 'none' } });
    expect(status).toHaveBeenCalledWith('popup-doc-1');

    const request = {
      type: 'autofill.continuation.authorizeReprompt' as const,
      continuationId: '11111111-1111-4111-8111-111111111111',
      masterPassword: 'right',
    };
    await expect(router.handle(request, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: { verified: true } });
    expect(authorizeReprompt).toHaveBeenCalledWith(
      'popup-doc-1', request.continuationId, 'right',
    );
    expect(request.masterPassword).toBe('');
  });

  it.each(['login', 'totp', 'card'] as const)(
    'carries a verified keyboard reprompt proof through final %s secret release exactly once',
    async (purpose) => {
      const assertion = vi.fn();
      const binding = purpose === 'login'
        ? {
            purpose,
            customPlan: EMPTY_LOGIN_CUSTOM_PLAN,
            customPlanDigest: EMPTY_LOGIN_CUSTOM_PLAN_DIGEST,
          }
        : purpose === 'totp'
          ? { purpose }
          : { purpose, structuredTarget: STRUCTURED_TARGET };
      const continuationId = '55555555-5555-4555-8555-555555555555';
      const getLogin = vi.fn(async (
        _id: string,
        _url: string,
        _strategy: UriMatchStrategySetting,
        _plan: unknown,
        assertReprompt?: () => void,
      ) => {
        assertReprompt?.();
        return { login: { username: 'u', password: 'p' }, customAssignments: [] };
      });
      const getTotp = vi.fn(async (
        _id: string,
        _url: string,
        _strategy: UriMatchStrategySetting,
        _bind: unknown,
        assertReprompt?: () => void,
      ) => {
        assertReprompt?.();
        return { code: '123456', period: 30, remaining: 10 };
      });
      const fill = vi.fn(async (
        _tabId: number,
        _cipherId: string,
        _target: unknown,
        _assert: () => void,
        reprompt?: { assertCurrent(): void },
      ) => {
        reprompt?.assertCurrent();
        return { status: 'filled' as const };
      });
      const continuation = {
        status: vi.fn(async () => ({ status: 'none' as const })),
        cancel: vi.fn(async () => true),
        resumeUnlock: vi.fn(async () => ({ status: 'started' as const })),
        authorizeReprompt: vi.fn(async () => ({ verified: true })),
        stageKeyboardReprompt: vi.fn(async () => continuationId),
        redeemKeyboardReprompt: vi.fn(),
      };
      const router = createRouter({
        auth: {},
        vault: {
          findAutofillCandidates: vi.fn(async () => [{ id: 'protected', reprompt: true }] as never),
          findFillItems: vi.fn(async () => [{ id: 'protected', reprompt: true }] as never),
          getInteractiveAutofillLoginData: getLogin,
          getAutofillTotpData: getTotp,
        },
        settings: settingsStub,
        autofillContinuation: continuation as never,
        tabAutofill: { getSuggestions: vi.fn(), fill },
      });
      continuation.redeemKeyboardReprompt.mockReset()
        .mockResolvedValueOnce({
          cipherId: 'protected',
          runtimeIncarnation: TEST_RUNTIME_INCARNATION,
          binding,
          source: {
            tabId: CONTENT_CONTEXT.tabId,
            windowId: 3,
            topDocumentId: CONTENT_CONTEXT.documentId,
            topRuntimeIncarnation: TEST_RUNTIME_INCARNATION,
            topOrigin: CONTENT_CONTEXT.origin,
            topUrlDigest: 'a'.repeat(64),
            frameId: CONTENT_CONTEXT.frameId,
            frameDocumentId: CONTENT_CONTEXT.documentId,
            frameRuntimeIncarnation: TEST_RUNTIME_INCARNATION,
            frameOrigin: CONTENT_CONTEXT.origin,
            frameUrlDigest: 'b'.repeat(64),
          },
          sessionLease: router.captureSessionLease(),
          accountLease: router.captureAccountLease(),
          policyLease: router.capturePolicyLease(),
          repromptAuthorization: { assertCurrent: assertion },
        })
        .mockResolvedValue(undefined);

      const issued = await router.handle({
        type: 'autofill.continuation.redeemKeyboardReprompt', continuationId,
      }, CONTENT_CONTEXT);
      expect(continuation.redeemKeyboardReprompt).toHaveBeenNthCalledWith(1, continuationId, {
        tabId: CONTENT_CONTEXT.tabId,
        frameId: CONTENT_CONTEXT.frameId,
        documentId: CONTENT_CONTEXT.documentId,
        runtimeIncarnation: TEST_RUNTIME_INCARNATION,
        url: CONTENT_CONTEXT.url,
      });
      const token = intentId(issued);
      const redeemed = purpose === 'login'
        ? await router.handle({ type: 'autofill.keyboard.redeemLoginIntent', intentId: token }, CONTENT_CONTEXT)
        : purpose === 'totp'
          ? await router.handle({ type: 'autofill.keyboard.redeemTotpIntent', intentId: token }, CONTENT_CONTEXT)
          : await router.handle({
              type: 'autofill.keyboard.redeemStructuredIntent', intentId: token, target: STRUCTURED_TARGET,
            }, CONTENT_CONTEXT);
      expect(redeemed).toMatchObject({ ok: true });
      expect(assertion).toHaveBeenCalled();
      await expect(router.handle({
        type: 'autofill.continuation.redeemKeyboardReprompt', continuationId,
      }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    },
  );

  it('routes manual autofill only from the exact Popup and scrubs its one-use password', async () => {
    const prepare = vi.fn(async () => ({
      warning: { risk: 'no_match' as const, site: 'example.com', canSave: false, requiresReprompt: true },
      authorization: {
        authorizationId: '11111111-1111-4111-8111-111111111111', expiresAt: Date.now() + 30_000,
      },
    }));
    const cancel = vi.fn(() => true);
    let observedPassword = '';
    const commit = vi.fn(async (_documentId: string, input: unknown) => {
      observedPassword = (input as { masterPassword?: string }).masterPassword ?? '';
      return { status: 'filled' as const };
    });
    const router = createRouter({
      auth: {}, vault: {}, settings: settingsStub, manualAutofill: { prepare, cancel, commit },
    });
    await expect(router.handle({
      type: 'autofill.manual.prepare', tabId: 7, cipherId: 'c1',
    }, OPTIONS_PAGE_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({
      type: 'autofill.manual.prepare', tabId: 7, cipherId: 'c1',
    }, EXTENSION_PAGE_CONTEXT)).resolves.toMatchObject({ ok: true });
    expect(prepare).toHaveBeenCalledWith('popup-doc-1', expect.objectContaining({
      type: 'autofill.manual.prepare', tabId: 7, cipherId: 'c1',
    }));

    const request = {
      type: 'autofill.manual.commit' as const,
      authorizationId: '11111111-1111-4111-8111-111111111111',
      action: 'fill_only' as const,
      masterPassword: 'one-use-password',
    };
    await expect(router.handle(request, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: { outcome: { status: 'filled' } } });
    expect(observedPassword).toBe('one-use-password');
    expect(request.masterPassword).toBe('');
  });

  it('issues and consumes one exact Popup reprompt fill authorization without forwarding the password', async () => {
    const target = loginTabTarget();
    const binding = {
      tabId: 7,
      frameId: target.frameId,
      targetDocumentId: target.documentId,
      topUrl: 'https://sender.example/login',
      frameUrl: 'https://sender.example/login',
      targetKey: 'login-target-key',
    };
    const verifyMasterPassword = vi.fn(async () => true);
    const findAutofillCandidates = vi.fn(async () => [{
      id: 'c1', name: 'Protected', matchedUri: binding.frameUrl, matchType: 0 as const,
      favorite: false, reprompt: true,
    }]);
    const resolveRepromptBinding = vi.fn(async () => binding);
    const fill = vi.fn(async (
      _tabId: number,
      _cipherId: string,
      _target: unknown,
      _assertExternalCurrent?: () => void,
      authorization?: { assertCurrent(): void },
    ) => {
      authorization?.assertCurrent();
      return { status: 'filled' as const };
    });
    const router = createRouter({
      auth: { verifyMasterPassword },
      vault: { findAutofillCandidates, findFillItems: vi.fn() },
      settings: settingsStub,
      tabAutofill: { getSuggestions: vi.fn(), resolveRepromptBinding, fill },
    });
    const authorizeRequest = {
      type: 'autofill.authorizeRepromptFill' as const,
      tabId: 7,
      cipherId: 'c1',
      target,
      masterPassword: 'master-secret',
    };
    const issued = await router.handle(authorizeRequest);
    expect(authorizeRequest.masterPassword).toBe('');
    expect(verifyMasterPassword).toHaveBeenCalledWith('master-secret');
    expect(issued).toMatchObject({ ok: true, data: { verified: true, authorization: {
      authorizationId: expect.any(String), expiresAt: expect.any(Number),
    } } });
    const authorizationId = issued.ok
      ? (issued.data as { authorization?: { authorizationId: string } }).authorization?.authorizationId
      : undefined;
    expect(authorizationId).toBeTypeOf('string');

    await expect(router.handle({
      type: 'autofill.fillTabSuggestion',
      tabId: 7,
      cipherId: 'c1',
      target,
      repromptAuthorizationId: authorizationId!,
    })).resolves.toEqual({ ok: true, data: { outcome: { status: 'filled' } } });
    expect(fill).toHaveBeenCalledWith(7, 'c1', target, undefined, {
      assertCurrent: expect.any(Function),
    });

    await expect(router.handle({
      type: 'autofill.fillTabSuggestion',
      tabId: 7,
      cipherId: 'c1',
      target,
      repromptAuthorizationId: authorizationId!,
    })).resolves.toMatchObject({ ok: false, error: { code: 'reprompt_required' } });
    expect(fill).toHaveBeenCalledTimes(1);
  });

  it('authorizes a reprompt card only through its exact structured target', async () => {
    const target = {
      kind: 'card' as const,
      frameId: 2,
      formId: 'card-form',
      documentId: 'card-doc',
      runtimeIncarnation: TEST_RUNTIME_INCARNATION,
      generation: 4,
      roles: ['number', 'exp'] as const,
    };
    const binding = {
      tabId: 7,
      frameId: target.frameId,
      targetDocumentId: target.documentId,
      topUrl: 'https://shop.example/checkout',
      frameUrl: 'https://pay.example/frame',
      targetKey: 'card-target-key',
    };
    const findFillItems = vi.fn(async () => [{ id: 'card-1', name: 'Card', favorite: false, reprompt: true }]);
    const resolveRepromptBinding = vi.fn(async () => binding);
    const fill = vi.fn(async () => ({ status: 'filled' as const }));
    const router = createRouter({
      auth: { verifyMasterPassword: vi.fn(async () => true) },
      vault: { findAutofillCandidates: vi.fn(), findFillItems },
      settings: settingsStub,
      tabAutofill: { getSuggestions: vi.fn(), resolveRepromptBinding, fill },
    });
    const issued = await router.handle({
      type: 'autofill.authorizeRepromptFill',
      tabId: 7,
      cipherId: 'card-1',
      target,
      masterPassword: 'master-secret',
    });
    expect(findFillItems).toHaveBeenCalledWith('card');
    expect(issued).toMatchObject({ ok: true, data: { verified: true, authorization: {
      authorizationId: expect.any(String),
    } } });
  });

  it('issues and redeems the same bounded grant shape for a reprompt identity target', async () => {
    const target = {
      kind: 'identity' as const,
      frameId: 1,
      formId: 'identity-form',
      documentId: 'identity-doc',
      runtimeIncarnation: TEST_RUNTIME_INCARNATION,
      generation: 6,
      roles: ['fullName', 'email'] as const,
    };
    const binding = {
      tabId: 7,
      frameId: target.frameId,
      targetDocumentId: target.documentId,
      topUrl: 'https://shop.example/checkout',
      frameUrl: 'https://profile.example/frame',
      targetKey: 'identity-target-key',
    };
    const fill = vi.fn(async () => ({ status: 'filled' as const }));
    const router = createRouter({
      auth: { verifyMasterPassword: vi.fn(async () => true) },
      vault: {
        findAutofillCandidates: vi.fn(),
        findFillItems: vi.fn(async () => [{
          id: 'identity-1', name: 'Identity', favorite: false, reprompt: true,
        }]),
      },
      settings: settingsStub,
      tabAutofill: {
        getSuggestions: vi.fn(),
        resolveRepromptBinding: vi.fn(async () => binding),
        fill,
      },
    });
    const issued = await router.handle({
      type: 'autofill.authorizeRepromptFill',
      tabId: 7,
      cipherId: 'identity-1',
      target,
      masterPassword: 'master-secret',
    });
    const authorizationId = issued.ok
      ? (issued.data as { authorization?: { authorizationId: string } }).authorization?.authorizationId
      : undefined;
    expect(authorizationId).toBeTypeOf('string');

    await expect(router.handle({
      type: 'autofill.fillTabSuggestion',
      tabId: 7,
      cipherId: 'identity-1',
      target,
      repromptAuthorizationId: authorizationId!,
    })).resolves.toEqual({ ok: true, data: { outcome: { status: 'filled' } } });
    expect(fill).toHaveBeenCalledWith(7, 'identity-1', target, undefined, {
      assertCurrent: expect.any(Function),
    });
  });

  it('rejects popup-only tab autofill verbs from content contexts', async () => {
    const getSuggestions = vi.fn(async () => ({ status: 'ready' as const, suggestions: [] }));
    const fill = vi.fn(async () => ({ status: 'filled' as const }));
    const router = createRouter({ auth: {}, vault: {}, settings: settingsStub, tabAutofill: { getSuggestions, fill } });

    await expect(router.handle(
      { type: 'autofill.getTabSuggestions', tabId: CONTENT_CONTEXT.tabId },
      CONTENT_CONTEXT,
    )).resolves.toEqual({ ok: false, error: { code: 'denied', message: 'sender not permitted' } });
    await expect(router.handle(
      {
        type: 'autofill.fillTabSuggestion',
        tabId: CONTENT_CONTEXT.tabId,
        cipherId: 'c1',
        target: loginTabTarget(),
      },
      CONTENT_CONTEXT,
    )).resolves.toEqual({ ok: false, error: { code: 'denied', message: 'sender not permitted' } });
    expect(getSuggestions).not.toHaveBeenCalled();
    expect(fill).not.toHaveBeenCalled();
  });

  it('throws when tabAutofill is not wired', async () => {
    const router = createRouter({ auth: {}, vault: {}, settings: settingsStub });
    await expect(router.handle({ type: 'autofill.getTabSuggestions', tabId: 7 }))
      .resolves.toEqual({ ok: false, error: { code: 'error', message: 'tabAutofill is not wired' } });
    await expect(router.handle({ type: 'autofill.fillTabSuggestion', tabId: 7, cipherId: 'c1', target: loginTabTarget() }))
      .resolves.toEqual({ ok: false, error: { code: 'error', message: 'tabAutofill is not wired' } });
  });

  it('routes sends.createFile to vault.createFileSend with the server URL', async () => {
    const createFileSend = vi.fn(async () => ({ id: 's1', url: 'u', name: 'Doc', type: 1 }));
    const settings = { getServerUrl: vi.fn(async () => 'http://localhost:8080'), saveServerUrl: vi.fn(), getDefaultUriMatchStrategy: vi.fn(async () => 0), saveDefaultUriMatchStrategy: vi.fn(), getLockTimeout: vi.fn(async () => '15'), saveLockTimeout: vi.fn() };
    const router = createRouter({ auth: {}, vault: { createFileSend } as never, settings: settings as never });
    const res = await router.handle({ type: 'sends.createFile', input: { name: 'Doc', deletionDays: 7 } as never, dataB64: 'AQID', fileName: 'secret.pdf' });
    expect(createFileSend).toHaveBeenCalledWith(
      { name: 'Doc', deletionDays: 7 }, 'AQID', 'secret.pdf', 'http://localhost:8080', expect.any(Function),
    );
    expect(res).toEqual({ ok: true, data: { send: { id: 's1', url: 'u', name: 'Doc', type: 1 } } });
  });

  it('does not reuse a request-start timeout lease after a successful metadata mutation reconfigures timeout', async () => {
    let timeoutGeneration = 1;
    const listing = { items: [], folders: [], collections: [], orgPermissions: [] };
    const createCipher = vi.fn(async () => {
      timeoutGeneration += 1;
      return listing;
    });
    const vaultReleaseGate: NonNullable<RouterDeps['vaultReleaseGate']> = {
      capture: vi.fn((_sessionLease) => ({
        sessionLease: { generation: 0 },
        timeoutLease: { generation: timeoutGeneration },
      } as never)),
      checkpoint: vi.fn(async (lease) => {
        if ((lease.timeoutLease as { generation: number }).generation !== timeoutGeneration) {
          throw new AppError('locked', 'stale timeout generation');
        }
        return {} as never;
      }),
      assertAuthorities: vi.fn((_proof, assertCurrent) => assertCurrent()),
      assert: vi.fn(),
    };
    const router = createRouter({
      auth: {}, settings: settingsStub, vaultReleaseGate, vault: { createCipher } as never,
    });

    await expect(router.handle({
      type: 'vault.createCipher', input: { type: 1, name: 'One' }, target: { kind: 'personal' },
    })).resolves.toEqual({ ok: true, data: listing });
    expect(createCipher).toHaveBeenCalledOnce();
    expect(vaultReleaseGate.capture).not.toHaveBeenCalled();
    expect(vaultReleaseGate.checkpoint).not.toHaveBeenCalled();
  });

  it('captures the final timeout generation once for a successful secret-bearing Send mutation', async () => {
    let timeoutGeneration = 1;
    const send = { id: 's1', url: 'https://send.example/s1', name: 'Secret', type: 0, text: 'value' };
    const createTextSend = vi.fn(async (
      _input: unknown,
      _serverUrl: string,
      bindFinalAuthority?: (assertCurrent: () => void) => void,
    ) => {
      timeoutGeneration += 1;
      const resultGeneration = timeoutGeneration;
      bindFinalAuthority?.(() => {
        if (timeoutGeneration !== resultGeneration) throw new AppError('denied', 'Send result changed');
      });
      return send;
    });
    const captureRelease = vi.fn((sessionLease: SessionLease) => ({
        sessionLease,
        timeoutLease: { generation: timeoutGeneration },
      } as never));
    const vaultReleaseGate: NonNullable<RouterDeps['vaultReleaseGate']> = {
      capture: captureRelease,
      checkpoint: vi.fn(async (lease) => {
        if ((lease.timeoutLease as { generation: number }).generation !== timeoutGeneration) {
          throw new AppError('locked', 'stale timeout generation');
        }
        return {} as never;
      }),
      assertAuthorities: vi.fn((_proof, assertCurrent) => assertCurrent()),
      assert: vi.fn(),
    };
    const settings = intentSettings();
    settings.getServerUrl = vi.fn(async () => 'https://vault.example/');
    const router = createRouter({
      auth: {}, settings, vaultReleaseGate, vault: { createTextSend } as never,
    });

    await expect(router.handle({
      type: 'sends.createText', input: { name: 'Secret', text: 'value', deletionDays: 7 },
    })).resolves.toEqual({ ok: true, data: { send } });
    expect(createTextSend).toHaveBeenCalledOnce();
    expect(vaultReleaseGate.capture).toHaveBeenCalledOnce();
    expect(captureRelease.mock.results[0]?.value.timeoutLease).toEqual({ generation: 2 });
    expect(vaultReleaseGate.checkpoint).toHaveBeenCalledOnce();
  });

  it.each(['capture', 'checkpoint'] as const)(
    'returns a non-secret committed result when Send %s fails after the remote commit',
    async (failureStage) => {
      const send = { id: 's1', url: 'https://send.example/s1', name: 'Secret', type: 0, text: 'value' };
      const createTextSend = vi.fn(async (
        _input: unknown,
        _serverUrl: string,
        bindFinalAuthority?: (assertCurrent: () => void) => void,
      ) => {
        bindFinalAuthority?.(() => undefined);
        return send;
      });
      const capture = vi.fn((_sessionLease: SessionLease) => {
        if (failureStage === 'capture') throw new AppError('locked', 'session timed out');
        return { sessionLease: { generation: 0 }, timeoutLease: {} } as never;
      });
      const vaultReleaseGate: NonNullable<RouterDeps['vaultReleaseGate']> = {
        capture,
        checkpoint: vi.fn(async () => {
          throw new AppError('locked', 'session timed out');
        }),
        assertAuthorities: vi.fn((_proof, assertCurrent) => assertCurrent()),
        assert: vi.fn(),
      };
      const settings = intentSettings();
      settings.getServerUrl = vi.fn(async () => 'https://vault.example/');
      const router = createRouter({
        auth: {}, settings, vaultReleaseGate, vault: { createTextSend } as never,
      });

      const response = await router.handle({
        type: 'sends.createText', input: { name: 'Secret', text: 'value', deletionDays: 7 },
      });

      expect(response).toEqual({
        ok: false,
        error: {
          code: 'committed_unsynced',
          message: 'The Send was saved, but its secret result was withheld. Unlock and sync before continuing.',
        },
      });
      expect(JSON.stringify(response)).not.toContain('https://send.example/s1');
      expect(JSON.stringify(response)).not.toContain('"text":"value"');
      expect(createTextSend).toHaveBeenCalledOnce();
      expect(capture).toHaveBeenCalledOnce();
      expect(vaultReleaseGate.checkpoint).toHaveBeenCalledTimes(failureStage === 'checkpoint' ? 1 : 0);
    },
  );

  it.each([
    ['text create', 'createTextSend', {
      type: 'sends.createText', input: { name: 'Secret', text: 'value', deletionDays: 7 },
    }],
    ['file create', 'createFileSend', {
      type: 'sends.createFile', input: { name: 'Secret', deletionDays: 7 }, dataB64: 'AQID', fileName: 'a.txt',
    }],
    ['update', 'updateSend', {
      type: 'sends.update', id: 's1', input: { name: 'Secret' },
    }],
  ] as const)(
    'never reports a committed Send %s as an ordinary checkpoint failure',
    async (_label, method, request) => {
      const send = { id: 's1', url: 'https://send.example/s1', name: 'Secret', type: 0, text: 'value' };
      const mutation = vi.fn(async (...args: unknown[]) => {
        const bindFinalAuthority = args.at(-1);
        if (typeof bindFinalAuthority !== 'function') throw new Error('final authority binder is missing');
        bindFinalAuthority(() => undefined);
        return send;
      });
      const vaultReleaseGate: NonNullable<RouterDeps['vaultReleaseGate']> = {
        capture: vi.fn((sessionLease) => ({ sessionLease, timeoutLease: {} } as never)),
        checkpoint: vi.fn(async () => { throw new AppError('locked', 'session timed out'); }),
        assertAuthorities: vi.fn(),
        assert: vi.fn(),
      };
      const settings = intentSettings();
      settings.getServerUrl = vi.fn(async () => 'https://vault.example/');
      const router = createRouter({
        auth: {},
        settings,
        vaultReleaseGate,
        vault: { [method]: mutation } as unknown as RouterDeps['vault'],
      });

      await expect(router.handle(request as RequestMessage)).resolves.toMatchObject({
        ok: false,
        error: { code: 'committed_unsynced' },
      });
      expect(mutation).toHaveBeenCalledOnce();
    },
  );

  it('routes sends.update to vault.updateSend with the server URL', async () => {
    const updateSend = vi.fn(async () => ({ id: 's1', url: 'u', name: 'New', type: 0 }));
    const settings = { getServerUrl: vi.fn(async () => 'http://localhost:8080'), saveServerUrl: vi.fn(), getDefaultUriMatchStrategy: vi.fn(async () => 0), saveDefaultUriMatchStrategy: vi.fn(), getLockTimeout: vi.fn(async () => '15'), saveLockTimeout: vi.fn() };
    const router = createRouter({ auth: {}, vault: { updateSend } as never, settings: settings as never });
    const res = await router.handle({ type: 'sends.update', id: 's1', input: { name: 'New' } as never });
    expect(updateSend).toHaveBeenCalledWith(
      's1', { name: 'New' }, 'http://localhost:8080', expect.any(Function),
    );
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

  it('saves security settings and schedules a clipboard clear', async () => {
    const settings = {
      getServerUrl: async () => 'https://x', getDefaultUriMatchStrategy: async () => 0,
      getLockTimeout: async () => '15', getOnIdleAction: vi.fn(async (): Promise<OnIdleAction> => 'lock'),
      getClipboardClearSetting: vi.fn(async (): Promise<ClipboardClearSetting> => '60'), saveOnIdleAction: vi.fn(async () => {}),
      saveClipboardClearSetting: vi.fn(async () => {}), saveServerUrl: vi.fn(), saveDefaultUriMatchStrategy: vi.fn(), saveLockTimeout: vi.fn(),
    };
    const clipboard = { scheduleClear: vi.fn(async () => {}), cancelClear: vi.fn() };
    const router = createRouter({ auth: {} as never, vault: {} as never, settings: settings as never, clipboard } as never);

    const got = await router.handle({ type: 'settings.get' } as never);
    expect(got).toMatchObject({ ok: true, data: { onIdleAction: 'lock', clipboardClearSeconds: '60' } });

    await router.handle({ type: 'settings.saveSecurity', onIdleAction: 'logout', clipboardClearSeconds: '120' } as never);
    expect(settings.saveOnIdleAction).toHaveBeenCalledWith('logout');
    expect(settings.saveClipboardClearSetting).toHaveBeenCalledWith('120');

    await router.handle({ type: 'clipboard.scheduleClear', value: 'owned-secret' } as never);
    expect(clipboard.scheduleClear).toHaveBeenCalledWith('owned-secret');

    await router.handle({ type: 'settings.saveSecurity', onIdleAction: 'lock', clipboardClearSeconds: 'never' } as never);
    expect(clipboard.cancelClear).toHaveBeenCalledOnce();
  });

  it('clipboard.scheduleClear throws when clipboard dep is not wired', async () => {
    const router = createRouter({ auth: {}, vault: {}, settings: settingsStub });
    const res = await router.handle({ type: 'clipboard.scheduleClear', value: 'owned-secret' });
    expect(res).toEqual({ ok: false, error: { code: 'error', message: 'clipboard is not wired' } });
  });

  it.each(['0', '123456', '1234567890', '7W6CJ'])(
    'allows a content caller to claim owned clear for TOTP code %s',
    async (value) => {
      const clipboard = { scheduleClear: vi.fn(async () => {}) };
      const router = createRouter({
        auth: {}, vault: {}, settings: settingsStub, clipboard,
      });

      await expect(router.handle(
        { type: 'clipboard.scheduleClear', value },
        CONTENT_CONTEXT,
      )).resolves.toEqual({ ok: true, data: null });
      expect(clipboard.scheduleClear).toHaveBeenCalledWith(value);
    },
  );

  it.each([
    ['generic secret', { type: 'clipboard.scheduleClear', value: 'owned-secret' }],
    ['whitespace', { type: 'clipboard.scheduleClear', value: ' 123456' }],
    ['oversized numeric code', { type: 'clipboard.scheduleClear', value: '12345678901' }],
    ['lowercase Steam code', { type: 'clipboard.scheduleClear', value: '7w6cj' }],
    ['unknown property', { type: 'clipboard.scheduleClear', value: '123456', scope: 'generic' }],
  ])('rejects a content clipboard ownership claim containing %s', async (_label, unsafe) => {
    const clipboard = { scheduleClear: vi.fn(async () => {}) };
    const router = createRouter({ auth: {}, vault: {}, settings: settingsStub, clipboard });

    await expect(router.handle(unsafe as RequestMessage, CONTENT_CONTEXT)).resolves.toEqual({
      ok: false,
      error: { code: 'denied', message: 'TOTP clipboard ownership request is invalid' },
    });
    expect(clipboard.scheduleClear).not.toHaveBeenCalled();
  });

  it('keeps generic clipboard ownership available only to extension pages', async () => {
    const clipboard = { scheduleClear: vi.fn(async () => {}) };
    const router = createRouter({ auth: {}, vault: {}, settings: settingsStub, clipboard });

    await expect(router.handle({
      type: 'clipboard.scheduleClear',
      value: 'long-extension-page-secret',
    })).resolves.toEqual({ ok: true, data: null });
    expect(clipboard.scheduleClear).toHaveBeenCalledWith('long-extension-page-secret');
  });

  it('routes auth.rotateAccountKey', async () => {
    const auth = { rotateAccountKey: vi.fn(async () => {}) };
    const router = createRouter({ auth: auth as never, vault: {} as never, settings: {} as never } as never);
    expect(await router.handle({ type: 'auth.rotateAccountKey', masterPassword: 'pw' } as never)).toEqual({ ok: true, data: null });
    expect(auth.rotateAccountKey).toHaveBeenCalledWith('pw');
  });


  it('passes master-password proof to the worker-side cipher-detail reprompt gate', async () => {
    const getCipherDetail = vi.fn(async () => undefined);
    const router = createRouter({ auth: {}, vault: { getCipherDetail }, settings: settingsStub });

    await router.handle({
      type: 'vault.getCipherDetail', id: 'cipher-1', masterPassword: 'verified-secret',
    });

    expect(getCipherDetail).toHaveBeenCalledWith(
      'cipher-1', 'verified-secret', expect.any(Function),
    );
  });

  it('routes popup-open and identity-scoped sync status without requiring an unlocked lease', async () => {
    const popupOpened = vi.fn(async () => {});
    const suppressApprovalNotifications = vi.fn(async () => undefined);
    const status = {
      identity: 'https://vault.example/\nuser@example.com',
      lastSuccessfulSyncAt: 123,
      dirty: true,
      syncing: false,
    };
    const syncScheduler = {
      manual: vi.fn(async () => {}),
      popupOpened,
      getLastSuccess: vi.fn(async () => 123),
      getSyncStatus: vi.fn(async () => status),
    };
    const lockedGate = {
      capture: () => { throw new AppError('locked', 'Vault is locked'); },
      assert: vi.fn(),
    };
    const router = createRouter({
      auth: {}, vault: {}, settings: settingsStub, sessionGate: lockedGate, syncScheduler,
      onDeviceLoginApprovalPopupOpened: suppressApprovalNotifications,
    });

    await expect(router.handle({ type: 'vault.popupOpened' }, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: null });
    await expect(router.handle({ type: 'vault.getSyncStatus' }, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: status });
    expect(popupOpened).toHaveBeenCalledOnce();
    expect(suppressApprovalNotifications).toHaveBeenCalledOnce();
  });

  it('keeps popup routing available when approval-notification cleanup fails', async () => {
    const popupOpened = vi.fn(async () => undefined);
    const router = createRouter({
      auth: {},
      vault: {},
      settings: settingsStub,
      syncScheduler: {
        manual: vi.fn(async () => undefined),
        popupOpened,
        getLastSuccess: vi.fn(async () => undefined),
        getSyncStatus: vi.fn(async () => ({ dirty: false, syncing: false })),
      },
      onDeviceLoginApprovalPopupOpened: () => {
        throw new Error('private notification cleanup failure');
      },
    });

    await expect(router.handle({ type: 'vault.popupOpened' }, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: null });
    expect(popupOpened).toHaveBeenCalledOnce();
  });

  it('does not return a manual-sync listing when the session expires during sync', async () => {
    let current = true;
    const sessionGate: RouterDeps['sessionGate'] = {
      capture: () => ({ generation: 1 }),
      assert: () => {
        if (!current) throw new AppError('locked', 'Vault session timed out');
      },
    };
    const listItems = vi.fn(async () => ({ items: [], folders: [], collections: [], orgPermissions: [] }));
    const router = createRouter({
      auth: {},
      vault: { listItems },
      settings: settingsStub,
      sessionGate,
      syncScheduler: {
        manual: vi.fn(async () => { current = false; }),
        popupOpened: vi.fn(async () => undefined),
        getLastSuccess: vi.fn(async () => undefined),
        getSyncStatus: vi.fn(async () => ({ dirty: false, syncing: false })),
      },
    });

    await expect(router.handle({ type: 'vault.sync' }, EXTENSION_PAGE_CONTEXT)).resolves.toEqual({
      ok: false,
      error: { code: 'locked', message: 'Vault session timed out' },
    });
    expect(listItems).toHaveBeenCalledOnce();
  });

  it('rejects popup lifecycle messages from non-popup pages', async () => {
    const router = createRouter({ auth: {}, vault: {}, settings: settingsStub });
    await expect(router.handle({ type: 'vault.popupOpened' }, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    await expect(router.handle({ type: 'vault.popupOpened' }, OPTIONS_PAGE_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
  });

  it('records exact iframe inventories using only browser-owned content identity', async () => {
    const recordIframeAllowReport = vi.fn(async () => true);
    const invalidateFrame = vi.fn();
    const router = createRouter({
      auth: {},
      vault: {},
      settings: settingsStub,
      websitePasskeyPermissionsPolicy: { recordIframeAllowReport, invalidateFrame },
    });
    const request = {
      type: 'websitePasskey.reportIframeInventory' as const,
      iframes: [{
        src: 'https://child.example/frame',
        allow: 'publickey-credentials-get',
        srcdoc: false,
      }],
    };

    await expect(router.handle(request, CONTENT_CONTEXT))
      .resolves.toEqual({ ok: true, data: null });
    expect(recordIframeAllowReport).toHaveBeenCalledWith({
      tabId: CONTENT_CONTEXT.tabId,
      frameId: CONTENT_CONTEXT.frameId,
      documentId: CONTENT_CONTEXT.documentId,
      url: CONTENT_CONTEXT.url,
    }, { iframes: request.iframes });
    await expect(router.handle(request, EXTENSION_PAGE_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(recordIframeAllowReport).toHaveBeenCalledOnce();
  });

  it('actively revokes malformed iframe reports without invoking accessors', async () => {
    const recordIframeAllowReport = vi.fn(async () => true);
    const invalidateFrame = vi.fn();
    const getter = vi.fn(() => []);
    const request = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(request, 'type', {
      enumerable: true,
      value: 'websitePasskey.reportIframeInventory',
    });
    Object.defineProperty(request, 'iframes', { enumerable: true, get: getter });
    const router = createRouter({
      auth: {},
      vault: {},
      settings: settingsStub,
      websitePasskeyPermissionsPolicy: { recordIframeAllowReport, invalidateFrame },
    });

    await expect(router.handle(request as never, CONTENT_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(getter).not.toHaveBeenCalled();
    expect(invalidateFrame).toHaveBeenCalledWith(CONTENT_CONTEXT.tabId, CONTENT_CONTEXT.frameId);
    expect(recordIframeAllowReport).not.toHaveBeenCalled();
  });

  it('routes website passkey commands only from the exact popup path', async () => {
    const ceremonyId = '00000000-0000-4000-8000-000000000001';
    const approval = {
      ceremonyId,
      kind: 'get' as const,
      origin: 'https://example.com',
      rpId: 'example.com',
      state: 'awaiting' as const,
      candidates: [{ id: 'credential-A', name: 'Work' }],
    };
    const getApproval = vi.fn(async () => approval);
    const websitePasskeys = {
      getApproval,
      approve: vi.fn(async () => 'completed' as const),
      fallbackOnce: vi.fn(async () => 'fallback' as const),
      fallbackAlways: vi.fn(async () => 'fallback' as const),
      cancel: vi.fn(async () => 'fallback' as const),
      getLockedContinuation: vi.fn(async () => ({ status: 'none' as const })),
      resumeLockedContinuation: vi.fn(async () => 'stale' as const),
      cancelLockedContinuation: vi.fn(async () => false),
    };
    const router = createRouter({ auth: {}, vault: {}, settings: settingsStub, websitePasskeys });

    await expect(router.handle({ type: 'websitePasskey.getApproval', ceremonyId }))
      .resolves.toEqual({ ok: true, data: { approval } });
    expect(getApproval).toHaveBeenCalledWith(ceremonyId);

    const optionsContext = {
      kind: 'extensionPage' as const,
      url: 'chrome-extension://test/ui/options/options.html',
      origin: 'chrome-extension://test',
    };
    await expect(router.handle({ type: 'websitePasskey.cancel', ceremonyId }, optionsContext))
      .resolves.toEqual({ ok: false, error: { code: 'denied', message: 'sender not permitted' } });
    await expect(router.handle({ type: 'websitePasskey.cancel', ceremonyId }, {
      ...EXTENSION_PAGE_CONTEXT,
      url: 'chrome-extension://test/ui/popup/popup.html.evil',
    })).resolves.toEqual({ ok: false, error: { code: 'denied', message: 'sender not permitted' } });
    await expect(router.handle({ type: 'websitePasskey.cancel', ceremonyId }, CONTENT_CONTEXT))
      .resolves.toEqual({ ok: false, error: { code: 'denied', message: 'sender not permitted' } });
    await expect(router.handle({
      type: 'websitePasskey.getApproval',
      ceremonyId: `${ceremonyId}\n`,
    }, EXTENSION_PAGE_CONTEXT)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    expect(websitePasskeys.cancel).not.toHaveBeenCalled();
  });

  it('binds locked continuation lifecycle to the exact popup document', async () => {
    const continuationId = '00000000-0000-4000-8000-000000000001';
    const websitePasskeys = {
      getApproval: vi.fn(),
      approve: vi.fn(),
      fallbackOnce: vi.fn(),
      fallbackAlways: vi.fn(),
      cancel: vi.fn(),
      getLockedContinuation: vi.fn(async () => ({
        status: 'unlock_required' as const,
        continuationId,
        expiresAt: 30_000,
      })),
      resumeLockedContinuation: vi.fn(async () => 'started' as const),
      cancelLockedContinuation: vi.fn(async () => true),
    };
    const router = createRouter({ auth: {}, vault: {}, settings: settingsStub, websitePasskeys });

    await expect(router.handle({
      type: 'websitePasskey.lockedStatus',
      continuationId,
    }, EXTENSION_PAGE_CONTEXT)).resolves.toEqual({
      ok: true,
      data: { status: 'unlock_required', continuationId, expiresAt: 30_000 },
    });
    expect(websitePasskeys.getLockedContinuation).toHaveBeenCalledWith(
      continuationId,
      EXTENSION_PAGE_CONTEXT.documentId,
    );
    await expect(router.handle({
      type: 'websitePasskey.resumeLocked',
      continuationId,
    }, EXTENSION_PAGE_CONTEXT)).resolves.toEqual({ ok: true, data: { status: 'started' } });
    await expect(router.handle({
      type: 'websitePasskey.cancelLocked',
      continuationId,
    }, EXTENSION_PAGE_CONTEXT)).resolves.toEqual({ ok: true, data: { cancelled: true } });

    const noDocument = { ...EXTENSION_PAGE_CONTEXT } as Partial<typeof EXTENSION_PAGE_CONTEXT>;
    delete noDocument.documentId;
    await expect(router.handle({
      type: 'websitePasskey.lockedStatus',
      continuationId,
    }, noDocument as RequestContext)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    await expect(router.handle({
      type: 'websitePasskey.resumeLocked',
      continuationId,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });

    const getter = vi.fn(() => continuationId);
    const unsafe = { type: 'websitePasskey.resumeLocked' } as Record<string, unknown>;
    Object.defineProperty(unsafe, 'continuationId', { enumerable: true, get: getter });
    await expect(router.handle(unsafe as never, EXTENSION_PAGE_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(getter).not.toHaveBeenCalled();
    expect(websitePasskeys.resumeLockedContinuation).toHaveBeenCalledTimes(1);
  });

  it('strictly validates website passkey popup selections before coordinator access', async () => {
    const ceremonyId = '00000000-0000-4000-8000-000000000001';
    const approve = vi.fn(async () => 'completed' as const);
    const websitePasskeys = {
      getApproval: vi.fn(),
      approve,
      fallbackOnce: vi.fn(),
      fallbackAlways: vi.fn(),
      cancel: vi.fn(),
      getLockedContinuation: vi.fn(),
      resumeLockedContinuation: vi.fn(),
      cancelLockedContinuation: vi.fn(),
    };
    const router = createRouter({ auth: {}, vault: {}, settings: settingsStub, websitePasskeys });
    await expect(router.handle({
      type: 'websitePasskey.approve',
      ceremonyId,
      selection: { kind: 'credential', credentialId: 'credential-A' },
    })).resolves.toEqual({ ok: true, data: { outcome: 'completed' } });
    expect(approve).toHaveBeenCalledWith(ceremonyId, { kind: 'credential', credentialId: 'credential-A' });

    await expect(router.handle({
      type: 'websitePasskey.approve',
      ceremonyId,
      selection: { kind: 'credential', credentialId: 'credential-A', injected: true },
    } as never)).resolves.toEqual({
      ok: false,
      error: { code: 'denied', message: 'Website passkey request is invalid' },
    });
    expect(approve).toHaveBeenCalledTimes(1);
  });
});

describe('account passkey router boundary', () => {
  it('routes begin, status, and cancel only through the extension-page browser orchestrator', async () => {
    const waiting = Object.freeze({
      status: 'waiting' as const,
      attemptId: '11111111-1111-4111-8111-111111111111',
      expiresAt: 2_000,
    });
    const accountPasskey = {
      begin: vi.fn(async () => waiting),
      status: vi.fn(async () => waiting),
      cancel: vi.fn(async () => true),
    };
    const deviceCancel = vi.fn(async () => true);
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      accountPasskey: accountPasskey as never,
      deviceLogin: { cancelCurrent: deviceCancel } as never,
    });

    await expect(router.handle({ type: 'auth.accountPasskey.begin' }, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: waiting });
    await expect(router.handle({ type: 'auth.accountPasskey.status' }, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: waiting });
    await expect(router.handle({ type: 'auth.accountPasskey.cancel' }, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: { cancelled: true } });
    accountPasskey.cancel.mockResolvedValueOnce(false);
    await expect(router.handle({ type: 'auth.accountPasskey.cancel' }, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: { cancelled: false } });
    expect(deviceCancel).toHaveBeenCalledBefore(accountPasskey.begin);

    for (const request of [
      { type: 'auth.accountPasskey.begin' as const },
      { type: 'auth.accountPasskey.status' as const },
      { type: 'auth.accountPasskey.cancel' as const },
    ]) {
      await expect(router.handle(request, CONTENT_CONTEXT)).resolves.toMatchObject({
        ok: false,
        error: { code: 'denied' },
      });
    }
    expect(accountPasskey.begin).toHaveBeenCalledTimes(1);
    expect(accountPasskey.status).toHaveBeenCalledTimes(1);
    expect(accountPasskey.cancel).toHaveBeenCalledTimes(2);
  });

  it('clears an account passkey attempt before password or device login starts', async () => {
    const events: string[] = [];
    const accountPasskey = {
      begin: vi.fn(async () => ({
        status: 'unavailable' as const,
        reason: 'host_access_unavailable' as const,
      })),
      status: vi.fn(async () => ({ status: 'none' as const })),
      cancel: vi.fn(async () => { events.push('account-cancel'); return true; }),
    };
    const auth = {
      login: vi.fn(async () => { events.push('password-login'); return { kind: 'unlocked' as const }; }),
    };
    const deviceLogin = {
      cancelCurrent: vi.fn(async () => true),
      begin: vi.fn(async () => { events.push('device-login'); return { status: 'not_known_device' as const }; }),
    };
    const router = createRouter({
      auth,
      vault: {},
      settings: intentSettings(),
      accountPasskey: accountPasskey as never,
      deviceLogin: deviceLogin as never,
    });

    await router.handle({ type: 'auth.login', email: 'user@example.com', masterPassword: 'secret' });
    expect(events).toEqual(['account-cancel', 'password-login']);
    events.length = 0;
    await router.handle({ type: 'auth.deviceLogin.begin', email: 'user@example.com' });
    expect(events).toEqual(['account-cancel', 'device-login']);
  });
});

describe('standard SSO router boundary', () => {
  it('routes exact popup requests, binds requirement reads to a document, and isolates auth flows', async () => {
    const events: string[] = [];
    const waiting = Object.freeze({
      status: 'waiting' as const,
      attemptId: '11111111-1111-4111-8111-111111111111',
      generation: 1,
      email: 'user@example.com',
      expiresAt: 2_000,
    });
    const sso = {
      reconcileHandoff: vi.fn(async () => { events.push('sso-reconcile'); return false; }),
      begin: vi.fn(async () => { events.push('sso-begin'); return waiting; }),
      status: vi.fn(async () => waiting),
      cancel: vi.fn(async () => true),
      cancelCurrent: vi.fn(async () => true),
    };
    const requirement = vi.fn(async () => true);
    const accountCancel = vi.fn(async () => { events.push('account-cancel'); return true; });
    const deviceCancel = vi.fn(async () => { events.push('device-cancel'); return true; });
    const pendingCancel = vi.fn(async () => { events.push('pending-cancel'); return true; });
    const router = createRouter({
      auth: { cancelPendingLogin: pendingCancel },
      vault: {},
      settings: intentSettings(),
      sso: sso as never,
      ssoRequirement: { isRequired: requirement },
      accountPasskey: { cancel: accountCancel } as never,
      deviceLogin: { cancelCurrent: deviceCancel } as never,
    });

    await expect(router.handle({
      type: 'auth.sso.begin',
      email: 'user@example.com',
      organizationIdentifier: 'example-org',
    }, EXTENSION_PAGE_CONTEXT)).resolves.toEqual({ ok: true, data: waiting });
    expect(events).toEqual([
      'sso-reconcile',
      'account-cancel',
      'device-cancel',
      'pending-cancel',
      'sso-begin',
    ]);
    expect(sso.begin).toHaveBeenCalledWith(
      'user@example.com',
      EXTENSION_PAGE_CONTEXT.documentId,
      'example-org',
    );
    await expect(router.handle({ type: 'auth.sso.status' }, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: waiting });
    await expect(router.handle({
      type: 'auth.sso.status',
      attemptId: waiting.attemptId,
      generation: waiting.generation,
    }, EXTENSION_PAGE_CONTEXT)).resolves.toEqual({ ok: true, data: waiting });
    expect(sso.status).toHaveBeenLastCalledWith({
      attemptId: waiting.attemptId,
      generation: waiting.generation,
    });
    await expect(router.handle({
      type: 'auth.sso.cancel',
      attemptId: waiting.attemptId,
      generation: waiting.generation,
    }, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: { cancelled: true } });
    expect(sso.cancel).toHaveBeenCalledWith({
      attemptId: waiting.attemptId,
      generation: waiting.generation,
    });
    await expect(router.handle({
      type: 'auth.sso.requirement',
      email: 'user@example.com',
    }, EXTENSION_PAGE_CONTEXT)).resolves.toEqual({ ok: true, data: { required: true } });
    expect(requirement).toHaveBeenCalledWith('user@example.com');

    const popupWithoutDocument = { ...EXTENSION_PAGE_CONTEXT };
    delete (popupWithoutDocument as Partial<RequestContext>).documentId;
    await expect(router.handle({
      type: 'auth.sso.requirement',
      email: 'user@example.com',
    }, popupWithoutDocument)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    await expect(router.handle({
      type: 'auth.sso.begin',
      email: 'user@example.com',
    }, popupWithoutDocument)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
  });

  it.each([
    { type: 'auth.sso.begin', email: 'user@example.com' },
    { type: 'auth.sso.requirement', email: 'user@example.com' },
    { type: 'auth.sso.status' },
    {
      type: 'auth.sso.cancel',
      attemptId: '11111111-1111-4111-8111-111111111111',
      generation: 1,
    },
  ] as const)('rejects $type from content and non-popup extension pages', async (request) => {
    const call = vi.fn();
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      sso: {
        reconcileHandoff: call, begin: call, status: call, cancel: call, cancelCurrent: call,
      } as never,
      ssoRequirement: { isRequired: call },
    });

    await expect(router.handle(request as RequestMessage, CONTENT_CONTEXT)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    await expect(router.handle(request as RequestMessage, OPTIONS_PAGE_CONTEXT)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    expect(call).not.toHaveBeenCalled();
  });
});

describe('Duo two-factor router boundary', () => {
  it('starts and cancels Duo only from the exact popup document', async () => {
    const begin = vi.fn(async () => ({ status: 'waiting' as const }));
    const cancel = vi.fn(async () => true);
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      duo: { begin, cancel } as never,
    });
    const request = {
      type: 'auth.duo.begin' as const,
      flow: 'password' as const,
      provider: 2 as const,
      continuationId: '22222222-2222-4222-8222-222222222222',
      remember: true,
    };

    await expect(router.handle(request, EXTENSION_PAGE_CONTEXT)).resolves.toEqual({
      ok: true,
      data: { status: 'waiting' },
    });
    expect(begin).toHaveBeenCalledWith(request, EXTENSION_PAGE_CONTEXT.documentId);
    await expect(router.handle({
      type: 'auth.duo.cancel',
      flow: 'password',
      continuationId: request.continuationId,
    }, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: { cancelled: true } });
    for (const context of [CONTENT_CONTEXT, OPTIONS_PAGE_CONTEXT]) {
      await expect(router.handle(request, context)).resolves.toMatchObject({
        ok: false,
        error: { code: 'denied' },
      });
    }
    expect(begin).toHaveBeenCalledOnce();
  });

  it('closes a waiting Duo tab before cancelling the password continuation', async () => {
    const order: string[] = [];
    const router = createRouter({
      auth: { cancelPendingLogin: vi.fn(async () => { order.push('pending'); return true; }) },
      vault: {},
      settings: intentSettings(),
      duo: {
        begin: vi.fn(),
        cancel: vi.fn(async () => { order.push('duo'); return true; }),
      } as never,
    });

    await router.handle({
      type: 'auth.pendingLogin.cancel',
      continuationId: '22222222-2222-4222-8222-222222222222',
    }, EXTENSION_PAGE_CONTEXT);
    expect(order).toEqual(['duo', 'pending']);
  });

  it('passes the stale password continuation only to an exact Duo cancel', async () => {
    const cancel = vi.fn(async () => false);
    const cancelPendingLogin = vi.fn(async () => false);
    const router = createRouter({
      auth: { cancelPendingLogin },
      vault: {},
      settings: intentSettings(),
      duo: { cancel } as never,
    });
    const continuationId = '33333333-3333-4333-8333-333333333333';

    await router.handle({
      type: 'auth.pendingLogin.cancel',
      continuationId,
    }, EXTENSION_PAGE_CONTEXT);

    expect(cancel).toHaveBeenCalledWith({ flow: 'password', continuationId });
    expect(cancelPendingLogin).toHaveBeenCalledWith({ continuationId });
  });

  it('cancels only the matching device Duo generation before device-login Back', async () => {
    const order: string[] = [];
    const cancelDeviceLogin = vi.fn(async (generation: number) => {
      order.push(`duo:${generation}`);
      return true;
    });
    const cancel = vi.fn(async (generation: number) => {
      order.push(`device:${generation}`);
      return true;
    });
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      duo: { cancelDeviceLogin } as never,
      deviceLogin: { cancel } as never,
    });

    await router.handle({ type: 'auth.deviceLogin.cancel', generation: 9 }, EXTENSION_PAGE_CONTEXT);
    expect(order).toEqual(['duo:9', 'device:9']);
  });

  it.each([
    { type: 'auth.login', email: 'user@example.com', masterPassword: 'password' },
    { type: 'auth.sso.begin', email: 'user@example.com' },
    { type: 'auth.startRegistration', email: 'user@example.com' },
    { type: 'auth.accountPasskey.begin' },
    { type: 'auth.deviceLogin.begin', email: 'user@example.com' },
  ] as const)('retires only an invalidated Duo owner after $type replaces auth', async (request) => {
    const retireInvalidWaiting = vi.fn(async () => true);
    const router = createRouter({
      auth: {
        login: vi.fn(async () => ({ kind: 'unlocked' as const })),
        startRegistration: vi.fn(async () => ({
          kind: 'registrationEmailSent' as const,
          email: 'user@example.com',
        })),
        cancelPendingLogin: vi.fn(async () => true),
      },
      vault: {},
      settings: intentSettings(),
      duo: { retireInvalidWaiting } as never,
      sso: {
        cancelCurrent: vi.fn(async () => true),
        reconcileHandoff: vi.fn(async () => undefined),
        begin: vi.fn(async () => ({ status: 'waiting' as const })),
      } as never,
      deviceLogin: {
        cancelCurrent: vi.fn(async () => true),
        begin: vi.fn(async () => ({ status: 'pending' as const })),
      } as never,
      accountPasskey: {
        cancel: vi.fn(async () => true),
        begin: vi.fn(async () => ({ status: 'waiting' as const })),
      } as never,
    });

    await router.handle(request, EXTENSION_PAGE_CONTEXT);
    expect(retireInvalidWaiting).toHaveBeenCalledOnce();
  });
});

describe('client event acknowledgement router boundary', () => {
  const cipherId = '33333333-3333-4333-8333-333333333333';
  const ackId = '44444444-4444-4444-8444-444444444444';

  it('maps only auditable field actions to worker-owned popup acknowledgements', async () => {
    const events = clientEventsHarness();
    const issue = vi.fn((..._args: unknown[]) => ackId);
    let vaultReadCurrent = true;
    const assertVaultReadCurrent = vi.fn(() => {
      if (!vaultReadCurrent) throw new Error('vault read changed');
    });
    const getField = vi.fn(async (...args: unknown[]) => {
      const bindFinalAuthority = args[3] as ((assertCurrent: () => void) => void) | undefined;
      bindFinalAuthority?.(assertVaultReadCurrent);
      return 'secret';
    });
    const router = createRouter({
      auth: {},
      settings: intentSettings(),
      vault: { getField } as never,
      clientEvents: events.clientEvents,
      clientEventAcks: { issue, consume: vi.fn() } as never,
    });
    const cases = [
      ['password', 'reveal', ClientEventType.Cipher_ClientToggledPasswordVisible],
      ['password', 'copy', ClientEventType.Cipher_ClientCopiedPassword],
      ['card.code', 'reveal', ClientEventType.Cipher_ClientToggledCardCodeVisible],
      ['card.code', 'copy', ClientEventType.Cipher_ClientCopiedCardCode],
      ['card.number', 'reveal', ClientEventType.Cipher_ClientToggledCardNumberVisible],
    ] as const;

    for (const [field, clientEventPurpose, type] of cases) {
      await expect(router.handle({
        type: 'vault.getField',
        id: cipherId,
        field,
        clientEventPurpose,
      }, EXTENSION_PAGE_CONTEXT)).resolves.toMatchObject({
        ok: true,
        data: { value: 'secret', clientEventAckId: ackId },
      });
      expect(events.clientEvents.prepare).toHaveBeenLastCalledWith({ type, cipherId });
    }

    const prepareCount = events.clientEvents.prepare.mock.calls.length;
    await expect(router.handle({
      type: 'vault.getField',
      id: cipherId,
      field: 'card.number',
      clientEventPurpose: 'copy',
    }, EXTENSION_PAGE_CONTEXT)).resolves.toEqual({ ok: true, data: { value: 'secret' } });
    expect(events.clientEvents.prepare).toHaveBeenCalledTimes(prepareCount);
    expect(issue).toHaveBeenCalledTimes(cases.length);
    expect(issue.mock.calls[0]?.[0]).toEqual({ kind: 'popup', documentId: 'popup-doc-1' });
    expect(issue.mock.calls[0]?.[1]).toBe(events.eventReceipt);
    expect(issue.mock.calls[0]?.[2]).toEqual(expect.any(Function));
    const assertAckCurrent = issue.mock.calls[0]?.[2] as (() => void) | undefined;
    expect(() => assertAckCurrent?.()).not.toThrow();
    vaultReadCurrent = false;
    expect(() => assertAckCurrent?.()).toThrow('vault read changed');
    expect(assertVaultReadCurrent).toHaveBeenCalled();
  });

  it('validates Hidden custom fields and intentional detail/editor purposes before issuing', async () => {
    const events = clientEventsHarness();
    const issue = vi.fn((..._args: unknown[]) => ackId);
    const getCipherDetail = vi.fn(async () => ({
      id: cipherId,
      type: 1,
      name: 'Example',
      fields: [{ type: 1, name: 'Hidden' }],
    }));
    const router = createRouter({
      auth: {},
      settings: intentSettings(),
      vault: {
        getCipherDetail,
        getCustomField: vi.fn(async () => 'hidden'),
        getCipherInput: vi.fn(async () => ({ type: 1, name: 'Example' })),
      } as never,
      clientEvents: events.clientEvents,
      clientEventAcks: { issue, consume: vi.fn() } as never,
    });

    await expect(router.handle({
      type: 'vault.getCustomField', id: cipherId, index: 0, clientEventPurpose: 'reveal',
    }, EXTENSION_PAGE_CONTEXT)).resolves.toMatchObject({
      ok: true, data: { clientEventAckId: ackId },
    });
    expect(events.clientEvents.prepare).toHaveBeenLastCalledWith({
      type: ClientEventType.Cipher_ClientToggledHiddenFieldVisible,
      cipherId,
    });

    await expect(router.handle({
      type: 'vault.getCipherDetail', id: cipherId, clientEventPurpose: 'view',
    }, EXTENSION_PAGE_CONTEXT)).resolves.toMatchObject({
      ok: true, data: { clientEventAckId: ackId },
    });
    await expect(router.handle({
      type: 'vault.getCipherInput', id: cipherId, cipherInputPurpose: 'edit', clientEventPurpose: 'editor',
    }, EXTENSION_PAGE_CONTEXT)).resolves.toMatchObject({
      ok: true, data: { clientEventAckId: ackId },
    });
    expect(events.clientEvents.prepare).toHaveBeenLastCalledWith({
      type: ClientEventType.Cipher_ClientViewed,
      cipherId,
    });
  });

  it('derives every acknowledgement owner exclusively from browser sender metadata', async () => {
    const consume = vi.fn(async (..._args: unknown[]) => ({ kind: 'committed' as const }));
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      clientEventAcks: { issue: vi.fn(), consume } as never,
    });
    const options = { ...OPTIONS_PAGE_CONTEXT, documentId: 'options-doc-1' } satisfies RequestContext;

    await router.handle({ type: 'clientEvent.ack', ackId }, EXTENSION_PAGE_CONTEXT);
    await router.handle({ type: 'clientEvent.ack', ackId }, CONTENT_CONTEXT);
    await router.handle({ type: 'clientEvent.ack', ackId }, options);

    expect(consume.mock.calls.map((call) => call[1])).toEqual([
      { kind: 'popup', documentId: 'popup-doc-1' },
      { kind: 'content', tabId: 7, frameId: 0, documentId: 'doc-1' },
      { kind: 'options', documentId: 'options-doc-1' },
    ]);
  });

  it('issues content ACK IDs only after exact login intent redemption', async () => {
    const events = clientEventsHarness();
    const issue = vi.fn((..._args: unknown[]) => ackId);
    const findAutofillCandidates = vi.fn(async () => [{
      id: cipherId,
      name: 'Example',
      matchedUri: CONTENT_CONTEXT.url,
      matchType: 0 as const,
      favorite: false,
    }]);
    let vaultReadCurrent = true;
    const getInteractiveAutofillLoginData = vi.fn(async (...args: unknown[]) => {
      const bindFinalAuthority = args[5] as ((assertCurrent: () => void) => void) | undefined;
      bindFinalAuthority?.(() => {
        if (!vaultReadCurrent) throw new Error('interactive read changed');
      });
      return {
        login: { username: 'user@example.com', password: 'secret' },
        customAssignments: [],
      };
    });
    const router = createRouter({
      auth: {},
      vault: { findAutofillCandidates, getInteractiveAutofillLoginData },
      settings: intentSettings(),
      clientEvents: events.clientEvents,
      clientEventAcks: { issue, consume: vi.fn() } as never,
    });
    const issued = await router.handle(loginIntentRequest(cipherId), CONTENT_CONTEXT);
    const token = intentId(issued);

    await expect(router.handle({
      type: 'autofill.redeemLoginIntent', intentId: token,
    }, CONTENT_CONTEXT)).resolves.toMatchObject({
      ok: true,
      data: { clientEventAckId: ackId },
    });
    expect(events.clientEvents.prepare).toHaveBeenCalledWith({
      type: ClientEventType.Cipher_ClientAutofilled,
      cipherId,
    });
    expect(issue).toHaveBeenCalledWith(
      { kind: 'content', tabId: 7, frameId: 0, documentId: 'doc-1' },
      events.eventReceipt,
      expect.any(Function),
    );
    const assertAckCurrent = issue.mock.calls[0]?.[2] as (() => void) | undefined;
    expect(() => assertAckCurrent?.()).not.toThrow();
    vaultReadCurrent = false;
    expect(() => assertAckCurrent?.()).toThrow('interactive read changed');
  });
});

describe('organization data ownership router boundary', () => {
  const migrateAuthorizationId = '11111111-1111-4111-8111-111111111111';
  const leaveAuthorizationId = '22222222-2222-4222-8222-222222222222';
  const listing = Object.freeze({
    items: [], folders: [], collections: [], orgPermissions: [], personalCreationAllowed: false,
  });

  it('forwards exact popup-bound consent data', async () => {
    const getOrganizationDataOwnershipStatus = vi.fn(async () => ({
      status: 'migration_available' as const,
      organizationId: 'org-1',
      collectionId: 'collection-1',
      personalItemCount: 2,
      migrateAuthorization: { authorizationId: migrateAuthorizationId, expiresAt: 31_000 },
      leaveAuthorization: { authorizationId: leaveAuthorizationId, expiresAt: 31_000 },
    }));
    const migrateOrganizationDataOwnership = vi.fn(async () => listing);
    const leaveOrganizationDataOwnership = vi.fn(async () => listing);
    const events = clientEventsHarness();
    const router = createRouter({
      auth: {},
      settings: intentSettings(),
      vault: {
        getOrganizationDataOwnershipStatus,
        migrateOrganizationDataOwnership,
        leaveOrganizationDataOwnership,
      } as never,
      clientEvents: events.clientEvents,
    });

    await expect(router.handle(
      { type: 'vault.getOrganizationDataOwnershipStatus' },
      EXTENSION_PAGE_CONTEXT,
    )).resolves.toMatchObject({
      ok: true,
      data: { migrateAuthorization: { authorizationId: migrateAuthorizationId } },
    });
    const migrationRequest = {
      type: 'vault.migrateOrganizationDataOwnership',
      organizationId: 'org-1',
      collectionId: 'collection-1',
      authorizationId: migrateAuthorizationId,
      masterPassword: 'secret',
    } as const;
    await expect(router.handle(
      migrationRequest,
      EXTENSION_PAGE_CONTEXT,
    )).resolves.toEqual({ ok: true, data: listing });
    await expect(router.handle({
      type: 'vault.leaveOrganizationDataOwnership',
      organizationId: 'org-1',
      authorizationId: leaveAuthorizationId,
    }, EXTENSION_PAGE_CONTEXT)).resolves.toEqual({ ok: true, data: listing });

    expect(migrateOrganizationDataOwnership)
      .toHaveBeenCalledWith(
        'org-1', 'collection-1', migrateAuthorizationId, 'popup-doc-1', 'secret',
      );
    expect(leaveOrganizationDataOwnership)
      .toHaveBeenCalledWith('org-1', leaveAuthorizationId, 'popup-doc-1');
    expect(migrationRequest.masterPassword).toBe('');
    expect(getOrganizationDataOwnershipStatus).toHaveBeenCalledWith('popup-doc-1');
    expect(events.clientEvents.prepare).toHaveBeenCalledOnce();
    expect(events.clientEvents.prepare).toHaveBeenCalledWith({
      type: ClientEventType.Organization_ItemOrganization_Accepted,
      organizationId: 'org-1',
    });
    expect(events.clientEvents.commit).toHaveBeenCalledWith(events.eventReceipt);
  });

  it('commits migration events only after authoritative migration success', async () => {
    const order: string[] = [];
    const events = clientEventsHarness(order);
    const migrateOrganizationDataOwnership = vi.fn(async () => {
      order.push('migrate');
      return listing;
    });
    const router = createRouter({
      auth: {}, settings: intentSettings(),
      vault: { migrateOrganizationDataOwnership } as never,
      clientEvents: events.clientEvents,
    });
    const request = {
      type: 'vault.migrateOrganizationDataOwnership' as const,
      organizationId: '11111111-1111-4111-8111-111111111111',
      collectionId: 'collection-1',
      authorizationId: migrateAuthorizationId,
      masterPassword: 'secret',
    };

    await expect(router.handle(request, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: listing });
    expect(order).toEqual(['prepare', 'migrate', 'commit']);

    const failedEvents = clientEventsHarness();
    const failed = createRouter({
      auth: {}, settings: intentSettings(),
      vault: {
        migrateOrganizationDataOwnership: vi.fn(async () => { throw new Error('migration failed'); }),
      } as never,
      clientEvents: failedEvents.clientEvents,
    });
    await expect(failed.handle({ ...request, masterPassword: 'secret' }, EXTENSION_PAGE_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { message: 'migration failed' } });
    expect(failedEvents.clientEvents.commit).not.toHaveBeenCalled();
  });

  it('commits decline only after authoritative leave success on an explicitly supported server', async () => {
    const order: string[] = [];
    const events = clientEventsHarness(order);
    const leaveOrganizationDataOwnership = vi.fn(async () => {
      order.push('leave');
      return listing;
    });
    const router = createRouter({
      auth: {},
      settings: intentSettings(),
      vault: { leaveOrganizationDataOwnership } as never,
      clientEvents: {
        ...events.clientEvents,
        supportsOrganizationDecline: () => true,
      },
    });
    const request = {
      type: 'vault.leaveOrganizationDataOwnership' as const,
      organizationId: '11111111-1111-4111-8111-111111111111',
      authorizationId: leaveAuthorizationId,
    };

    await expect(router.handle(request, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: listing });
    expect(order).toEqual(['prepare', 'leave', 'commit']);
    expect(events.clientEvents.prepare).toHaveBeenCalledWith({
      type: ClientEventType.Organization_ItemOrganization_Declined,
      organizationId: request.organizationId,
    });

    const failedEvents = clientEventsHarness();
    const failed = createRouter({
      auth: {},
      settings: intentSettings(),
      vault: {
        leaveOrganizationDataOwnership: vi.fn(async () => { throw new Error('leave failed'); }),
      } as never,
      clientEvents: {
        ...failedEvents.clientEvents,
        supportsOrganizationDecline: () => true,
      },
    });
    await expect(failed.handle(request, EXTENSION_PAGE_CONTEXT))
      .resolves.toMatchObject({ ok: false, error: { message: 'leave failed' } });
    expect(failedEvents.clientEvents.commit).not.toHaveBeenCalled();
  });

  it('does not let event preparation or commit failures change a successful migration', async () => {
    const prepareFailure = clientEventsHarness();
    prepareFailure.clientEvents.prepare.mockRejectedValue(new Error('authority unavailable'));
    const prepareRouter = createRouter({
      auth: {}, settings: intentSettings(),
      vault: { migrateOrganizationDataOwnership: vi.fn(async () => listing) } as never,
      clientEvents: prepareFailure.clientEvents,
    });
    const request = {
      type: 'vault.migrateOrganizationDataOwnership' as const,
      organizationId: '11111111-1111-4111-8111-111111111111',
      collectionId: 'collection-1',
      authorizationId: migrateAuthorizationId,
      masterPassword: 'secret',
    };
    await expect(prepareRouter.handle(request, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: listing });

    const commitFailure = clientEventsHarness();
    commitFailure.clientEvents.commit.mockRejectedValue(new Error('queue unavailable'));
    const commitRouter = createRouter({
      auth: {}, settings: intentSettings(),
      vault: { migrateOrganizationDataOwnership: vi.fn(async () => listing) } as never,
      clientEvents: commitFailure.clientEvents,
    });
    await expect(commitRouter.handle({ ...request, masterPassword: 'secret' }, EXTENSION_PAGE_CONTEXT))
      .resolves.toEqual({ ok: true, data: listing });
  });

  it('rejects an otherwise exact Popup when the browser omits its document id', async () => {
    const status = vi.fn();
    const router = createRouter({
      auth: {},
      settings: intentSettings(),
      vault: { getOrganizationDataOwnershipStatus: status } as never,
    });
    const withoutDocument = { ...EXTENSION_PAGE_CONTEXT } as Partial<RequestContext>;
    delete withoutDocument.documentId;

    await expect(router.handle(
      { type: 'vault.getOrganizationDataOwnershipStatus' },
      withoutDocument as RequestContext,
    )).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(status).not.toHaveBeenCalled();
  });

  it.each([
    { type: 'vault.getOrganizationDataOwnershipStatus' },
    {
      type: 'vault.migrateOrganizationDataOwnership',
      organizationId: 'org-1',
      collectionId: 'collection-1',
      authorizationId: migrateAuthorizationId,
      masterPassword: 'secret',
    },
    {
      type: 'vault.leaveOrganizationDataOwnership',
      organizationId: 'org-1',
      authorizationId: leaveAuthorizationId,
    },
  ] as const)('rejects $type from non-popup extension pages', async (request) => {
    const call = vi.fn(async () => listing);
    const router = createRouter({
      auth: {},
      settings: intentSettings(),
      vault: {
        getOrganizationDataOwnershipStatus: call,
        migrateOrganizationDataOwnership: call,
        leaveOrganizationDataOwnership: call,
      } as never,
    });

    await expect(router.handle(request as RequestMessage, OPTIONS_PAGE_CONTEXT)).resolves.toEqual({
      ok: false,
      error: { code: 'denied', message: 'sender not permitted' },
    });
    expect(call).not.toHaveBeenCalled();
  });
});

describe('device login router boundary', () => {
  it.each([
    { type: 'auth.deviceLogin.retry' },
    { type: 'auth.deviceLogin.submitTwoFactor', provider: 0, code: '123456' },
    { type: 'auth.deviceLogin.sendEmailCode' },
    { type: 'auth.deviceLogin.cancel' },
  ] as const)('rejects a requester mutation without an exact generation: $type', async (request) => {
    const call = vi.fn();
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      deviceLogin: {
        retryActivation: call,
        submitTwoFactor: call,
        sendEmailCode: call,
        cancel: call,
      } as never,
    });

    await expect(router.handle(request as never, EXTENSION_PAGE_CONTEXT)).resolves.toMatchObject({
      ok: false,
      error: { code: 'denied' },
    });
    expect(call).not.toHaveBeenCalled();
  });

  it('routes every requester verb from extension pages with only the intended arguments', async () => {
    const pending = Object.freeze({
      status: 'pending' as const,
      generation: 9,
      fingerprint: 'one-two-three-four-five',
      serverOrigin: 'https://vault.example',
      email: 'user@example.com',
      deviceName: 'chrome',
      expiresAt: 2_000,
    });
    const twoFactorUnsupported = Object.freeze({
      ...pending,
      status: 'two_factor_unsupported' as const,
      providers: [2, 6] as const,
    });
    const deviceLogin = {
      begin: vi.fn(async () => pending),
      status: vi.fn(async () => pending),
      retryActivation: vi.fn(async () => twoFactorUnsupported),
      submitTwoFactor: vi.fn(async () => pending),
      sendEmailCode: vi.fn(async () => undefined),
      cancel: vi.fn(async () => true),
      cancelCurrent: vi.fn(async () => true),
    };
    const router = createRouter({
      auth: {}, vault: {}, settings: intentSettings(), deviceLogin,
    });

    await expect(router.handle({ type: 'auth.deviceLogin.begin', email: 'user@example.com' }))
      .resolves.toEqual({ ok: true, data: pending });
    await expect(router.handle({ type: 'auth.deviceLogin.status', generation: pending.generation }))
      .resolves.toEqual({ ok: true, data: pending });
    await expect(router.handle({ type: 'auth.deviceLogin.retry', generation: pending.generation }))
      .resolves.toEqual({ ok: true, data: twoFactorUnsupported });
    await expect(router.handle({
      type: 'auth.deviceLogin.submitTwoFactor', generation: pending.generation,
      provider: 1, code: '123456', remember: true,
    })).resolves.toEqual({ ok: true, data: pending });
    await expect(router.handle({
      type: 'auth.deviceLogin.sendEmailCode', generation: pending.generation,
    }))
      .resolves.toEqual({ ok: true, data: null });
    await expect(router.handle({ type: 'auth.deviceLogin.cancel', generation: pending.generation }))
      .resolves.toEqual({ ok: true, data: { cancelled: true } });

    expect(deviceLogin.begin).toHaveBeenCalledWith('user@example.com');
    expect(deviceLogin.status).toHaveBeenCalledWith(pending.generation);
    expect(deviceLogin.retryActivation).toHaveBeenCalledWith(pending.generation);
    expect(deviceLogin.submitTwoFactor).toHaveBeenCalledWith({
      generation: pending.generation, provider: 1, code: '123456', remember: true,
    });
    expect(deviceLogin.sendEmailCode).toHaveBeenCalledWith(pending.generation);
    expect(deviceLogin.cancel).toHaveBeenCalledWith(pending.generation);
  });

  it('routes approval reads and binds decisions exclusively to decisionBinding', async () => {
    const receipt = Object.freeze({
      requestId: DEVICE_LOGIN_BINDING.requestId,
      requestApproved: true,
      responseDate: '2026-08-30T08:01:00.000Z',
    });
    const approvals = {
      list: vi.fn(async () => Object.freeze([DEVICE_LOGIN_APPROVAL])),
      get: vi.fn(async () => DEVICE_LOGIN_APPROVAL),
      approve: vi.fn(async () => receipt),
      deny: vi.fn(async () => ({ ...receipt, requestApproved: false })),
    };
    const refresh = vi.fn(async () => undefined);
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      deviceLoginApprovals: approvals,
      onDeviceLoginApprovalDecision: refresh,
    });

    await expect(router.handle({ type: 'auth.deviceLogin.approvals.list' }))
      .resolves.toEqual({ ok: true, data: { approvals: [DEVICE_LOGIN_APPROVAL] } });
    await expect(router.handle({
      type: 'auth.deviceLogin.approvals.get', requestId: DEVICE_LOGIN_BINDING.requestId,
    })).resolves.toEqual({ ok: true, data: { approval: DEVICE_LOGIN_APPROVAL } });
    await expect(router.handle({
      type: 'auth.deviceLogin.approvals.approve', decisionBinding: DEVICE_LOGIN_BINDING,
    })).resolves.toEqual({ ok: true, data: { decision: receipt } });
    await expect(router.handle({
      type: 'auth.deviceLogin.approvals.deny', decisionBinding: DEVICE_LOGIN_BINDING,
    })).resolves.toMatchObject({
      ok: true,
      data: { decision: { requestApproved: false } },
    });

    expect(approvals.get).toHaveBeenCalledWith(DEVICE_LOGIN_BINDING.requestId);
    expect(approvals.approve).toHaveBeenCalledWith(DEVICE_LOGIN_BINDING);
    expect(approvals.deny).toHaveBeenCalledWith(DEVICE_LOGIN_BINDING);
    expect(refresh).toHaveBeenCalledTimes(2);

    await expect(router.handle({
      type: 'auth.deviceLogin.approvals.approve',
      decisionBinding: DEVICE_LOGIN_BINDING,
      requestId: DEVICE_LOGIN_BINDING.requestId,
    } as never)).resolves.toMatchObject({ ok: false, error: { code: 'denied' } });
    expect(approvals.approve).toHaveBeenCalledTimes(1);
  });

  it('rejects every requester and approval verb from content before service access', async () => {
    const call = vi.fn(async () => ({ status: 'none' as const }));
    const deviceLogin = {
      begin: call,
      status: call,
      retryActivation: call,
      submitTwoFactor: call,
      sendEmailCode: call,
      cancel: call,
    } as never;
    const approvals = { list: call, get: call, approve: call, deny: call } as never;
    const router = createRouter({
      auth: {}, vault: {}, settings: intentSettings(), deviceLogin, deviceLoginApprovals: approvals,
    });
    const requests: RequestMessage[] = [
      { type: 'auth.deviceLogin.begin', email: 'user@example.com' },
      { type: 'auth.deviceLogin.status', generation: 9 },
      { type: 'auth.deviceLogin.retry', generation: 9 },
      { type: 'auth.deviceLogin.submitTwoFactor', generation: 9, provider: 0, code: '123456' },
      { type: 'auth.deviceLogin.sendEmailCode', generation: 9 },
      { type: 'auth.deviceLogin.cancel', generation: 9 },
      { type: 'auth.deviceLogin.approvals.list' },
      { type: 'auth.deviceLogin.approvals.get', requestId: DEVICE_LOGIN_BINDING.requestId },
      { type: 'auth.deviceLogin.approvals.approve', decisionBinding: DEVICE_LOGIN_BINDING },
      { type: 'auth.deviceLogin.approvals.deny', decisionBinding: DEVICE_LOGIN_BINDING },
    ];

    for (const request of requests) {
      await expect(router.handle(request, CONTENT_CONTEXT)).resolves.toMatchObject({
        ok: false, error: { code: 'denied' },
      });
    }
    expect(call).not.toHaveBeenCalled();
  });

  it.each(['login', 'startRegistration'] as const)(
    'cancels the durable requester flow before ordinary auth.%s begins',
    async (method) => {
      const events: string[] = [];
      const cancelCurrent = vi.fn(async () => { events.push('cancel'); return true; });
      const login = vi.fn(async () => { events.push('auth'); return { kind: 'unlocked' as const }; });
      const startRegistration = vi.fn(async () => {
        events.push('auth');
        return { kind: 'registrationEmailSent' as const, email: 'user@example.com' };
      });
      const router = createRouter({
        auth: { login, startRegistration },
        vault: {},
        settings: intentSettings(),
        deviceLogin: { cancelCurrent } as never,
      });
      const request: RequestMessage = method === 'login'
        ? { type: 'auth.login', email: 'user@example.com', masterPassword: 'secret' }
        : { type: 'auth.startRegistration', email: 'user@example.com' };

      await router.handle(request);

      expect(events).toEqual(['cancel', 'auth']);
    },
  );

  it('routes all registration phases only from extension pages with exact arguments', async () => {
    const startRegistration = vi.fn(async () => ({
      kind: 'registrationFinish' as const,
      attemptId: 9,
      email: 'new@example.com',
      expiresAt: 60_000,
    }));
    const register = vi.fn(async () => ({ kind: 'locked' as const }));
    const cancelRegistration = vi.fn(async () => true);
    const router = createRouter({
      auth: { startRegistration, register, cancelRegistration },
      vault: {},
      settings: intentSettings(),
    });

    await expect(router.handle({
      type: 'auth.startRegistration', email: 'new@example.com', name: 'Ada',
    })).resolves.toMatchObject({ ok: true, data: { kind: 'registrationFinish', attemptId: 9 } });
    expect(startRegistration).toHaveBeenCalledWith({ email: 'new@example.com', name: 'Ada' });
    await expect(router.handle({
      type: 'auth.register', attemptId: 9, masterPassword: 'TwelveChars!', masterPasswordHint: '',
    })).resolves.toEqual({ ok: true, data: { kind: 'locked' } });
    expect(register).toHaveBeenCalledWith({
      attemptId: 9,
      masterPassword: 'TwelveChars!',
      masterPasswordHint: '',
    });
    await expect(router.handle({
      type: 'auth.cancelRegistration', attemptId: 9,
    })).resolves.toEqual({ ok: true, data: { cancelled: true } });
    expect(cancelRegistration).toHaveBeenCalledWith(9);

    for (const request of [
      { type: 'auth.startRegistration', email: 'new@example.com' },
      { type: 'auth.register', attemptId: 9, masterPassword: 'TwelveChars!', masterPasswordHint: '' },
      { type: 'auth.cancelRegistration', attemptId: 9 },
    ] as const) {
      await expect(router.handle(request, CONTENT_CONTEXT)).resolves.toMatchObject({
        ok: false,
        error: { code: 'denied' },
      });
    }
  });

  it('forwards an explicit master-password hint on ordinary password changes', async () => {
    const changeMasterPassword = vi.fn(async () => undefined);
    const router = createRouter({
      auth: { changeMasterPassword },
      vault: {},
      settings: intentSettings(),
    });

    await expect(router.handle({
      type: 'auth.changePassword',
      currentPassword: 'old-password',
      newPassword: 'new-password',
      masterPasswordHint: '',
    })).resolves.toEqual({ ok: true, data: null });
    expect(changeMasterPassword).toHaveBeenCalledWith(
      'old-password',
      'new-password',
      '',
    );
  });

  it('does not begin ordinary login when durable requester cancellation fails', async () => {
    const login = vi.fn(async () => ({ kind: 'unlocked' as const }));
    const router = createRouter({
      auth: { login },
      vault: {},
      settings: intentSettings(),
      deviceLogin: {
        cancelCurrent: vi.fn(async () => { throw new Error('requester cancellation failed'); }),
      } as never,
    });

    await expect(router.handle({
      type: 'auth.login', email: 'user@example.com', masterPassword: 'secret',
    })).resolves.toMatchObject({ ok: false });
    expect(login).not.toHaveBeenCalled();
  });

  it('cancels the durable requester flow before a changed server is committed', async () => {
    const events: string[] = [];
    const settings = intentSettings();
    settings.getServerUrl = vi.fn(async () => 'https://old.example/');
    settings.saveServerUrl = vi.fn(async () => { events.push('save'); });
    const cancelCurrent = vi.fn(async () => { events.push('cancel'); return true; });
    const resetForServerChange = vi.fn(async (commit?: () => Promise<void>) => {
      events.push('reset');
      await commit?.();
    });
    const router = createRouter({
      auth: { resetForServerChange },
      vault: {},
      settings,
      deviceLogin: { cancelCurrent } as never,
    });

    await router.handle({ type: 'settings.save', serverUrl: 'https://new.example/' });

    expect(events).toEqual(['cancel', 'reset', 'save']);
  });

  it('refreshes approval authority after success or outcome-unknown without masking either result', async () => {
    const approve = vi.fn()
      .mockResolvedValueOnce({
        requestId: DEVICE_LOGIN_BINDING.requestId,
        requestApproved: true,
        responseDate: '2026-08-30T08:01:00.000Z',
      })
      .mockRejectedValueOnce(new AppError('outcome_unknown', 'Decision outcome is unknown'))
      .mockRejectedValueOnce(new AppError('denied', 'Stale decision'));
    const refresh = vi.fn(async () => undefined);
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      deviceLoginApprovals: { approve } as never,
      onDeviceLoginApprovalDecision: refresh,
    });
    const request = {
      type: 'auth.deviceLogin.approvals.approve' as const,
      decisionBinding: DEVICE_LOGIN_BINDING,
    };

    await expect(router.handle(request)).resolves.toMatchObject({ ok: true });
    await expect(router.handle(request)).resolves.toMatchObject({
      ok: false, error: { code: 'outcome_unknown' },
    });
    await expect(router.handle(request)).resolves.toMatchObject({
      ok: false, error: { code: 'denied' },
    });
    expect(refresh).toHaveBeenCalledTimes(2);
  });

  it('does not delay a settled decision response on the auxiliary badge refresh', async () => {
    let releaseRefresh!: () => void;
    const refreshPending = new Promise<void>((resolve) => { releaseRefresh = resolve; });
    const refresh = vi.fn(() => refreshPending);
    const approve = vi.fn(async () => ({
      requestId: DEVICE_LOGIN_BINDING.requestId,
      requestApproved: true,
      responseDate: '2026-08-30T08:01:00.000Z',
    }));
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      deviceLoginApprovals: { approve } as never,
      onDeviceLoginApprovalDecision: refresh,
    });

    await expect(router.handle({
      type: 'auth.deviceLogin.approvals.approve',
      decisionBinding: DEVICE_LOGIN_BINDING,
    })).resolves.toMatchObject({ ok: true });
    expect(refresh).toHaveBeenCalledOnce();
    releaseRefresh();
  });

  it('leaves approval session enforcement to the lease-bound approval service', async () => {
    const serviceList = vi.fn(async () => {
      throw new AppError('locked', 'Vault is locked');
    });
    const router = createRouter({
      auth: {},
      vault: {},
      settings: intentSettings(),
      sessionGate: {
        capture: vi.fn(() => { throw new Error('router must not pre-gate approval reads'); }),
        assert: vi.fn(),
      },
      deviceLoginApprovals: { list: serviceList } as never,
    });

    await expect(router.handle({ type: 'auth.deviceLogin.approvals.list' }))
      .resolves.toEqual({ ok: false, error: { code: 'locked', message: 'Vault is locked' } });
    expect(serviceList).toHaveBeenCalledOnce();
  });
});
