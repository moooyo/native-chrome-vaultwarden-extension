import { describe, expect, it, vi } from 'vitest';
import { createMemoryStore, type KeyValueStore } from '../platform/store.js';
import {
  canonicalizeWebsitePasskeyRequest,
  type CanonicalWebsitePasskeyCreateRequest,
  type CanonicalWebsitePasskeyGetRequest,
  type PasskeyAssertionResultSnapshot,
  type PasskeyRegistrationResultSnapshot,
  type WebsitePasskeyOutcomeMessage,
  type WebsitePasskeyServerMessage,
} from '../messaging/website-passkey-port.js';
import { PasskeyCeremonyRegistry, PASSKEY_CEREMONY_STORAGE_KEY } from './passkey-ceremony-registry.js';
import {
  WebsitePasskeyCoordinator,
  type WebsitePasskeyAvailabilitySnapshot,
  type WebsitePasskeyDocumentContext,
  type WebsitePasskeySecuritySnapshot,
  type WebsitePasskeyTimerAdapter,
  type WebsitePasskeyVaultAdapter,
} from './website-passkey-coordinator.js';
import { WebsitePasskeyLockedContinuationStore } from './website-passkey-locked-continuation-store.js';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: {}, session: {} } },
}));

const DOCUMENT: WebsitePasskeyDocumentContext = {
  tabId: 7,
  frameId: 0,
  documentId: 'doc-A',
  url: 'https://login.example.com/path',
  origin: 'https://login.example.com',
};
const BRIDGE_A = '10000000-0000-4000-8000-000000000001';
const BRIDGE_B = '10000000-0000-4000-8000-000000000002';
const BRIDGE_CREATE = '10000000-0000-4000-8000-000000000003';
const BRIDGE_EXCLUDE = '10000000-0000-4000-8000-000000000004';

function getRequest(overrides: Partial<CanonicalWebsitePasskeyGetRequest> = {}): CanonicalWebsitePasskeyGetRequest {
  return canonicalizeWebsitePasskeyRequest({
    bridgeRequestId: BRIDGE_A,
    kind: 'get',
    rpId: 'example.com',
    challenge: 'Y2hhbGxlbmdl',
    allowCredentials: [],
    userVerification: 'preferred',
    mediation: 'optional',
    timeout: 30_000,
    ...overrides,
  }) as CanonicalWebsitePasskeyGetRequest;
}

function createRequest(overrides: Partial<CanonicalWebsitePasskeyCreateRequest> = {}): CanonicalWebsitePasskeyCreateRequest {
  return canonicalizeWebsitePasskeyRequest({
    bridgeRequestId: BRIDGE_CREATE,
    kind: 'create',
    rp: { id: 'example.com', name: 'Example' },
    user: { id: 'dXNlcg', name: 'alice', displayName: 'Alice' },
    challenge: 'Y2hhbGxlbmdl',
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    excludeCredentials: [],
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    attestation: 'none',
    extensions: { credProps: true },
    timeout: 30_000,
    ...overrides,
  }) as CanonicalWebsitePasskeyCreateRequest;
}

function assertion(): PasskeyAssertionResultSnapshot {
  return {
    kind: 'get',
    authenticatorAttachment: 'platform',
    transports: ['internal'],
    credentialId: 'Y3JlZGVudGlhbA',
    authenticatorData: 'YXV0aA',
    clientDataJSON: 'Y2xpZW50',
    signature: 'c2ln',
  };
}

function registration(): PasskeyRegistrationResultSnapshot {
  return {
    kind: 'create',
    authenticatorAttachment: 'platform',
    transports: ['internal'],
    credProps: { rk: true },
    credentialId: 'Y3JlZGVudGlhbA',
    attestationObject: 'YXR0ZXN0',
    clientDataJSON: 'Y2xpZW50',
    authData: 'YXV0aA',
    publicKeySpki: 'cHVibGlj',
    publicKeyAlgorithm: -7,
  };
}

function idFactory(): () => string {
  let value = 0;
  return () => `00000000-0000-4000-8000-${String(++value).padStart(12, '0')}`;
}

class ManualTimers implements WebsitePasskeyTimerAdapter {
  private next = 0;
  readonly callbacks = new Map<number, () => void>();

  set(callback: () => void): number {
    const id = ++this.next;
    this.callbacks.set(id, callback);
    return id;
  }

  clear(handle: unknown): void {
    this.callbacks.delete(handle as number);
  }

  fireAll(): void {
    const callbacks = [...this.callbacks.values()];
    this.callbacks.clear();
    for (const callback of callbacks) callback();
  }
}

function deferred<Value>() {
  let resolve!: (value: Value) => void;
  const promise = new Promise<Value>((done) => { resolve = done; });
  return { promise, resolve };
}

function makeHarness(options: {
  store?: KeyValueStore;
  now?: { value: number };
  epoch?: { value: number };
  prepareGet?: WebsitePasskeyVaultAdapter<number>['prepareGet'];
  prepareCreate?: WebsitePasskeyVaultAdapter<number>['prepareCreate'];
  executeGet?: WebsitePasskeyVaultAdapter<number>['executeGet'];
  executeCreate?: WebsitePasskeyVaultAdapter<number>['executeCreate'];
  maxEntries?: number;
  excludeOrigin?: (origin: string, rpId: string) => void | Promise<void>;
  sessionState?: { value: 'locked' | 'unlocked' | 'loggedOut' | 'restricted' };
  lockedContinuations?: WebsitePasskeyLockedContinuationStore;
  workerInstanceId?: string;
  identity?: { value: { accountIdentity: string; serverUrl: string } };
  documentCurrent?: { value: boolean };
} = {}) {
  const store = options.store ?? createMemoryStore();
  const now = options.now ?? { value: 1_000 };
  const timers = new ManualTimers();
  const epoch = options.epoch ?? { value: 0 };
  const identity = options.identity ?? {
    value: { accountIdentity: 'alice@example.com', serverUrl: 'https://vault.example.com/' },
  };
  const documentCurrent = options.documentCurrent ?? { value: true };
  const capture = vi.fn(async (): Promise<WebsitePasskeySecuritySnapshot<number>> => ({
    sessionBindingId: 'session-A',
    accountIdentity: identity.value.accountIdentity,
    serverUrl: identity.value.serverUrl,
    rawGeneration: 'raw-A',
    snapshotGeneration: 'snapshot-A',
    policyGeneration: epoch.value,
    proof: epoch.value,
  }));
  const security = {
    capture,
    assertCurrent: vi.fn(async (
      snapshot: WebsitePasskeySecuritySnapshot<number>,
      _options?: { readonly allowVaultGenerationChange?: boolean },
    ) => {
      if (snapshot.proof !== epoch.value) throw new Error('stale');
    }),
    assertBindingCurrent: vi.fn(async (binding: { policyGeneration: number }) => {
      if (binding.policyGeneration !== epoch.value) throw new Error('stale');
      return capture();
    }),
    assertDeliveryCurrent: vi.fn((
      snapshot: WebsitePasskeySecuritySnapshot<number>,
      options?: { readonly allowVaultGenerationChange?: boolean },
    ) => {
      if (snapshot.proof !== epoch.value && options?.allowVaultGenerationChange !== true) {
        throw new Error('stale');
      }
    }),
  };
  const vault: WebsitePasskeyVaultAdapter<number> = {
    prepareGet: vi.fn(options.prepareGet ?? (async () => [{ id: 'credential-A', name: 'Work', username: 'alice' }])),
    prepareCreate: vi.fn(options.prepareCreate ?? (async () => [{ id: 'cipher-A', name: 'Existing login' }])),
    executeGet: vi.fn(options.executeGet ?? (async () => assertion())),
    executeCreate: vi.fn(options.executeCreate ?? (async () => ({ status: 'committed' as const, result: registration() }))),
  };
  const windows = {
    open: vi.fn(async (_url: string) => 91),
    close: vi.fn(async (_windowId: number) => {}),
    isOpen: vi.fn(async (_windowId: number) => true),
  };
  const registry = new PasskeyCeremonyRegistry({
    store,
    now: () => now.value,
    createId: idFactory(),
    ...(options.maxEntries === undefined ? {} : { maxEntries: options.maxEntries }),
  });
  const availability = options.sessionState
    ? {
        capture: vi.fn(async (): Promise<WebsitePasskeyAvailabilitySnapshot<number>> => ({
          proof: epoch.value,
          sessionState: options.sessionState!.value === 'unlocked' ? 'unlocked' : 'locked',
          accountIdentity: identity.value.accountIdentity,
          serverUrl: identity.value.serverUrl,
          policyGeneration: epoch.value,
        })),
        assertCurrent: vi.fn(async (snapshot: WebsitePasskeyAvailabilitySnapshot<number>) => {
          if (snapshot.proof !== epoch.value
              || !documentCurrent.value
              || (options.sessionState!.value !== 'locked'
                && options.sessionState!.value !== 'unlocked')
              || snapshot.sessionState !== options.sessionState!.value) throw new Error('stale');
        }),
      }
    : undefined;
  const lockedContinuations = options.sessionState
    ? options.lockedContinuations ?? new WebsitePasskeyLockedContinuationStore({
        store,
        workerInstanceId: options.workerInstanceId
          ?? '90000000-0000-4000-8000-000000000001',
        createId: idFactory(),
        now: () => now.value,
      })
    : undefined;
  const coordinator = new WebsitePasskeyCoordinator({
    registry,
    security,
    vault,
    windows,
    extensionBaseUrl: 'chrome-extension://test/',
    now: () => now.value,
    timers,
    ...(availability ? { availability } : {}),
    ...(lockedContinuations ? { lockedContinuations } : {}),
    ...(options.excludeOrigin === undefined ? {} : { excludeOrigin: options.excludeOrigin }),
  });
  const delivered: WebsitePasskeyOutcomeMessage[] = [];
  const controls: Exclude<WebsitePasskeyServerMessage,
    { type: 'config' } | WebsitePasskeyOutcomeMessage>[] = [];
  const connection = coordinator.connect(DOCUMENT, (message, assertCurrent) => {
    assertCurrent?.();
    delivered.push(message);
  }, (message) => { controls.push(message); });
  return {
    availability,
    controls,
    coordinator,
    connection,
    delivered,
    epoch,
    lockedContinuations,
    now,
    registry,
    security,
    store,
    timers,
    vault,
    windows,
  };
}

async function makeRecoveredActiveHarness(options: {
  recordSnapshotGeneration?: string;
  freshSnapshotGeneration?: string;
  advancePolicyAfterBinding?: boolean;
}) {
  const now = { value: 1_000 };
  const store = createMemoryStore();
  const registry = new PasskeyCeremonyRegistry({
    store,
    now: () => now.value,
    createId: idFactory(),
  });
  const request = getRequest();
  await registry.begin({
    tabId: DOCUMENT.tabId,
    frameId: DOCUMENT.frameId,
    documentId: DOCUMENT.documentId,
    frameUrl: DOCUMENT.url,
    origin: DOCUMENT.origin,
    request,
    sessionBindingId: 'session-A',
    accountIdentity: 'alice@example.com',
    serverUrl: 'https://vault.example.com/',
    rawGeneration: 'raw-A',
    ...(options.recordSnapshotGeneration === undefined
      ? {}
      : { snapshotGeneration: options.recordSnapshotGeneration }),
    policyGeneration: 0,
    candidates: [{ kind: 'credential', id: 'credential-A', name: 'Work' }],
  });
  const epoch = { value: 0 };
  const capture = vi.fn(async (): Promise<WebsitePasskeySecuritySnapshot<number>> => ({
    sessionBindingId: 'session-A',
    accountIdentity: 'alice@example.com',
    serverUrl: 'https://vault.example.com/',
    rawGeneration: 'raw-A',
    ...(options.freshSnapshotGeneration === undefined
      ? {}
      : { snapshotGeneration: options.freshSnapshotGeneration }),
    policyGeneration: epoch.value,
    proof: epoch.value,
  }));
  const security = {
    capture,
    assertCurrent: vi.fn(async (snapshot: WebsitePasskeySecuritySnapshot<number>) => {
      if (snapshot.proof !== epoch.value) throw new Error('stale');
    }),
    assertBindingCurrent: vi.fn(async () => {
      if (options.advancePolicyAfterBinding) epoch.value += 1;
      return capture();
    }),
    assertDeliveryCurrent: vi.fn((
      snapshot: WebsitePasskeySecuritySnapshot<number>,
      options?: { readonly allowVaultGenerationChange?: boolean },
    ) => {
      if (snapshot.proof !== epoch.value && options?.allowVaultGenerationChange !== true) {
        throw new Error('stale');
      }
    }),
  };
  const vault: WebsitePasskeyVaultAdapter<number> = {
    prepareGet: vi.fn(async () => []),
    prepareCreate: vi.fn(async () => []),
    executeGet: vi.fn(async () => undefined),
    executeCreate: vi.fn(async () => ({
      status: 'not_committed' as const,
      reason: 'operation_failed' as const,
    })),
  };
  const coordinator = new WebsitePasskeyCoordinator({
    registry: {
      recoverStartup: vi.fn(async () => ({} as never)),
      begin: registry.begin.bind(registry),
      claim: registry.claim.bind(registry),
      complete: registry.complete.bind(registry),
      markFailed: registry.markFailed.bind(registry),
      markUncertain: registry.markUncertain.bind(registry),
      markFallback: registry.markFallback.bind(registry),
      abort: registry.abort.bind(registry),
      invalidateContext: registry.invalidateContext.bind(registry),
      cancel: registry.cancel.bind(registry),
      acknowledge: registry.acknowledge.bind(registry),
      get: registry.get.bind(registry),
      listAwaitingApproval: registry.listAwaitingApproval.bind(registry),
      listRedeliverable: registry.listRedeliverable.bind(registry),
    },
    security,
    vault,
    windows: { open: vi.fn(async () => 91) },
    extensionBaseUrl: 'chrome-extension://test/',
    now: () => now.value,
  });
  return { connection: coordinator.connect(DOCUMENT, () => {}), epoch, registry, request, security };
}

describe('WebsitePasskeyCoordinator begin and approval', () => {
  it('enables document config when create is delegated but get is denied', async () => {
    const harness = makeHarness();
    harness.security.capture.mockRejectedValueOnce(new Error('get denied'));

    await expect(harness.connection.getConfig()).resolves.toBe(true);
    expect(harness.security.capture).toHaveBeenNthCalledWith(1, DOCUMENT, 'get');
    expect(harness.security.capture).toHaveBeenNthCalledWith(2, DOCUMENT, 'create');
    expect(harness.security.assertCurrent).toHaveBeenCalledWith(expect.any(Object), { operation: 'create' });
  });

  it('durably begins before opening the exact popup URL and returns one stable ceremony on duplicate begin', async () => {
    const base = createMemoryStore();
    let persistedBeforeOpen = false;
    const store: KeyValueStore = {
      get: <T>(key: string) => base.get<T>(key),
      set: async (key, value) => { await base.set(key, value); },
      remove: (key) => base.remove(key),
      clear: () => base.clear(),
    };
    const harness = makeHarness({ store });
    harness.windows.open.mockImplementation(async (url) => {
      persistedBeforeOpen = Boolean(await base.get(PASSKEY_CEREMONY_STORAGE_KEY));
      expect(new URL(url).pathname).toBe('/ui/popup/popup.html');
      return 91;
    });

    const first = await harness.connection.begin(getRequest());
    const second = await harness.connection.begin(getRequest());

    expect(first).toMatchObject({ type: 'accepted', bridgeRequestId: BRIDGE_A });
    expect(second).toEqual(first);
    expect(persistedBeforeOpen).toBe(true);
    expect(harness.windows.open).toHaveBeenCalledTimes(1);
  });

  it('admits conditional mediation as a resident-credential request instead of native fallback', async () => {
    const request = getRequest({ mediation: 'conditional', allowCredentials: [] });
    const harness = makeHarness();

    const response = await harness.connection.begin(request);

    expect(response).toMatchObject({
      type: 'conditionalActive',
      bridgeRequestId: BRIDGE_A,
      candidates: [{ id: 'credential-A', name: 'Work', username: 'alice' }],
    });
    expect(harness.vault.prepareGet).toHaveBeenCalledWith(
      request,
      DOCUMENT.origin,
      expect.any(Object),
      expect.any(AbortSignal),
    );
    const ceremonyId = (response as { ceremonyId: string }).ceremonyId;
    expect(await harness.registry.get(ceremonyId)).toMatchObject({
      state: 'awaitingApproval',
      request: { mediation: 'conditional', allowCredentials: [] },
    });
    expect(harness.windows.open).not.toHaveBeenCalled();
  });

  it('claims a conditional ceremony only after its document selects an exact candidate', async () => {
    const request = getRequest({ mediation: 'conditional' });
    const harness = makeHarness();
    const active = await harness.connection.begin(request);
    const ceremonyId = (active as { ceremonyId: string }).ceremonyId;

    expect(harness.vault.executeGet).not.toHaveBeenCalled();
    await expect(harness.connection.selectConditional(
      ceremonyId,
      request.bridgeRequestId,
      'credential-A',
    )).resolves.toBe(true);

    expect(harness.vault.executeGet).toHaveBeenCalledWith(
      request,
      DOCUMENT.origin,
      'credential-A',
      expect.any(Object),
      expect.any(AbortSignal),
    );
    expect(harness.delivered.at(-1)).toMatchObject({ outcome: { status: 'success' } });
    expect(harness.windows.open).not.toHaveBeenCalled();
  });

  it('keeps an invalid conditional selection unclaimed and private vault access untouched', async () => {
    const request = getRequest({ mediation: 'conditional' });
    const harness = makeHarness();
    const active = await harness.connection.begin(request);
    const ceremonyId = (active as { ceremonyId: string }).ceremonyId;

    await expect(harness.connection.selectConditional(
      ceremonyId,
      request.bridgeRequestId,
      'aW5qZWN0ZWQ',
    )).resolves.toBe(false);
    expect(await harness.registry.get(ceremonyId)).toMatchObject({ state: 'awaitingApproval' });
    expect(harness.vault.executeGet).not.toHaveBeenCalled();
  });

  it('binds a same-origin iframe ceremony to its exact frame and rejects cross-frame resume', async () => {
    const harness = makeHarness();
    const frameDocument: WebsitePasskeyDocumentContext = {
      ...DOCUMENT,
      frameId: 4,
      documentId: 'frame-document',
      url: 'https://login.example.com/frame',
    };
    const connection = harness.coordinator.connect(frameDocument, () => {});
    const request = getRequest();

    const accepted = await connection.begin(request);

    expect(accepted).toMatchObject({ type: 'accepted', bridgeRequestId: BRIDGE_A });
    const ceremonyId = (accepted as { ceremonyId: string }).ceremonyId;
    expect(await harness.registry.get(ceremonyId)).toMatchObject({
      tabId: 7,
      frameId: 4,
      documentId: 'frame-document',
      frameUrl: frameDocument.url,
      origin: frameDocument.origin,
    });

    const sibling = harness.coordinator.connect({
      ...frameDocument,
      frameId: 5,
      documentId: 'sibling-document',
    }, () => {});
    await expect(sibling.resume(request)).resolves.toBeUndefined();
  });

  it('settles an invalidated iframe context and closes its approval resources', async () => {
    const harness = makeHarness();
    const delivered: WebsitePasskeyOutcomeMessage[] = [];
    const frameDocument: WebsitePasskeyDocumentContext = {
      ...DOCUMENT,
      frameId: 4,
      documentId: 'navigating-frame',
      url: 'https://login.example.com/frame',
    };
    const connection = harness.coordinator.connect(frameDocument, (message) => { delivered.push(message); });
    const accepted = await connection.begin(getRequest());
    const ceremonyId = (accepted as { ceremonyId: string }).ceremonyId;

    harness.epoch.value += 1;
    await harness.coordinator.handleBrowserDocumentChange(frameDocument.tabId);

    expect(await harness.registry.get(ceremonyId)).toMatchObject({
      state: 'failed',
      reason: 'context_changed',
      frameId: 4,
    });
    expect(delivered).toEqual([
      expect.objectContaining({
        ceremonyId,
        outcome: { status: 'error', error: expect.objectContaining({ name: 'NotAllowedError' }) },
      }),
    ]);
    expect(harness.windows.close).toHaveBeenCalledWith(91);
  });

  it('persists and returns explicit native fallback when get has no candidates', async () => {
    const harness = makeHarness({ prepareGet: async () => [] });
    const response = await harness.connection.begin(getRequest());

    expect(response).toMatchObject({ type: 'outcome', outcome: { status: 'fallback', reason: 'no_match' } });
    expect(harness.windows.open).not.toHaveBeenCalled();
    expect((await harness.registry.get((response as WebsitePasskeyOutcomeMessage).ceremonyId))?.state).toBe('fallback');
  });

  it('durably falls back required conditional user verification until a trusted verifier exists', async () => {
    const harness = makeHarness();
    const response = await harness.connection.begin(getRequest({
      mediation: 'conditional',
      userVerification: 'required',
    }));
    expect(response).toMatchObject({ type: 'outcome', outcome: { status: 'fallback', reason: 'unsupported' } });
    expect(harness.vault.prepareGet).not.toHaveBeenCalled();
    expect(harness.windows.open).not.toHaveBeenCalled();
  });

  it('returns pre-acceptance failure for a different live request in the same document', async () => {
    const harness = makeHarness();
    await harness.connection.begin(getRequest());
    const competing = await harness.connection.begin(getRequest({
      bridgeRequestId: BRIDGE_B,
      challenge: 'b3RoZXI',
    }));
    expect(competing).toMatchObject({
      type: 'preflightOutcome',
      bridgeRequestId: BRIDGE_B,
      outcome: { status: 'error', error: { name: 'NotAllowedError' } },
    });
    expect(harness.windows.open).toHaveBeenCalledTimes(1);
  });

  it('rejects a competing document request before a pending candidate discovery can decrypt twice', async () => {
    const pending = deferred<readonly [{ id: string; name: string }]>();
    const harness = makeHarness({ prepareGet: () => pending.promise });
    const first = harness.connection.begin(getRequest());
    await vi.waitFor(() => expect(harness.vault.prepareGet).toHaveBeenCalledOnce());

    const competing = await harness.connection.begin(getRequest({
      bridgeRequestId: BRIDGE_B,
      challenge: 'b3RoZXI',
    }));
    expect(competing).toMatchObject({
      type: 'preflightOutcome',
      bridgeRequestId: BRIDGE_B,
      outcome: { status: 'error', error: { name: 'NotAllowedError' } },
    });
    expect(harness.vault.prepareGet).toHaveBeenCalledOnce();

    pending.resolve([{ id: 'credential-A', name: 'Work' }]);
    await expect(first).resolves.toMatchObject({ type: 'accepted', bridgeRequestId: BRIDGE_A });
  });

  it('lets an exact reconnect resume the original pending discovery without duplicating work', async () => {
    const pending = deferred<readonly [{ id: string; name: string }]>();
    const harness = makeHarness({ prepareGet: () => pending.promise });
    const request = getRequest();
    const first = harness.connection.begin(request);
    await vi.waitFor(() => expect(harness.vault.prepareGet).toHaveBeenCalledOnce());
    harness.connection.close();

    const reconnected = harness.coordinator.connect(DOCUMENT, () => {});
    const resumed = reconnected.resume(request);
    pending.resolve([{ id: 'credential-A', name: 'Work' }]);

    const [firstResponse, resumedResponse] = await Promise.all([first, resumed]);
    expect(resumedResponse).toEqual(firstResponse);
    expect(resumedResponse).toMatchObject({ type: 'accepted', bridgeRequestId: BRIDGE_A });
    expect(harness.vault.prepareGet).toHaveBeenCalledOnce();
    expect(harness.windows.open).toHaveBeenCalledOnce();
  });

  it('does not open an orphan approval window after the initiating document disconnects', async () => {
    const pending = deferred<readonly [{ id: string; name: string }]>();
    const harness = makeHarness({ prepareGet: () => pending.promise });
    const request = getRequest();
    const first = harness.connection.begin(request);
    await vi.waitFor(() => expect(harness.vault.prepareGet).toHaveBeenCalledOnce());
    harness.connection.close();
    pending.resolve([{ id: 'credential-A', name: 'Work' }]);
    const accepted = await first;

    expect(accepted).toMatchObject({ type: 'accepted' });
    expect(harness.windows.open).not.toHaveBeenCalled();

    const otherDocument = harness.coordinator.connect({
      ...DOCUMENT,
      documentId: 'doc-B',
      url: 'https://other.example.com/',
      origin: 'https://other.example.com',
    }, () => {});
    await expect(otherDocument.resume(request)).resolves.toBeUndefined();
    expect(harness.windows.open).not.toHaveBeenCalled();

    const exactDocument = harness.coordinator.connect(DOCUMENT, () => {});
    await expect(exactDocument.resume(request)).resolves.toEqual(accepted);
    expect(harness.windows.open).toHaveBeenCalledOnce();
  });

  it('keeps the ingress deadline fixed across asynchronous candidate discovery', async () => {
    const now = { value: 1_000 };
    const harness = makeHarness({
      now,
      prepareGet: async () => {
        now.value = 11_000;
        return [{ id: 'credential-A', name: 'Work' }];
      },
    });

    const response = await harness.connection.begin(getRequest());

    expect(response).toMatchObject({ type: 'accepted', deadlineAt: 31_000 });
  });

  it('does not start discovery after security capture consumes the ingress deadline', async () => {
    const now = { value: 1_000 };
    const harness = makeHarness({ now });
    const snapshot = await harness.security.capture();
    harness.security.capture.mockImplementation(async () => {
      now.value = 31_000;
      return snapshot;
    });

    await expect(harness.connection.begin(getRequest())).resolves.toMatchObject({
      type: 'preflightOutcome',
      outcome: { status: 'error', error: { name: 'NotAllowedError' } },
    });
    expect(harness.vault.prepareGet).not.toHaveBeenCalled();
  });

  it('does not persist candidates returned after the ingress deadline', async () => {
    const now = { value: 1_000 };
    const harness = makeHarness({
      now,
      prepareGet: async () => {
        now.value = 31_000;
        return [{ id: 'credential-A', name: 'Work' }];
      },
    });

    await expect(harness.connection.begin(getRequest())).resolves.toMatchObject({
      type: 'preflightOutcome',
      outcome: { status: 'error', error: { name: 'NotAllowedError' } },
    });
    expect(await harness.registry.listAwaitingApproval()).toEqual([]);
  });

  it('returns explicit capacity fallback without inventing a ceremony', async () => {
    const harness = makeHarness({ maxEntries: 1 });
    await harness.connection.begin(getRequest());
    const other = harness.coordinator.connect({
      ...DOCUMENT,
      tabId: 8,
      documentId: 'doc-B',
      url: 'https://other.example.com/',
      origin: 'https://other.example.com',
    }, () => {});
    const response = await other.begin(getRequest({ bridgeRequestId: BRIDGE_B }));
    expect(response).toMatchObject({
      type: 'preflightOutcome',
      bridgeRequestId: BRIDGE_B,
      outcome: { status: 'fallback', reason: 'capacity' },
    });
  });

  it('rejects an injected selection against the persisted candidate snapshot before private vault access', async () => {
    const harness = makeHarness();
    const begun = await harness.connection.begin(getRequest());
    const outcome = await harness.coordinator.approve(
      (begun as { ceremonyId: string }).ceremonyId,
      { kind: 'credential', credentialId: 'injected' },
    );
    expect(outcome).toBe('failed');
    expect(harness.vault.executeGet).not.toHaveBeenCalled();
    expect(harness.delivered.at(-1)).toMatchObject({ outcome: { status: 'error' } });
  });

  it('passes only the persisted request and approved candidate to vault, then persists before delivery', async () => {
    const harness = makeHarness();
    const request = getRequest();
    const begun = await harness.connection.begin(request);
    const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;
    const outcome = await harness.coordinator.approve(ceremonyId, {
      kind: 'credential', credentialId: 'credential-A',
    });

    expect(outcome).toBe('completed');
    expect(harness.vault.executeGet).toHaveBeenCalledWith(
      request,
      DOCUMENT.origin,
      'credential-A',
      expect.objectContaining({ sessionBindingId: 'session-A', rawGeneration: 'raw-A' }),
      expect.any(AbortSignal),
    );
    expect((await harness.registry.get(ceremonyId))?.state).toBe('completed');
    expect(harness.delivered.at(-1)).toMatchObject({ outcome: { status: 'success', result: assertion() } });
    expect(harness.windows.close).toHaveBeenCalledWith(91);
    await harness.coordinator.handleWindowClosed(91);
    expect((await harness.registry.get(ceremonyId))?.state).toBe('completed');
  });

  it.each(['locked', 'restricted'] as const)(
    'retires a completed result without delivery when the session becomes %s while registry completion is pending',
    async (nextState) => {
      const harness = makeHarness();
      const sessionState = { value: 'unlocked' as 'unlocked' | 'locked' | 'restricted' };
      harness.security.assertCurrent.mockImplementation(async (snapshot) => {
        if (sessionState.value !== 'unlocked' || snapshot.proof !== harness.epoch.value) {
          throw new Error('stale');
        }
      });
      const complete = harness.registry.complete.bind(harness.registry);
      const completionPersisted = deferred<void>();
      const releaseCompletion = deferred<void>();
      vi.spyOn(harness.registry, 'complete').mockImplementation(async (ceremonyId, executionId, result) => {
        const terminal = await complete(ceremonyId, executionId, result);
        completionPersisted.resolve(undefined);
        await releaseCompletion.promise;
        return terminal;
      });
      const begun = await harness.connection.begin(getRequest());
      const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;

      const approval = harness.coordinator.approve(ceremonyId, {
        kind: 'credential', credentialId: 'credential-A',
      });
      await completionPersisted.promise;
      expect(await harness.registry.get(ceremonyId)).toMatchObject({ state: 'completed' });
      sessionState.value = nextState;
      releaseCompletion.resolve(undefined);

      await expect(approval).resolves.toBe('completed');
      expect(harness.delivered).toEqual([]);
      expect(await harness.registry.get(ceremonyId)).toBeUndefined();
    },
  );

  it('retires a completed result when its exact document channel is replaced during registry completion', async () => {
    const harness = makeHarness();
    const complete = harness.registry.complete.bind(harness.registry);
    const completionPersisted = deferred<void>();
    const releaseCompletion = deferred<void>();
    vi.spyOn(harness.registry, 'complete').mockImplementation(async (ceremonyId, executionId, result) => {
      const terminal = await complete(ceremonyId, executionId, result);
      completionPersisted.resolve(undefined);
      await releaseCompletion.promise;
      return terminal;
    });
    const begun = await harness.connection.begin(getRequest());
    const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;

    const approval = harness.coordinator.approve(ceremonyId, {
      kind: 'credential', credentialId: 'credential-A',
    });
    await completionPersisted.promise;
    expect(await harness.registry.get(ceremonyId)).toMatchObject({ state: 'completed' });
    harness.connection.close();
    const replacementDeliver = vi.fn();
    harness.coordinator.connect(DOCUMENT, replacementDeliver);
    releaseCompletion.resolve(undefined);

    await expect(approval).resolves.toBe('completed');
    expect(harness.delivered).toEqual([]);
    expect(replacementDeliver).not.toHaveBeenCalled();
    expect(await harness.registry.get(ceremonyId)).toBeUndefined();
  });

  it('fails closed when the security snapshot changes during discovery', async () => {
    const epoch = { value: 0 };
    const harness = makeHarness({
      epoch,
      prepareGet: async () => {
        epoch.value += 1;
        return [{ id: 'credential-A', name: 'Work' }];
      },
    });
    expect(await harness.connection.begin(getRequest())).toBeUndefined();
    expect(harness.windows.open).not.toHaveBeenCalled();
    expect(await harness.registry.listAwaitingApproval()).toEqual([]);
  });

  it('settles as AbortError when session, account, policy, or cache security changes before approval', async () => {
    const harness = makeHarness();
    const begun = await harness.connection.begin(getRequest());
    const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;
    harness.epoch.value += 1;

    await expect(harness.coordinator.approve(ceremonyId, {
      kind: 'credential', credentialId: 'credential-A',
    })).resolves.toBe('failed');
    expect(harness.vault.executeGet).not.toHaveBeenCalled();
    expect(harness.delivered.at(-1)).toMatchObject({
      outcome: { status: 'error', error: { name: 'AbortError' } },
    });
  });

  it('uses the same AbortError terminal when approval loading first observes security drift', async () => {
    const harness = makeHarness();
    const begun = await harness.connection.begin(getRequest());
    const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;
    harness.epoch.value += 1;

    await expect(harness.coordinator.getApproval(ceremonyId)).resolves.toBeUndefined();

    expect(await harness.registry.get(ceremonyId)).toMatchObject({ state: 'failed', reason: 'cancelled' });
    expect(harness.delivered.at(-1)).toMatchObject({
      outcome: { status: 'error', error: { name: 'AbortError' } },
    });
  });

  it('never falls back after durable begin when the final security assertion or window open fails', async () => {
    const changed = makeHarness();
    let assertions = 0;
    changed.security.assertCurrent.mockImplementation(async () => {
      assertions += 1;
      if (assertions === 3) throw new Error('stale');
    });
    await expect(changed.connection.begin(getRequest())).resolves.toMatchObject({
      type: 'outcome',
      outcome: { status: 'error', error: { name: 'AbortError' } },
    });

    const windowFailure = makeHarness();
    windowFailure.windows.open.mockRejectedValue(new Error('window unavailable'));
    await expect(windowFailure.connection.begin(getRequest())).resolves.toMatchObject({
      type: 'outcome',
      outcome: { status: 'error', error: { name: 'AbortError' } },
    });
    expect(changed.delivered.some((message) => message.outcome.status === 'fallback')).toBe(false);
    expect(windowFailure.delivered.some((message) => message.outcome.status === 'fallback')).toBe(false);
  });

  it('never resumes an active ceremony after its original security proof changes', async () => {
    const harness = makeHarness();
    const request = getRequest();
    const begun = await harness.connection.begin(request);
    const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;
    harness.epoch.value += 1;

    const resumed = await harness.connection.resume(request);

    expect(resumed).toMatchObject({
      type: 'outcome',
      ceremonyId,
      outcome: { status: 'error', error: { name: 'AbortError' } },
    });
    expect((await harness.registry.get(ceremonyId))?.state).toBe('failed');
    expect(harness.vault.executeGet).not.toHaveBeenCalled();
  });

  it('detects a policy ABA between persisted-binding validation and fresh proof capture', async () => {
    const harness = await makeRecoveredActiveHarness({
      recordSnapshotGeneration: 'snapshot-A',
      freshSnapshotGeneration: 'snapshot-A',
      advancePolicyAfterBinding: true,
    });
    const resumed = await harness.connection.resume(harness.request);

    expect(resumed).toMatchObject({
      type: 'outcome',
      outcome: { status: 'error', error: { name: 'AbortError' } },
    });
    expect(harness.security.assertBindingCurrent).toHaveBeenCalledOnce();
    expect(harness.security.capture).toHaveBeenCalledOnce();
  });

  it.each([
    ['present to missing', 'snapshot-A', undefined],
    ['missing to present', undefined, 'snapshot-A'],
  ] as const)('rejects recovered snapshot generation drift from %s', async (_label, persisted, fresh) => {
    const harness = await makeRecoveredActiveHarness({
      ...(persisted === undefined ? {} : { recordSnapshotGeneration: persisted }),
      ...(fresh === undefined ? {} : { freshSnapshotGeneration: fresh }),
    });

    const resumed = await harness.connection.resume(harness.request);

    expect(resumed).toMatchObject({
      type: 'outcome',
      outcome: { status: 'error', error: { name: 'AbortError' } },
    });
  });
});

describe('WebsitePasskeyCoordinator locked continuation', () => {
  it('keeps configuration enabled while locked and stages without reading vault candidates', async () => {
    const sessionState = { value: 'locked' as const };
    const harness = makeHarness({ sessionState });

    await expect(harness.connection.getConfig()).resolves.toBe(true);
    const response = await harness.connection.begin(getRequest(), undefined, harness.now.value + 20_000);

    expect(response).toMatchObject({
      type: 'unlockPending',
      bridgeRequestId: BRIDGE_A,
      deadlineAt: harness.now.value + 20_000,
    });
    expect(harness.security.capture).not.toHaveBeenCalled();
    expect(harness.vault.prepareGet).not.toHaveBeenCalled();
    expect(harness.vault.prepareCreate).not.toHaveBeenCalled();
    expect(harness.windows.open).toHaveBeenCalledTimes(1);
    const popupUrl = new URL(harness.windows.open.mock.calls[0]![0]);
    expect(popupUrl.pathname).toBe('/ui/popup/popup.html');
    expect(popupUrl.searchParams.get('websitePasskeyUnlock')).toBe(
      (response as { continuationId: string }).continuationId,
    );
  });

  it('holds conditional mediation without enumerating candidates or opening an unlock window', async () => {
    const sessionState = { value: 'locked' as const };
    const harness = makeHarness({ sessionState });
    const request = getRequest({ mediation: 'conditional' });

    const pending = await harness.connection.begin(request, undefined, harness.now.value + 20_000);
    await expect(Promise.resolve(pending))
      .resolves.toMatchObject({ type: 'unlockPending', bridgeRequestId: BRIDGE_A });
    expect(harness.windows.open).not.toHaveBeenCalled();
    expect(harness.security.capture).not.toHaveBeenCalled();
    expect(harness.vault.prepareGet).not.toHaveBeenCalled();
    if (pending?.type !== 'unlockPending') throw new Error('expected locked continuation');
    await expect(harness.coordinator.getLockedContinuation(undefined, 'toolbar-popup'))
      .resolves.toMatchObject({
        status: 'unlock_required',
        continuationId: pending.continuationId,
      });
  });

  it('refreshes a passive conditional request after the same account unlocks elsewhere', async () => {
    const sessionState: { value: 'locked' | 'unlocked' } = { value: 'locked' };
    const harness = makeHarness({ sessionState });
    const request = getRequest({ mediation: 'conditional' });
    const pending = await harness.connection.begin(
      request,
      undefined,
      harness.now.value + 20_000,
    );
    if (pending?.type !== 'unlockPending') throw new Error('expected locked continuation');
    sessionState.value = 'unlocked';

    await expect(harness.coordinator.resumeConditionalAfterUnlock()).resolves.toBe('started');

    expect(harness.vault.prepareGet).toHaveBeenCalledTimes(1);
    expect(harness.controls.at(-1)).toMatchObject({
      type: 'conditionalActive',
      ceremonyId: pending.continuationId,
      bridgeRequestId: BRIDGE_A,
    });
    expect(harness.windows.open).not.toHaveBeenCalled();
  });

  it('does not let an unbound toolbar popup claim an ordinary locked request', async () => {
    const sessionState = { value: 'locked' as const };
    const harness = makeHarness({ sessionState });
    await harness.connection.begin(getRequest(), undefined, harness.now.value + 20_000);

    await expect(harness.coordinator.getLockedContinuation(undefined, 'toolbar-popup'))
      .resolves.toEqual({ status: 'none' });
  });

  it('enforces a global locked single flight while returning one stable duplicate', async () => {
    const sessionState = { value: 'locked' as const };
    const harness = makeHarness({ sessionState });
    const deadline = harness.now.value + 20_000;
    const first = await harness.connection.begin(getRequest(), undefined, deadline);

    await expect(harness.connection.begin(getRequest(), undefined, deadline)).resolves.toEqual(first);
    await expect(harness.connection.begin(getRequest({ bridgeRequestId: BRIDGE_B }), undefined, deadline))
      .resolves.toMatchObject({
        type: 'preflightOutcome',
        outcome: { status: 'error', error: { name: 'NotAllowedError' } },
      });
    expect(harness.windows.open).toHaveBeenCalledTimes(1);
  });

  it('consumes after popup ownership then revalidates and promotes the same id after unlock', async () => {
    const sessionState: { value: 'locked' | 'unlocked' } = { value: 'locked' };
    const harness = makeHarness({ sessionState });
    const deadline = harness.now.value + 20_000;
    const pending = await harness.connection.begin(getRequest(), undefined, deadline);
    if (pending?.type !== 'unlockPending') throw new Error('expected locked continuation');
    await expect(harness.coordinator.getLockedContinuation(
      pending.continuationId,
      'popup-document',
    )).resolves.toEqual({
      status: 'unlock_required',
      continuationId: pending.continuationId,
      expiresAt: deadline,
    });

    sessionState.value = 'unlocked';
    await expect(harness.coordinator.resumeLockedContinuation(
      pending.continuationId,
      'popup-document',
    )).resolves.toBe('started');

    expect(harness.security.capture).toHaveBeenCalledWith(DOCUMENT, 'get');
    expect(harness.vault.prepareGet).toHaveBeenCalledTimes(1);
    expect(harness.controls.at(-1)).toMatchObject({
      type: 'accepted',
      ceremonyId: pending.continuationId,
      bridgeRequestId: BRIDGE_A,
      deadlineAt: deadline,
    });
    expect(await harness.registry.get(pending.continuationId)).toMatchObject({
      state: 'awaitingApproval',
      ceremonyId: pending.continuationId,
    });
    expect(harness.windows.close).toHaveBeenCalledWith(91);
  });

  it('consumes before rejecting a changed policy generation after unlock', async () => {
    const sessionState: { value: 'locked' | 'unlocked' } = { value: 'locked' };
    const harness = makeHarness({ sessionState });
    const pending = await harness.connection.begin(
      getRequest(),
      undefined,
      harness.now.value + 20_000,
    );
    if (pending?.type !== 'unlockPending') throw new Error('expected locked continuation');
    await harness.coordinator.getLockedContinuation(pending.continuationId, 'popup-document');
    sessionState.value = 'unlocked';
    harness.epoch.value += 1;

    await expect(harness.coordinator.resumeLockedContinuation(
      pending.continuationId,
      'popup-document',
    )).resolves.toBe('stale');
    expect(harness.vault.prepareGet).not.toHaveBeenCalled();
    await expect(harness.lockedContinuations!.readPending()).resolves.toBeUndefined();
    expect(harness.controls.at(-1)).toMatchObject({
      type: 'preflightOutcome',
      outcome: { status: 'error', error: { name: 'NotAllowedError' } },
    });
  });

  it('terminates with NotAllowed when the unlock popout closes', async () => {
    const sessionState = { value: 'locked' as const };
    const harness = makeHarness({ sessionState });
    await harness.connection.begin(getRequest(), undefined, harness.now.value + 20_000);

    await harness.coordinator.handleWindowClosed(91);

    expect(harness.controls.at(-1)).toMatchObject({
      type: 'preflightOutcome',
      bridgeRequestId: BRIDGE_A,
      outcome: { status: 'error', error: { name: 'NotAllowedError' } },
    });
    expect(harness.vault.prepareGet).not.toHaveBeenCalled();
  });

  it('consumes an Abort-bound continuation without touching vault state', async () => {
    const sessionState = { value: 'locked' as const };
    const harness = makeHarness({ sessionState });
    const pending = await harness.connection.begin(
      getRequest(),
      undefined,
      harness.now.value + 20_000,
    );
    if (pending?.type !== 'unlockPending') throw new Error('expected locked continuation');

    await harness.connection.cancel(pending.continuationId, BRIDGE_A);

    await expect(harness.lockedContinuations!.readPending()).resolves.toBeUndefined();
    expect(harness.vault.prepareGet).not.toHaveBeenCalled();
    expect(harness.controls).toHaveLength(0);
  });

  it('expires at the original request deadline and returns an explicit NotAllowed outcome', async () => {
    const sessionState = { value: 'locked' as const };
    const harness = makeHarness({ sessionState });
    const deadline = harness.now.value + 20_000;
    await harness.connection.begin(getRequest(), undefined, deadline);
    harness.now.value = deadline;

    harness.timers.fireAll();
    await vi.waitFor(() => expect(harness.controls.at(-1)).toMatchObject({
      type: 'preflightOutcome',
      outcome: {
        status: 'error',
        error: { name: 'NotAllowedError', message: expect.stringMatching(/timed out/i) },
      },
    }));
    expect(harness.vault.prepareGet).not.toHaveBeenCalled();
  });

  it('allows only one consume-and-promote winner when unlock resume races', async () => {
    const sessionState: { value: 'locked' | 'unlocked' } = { value: 'locked' };
    const harness = makeHarness({ sessionState });
    const pending = await harness.connection.begin(
      getRequest(),
      undefined,
      harness.now.value + 20_000,
    );
    if (pending?.type !== 'unlockPending') throw new Error('expected locked continuation');
    await harness.coordinator.getLockedContinuation(pending.continuationId, 'popup-document');
    sessionState.value = 'unlocked';

    const outcomes = await Promise.all([
      harness.coordinator.resumeLockedContinuation(pending.continuationId, 'popup-document'),
      harness.coordinator.resumeLockedContinuation(pending.continuationId, 'popup-document'),
    ]);

    expect(outcomes.sort()).toEqual(['stale', 'started']);
    expect(harness.vault.prepareGet).toHaveBeenCalledTimes(1);
  });

  it('makes a Port reconnect await the in-flight consume-and-promote operation', async () => {
    const choices = deferred<readonly [{ id: string; name: string; username: string }]>();
    const sessionState: { value: 'locked' | 'unlocked' } = { value: 'locked' };
    const harness = makeHarness({
      sessionState,
      prepareGet: async () => choices.promise,
    });
    const request = getRequest();
    const pending = await harness.connection.begin(
      request,
      undefined,
      harness.now.value + 20_000,
    );
    if (pending?.type !== 'unlockPending') throw new Error('expected locked continuation');
    await harness.coordinator.getLockedContinuation(pending.continuationId, 'popup-document');
    sessionState.value = 'unlocked';

    const promoting = harness.coordinator.resumeLockedContinuation(
      pending.continuationId,
      'popup-document',
    );
    await vi.waitFor(() => expect(harness.vault.prepareGet).toHaveBeenCalledOnce());
    const reconnect = harness.connection.resume(request);
    choices.resolve([{ id: 'credential-A', name: 'Work', username: 'alice' }]);

    await expect(promoting).resolves.toBe('started');
    await expect(reconnect).resolves.toMatchObject({
      type: 'accepted',
      ceremonyId: pending.continuationId,
      deadlineAt: harness.now.value + 20_000,
    });
    expect(harness.vault.prepareGet).toHaveBeenCalledTimes(1);
  });

  it('rechecks the stored policy generation against the full unlocked security proof', async () => {
    const sessionState: { value: 'locked' | 'unlocked' } = { value: 'locked' };
    const harness = makeHarness({ sessionState });
    const pending = await harness.connection.begin(
      getRequest(),
      undefined,
      harness.now.value + 20_000,
    );
    if (pending?.type !== 'unlockPending') throw new Error('expected locked continuation');
    await harness.coordinator.getLockedContinuation(pending.continuationId, 'popup-document');
    sessionState.value = 'unlocked';
    harness.security.capture.mockResolvedValueOnce({
      sessionBindingId: 'session-A',
      accountIdentity: 'alice@example.com',
      serverUrl: 'https://vault.example.com/',
      rawGeneration: 'raw-A',
      snapshotGeneration: 'snapshot-A',
      policyGeneration: 1,
      proof: 0,
    });

    await expect(harness.coordinator.resumeLockedContinuation(
      pending.continuationId,
      'popup-document',
    )).resolves.toBe('stale');
    expect(harness.vault.prepareGet).not.toHaveBeenCalled();
  });

  it('adopts the exact pending request across worker restart and Port resume', async () => {
    const store = createMemoryStore();
    const sessionState = { value: 'locked' as const };
    const first = makeHarness({
      store,
      sessionState,
      workerInstanceId: '90000000-0000-4000-8000-000000000001',
    });
    const deadline = first.now.value + 20_000;
    const before = await first.connection.begin(getRequest(), undefined, deadline);
    if (before?.type !== 'unlockPending') throw new Error('expected locked continuation');

    const restarted = makeHarness({
      store,
      sessionState,
      workerInstanceId: '90000000-0000-4000-8000-000000000002',
    });
    await expect(restarted.connection.resume(getRequest())).resolves.toEqual(before);
    expect(restarted.vault.prepareGet).not.toHaveBeenCalled();
    expect(restarted.windows.open).not.toHaveBeenCalled();
  });

  it.each([
    ['policy', (state: {
      epoch: { value: number };
      identity: { value: { accountIdentity: string; serverUrl: string } };
      documentCurrent: { value: boolean };
    }) => { state.epoch.value += 1; }],
    ['account', (state: {
      epoch: { value: number };
      identity: { value: { accountIdentity: string; serverUrl: string } };
      documentCurrent: { value: boolean };
    }) => { state.identity.value = { ...state.identity.value, accountIdentity: 'bob@example.com' }; }],
    ['document', (state: {
      epoch: { value: number };
      identity: { value: { accountIdentity: string; serverUrl: string } };
      documentCurrent: { value: boolean };
    }) => { state.documentCurrent.value = false; }],
  ])('consumes a restarted continuation before replay when %s authority changed', async (_name, mutate) => {
    const store = createMemoryStore();
    const sessionState = { value: 'locked' as const };
    const epoch = { value: 0 };
    const identity = {
      value: { accountIdentity: 'alice@example.com', serverUrl: 'https://vault.example.com/' },
    };
    const documentCurrent = { value: true };
    const shared = { store, sessionState, epoch, identity, documentCurrent };
    const first = makeHarness({
      ...shared,
      workerInstanceId: '90000000-0000-4000-8000-000000000001',
    });
    await first.connection.begin(getRequest(), undefined, first.now.value + 20_000);
    mutate({ epoch, identity, documentCurrent });

    const restarted = makeHarness({
      ...shared,
      workerInstanceId: '90000000-0000-4000-8000-000000000002',
    });
    await expect(restarted.connection.resume(getRequest())).resolves.toMatchObject({
      type: 'preflightOutcome',
      outcome: { status: 'error', error: { name: 'NotAllowedError' } },
    });
    await expect(restarted.lockedContinuations!.readPending()).resolves.toBeUndefined();
    expect(restarted.vault.prepareGet).not.toHaveBeenCalled();
    expect(restarted.windows.open).not.toHaveBeenCalled();
  });

  it('revokes a pending locked request after document or policy invalidation', async () => {
    const sessionState = { value: 'locked' as const };
    const harness = makeHarness({ sessionState });
    await harness.connection.begin(getRequest(), undefined, harness.now.value + 20_000);
    harness.epoch.value += 1;

    await harness.coordinator.handleBrowserDocumentChange(DOCUMENT.tabId);

    expect(harness.controls.at(-1)).toMatchObject({
      type: 'preflightOutcome',
      outcome: { status: 'error', error: { name: 'NotAllowedError' } },
    });
    expect(harness.vault.prepareGet).not.toHaveBeenCalled();
  });
});

describe('WebsitePasskeyCoordinator cancellation and recovery', () => {
  it('cancels a silent conditional request without ever opening approval UI', async () => {
    const request = getRequest({ mediation: 'conditional' });
    const harness = makeHarness();
    const active = await harness.connection.begin(request);
    const ceremonyId = (active as { ceremonyId: string }).ceremonyId;

    await harness.connection.cancel(ceremonyId, request.bridgeRequestId);

    expect(await harness.registry.get(ceremonyId)).toMatchObject({ state: 'failed', reason: 'cancelled' });
    expect(harness.delivered.at(-1)).toMatchObject({
      outcome: { status: 'error', error: { name: 'AbortError' } },
    });
    expect(harness.windows.open).not.toHaveBeenCalled();
  });

  it('invalidates a conditional request on navigation without an orphan approval window', async () => {
    const request = getRequest({ mediation: 'conditional' });
    const harness = makeHarness();
    const active = await harness.connection.begin(request);
    const ceremonyId = (active as { ceremonyId: string }).ceremonyId;
    harness.epoch.value += 1;

    await harness.coordinator.handleBrowserDocumentChange(DOCUMENT.tabId);

    expect(await harness.registry.get(ceremonyId)).toMatchObject({
      state: 'failed', reason: 'context_changed',
    });
    expect(harness.delivered.at(-1)).toMatchObject({
      outcome: { status: 'error', error: { name: 'NotAllowedError' } },
    });
    expect(harness.windows.open).not.toHaveBeenCalled();
  });

  it('times out a conditional request while it remains unclaimed and silent', async () => {
    const request = getRequest({ mediation: 'conditional' });
    const harness = makeHarness();
    const active = await harness.connection.begin(request);
    const ceremonyId = (active as { ceremonyId: string }).ceremonyId;
    harness.now.value = 31_001;

    harness.timers.fireAll();
    await vi.waitFor(async () => {
      expect(await harness.registry.get(ceremonyId)).toMatchObject({ state: 'failed', reason: 'expired' });
    });

    expect(harness.delivered.at(-1)).toMatchObject({
      outcome: { status: 'error', error: { name: 'NotAllowedError' } },
    });
    expect(harness.vault.executeGet).not.toHaveBeenCalled();
    expect(harness.windows.open).not.toHaveBeenCalled();
  });

  it('withholds an assertion when the original security proof expires at final delivery', async () => {
    const harness = makeHarness();
    harness.security.assertDeliveryCurrent.mockImplementationOnce(() => {
      throw new Error('session timed out');
    });
    const begun = await harness.connection.begin(getRequest());
    const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;

    await expect(harness.coordinator.approve(ceremonyId, {
      kind: 'credential', credentialId: 'credential-A',
    })).resolves.toBe('completed');

    expect(harness.security.assertDeliveryCurrent).toHaveBeenCalledWith(
      expect.objectContaining({ proof: 0, sessionBindingId: 'session-A' }),
      { allowVaultGenerationChange: false },
    );
    expect(harness.delivered.some((message) => message.outcome.status === 'success')).toBe(false);
    expect(await harness.registry.get(ceremonyId)).toBeUndefined();
  });

  it('turns an awaiting approval window close into AbortError without native fallback', async () => {
    const harness = makeHarness();
    const begun = await harness.connection.begin(getRequest());
    const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;

    await harness.coordinator.handleWindowClosed(91);

    expect((await harness.registry.get(ceremonyId))?.state).toBe('failed');
    expect(harness.delivered.at(-1)).toMatchObject({
      ceremonyId,
      outcome: { status: 'error', error: { name: 'AbortError' } },
    });
  });

  it('uses native fallback only for the explicit browser buttons', async () => {
    const excludeOrigin = vi.fn(async () => {});
    const once = makeHarness();
    const onceBegin = await once.connection.begin(getRequest());
    const onceId = (onceBegin as { ceremonyId: string }).ceremonyId;
    await expect(once.coordinator.fallbackOnce(onceId)).resolves.toBe('fallback');
    expect(once.delivered.at(-1)).toMatchObject({
      outcome: { status: 'fallback', reason: 'user_selected_browser' },
    });
    expect(once.windows.close).toHaveBeenCalledWith(91);

    const always = makeHarness({ excludeOrigin });
    const alwaysBegin = await always.connection.begin(getRequest({ bridgeRequestId: BRIDGE_EXCLUDE }));
    const alwaysId = (alwaysBegin as { ceremonyId: string }).ceremonyId;
    await expect(always.coordinator.fallbackAlways(alwaysId)).resolves.toBe('fallback');
    expect(excludeOrigin).toHaveBeenCalledWith(DOCUMENT.origin, 'example.com');
    expect(always.delivered.at(-1)).toMatchObject({
      outcome: { status: 'fallback', reason: 'excluded_domain' },
    });
  });

  it('cancels an executing get as AbortError and never delivers its late result', async () => {
    const pending = deferred<PasskeyAssertionResultSnapshot>();
    const harness = makeHarness({ executeGet: () => pending.promise });
    const begun = await harness.connection.begin(getRequest());
    const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;
    const approval = harness.coordinator.approve(ceremonyId, {
      kind: 'credential', credentialId: 'credential-A',
    });
    await vi.waitFor(() => expect(harness.vault.executeGet).toHaveBeenCalled());

    await harness.coordinator.cancel(ceremonyId);
    pending.resolve(assertion());

    await expect(approval).resolves.toBe('failed');
    expect((await harness.registry.get(ceremonyId))?.state).toBe('failed');
    expect(harness.delivered.at(-1)).toMatchObject({
      outcome: { status: 'error', error: { name: 'AbortError', message: 'The operation was aborted.' } },
    });
    expect(harness.delivered).toHaveLength(1);
    expect(harness.windows.close).toHaveBeenCalledOnce();
    expect(harness.delivered.filter((message) => message.outcome.status === 'success')).toHaveLength(0);
  });

  it('cancels an executing create as uncertain and never requests native fallback', async () => {
    const pending = deferred<ReturnType<typeof registration>>();
    const harness = makeHarness({
      executeCreate: async () => ({ status: 'committed', result: await pending.promise }),
    });
    const begun = await harness.connection.begin(createRequest());
    const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;
    const approval = harness.coordinator.approve(ceremonyId, { kind: 'new' });
    await vi.waitFor(() => expect(harness.vault.executeCreate).toHaveBeenCalled());

    await harness.coordinator.handleWindowClosed(91);
    pending.resolve(registration());

    await expect(approval).resolves.toBe('uncertain');
    expect((await harness.registry.get(ceremonyId))?.state).toBe('uncertain');
    expect(harness.delivered.at(-1)).toMatchObject({
      outcome: { status: 'error', error: { name: 'UnknownError' } },
    });
    expect(harness.delivered.some((message) => message.outcome.status === 'fallback')).toBe(false);
  });

  it('keeps an executing iframe create uncertain when its browser document changes', async () => {
    const pending = deferred<ReturnType<typeof registration>>();
    const harness = makeHarness({
      executeCreate: async () => ({ status: 'committed', result: await pending.promise }),
    });
    const frameDocument: WebsitePasskeyDocumentContext = {
      ...DOCUMENT,
      frameId: 4,
      documentId: 'executing-create-frame',
      url: 'https://login.example.com/frame',
    };
    const delivered: WebsitePasskeyOutcomeMessage[] = [];
    const connection = harness.coordinator.connect(frameDocument, (message) => { delivered.push(message); });
    const begun = await connection.begin(createRequest());
    const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;
    const approval = harness.coordinator.approve(ceremonyId, { kind: 'new' });
    await vi.waitFor(() => expect(harness.vault.executeCreate).toHaveBeenCalled());

    harness.epoch.value += 1;
    await harness.coordinator.handleBrowserDocumentChange(frameDocument.tabId);
    pending.resolve(registration());

    await expect(approval).resolves.toBe('uncertain');
    expect(await harness.registry.get(ceremonyId)).toMatchObject({
      state: 'uncertain',
      reason: 'context_changed',
      frameId: 4,
    });
    expect(delivered).toHaveLength(1);
    expect(delivered[0]).toMatchObject({
      outcome: { status: 'error', error: { name: 'UnknownError' } },
    });
    expect(harness.windows.close).toHaveBeenCalledWith(91);
  });

  it('maps a create outcome_unknown to uncertain and committed_unsynced to success', async () => {
    const unknown = makeHarness({ executeCreate: async () => ({ status: 'outcome_unknown' }) });
    const unknownBegin = await unknown.connection.begin(createRequest());
    await expect(unknown.coordinator.approve(
      (unknownBegin as { ceremonyId: string }).ceremonyId,
      { kind: 'new' },
    )).resolves.toBe('uncertain');
    expect(unknown.delivered.at(-1)?.outcome.status).toBe('error');

    const committed = makeHarness({
      executeCreate: async () => ({ status: 'committed_unsynced', result: registration() }),
    });
    const committedBegin = await committed.connection.begin(createRequest());
    await expect(committed.coordinator.approve(
      (committedBegin as { ceremonyId: string }).ceremonyId,
      { kind: 'new' },
    )).resolves.toBe('completed');
    expect(committed.delivered.at(-1)?.outcome.status).toBe('success');
  });

  it.each([
    ['invalid_state', 'InvalidStateError'],
    ['not_allowed', 'NotAllowedError'],
    ['not_supported', 'NotSupportedError'],
    ['operation_failed', 'UnknownError'],
  ] as const)('maps known not-committed reason %s to fixed %s', async (reason, name) => {
    const harness = makeHarness({ executeCreate: async () => ({ status: 'not_committed', reason }) });
    const begun = await harness.connection.begin(createRequest());
    const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;
    await expect(harness.coordinator.approve(ceremonyId, { kind: 'new' })).resolves.toBe('failed');
    expect(await harness.registry.get(ceremonyId)).toMatchObject({ state: 'failed', reason });
    expect(harness.delivered.at(-1)).toMatchObject({ outcome: { status: 'error', error: { name } } });
  });

  it('passes the full persisted create request and exact approved target atomically to the vault boundary', async () => {
    const harness = makeHarness();
    const request = createRequest({
      excludeCredentials: [{ id: 'ZXhjbHVkZWQ', type: 'public-key', transports: ['internal'] }],
      authenticatorSelection: {
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'preferred',
        authenticatorAttachment: 'platform',
      },
    });
    const begun = await harness.connection.begin(request);
    await expect(harness.coordinator.approve(
      (begun as { ceremonyId: string }).ceremonyId,
      { kind: 'target', cipherId: 'cipher-A' },
    )).resolves.toBe('completed');
    expect(harness.vault.executeCreate).toHaveBeenCalledWith(
      request,
      DOCUMENT.origin,
      { kind: 'target', cipherId: 'cipher-A' },
      expect.objectContaining({ rawGeneration: 'raw-A', policyGeneration: 0 }),
      expect.any(AbortSignal),
    );
  });

  it('keeps a known create commit byte-stable across later security changes and redelivery', async () => {
    const epoch = { value: 0 };
    const harness = makeHarness({
      epoch,
      executeCreate: async () => {
        epoch.value += 1;
        return { status: 'committed', result: registration() };
      },
    });
    harness.security.assertCurrent.mockImplementation(async (snapshot, options) => {
      if (snapshot.proof !== epoch.value && options?.allowVaultGenerationChange !== true) {
        throw new Error('stale');
      }
    });
    const request = createRequest();
    const begun = await harness.connection.begin(request);
    const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;

    await expect(harness.coordinator.approve(ceremonyId, { kind: 'new' })).resolves.toBe('completed');
    expect((await harness.registry.get(ceremonyId))?.state).toBe('completed');
    const delivered = harness.delivered.at(-1);
    expect(delivered).toMatchObject({ outcome: { status: 'success', result: registration() } });
    harness.security.assertBindingCurrent.mockImplementation(async () => ({
      ...(await harness.security.capture()),
      policyGeneration: 0,
    }));

    const redelivered = await harness.connection.resume(request);
    expect(redelivered).toBeUndefined();
    expect(harness.delivered).toEqual([delivered, delivered]);
  });

  it.each(['locked', 'restricted'] as const)(
    'never returns a completed assertion from resume after the session becomes %s',
    async (nextState) => {
      const sessionState = { value: 'unlocked' as 'unlocked' | 'locked' | 'restricted' };
      const harness = makeHarness();
      harness.security.assertBindingCurrent.mockImplementation(async () => {
        if (sessionState.value !== 'unlocked') throw new Error('stale');
        return harness.security.capture();
      });
      const request = getRequest();
      const begun = await harness.connection.begin(request);
      const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;
      await harness.coordinator.approve(ceremonyId, {
        kind: 'credential', credentialId: 'credential-A',
      });
      expect(await harness.registry.get(ceremonyId)).toMatchObject({ state: 'completed' });
      harness.delivered.length = 0;
      sessionState.value = nextState;

      await expect(harness.connection.resume(request)).resolves.toBeUndefined();
      expect(harness.delivered).toEqual([]);
      expect(await harness.registry.get(ceremonyId)).toBeUndefined();
    },
  );

  it('never returns a completed assertion from a duplicate begin after security changes', async () => {
    const harness = makeHarness();
    const request = getRequest();
    const begun = await harness.connection.begin(request);
    const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;
    await harness.coordinator.approve(ceremonyId, {
      kind: 'credential', credentialId: 'credential-A',
    });
    harness.delivered.length = 0;
    harness.security.assertBindingCurrent.mockRejectedValue(new Error('session locked'));

    await expect(harness.connection.begin(request)).resolves.toBeUndefined();
    expect(harness.delivered).toEqual([]);
    expect(await harness.registry.get(ceremonyId)).toBeUndefined();
  });

  it('retires a completed open-approval race without returning or delivering its assertion', async () => {
    const harness = makeHarness();
    const opened = deferred<number>();
    harness.windows.open.mockImplementationOnce(() => opened.promise);
    const sessionState = { value: 'unlocked' as 'unlocked' | 'restricted' };
    harness.security.assertCurrent.mockImplementation(async () => {
      if (sessionState.value !== 'unlocked') throw new Error('stale');
    });
    const request = getRequest();
    const beginning = harness.connection.begin(request);
    await vi.waitFor(() => expect(harness.windows.open).toHaveBeenCalledOnce());
    const awaiting = (await harness.registry.listAwaitingApproval())[0];
    if (!awaiting) throw new Error('Expected awaiting ceremony');
    const executing = await harness.registry.claim(
      awaiting.ceremonyId,
      awaiting.request.bridgeRequestId,
    );
    if (!executing) throw new Error('Expected executing ceremony');
    await harness.registry.complete(executing.ceremonyId, executing.executionId, assertion());
    sessionState.value = 'restricted';
    opened.resolve(91);

    await expect(beginning).resolves.toBeUndefined();
    expect(harness.delivered).toEqual([]);
    expect(harness.windows.close).toHaveBeenCalledWith(91);
    expect(await harness.registry.get(executing.ceremonyId)).toBeUndefined();
  });

  it('never replays an executing create after worker restart', async () => {
    const store = createMemoryStore();
    const pending = deferred<ReturnType<typeof registration>>();
    const first = makeHarness({
      store,
      executeCreate: async () => ({ status: 'committed', result: await pending.promise }),
    });
    const begun = await first.connection.begin(createRequest());
    const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;
    const oldApproval = first.coordinator.approve(ceremonyId, { kind: 'new' });
    await vi.waitFor(() => expect(first.vault.executeCreate).toHaveBeenCalledOnce());

    const restarted = makeHarness({ store });
    const recovered = await restarted.connection.begin(createRequest());

    expect(recovered).toMatchObject({
      type: 'outcome',
      ceremonyId,
      outcome: { status: 'error', error: { name: 'UnknownError' } },
    });
    expect(restarted.vault.executeCreate).not.toHaveBeenCalled();
    pending.resolve(registration());
    await expect(oldApproval).resolves.toBe('uncertain');
  });

  it('redelivers an awaiting conditional worker restart as an extension error', async () => {
    const store = createMemoryStore();
    const request = getRequest({ mediation: 'conditional', allowCredentials: [] });
    const first = makeHarness({ store });
    const begun = await first.connection.begin(request);
    first.connection.close();

    const restarted = makeHarness({
      store,
      prepareGet: async () => { throw new Error('must not rediscover'); },
    });
    const recovered = await restarted.connection.resume(request);

    expect(recovered).toMatchObject({
      type: 'outcome',
      ceremonyId: (begun as { ceremonyId: string }).ceremonyId,
      outcome: { status: 'error', error: { name: 'UnknownError' } },
    });
    expect(restarted.vault.prepareGet).not.toHaveBeenCalled();
    expect(await restarted.registry.get((begun as { ceremonyId: string }).ceremonyId))
      .toMatchObject({ state: 'failed', reason: 'worker_restart' });
  });

  it('keeps the ceremony awaiting when fallback-always exclusion persistence fails', async () => {
    const harness = makeHarness({
      excludeOrigin: async () => { throw new Error('storage failed'); },
    });
    const begun = await harness.connection.begin(getRequest({ bridgeRequestId: BRIDGE_EXCLUDE }));
    const ceremonyId = (begun as { ceremonyId: string }).ceremonyId;

    await expect(harness.coordinator.fallbackAlways(ceremonyId)).resolves.toBe('failed');
    expect((await harness.registry.get(ceremonyId))?.state).toBe('awaitingApproval');
  });

  it('redelivers the same durable terminal after restart and removes it only on exact ACK', async () => {
    const store = createMemoryStore();
    const first = makeHarness({ store, prepareGet: async () => [] });
    const initial = await first.connection.begin(getRequest());
    const outcome = initial as WebsitePasskeyOutcomeMessage;
    first.connection.close();

    const restarted = makeHarness({ store, prepareGet: async () => { throw new Error('must not rediscover'); } });
    const redelivered = await restarted.connection.resume(getRequest());
    expect(redelivered).toEqual(outcome);
    await expect(restarted.connection.acknowledge(
      outcome.ceremonyId,
      outcome.bridgeRequestId,
      '00000000-0000-4000-8000-999999999999',
    )).resolves.toBe(false);
    await expect(restarted.connection.acknowledge(
      outcome.ceremonyId,
      outcome.bridgeRequestId,
      outcome.outcomeId,
    )).resolves.toBe(true);
    expect(await restarted.registry.get(outcome.ceremonyId)).toBeUndefined();
  });

  it('releases terminal runtime state before retention expiry and deduplicates the next generation', async () => {
    const harness = makeHarness();
    const request = getRequest();
    const first = await harness.connection.begin(request);
    const firstId = (first as { ceremonyId: string }).ceremonyId;
    await harness.coordinator.approve(firstId, {
      kind: 'credential', credentialId: 'credential-A',
    });
    const terminal = await harness.registry.get(firstId);
    expect(terminal).toMatchObject({ state: 'completed' });
    harness.now.value = (terminal as { retireAt: number }).retireAt;
    expect(await harness.registry.get(firstId)).toBeUndefined();

    const next = await harness.connection.begin(request);
    const duplicate = await harness.connection.begin(request);

    expect(next).toMatchObject({ type: 'accepted' });
    expect((next as { ceremonyId: string }).ceremonyId).not.toBe(firstId);
    expect(duplicate).toEqual(next);
    expect(harness.vault.prepareGet).toHaveBeenCalledTimes(2);
  });

  it('settles an awaiting ceremony as expired at its absolute deadline', async () => {
    const harness = makeHarness();
    const begun = await harness.connection.begin(getRequest());
    const accepted = begun as { ceremonyId: string; deadlineAt: number };

    harness.timers.fireAll();
    expect((await harness.registry.get(accepted.ceremonyId))?.state).toBe('awaitingApproval');
    expect(harness.timers.callbacks.size).toBeGreaterThan(0);

    harness.now.value = accepted.deadlineAt;
    harness.timers.fireAll();
    await vi.waitFor(async () => {
      expect((await harness.registry.get(accepted.ceremonyId))?.state).toBe('failed');
    });
    expect(harness.delivered.at(-1)).toMatchObject({
      outcome: { status: 'error', error: { name: 'NotAllowedError' } },
    });
    expect(harness.windows.close).toHaveBeenCalledWith(91);
  });
});
