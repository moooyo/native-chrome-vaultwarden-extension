import { describe, expect, it, vi } from 'vitest';
import { AppError, type AppErrorCode } from '../core/errors.js';
import type { PolicyLease } from '../core/policy/effective-enterprise-policy.js';
import type { AccountLease } from '../core/session/account-gate.js';
import type { SessionLease } from '../core/session/session-manager.js';
import type { PasskeyCandidate, PasskeyTarget } from '../core/vault/models.js';
import type { PasskeyCreateOptions } from '../core/vault/vault-service.js';
import {
  canonicalizeWebsitePasskeyRequest,
  type CanonicalWebsitePasskeyCreateRequest,
  type CanonicalWebsitePasskeyGetRequest,
} from '../messaging/website-passkey-port.js';
import type {
  WebsitePasskeyDocumentContext,
  WebsitePasskeySecurityBinding,
  WebsitePasskeySecuritySnapshot,
} from './website-passkey-coordinator.js';
import type { WebsitePasskeyDocumentLease } from './website-passkey-document-gate.js';
import {
  createWebsitePasskeyAvailabilityAdapter,
  createWebsitePasskeySecurityAdapter,
  createWebsitePasskeyVaultAdapter,
  type WebsitePasskeyProductionSecurityDeps,
  type WebsitePasskeyProductionSecurityProof,
  type WebsitePasskeyProductionVault,
} from './website-passkey-production.js';

const DOCUMENT: WebsitePasskeyDocumentContext = {
  tabId: 7,
  frameId: 0,
  documentId: 'document-A',
  url: 'https://login.example.com/path?flow=1',
  origin: 'https://login.example.com',
};
const BRIDGE_GET = '10000000-0000-4000-8000-000000000001';
const BRIDGE_CREATE = '10000000-0000-4000-8000-000000000002';

function getRequest(
  overrides: Partial<CanonicalWebsitePasskeyGetRequest> = {},
): CanonicalWebsitePasskeyGetRequest {
  return canonicalizeWebsitePasskeyRequest({
    bridgeRequestId: BRIDGE_GET,
    kind: 'get',
    rpId: 'example.com',
    challenge: 'Y2hhbGxlbmdl',
    allowCredentials: [
      { type: 'public-key', id: 'Y3JlZC1B', transports: ['internal'] },
      { type: 'public-key', id: 'Y3JlZC1C', transports: [] },
    ],
    userVerification: 'preferred',
    mediation: 'optional',
    timeout: 30_000,
    ...overrides,
  }) as CanonicalWebsitePasskeyGetRequest;
}

function createRequest(
  overrides: Partial<CanonicalWebsitePasskeyCreateRequest> = {},
): CanonicalWebsitePasskeyCreateRequest {
  return canonicalizeWebsitePasskeyRequest({
    bridgeRequestId: BRIDGE_CREATE,
    kind: 'create',
    rp: { id: 'example.com', name: 'Example' },
    user: { id: 'dXNlci1pZA', name: 'alice', displayName: 'Alice Example' },
    challenge: 'Y2hhbGxlbmdl',
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    excludeCredentials: [{ type: 'public-key', id: 'ZXhjbHVkZWQ', transports: ['internal'] }],
    authenticatorSelection: {
      residentKey: 'preferred',
      requireResidentKey: false,
      userVerification: 'preferred',
      authenticatorAttachment: 'platform',
    },
    attestation: 'none',
    extensions: { credProps: true },
    timeout: 30_000,
    ...overrides,
  }) as CanonicalWebsitePasskeyCreateRequest;
}

function deferred<Value>() {
  let resolve!: (value: Value) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<Value>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, resolve, reject };
}

interface TestCapabilitySnapshot {
  readonly availability: 'available' | 'unavailable';
  readonly identity: { readonly serverUrl: string; readonly accountIdentity?: string };
}

function makeSecurityHarness(options: {
  resolveCapability?: () => PromiseLike<TestCapabilitySnapshot>;
  getActiveAuth?: WebsitePasskeyProductionSecurityDeps['session']['getActiveAuth'];
} = {}) {
  const state = {
    sessionGeneration: 1,
    serverGeneration: 2,
    accountGeneration: 3,
    enterpriseGeneration: 4,
    rawGeneration: 'raw-A',
    capabilityGeneration: 5,
    websiteGeneration: 6,
    permissionGeneration: 7,
    accountIdentity: 'alice@example.com',
    serverUrl: 'https://vault.example.com/',
    sessionBindingId: 'binding-A',
    enterpriseAvailable: true,
  };
  const issuedSessions = new WeakSet<object>();
  const issuedAccounts = new WeakSet<object>();
  const issuedPolicies = new WeakSet<object>();
  const issuedCapabilities = new WeakSet<object>();
  const issuedWebsitePolicies = new WeakSet<object>();
  const issuedPermissions = new WeakSet<object>();
  let capabilitySnapshot: TestCapabilitySnapshot = capability();

  function capability() {
    return Object.freeze({
      availability: 'available' as const,
      identity: Object.freeze({
        serverUrl: state.serverUrl,
        accountIdentity: state.accountIdentity,
      }),
    });
  }

  const deps: WebsitePasskeyProductionSecurityDeps = {
    sessionGate: {
      capture(): SessionLease {
        const lease = Object.freeze({ generation: state.sessionGeneration });
        issuedSessions.add(lease);
        return lease;
      },
      assert(lease): void {
        if (!issuedSessions.has(lease) || lease.generation !== state.sessionGeneration) {
          throw new AppError('locked', 'secret session error');
        }
      },
    },
    accountGate: {
      capture(): AccountLease {
        const lease = Object.freeze({
          serverGeneration: state.serverGeneration,
          accountGeneration: state.accountGeneration,
          serverUrl: state.serverUrl,
          accountIdentity: state.accountIdentity,
        });
        issuedAccounts.add(lease);
        return lease;
      },
      assert(lease): void {
        if (!issuedAccounts.has(lease)
          || lease.serverGeneration !== state.serverGeneration
          || lease.accountGeneration !== state.accountGeneration
          || lease.serverUrl !== state.serverUrl
          || lease.accountIdentity !== state.accountIdentity) {
          throw new AppError('session_expired', 'secret account error');
        }
      },
    },
    enterprisePolicyGate: {
      capture(): PolicyLease {
        if (!state.enterpriseAvailable) throw new AppError('sync_required', 'secret policy error');
        const lease = Object.freeze({
          generation: state.enterpriseGeneration,
          serverGeneration: state.serverGeneration,
          accountGeneration: state.accountGeneration,
          serverUrl: state.serverUrl,
          accountIdentity: state.accountIdentity,
          rawGeneration: state.rawGeneration,
        });
        issuedPolicies.add(lease);
        return lease;
      },
      assert(lease): void {
        if (!state.enterpriseAvailable
          || !issuedPolicies.has(lease)
          || lease.generation !== state.enterpriseGeneration
          || lease.rawGeneration !== state.rawGeneration) {
          throw new AppError('denied', 'secret policy error');
        }
      },
    },
    serverCapabilities: {
      resolve: options.resolveCapability ?? (() => Promise.resolve(capabilitySnapshot)),
      capture() {
        const lease = Object.freeze({
          generation: state.capabilityGeneration,
          serverUrl: state.serverUrl,
          accountIdentity: state.accountIdentity,
        });
        issuedCapabilities.add(lease);
        return lease;
      },
      assert(lease) {
        if (!issuedCapabilities.has(lease)
          || lease.generation !== state.capabilityGeneration
          || lease.serverUrl !== state.serverUrl
          || lease.accountIdentity !== state.accountIdentity) {
          throw new AppError('denied', 'secret capability error');
        }
        return capabilitySnapshot;
      },
    },
    websitePolicyGate: {
      capture() {
        const lease = Object.freeze({ generation: state.websiteGeneration });
        issuedWebsitePolicies.add(lease);
        return lease;
      },
      assert(lease): void {
        if (!issuedWebsitePolicies.has(lease) || lease.generation !== state.websiteGeneration) {
          throw new AppError('denied', 'secret website policy error');
        }
      },
      assertAllowed(lease, browserUrl): void {
        this.assert(lease);
        if (browserUrl !== DOCUMENT.url) throw new AppError('denied', 'secret URL error');
      },
    },
    permissionGate: {
      async capture(browserUrl) {
        if (browserUrl !== DOCUMENT.url) {
          throw new AppError('denied', 'secret permission URL error');
        }
        const lease = Object.freeze({
          generation: state.permissionGeneration,
          originPattern: 'https://login.example.com/*',
        });
        issuedPermissions.add(lease);
        return lease;
      },
      assert(lease): void {
        if (!issuedPermissions.has(lease) || lease.generation !== state.permissionGeneration) {
          throw new AppError('denied', 'secret permission error');
        }
      },
    },
    documentGate: {
      capture: vi.fn(async (document, operation = 'get'): Promise<WebsitePasskeyDocumentLease> => ({
        tabId: document.tabId,
        frameId: document.frameId,
        documentId: document.documentId,
        url: document.url,
        origin: document.origin,
        operation,
        topOrigin: document.origin,
        crossOrigin: false,
        lineage: [],
        epochs: [],
      })),
      assert: vi.fn(),
      assertCurrent: vi.fn(async () => {}),
    },
    session: {
      getActiveAuth: options.getActiveAuth ?? (() => Promise.resolve({
        email: state.accountIdentity,
        sessionBindingId: state.sessionBindingId,
      })),
    },
  };
  const adapter = createWebsitePasskeySecurityAdapter(deps);
  return {
    adapter,
    deps,
    state,
    replaceCapability(value?: TestCapabilitySnapshot): void {
      capabilitySnapshot = value ?? capability();
    },
  };
}

describe('website passkey production security adapter', () => {
  it('captures only verified public binding fields and retains exact non-secret proof state', async () => {
    const { adapter } = makeSecurityHarness();
    const snapshot = await adapter.capture(DOCUMENT);

    expect(snapshot).toMatchObject({
      sessionBindingId: 'binding-A',
      accountIdentity: 'alice@example.com',
      serverUrl: 'https://vault.example.com/',
      rawGeneration: 'raw-A',
      policyGeneration: 6,
    });
    expect(Object.keys(snapshot).sort()).toEqual([
      'accountIdentity', 'policyGeneration', 'proof', 'rawGeneration', 'serverUrl', 'sessionBindingId',
    ]);
    expect(snapshot.proof.document).toEqual(DOCUMENT);
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.proof)).toBe(true);
    await expect(adapter.assertCurrent(snapshot)).resolves.toBeUndefined();
  });

  it('binds a same-origin subframe through the browser document gate', async () => {
    const harness = makeSecurityHarness();
    const frameDocument: WebsitePasskeyDocumentContext = {
      ...DOCUMENT,
      frameId: 3,
      documentId: 'subframe-document',
    };

    const snapshot = await harness.adapter.capture(frameDocument);
    await expect(harness.adapter.assertCurrent(snapshot)).resolves.toBeUndefined();

    expect(harness.deps.documentGate.capture).toHaveBeenCalledWith(frameDocument);
    expect(harness.deps.documentGate.assertCurrent).toHaveBeenCalledWith(
      snapshot.proof.documentLease,
      frameDocument,
    );
    expect(snapshot.proof.document).toEqual(frameDocument);
  });

  it('keeps document revocation in the synchronous final write guard', async () => {
    const harness = makeSecurityHarness();
    const snapshot = await harness.adapter.capture(DOCUMENT);
    vi.mocked(harness.deps.documentGate.assert).mockImplementation(() => {
      throw new AppError('denied', 'private document error');
    });

    expect(() => snapshot.proof.assertWriteCurrent()).toThrowError(expect.objectContaining({
      message: 'Website passkey authorization is unavailable.',
    }));
  });

  it.each([
    ['session', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.sessionGeneration += 2; }],
    ['account', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.accountGeneration += 2; }],
    ['enterprise policy', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.enterpriseGeneration += 2; }],
    ['server capability', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.capabilityGeneration += 2; }],
    ['website policy', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.websiteGeneration += 2; }],
    ['host permission', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.permissionGeneration += 2; }],
  ])('rejects an ABA-invalidated %s lease with a fixed error', async (_name, invalidate) => {
    const harness = makeSecurityHarness();
    const snapshot = await harness.adapter.capture(DOCUMENT);
    invalidate(harness.state);

    await expect(harness.adapter.assertCurrent(snapshot)).rejects.toMatchObject({
      message: 'Website passkey authorization is unavailable.',
    });
  });

  it('rejects a lease transition while capability resolution is awaiting', async () => {
    const flight = deferred<{ availability: 'available'; identity: { serverUrl: string; accountIdentity: string } }>();
    const harness = makeSecurityHarness({ resolveCapability: () => flight.promise });
    const pending = harness.adapter.capture(DOCUMENT);
    await vi.waitFor(() => expect(harness.deps.serverCapabilities.resolve).toBeDefined());
    harness.state.sessionGeneration += 1;
    flight.resolve({
      availability: 'available',
      identity: { serverUrl: harness.state.serverUrl, accountIdentity: harness.state.accountIdentity },
    });

    await expect(pending).rejects.toMatchObject({ code: 'locked' });
  });

  it('rejects a lease transition while active auth is awaiting', async () => {
    const auth = deferred<{ email: string; sessionBindingId: string } | undefined>();
    const harness = makeSecurityHarness({ getActiveAuth: () => auth.promise });
    const pending = harness.adapter.capture(DOCUMENT);
    await Promise.resolve();
    harness.state.websiteGeneration += 1;
    auth.resolve({ email: harness.state.accountIdentity, sessionBindingId: harness.state.sessionBindingId });

    await expect(pending).rejects.toMatchObject({ code: 'denied' });
  });

  it('requires an available capability whose exact identity matches the account lease', async () => {
    const unavailable = makeSecurityHarness();
    unavailable.replaceCapability({
      availability: 'unavailable',
      identity: { serverUrl: unavailable.state.serverUrl, accountIdentity: unavailable.state.accountIdentity },
    });
    await expect(unavailable.adapter.capture(DOCUMENT)).rejects.toMatchObject({ code: 'sync_required' });

    const wrongAccount = makeSecurityHarness();
    wrongAccount.replaceCapability({
      availability: 'available',
      identity: { serverUrl: wrongAccount.state.serverUrl, accountIdentity: 'mallory@example.com' },
    });
    await expect(wrongAccount.adapter.capture(DOCUMENT)).rejects.toMatchObject({ code: 'sync_required' });
  });

  it('requires exact document origin and a current matching session binding', async () => {
    const harness = makeSecurityHarness();
    await expect(harness.adapter.capture({ ...DOCUMENT, origin: 'https://evil.example' }))
      .rejects.toMatchObject({ code: 'denied' });

    harness.state.sessionBindingId = '';
    await expect(harness.adapter.capture(DOCUMENT)).rejects.toMatchObject({ code: 'session_expired' });
  });

  it('relaxes only enterprise raw state after a create commit', async () => {
    const harness = makeSecurityHarness();
    const snapshot = await harness.adapter.capture(DOCUMENT);
    harness.state.enterpriseGeneration += 1;
    harness.state.rawGeneration = 'raw-B';
    harness.state.enterpriseAvailable = false;

    await expect(harness.adapter.assertCurrent(snapshot)).rejects.toMatchObject({ code: 'denied' });
    await expect(harness.adapter.assertCurrent(snapshot, { allowVaultGenerationChange: true }))
      .resolves.toBeUndefined();

    harness.state.sessionGeneration += 1;
    await expect(harness.adapter.assertCurrent(snapshot, { allowVaultGenerationChange: true }))
      .rejects.toMatchObject({ code: 'locked' });
  });

  it('does not let allowVaultGenerationChange relax account, binding, site, or capability state', async () => {
    const mutations = [
      (harness: ReturnType<typeof makeSecurityHarness>) => { harness.state.accountGeneration += 1; },
      (harness: ReturnType<typeof makeSecurityHarness>) => { harness.state.sessionBindingId = 'binding-B'; },
      (harness: ReturnType<typeof makeSecurityHarness>) => { harness.state.websiteGeneration += 1; },
      (harness: ReturnType<typeof makeSecurityHarness>) => { harness.state.capabilityGeneration += 1; },
      (harness: ReturnType<typeof makeSecurityHarness>) => { harness.state.permissionGeneration += 1; },
    ];
    for (const mutate of mutations) {
      const harness = makeSecurityHarness();
      const snapshot = await harness.adapter.capture(DOCUMENT);
      mutate(harness);
      await expect(harness.adapter.assertCurrent(snapshot, { allowVaultGenerationChange: true })).rejects.toThrow();
    }
  });

  it('reconstructs active proof and compares raw/snapshot presence strictly unless relaxed', async () => {
    const harness = makeSecurityHarness();
    const original = await harness.adapter.capture(DOCUMENT);
    const withSnapshot = {
      ...bindingOf(original),
      snapshotGeneration: 'snapshot-A',
    };
    await expect(harness.adapter.assertBindingCurrent(withSnapshot, DOCUMENT)).rejects.toThrow();
    await expect(harness.adapter.assertBindingCurrent(
      withSnapshot,
      DOCUMENT,
      { allowVaultGenerationChange: true },
    )).resolves.toMatchObject({ sessionBindingId: 'binding-A' });

    const explicitUndefined = {
      ...bindingOf(original),
      snapshotGeneration: undefined,
    } as unknown as WebsitePasskeySecurityBinding;
    await expect(harness.adapter.assertBindingCurrent(explicitUndefined, DOCUMENT)).rejects.toThrow();

    harness.state.enterpriseGeneration += 1;
    harness.state.rawGeneration = 'raw-B';
    await expect(harness.adapter.assertBindingCurrent(bindingOf(original), DOCUMENT)).rejects.toThrow();
    await expect(harness.adapter.assertBindingCurrent(
      bindingOf(original),
      DOCUMENT,
      { allowVaultGenerationChange: true },
    )).resolves.toMatchObject({ sessionBindingId: 'binding-A' });
  });

  it.each([
    ['sessionBindingId', 'binding-B'],
    ['accountIdentity', 'mallory@example.com'],
    ['serverUrl', 'https://other.example.com/'],
    ['policyGeneration', 999],
  ] as const)('never relaxes recovered binding field %s', async (field, value) => {
    const harness = makeSecurityHarness();
    const original = await harness.adapter.capture(DOCUMENT);
    const changed = { ...bindingOf(original), [field]: value };

    await expect(harness.adapter.assertBindingCurrent(changed, DOCUMENT)).rejects.toThrow();
    await expect(harness.adapter.assertBindingCurrent(
      changed,
      DOCUMENT,
      { allowVaultGenerationChange: true },
    )).rejects.toThrow();
  });

  it('rejects a forged snapshot even when it reuses an issued proof', async () => {
    const harness = makeSecurityHarness();
    const snapshot = await harness.adapter.capture(DOCUMENT);
    const forged = { ...snapshot, accountIdentity: 'mallory@example.com' };
    await expect(harness.adapter.assertCurrent(forged)).rejects.toMatchObject({ code: 'denied' });
  });

  it.each([
    ['session', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.sessionGeneration += 1; }],
    ['account', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.accountGeneration += 1; }],
    ['enterprise policy', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.enterpriseGeneration += 1; }],
    ['site policy', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.websiteGeneration += 1; }],
    ['server capability', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.capabilityGeneration += 1; }],
    ['host permission', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.permissionGeneration += 1; }],
  ])('exposes a synchronous write guard that rejects %s revocation', async (_name, revoke) => {
    const harness = makeSecurityHarness();
    const snapshot = await harness.adapter.capture(DOCUMENT);
    revoke(harness.state);

    expect(() => snapshot.proof.assertWriteCurrent()).toThrowError(expect.objectContaining({
      message: 'Website passkey authorization is unavailable.',
    }));
  });
});

describe('website passkey production availability adapter', () => {
  function availabilityHarness(
    sessionState: { value: 'loggedOut' | 'locked' | 'restricted' | 'unlocked' } = {
      value: 'locked',
    },
  ) {
    const harness = makeSecurityHarness({
      getActiveAuth: async () => { throw new Error('availability must not read active auth'); },
    });
    const adapter = createWebsitePasskeyAvailabilityAdapter({
      accountGate: harness.deps.accountGate,
      websitePolicyGate: harness.deps.websitePolicyGate,
      permissionGate: harness.deps.permissionGate,
      documentGate: harness.deps.documentGate,
      session: { getState: async () => sessionState.value },
    });
    return { ...harness, adapter, sessionState };
  }

  it.each(['locked', 'unlocked'] as const)(
    'captures only public document, host, account, and policy authority while %s',
    async (state) => {
      const harness = availabilityHarness({ value: state });
      const snapshot = await harness.adapter.capture(DOCUMENT, 'get');

      expect(snapshot).toMatchObject({
        sessionState: state,
        accountIdentity: 'alice@example.com',
        serverUrl: 'https://vault.example.com/',
        policyGeneration: 6,
      });
      expect(Object.keys(snapshot).sort()).toEqual([
        'accountIdentity', 'policyGeneration', 'proof', 'serverUrl', 'sessionState',
      ]);
      expect(harness.deps.documentGate.capture).toHaveBeenCalledWith(DOCUMENT, 'get');
      await expect(harness.adapter.assertCurrent(snapshot)).resolves.toBeUndefined();
      expect(harness.deps.documentGate.assertCurrent).toHaveBeenCalledWith(
        snapshot.proof.documentLease,
        DOCUMENT,
      );
    },
  );

  it.each(['loggedOut', 'restricted'] as const)(
    'keeps interception unavailable while the session is %s',
    async (state) => {
      const harness = availabilityHarness({ value: state });
      await expect(harness.adapter.capture(DOCUMENT, 'create')).rejects.toMatchObject({
        message: 'Website passkey authorization is unavailable.',
      });
    },
  );

  it('revokes a public proof on account, policy, host, document, or state change', async () => {
    const cases = [
      (harness: ReturnType<typeof availabilityHarness>) => { harness.state.accountGeneration += 1; },
      (harness: ReturnType<typeof availabilityHarness>) => { harness.state.websiteGeneration += 1; },
      (harness: ReturnType<typeof availabilityHarness>) => { harness.state.permissionGeneration += 1; },
      (harness: ReturnType<typeof availabilityHarness>) => {
        vi.mocked(harness.deps.documentGate.assert).mockImplementation(() => {
          throw new AppError('denied', 'document changed');
        });
      },
      (harness: ReturnType<typeof availabilityHarness>) => { harness.sessionState.value = 'unlocked'; },
    ];

    for (const invalidate of cases) {
      const harness = availabilityHarness();
      const snapshot = await harness.adapter.capture(DOCUMENT, 'get');
      invalidate(harness);
      await expect(harness.adapter.assertCurrent(snapshot)).rejects.toMatchObject({
        message: 'Website passkey authorization is unavailable.',
      });
    }
  });
});

function bindingOf(
  snapshot: WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>,
): WebsitePasskeySecurityBinding {
  return {
    sessionBindingId: snapshot.sessionBindingId,
    accountIdentity: snapshot.accountIdentity,
    serverUrl: snapshot.serverUrl,
    rawGeneration: snapshot.rawGeneration,
    policyGeneration: snapshot.policyGeneration,
  };
}

function makeVault(overrides: Partial<WebsitePasskeyProductionVault> = {}) {
  const vault: WebsitePasskeyProductionVault = {
    listPasskeyCandidates: vi.fn(async () => []),
    getPasskeyTargets: vi.fn(async () => []),
    getPasskeyAssertion: vi.fn(async () => undefined),
    createPasskey: vi.fn(async () => registration()),
    ...overrides,
  };
  return { vault, adapter: createWebsitePasskeyVaultAdapter(vault) };
}

function registration() {
  return {
    credentialId: 'Y3JlZC1B',
    attestationObject: 'YXR0ZXN0YXRpb24',
    clientDataJSON: 'Y2xpZW50',
    authData: 'YXV0aA',
    publicKeySpki: 'cHVibGlj',
    publicKeyAlgorithm: -7 as const,
  };
}

const UNUSED_SNAPSHOT = {
  proof: { assertWriteCurrent: () => {} },
} as unknown as WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>;

function crossOriginSnapshot(operation: 'get' | 'create') {
  return {
    proof: {
      assertWriteCurrent: () => {},
      documentLease: {
        tabId: DOCUMENT.tabId,
        frameId: DOCUMENT.frameId,
        documentId: DOCUMENT.documentId,
        url: DOCUMENT.url,
        origin: DOCUMENT.origin,
        operation,
        topOrigin: 'https://top.example',
        crossOrigin: true,
        lineage: [],
        epochs: [],
      },
    },
  } as unknown as WebsitePasskeySecuritySnapshot<WebsitePasskeyProductionSecurityProof>;
}

describe('website passkey production vault adapter', () => {
  it('rejects an rpId that is not valid for the browser-authoritative frame origin', async () => {
    const { adapter, vault } = makeVault();

    await expect(adapter.prepareGet(
      getRequest({ rpId: 'evil.example' }),
      DOCUMENT.origin,
      UNUSED_SNAPSHOT,
      new AbortController().signal,
    )).rejects.toMatchObject({ code: 'denied' });

    expect(vault.listPasskeyCandidates).not.toHaveBeenCalled();
  });

  it('preserves an empty conditional allow-list so the vault performs resident-only discovery', async () => {
    const listPasskeyCandidates = vi.fn(async () => ([
      { credentialId: 'Y3JlZC1S', name: 'Resident', username: 'alice' },
    ]));
    const { adapter } = makeVault({ listPasskeyCandidates });
    const request = getRequest({ mediation: 'conditional', allowCredentials: [] });

    const result = await adapter.prepareGet(
      request,
      DOCUMENT.origin,
      UNUSED_SNAPSHOT,
      new AbortController().signal,
    );

    expect(listPasskeyCandidates).toHaveBeenCalledWith({
      rpId: 'example.com',
      origin: DOCUMENT.origin,
      allowedCredentialIds: [],
    });
    expect(result).toEqual([{ id: 'Y3JlZC1S', name: 'Resident', username: 'alice' }]);
  });

  it('maps get discovery fields and filters every reprompt candidate', async () => {
    const candidates: PasskeyCandidate[] = [
      { credentialId: 'Y3JlZC1B', name: 'Work', username: 'alice' },
      { credentialId: 'Y3JlZC1S', name: 'Secret', requiresReprompt: true },
    ];
    const { adapter, vault } = makeVault({ listPasskeyCandidates: vi.fn(async () => candidates) });
    const result = await adapter.prepareGet(
      getRequest(),
      DOCUMENT.origin,
      UNUSED_SNAPSHOT,
      new AbortController().signal,
    );

    expect(vault.listPasskeyCandidates).toHaveBeenCalledWith({
      rpId: 'example.com',
      origin: DOCUMENT.origin,
      allowedCredentialIds: ['Y3JlZC1B', 'Y3JlZC1C'],
    });
    expect(result).toEqual([{ id: 'Y3JlZC1B', name: 'Work', username: 'alice' }]);
  });

  it('maps create discovery fields and filters every reprompt target', async () => {
    const targets: PasskeyTarget[] = [
      { id: 'cipher-A', name: 'Existing', username: 'alice' },
      { id: 'cipher-B', name: 'Protected', requiresReprompt: true },
    ];
    const { adapter, vault } = makeVault({ getPasskeyTargets: vi.fn(async () => targets) });
    const result = await adapter.prepareCreate(
      createRequest(),
      DOCUMENT.origin,
      UNUSED_SNAPSHOT,
      new AbortController().signal,
    );

    expect(vault.getPasskeyTargets).toHaveBeenCalledWith({
      rpId: 'example.com',
      origin: DOCUMENT.origin,
    });
    expect(result).toEqual([{ id: 'cipher-A', name: 'Existing', username: 'alice' }]);
  });

  it('signs with only the selected credential and returns fixed platform/internal metadata', async () => {
    const getPasskeyAssertion = vi.fn(async () => ({
      credentialId: 'Y3JlZC1B',
      authenticatorData: 'YXV0aA',
      clientDataJSON: 'Y2xpZW50',
      signature: 'c2ln',
      userHandle: 'dXNlcg',
    }));
    const { adapter } = makeVault({ getPasskeyAssertion });
    const result = await adapter.executeGet(
      getRequest(),
      DOCUMENT.origin,
      'Y3JlZC1B',
      UNUSED_SNAPSHOT,
      new AbortController().signal,
    );

    expect(getPasskeyAssertion).toHaveBeenCalledWith({
      rpId: 'example.com',
      origin: DOCUMENT.origin,
      challenge: 'Y2hhbGxlbmdl',
      allowedCredentialIds: ['Y3JlZC1B'],
    });
    expect(result).toEqual({
      kind: 'get',
      authenticatorAttachment: 'platform',
      transports: ['internal'],
      credentialId: 'Y3JlZC1B',
      authenticatorData: 'YXV0aA',
      clientDataJSON: 'Y2xpZW50',
      signature: 'c2ln',
      userHandle: 'dXNlcg',
    });
  });

  it('passes only a document-proof-derived crossOrigin flag into get/create core calls', async () => {
    const getPasskeyAssertion = vi.fn(async () => undefined);
    const createPasskey = vi.fn(async () => registration());
    const { adapter } = makeVault({ getPasskeyAssertion, createPasskey });

    await adapter.executeGet(
      getRequest(),
      DOCUMENT.origin,
      'Y3JlZC1B',
      crossOriginSnapshot('get'),
      new AbortController().signal,
    );
    await adapter.executeCreate(
      createRequest(),
      DOCUMENT.origin,
      { kind: 'new' },
      crossOriginSnapshot('create'),
      new AbortController().signal,
    );

    expect(getPasskeyAssertion).toHaveBeenCalledWith(expect.objectContaining({ crossOrigin: true }));
    expect(createPasskey).toHaveBeenCalledWith(
      expect.objectContaining({ crossOrigin: true }),
      { assertAuthorized: expect.any(Function) },
    );
  });

  it('maps every create field, target selection, and requested credProps', async () => {
    const createPasskey = vi.fn(async () => registration());
    const { adapter } = makeVault({ createPasskey });
    const result = await adapter.executeCreate(
      createRequest(),
      DOCUMENT.origin,
      { kind: 'target', cipherId: 'cipher-A' },
      UNUSED_SNAPSHOT,
      new AbortController().signal,
    );

    expect(createPasskey).toHaveBeenCalledWith({
      rpId: 'example.com',
      rpName: 'Example',
      userHandle: 'dXNlci1pZA',
      userName: 'alice',
      userDisplayName: 'Alice Example',
      challenge: 'Y2hhbGxlbmdl',
      origin: DOCUMENT.origin,
      residentKey: 'preferred',
      requireResidentKey: false,
      excludeCredentialIds: ['ZXhjbHVkZWQ'],
      authenticatorAttachment: 'platform',
      targetCipherId: 'cipher-A',
    }, { assertAuthorized: expect.any(Function) });
    expect(result).toEqual({
      status: 'committed',
      result: {
        kind: 'create',
        authenticatorAttachment: 'platform',
        transports: ['internal'],
        credProps: { rk: true },
        ...registration(),
      },
    });
  });

  it('omits a new-item target and returns null credProps when the RP did not request it', async () => {
    const createPasskey = vi.fn(async () => registration());
    const { adapter } = makeVault({ createPasskey });
    const request = createRequest({
      authenticatorSelection: {
        residentKey: 'discouraged',
        requireResidentKey: false,
        userVerification: 'preferred',
      },
      extensions: { credProps: false },
    });
    const result = await adapter.executeCreate(
      request,
      DOCUMENT.origin,
      { kind: 'new' },
      UNUSED_SNAPSHOT,
      new AbortController().signal,
    );

    expect(createPasskey).toHaveBeenCalledWith(
      expect.not.objectContaining({ targetCipherId: expect.anything() }),
      { assertAuthorized: expect.any(Function) },
    );
    expect(result.status).toBe('committed');
    if (result.status === 'committed') expect(result.result.credProps).toBeNull();
  });

  it.each([
    ['outcome_unknown', 'outcome_unknown', undefined],
    ['committed_unsynced', 'outcome_unknown', undefined],
    ['conflict', 'not_committed', 'invalid_state'],
    ['stale_form', 'not_committed', 'invalid_state'],
    ['no_match', 'not_committed', 'not_supported'],
    ['locked', 'not_committed', 'not_allowed'],
    ['session_expired', 'not_committed', 'not_allowed'],
    ['sync_required', 'not_committed', 'not_allowed'],
    ['denied', 'not_committed', 'not_allowed'],
    ['reprompt_required', 'not_committed', 'not_allowed'],
    ['error', 'not_committed', 'operation_failed'],
  ] as const)('classifies AppError %s as %s', async (code, status, reason) => {
    const { adapter } = makeVault({
      createPasskey: vi.fn(async () => { throw new AppError(code as AppErrorCode, 'secret'); }),
    });
    const result = await adapter.executeCreate(
      createRequest(),
      DOCUMENT.origin,
      { kind: 'new' },
      UNUSED_SNAPSHOT,
      new AbortController().signal,
    );
    expect(result.status).toBe(status);
    if (reason !== undefined && result.status === 'not_committed') expect(result.reason).toBe(reason);
  });

  it('lets non-AppError create failures escape for the coordinator uncertain path', async () => {
    const failure = new TypeError('transport failed after dispatch');
    const { adapter } = makeVault({ createPasskey: vi.fn(async () => { throw failure; }) });
    await expect(adapter.executeCreate(
      createRequest(),
      DOCUMENT.origin,
      { kind: 'new' },
      UNUSED_SNAPSHOT,
      new AbortController().signal,
    )).rejects.toBe(failure);
  });

  it.each([
    ['session', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.sessionGeneration += 1; }],
    ['account', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.accountGeneration += 1; }],
    ['enterprise policy', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.enterpriseGeneration += 1; }],
    ['site policy', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.websiteGeneration += 1; }],
    ['server capability', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.capabilityGeneration += 1; }],
    ['host permission', (state: ReturnType<typeof makeSecurityHarness>['state']) => { state.permissionGeneration += 1; }],
  ])('returns not_allowed without remote I/O when %s is revoked after key generation', async (
    _name,
    revoke,
  ) => {
    const security = makeSecurityHarness();
    const snapshot = await security.adapter.capture(DOCUMENT, 'create');
    const remote = vi.fn();
    const generate = vi.fn(() => revoke(security.state));
    const createPasskey = vi.fn(async (
      _request: unknown,
      options?: PasskeyCreateOptions,
    ) => {
      generate();
      options?.assertAuthorized?.();
      remote();
      return registration();
    });
    const { adapter } = makeVault({ createPasskey });

    await expect(adapter.executeCreate(
      createRequest(),
      DOCUMENT.origin,
      { kind: 'new' },
      snapshot,
      new AbortController().signal,
    )).resolves.toEqual({ status: 'not_committed', reason: 'not_allowed' });
    expect(generate).toHaveBeenCalledOnce();
    expect(remote).not.toHaveBeenCalled();
  });

  it('checks an already-aborted signal before every vault call', async () => {
    const { adapter, vault } = makeVault();
    const controller = new AbortController();
    controller.abort();
    const calls = [
      adapter.prepareGet(getRequest(), DOCUMENT.origin, UNUSED_SNAPSHOT, controller.signal),
      adapter.prepareCreate(createRequest(), DOCUMENT.origin, UNUSED_SNAPSHOT, controller.signal),
      adapter.executeGet(getRequest(), DOCUMENT.origin, 'Y3JlZC1B', UNUSED_SNAPSHOT, controller.signal),
      adapter.executeCreate(createRequest(), DOCUMENT.origin, { kind: 'new' }, UNUSED_SNAPSHOT, controller.signal),
    ];
    for (const call of calls) await expect(call).rejects.toMatchObject({ name: 'AbortError' });
    expect(vault.listPasskeyCandidates).not.toHaveBeenCalled();
    expect(vault.getPasskeyTargets).not.toHaveBeenCalled();
    expect(vault.getPasskeyAssertion).not.toHaveBeenCalled();
    expect(vault.createPasskey).not.toHaveBeenCalled();
  });

  it('checks a newly aborted signal after every awaited discovery or assertion call', async () => {
    const candidates = deferred<readonly PasskeyCandidate[]>();
    const targets = deferred<readonly PasskeyTarget[]>();
    const assertion = deferred<undefined>();
    const { adapter } = makeVault({
      listPasskeyCandidates: () => candidates.promise,
      getPasskeyTargets: () => targets.promise,
      getPasskeyAssertion: () => assertion.promise,
    });
    const controllers = Array.from({ length: 3 }, () => new AbortController());
    const calls = [
      adapter.prepareGet(getRequest(), DOCUMENT.origin, UNUSED_SNAPSHOT, controllers[0]!.signal),
      adapter.prepareCreate(createRequest(), DOCUMENT.origin, UNUSED_SNAPSHOT, controllers[1]!.signal),
      adapter.executeGet(getRequest(), DOCUMENT.origin, 'Y3JlZC1B', UNUSED_SNAPSHOT, controllers[2]!.signal),
    ];
    for (const controller of controllers) controller.abort();
    candidates.resolve([]);
    targets.resolve([]);
    assertion.resolve(undefined);
    for (const call of calls) await expect(call).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('does not overwrite a known committed create when abort arrives in the resolve tick', async () => {
    const creation = deferred<ReturnType<typeof registration>>();
    const { adapter } = makeVault({ createPasskey: () => creation.promise });
    const controller = new AbortController();
    const pending = adapter.executeCreate(
      createRequest(),
      DOCUMENT.origin,
      { kind: 'new' },
      UNUSED_SNAPSHOT,
      controller.signal,
    );

    creation.resolve(registration());
    controller.abort();
    await expect(pending).resolves.toMatchObject({ status: 'committed' });
  });

  it('keeps a resolved create committed when the signal aborts afterward', async () => {
    const { adapter } = makeVault();
    const controller = new AbortController();
    const result = await adapter.executeCreate(
      createRequest(),
      DOCUMENT.origin,
      { kind: 'new' },
      UNUSED_SNAPSHOT,
      controller.signal,
    );
    controller.abort();

    expect(result.status).toBe('committed');
  });
});
