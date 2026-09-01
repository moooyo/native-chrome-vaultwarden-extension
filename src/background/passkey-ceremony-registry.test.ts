import { describe, expect, it, vi } from 'vitest';
import { bytesToBase64Url } from '../core/crypto/encoding.js';
import { createMemoryStore, type KeyValueStore } from '../platform/store.js';
import {
  MAX_WEBSITE_PASSKEY_ATTESTATION_OBJECT_BYTES,
  MAX_WEBSITE_PASSKEY_AUTHENTICATOR_DATA_BYTES,
  MAX_WEBSITE_PASSKEY_CLIENT_DATA_JSON_BYTES,
  MAX_WEBSITE_PASSKEY_CREDENTIAL_ID_BYTES,
  MAX_WEBSITE_PASSKEY_DESCRIPTORS,
  MAX_WEBSITE_PASSKEY_PUBLIC_KEY_SPKI_BYTES,
  MAX_WEBSITE_PASSKEY_SIGNATURE_BYTES,
  MAX_WEBSITE_PASSKEY_USER_HANDLE_BYTES,
} from '../messaging/website-passkey-port.js';
import type {
  CanonicalWebsitePasskeyCreateRequest,
  CanonicalWebsitePasskeyGetRequest,
} from '../messaging/website-passkey-port.js';
import {
  DEFAULT_PASSKEY_CEREMONY_TERMINAL_TTL_MS,
  PASSKEY_CEREMONY_ENVELOPE_UTF8_BYTE_BUDGET,
  PASSKEY_CEREMONY_STORAGE_KEY,
  PASSKEY_CEREMONY_SCHEMA_VERSION,
  PASSKEY_CEREMONY_TERMINAL_GROWTH_RESERVE_BYTES,
  PasskeyCeremonyRegistry,
  type BeginPasskeyCeremonyInput,
  type PasskeyAssertionResultSnapshot,
  type PasskeyRegistrationResultSnapshot,
} from './passkey-ceremony-registry.js';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
      session: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
    },
  },
}));

const GET_BRIDGE_ID = '11111111-1111-4111-8111-111111111111';
const CREATE_BRIDGE_ID = '22222222-2222-4222-8222-222222222222';
const GET_DIGEST = '65d789ec6cf1a49263ecd555ab8b8ef49b9d51e2276e0891926f0d67520e4545';

function getRequest(
  overrides: Partial<CanonicalWebsitePasskeyGetRequest> = {},
): CanonicalWebsitePasskeyGetRequest {
  return {
    bridgeRequestId: GET_BRIDGE_ID,
    kind: 'get',
    rpId: 'example.com',
    challenge: 'AQID',
    allowCredentials: [{ id: 'BAUG', type: 'public-key', transports: ['internal'] }],
    userVerification: 'preferred',
    mediation: 'optional',
    timeout: 120_000,
    ...overrides,
  };
}

function createRequest(
  overrides: Partial<CanonicalWebsitePasskeyCreateRequest> = {},
): CanonicalWebsitePasskeyCreateRequest {
  return {
    bridgeRequestId: CREATE_BRIDGE_ID,
    kind: 'create',
    rp: { id: 'example.com', name: 'Example' },
    user: { id: 'AQ', name: 'alice', displayName: 'Alice' },
    challenge: 'BwgJ',
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    excludeCredentials: [],
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'preferred',
      authenticatorAttachment: 'platform',
    },
    attestation: 'none',
    extensions: { credProps: true },
    timeout: 180_000,
    ...overrides,
  };
}

function beginInput(
  request: CanonicalWebsitePasskeyGetRequest | CanonicalWebsitePasskeyCreateRequest = getRequest(),
  overrides: Partial<BeginPasskeyCeremonyInput> = {},
): BeginPasskeyCeremonyInput {
  return {
    tabId: 7,
    frameId: 0,
    documentId: 'doc-A',
    frameUrl: 'https://login.example.com/path',
    origin: 'https://login.example.com',
    request,
    sessionBindingId: 'session-A',
    accountIdentity: 'alice@example.com',
    serverUrl: 'https://vault.example.com',
    rawGeneration: 'raw-A',
    snapshotGeneration: 'snapshot-A',
    policyGeneration: 1,
    candidates: request.kind === 'get'
      ? [{ kind: 'credential', id: 'credential-A', name: 'Example', username: 'alice' }]
      : [{ kind: 'target', id: 'cipher-A', name: 'Existing login' }],
    ...overrides,
  };
}

function assertion(): PasskeyAssertionResultSnapshot {
  return {
    kind: 'get',
    authenticatorAttachment: 'platform',
    transports: ['internal'],
    credentialId: 'Y3JlZGVudGlhbA',
    authenticatorData: 'YXV0aA',
    clientDataJSON: 'Y2xpZW50',
    signature: 'c2lnbmF0dXJl',
  };
}

function registration(
  overrides: Partial<PasskeyRegistrationResultSnapshot> = {},
): PasskeyRegistrationResultSnapshot {
  return {
    kind: 'create',
    authenticatorAttachment: 'platform',
    transports: ['internal'],
    credProps: { rk: true },
    credentialId: 'Y3JlZGVudGlhbA',
    attestationObject: 'YXR0ZXN0YXRpb24',
    clientDataJSON: 'Y2xpZW50',
    authData: 'YXV0aA',
    publicKeySpki: 'cHVibGlj',
    publicKeyAlgorithm: -7,
    ...overrides,
  };
}

function idFactory(initialSequence = 0): () => string {
  let sequence = initialSequence;
  return () => {
    sequence += 1;
    return `00000000-0000-4000-8000-${String(sequence).padStart(12, '0')}`;
  };
}

function bridgeId(sequence: number): string {
  return `10000000-0000-4000-8000-${String(sequence).padStart(12, '0')}`;
}

function maximumBase64Url(byteLength: number, discriminator = 0): string {
  const bytes = new Uint8Array(byteLength);
  bytes[0] = discriminator & 0xff;
  if (byteLength > 1) bytes[byteLength - 1] = (discriminator + 1) & 0xff;
  return bytesToBase64Url(bytes);
}

function maximumAssertion(): PasskeyAssertionResultSnapshot {
  return assertionWith({
    credentialId: maximumBase64Url(MAX_WEBSITE_PASSKEY_CREDENTIAL_ID_BYTES, 1),
    authenticatorData: maximumBase64Url(MAX_WEBSITE_PASSKEY_AUTHENTICATOR_DATA_BYTES, 2),
    clientDataJSON: maximumBase64Url(MAX_WEBSITE_PASSKEY_CLIENT_DATA_JSON_BYTES, 3),
    signature: maximumBase64Url(MAX_WEBSITE_PASSKEY_SIGNATURE_BYTES, 4),
    userHandle: maximumBase64Url(MAX_WEBSITE_PASSKEY_USER_HANDLE_BYTES, 5),
  });
}

function maximumRegistration(): PasskeyRegistrationResultSnapshot {
  return registration({
    credentialId: maximumBase64Url(MAX_WEBSITE_PASSKEY_CREDENTIAL_ID_BYTES, 6),
    attestationObject: maximumBase64Url(MAX_WEBSITE_PASSKEY_ATTESTATION_OBJECT_BYTES, 7),
    clientDataJSON: maximumBase64Url(MAX_WEBSITE_PASSKEY_CLIENT_DATA_JSON_BYTES, 8),
    authData: maximumBase64Url(MAX_WEBSITE_PASSKEY_AUTHENTICATOR_DATA_BYTES, 9),
    publicKeySpki: maximumBase64Url(MAX_WEBSITE_PASSKEY_PUBLIC_KEY_SPKI_BYTES, 10),
  });
}

function assertionWith(
  overrides: Partial<PasskeyAssertionResultSnapshot>,
): PasskeyAssertionResultSnapshot {
  return { ...assertion(), ...overrides };
}

function largeCandidates(
  kind: 'credential' | 'target',
  count: number,
  display: string,
) {
  return Array.from({ length: count }, (_, index) => ({
    kind,
    id: `${String(index).padStart(3, '0')}${'x'.repeat(4_093)}`,
    name: display,
    username: display,
  })) as BeginPasskeyCeremonyInput['candidates'];
}

function maximumDescriptors() {
  return Array.from({ length: MAX_WEBSITE_PASSKEY_DESCRIPTORS }, (_, index) => ({
    id: maximumBase64Url(MAX_WEBSITE_PASSKEY_CREDENTIAL_ID_BYTES, index),
    type: 'public-key' as const,
    transports: ['internal'] as const,
  }));
}

function persistedUtf8Bytes(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify({ [PASSKEY_CEREMONY_STORAGE_KEY]: value })).byteLength;
}

function makeRegistry(options: {
  store?: KeyValueStore;
  now?: () => number;
  ttlMs?: number;
  terminalTtlMs?: number;
  maxEntries?: number;
  createId?: () => string;
} = {}): PasskeyCeremonyRegistry {
  return new PasskeyCeremonyRegistry({
    store: options.store ?? createMemoryStore(),
    now: options.now ?? (() => 1_000),
    createId: options.createId ?? idFactory(),
    ...(options.ttlMs === undefined ? {} : { ttlMs: options.ttlMs }),
    ...(options.terminalTtlMs === undefined ? {} : { terminalTtlMs: options.terminalTtlMs }),
    ...(options.maxEntries === undefined ? {} : { maxEntries: options.maxEntries }),
  });
}

async function created(
  registry: PasskeyCeremonyRegistry,
  input = beginInput(),
) {
  const result = await registry.begin(input);
  if (result.status !== 'created') throw new Error(`Expected created, got ${result.status}`);
  return result.ceremony;
}

describe('PasskeyCeremonyRegistry schema v2', () => {
  it('rejects non-string and newline-suffixed generated identifiers', async () => {
    const nonString = makeRegistry({ createId: (() => 42) as unknown as () => string });
    await expect(nonString.begin(beginInput())).rejects.toMatchObject({ code: 'id_generation' });

    const newline = makeRegistry({
      createId: () => '00000000-0000-4000-8000-000000000001\n',
    });
    await expect(newline.begin(beginInput())).rejects.toMatchObject({ code: 'id_generation' });
  });

  it('persists the full canonical request, browser-owned bindings, fixed digest, and absolute deadline', async () => {
    const store = createMemoryStore();
    const registry = makeRegistry({ store });
    const input = beginInput(getRequest({ rpId: 'EXAMPLE.COM' }), {
      frameUrl: 'https://login.example.com/path/../login',
    });

    const result = await registry.begin(input);

    expect(result.status).toBe('created');
    if (result.status !== 'created') return;
    expect(result.ceremony).toMatchObject({
      schemaVersion: PASSKEY_CEREMONY_SCHEMA_VERSION,
      state: 'awaitingApproval',
      frameUrl: 'https://login.example.com/login',
      origin: 'https://login.example.com',
      request: { ...getRequest(), rpId: 'example.com' },
      requestDigest: GET_DIGEST,
      sessionBindingId: 'session-A',
      accountIdentity: 'alice@example.com',
      serverUrl: 'https://vault.example.com/',
      rawGeneration: 'raw-A',
      snapshotGeneration: 'snapshot-A',
      policyGeneration: 1,
      createdAt: 1_000,
      deadlineAt: 121_000,
    });
    expect(await store.get(PASSKEY_CEREMONY_STORAGE_KEY)).toEqual({
      schemaVersion: PASSKEY_CEREMONY_SCHEMA_VERSION,
      entries: [result.ceremony],
    });
  });

  it('uses the smaller of request timeout and policy TTL and never extends it on claim', async () => {
    const registry = makeRegistry({ ttlMs: 90_000 });
    const ceremony = await created(registry, beginInput(getRequest({ timeout: 180_000 })));
    const executing = await registry.claim(ceremony.ceremonyId, GET_BRIDGE_ID);

    expect(ceremony.deadlineAt).toBe(91_000);
    expect(executing?.deadlineAt).toBe(91_000);
  });

  it('deduplicates the exact request but keeps a different live request in the document busy', async () => {
    const registry = makeRegistry();
    const first = await registry.begin(beginInput());
    const retry = await registry.begin(beginInput());
    const competing = await registry.begin(beginInput(getRequest({ challenge: 'Cg' })));
    const changedCandidates = await registry.begin(beginInput(getRequest(), {
      candidates: [{ kind: 'credential', id: 'credential-B', name: 'Other' }],
    }));

    expect(first.status).toBe('created');
    expect(retry.status).toBe('existing');
    if (first.status === 'created' && retry.status === 'existing') {
      expect(retry.ceremony.ceremonyId).toBe(first.ceremony.ceremonyId);
    }
    expect(competing).toEqual({ status: 'busy' });
    expect(changedCandidates).toEqual({ status: 'busy' });
  });

  it('promotes only the exact reserved locked-continuation id', async () => {
    const reserved = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    const other = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
    const registry = makeRegistry();
    const created = await registry.begin(beginInput(getRequest(), {
      requestedCeremonyId: reserved,
      requestedDeadlineAt: 20_000,
    }));
    expect(created).toMatchObject({
      status: 'created',
      ceremony: { ceremonyId: reserved, deadlineAt: 20_000 },
    });

    await expect(registry.begin(beginInput(getRequest(), {
      requestedCeremonyId: other,
      requestedDeadlineAt: 20_000,
    }))).rejects.toMatchObject({ code: 'id_collision' });
  });

  it('serializes concurrent capacity decisions across registries sharing one store', async () => {
    const store = createMemoryStore();
    const left = makeRegistry({ store, maxEntries: 1 });
    const right = makeRegistry({ store, maxEntries: 1 });
    const results = await Promise.all([
      left.begin(beginInput(getRequest(), { documentId: 'doc-A' })),
      right.begin(beginInput(getRequest({ bridgeRequestId: '33333333-3333-4333-8333-333333333333' }), {
        documentId: 'doc-B',
      })),
    ]);

    expect(results.map((result) => result.status).sort()).toEqual(['capacity', 'created']);
    expect(await left.listAwaitingApproval()).toHaveLength(1);
  });

  it('counts multi-byte UTF-8 input and rejects an oversized request without writing', async () => {
    const asciiCandidates = largeCandidates('target', 96, 'a'.repeat(4_096));
    const unicodeCandidates = largeCandidates('target', 96, '界'.repeat(4_096));
    expect(JSON.stringify(asciiCandidates)).toHaveLength(JSON.stringify(unicodeCandidates).length);
    expect(new TextEncoder().encode(JSON.stringify(unicodeCandidates)).byteLength)
      .toBeGreaterThan(new TextEncoder().encode(JSON.stringify(asciiCandidates)).byteLength);

    await expect(makeRegistry().begin(beginInput(createRequest(), {
      candidates: asciiCandidates,
    }))).resolves.toMatchObject({ status: 'created' });

    const base = createMemoryStore();
    const set = vi.fn((key: string, value: unknown) => base.set(key, value));
    const store: KeyValueStore = {
      get: <T>(key: string) => base.get<T>(key),
      set,
      remove: (key) => base.remove(key),
      clear: () => base.clear(),
    };
    const registry = makeRegistry({ store });
    const seed = await created(registry);
    await registry.markFallback(seed.ceremonyId, GET_BRIDGE_ID, 'no_match');
    const before = await base.get(PASSKEY_CEREMONY_STORAGE_KEY);
    set.mockClear();
    await expect(registry.begin(beginInput(createRequest(), {
      documentId: 'unicode-request',
      candidates: unicodeCandidates,
    }))).resolves.toEqual({ status: 'capacity' });
    expect(set).not.toHaveBeenCalled();
    expect(await base.get(PASSKEY_CEREMONY_STORAGE_KEY)).toEqual(before);
  });

  it('stops admitting descriptor-heavy ceremonies before the byte budget is exhausted', async () => {
    const store = createMemoryStore();
    const registry = makeRegistry({ store });
    const descriptors = maximumDescriptors();
    let admitted = 0;
    let stopped = false;
    for (let index = 1; index <= 16; index += 1) {
      const result = await registry.begin(beginInput(getRequest({
        bridgeRequestId: bridgeId(index),
        allowCredentials: descriptors,
      }), { documentId: `large-${index}` }));
      if (result.status === 'capacity') {
        stopped = true;
        break;
      }
      expect(result.status).toBe('created');
      admitted += 1;
    }

    expect(stopped).toBe(true);
    expect(admitted).toBeGreaterThan(1);
    expect(admitted).toBeLessThan(16);
    const envelope = await store.get(PASSKEY_CEREMONY_STORAGE_KEY);
    expect(persistedUtf8Bytes(envelope)
      + (admitted * PASSKEY_CEREMONY_TERMINAL_GROWTH_RESERVE_BYTES.get))
      .toBeLessThanOrEqual(PASSKEY_CEREMONY_ENVELOPE_UTF8_BYTE_BUDGET);
  });

  it('admits and settles sixteen ordinary get ceremonies with terminal headroom reserved', async () => {
    const store = createMemoryStore();
    const registry = makeRegistry({ store });
    const ceremonies = [];
    for (let index = 1; index <= 16; index += 1) {
      const result = await registry.begin(beginInput(getRequest({ bridgeRequestId: bridgeId(index) }), {
        documentId: `ordinary-${index}`,
      }));
      expect(result.status).toBe('created');
      if (result.status === 'created') ceremonies.push(result.ceremony);
    }

    const activeEnvelope = await store.get(PASSKEY_CEREMONY_STORAGE_KEY);
    expect(persistedUtf8Bytes(activeEnvelope)
      + (ceremonies.length * PASSKEY_CEREMONY_TERMINAL_GROWTH_RESERVE_BYTES.get))
      .toBeLessThanOrEqual(PASSKEY_CEREMONY_ENVELOPE_UTF8_BYTE_BUDGET);
    for (const ceremony of ceremonies) {
      const executing = await registry.claim(ceremony.ceremonyId, ceremony.request.bridgeRequestId);
      if (!executing) throw new Error('Expected execution');
      await expect(registry.complete(ceremony.ceremonyId, executing.executionId, assertion()))
        .resolves.toMatchObject({ state: 'completed' });
    }
    expect(await registry.listRedeliverable()).toHaveLength(16);
  });

  it('reserves enough growth for the largest canonical ES256 terminal results', async () => {
    const store = createMemoryStore();
    const registry = makeRegistry({ store });
    const ceremony = await created(registry, beginInput(createRequest()));
    const before = persistedUtf8Bytes(await store.get(PASSKEY_CEREMONY_STORAGE_KEY));
    const executing = await registry.claim(ceremony.ceremonyId, CREATE_BRIDGE_ID);
    if (!executing) throw new Error('Expected execution');

    await expect(registry.complete(
      ceremony.ceremonyId,
      executing.executionId,
      maximumRegistration(),
    )).resolves.toMatchObject({ state: 'completed' });
    const after = persistedUtf8Bytes(await store.get(PASSKEY_CEREMONY_STORAGE_KEY));
    expect(after - before).toBeLessThanOrEqual(
      PASSKEY_CEREMONY_TERMINAL_GROWTH_RESERVE_BYTES.create,
    );
    expect(after).toBeLessThanOrEqual(PASSKEY_CEREMONY_ENVELOPE_UTF8_BYTE_BUDGET);

    const assertionStore = createMemoryStore();
    const assertionRegistry = makeRegistry({ store: assertionStore });
    const assertionCeremony = await created(assertionRegistry);
    const assertionBefore = persistedUtf8Bytes(
      await assertionStore.get(PASSKEY_CEREMONY_STORAGE_KEY),
    );
    const assertionExecution = await assertionRegistry.claim(assertionCeremony.ceremonyId, GET_BRIDGE_ID);
    if (!assertionExecution) throw new Error('Expected execution');
    await expect(assertionRegistry.complete(
      assertionCeremony.ceremonyId,
      assertionExecution.executionId,
      maximumAssertion(),
    )).resolves.toMatchObject({ state: 'completed' });
    const assertionAfter = persistedUtf8Bytes(
      await assertionStore.get(PASSKEY_CEREMONY_STORAGE_KEY),
    );
    expect(assertionAfter - assertionBefore).toBeLessThanOrEqual(
      PASSKEY_CEREMONY_TERMINAL_GROWTH_RESERVE_BYTES.get,
    );
  });

  it('hard-fails an unreserved terminal write without touching the executing record', async () => {
    const fallbackStore = createMemoryStore();
    const fallbackRegistry = makeRegistry({ store: fallbackStore, createId: idFactory(100) });
    const fallback = await fallbackRegistry.begin(beginInput({
      ...getRequest({ bridgeRequestId: bridgeId(901) }),
      mediation: 'silent',
    } as unknown as CanonicalWebsitePasskeyGetRequest, {
      documentId: 'large-fallback',
      candidates: largeCandidates('credential', 128, '界'.repeat(3_800)),
    }));
    expect(fallback.status).toBe('fallback');
    if (fallback.status !== 'fallback') return;

    const executionStore = createMemoryStore();
    const executionRegistry = makeRegistry({ store: executionStore, createId: idFactory(200) });
    const ceremony = await created(executionRegistry, beginInput(createRequest({
      bridgeRequestId: bridgeId(902),
    }), { documentId: 'executing-create' }));
    const executing = await executionRegistry.claim(ceremony.ceremonyId, bridgeId(902));
    if (!executing) throw new Error('Expected execution');

    const fallbackEnvelope = await fallbackStore.get<{ entries: unknown[] }>(PASSKEY_CEREMONY_STORAGE_KEY);
    const executionEnvelope = await executionStore.get<{ entries: unknown[] }>(PASSKEY_CEREMONY_STORAGE_KEY);
    if (!fallbackEnvelope || !executionEnvelope) throw new Error('Expected durable fixtures');
    const combined = {
      schemaVersion: PASSKEY_CEREMONY_SCHEMA_VERSION,
      entries: [...fallbackEnvelope.entries, ...executionEnvelope.entries],
    };
    expect(persistedUtf8Bytes(combined)).toBeLessThan(PASSKEY_CEREMONY_ENVELOPE_UTF8_BYTE_BUDGET);

    const base = createMemoryStore();
    await base.set(PASSKEY_CEREMONY_STORAGE_KEY, combined);
    const set = vi.fn((key: string, value: unknown) => base.set(key, value));
    const store: KeyValueStore = {
      get: <T>(key: string) => base.get<T>(key),
      set,
      remove: (key) => base.remove(key),
      clear: () => base.clear(),
    };
    const registry = makeRegistry({ store, createId: idFactory(300) });
    await expect(registry.complete(
      ceremony.ceremonyId,
      executing.executionId,
      maximumRegistration(),
    )).rejects.toMatchObject({ code: 'storage_capacity' });
    expect(set).not.toHaveBeenCalled();
    const unchanged = await base.get<{ entries: Array<{ ceremonyId: string; state: string }> }>(
      PASSKEY_CEREMONY_STORAGE_KEY,
    );
    expect(unchanged?.entries.find((entry) => entry.ceremonyId === ceremony.ceremonyId)?.state)
      .toBe('executing');
  });

  it('claims once with exact bridge binding and refuses stale execution tokens', async () => {
    const registry = makeRegistry();
    const ceremony = await created(registry);
    expect(await registry.claim(ceremony.ceremonyId, CREATE_BRIDGE_ID)).toBeUndefined();
    const [left, right] = await Promise.all([
      registry.claim(ceremony.ceremonyId, GET_BRIDGE_ID),
      registry.claim(ceremony.ceremonyId, GET_BRIDGE_ID),
    ]);
    const executing = left ?? right;

    expect([left, right].filter(Boolean)).toHaveLength(1);
    expect(executing).toMatchObject({ state: 'executing', startedAt: 1_000 });
    expect(await registry.complete(
      ceremony.ceremonyId,
      '99999999-9999-4999-8999-999999999999',
      assertion(),
    )).toBeUndefined();
    expect((await registry.get(ceremony.ceremonyId))?.state).toBe('executing');
  });

  it('persists completion for restart redelivery and requires the full ACK binding', async () => {
    const store = createMemoryStore();
    const registry = makeRegistry({ store });
    const ceremony = await created(registry);
    const executing = await registry.claim(ceremony.ceremonyId, GET_BRIDGE_ID);
    if (!executing) throw new Error('Expected execution');

    const completed = await registry.complete(ceremony.ceremonyId, executing.executionId, assertion());
    if (!completed) throw new Error('Expected completion');
    const restarted = makeRegistry({ store, createId: idFactory() });
    expect((await restarted.recoverStartup()).redeliverable).toEqual([
      expect.objectContaining({ ceremonyId: ceremony.ceremonyId, state: 'completed' }),
    ]);
    expect(await restarted.acknowledge(ceremony.ceremonyId, CREATE_BRIDGE_ID, completed.outcomeId)).toBe(false);
    expect(await restarted.acknowledge(
      ceremony.ceremonyId,
      GET_BRIDGE_ID,
      '99999999-9999-4999-8999-999999999999',
    )).toBe(false);
    expect(await restarted.acknowledge(ceremony.ceremonyId, GET_BRIDGE_ID, completed.outcomeId)).toBe(true);
    expect(await restarted.listRedeliverable()).toEqual([]);
  });

  it('durably falls back an awaiting request and will not claim it afterward', async () => {
    const registry = makeRegistry();
    const ceremony = await created(registry);

    expect(await registry.markFallback(ceremony.ceremonyId, CREATE_BRIDGE_ID, 'unsupported'))
      .toBeUndefined();
    expect(await registry.markFallback(ceremony.ceremonyId, GET_BRIDGE_ID, 'unsupported'))
      .toMatchObject({ state: 'fallback', reason: 'unsupported' });
    expect(await registry.claim(ceremony.ceremonyId, GET_BRIDGE_ID)).toBeUndefined();
  });

  it.each([
    'account_changed',
    'cache_changed',
    'capacity',
    'cancelled',
    'context_changed',
    'expired',
    'feature_disabled',
    'session_changed',
    'vault_locked',
    'worker_restart',
  ])('clears a legacy durable fallback carrying error reason %s', async (reason) => {
    const store = createMemoryStore();
    const registry = makeRegistry({ store });
    const ceremony = await created(registry);
    await registry.markFallback(ceremony.ceremonyId, GET_BRIDGE_ID, 'no_match');
    const envelope = await store.get<{ entries: Array<Record<string, unknown>> }>(
      PASSKEY_CEREMONY_STORAGE_KEY,
    );
    if (!envelope?.entries[0]) throw new Error('Expected fallback entry');
    envelope.entries[0].reason = reason;
    await store.set(PASSKEY_CEREMONY_STORAGE_KEY, envelope);

    expect(await registry.listRedeliverable()).toEqual([]);
    expect(await store.get(PASSKEY_CEREMONY_STORAGE_KEY)).toEqual({
      schemaVersion: PASSKEY_CEREMONY_SCHEMA_VERSION,
      entries: [],
    });
  });

  it.each(['cancelled', 'capacity'])('rejects %s at the runtime fallback boundary', async (reason) => {
    const registry = makeRegistry();
    const ceremony = await created(registry);
    await expect(registry.markFallback(
      ceremony.ceremonyId,
      GET_BRIDGE_ID,
      reason as never,
    )).rejects.toMatchObject({ code: 'invalid_input' });
    expect((await registry.get(ceremony.ceremonyId))?.state).toBe('awaitingApproval');
  });

  it('atomically maps abort by execution risk without inventing a pre-execution execution id', async () => {
    const store = createMemoryStore();
    const registry = makeRegistry({ store });
    const awaiting = await created(registry, beginInput(getRequest(), { documentId: 'awaiting' }));
    const getBase = await created(registry, beginInput(getRequest({
      bridgeRequestId: '33333333-3333-4333-8333-333333333333',
    }), { documentId: 'get' }));
    const createBase = await created(registry, beginInput(createRequest(), { documentId: 'create' }));
    await registry.claim(getBase.ceremonyId, getBase.request.bridgeRequestId);
    await registry.claim(createBase.ceremonyId, CREATE_BRIDGE_ID);

    const awaitingAbort = await registry.abort(awaiting.ceremonyId, GET_BRIDGE_ID);
    expect(awaitingAbort).toMatchObject({ state: 'failed', reason: 'cancelled' });
    expect(awaitingAbort).not.toHaveProperty('executionId');
    expect(await registry.abort(getBase.ceremonyId, getBase.request.bridgeRequestId))
      .toMatchObject({ state: 'failed', reason: 'cancelled' });
    expect(await registry.abort(createBase.ceremonyId, CREATE_BRIDGE_ID))
      .toMatchObject({ state: 'uncertain', reason: 'context_changed' });
    const restarted = makeRegistry({ store });
    const restoredAbort = await restarted.get(awaiting.ceremonyId);
    expect(restoredAbort).toMatchObject({ state: 'failed', reason: 'cancelled' });
    expect(restoredAbort).not.toHaveProperty('executionId');
  });

  it('atomically maps browser document invalidation by execution risk', async () => {
    const registry = makeRegistry();
    const awaiting = await created(registry, beginInput(getRequest(), {
      frameId: 1,
      documentId: 'awaiting-frame',
    }));
    const getBase = await created(registry, beginInput(getRequest({
      bridgeRequestId: '33333333-3333-4333-8333-333333333333',
    }), { frameId: 2, documentId: 'executing-get-frame' }));
    const createBase = await created(registry, beginInput(createRequest(), {
      frameId: 3,
      documentId: 'executing-create-frame',
    }));
    await registry.claim(getBase.ceremonyId, getBase.request.bridgeRequestId);
    await registry.claim(createBase.ceremonyId, CREATE_BRIDGE_ID);

    expect(await registry.invalidateContext(awaiting.ceremonyId))
      .toMatchObject({ state: 'failed', reason: 'context_changed', frameId: 1 });
    expect(await registry.invalidateContext(getBase.ceremonyId))
      .toMatchObject({ state: 'failed', reason: 'context_changed', frameId: 2 });
    expect(await registry.invalidateContext(createBase.ceremonyId))
      .toMatchObject({ state: 'uncertain', reason: 'context_changed', frameId: 3 });
  });

  it('never records an executing get as uncertain through the public transition', async () => {
    const registry = makeRegistry();
    const ceremony = await created(registry);
    const executing = await registry.claim(ceremony.ceremonyId, GET_BRIDGE_ID);
    if (!executing) throw new Error('Expected execution');

    expect(await registry.markUncertain(ceremony.ceremonyId, executing.executionId))
      .toMatchObject({ state: 'failed', reason: 'delivery_failed' });
  });

  it('maps deadline expiry by execution risk and prevents a late settlement', async () => {
    let now = 1_000;
    const registry = makeRegistry({ now: () => now, ttlMs: 100 });
    const awaiting = await created(registry, beginInput(getRequest(), { documentId: 'awaiting' }));
    const getBase = await created(registry, beginInput(getRequest({
      bridgeRequestId: '33333333-3333-4333-8333-333333333333',
    }), { documentId: 'get' }));
    const createBase = await created(registry, beginInput(createRequest(), { documentId: 'create' }));
    const getExecution = await registry.claim(getBase.ceremonyId, getBase.request.bridgeRequestId);
    const createExecution = await registry.claim(createBase.ceremonyId, CREATE_BRIDGE_ID);
    if (!getExecution || !createExecution) throw new Error('Expected executions');

    now = 1_101;
    expect(await registry.get(awaiting.ceremonyId))
      .toMatchObject({ state: 'failed', reason: 'expired' });
    expect(await registry.get(getBase.ceremonyId))
      .toMatchObject({ state: 'failed', reason: 'expired' });
    expect(await registry.get(createBase.ceremonyId))
      .toMatchObject({ state: 'uncertain', reason: 'expired' });
    expect(await registry.complete(getBase.ceremonyId, getExecution.executionId, assertion()))
      .toBeUndefined();
    expect(await registry.complete(createBase.ceremonyId, createExecution.executionId, registration()))
      .toBeUndefined();
  });

  it('recovers awaiting and executing get as failed, and executing create as uncertain', async () => {
    const store = createMemoryStore();
    const registry = makeRegistry({ store });
    const awaiting = await created(registry, beginInput(getRequest(), { documentId: 'awaiting' }));
    const getBase = await created(registry, beginInput(getRequest({
      bridgeRequestId: '33333333-3333-4333-8333-333333333333',
    }), { documentId: 'get' }));
    const createBase = await created(registry, beginInput(createRequest(), { documentId: 'create' }));
    await registry.claim(getBase.ceremonyId, getBase.request.bridgeRequestId);
    await registry.claim(createBase.ceremonyId, CREATE_BRIDGE_ID);

    const recovery = await makeRegistry({ store, createId: idFactory() }).recoverStartup();

    expect(recovery.redeliverable).toEqual(expect.arrayContaining([
      expect.objectContaining({ ceremonyId: awaiting.ceremonyId, state: 'failed', reason: 'worker_restart' }),
      expect.objectContaining({ ceremonyId: getBase.ceremonyId, state: 'failed', reason: 'worker_restart' }),
      expect.objectContaining({ ceremonyId: createBase.ceremonyId, state: 'uncertain', reason: 'worker_restart' }),
    ]));
    const allIds = recovery.redeliverable.flatMap((entry) => {
      const ids = [entry.ceremonyId, entry.outcomeId];
      return 'executionId' in entry ? [...ids, entry.executionId] : ids;
    });
    expect(new Set(allIds).size).toBe(allIds.length);
  });

  it('retains exact subframe identity while failing an awaiting ceremony on worker restart', async () => {
    const store = createMemoryStore();
    const first = makeRegistry({ store });
    const ceremony = await created(first, beginInput(getRequest(), {
      frameId: 8,
      documentId: 'worker-restart-frame',
      frameUrl: 'https://login.example.com/frame',
    }));

    const restarted = makeRegistry({ store, createId: idFactory() });
    const recovery = await restarted.recoverStartup();

    expect(recovery.redeliverable).toEqual([
      expect.objectContaining({
        ceremonyId: ceremony.ceremonyId,
        frameId: 8,
        documentId: 'worker-restart-frame',
        state: 'failed',
        reason: 'worker_restart',
      }),
    ]);
  });

  it('retains an early completed create through its original deadline plus delivery grace', async () => {
    let now = 1_000;
    const registry = makeRegistry({ now: () => now, ttlMs: 600_000 });
    const input = beginInput(createRequest());
    const ceremony = await created(registry, input);
    const executing = await registry.claim(ceremony.ceremonyId, CREATE_BRIDGE_ID);
    if (!executing) throw new Error('Expected execution');
    const completed = await registry.complete(ceremony.ceremonyId, executing.executionId, registration());
    if (!completed) throw new Error('Expected completion');

    expect(DEFAULT_PASSKEY_CEREMONY_TERMINAL_TTL_MS).toBe(120_000);
    expect(completed).toMatchObject({ deadlineAt: 181_000, terminalAt: 1_000, retireAt: 301_000 });

    now = 31_001;
    const retry = await registry.begin(input);
    expect(retry).toMatchObject({
      status: 'existing',
      ceremony: { ceremonyId: ceremony.ceremonyId, state: 'completed' },
    });
    expect(await registry.listRedeliverable()).toHaveLength(1);

    now = 300_999;
    expect(await registry.listRedeliverable()).toHaveLength(1);
    now = 301_000;
    expect(await registry.listRedeliverable()).toEqual([]);
    expect(await registry.begin(input)).toMatchObject({ status: 'created' });
  });

  it('applies the same deadline-based grace to create uncertainty and fallback', async () => {
    let now = 1_000;
    const registry = makeRegistry({ now: () => now, ttlMs: 600_000 });
    const createBase = await created(registry, beginInput(createRequest(), { documentId: 'create' }));
    const createExecution = await registry.claim(createBase.ceremonyId, CREATE_BRIDGE_ID);
    if (!createExecution) throw new Error('Expected execution');
    const uncertain = await registry.markUncertain(createBase.ceremonyId, createExecution.executionId);

    const fallbackBridge = '33333333-3333-4333-8333-333333333333';
    const fallbackBase = await created(registry, beginInput(getRequest({
      bridgeRequestId: fallbackBridge,
      timeout: 180_000,
    }), { documentId: 'fallback' }));
    const fallback = await registry.markFallback(fallbackBase.ceremonyId, fallbackBridge, 'no_match');

    expect(uncertain).toMatchObject({ deadlineAt: 181_000, terminalAt: 1_000, retireAt: 301_000 });
    expect(fallback).toMatchObject({ deadlineAt: 181_000, terminalAt: 1_000, retireAt: 301_000 });

    now = 31_001;
    expect(await registry.listRedeliverable()).toHaveLength(2);
    now = 300_999;
    expect(await registry.listRedeliverable()).toHaveLength(2);
    now = 301_000;
    expect(await registry.listRedeliverable()).toEqual([]);
  });

  it.each([
    { schemaVersion: 1, entries: [] },
    { schemaVersion: 99, entries: [] },
    { schemaVersion: PASSKEY_CEREMONY_SCHEMA_VERSION, entries: 'not-an-array' },
    { schemaVersion: PASSKEY_CEREMONY_SCHEMA_VERSION, entries: new Array(129).fill({}) },
  ])('clears legacy, future, malformed, and oversized durable envelopes %#', async (stored) => {
    const store = createMemoryStore();
    await store.set(PASSKEY_CEREMONY_STORAGE_KEY, stored);
    const registry = makeRegistry({ store });

    await expect(registry.recoverStartup()).resolves.toEqual({ redeliverable: [] });
    expect(await store.get(PASSKEY_CEREMONY_STORAGE_KEY)).toEqual({
      schemaVersion: PASSKEY_CEREMONY_SCHEMA_VERSION,
      entries: [],
    });
  });

  it('clears a tampered request digest or deadline instead of reviving the request', async () => {
    const store = createMemoryStore();
    const registry = makeRegistry({ store, ttlMs: 100_000 });
    await created(registry);
    const envelope = await store.get<{ entries: Array<Record<string, unknown>> }>(
      PASSKEY_CEREMONY_STORAGE_KEY,
    );
    if (!envelope) throw new Error('Expected envelope');
    const entry = envelope.entries[0];
    if (!entry) throw new Error('Expected entry');
    entry.deadlineAt = 101_001;
    await store.set(PASSKEY_CEREMONY_STORAGE_KEY, envelope);

    expect(await registry.listAwaitingApproval()).toEqual([]);
    expect(await store.get(PASSKEY_CEREMONY_STORAGE_KEY)).toEqual({
      schemaVersion: PASSKEY_CEREMONY_SCHEMA_VERSION,
      entries: [],
    });

    await created(registry, beginInput(getRequest({
      bridgeRequestId: '33333333-3333-4333-8333-333333333333',
    }), { documentId: 'doc-B' }));
    const second = await store.get<{ entries: Array<Record<string, unknown>> }>(
      PASSKEY_CEREMONY_STORAGE_KEY,
    );
    if (!second?.entries[0]) throw new Error('Expected second entry');
    const request = second.entries[0].request as Record<string, unknown>;
    request.challenge = 'Cg';
    await store.set(PASSKEY_CEREMONY_STORAGE_KEY, second);

    expect(await registry.listAwaitingApproval()).toEqual([]);
  });

  it('rejects accessors without invoking them in caller or durable state', async () => {
    let inputGetterInvoked = false;
    const request = getRequest() as unknown as Record<string, unknown>;
    Object.defineProperty(request, 'secret', {
      enumerable: true,
      get() {
        inputGetterInvoked = true;
        return 'secret';
      },
    });
    await expect(makeRegistry().begin(beginInput(
      request as unknown as CanonicalWebsitePasskeyGetRequest,
    ))).rejects.toMatchObject({ code: 'invalid_input' });
    expect(inputGetterInvoked).toBe(false);

    let storedGetterInvoked = false;
    const envelope = Object.defineProperty(
      { schemaVersion: PASSKEY_CEREMONY_SCHEMA_VERSION },
      'entries',
      {
        enumerable: true,
        get() {
          storedGetterInvoked = true;
          return [];
        },
      },
    );
    let stored: unknown = envelope;
    const store: KeyValueStore = {
      async get<T>() { return stored as T; },
      async set(_key, value) { stored = value; },
      async remove() { stored = undefined; },
      async clear() { stored = undefined; },
    };

    expect(await makeRegistry({ store }).listAwaitingApproval()).toEqual([]);
    expect(storedGetterInvoked).toBe(false);
  });

  it('deep-copies input, persists subframe identity, and rejects malformed shapes or result kinds', async () => {
    const rawRequest = getRequest() as {
      allowCredentials: Array<{ id: string; type: 'public-key'; transports: string[] }>;
      challenge: string;
    } & CanonicalWebsitePasskeyGetRequest;
    const registry = makeRegistry();
    const ceremony = await created(registry, beginInput(rawRequest));
    rawRequest.challenge = 'Cg';
    rawRequest.allowCredentials[0]!.id = 'DA';
    expect((await registry.get(ceremony.ceremonyId))?.request).toEqual(getRequest());

    await expect(registry.begin({
      ...beginInput(getRequest({ bridgeRequestId: '33333333-3333-4333-8333-333333333333' })),
      token: 'forbidden',
    } as unknown as BeginPasskeyCeremonyInput)).rejects.toMatchObject({ code: 'invalid_input' });
    const iframe = await created(registry, beginInput(getRequest({
      bridgeRequestId: '44444444-4444-4444-8444-444444444444',
    }), { frameId: 1, documentId: 'iframe-document' }));
    expect(iframe).toMatchObject({ frameId: 1, documentId: 'iframe-document' });

    const sparse = new Array(1) as BeginPasskeyCeremonyInput['candidates'];
    await expect(registry.begin(beginInput(getRequest({
      bridgeRequestId: '55555555-5555-4555-8555-555555555555',
    }), { documentId: 'sparse', candidates: sparse })))
      .rejects.toMatchObject({ code: 'invalid_input' });

    const executing = await registry.claim(ceremony.ceremonyId, GET_BRIDGE_ID);
    if (!executing) throw new Error('Expected execution');
    await expect(registry.complete(ceremony.ceremonyId, executing.executionId, registration()))
      .rejects.toMatchObject({ code: 'invalid_input' });
    expect((await registry.get(ceremony.ceremonyId))?.state).toBe('executing');
  });

  it('does not report completion when the terminal write fails', async () => {
    const base = createMemoryStore();
    let rejectWrites = false;
    const store: KeyValueStore = {
      get: <T>(key: string) => base.get<T>(key),
      set: async (key, value) => {
        if (rejectWrites && JSON.stringify(value).includes('"state":"completed"')) {
          throw new Error('storage unavailable');
        }
        await base.set(key, value);
      },
      remove: (key) => base.remove(key),
      clear: () => base.clear(),
    };
    const registry = makeRegistry({ store });
    const ceremony = await created(registry);
    const executing = await registry.claim(ceremony.ceremonyId, GET_BRIDGE_ID);
    if (!executing) throw new Error('Expected execution');

    rejectWrites = true;
    await expect(registry.complete(ceremony.ceremonyId, executing.executionId, assertion()))
      .rejects.toThrow('storage unavailable');
    rejectWrites = false;
    expect((await makeRegistry({ store }).get(ceremony.ceremonyId))?.state).toBe('executing');
  });

  it('binds create credProps output to whether the extension was requested', async () => {
    const requested = makeRegistry();
    const requestedBase = await created(requested, beginInput(createRequest()));
    const requestedExecution = await requested.claim(requestedBase.ceremonyId, CREATE_BRIDGE_ID);
    if (!requestedExecution) throw new Error('Expected execution');
    await expect(requested.complete(
      requestedBase.ceremonyId,
      requestedExecution.executionId,
      registration({ credProps: null }),
    )).rejects.toMatchObject({ code: 'invalid_input' });

    const omitted = makeRegistry();
    const omittedRequest = createRequest({ extensions: { credProps: false } });
    const omittedBase = await created(omitted, beginInput(omittedRequest));
    const omittedExecution = await omitted.claim(omittedBase.ceremonyId, CREATE_BRIDGE_ID);
    if (!omittedExecution) throw new Error('Expected execution');
    await expect(omitted.complete(
      omittedBase.ceremonyId,
      omittedExecution.executionId,
      registration(),
    )).rejects.toMatchObject({ code: 'invalid_input' });
    expect(await omitted.complete(
      omittedBase.ceremonyId,
      omittedExecution.executionId,
      registration({ credProps: null }),
    )).toMatchObject({ state: 'completed', result: { credProps: null } });
  });

  it('validates RP ID against the browser-owned origin and accepts supported loopback context', async () => {
    await expect(makeRegistry().begin(beginInput(getRequest({ rpId: 'github.io' }), {
      frameUrl: 'https://a.github.io/',
      origin: 'https://a.github.io',
    }))).rejects.toMatchObject({ code: 'invalid_input' });
    await expect(makeRegistry().begin(beginInput(getRequest({ rpId: 'evil.example' }))))
      .rejects.toMatchObject({ code: 'invalid_input' });
    await expect(makeRegistry().begin(beginInput(getRequest({ rpId: 'localhost' }), {
      frameUrl: 'http://localhost/path',
      origin: 'http://localhost',
    }))).resolves.toMatchObject({ status: 'created' });
    await expect(makeRegistry().begin(beginInput(getRequest({ rpId: '127.0.0.1' }), {
      frameUrl: 'http://127.0.0.1:43123/path',
      origin: 'http://127.0.0.1:43123',
    }))).resolves.toMatchObject({ status: 'created' });
    await expect(makeRegistry().begin(beginInput(getRequest(), { policyGeneration: -1 })))
      .rejects.toMatchObject({ code: 'invalid_input' });
  });

  it('clears a durable envelope with duplicate active documents or an extended terminal lease', async () => {
    const activeStore = createMemoryStore();
    const activeRegistry = makeRegistry({ store: activeStore });
    await created(activeRegistry, beginInput(getRequest(), { documentId: 'doc-A' }));
    await created(activeRegistry, beginInput(getRequest({
      bridgeRequestId: '33333333-3333-4333-8333-333333333333',
    }), { documentId: 'doc-B' }));
    const activeEnvelope = await activeStore.get<{ entries: Array<Record<string, unknown>> }>(
      PASSKEY_CEREMONY_STORAGE_KEY,
    );
    if (!activeEnvelope?.entries[1]) throw new Error('Expected active entries');
    activeEnvelope.entries[1].documentId = 'doc-A';
    await activeStore.set(PASSKEY_CEREMONY_STORAGE_KEY, activeEnvelope);
    expect(await activeRegistry.listAwaitingApproval()).toEqual([]);

    for (const corruptRetireAt of [121_000, 121_001, 121_101]) {
      const terminalStore = createMemoryStore();
      const terminalRegistry = makeRegistry({ store: terminalStore, terminalTtlMs: 100 });
      const ceremony = await created(terminalRegistry);
      await terminalRegistry.markFallback(ceremony.ceremonyId, GET_BRIDGE_ID, 'no_match');
      const terminalEnvelope = await terminalStore.get<{ entries: Array<Record<string, unknown>> }>(
        PASSKEY_CEREMONY_STORAGE_KEY,
      );
      if (!terminalEnvelope?.entries[0]) throw new Error('Expected terminal entry');
      terminalEnvelope.entries[0].retireAt = corruptRetireAt;
      await terminalStore.set(PASSKEY_CEREMONY_STORAGE_KEY, terminalEnvelope);
      expect(await terminalRegistry.listRedeliverable()).toEqual([]);
    }
  });

  it('rejects a terminal transition whose deadline-based grace would overflow safe time', async () => {
    const now = Number.MAX_SAFE_INTEGER - 200_000;
    const registry = makeRegistry({ now: () => now });
    const ceremony = await created(registry);
    const executing = await registry.claim(ceremony.ceremonyId, GET_BRIDGE_ID);
    if (!executing) throw new Error('Expected execution');

    await expect(registry.complete(ceremony.ceremonyId, executing.executionId, assertion()))
      .rejects.toMatchObject({ code: 'invalid_configuration' });
    expect((await registry.get(ceremony.ceremonyId))?.state).toBe('executing');
  });

  it('persists a canonical terminal record for a recognized unsupported request', async () => {
    const store = createMemoryStore();
    const rawRequest = { ...getRequest(), mediation: 'silent' };
    const registry = makeRegistry({ store });

    const result = await registry.begin(beginInput(
      rawRequest as unknown as CanonicalWebsitePasskeyGetRequest,
    ));

    expect(result.status).toBe('fallback');
    if (result.status !== 'fallback') return;
    expect(result).toMatchObject({ reason: 'silent_mediation', bridgeRequestId: GET_BRIDGE_ID });
    expect(result.ceremony.request.kind).toBe('get');
    if (result.ceremony.request.kind !== 'get') return;
    expect(result.ceremony.request.mediation).toBe('optional');
    expect(result.ceremony).not.toHaveProperty('unsupportedReason');
    const restarted = makeRegistry({ store, createId: idFactory() });
    expect(await restarted.listRedeliverable()).toEqual([
      expect.objectContaining({
        ceremonyId: result.ceremony.ceremonyId,
        state: 'fallback',
        reason: 'unsupported',
      }),
    ]);
    expect(await restarted.acknowledge(
      result.ceremony.ceremonyId,
      GET_BRIDGE_ID,
      result.ceremony.outcomeId,
    )).toBe(true);
  });
});
