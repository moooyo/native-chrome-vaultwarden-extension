import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
      session: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
    },
  },
}));

import { createMemoryStore } from '../platform/store.js';
import {
  SSO_BROWSER_STATE_SUFFIX,
  generateSsoState,
} from '../core/session/sso-login.js';
import {
  SSO_ATTEMPT_MAX_UTF8_BYTES,
  SSO_ATTEMPT_SCHEMA_VERSION,
  SSO_ATTEMPT_STORAGE_KEY,
  SSO_ATTEMPT_TTL_MS,
  SSO_OUTCOME_UNKNOWN_TTL_MS,
  SsoAttemptStore,
} from './sso-attempt-store.js';

const SERVER = 'https://server.example/base/';
const IDENTITY = 'https://identity.example/tenant/identity/';
const EMAIL = 'user@example.com';
const CONNECTOR_ORIGIN = 'https://vault.example';
const CONNECTOR_PATH = '/tenant/sso-connector.html';
const REDIRECT_URI = `${CONNECTOR_ORIGIN}${CONNECTOR_PATH}`;
const STATE = `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA${SSO_BROWSER_STATE_SUFFIX}`;
const OTHER_STATE = generateSsoState(() => new Uint8Array(32).fill(1));
const VERIFIER = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const ATTEMPT_A = '11111111-1111-4111-8111-111111111111';
const ATTEMPT_B = '22222222-2222-4222-8222-222222222222';
const WORKER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const WORKER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const SOURCE = Object.freeze({
  popupDocumentId: 'popup-document',
  windowId: 7,
  document: Object.freeze({
    tabId: 8,
    windowId: 7,
    documentId: 'source-document',
    url: 'https://app.example/login',
  }),
});

function attemptInput() {
  return {
    serverUrl: SERVER,
    identityUrl: IDENTITY,
    serverGeneration: 7,
    capabilityGeneration: 11,
    emailIntent: EMAIL,
    tabId: 42,
    connectorOrigin: CONNECTOR_ORIGIN,
    connectorPath: CONNECTOR_PATH,
    state: STATE,
    verifier: VERIFIER,
    redirectUri: REDIRECT_URI,
    emailTwoFactorMode: 'vaultwarden-device' as const,
    source: SOURCE,
  };
}

function callbackUrl(
  state = STATE,
  code = 'opaque-code_123',
  extras = '',
): string {
  return `${REDIRECT_URI}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}${extras}`;
}

describe('SsoAttemptStore', () => {
  it('creates one canonical five-minute attempt and restores it across a worker restart', async () => {
    const storage = createMemoryStore();
    const first = makeStore(storage, { now: () => 1_000 });
    const waiting = await first.create({
      ...attemptInput(),
      serverUrl: 'https://SERVER.example/base',
      identityUrl: 'https://IDENTITY.example/tenant/identity',
      emailIntent: ' User@Example.COM ',
    });

    expect(waiting).toMatchObject({
      status: 'waiting',
      owner: {
        generation: 1,
        attemptGeneration: 1,
        attemptId: ATTEMPT_A,
        serverUrl: SERVER,
        identityUrl: IDENTITY,
        serverGeneration: 7,
        capabilityGeneration: 11,
        emailIntent: EMAIL,
      },
      tabId: 42,
      connectorOrigin: CONNECTOR_ORIGIN,
      connectorPath: CONNECTOR_PATH,
      state: STATE,
      verifier: VERIFIER,
      redirectUri: REDIRECT_URI,
      emailTwoFactorMode: 'vaultwarden-device',
      createdAt: 1_000,
      expiresAt: 1_000 + SSO_ATTEMPT_TTL_MS,
    });
    expect(waiting).not.toHaveProperty('callbackDocumentId');

    const restarted = makeStore(storage, {
      now: () => 2_000,
      workerId: WORKER_B,
      createAttemptId: () => ATTEMPT_B,
    });
    await expect(restarted.read()).resolves.toEqual(waiting);
  });

  it('serializes concurrent creators so only one active attempt wins', async () => {
    const storage = createMemoryStore();
    const first = makeStore(storage, { createAttemptId: () => ATTEMPT_A });
    const second = makeStore(storage, {
      workerId: WORKER_B,
      createAttemptId: () => ATTEMPT_B,
    });

    const results = await Promise.allSettled([
      first.create(attemptInput()),
      second.create(attemptInput()),
    ]);

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
    expect(results.find((result) => result.status === 'rejected')).toMatchObject({
      reason: { code: 'busy' },
    });
  });

  it('lets only waiting cancellation or callback claim win', async () => {
    const storage = createMemoryStore();
    const store = makeStore(storage);
    const waiting = await store.create(attemptInput());
    const bound = await store.bindCallbackDocument(waiting.owner, {
      tabId: 42,
      documentId: 'document-a',
      callbackUrl: callbackUrl(),
    });

    const [cancelled, claimed] = await Promise.all([
      store.cancelWaiting(bound!.attempt.owner),
      store.claim(bound!.attempt.owner),
    ]);
    expect([cancelled, claimed !== undefined].filter(Boolean)).toHaveLength(1);
  });

  it('atomically binds one exact callback document, then claims that generation once', async () => {
    const storage = createMemoryStore();
    const store = makeStore(storage);
    const waiting = await store.create(attemptInput());
    const bound = await store.bindCallbackDocument(waiting.owner, {
      tabId: 42,
      documentId: 'document-a',
      callbackUrl: callbackUrl(
        STATE,
        'opaque-code_123',
        '&scope=api+offline_access&iss=https%3A%2F%2Fidentity.example%2Ftenant%2Fidentity%2F',
      ),
    });

    expect(bound).toMatchObject({
      code: 'opaque-code_123',
      state: STATE,
      scope: 'api offline_access',
      iss: IDENTITY,
      scrubbedUrl: REDIRECT_URI,
      attempt: {
        status: 'waiting',
        owner: { generation: 2, attemptId: ATTEMPT_A },
        callbackDocumentId: 'document-a',
      },
    });
    const rawAfterBind = JSON.stringify(await storage.get(SSO_ATTEMPT_STORAGE_KEY));
    expect(rawAfterBind).not.toContain('opaque-code_123');
    const rebound = await store.bindCallbackDocument(bound!.attempt.owner, {
      tabId: 42,
      documentId: 'document-a',
      callbackUrl: callbackUrl(),
    });
    expect(rebound?.attempt.owner).toEqual(bound!.attempt.owner);
    await expect(store.bindCallbackDocument(waiting.owner, {
      tabId: 42,
      documentId: 'document-b',
      callbackUrl: callbackUrl(),
    })).resolves.toBeUndefined();

    const [claimed, replay] = await Promise.all([
      store.claim(bound!.attempt.owner),
      store.claim(bound!.attempt.owner),
    ]);
    expect(claimed).toMatchObject({
      status: 'claimed',
      owner: { generation: 3 },
      callbackDocumentId: 'document-a',
      workerId: WORKER_A,
    });
    expect(replay).toBeUndefined();
    expect(await store.clear(bound!.attempt.owner)).toBe(false);
  });

  it('refuses a wrong tab or callback state without binding the attempt', async () => {
    const storage = createMemoryStore();
    const store = makeStore(storage);
    const waiting = await store.create(attemptInput());

    await expect(store.bindCallbackDocument(waiting.owner, {
      tabId: 43,
      documentId: 'document-a',
      callbackUrl: callbackUrl(),
    })).resolves.toBeUndefined();
    await expect(store.bindCallbackDocument(waiting.owner, {
      tabId: 42,
      documentId: 'document-a',
      callbackUrl: callbackUrl(OTHER_STATE),
    })).rejects.toThrow(/state/u);
    await expect(store.read()).resolves.toEqual(waiting);
  });

  it('binds a callback organization identifier without rejecting Vaultwarden omission', async () => {
    const storage = createMemoryStore();
    const store = makeStore(storage);
    const expected = await store.create({
      ...attemptInput(),
      organizationIdentifier: 'expected-org',
    });

    await expect(store.bindCallbackDocument(expected.owner, {
      tabId: 42,
      documentId: 'document-a',
      callbackUrl: callbackUrl(`${STATE}_identifier=other-org`),
    })).rejects.toThrow(/organization identifier/);
    const withoutSuffix = await store.bindCallbackDocument(expected.owner, {
      tabId: 42,
      documentId: 'document-a',
      callbackUrl: callbackUrl(),
    });
    expect(withoutSuffix?.attempt.organizationIdentifier).toBe('expected-org');

    await store.clear(withoutSuffix!.attempt.owner);
    const discovered = await store.create(attemptInput());
    const withSuffix = await store.bindCallbackDocument(discovered.owner, {
      tabId: 42,
      documentId: 'document-b',
      callbackUrl: callbackUrl(`${STATE}_identifier=discovered-org`),
    });
    expect(withSuffix?.attempt.organizationIdentifier).toBe('discovered-org');
  });

  it('turns a claim from a previous worker into a secret-free terminal marker', async () => {
    const storage = createMemoryStore();
    const first = makeStore(storage);
    const waiting = await first.create(attemptInput());
    const bound = await first.bindCallbackDocument(waiting.owner, {
      tabId: 42,
      documentId: 'document-a',
      callbackUrl: callbackUrl(),
    });
    await first.claim(bound!.attempt.owner);

    const restarted = makeStore(storage, {
      workerId: WORKER_B,
      createAttemptId: () => ATTEMPT_B,
    });
    const unknown = await restarted.read();

    expect(unknown).toMatchObject({
      status: 'outcome_unknown',
      owner: { generation: 4, attemptGeneration: 1, attemptId: ATTEMPT_A },
      tabId: 42,
      callbackDocumentId: 'document-a',
      redirectUri: REDIRECT_URI,
      source: SOURCE,
      terminalAt: 1_000,
      expiresAt: 1_000 + SSO_OUTCOME_UNKNOWN_TTL_MS,
    });
    const raw = JSON.stringify(await storage.get(SSO_ATTEMPT_STORAGE_KEY));
    for (const secret of [STATE, VERIFIER, 'opaque-code_123']) {
      expect(raw).not.toContain(secret);
    }
  });

  it('marks an ambiguous exchange terminal and clears only its exact terminal owner', async () => {
    const storage = createMemoryStore();
    const store = makeStore(storage);
    const waiting = await store.create(attemptInput());
    const bound = await store.bindCallbackDocument(waiting.owner, {
      tabId: 42,
      documentId: 'document-a',
      callbackUrl: callbackUrl(),
    });
    const claimed = await store.claim(bound!.attempt.owner);
    const unknown = await store.markOutcomeUnknown(claimed!.owner);

    expect(unknown).toMatchObject({ status: 'outcome_unknown', owner: { generation: 4 } });
    await expect(store.markOutcomeUnknown(claimed!.owner)).resolves.toBeUndefined();
    await expect(store.clear(claimed!.owner)).resolves.toBe(false);
    await expect(store.clear(unknown!.owner)).resolves.toBe(true);
  });

  it('retires a claimed or unknown outer attempt only for an exact durable SSO handoff', async () => {
    for (const settleUnknownFirst of [false, true]) {
      const storage = createMemoryStore();
      const first = makeStore(storage);
      const waiting = await first.create(attemptInput());
      const bound = await first.bindCallbackDocument(waiting.owner, {
        tabId: 42,
        documentId: 'document-a',
        callbackUrl: callbackUrl(),
      });
      const claimed = await first.claim(bound!.attempt.owner);
      const restarted = makeStore(storage, { workerId: WORKER_B });
      if (settleUnknownFirst) {
        await expect(restarted.read()).resolves.toMatchObject({ status: 'outcome_unknown' });
      }

      const exact = {
        attemptId: ATTEMPT_A,
        attemptGeneration: claimed!.owner.generation,
        serverUrl: SERVER,
        identityUrl: IDENTITY,
        email: EMAIL,
      } as const;
      for (const mismatch of [
        { ...exact, attemptId: ATTEMPT_B },
        { ...exact, attemptGeneration: exact.attemptGeneration + 1 },
        { ...exact, serverUrl: 'https://other.example/base/' },
        { ...exact, identityUrl: 'https://identity.example/other/' },
        { ...exact, email: 'other@example.com' },
      ]) {
        await expect(restarted.completeHandoff(mismatch)).resolves.toBe(false);
      }
      await expect(restarted.completeHandoff(exact)).resolves.toBe(true);
      await expect(restarted.read()).resolves.toBeUndefined();
    }

    const waitingStore = makeStore(createMemoryStore());
    await waitingStore.create(attemptInput());
    await expect(waitingStore.completeHandoff({
      attemptId: ATTEMPT_A,
      attemptGeneration: 1,
      serverUrl: SERVER,
      identityUrl: IDENTITY,
      email: EMAIL,
    })).resolves.toBe(false);
    await expect(waitingStore.read()).resolves.toMatchObject({ status: 'waiting' });
  });

  it('does not let an old handoff with a reused attempt id clear a newer claim', async () => {
    const storage = createMemoryStore();
    const store = makeStore(storage, { createAttemptId: () => ATTEMPT_A });
    const first = await store.create(attemptInput());
    const firstBound = await store.bindCallbackDocument(first.owner, {
      tabId: 42,
      documentId: 'document-a',
      callbackUrl: callbackUrl(),
    });
    const firstClaim = await store.claim(firstBound!.attempt.owner);
    await store.clear(firstClaim!.owner);
    const second = await store.create({ ...attemptInput(), tabId: 99 });
    const secondBound = await store.bindCallbackDocument(second.owner, {
      tabId: 99,
      documentId: 'document-b',
      callbackUrl: callbackUrl(),
    });
    const secondClaim = await store.claim(secondBound!.attempt.owner);

    await expect(store.completeHandoff({
      attemptId: ATTEMPT_A,
      attemptGeneration: firstClaim!.owner.generation,
      serverUrl: SERVER,
      identityUrl: IDENTITY,
      email: EMAIL,
    })).resolves.toBe(false);
    await expect(store.read()).resolves.toEqual(secondClaim);
  });

  it('prevents ABA owners even if an injected attempt id is repeated', async () => {
    const storage = createMemoryStore();
    const store = makeStore(storage, { createAttemptId: () => ATTEMPT_A });
    const first = await store.create(attemptInput());
    expect(await store.clear(first.owner)).toBe(true);
    const second = await store.create({ ...attemptInput(), tabId: 99 });

    expect(second.owner.attemptId).toBe(first.owner.attemptId);
    expect(second.owner.generation).toBeGreaterThan(first.owner.generation);
    await expect(store.bindCallbackDocument(first.owner, {
      tabId: 42,
      documentId: 'stale-document',
      callbackUrl: callbackUrl(),
    })).resolves.toBeUndefined();
    expect(await store.clear(first.owner)).toBe(false);
    expect(await store.clear(second.owner)).toBe(true);
  });

  it('purges expired, malformed, and oversized persisted envelopes', async () => {
    let now = 1_000;
    const storage = createMemoryStore();
    const store = makeStore(storage, { now: () => now });
    await store.create(attemptInput());
    now += SSO_ATTEMPT_TTL_MS;
    await expect(store.read()).resolves.toBeUndefined();
    expect(await storage.get(SSO_ATTEMPT_STORAGE_KEY)).toBeUndefined();

    await storage.set(SSO_ATTEMPT_STORAGE_KEY, {
      schemaVersion: SSO_ATTEMPT_SCHEMA_VERSION,
      generation: 7,
      status: 'waiting',
      verifier: VERIFIER,
      extra: true,
    });
    await expect(store.read()).resolves.toBeUndefined();

    await storage.set(SSO_ATTEMPT_STORAGE_KEY, {
      schemaVersion: SSO_ATTEMPT_SCHEMA_VERSION,
      generation: 8,
      status: 'waiting',
      padding: 'x'.repeat(SSO_ATTEMPT_MAX_UTF8_BYTES),
    });
    await expect(store.read()).resolves.toBeUndefined();
    expect(await storage.get(SSO_ATTEMPT_STORAGE_KEY)).toBeUndefined();
  });

  it('rejects malformed create bindings and a low-entropy attempt id shape', async () => {
    const invalidInputs = [
      { serverUrl: 'http://server.example/' },
      { identityUrl: 'http://identity.example/' },
      { serverGeneration: -1 },
      { emailIntent: 'not-an-email' },
      { tabId: -1 },
      { connectorOrigin: 'https://other.example' },
      { connectorPath: '/other.html' },
      { state: 'short:clientId=browser' },
      { verifier: 'short' },
      { redirectUri: `${REDIRECT_URI}?query=1` },
    ];
    for (const override of invalidInputs) {
      await expect(makeStore(createMemoryStore()).create({
        ...attemptInput(),
        ...override,
      })).rejects.toThrow();
    }

    await expect(makeStore(createMemoryStore(), {
      createAttemptId: () => 'predictable-attempt',
    }).create(attemptInput())).rejects.toMatchObject({ code: 'invalid_input' });
  });

  it('fails closed when the persisted generation high-water mark is exhausted', async () => {
    const storage = createMemoryStore();
    const store = makeStore(storage);
    const now = 1_000;
    await storage.set(SSO_ATTEMPT_STORAGE_KEY, {
      schemaVersion: SSO_ATTEMPT_SCHEMA_VERSION,
      generation: Number.MAX_SAFE_INTEGER,
      attemptGeneration: Number.MAX_SAFE_INTEGER,
      status: 'waiting',
      attemptId: ATTEMPT_A,
      ...attemptInput(),
      createdAt: now,
      expiresAt: now + SSO_ATTEMPT_TTL_MS,
    });
    const current = await store.read();
    expect(current?.owner.generation).toBe(Number.MAX_SAFE_INTEGER);
    expect(await store.clear(current!.owner)).toBe(true);
    await expect(store.create(attemptInput())).rejects.toMatchObject({
      code: 'generation_exhausted',
    });
  });
});

type MemoryStore = ReturnType<typeof createMemoryStore>;

function makeStore(
  storage: MemoryStore,
  overrides: {
    now?: () => number;
    workerId?: string;
    createAttemptId?: () => string;
  } = {},
): SsoAttemptStore {
  return new SsoAttemptStore(storage, {
    now: overrides.now ?? (() => 1_000),
    workerId: overrides.workerId ?? WORKER_A,
    createAttemptId: overrides.createAttemptId ?? (() => ATTEMPT_A),
  });
}
