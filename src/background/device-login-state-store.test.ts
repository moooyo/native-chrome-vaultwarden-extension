import { beforeAll, describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
      session: { get: vi.fn(), set: vi.fn(), remove: vi.fn(), clear: vi.fn() },
    },
  },
}));

import { createMemoryStore, type KeyValueStore } from '../platform/store.js';
import {
  bindDeviceLoginRequest,
  createDeviceLoginRequest,
  type DeviceLoginBoundState,
  type DeviceLoginPendingState,
} from '../core/session/device-login.js';
import { bytesToBase64Url } from '../core/crypto/encoding.js';
import { parseFido2TwoFactorRequest } from '../core/session/fido2-two-factor.js';
import { interactiveTwoFactorConnectorUrl } from '../core/session/interactive-two-factor.js';
import {
  DEVICE_LOGIN_STATE_ENVELOPE_MAX_UTF8_BYTES,
  DEVICE_LOGIN_STATE_STORAGE_KEY,
  DeviceLoginStateStore,
  projectDeviceLoginStateMetadata,
} from './device-login-state-store.js';

const NOW = Date.parse('2026-08-30T08:00:00.000Z');
const SERVER_CREATED_AT = NOW + 1_000;
const SERVER_URL = 'https://vault.example/tenant/';
const REQUEST_ID = 'f4b47b53-a174-4a40-bbd6-08b2bb6f9d34';
const OTHER_REQUEST_ID = 'c05e732e-77b1-457b-8f89-5b5ba1b4e1d2';
const DEVICE = Object.freeze({ type: 2, name: 'chrome', identifier: 'device-123' });

function fido2Challenge() {
  const connectorUrl = interactiveTwoFactorConnectorUrl(SERVER_URL);
  const connector = new URL(connectorUrl);
  const request = parseFido2TwoFactorRequest({
    challenge: bytesToBase64Url(new Uint8Array(32).fill(1)),
    rpId: connector.hostname,
    allowCredentials: [{
      type: 'public-key',
      id: bytesToBase64Url(new Uint8Array(32).fill(2)),
    }],
  }, { origin: connector.origin, rpId: connector.hostname });
  return Object.freeze({ connectorData: request.connectorData, connectorUrl });
}

let pending: DeviceLoginPendingState;
let otherPending: DeviceLoginPendingState;
let bound: DeviceLoginBoundState;
let otherBound: DeviceLoginBoundState;

beforeAll(async () => {
  pending = (await createDeviceLoginRequest({ email: 'user@example.com', device: DEVICE }, NOW)).state;
  otherPending = (await createDeviceLoginRequest({ email: 'other@example.com', device: DEVICE }, NOW)).state;
  bound = await bindDeviceLoginRequest(pending, creationResponse(pending, REQUEST_ID), NOW + 2_000);
  otherBound = await bindDeviceLoginRequest(
    otherPending,
    creationResponse(otherPending, OTHER_REQUEST_ID),
    NOW + 2_000,
  );
});

describe('DeviceLoginStateStore', () => {
  it('writes one strict server-bound pending envelope to the supplied session store', async () => {
    const sessionStore = createMemoryStore();
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 1,
      workerId: 'worker-a',
    });

    const snapshot = await store.write(' HTTPS://VAULT.EXAMPLE/tenant ', pending);

    expect(snapshot).toEqual({
      owner: { generation: 1, serverUrl: SERVER_URL },
      claimed: false,
      state: pending,
    });
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.owner)).toBe(true);
    expect(await sessionStore.get(DEVICE_LOGIN_STATE_STORAGE_KEY)).toEqual({
      schemaVersion: 1,
      generation: 1,
      status: 'active',
      serverUrl: SERVER_URL,
      state: pending,
    });
  });

  it('restores cryptographically valid state across store instances sharing one session area', async () => {
    const sessionStore = createMemoryStore();
    const first = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 1,
      workerId: 'worker-shared',
    });
    await first.write(SERVER_URL, pending);
    const second = new DeviceLoginStateStore(sessionStore, { now: () => NOW + 2 });

    await expect(second.read()).resolves.toEqual({
      owner: { generation: 1, serverUrl: SERVER_URL },
      claimed: false,
      state: pending,
    });
  });

  it('projects UI metadata without private key, access code, or device identifier', async () => {
    const sessionStore = createMemoryStore();
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 1,
      workerId: 'worker-metadata',
    });
    const written = await store.write(SERVER_URL, pending);

    const metadata = projectDeviceLoginStateMetadata(written);
    const serialized = JSON.stringify(metadata);
    expect(metadata).toEqual({
      generation: written.owner.generation,
      claimed: false,
      phase: 'pending',
      email: pending.email,
      serverOrigin: 'https://vault.example',
      device: { type: DEVICE.type, name: DEVICE.name },
      createdAt: pending.createdAt,
      expiresAt: pending.expiresAt,
    });
    expect(serialized).not.toContain(pending.privateKeyPkcs8);
    expect(serialized).not.toContain(pending.accessCode);
    expect(serialized).not.toContain(DEVICE.identifier);
    expect(serialized).not.toContain(pending.publicKey);
    expect(serialized).not.toContain(REQUEST_ID);
    expect(serialized).not.toContain('/tenant/');
    expect(Object.isFrozen(metadata)).toBe(true);
    if (!metadata || 'status' in metadata) throw new Error('Expected active metadata');
    expect(Object.isFrozen(metadata.device)).toBe(true);
    await expect(store.readMetadata()).resolves.toEqual(metadata);
  });

  it('replaces only the exact pending owner with its bound continuation', async () => {
    const sessionStore = createMemoryStore();
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 2_000,
      workerId: 'worker-replace',
    });
    const written = await store.write(SERVER_URL, pending);

    const replaced = await store.replace(written.owner, bound);

    expect(replaced).toEqual({
      owner: { generation: 2, serverUrl: SERVER_URL, requestId: REQUEST_ID },
      claimed: false,
      state: bound,
    });
    await expect(store.clear(written.owner)).resolves.toBe(false);
    await expect(store.read()).resolves.toEqual(replaced);
    const metadata = await store.readMetadata();
    const serialized = JSON.stringify(metadata);
    expect(metadata).toMatchObject({
      phase: 'bound',
      serverOrigin: 'https://vault.example',
    });
    expect(serialized).not.toContain(bound.publicKey);
    expect(serialized).not.toContain(bound.requestId);
    expect(serialized).not.toContain(bound.privateKeyPkcs8);
    expect(serialized).not.toContain(bound.accessCode);
  });

  it('rejects a replacement assembled from another ceremony without changing the current state', async () => {
    const sessionStore = createMemoryStore();
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 2_000,
      workerId: 'worker-cross-ceremony',
    });
    const written = await store.write(SERVER_URL, pending);

    await expect(store.replace(written.owner, otherBound)).rejects.toMatchObject({
      code: 'invalid_transition',
    });
    await expect(store.read()).resolves.toEqual(written);
  });

  it('claims one bound generation atomically and erases it on terminal clear', async () => {
    const sessionStore = createMemoryStore();
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 3_000,
      workerId: 'worker-claim',
    });
    const written = await store.write(SERVER_URL, pending);
    const replaced = (await store.replace(written.owner, bound))!;

    const [first, second] = await Promise.all([
      store.claim(replaced.owner),
      store.claim(replaced.owner),
    ]);

    expect(first).toEqual({
      owner: { generation: 3, serverUrl: SERVER_URL, requestId: REQUEST_ID },
      claimed: true,
      state: bound,
    });
    expect(second).toBeUndefined();
    await expect(store.clear(replaced.owner)).resolves.toBe(false);
    await expect(store.clear(first!.owner)).resolves.toBe(true);
    await expect(store.read()).resolves.toBeUndefined();
    const raw = await sessionStore.get<Record<string, unknown>>(DEVICE_LOGIN_STATE_STORAGE_KEY);
    expect(raw).toEqual({ schemaVersion: 1, generation: 4, status: 'empty' });
    const serialized = JSON.stringify(raw);
    expect(serialized).not.toContain(bound.privateKeyPkcs8);
    expect(serialized).not.toContain(bound.accessCode);
  });

  it('releases a 2FA challenge to a fresh resumable owner and permits one later claim', async () => {
    const sessionStore = createMemoryStore();
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 3_000,
      workerId: 'worker-release',
    });
    const written = await store.write(SERVER_URL, pending);
    const replaced = (await store.replace(written.owner, bound))!;
    const claimed = (await store.claim(replaced.owner))!;

    const released = await store.release(claimed.owner);

    expect(released).toEqual({
      owner: { generation: 4, serverUrl: SERVER_URL, requestId: REQUEST_ID },
      claimed: false,
      state: bound,
    });
    await expect(store.clear(claimed.owner)).resolves.toBe(false);
    await expect(store.claim(claimed.owner)).resolves.toBeUndefined();
    await expect(store.release(claimed.owner)).resolves.toBeUndefined();
    await expect(store.claim(released!.owner)).resolves.toMatchObject({
      owner: { generation: 5, serverUrl: SERVER_URL, requestId: REQUEST_ID },
      claimed: true,
    });
  });

  it('erases an expired claim instead of releasing it for another token attempt', async () => {
    const sessionStore = createMemoryStore();
    let now = NOW + 3_000;
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => now,
      workerId: 'worker-release-expired',
    });
    const written = await store.write(SERVER_URL, pending);
    const replaced = (await store.replace(written.owner, bound))!;
    const claimed = (await store.claim(replaced.owner))!;
    now = bound.expiresAt;

    await expect(store.release(claimed.owner)).resolves.toBeUndefined();
    await expect(store.read()).resolves.toBeUndefined();
    expect(JSON.stringify(await sessionStore.get(DEVICE_LOGIN_STATE_STORAGE_KEY)))
      .not.toContain(bound.accessCode);
  });

  it('persists only strict internal two-factor challenge data across release and reclaim', async () => {
    const sessionStore = createMemoryStore();
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 3_000,
      workerId: 'worker-two-factor',
    });
    const written = await store.write(SERVER_URL, pending);
    const replaced = (await store.replace(written.owner, bound))!;
    const claimed = (await store.claim(replaced.owner))!;
    const challenge = Object.freeze({
      providers: Object.freeze([0, 1]),
      token: 'session-only-two-factor-token',
      forcePasswordReset: true as const,
      masterPasswordPolicy: Object.freeze({
        minComplexity: 2,
        minLength: 16,
        requireUpper: true,
        requireLower: false,
        requireNumbers: true,
        requireSpecial: false,
        enforceOnLogin: false,
      }),
    });

    const released = (await store.release(claimed.owner, {
      twoFactor: challenge,
      retryRequired: true,
    }))!;

    expect(released.twoFactor).toEqual(challenge);
    expect(released.retryRequired).toBe(true);
    expect(Object.isFrozen(released.twoFactor)).toBe(true);
    expect(Object.isFrozen(released.twoFactor!.providers)).toBe(true);
    const reclaimed = await store.claim(released.owner);
    expect(reclaimed?.twoFactor).toEqual(challenge);
    expect(reclaimed?.retryRequired).toBe(true);
    const metadata = await store.readMetadata();
    expect(JSON.stringify(metadata)).not.toContain(challenge.token);
    expect(metadata).not.toHaveProperty('twoFactor');
    expect(JSON.stringify(await sessionStore.get(DEVICE_LOGIN_STATE_STORAGE_KEY)))
      .toContain(challenge.token);
  });

  it('persists only canonical owner-bound FIDO2 connector data and rebuilds it after restart', async () => {
    const sessionStore = createMemoryStore();
    const first = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 3_000,
      workerId: 'worker-fido-first',
    });
    const written = await first.write(SERVER_URL, pending);
    const replaced = (await first.replace(written.owner, bound))!;
    const claimed = (await first.claim(replaced.owner))!;
    const fido2 = fido2Challenge();

    const released = (await first.release(claimed.owner, {
      twoFactor: {
        providers: [0, 7],
        fido2,
        forcePasswordReset: true,
      },
    }))!;
    expect(released.twoFactor).toEqual({
      providers: [0, 7],
      fido2,
      forcePasswordReset: true,
    });
    expect(released.owner).toMatchObject({
      serverUrl: SERVER_URL,
      requestId: REQUEST_ID,
    });

    const restarted = new DeviceLoginStateStore(wrapStore(sessionStore), {
      now: () => NOW + 3_001,
      workerId: 'worker-fido-restarted',
    });
    const restored = await restarted.read();
    expect(restored).toMatchObject({
      claimed: false,
      owner: released.owner,
      twoFactor: { providers: [0, 7], fido2 },
    });
    const raw = await sessionStore.get<{ twoFactor: { fido2: unknown } }>(
      DEVICE_LOGIN_STATE_STORAGE_KEY,
    );
    expect(raw?.twoFactor.fido2).toEqual(fido2);
    const serialized = JSON.stringify(raw);
    expect(serialized).not.toContain('assertion');
    expect(serialized).not.toContain('parentUrl');
    expect(serialized).not.toContain('tabId');
  });

  it('rejects non-canonical or metadata-bearing two-factor challenge state', async () => {
    const sessionStore = createMemoryStore();
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 3_000,
      workerId: 'worker-invalid-two-factor',
    });
    const written = await store.write(SERVER_URL, pending);
    const replaced = (await store.replace(written.owner, bound))!;
    const claimed = (await store.claim(replaced.owner))!;

    await expect(store.release(claimed.owner, { twoFactor: {
      providers: [1, 0],
      token: 'token',
    } })).rejects.toMatchObject({ code: 'invalid_transition' });
    await expect(store.release(claimed.owner, { twoFactor: {
      providers: [0],
      token: 'token',
      providerMetadata: { secret: true },
    } as never })).rejects.toMatchObject({ code: 'invalid_transition' });
    const fido2 = fido2Challenge();
    await expect(store.release(claimed.owner, { twoFactor: {
      providers: [7],
    } })).rejects.toMatchObject({ code: 'invalid_transition' });
    await expect(store.release(claimed.owner, { twoFactor: {
      providers: [0],
      fido2,
    } })).rejects.toMatchObject({ code: 'invalid_transition' });
    await expect(store.release(claimed.owner, { twoFactor: {
      providers: [7],
      fido2: { ...fido2, connectorUrl: 'https://evil.example/webauthn-fallback-connector.html' },
    } })).rejects.toMatchObject({ code: 'invalid_transition' });
    await expect(store.release(claimed.owner, { twoFactor: {
      providers: [7],
      fido2: { ...fido2, connectorData: '{ "challenge": "bad" }' },
    } })).rejects.toMatchObject({ code: 'invalid_transition' });
    await expect(store.release(claimed.owner, {
      retryRequired: false,
    } as never)).rejects.toMatchObject({ code: 'invalid_transition' });
    await expect(store.read()).resolves.toEqual(claimed);
  });

  it('keeps exactly one active ceremony until its current owner clears it', async () => {
    const sessionStore = createMemoryStore();
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 1,
      workerId: 'worker-single',
    });
    const written = await store.write(SERVER_URL, pending);

    await expect(store.write('https://other.example/', otherPending)).rejects.toMatchObject({
      code: 'busy',
    });
    await expect(store.clear(written.owner)).resolves.toBe(true);
    await expect(store.write('https://other.example/', otherPending)).resolves.toMatchObject({
      owner: { generation: 3, serverUrl: 'https://other.example/' },
      state: { email: 'other@example.com' },
    });
  });

  it('compares generation, request id, and canonical server URL in every CAS operation', async () => {
    const sessionStore = createMemoryStore();
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 3_000,
      workerId: 'worker-owner-cas',
    });
    const written = await store.write(SERVER_URL, pending);
    await expect(store.replace(
      { ...written.owner, serverUrl: 'https://other.example/' },
      bound,
    )).resolves.toBeUndefined();
    await expect(store.replace(
      { ...written.owner, requestId: REQUEST_ID },
      bound,
    )).resolves.toBeUndefined();
    const replaced = (await store.replace(written.owner, bound))!;
    const wrongServer = { ...replaced.owner, serverUrl: 'https://other.example/' };
    const wrongRequest = { ...replaced.owner, requestId: OTHER_REQUEST_ID };

    await expect(store.claim(wrongServer)).resolves.toBeUndefined();
    await expect(store.clear(wrongRequest)).resolves.toBe(false);
    await expect(store.read()).resolves.toEqual(replaced);
  });

  it('prevents a delayed clear or replace from affecting a newer ceremony after ABA', async () => {
    const sessionStore = createMemoryStore();
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 2_000,
      workerId: 'worker-aba',
    });
    const old = await store.write(SERVER_URL, pending);
    await store.clear(old.owner);
    const current = await store.write('https://other.example/', otherPending);

    await expect(store.clear(old.owner)).resolves.toBe(false);
    await expect(store.replace(old.owner, bound)).resolves.toBeUndefined();
    await expect(store.read()).resolves.toEqual(current);
    expect(current.owner.generation).toBeGreaterThan(old.owner.generation);
  });

  it('linearizes ABA operations across distinct wrappers for the same session storage key', async () => {
    const backing = createMemoryStore();
    const initial = new DeviceLoginStateStore(backing, {
      now: () => NOW + 2_000,
      workerId: 'worker-cross-wrapper',
    });
    const old = await initial.write(SERVER_URL, pending);
    let releaseRead!: () => void;
    let observedRead!: () => void;
    const readGate = new Promise<void>((resolve) => { releaseRead = resolve; });
    const readObserved = new Promise<void>((resolve) => { observedRead = resolve; });
    const delayedWrapper: KeyValueStore = {
      async get<T>(key: string) {
        const value = await backing.get<T>(key);
        observedRead();
        await readGate;
        return value;
      },
      set: (key, value) => backing.set(key, value),
      setMany: (values) => backing.setMany(values),
      remove: (key) => backing.remove(key),
      clear: () => backing.clear(),
    };
    const delayed = new DeviceLoginStateStore(delayedWrapper, {
      now: () => NOW + 2_000,
      workerId: 'worker-cross-wrapper',
    });
    const competing = new DeviceLoginStateStore(wrapStore(backing), {
      now: () => NOW + 2_000,
      workerId: 'worker-cross-wrapper',
    });

    const oldClear = delayed.clear(old.owner);
    await readObserved;
    const replacement = (async () => {
      await competing.clear(old.owner);
      return competing.write('https://other.example/', otherPending);
    })();
    releaseRead();

    await expect(oldClear).resolves.toBe(true);
    const current = await replacement;
    await expect(initial.read()).resolves.toEqual(current);
    expect(current.owner.generation).toBeGreaterThan(old.owner.generation);
  });

  it('clears a claimed ceremony owned by a prior service-worker lifetime', async () => {
    const backing = createMemoryStore();
    const first = new DeviceLoginStateStore(backing, {
      now: () => NOW + 3_000,
      workerId: 'worker-before-restart',
    });
    const written = await first.write(SERVER_URL, pending);
    const replaced = (await first.replace(written.owner, bound))!;
    const claim = (await first.claim(replaced.owner))!;
    const wrapper = wrapStore(backing);
    const restarted = new DeviceLoginStateStore(wrapper, {
      now: () => NOW + 4_000,
      workerId: 'worker-after-restart',
    });

    await expect(restarted.read()).resolves.toEqual({
      owner: { generation: 4, serverUrl: SERVER_URL },
      status: 'outcome_unknown',
      createdAt: bound.createdAt,
      expiresAt: bound.expiresAt,
      terminalAt: NOW + 4_000,
    });
    const raw = await backing.get<Record<string, unknown>>(DEVICE_LOGIN_STATE_STORAGE_KEY);
    expect(raw).toEqual({
      schemaVersion: 1,
      generation: 4,
      status: 'outcome_unknown',
      serverUrl: SERVER_URL,
      createdAt: bound.createdAt,
      expiresAt: bound.expiresAt,
      terminalAt: NOW + 4_000,
    });
    expect((raw?.generation as number)).toBeGreaterThan(claim.owner.generation);
    expect(JSON.stringify(raw)).not.toContain(bound.accessCode);
    expect(JSON.stringify(raw)).not.toContain(bound.privateKeyPkcs8);
    expect(JSON.stringify(raw)).not.toContain(bound.requestId);
  });

  it.each([
    ['unknown schema', (state: DeviceLoginPendingState) => ({
      schemaVersion: 99, generation: 7, status: 'active', serverUrl: SERVER_URL, state,
    })],
    ['unknown envelope field', (state: DeviceLoginPendingState) => ({
      schemaVersion: 1, generation: 7, status: 'active', serverUrl: SERVER_URL, state, extra: true,
    })],
    ['unknown state field', (state: DeviceLoginPendingState) => ({
      schemaVersion: 1, generation: 7, status: 'active', serverUrl: SERVER_URL,
      state: { ...state, extra: true },
    })],
    ['non-canonical server', (state: DeviceLoginPendingState) => ({
      schemaVersion: 1, generation: 7, status: 'active', serverUrl: 'https://VAULT.example/tenant', state,
    })],
    ['future local creation time', (state: DeviceLoginPendingState) => ({
      schemaVersion: 1,
      generation: 7,
      status: 'active',
      serverUrl: SERVER_URL,
      state: {
        ...state,
        createdAt: NOW + 60_000,
        expiresAt: NOW + 60_000 + 15 * 60_000,
      },
    })],
  ])('fails closed and erases %s', async (_label, makeEnvelope) => {
    const sessionStore = createMemoryStore();
    await sessionStore.set(DEVICE_LOGIN_STATE_STORAGE_KEY, makeEnvelope(pending));
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 1,
      workerId: `worker-invalid-${_label.replaceAll(' ', '-')}`,
    });

    await expect(store.read()).resolves.toBeUndefined();
    const raw = await sessionStore.get<Record<string, unknown>>(DEVICE_LOGIN_STATE_STORAGE_KEY);
    expect(raw).toMatchObject({ schemaVersion: 1, status: 'empty' });
    expect(JSON.stringify(raw)).not.toContain(pending.accessCode);
  });

  it('clears expired state and cryptographically mismatched key material', async () => {
    const expiredStorage = createMemoryStore();
    const expiredStore = new DeviceLoginStateStore(expiredStorage, {
      now: () => pending.expiresAt,
      workerId: 'worker-expired',
    });
    await expiredStorage.set(DEVICE_LOGIN_STATE_STORAGE_KEY, {
      schemaVersion: 1,
      generation: 1,
      status: 'active',
      serverUrl: SERVER_URL,
      state: pending,
    });
    await expect(expiredStore.read()).resolves.toBeUndefined();
    expect(JSON.stringify(await expiredStorage.get(DEVICE_LOGIN_STATE_STORAGE_KEY)))
      .not.toContain(pending.accessCode);

    const mismatchedStorage = createMemoryStore();
    await mismatchedStorage.set(DEVICE_LOGIN_STATE_STORAGE_KEY, {
      schemaVersion: 1,
      generation: 1,
      status: 'active',
      serverUrl: SERVER_URL,
      state: { ...pending, privateKeyPkcs8: otherPending.privateKeyPkcs8 },
    });
    const mismatchedStore = new DeviceLoginStateStore(mismatchedStorage, {
      now: () => NOW + 1,
      workerId: 'worker-mismatched',
    });
    await expect(mismatchedStore.read()).resolves.toBeUndefined();
    expect(JSON.stringify(await mismatchedStorage.get(DEVICE_LOGIN_STATE_STORAGE_KEY)))
      .not.toContain(pending.accessCode);
  });

  it('erases an envelope above the four-megabyte UTF-8 budget', async () => {
    const sessionStore = createMemoryStore();
    const oversized = {
      schemaVersion: 1,
      generation: 12,
      status: 'active',
      serverUrl: SERVER_URL,
      state: pending,
      padding: 'x'.repeat(DEVICE_LOGIN_STATE_ENVELOPE_MAX_UTF8_BYTES),
    };
    await sessionStore.set(DEVICE_LOGIN_STATE_STORAGE_KEY, oversized);
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 1,
      workerId: 'worker-oversized',
    });

    await expect(store.read()).resolves.toBeUndefined();
    const raw = await sessionStore.get<Record<string, unknown>>(DEVICE_LOGIN_STATE_STORAGE_KEY);
    expect(raw).toEqual({ schemaVersion: 1, generation: 13, status: 'empty' });
    expect(JSON.stringify(raw)).not.toContain(pending.accessCode);
  });

  it('still erases terminal secrets when the persisted generation is exhausted', async () => {
    const sessionStore = createMemoryStore();
    await sessionStore.set(DEVICE_LOGIN_STATE_STORAGE_KEY, {
      schemaVersion: 1,
      generation: Number.MAX_SAFE_INTEGER,
      status: 'active',
      serverUrl: SERVER_URL,
      state: pending,
    });
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 1,
      workerId: 'worker-generation-limit',
    });
    const current = (await store.read())!;

    await expect(store.clear(current.owner)).resolves.toBe(true);
    await expect(sessionStore.get(DEVICE_LOGIN_STATE_STORAGE_KEY)).resolves.toBeUndefined();
  });

  it('erases active and claimed secrets when outcome retirement reaches generation exhaustion', async () => {
    const activeStorage = createMemoryStore();
    await activeStorage.set(DEVICE_LOGIN_STATE_STORAGE_KEY, {
      schemaVersion: 1,
      generation: Number.MAX_SAFE_INTEGER,
      status: 'active',
      serverUrl: SERVER_URL,
      state: pending,
    });
    const activeStore = new DeviceLoginStateStore(activeStorage, {
      now: () => NOW + 1,
      workerId: 'worker-active-outcome-limit',
    });
    const active = (await activeStore.read())!;
    await expect(activeStore.retireOutcomeUnknown(active.owner)).resolves.toMatchObject({
      status: 'outcome_unknown',
    });
    await expect(activeStorage.get(DEVICE_LOGIN_STATE_STORAGE_KEY)).resolves.toBeUndefined();

    const claimedStorage = createMemoryStore();
    await claimedStorage.set(DEVICE_LOGIN_STATE_STORAGE_KEY, {
      schemaVersion: 1,
      generation: Number.MAX_SAFE_INTEGER,
      status: 'claimed',
      serverUrl: SERVER_URL,
      state: bound,
      workerId: 'worker-claimed-outcome-limit',
      claimedAt: NOW + 1,
    });
    const claimedStore = new DeviceLoginStateStore(claimedStorage, {
      now: () => NOW + 2,
      workerId: 'worker-claimed-outcome-limit',
    });
    const claimed = (await claimedStore.read())!;
    await expect(claimedStore.markOutcomeUnknown(claimed.owner)).resolves.toMatchObject({
      status: 'outcome_unknown',
    });
    await expect(claimedStorage.get(DEVICE_LOGIN_STATE_STORAGE_KEY)).resolves.toBeUndefined();
  });

  it('validates owners and server URLs before mutating session storage', async () => {
    const sessionStore = createMemoryStore();
    const set = vi.spyOn(sessionStore, 'set');
    const store = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 1,
      workerId: 'worker-inputs',
    });

    await expect(store.write('http://remote.example/', pending)).rejects.toMatchObject({
      code: 'invalid_transition',
    });
    await expect(store.clear({ generation: 0, serverUrl: SERVER_URL })).rejects.toMatchObject({
      code: 'invalid_generation',
    });
    await expect(store.claim({
      generation: 1,
      serverUrl: SERVER_URL,
      requestId: REQUEST_ID,
      extra: true,
    } as never)).rejects.toMatchObject({ code: 'invalid_generation' });
    await expect(store.clear({
      generation: 1,
      serverUrl: SERVER_URL,
      requestId: 'short',
    })).rejects.toMatchObject({ code: 'invalid_generation' });
    await expect(store.clear({
      generation: 1,
      serverUrl: SERVER_URL,
      requestId: `${REQUEST_ID}\n`,
    })).rejects.toMatchObject({ code: 'invalid_generation' });
    expect(set).not.toHaveBeenCalled();
  });

  it('shares one mutation queue across instances and remains usable after storage failure', async () => {
    const backing = createMemoryStore();
    const failure = new Error('session storage write failed');
    let fail = true;
    const sessionStore: KeyValueStore = {
      get: <T>(key: string) => backing.get<T>(key),
      async set(key, value) {
        if (fail) {
          fail = false;
          throw failure;
        }
        await backing.set(key, value);
      },
      setMany: (values) => backing.setMany(values),
      remove: (key) => backing.remove(key),
      clear: () => backing.clear(),
    };
    const first = new DeviceLoginStateStore(sessionStore, {
      now: () => NOW + 1,
      workerId: 'worker-failure',
    });
    const second = new DeviceLoginStateStore(sessionStore, { now: () => NOW + 1 });

    await expect(first.write(SERVER_URL, pending)).rejects.toBe(failure);
    await expect(second.write(SERVER_URL, pending)).resolves.toMatchObject({
      owner: { generation: 2, serverUrl: SERVER_URL },
    });
  });
});

function creationResponse(state: DeviceLoginPendingState, id: string) {
  return {
    object: 'auth-request',
    id,
    publicKey: state.publicKey,
    requestDeviceType: 'Chrome',
    requestDeviceTypeValue: state.device.type,
    requestDeviceIdentifier: state.device.identifier,
    requestIpAddress: '203.0.113.7',
    requestCountryName: 'Test Country',
    key: null,
    masterPasswordHash: null,
    creationDate: new Date(SERVER_CREATED_AT).toISOString(),
    requestApproved: false,
    responseDate: null,
    origin: 'Admin',
  };
}

function wrapStore(backing: KeyValueStore): KeyValueStore {
  return {
    get: <T>(key: string) => backing.get<T>(key),
    set: (key, value) => backing.set(key, value),
    ...(backing.setMany ? { setMany: (values: Readonly<Record<string, unknown>>) => backing.setMany!(values) } : {}),
    remove: (key) => backing.remove(key),
    clear: () => backing.clear(),
  };
}
