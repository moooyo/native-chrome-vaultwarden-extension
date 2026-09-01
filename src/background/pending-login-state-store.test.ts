import { describe, expect, it, vi } from 'vitest';

import { bytesToBase64 } from '../core/crypto/encoding.js';
import { PENDING_LOGIN_CONTINUATION_TTL_MS } from '../core/session/pending-login-continuation.js';
import type { KeyValueStore } from '../platform/store.js';
import {
  PENDING_LOGIN_CONTINUATION_EXPIRY_ALARM_PREFIX,
  PENDING_LOGIN_CONTINUATION_STORAGE_KEY,
  PendingLoginStateStore,
} from './pending-login-state-store.js';

const SERVER = 'https://vault.example.com/';
const EMAIL = 'user@example.com';
const HASH = bytesToBase64(new Uint8Array(32).fill(7));
const WORKER_A = '9fbb77e8-8f83-4b11-8cc6-94d6c78ba737';
const WORKER_B = '7ecaf599-7583-4f4d-bf81-9a320e4181dc';
const ATTEMPT_A = 'a5d9e191-aa77-41d1-8a22-26366516dbd7';
const ATTEMPT_B = '0b688c75-8429-4284-a908-5106d2258b7f';

const twoFactor = Object.freeze({
  stage: 'twoFactor' as const,
  email: EMAIL,
  masterPasswordHash: HASH,
  kdf: Object.freeze({ kdf: 0 as const, kdfIterations: 600_000 }),
  providers: Object.freeze([0, 1]),
  twoFactorToken: 'email-continuation',
});

const ssoTwoFactor = Object.freeze({
  stage: 'twoFactor' as const,
  email: EMAIL,
  sso: Object.freeze({
    ssoAttemptId: ATTEMPT_A,
    ssoAttemptGeneration: 3,
    code: 'authorization-code',
    codeVerifier: 'A'.repeat(43),
    redirectUri: 'https://vault.example.com/sso-connector.html',
    identityUrl: 'https://vault.example.com/identity/',
    emailTwoFactorMode: 'bitwarden-session' as const,
    emailTwoFactorSessionToken: 'email-session-token',
  }),
  kdf: Object.freeze({ kdf: 0 as const, kdfIterations: 600_000 }),
  providers: Object.freeze([1]),
});

describe('PendingLoginStateStore', () => {
  it('writes a five-minute active continuation with a random owner and no forbidden secrets', async () => {
    const storage = createMemoryStore();
    const store = makeStore(storage);

    const active = await store.write(SERVER, twoFactor);

    expect(active).toMatchObject({
      status: 'active',
      owner: {
        generation: 1,
        attemptId: ATTEMPT_A,
        serverUrl: SERVER,
        email: EMAIL,
      },
      createdAt: 1_000,
      expiresAt: 1_000 + PENDING_LOGIN_CONTINUATION_TTL_MS,
      data: twoFactor,
    });
    const raw = JSON.stringify(await storage.get(PENDING_LOGIN_CONTINUATION_STORAGE_KEY));
    expect(raw).toContain(HASH);
    expect(raw).not.toMatch(/password"|stretched|masterKey|userKey|privateKey|assertion|newDeviceOtp|\botp\b/i);
  });

  it('persists one exact SSO grant and rejects password, NDV, or email-mode mixing', async () => {
    const storage = createMemoryStore();
    const store = makeStore(storage);

    const active = await store.write(SERVER, ssoTwoFactor);
    expect(active.data).toEqual(ssoTwoFactor);
    expect(await store.read()).toMatchObject({ data: ssoTwoFactor });
    await store.clear(active.owner);

    await expect(store.write(SERVER, {
      ...ssoTwoFactor,
      masterPasswordHash: HASH,
    } as never)).rejects.toThrow(/exactly one grant/);
    await expect(store.write(SERVER, {
      ...ssoTwoFactor,
      stage: 'newDeviceVerification',
      providers: [],
    })).rejects.toThrow(/unsupported/);
    await expect(store.write(SERVER, {
      ...ssoTwoFactor,
      sso: {
        ...ssoTwoFactor.sso,
        emailTwoFactorMode: 'vaultwarden-device',
      },
    })).rejects.toThrow(/Bitwarden email session token/);
  });

  it('claims, releases, and clears only an exact owner generation', async () => {
    let now = 1_000;
    const storage = createMemoryStore();
    const store = makeStore(storage, { now: () => now });
    const active = await store.write(SERVER, twoFactor);

    const claimed = await store.claim(active.owner);
    expect(claimed).toMatchObject({ status: 'claimed', owner: { generation: 2 }, claimedAt: 1_000 });
    expect(await store.claim(active.owner)).toBeUndefined();
    expect(await store.clear(active.owner)).toBe(false);

    now = 2_000;
    const released = await store.release(claimed!.owner, {
      ...twoFactor,
      providers: [1, 7],
      fido2: {
        connectorData: JSON.stringify({ challenge: 'AQID', rpId: 'vault.example.com' }),
        connectorUrl: 'https://vault.example.com/webauthn-fallback-connector.html',
      },
    });
    expect(released).toMatchObject({
      status: 'active',
      owner: { generation: 3, attemptId: ATTEMPT_A },
      createdAt: 1_000,
      expiresAt: 1_000 + PENDING_LOGIN_CONTINUATION_TTL_MS,
    });
    expect(await store.release(claimed!.owner, twoFactor)).toBeUndefined();
    expect(await store.clear(released!.owner)).toBe(true);
    expect(await store.read()).toBeUndefined();
  });

  it('turns a claim from a dead worker into secret-free outcome_unknown', async () => {
    const storage = createMemoryStore();
    const first = makeStore(storage, { workerId: WORKER_A });
    const active = await first.write(SERVER, twoFactor);
    await first.claim(active.owner);

    const restarted = makeStore(storage, { workerId: WORKER_B });
    const outcome = await restarted.read();

    expect(outcome).toMatchObject({
      status: 'outcome_unknown',
      owner: { generation: 3, attemptId: ATTEMPT_A },
      terminalAt: 1_000,
    });
    const raw = JSON.stringify(await storage.get(PENDING_LOGIN_CONTINUATION_STORAGE_KEY));
    expect(raw).not.toContain(HASH);
    expect(raw).not.toContain('email-continuation');
  });

  it('keeps a secret-free marker across a memory-only combined leg and makes a dead claim terminal', async () => {
    const storage = createMemoryStore();
    const first = makeStore(storage, { workerId: WORKER_A });
    const active = await first.write(SERVER, twoFactor);
    const claimed = await first.claim(active.owner);
    const marker = await first.redact(claimed!.owner);

    expect(marker).toMatchObject({
      status: 'active',
      memoryOnly: true,
      owner: { attemptId: ATTEMPT_A, generation: 3 },
    });
    let raw = JSON.stringify(await storage.get(PENDING_LOGIN_CONTINUATION_STORAGE_KEY));
    expect(raw).not.toContain(HASH);
    expect(raw).not.toContain('email-continuation');

    const markerClaim = await first.claim(marker!.owner);
    expect(markerClaim).toMatchObject({ status: 'claimed', memoryOnly: true });
    const restarted = makeStore(storage, { workerId: WORKER_B });
    await expect(restarted.read()).resolves.toMatchObject({ status: 'outcome_unknown' });
    raw = JSON.stringify(await storage.get(PENDING_LOGIN_CONTINUATION_STORAGE_KEY));
    expect(raw).not.toContain(HASH);
  });

  it('releases a rejected memory-only grant without restoring credential data', async () => {
    const storage = createMemoryStore();
    const store = makeStore(storage);
    const active = await store.write(SERVER, twoFactor);
    const claimed = await store.claim(active.owner);
    const marker = await store.redact(claimed!.owner);
    const markerClaim = await store.claim(marker!.owner);
    const released = await store.releaseMarker(markerClaim!.owner);

    expect(released).toMatchObject({ status: 'active', memoryOnly: true });
    expect(JSON.stringify(await storage.get(PENDING_LOGIN_CONTINUATION_STORAGE_KEY)))
      .not.toContain(HASH);
  });

  it('uses an attempt-bound alarm to physically delete credentials at five minutes', async () => {
    let now = 1_000;
    const storage = createMemoryStore();
    const create = vi.fn(async () => undefined);
    const clear = vi.fn(async () => true);
    const store = new PendingLoginStateStore(storage, {
      now: () => now,
      workerId: WORKER_A,
      createAttemptId: () => ATTEMPT_A,
      alarms: { create, clear },
    });
    await store.write(SERVER, twoFactor);
    const alarmName = `${PENDING_LOGIN_CONTINUATION_EXPIRY_ALARM_PREFIX}${ATTEMPT_A}`;
    expect(create).toHaveBeenCalledWith(alarmName, {
      when: 1_000 + PENDING_LOGIN_CONTINUATION_TTL_MS,
    });

    now += PENDING_LOGIN_CONTINUATION_TTL_MS;
    await expect(store.handleExpirationAlarm(alarmName)).resolves.toBe(true);
    expect(await storage.get(PENDING_LOGIN_CONTINUATION_STORAGE_KEY)).toBeUndefined();
    expect(clear).toHaveBeenCalledWith(alarmName);
  });

  it('re-arms an early stale alarm without deleting a newer attempt', async () => {
    const storage = createMemoryStore();
    const create = vi.fn(async () => undefined);
    const clear = vi.fn(async () => true);
    const store = new PendingLoginStateStore(storage, {
      now: () => 1_000,
      workerId: WORKER_A,
      createAttemptId: () => ATTEMPT_A,
      alarms: { create, clear },
    });
    await store.write(SERVER, twoFactor);

    await expect(store.handleExpirationAlarm(
      `${PENDING_LOGIN_CONTINUATION_EXPIRY_ALARM_PREFIX}${ATTEMPT_B}`,
    )).resolves.toBe(true);
    expect(await store.read()).toMatchObject({ status: 'active' });
    expect(clear).toHaveBeenCalledWith(
      `${PENDING_LOGIN_CONTINUATION_EXPIRY_ALARM_PREFIX}${ATTEMPT_B}`,
    );
  });

  it('marks ambiguous active or claimed work outcome_unknown without retaining credentials', async () => {
    const storage = createMemoryStore();
    const store = makeStore(storage);
    const active = await store.write(SERVER, twoFactor);
    const outcome = await store.markOutcomeUnknown(active.owner);
    expect(outcome?.status).toBe('outcome_unknown');
    expect(await store.markOutcomeUnknown(active.owner)).toBeUndefined();
    expect(JSON.stringify(await storage.get(PENDING_LOGIN_CONTINUATION_STORAGE_KEY)))
      .not.toContain(HASH);
  });

  it('purges expired and malformed envelopes', async () => {
    let now = 1_000;
    const storage = createMemoryStore();
    const store = makeStore(storage, { now: () => now });
    await store.write(SERVER, twoFactor);
    now += PENDING_LOGIN_CONTINUATION_TTL_MS;
    expect(await store.read()).toBeUndefined();

    await storage.set(PENDING_LOGIN_CONTINUATION_STORAGE_KEY, {
      schemaVersion: 1,
      generation: 8,
      status: 'active',
      password: 'forbidden',
    });
    expect(await store.read()).toBeUndefined();
    expect(await storage.get(PENDING_LOGIN_CONTINUATION_STORAGE_KEY)).toBeUndefined();
  });

  it.each([
    ['raw password', { ...twoFactor, password: 'secret' }],
    ['master key', { ...twoFactor, masterKey: 'secret' }],
    ['OTP', { ...twoFactor, otp: '123456' }],
    ['assertion', { ...twoFactor, assertion: '{}' }],
    ['duplicate providers', { ...twoFactor, providers: [0, 0] }],
    ['invalid hash', { ...twoFactor, masterPasswordHash: 'not-base64' }],
    ['NDV providers', { ...twoFactor, stage: 'newDeviceVerification', providers: [0] }],
  ])('rejects forbidden or malformed continuation data: %s', async (_label, data) => {
    await expect(makeStore(createMemoryStore()).write(SERVER, data as never)).rejects.toThrow();
  });

  it('rejects oversized state and a connector URL outside the bound server', async () => {
    await expect(makeStore(createMemoryStore()).write(SERVER, {
      ...twoFactor,
      twoFactorToken: 'x'.repeat(32 * 1024 + 1),
    })).rejects.toThrow();
    await expect(makeStore(createMemoryStore()).write(SERVER, {
      ...twoFactor,
      providers: [7],
      fido2: {
        connectorData: '{}',
        connectorUrl: 'https://evil.example/webauthn-fallback-connector.html',
      },
    })).rejects.toThrow(/connector URL/);
  });

  it('serializes concurrent writers so only one continuation can win', async () => {
    const storage = createMemoryStore();
    const attempts = [ATTEMPT_A, ATTEMPT_B];
    const store = new PendingLoginStateStore(storage, {
      now: () => 1_000,
      workerId: WORKER_A,
      createAttemptId: () => attempts.shift()!,
    });
    const writes = await Promise.allSettled([
      store.write(SERVER, twoFactor),
      store.write(SERVER, twoFactor),
    ]);
    expect(writes.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(writes.filter((result) => result.status === 'rejected')).toHaveLength(1);
  });
});

function makeStore(
  storage: MemoryStore,
  options: { now?: () => number; workerId?: string } = {},
): PendingLoginStateStore {
  return new PendingLoginStateStore(storage, {
    now: options.now ?? (() => 1_000),
    workerId: options.workerId ?? WORKER_A,
    createAttemptId: () => ATTEMPT_A,
  });
}

type MemoryStore = KeyValueStore & {
  readonly values: Map<string, unknown>;
};

function createMemoryStore(): MemoryStore {
  const values = new Map<string, unknown>();
  return {
    values,
    async get<T>(key: string): Promise<T | undefined> {
      const value = values.get(key);
      return value === undefined ? undefined : structuredClone(value) as T;
    },
    async set(key: string, value: unknown): Promise<void> {
      values.set(key, structuredClone(value));
    },
    async remove(key: string): Promise<void> {
      values.delete(key);
    },
    async clear(): Promise<void> {
      values.clear();
    },
  };
}
