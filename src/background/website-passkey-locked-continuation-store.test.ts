import { describe, expect, it, vi } from 'vitest';
import { canonicalizeWebsitePasskeyRequest } from '../messaging/website-passkey-port.js';
import type { KeyValueStore } from '../platform/store.js';
import {
  WEBSITE_PASSKEY_LOCKED_CONTINUATION_STORAGE_KEY,
  WebsitePasskeyLockedContinuationStore,
} from './website-passkey-locked-continuation-store.js';

const WORKER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const WORKER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const CONTINUATION_A = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const CONTINUATION_B = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const POPUP_A = 'popup-document-a';

function createMemoryStore(): KeyValueStore {
  const values = new Map<string, string>();
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const value = values.get(key);
      return value === undefined ? undefined : JSON.parse(value) as T;
    },
    async set(key, value): Promise<void> { values.set(key, JSON.stringify(value)); },
    async remove(key): Promise<void> { values.delete(key); },
    async clear(): Promise<void> { values.clear(); },
  };
}

const DOCUMENT = Object.freeze({
  tabId: 7,
  frameId: 2,
  documentId: 'website-document',
  url: 'https://login.example.test/frame',
  origin: 'https://login.example.test',
});

const REQUEST = canonicalizeWebsitePasskeyRequest({
  bridgeRequestId: '11111111-1111-4111-8111-111111111111',
  kind: 'get',
  rpId: 'example.test',
  challenge: 'AQID',
  allowCredentials: [],
  userVerification: 'preferred',
  mediation: 'required',
  timeout: 60_000,
});

function input(deadlineAt = 60_100) {
  return {
    document: DOCUMENT,
    request: REQUEST,
    accountIdentity: 'alice@example.test',
    serverUrl: 'https://vault.example.test/',
    policyGeneration: 9,
    deadlineAt,
  } as const;
}

describe('WebsitePasskeyLockedContinuationStore', () => {
  it('persists one exact public request and rejects a conflicting locked request as busy', async () => {
    const backing = createMemoryStore();
    const ids = [CONTINUATION_A, CONTINUATION_B];
    const store = new WebsitePasskeyLockedContinuationStore({
      store: backing,
      workerInstanceId: WORKER_A,
      createId: () => ids.shift() ?? CONTINUATION_B,
      now: () => 100,
    });

    const created = await store.stage(input());
    expect(created).toMatchObject({
      status: 'created',
      envelope: {
        continuationId: CONTINUATION_A,
        workerGeneration: 1,
        operation: 'get',
        document: DOCUMENT,
        request: REQUEST,
      },
    });
    await expect(store.stage(input())).resolves.toMatchObject({
      status: 'existing',
      envelope: { continuationId: CONTINUATION_A },
    });
    await expect(store.stage({ ...input(), document: { ...DOCUMENT, frameId: 3 } }))
      .resolves.toEqual({ status: 'busy' });

    const raw = await backing.get<unknown>(WEBSITE_PASSKEY_LOCKED_CONTINUATION_STORAGE_KEY);
    const serialized = JSON.stringify(raw);
    expect(serialized).toContain('AQID');
    expect(serialized).not.toMatch(/userKey|accessToken|refreshToken|candidate/i);
  });

  it('adopts an exact pending request across worker restart and rejects the stale generation', async () => {
    const backing = createMemoryStore();
    const first = new WebsitePasskeyLockedContinuationStore({
      store: backing,
      workerInstanceId: WORKER_A,
      createId: () => CONTINUATION_A,
      now: () => 100,
    });
    const created = await first.stage(input());

    const restarted = new WebsitePasskeyLockedContinuationStore({
      store: backing,
      workerInstanceId: WORKER_B,
      now: () => 101,
    });
    const generation = await restarted.recoverWorker();
    expect(generation).toBe(2);
    await expect(restarted.find(DOCUMENT, REQUEST)).resolves.toMatchObject({
      state: 'pending',
      envelope: {
        continuationId: CONTINUATION_A,
        workerInstanceId: WORKER_B,
        workerGeneration: 2,
      },
    });

    await expect(first.consume({
      continuationId: CONTINUATION_A,
      workerGeneration: created.status === 'busy' ? 0 : created.envelope.workerGeneration,
      reason: 'resumed',
      document: DOCUMENT,
      bridgeRequestId: REQUEST.bridgeRequestId,
    })).rejects.toThrow(/worker is stale/);
  });

  it('consumes before validating popup ownership and retains a replay tombstone', async () => {
    const backing = createMemoryStore();
    const store = new WebsitePasskeyLockedContinuationStore({
      store: backing,
      workerInstanceId: WORKER_A,
      createId: () => CONTINUATION_A,
      now: () => 100,
    });
    const staged = await store.stage(input());
    if (staged.status === 'busy') throw new Error('expected staged continuation');
    await store.claimPopup(CONTINUATION_A, POPUP_A);

    await expect(store.consume({
      continuationId: CONTINUATION_A,
      workerGeneration: staged.envelope.workerGeneration,
      reason: 'cancelled',
      popupDocumentId: 'wrong-popup-document',
    })).resolves.toBeUndefined();
    await expect(store.readPending()).resolves.toBeUndefined();
    await expect(store.find(DOCUMENT, REQUEST)).resolves.toMatchObject({
      state: 'retired',
      terminal: { reason: 'cancelled', envelope: { continuationId: CONTINUATION_A } },
    });
  });

  it('prevents retired-id ABA until its tombstone expires', async () => {
    const now = 100;
    const ids = [CONTINUATION_A, CONTINUATION_A, CONTINUATION_B];
    const store = new WebsitePasskeyLockedContinuationStore({
      store: createMemoryStore(),
      workerInstanceId: WORKER_A,
      createId: () => ids.shift() ?? CONTINUATION_B,
      retireMs: 10,
      now: () => now,
    });
    const staged = await store.stage(input());
    if (staged.status === 'busy') throw new Error('expected staged continuation');
    await store.consume({
      continuationId: CONTINUATION_A,
      workerGeneration: staged.envelope.workerGeneration,
      reason: 'cancelled',
      document: DOCUMENT,
      bridgeRequestId: REQUEST.bridgeRequestId,
    });

    const second = await store.stage(input());
    expect(second).toMatchObject({ status: 'created', envelope: { continuationId: CONTINUATION_B } });
  });

  it('expires pending state without extending the original request deadline', async () => {
    let now = 100;
    const store = new WebsitePasskeyLockedContinuationStore({
      store: createMemoryStore(),
      workerInstanceId: WORKER_A,
      createId: () => CONTINUATION_A,
      now: () => now,
    });
    await store.stage(input(110));
    now = 110;

    await expect(store.readPending()).resolves.toBeUndefined();
    await expect(store.find(DOCUMENT, REQUEST)).resolves.toMatchObject({
      state: 'retired',
      terminal: { reason: 'expired' },
    });
  });

  it('does not invoke accessor-bearing input while validating a stage request', async () => {
    const getter = vi.fn(() => DOCUMENT);
    const unsafe = { ...input() } as Record<string, unknown>;
    Object.defineProperty(unsafe, 'document', { enumerable: true, get: getter });
    const store = new WebsitePasskeyLockedContinuationStore({
      store: createMemoryStore(),
      workerInstanceId: WORKER_A,
      now: () => 100,
    });

    await expect(store.stage(unsafe as never)).rejects.toThrow(/fields are invalid/);
    expect(getter).not.toHaveBeenCalled();
  });
});
