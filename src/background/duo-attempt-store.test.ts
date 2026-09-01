import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: {}, session: {} } },
}));

import { createMemoryStore } from '../platform/store.js';
import type { KeyValueStore } from '../platform/store.js';
import type { DuoAuthorization } from '../core/session/duo-two-factor.js';
import { DuoAttemptStore, DuoAttemptWriteUncertainError } from './duo-attempt-store.js';

const SERVER = 'https://vault.example/';
const EMAIL = 'user@example.com';
const REDIRECT = 'https://vault.example/duo-redirect-connector.html?client=browser';
const STATE = 'server-state';
const ATTEMPT = '11111111-1111-4111-8111-111111111111';
const WORKER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const WORKER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

const challenge = Object.freeze({
  flow: 'password' as const,
  generation: 7,
  serverUrl: SERVER,
  email: EMAIL,
  provider: 2 as const,
  bindingId: '22222222-2222-4222-8222-222222222222',
});

const authorization: DuoAuthorization = Object.freeze({
  provider: 2,
  authUrl: 'https://api-example.duosecurity.com/oauth/v1/authorize?response_type=code',
  duoHost: 'api-example.duosecurity.com',
  redirectUri: REDIRECT,
  state: STATE,
});
const source = Object.freeze({
  windowId: 5,
  document: Object.freeze({
    tabId: 7,
    windowId: 5,
    documentId: 'source-doc',
    url: 'https://app.example/login',
  }),
});

function makeStore(storage: KeyValueStore, workerId = WORKER_A): DuoAttemptStore {
  return new DuoAttemptStore(storage, {
    now: () => 1_000,
    workerId,
    createAttemptId: () => ATTEMPT,
  });
}

describe('DuoAttemptStore', () => {
  it('binds one exact callback document and allows only one claim', async () => {
    const store = makeStore(createMemoryStore());
    const waiting = await store.create({ challenge, authorization, tabId: 42, remember: true, source });
    const callbackUrl = `${REDIRECT}&code=authorization-code&state=${STATE}`;

    const [claimed, duplicate] = await Promise.all([
      store.claimCallback(waiting.owner, { tabId: 42, documentId: 'doc-a', callbackUrl }),
      store.claimCallback(waiting.owner, { tabId: 42, documentId: 'doc-a', callbackUrl }),
    ]);

    expect(claimed).toMatchObject({
      callback: { token: `authorization-code|${STATE}`, scrubbedUrl: REDIRECT },
      attempt: { status: 'claimed', documentId: 'doc-a', remember: true },
    });
    expect(duplicate).toBeUndefined();
  });

  it('transfers a prior pre-grant claim for scrub-only restart cleanup', async () => {
    const storage = createMemoryStore();
    const first = makeStore(storage);
    const waiting = await first.create({ challenge, authorization, tabId: 42, remember: false, source });
    await first.claimCallback(waiting.owner, {
      tabId: 42,
      documentId: 'doc-a',
      callbackUrl: `${REDIRECT}&code=code&state=${STATE}`,
    });

    await expect(makeStore(storage, WORKER_B).claimRestartCleanup()).resolves.toMatchObject({
      status: 'claimed',
      tabId: 42,
      documentId: 'doc-a',
      workerId: WORKER_A,
    });
    const raw = JSON.stringify(await storage.get('duoTwoFactorAttempt'));
    expect(raw).not.toContain('"code"');
  });

  it('turns a prior in-flight submission into a secret-free unknown marker', async () => {
    const storage = createMemoryStore();
    const first = makeStore(storage);
    const waiting = await first.create({ challenge, authorization, tabId: 42, remember: false, source });
    const claim = await first.claimCallback(waiting.owner, {
      tabId: 42,
      documentId: 'doc-a',
      callbackUrl: `${REDIRECT}&code=code&state=${STATE}`,
    });
    if (!claim) throw new Error('expected claimed Duo attempt');
    await first.startSubmission(claim.attempt.owner);

    await expect(makeStore(storage, WORKER_B).read()).resolves.toMatchObject({
      status: 'outcome_unknown',
    });
    const raw = JSON.stringify(await storage.get('duoTwoFactorAttempt'));
    expect(raw).not.toContain(STATE);
    expect(raw).not.toContain('"authUrl"');
    expect(raw).not.toContain('"code"');
  });

  it('cancels only waiting and rejects callback confusion', async () => {
    const store = makeStore(createMemoryStore());
    const waiting = await store.create({ challenge, authorization, tabId: 42, remember: false, source });
    await expect(store.claimCallback(waiting.owner, {
      tabId: 42,
      documentId: 'doc-a',
      callbackUrl: `${REDIRECT}&code=code&state=wrong`,
    })).rejects.toThrow(/state/);
    await expect(store.cancelWaiting(waiting.owner)).resolves.toBe(true);
    await expect(store.read()).resolves.toBeUndefined();
  });

  it('retires commit-then-reject writes for both create and callback claim', async () => {
    const backing = createMemoryStore();
    let rejectAfterCommit = true;
    const storage: KeyValueStore = {
      get: (key) => backing.get(key),
      set: async (key, value) => {
        await backing.set(key, value);
        if (rejectAfterCommit) throw new Error('committed then rejected');
      },
      remove: vi.fn((key) => backing.remove(key)),
      clear: () => backing.clear(),
    };
    const store = makeStore(storage);
    await expect(store.create({ challenge, authorization, tabId: 42, remember: false, source }))
      .rejects.toThrow(/committed then rejected/);
    await expect(store.read()).resolves.toBeUndefined();

    rejectAfterCommit = false;
    const waiting = await store.create({ challenge, authorization, tabId: 42, remember: false, source });
    rejectAfterCommit = true;
    await expect(store.claimCallback(waiting.owner, {
      tabId: 42,
      documentId: 'doc-a',
      callbackUrl: `${REDIRECT}&code=code&state=${STATE}`,
    })).rejects.toThrow(/committed then rejected/);
    await expect(store.read()).resolves.toMatchObject({
      status: 'waiting',
      owner: waiting.owner,
    });
  });

  it('returns the exact committed owner when the first cleanup also fails', async () => {
    const backing = createMemoryStore();
    let failRemove = true;
    const storage: KeyValueStore = {
      get: (key) => backing.get(key),
      set: async (key, value) => {
        await backing.set(key, value);
        throw new Error('committed then rejected');
      },
      remove: async (key) => {
        if (failRemove) {
          failRemove = false;
          throw new Error('cleanup rejected');
        }
        await backing.remove(key);
      },
      clear: () => backing.clear(),
    };
    const store = makeStore(storage);
    let receipt: DuoAttemptWriteUncertainError | undefined;
    try {
      await store.create({ challenge, authorization, tabId: 42, remember: false, source });
    } catch (error) {
      if (error instanceof DuoAttemptWriteUncertainError) receipt = error;
    }

    expect(receipt).toBeInstanceOf(DuoAttemptWriteUncertainError);
    if (!receipt) throw new Error('expected uncertain Duo write receipt');
    await expect(store.clear(receipt.owner)).resolves.toBe(true);
    await expect(store.read()).resolves.toBeUndefined();
  });

  it('atomically replaces only a waiting attempt for the same challenge owner', async () => {
    const store = makeStore(createMemoryStore());
    const first = await store.create({
      challenge, authorization, tabId: 42, remember: false, source,
    });
    const replacement = await store.createOrReplaceWaiting({
      challenge, authorization, tabId: 43, remember: true, source,
    });

    expect(replacement.replaced?.owner).toEqual(first.owner);
    expect(replacement.attempt).toMatchObject({ tabId: 43, remember: true });
    await expect(store.cancelWaiting(first.owner)).resolves.toBe(false);

    const otherChallenge = { ...challenge, bindingId: '33333333-3333-4333-8333-333333333333' };
    await expect(store.createOrReplaceWaiting({
      challenge: otherChallenge,
      authorization,
      tabId: 44,
      remember: false,
      source,
    })).rejects.toThrow(/different/);
    await expect(store.read()).resolves.toMatchObject({ tabId: 43 });
  });

  it.each(['before', 'after'] as const)(
    'preserves the prior waiting attempt when replacement set rejects %s commit',
    async (phase) => {
      const backing = createMemoryStore();
      let writes = 0;
      const storage: KeyValueStore = {
        get: (key) => backing.get(key),
        set: async (key, value) => {
          writes += 1;
          if (writes === 2 && phase === 'before') throw new Error('replacement rejected');
          await backing.set(key, value);
          if (writes === 2 && phase === 'after') throw new Error('replacement rejected');
        },
        remove: (key) => backing.remove(key),
        clear: () => backing.clear(),
      };
      const store = makeStore(storage);
      const first = await store.create({
        challenge, authorization, tabId: 42, remember: false, source,
      });

      await expect(store.createOrReplaceWaiting({
        challenge, authorization, tabId: 43, remember: true, source,
      })).rejects.toThrow(/replacement rejected/);

      await expect(store.read()).resolves.toMatchObject({
        owner: first.owner,
        tabId: 42,
        remember: false,
      });
    },
  );
});
