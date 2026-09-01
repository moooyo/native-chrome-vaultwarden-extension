import { describe, expect, it } from 'vitest';
import {
  AUTOFILL_CONTINUATION_STORAGE_KEY,
  AutofillContinuationStore,
  type AutofillContinuationAction,
} from './autofill-continuation-store.js';

const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);

function createMemoryStore() {
  const values = new Map<string, unknown>();
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const value = values.get(key);
      return value === undefined ? undefined : structuredClone(value) as T;
    },
    async set(key: string, value: unknown): Promise<void> {
      values.set(key, structuredClone(value));
    },
    async remove(key: string): Promise<void> { values.delete(key); },
  };
}

function source(tabId = 7) {
  return {
    tabId,
    windowId: 3,
    topDocumentId: 'top-doc',
    topOrigin: 'https://example.com',
    topUrlDigest: DIGEST_A,
    frameId: 2,
    frameDocumentId: 'frame-doc',
    frameOrigin: 'https://login.example.com',
    frameUrlDigest: DIGEST_B,
  } as const;
}

const authority = Object.freeze({
  workerInstanceId: '99999999-9999-4999-8999-999999999999',
  serverUrl: 'https://vault.example.com/',
  accountIdentity: 'user@example.com',
  serverGeneration: 1,
  accountGeneration: 2,
  autofillPolicyGeneration: 3,
  autofillPolicyDigest: 'c'.repeat(64),
  enterprisePolicyGeneration: 4,
  rawPolicyGeneration: 'raw-1',
});

function createEnvelope(store: AutofillContinuationStore, action: AutofillContinuationAction, tabId = 7) {
  return store.create({ source: source(tabId), authority, action });
}

describe('AutofillContinuationStore', () => {
  it('persists only URL origins and digests, not path/query/hash data', async () => {
    const backing = createMemoryStore();
    const store = new AutofillContinuationStore({ store: backing, now: () => 100 });
    await store.put(createEnvelope(store, { kind: 'locked_keyboard' }));

    const raw = JSON.stringify(await backing.get(AUTOFILL_CONTINUATION_STORAGE_KEY));
    expect(raw).not.toContain('/form?token=secret');
    expect(raw).not.toContain('/login?code=secret');
    expect(raw).not.toContain('?');
    expect(raw).toContain(DIGEST_A);
    expect(raw).toContain('https://example.com');
  });

  it('serializes two instances sharing the production backing store so only one take wins', async () => {
    const backing = createMemoryStore();
    const first = new AutofillContinuationStore({ store: backing, now: () => 100 });
    const second = new AutofillContinuationStore({ store: backing, now: () => 100 });
    const envelope = createEnvelope(first, { kind: 'locked_context' });
    await first.put(envelope);
    await first.claimPopup('popup-doc');

    const results = await Promise.all([
      first.take('popup-doc', envelope.continuationId),
      second.take('popup-doc', envelope.continuationId),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await backing.get<{ state: string }>(AUTOFILL_CONTINUATION_STORAGE_KEY)).toMatchObject({
      state: 'consumed',
    });
  });

  it('keeps a newer record when an older tab clear was queued first', async () => {
    const backing = createMemoryStore();
    const first = new AutofillContinuationStore({ store: backing, now: () => 100 });
    const second = new AutofillContinuationStore({ store: backing, now: () => 100 });
    await first.put(createEnvelope(first, { kind: 'locked_context' }, 7));
    const newer = createEnvelope(second, { kind: 'locked_keyboard' }, 9);

    await Promise.all([first.clearForTab(7), second.put(newer)]);

    expect((await first.read())?.continuationId).toBe(newer.continuationId);
  });

  it('binds the first Popup document and refuses a second claimant', async () => {
    const backing = createMemoryStore();
    const first = new AutofillContinuationStore({ store: backing, now: () => 100 });
    const second = new AutofillContinuationStore({ store: backing, now: () => 100 });
    await first.put(createEnvelope(first, { kind: 'locked_context' }));

    const [a, b] = await Promise.all([
      first.claimPopup('popup-a'),
      second.claimPopup('popup-b'),
    ]);
    expect([a, b].filter(Boolean)).toHaveLength(1);
  });

  it('preserves a future schema record while failing closed', async () => {
    const backing = createMemoryStore();
    const store = new AutofillContinuationStore({ store: backing, now: () => 100 });
    const future = { state: 'pending', envelope: { schemaVersion: 2 } };
    await backing.set(AUTOFILL_CONTINUATION_STORAGE_KEY, future);

    expect(await store.read()).toBeUndefined();
    expect(await backing.get(AUTOFILL_CONTINUATION_STORAGE_KEY)).toEqual(future);
  });

  it('canonicalizes command and context-copy continuations without storing secrets', async () => {
    const backing = createMemoryStore();
    const store = new AutofillContinuationStore({ store: backing, now: () => 100 });
    const target = {
      kind: 'card' as const,
      frameId: 2,
      documentId: 'frame-doc',
      formId: 'form-1',
      generation: 1,
      roles: ['number' as const],
    };
    await store.put(createEnvelope(store, {
      kind: 'command_fill_reprompt',
      command: 'autofill-card',
      cipherId: 'cipher-1',
      target,
    }));
    expect((await store.read())?.action).toEqual({
      kind: 'command_fill_reprompt',
      command: 'autofill-card',
      cipherId: 'cipher-1',
      target,
    });

    await store.put(createEnvelope(store, {
      kind: 'context_copy_reprompt',
      cipherId: 'cipher-1',
      field: 'password',
    }));
    const raw = JSON.stringify(await backing.get(AUTOFILL_CONTINUATION_STORAGE_KEY));
    expect(raw).toContain('context_copy_reprompt');
    expect(raw).not.toContain('password-value');
  });

  it('rejects a direct command whose stored target kind does not match', () => {
    const store = new AutofillContinuationStore({ store: createMemoryStore(), now: () => 100 });
    expect(() => createEnvelope(store, {
      kind: 'command_fill_reprompt',
      command: 'autofill-card',
      cipherId: 'cipher-1',
      target: {
        kind: 'login', frameId: 2, documentId: 'frame-doc', formId: 'form-1', generation: 1,
        customPlanDigest: 'plan-digest',
      },
    })).toThrow('command target');
  });
});
