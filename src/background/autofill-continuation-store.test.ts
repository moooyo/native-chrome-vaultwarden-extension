import { describe, expect, it } from 'vitest';
import {
  AUTOFILL_CONTINUATION_STORAGE_KEY,
  AutofillContinuationStore,
  type AutofillContinuationAction,
} from './autofill-continuation-store.js';

const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);
const TOP_RUNTIME = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const FRAME_RUNTIME = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

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
    topRuntimeIncarnation: TOP_RUNTIME,
    topOrigin: 'https://example.com',
    topUrlDigest: DIGEST_A,
    frameId: 2,
    frameDocumentId: 'frame-doc',
    frameRuntimeIncarnation: FRAME_RUNTIME,
    frameOrigin: 'https://login.example.com',
    frameUrlDigest: DIGEST_B,
  } as const;
}

function lockedKeyboardSource(tabId = 7) {
  const current = source(tabId);
  return {
    ...current,
    topRuntimeIncarnation: null,
    frameId: 0,
    frameDocumentId: current.topDocumentId,
    frameRuntimeIncarnation: null,
    frameOrigin: current.topOrigin,
    frameUrlDigest: current.topUrlDigest,
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
    await store.put(store.create({
      source: lockedKeyboardSource(),
      authority,
      action: { kind: 'locked_keyboard' },
    }));

    const raw = JSON.stringify(await backing.get(AUTOFILL_CONTINUATION_STORAGE_KEY));
    expect(raw).not.toContain('/form?token=secret');
    expect(raw).not.toContain('/login?code=secret');
    expect(raw).not.toContain('?');
    expect(raw).toContain(DIGEST_A);
    expect(raw).toContain('https://example.com');
    expect(raw).toContain('"topRuntimeIncarnation":null');
    expect(raw).toContain('"frameRuntimeIncarnation":null');
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
    const newer = second.create({
      source: lockedKeyboardSource(9),
      authority,
      action: { kind: 'locked_keyboard' },
    });

    await Promise.all([first.clearForTab(7), second.put(newer)]);

    expect((await first.read())?.continuationId).toBe(newer.continuationId);
  });

  it('clears only the exact continuation without deleting a replacement', async () => {
    const backing = createMemoryStore();
    const store = new AutofillContinuationStore({ store: backing, now: () => 100 });
    const first = createEnvelope(store, { kind: 'locked_context' });
    const replacement = createEnvelope(store, { kind: 'locked_context' });
    await store.put(replacement);

    expect(await store.clearExact(first.continuationId)).toBe(false);
    expect((await store.read())?.continuationId).toBe(replacement.continuationId);
    expect(await store.clearExact(replacement.continuationId)).toBe(true);
    expect(await store.read()).toBeUndefined();
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
    const future = { state: 'pending', envelope: { schemaVersion: 3 } };
    await backing.set(AUTOFILL_CONTINUATION_STORAGE_KEY, future);

    expect(await store.read()).toBeUndefined();
    expect(await backing.get(AUTOFILL_CONTINUATION_STORAGE_KEY)).toEqual(future);
  });

  it('removes a legacy schema record instead of reviving it without runtime bindings', async () => {
    const backing = createMemoryStore();
    const store = new AutofillContinuationStore({ store: backing, now: () => 100 });
    await backing.set(AUTOFILL_CONTINUATION_STORAGE_KEY, {
      state: 'pending',
      envelope: { schemaVersion: 1 },
    });

    expect(await store.read()).toBeUndefined();
    expect(await backing.get(AUTOFILL_CONTINUATION_STORAGE_KEY)).toBeUndefined();
  });

  it('canonicalizes command and context-copy continuations without storing secrets', async () => {
    const backing = createMemoryStore();
    const store = new AutofillContinuationStore({ store: backing, now: () => 100 });
    const target = {
      kind: 'card' as const,
      frameId: 2,
      documentId: 'frame-doc',
      runtimeIncarnation: FRAME_RUNTIME,
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

  it('requires lowercase canonical UUID v4 runtime bindings and exact action-source ownership', () => {
    const store = new AutofillContinuationStore({ store: createMemoryStore(), now: () => 100 });
    expect(() => store.create({
      source: { ...source(), frameRuntimeIncarnation: FRAME_RUNTIME.toUpperCase() },
      authority,
      action: { kind: 'locked_context' },
    })).toThrow('frameRuntimeIncarnation');

    expect(() => createEnvelope(store, { kind: 'locked_keyboard' })).toThrow('action source');
    expect(() => store.create({
      source: lockedKeyboardSource(),
      authority,
      action: { kind: 'locked_context' },
    })).toThrow('action source');

    expect(() => createEnvelope(store, {
      kind: 'context_login_reprompt',
      cipherId: 'cipher-1',
      target: {
        kind: 'login',
        frameId: 2,
        documentId: 'frame-doc',
        runtimeIncarnation: TOP_RUNTIME,
        formId: 'form-1',
        generation: 1,
        customPlanDigest: 'plan-digest',
      },
    })).toThrow('action source');

    expect(() => createEnvelope(store, {
      kind: 'keyboard_reprompt',
      cipherId: 'cipher-1',
      binding: { purpose: 'totp', runtimeIncarnation: TOP_RUNTIME },
    })).toThrow('action source');
  });

  it('rejects a direct command whose stored target kind does not match', () => {
    const store = new AutofillContinuationStore({ store: createMemoryStore(), now: () => 100 });
    expect(() => createEnvelope(store, {
      kind: 'command_fill_reprompt',
      command: 'autofill-card',
      cipherId: 'cipher-1',
      target: {
        kind: 'login', frameId: 2, documentId: 'frame-doc', runtimeIncarnation: FRAME_RUNTIME,
        formId: 'form-1', generation: 1,
        customPlanDigest: 'plan-digest',
      },
    })).toThrow('command target');
  });
});
