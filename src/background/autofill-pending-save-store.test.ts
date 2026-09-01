import { describe, expect, it } from 'vitest';
import type { SymmetricKey } from '../core/crypto/keys.js';
import type { KeyValueStore } from '../platform/store.js';
import {
  AUTOFILL_PENDING_SAVE_ALARM,
  AUTOFILL_PENDING_SAVE_STORAGE_KEY,
  AUTOFILL_PENDING_SAVE_ENVELOPE_MAX_UTF8_BYTES,
  AUTOFILL_PENDING_SAVE_SCHEMA_VERSION,
  DEFAULT_AUTOFILL_PENDING_SAVE_CAPACITY,
  MAX_AUTOFILL_PENDING_SAVE_CAPACITY,
  AutofillPendingSaveStore,
  type AutofillPendingSaveDecision,
  type AutofillPendingSaveDocumentContext,
  type AutofillPendingSaveInput,
} from './autofill-pending-save-store.js';

it('reserves no more than 1 MiB and 64 entries of shared storage.session', () => {
  expect(AUTOFILL_PENDING_SAVE_ENVELOPE_MAX_UTF8_BYTES).toBe(1024 * 1024);
  expect(DEFAULT_AUTOFILL_PENDING_SAVE_CAPACITY).toBe(32);
  expect(MAX_AUTOFILL_PENDING_SAVE_CAPACITY).toBe(64);
});

it('uses a dedicated pending-save expiry alarm', () => {
  expect(AUTOFILL_PENDING_SAVE_ALARM).toBe('autofillPendingSaves.expiry');
});

interface InspectableStore extends Pick<KeyValueStore, 'get' | 'set'> {
  peek(key: string): unknown;
}

function createMemoryStore(): InspectableStore {
  const values = new Map<string, unknown>();
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const value = values.get(key);
      return value === undefined ? undefined : structuredClone(value) as T;
    },
    async set(key: string, value: unknown): Promise<void> {
      values.set(key, structuredClone(value));
    },
    peek(key: string): unknown {
      const value = values.get(key);
      return value === undefined ? undefined : structuredClone(value);
    },
  };
}

const BINDING = {
  sessionGeneration: 3,
  sessionBindingId: 'session-binding-A',
  serverGeneration: 4,
  accountGeneration: 5,
  serverUrl: 'https://vault.example.test/',
  accountIdentity: 'person@example.test',
  policyGeneration: 6,
  enterprisePolicyGeneration: 7,
  enterprisePolicyRawGeneration: 'enterprise-raw-generation-A',
} as const;

const RUNTIME_A = 'a0000000-0000-4000-8000-000000000001';
const RUNTIME_B = 'b0000000-0000-4000-8000-000000000002';

const INPUT: AutofillPendingSaveInput = {
  tabId: 7,
  frameId: 0,
  sourceDocumentId: 'source-document',
  runtimeIncarnation: RUNTIME_A,
  sourceUrl: 'https://login.example.test/sign-in?flow=1',
  origin: 'https://login.example.test',
  ...BINDING,
};

const CONTEXT: AutofillPendingSaveDocumentContext = {
  tabId: 7,
  frameId: 0,
  documentId: 'destination-document',
  runtimeIncarnation: RUNTIME_A,
  frameUrl: 'https://login.example.test/complete',
  origin: 'https://login.example.test',
  ...BINDING,
};

const CREDENTIALS = {
  username: 'submitted-user@example.test',
  password: 'correct horse battery staple',
} as const;

const UPDATE: AutofillPendingSaveDecision = {
  action: 'update',
  cipherId: 'cipher-secret-id',
  name: 'Personal account',
};

function userKey(seed = 1): SymmetricKey {
  return {
    encKey: new Uint8Array(32).fill(seed),
    macKey: new Uint8Array(32).fill(seed + 1),
  };
}

function expectZeroed(key: SymmetricKey): void {
  expect([...key.encKey]).toEqual(new Array(32).fill(0));
  expect([...key.macKey]).toEqual(new Array(32).fill(0));
}

function idGenerator(start = 0): () => string {
  let sequence = start;
  return () => `00000000-0000-4000-8000-${String(++sequence).padStart(12, '0')}`;
}

let storageSequence = 0;

function fixture(overrides: {
  store?: InspectableStore;
  now?: () => number;
  ttlMs?: number;
  claimLeaseMs?: number;
  maxEntries?: number;
  createId?: () => string;
  randomBytes?: (length: number) => Uint8Array;
  storageKey?: string;
  scheduler?: {
    schedule(when: number): void | Promise<void>;
    cancel(): void | Promise<void>;
  };
} = {}) {
  const store = overrides.store ?? createMemoryStore();
  const storageKey = overrides.storageKey ?? `pending-save-test-${++storageSequence}`;
  const createId = overrides.createId ?? idGenerator();
  const make = () => new AutofillPendingSaveStore({
    store,
    storageKey,
    createId,
    ...(overrides.now ? { now: overrides.now } : {}),
    ...(overrides.ttlMs === undefined ? {} : { ttlMs: overrides.ttlMs }),
    ...(overrides.claimLeaseMs === undefined ? {} : { claimLeaseMs: overrides.claimLeaseMs }),
    ...(overrides.maxEntries === undefined ? {} : { maxEntries: overrides.maxEntries }),
    ...(overrides.randomBytes ? { randomBytes: overrides.randomBytes } : {}),
    ...(overrides.scheduler ? { scheduler: overrides.scheduler } : {}),
  });
  return { store, storageKey, make };
}

async function put(pending: AutofillPendingSaveStore, input = INPUT): Promise<void> {
  await pending.put(input, CREDENTIALS, userKey());
}

async function claim(
  pending: AutofillPendingSaveStore,
  context = CONTEXT,
  decision: AutofillPendingSaveDecision = UPDATE,
) {
  return pending.claim(context, userKey(), async (credentials, sourceUrl) => {
    expect(credentials).toEqual(CREDENTIALS);
    expect(sourceUrl).toBe(INPUT.sourceUrl);
    return decision;
  });
}

function rawEnvelope(store: InspectableStore, storageKey: string): {
  schemaVersion: number;
  revision: number;
  entries: Array<Record<string, unknown>>;
} {
  return store.peek(storageKey) as {
    schemaVersion: number;
    revision: number;
    entries: Array<Record<string, unknown>>;
  };
}

describe('AutofillPendingSaveStore', () => {
  it('quarantines encrypted credentials until exact confirmation survives restart', async () => {
    const f = fixture();
    const stagedKey = userKey();
    const metadata = await f.make().putUnconfirmed(INPUT, CREDENTIALS, stagedKey);
    expectZeroed(stagedKey);
    expect(metadata).toMatchObject({
      captureId: expect.stringMatching(/^[0-9a-f-]{36}$/),
      tabId: INPUT.tabId,
      frameId: INPUT.frameId,
      sourceDocumentId: INPUT.sourceDocumentId,
      runtimeIncarnation: INPUT.runtimeIncarnation,
      sourceUrl: INPUT.sourceUrl,
    });
    expect(JSON.stringify(f.store.peek(f.storageKey))).not.toContain(CREDENTIALS.password);
    expect(rawEnvelope(f.store, f.storageKey).entries[0]).toMatchObject({
      state: 'unconfirmed',
      confirmation: 'unconfirmed',
    });
    await expect(claim(f.make())).resolves.toEqual({ action: 'none' });
    await expect(f.make().listUnconfirmed()).resolves.toEqual([metadata]);
    await expect(f.make().captureState(metadata.captureId)).resolves.toBe('unconfirmed');

    const confirmKey = userKey();
    await expect(f.make().confirmUnconfirmed(metadata, confirmKey)).resolves.toBe(true);
    expectZeroed(confirmKey);
    await expect(f.make().captureState(metadata.captureId)).resolves.toBe('confirmed');
    expect(rawEnvelope(f.store, f.storageKey).entries[0]).toMatchObject({
      state: 'pending',
      confirmation: 'confirmed',
    });
    await expect(claim(f.make())).resolves.toMatchObject({ action: 'update' });
  });

  it('rejects metadata substitution and unauthenticated state promotion', async () => {
    const f = fixture();
    const metadata = await f.make().putUnconfirmed(INPUT, CREDENTIALS, userKey());
    const wrongKey = userKey();
    await expect(f.make().confirmUnconfirmed({
      ...metadata,
      sourceUrl: 'https://login.example.test/other',
    }, wrongKey)).resolves.toBe(false);
    expectZeroed(wrongKey);

    const envelope = rawEnvelope(f.store, f.storageKey);
    envelope.entries[0]!.state = 'pending';
    envelope.entries[0]!.confirmation = 'confirmed';
    await f.store.set(f.storageKey, envelope);
    await expect(claim(f.make())).resolves.toEqual({ action: 'none' });
    expect(rawEnvelope(f.store, f.storageKey).entries).toEqual([]);
  });

  it('zeroes the owned key when confirmation metadata is malformed', async () => {
    const f = fixture();
    const metadata = await f.make().putUnconfirmed(INPUT, CREDENTIALS, userKey());
    const key = userKey();

    await expect(f.make().confirmUnconfirmed({
      ...metadata,
      captureId: 'not-a-capture-id',
    }, key)).rejects.toMatchObject({ code: 'invalid_input' });
    expectZeroed(key);
  });

  it('checks the confirmation fence immediately before durable promotion', async () => {
    const f = fixture();
    const metadata = await f.make().putUnconfirmed(INPUT, CREDENTIALS, userKey());
    const staleKey = userKey();
    const fenceChanged = new Error('before-request admission entered');

    await expect(f.make().confirmUnconfirmed(metadata, staleKey, () => {
      expect(rawEnvelope(f.store, f.storageKey).entries[0]).toMatchObject({
        state: 'unconfirmed',
        confirmation: 'unconfirmed',
      });
      throw fenceChanged;
    })).rejects.toBe(fenceChanged);
    expectZeroed(staleKey);
    await expect(f.make().captureState(metadata.captureId)).resolves.toBe('unconfirmed');

    let checks = 0;
    await expect(f.make().confirmUnconfirmed(metadata, userKey(), () => {
      checks += 1;
      expect(rawEnvelope(f.store, f.storageKey).entries[0]).toMatchObject({
        state: checks === 1 ? 'unconfirmed' : 'pending',
      });
    })).resolves.toBe(true);
    expect(checks).toBe(2);
    await expect(f.make().captureState(metadata.captureId)).resolves.toBe('confirmed');
  });

  it('rolls back a promotion whose fence changes while storage is committing', async () => {
    const baseStore = createMemoryStore();
    let promotionWriteEntered!: () => void;
    const promotionWrite = new Promise<void>((resolve) => { promotionWriteEntered = resolve; });
    let releasePromotionWrite!: () => void;
    const releasePromotion = new Promise<void>((resolve) => { releasePromotionWrite = resolve; });
    let blockPromotion = true;
    const store: InspectableStore = {
      get: baseStore.get.bind(baseStore),
      peek: baseStore.peek.bind(baseStore),
      async set(key, value): Promise<void> {
        await baseStore.set(key, value);
        if (blockPromotion && JSON.stringify(value).includes('"confirmation":"confirmed"')) {
          blockPromotion = false;
          promotionWriteEntered();
          await releasePromotion;
        }
      },
    };
    const f = fixture({ store });
    const metadata = await f.make().putUnconfirmed(INPUT, CREDENTIALS, userKey());
    const fenceChanged = new Error('before-request admission entered');
    let fenceCurrent = true;
    const confirmation = f.make().confirmUnconfirmed(metadata, userKey(), () => {
      if (!fenceCurrent) throw fenceChanged;
    });
    await promotionWrite;
    const competingClaim = claim(f.make());
    fenceCurrent = false;
    releasePromotionWrite();

    await expect(confirmation).rejects.toBe(fenceChanged);
    await expect(competingClaim).resolves.toEqual({ action: 'none' });
    await expect(f.make().captureState(metadata.captureId)).resolves.toBe('unconfirmed');
    expect(rawEnvelope(store, f.storageKey).entries[0]).toMatchObject({
      state: 'unconfirmed',
      confirmation: 'unconfirmed',
    });
  });

  it('leaves every pending-save mutation unchanged when its commit fence changes', async () => {
    const fenceChanged = new Error('runtime fence changed');
    const rejectCommit = () => { throw fenceChanged; };

    const putFixture = fixture();
    const putKey = userKey();
    await expect(putFixture.make().putUnconfirmed(
      INPUT,
      CREDENTIALS,
      putKey,
      rejectCommit,
    )).rejects.toBe(fenceChanged);
    expectZeroed(putKey);
    expect(putFixture.store.peek(putFixture.storageKey)).toBeUndefined();

    const f = fixture();
    await put(f.make());
    const claimKey = userKey();
    await expect(f.make().claim(
      CONTEXT,
      claimKey,
      async () => UPDATE,
      undefined,
      rejectCommit,
    )).rejects.toBe(fenceChanged);
    expectZeroed(claimKey);
    expect(rawEnvelope(f.store, f.storageKey).entries[0]).toMatchObject({ state: 'pending' });

    const prompt = await claim(f.make());
    if (prompt.action !== 'update') throw new Error('expected update prompt');
    const takeKey = userKey();
    await expect(f.make().take(
      prompt.promptId,
      CONTEXT,
      takeKey,
      rejectCommit,
    )).rejects.toBe(fenceChanged);
    expectZeroed(takeKey);
    expect(rawEnvelope(f.store, f.storageKey).entries[0]).toMatchObject({ state: 'claimed' });

    await expect(f.make().dismiss(
      prompt.promptId,
      CONTEXT,
      rejectCommit,
    )).rejects.toBe(fenceChanged);
    expect(rawEnvelope(f.store, f.storageKey).entries[0]).toMatchObject({ state: 'claimed' });
    await expect(f.make().take(prompt.promptId, CONTEXT, userKey())).resolves.toMatchObject({
      credentials: CREDENTIALS,
      decision: UPDATE,
    });
  });

  it('discards an exact capture in any phase and never affects another slot', async () => {
    const f = fixture();
    const first = await f.make().putUnconfirmed(INPUT, CREDENTIALS, userKey());
    const second = await f.make().putUnconfirmed({
      ...INPUT,
      tabId: 8,
      sourceDocumentId: 'other-document',
    }, CREDENTIALS, userKey());

    await expect(f.make().discardCapture(first.captureId)).resolves.toBe(true);
    await expect(f.make().discardCapture(first.captureId)).resolves.toBe(false);
    await expect(f.make().captureState(second.captureId)).resolves.toBe('unconfirmed');
  });

  it('restores an encrypted claimed decision after restart and exposes only public metadata', async () => {
    const f = fixture();
    await put(f.make());

    const publicPrompt = await claim(f.make());
    expect(publicPrompt).toMatchObject({
      action: 'update',
      promptId: expect.stringMatching(/^[0-9a-f-]{36}$/),
      name: UPDATE.action === 'update' ? UPDATE.name : '',
    });
    expect(publicPrompt).not.toHaveProperty('cipherId');
    expect(publicPrompt).not.toHaveProperty('credentials');
    if (publicPrompt.action !== 'update') throw new Error('expected update prompt');
    const storedClaim = rawEnvelope(f.store, f.storageKey).entries[0]!;
    expect(storedClaim.decisionIv).toEqual(expect.any(String));
    expect(storedClaim.decisionCiphertext).toEqual(expect.any(String));

    const restarted = f.make();
    const taken = await restarted.take(publicPrompt.promptId, CONTEXT, userKey());
    expect(taken).toEqual({
      credentials: CREDENTIALS,
      sourceUrl: INPUT.sourceUrl,
      decision: UPDATE,
    });
  });

  it('claims only the exact requested capture without letting another entry acknowledge it', async () => {
    const f = fixture();
    const firstInput = {
      ...INPUT,
      sourceDocumentId: 'source-document-A',
      sourceUrl: 'https://login.example.test/sign-in?flow=A',
    };
    const secondInput = {
      ...INPUT,
      sourceDocumentId: 'source-document-B',
      runtimeIncarnation: RUNTIME_B,
      sourceUrl: 'https://login.example.test/sign-in?flow=B',
    };
    const first = await f.make().putUnconfirmed(firstInput, CREDENTIALS, userKey());
    const second = await f.make().putUnconfirmed(secondInput, CREDENTIALS, userKey());
    await expect(f.make().confirmUnconfirmed(first, userKey())).resolves.toBe(true);
    await expect(f.make().confirmUnconfirmed(second, userKey())).resolves.toBe(true);

    const evaluatedSources: string[] = [];
    const prompt = await f.make().claim(CONTEXT, userKey(), async (_credentials, sourceUrl) => {
      evaluatedSources.push(sourceUrl);
      return UPDATE;
    }, first.captureId);
    expect(prompt).toMatchObject({ action: 'update' });
    expect(evaluatedSources).toEqual([firstInput.sourceUrl]);

    await expect(f.make().claim(
      CONTEXT,
      userKey(),
      async () => { throw new Error('unknown capture must not be evaluated'); },
      'f0000000-0000-4000-8000-000000000099',
    )).resolves.toEqual({ action: 'none' });
    await expect(f.make().captureState(second.captureId)).resolves.toBe('confirmed');

    if (prompt.action !== 'update') throw new Error('expected update prompt');
    await expect(f.make().take(prompt.promptId, CONTEXT, userKey())).resolves.toMatchObject({
      sourceUrl: firstInput.sourceUrl,
    });
    await expect(f.make().claim(
      CONTEXT,
      userKey(),
      async () => UPDATE,
      second.captureId,
    )).resolves.toMatchObject({ action: 'update' });
  });

  it('never persists credential plaintext or decision action, name, or cipher id', async () => {
    const f = fixture();
    await put(f.make());
    const beforeClaim = JSON.stringify(f.store.peek(f.storageKey));
    expect(beforeClaim).not.toContain(CREDENTIALS.username);
    expect(beforeClaim).not.toContain(CREDENTIALS.password);

    const prompt = await claim(f.make());
    expect(prompt.action).toBe('update');
    const afterClaim = JSON.stringify(f.store.peek(f.storageKey));
    expect(afterClaim).not.toContain(CREDENTIALS.username);
    expect(afterClaim).not.toContain(CREDENTIALS.password);
    expect(afterClaim).not.toContain(UPDATE.action === 'update' ? UPDATE.name : '');
    expect(afterClaim).not.toContain(UPDATE.action === 'update' ? UPDATE.cipherId : '');
    const storedClaim = rawEnvelope(f.store, f.storageKey).entries[0]!;
    expect(storedClaim).not.toHaveProperty('action');
    expect(storedClaim).not.toHaveProperty('name');
    expect(storedClaim).not.toHaveProperty('suggestedName');
    expect(storedClaim).not.toHaveProperty('cipherId');
    expect(Object.keys(rawEnvelope(f.store, f.storageKey)).sort()).toEqual([
      'entries', 'revision', 'schemaVersion',
    ]);
  });

  it('returns a same-document claim without evaluating it again', async () => {
    const f = fixture();
    await put(f.make());
    let evaluations = 0;
    const evaluate = async () => {
      evaluations += 1;
      return UPDATE;
    };

    const first = await f.make().claim(CONTEXT, userKey(), evaluate);
    const idempotent = await f.make().claim(CONTEXT, userKey(), evaluate);

    expect(first).toMatchObject({ action: 'update' });
    expect(idempotent).toEqual(first);
    expect(evaluations).toBe(1);
  });

  it.each([
    ['source document', (entry: Record<string, unknown>) => { entry.sourceDocumentId = 'tampered-source'; }, CONTEXT],
    ['runtime incarnation', (entry: Record<string, unknown>) => { entry.runtimeIncarnation = RUNTIME_B; }, { ...CONTEXT, runtimeIncarnation: RUNTIME_B }],
    ['exact source URL', (entry: Record<string, unknown>) => { entry.sourceUrl = 'https://login.example.test/other'; }, CONTEXT],
    ['session binding', (entry: Record<string, unknown>) => { entry.sessionBindingId = 'session-binding-B'; }, { ...CONTEXT, sessionBindingId: 'session-binding-B' }],
    ['session generation', (entry: Record<string, unknown>) => { entry.sessionGeneration = 30; }, { ...CONTEXT, sessionGeneration: 30 }],
    ['server generation', (entry: Record<string, unknown>) => { entry.serverGeneration = 40; }, { ...CONTEXT, serverGeneration: 40 }],
    ['account generation', (entry: Record<string, unknown>) => { entry.accountGeneration = 50; }, { ...CONTEXT, accountGeneration: 50 }],
    ['policy generation', (entry: Record<string, unknown>) => { entry.policyGeneration = 60; }, { ...CONTEXT, policyGeneration: 60 }],
    ['enterprise policy generation', (entry: Record<string, unknown>) => { entry.enterprisePolicyGeneration = 70; }, { ...CONTEXT, enterprisePolicyGeneration: 70 }],
    ['enterprise policy raw generation', (entry: Record<string, unknown>) => { entry.enterprisePolicyRawGeneration = 'enterprise-raw-generation-B'; }, { ...CONTEXT, enterprisePolicyRawGeneration: 'enterprise-raw-generation-B' }],
  ] as const)('rejects an AAD %s mutation', async (_label, mutate, context) => {
    const f = fixture();
    await put(f.make());
    const envelope = rawEnvelope(f.store, f.storageKey);
    mutate(envelope.entries[0]!);
    await f.store.set(f.storageKey, envelope);

    await expect(claim(f.make(), context)).resolves.toEqual({ action: 'none' });
    expect(rawEnvelope(f.store, f.storageKey).entries).toEqual([]);
  });

  it('rejects credential ciphertext, decision ciphertext, and decision-tag tampering', async () => {
    const ciphertextFixture = fixture();
    await put(ciphertextFixture.make());
    const encrypted = rawEnvelope(ciphertextFixture.store, ciphertextFixture.storageKey);
    const ciphertext = encrypted.entries[0]!.ciphertext as string;
    encrypted.entries[0]!.ciphertext = `${ciphertext[0] === 'A' ? 'B' : 'A'}${ciphertext.slice(1)}`;
    await ciphertextFixture.store.set(ciphertextFixture.storageKey, encrypted);
    await expect(claim(ciphertextFixture.make())).resolves.toEqual({ action: 'none' });

    const decisionFixture = fixture();
    await put(decisionFixture.make());
    const decisionPrompt = await claim(decisionFixture.make());
    if (decisionPrompt.action !== 'update') throw new Error('expected update prompt');
    const decisionEnvelope = rawEnvelope(decisionFixture.store, decisionFixture.storageKey);
    const decisionCiphertext = decisionEnvelope.entries[0]!.decisionCiphertext as string;
    decisionEnvelope.entries[0]!.decisionCiphertext =
      `${decisionCiphertext[0] === 'A' ? 'B' : 'A'}${decisionCiphertext.slice(1)}`;
    await decisionFixture.store.set(decisionFixture.storageKey, decisionEnvelope);
    await expect(decisionFixture.make().take(
      decisionPrompt.promptId,
      CONTEXT,
      userKey(),
    )).resolves.toBeUndefined();
    expect(rawEnvelope(decisionFixture.store, decisionFixture.storageKey).entries).toEqual([]);

    const tagFixture = fixture();
    await put(tagFixture.make());
    const prompt = await claim(tagFixture.make());
    if (prompt.action !== 'update') throw new Error('expected update prompt');
    const claimed = rawEnvelope(tagFixture.store, tagFixture.storageKey);
    const tag = claimed.entries[0]!.decisionTag as string;
    claimed.entries[0]!.decisionTag = `${tag[0] === 'A' ? 'B' : 'A'}${tag.slice(1)}`;
    await tagFixture.store.set(tagFixture.storageKey, claimed);
    await expect(tagFixture.make().take(
      prompt.promptId,
      CONTEXT,
      userKey(),
    )).resolves.toBeUndefined();
    expect(rawEnvelope(tagFixture.store, tagFixture.storageKey).entries).toEqual([]);
  });

  it.each([
    null,
    true,
    {},
    { schemaVersion: 1, revision: 1, entries: [] },
    { schemaVersion: 3, revision: 1, entries: [] },
    { schemaVersion: 4, revision: 1, entries: [], extra: true },
    { schemaVersion: 2, revision: '1', entries: [] },
    { schemaVersion: 99, revision: 7, entries: [] },
    { schemaVersion: 2, revision: 8, entries: [{ password: 'plaintext-must-not-parse' }] },
  ])('purges malformed storage through a fresh strict envelope: %j', async (malformed) => {
    const f = fixture();
    await f.store.set(f.storageKey, malformed);
    const key = userKey();

    await expect(f.make().claim(CONTEXT, key, async () => UPDATE)).resolves.toEqual({ action: 'none' });
    expectZeroed(key);
    const recovered = rawEnvelope(f.store, f.storageKey);
    expect(Object.keys(recovered).sort()).toEqual(['entries', 'revision', 'schemaVersion']);
    expect(recovered.schemaVersion).toBe(AUTOFILL_PENDING_SAVE_SCHEMA_VERSION);
    expect(recovered.entries).toEqual([]);
  });

  it('expires entries at the TTL boundary and prunes them durably', async () => {
    let now = 100;
    const f = fixture({ now: () => now, ttlMs: 10, claimLeaseMs: 5 });
    await put(f.make());
    now = 110;

    await expect(claim(f.make())).resolves.toEqual({ action: 'none' });
    expect(rawEnvelope(f.store, f.storageKey).entries).toEqual([]);
  });

  it('retains only the newest entries within configured capacity', async () => {
    let now = 100;
    const f = fixture({ now: () => now, maxEntries: 2 });
    const pending = f.make();
    await put(pending, { ...INPUT, tabId: 1, sourceDocumentId: 'doc-1' });
    now += 1;
    await put(pending, { ...INPUT, tabId: 2, sourceDocumentId: 'doc-2' });
    now += 1;
    await put(pending, { ...INPUT, tabId: 3, sourceDocumentId: 'doc-3' });

    expect(rawEnvelope(f.store, f.storageKey).entries).toHaveLength(2);
    await expect(claim(f.make(), { ...CONTEXT, tabId: 1 })).resolves.toEqual({ action: 'none' });
    await expect(claim(f.make(), { ...CONTEXT, tabId: 2 })).resolves.toMatchObject({ action: 'update' });
    await expect(claim(f.make(), { ...CONTEXT, tabId: 3 })).resolves.toMatchObject({ action: 'update' });
  });

  it('serializes concurrent read-modify-write operations across store instances', async () => {
    const f = fixture();
    const first = f.make();
    const second = f.make();
    await Promise.all([
      put(first, { ...INPUT, tabId: 1, sourceDocumentId: 'doc-1' }),
      put(second, { ...INPUT, tabId: 2, sourceDocumentId: 'doc-2' }),
    ]);
    const afterWrites = rawEnvelope(f.store, f.storageKey);
    expect(afterWrites.entries).toHaveLength(2);

    const destination = { ...CONTEXT, tabId: 1 };
    const [left, right] = await Promise.all([
      claim(first, destination),
      claim(second, destination),
    ]);
    expect(left).toMatchObject({ action: 'update' });
    expect(right).toEqual(left);
    expect(rawEnvelope(f.store, f.storageKey).revision).toBeGreaterThan(afterWrites.revision);
  });

  it('leases a prompt to one document, then rotates the prompt when another document reclaims it', async () => {
    let now = 1_000;
    const f = fixture({ now: () => now, claimLeaseMs: 5 });
    await put(f.make());
    let evaluations = 0;
    const first = await f.make().claim(
      { ...CONTEXT, documentId: 'document-A' },
      userKey(),
      async () => {
        evaluations += 1;
        return UPDATE;
      },
    );
    if (first.action !== 'update') throw new Error('expected first prompt');

    await expect(f.make().claim(
      { ...CONTEXT, documentId: 'document-B' },
      userKey(),
      async () => {
        evaluations += 1;
        return UPDATE;
      },
    )).resolves.toEqual({
      action: 'retry',
      retryAfterMs: 5,
    });
    expect(evaluations).toBe(1);
    now += 5;
    const reclaimed = await f.make().claim(
      { ...CONTEXT, documentId: 'document-B' },
      userKey(),
      async () => {
        evaluations += 1;
        return UPDATE;
      },
    );
    if (reclaimed.action !== 'update') throw new Error('expected reclaimed prompt');
    expect(reclaimed.promptId).not.toBe(first.promptId);
    expect(evaluations).toBe(2);

    await expect(f.make().take(
      first.promptId,
      { ...CONTEXT, documentId: 'document-A' },
      userKey(),
    )).resolves.toBeUndefined();
    await expect(f.make().take(
      reclaimed.promptId,
      { ...CONTEXT, documentId: 'document-B' },
      userKey(),
    )).resolves.toMatchObject({ credentials: CREDENTIALS, decision: UPDATE });
  });

  it('fences a BFCache runtime from reusing a same-document claim', async () => {
    let now = 1_000;
    const f = fixture({ now: () => now, claimLeaseMs: 5 });
    await put(f.make());
    const runtimeAContext = {
      ...CONTEXT,
      documentId: 'shared-bfcache-document',
      runtimeIncarnation: RUNTIME_A,
    };
    const runtimeBContext = {
      ...runtimeAContext,
      runtimeIncarnation: RUNTIME_B,
    };
    const first = await claim(f.make(), runtimeAContext);
    if (first.action !== 'update') throw new Error('expected first prompt');

    await expect(claim(f.make(), runtimeBContext)).resolves.toEqual({
      action: 'retry',
      retryAfterMs: 5,
    });
    await expect(f.make().take(first.promptId, runtimeBContext, userKey())).resolves.toBeUndefined();
    await expect(f.make().dismiss(first.promptId, runtimeBContext)).resolves.toBe(false);

    now += 5;
    const reclaimed = await claim(f.make(), runtimeBContext);
    if (reclaimed.action !== 'update') throw new Error('expected reclaimed prompt');
    expect(reclaimed.promptId).not.toBe(first.promptId);
    await expect(f.make().take(first.promptId, runtimeAContext, userKey())).resolves.toBeUndefined();
    await expect(f.make().take(reclaimed.promptId, runtimeBContext, userKey())).resolves.toMatchObject({
      credentials: CREDENTIALS,
      decision: UPDATE,
    });
  });

  it('lets the claimant act after the short lease when no newer document reclaimed it', async () => {
    let now = 1_000;
    const f = fixture({ now: () => now, claimLeaseMs: 5 });
    await put(f.make());
    const prompt = await claim(f.make());
    if (prompt.action !== 'update') throw new Error('expected update prompt');
    now += 30_000;

    await expect(f.make().take(
      prompt.promptId,
      CONTEXT,
      userKey(),
    )).resolves.toMatchObject({ credentials: CREDENTIALS, decision: UPDATE });
  });

  it('claims across source and destination documents but rejects other browser and security scopes', async () => {
    const accepted = fixture();
    await put(accepted.make(), { ...INPUT, sourceDocumentId: 'old-document' });
    await expect(claim(accepted.make(), { ...CONTEXT, documentId: 'new-document' }))
      .resolves.toMatchObject({ action: 'update' });

    const mismatches: AutofillPendingSaveDocumentContext[] = [
      { ...CONTEXT, tabId: 8 },
      { ...CONTEXT, frameId: 1 },
      {
        ...CONTEXT,
        origin: 'https://other.example.test',
        frameUrl: 'https://other.example.test/complete',
      },
      { ...CONTEXT, sessionGeneration: 30 },
      { ...CONTEXT, sessionBindingId: 'other-session' },
      { ...CONTEXT, serverGeneration: 40 },
      { ...CONTEXT, accountGeneration: 50 },
      { ...CONTEXT, serverUrl: 'https://other-vault.example.test/' },
      { ...CONTEXT, accountIdentity: 'other@example.test' },
      { ...CONTEXT, policyGeneration: 60 },
      { ...CONTEXT, enterprisePolicyGeneration: 70 },
      { ...CONTEXT, enterprisePolicyRawGeneration: 'enterprise-raw-generation-B' },
    ];
    for (const mismatch of mismatches) {
      const f = fixture();
      await put(f.make());
      await expect(claim(f.make(), mismatch)).resolves.toEqual({ action: 'none' });
    }
  });

  it('rejects an enterprise policy ABA transition after the effective policy returns to A', async () => {
    const f = fixture();
    await put(f.make());

    await expect(claim(f.make(), {
      ...CONTEXT,
      enterprisePolicyGeneration: BINDING.enterprisePolicyGeneration + 2,
      enterprisePolicyRawGeneration: 'enterprise-raw-generation-C',
    })).resolves.toEqual({ action: 'none' });
    expect(rawEnvelope(f.store, f.storageKey).entries).toEqual([]);
  });

  it('binds take to the exact claimant document without letting a mismatch consume it', async () => {
    const f = fixture();
    await put(f.make());
    const prompt = await claim(f.make());
    if (prompt.action !== 'update') throw new Error('expected update prompt');

    await expect(f.make().take(
      prompt.promptId,
      { ...CONTEXT, documentId: 'other-document' },
      userKey(),
    )).resolves.toBeUndefined();
    await expect(f.make().take(
      prompt.promptId,
      CONTEXT,
      userKey(),
    )).resolves.toMatchObject({ credentials: CREDENTIALS });
  });

  it('returns the claimed canonical decision once and permits no replay', async () => {
    const replay = fixture();
    await put(replay.make());
    const prompt = await claim(replay.make());
    if (prompt.action !== 'update') throw new Error('expected update prompt');
    const [first, second] = await Promise.all([
      replay.make().take(prompt.promptId, CONTEXT, userKey()),
      replay.make().take(prompt.promptId, CONTEXT, userKey()),
    ]);
    expect([first, second].filter(Boolean)).toHaveLength(1);
    expect(first ?? second).toMatchObject({ credentials: CREDENTIALS, decision: UPDATE });
    await expect(replay.make().take(
      prompt.promptId,
      CONTEXT,
      userKey(),
    )).resolves.toBeUndefined();
  });

  it('dismisses only the exact claim and clears one tab without affecting another', async () => {
    const f = fixture();
    const pending = f.make();
    await put(pending, { ...INPUT, tabId: 7 });
    await put(pending, { ...INPUT, tabId: 8, sourceDocumentId: 'tab-eight-source' });
    const prompt = await claim(pending, CONTEXT);
    if (prompt.action !== 'update') throw new Error('expected update prompt');

    await expect(pending.dismiss(prompt.promptId, {
      ...CONTEXT,
      documentId: 'other-document',
    })).resolves.toBe(false);
    await expect(pending.dismiss(prompt.promptId, CONTEXT)).resolves.toBe(true);
    await expect(claim(pending, CONTEXT)).resolves.toEqual({ action: 'none' });

    await pending.clearTab(7);
    await expect(claim(pending, { ...CONTEXT, tabId: 8 })).resolves.toMatchObject({ action: 'update' });
    await pending.clearTab(8);
    expect(rawEnvelope(f.store, f.storageKey).entries).toEqual([]);
  });

  it('zeroes every owned UserKey and random IV buffer on success and failure', async () => {
    const randomBuffers: Uint8Array[] = [];
    const f = fixture({
      randomBytes: (length) => {
        const randomBuffer = new Uint8Array(length).fill(9 + randomBuffers.length);
        randomBuffers.push(randomBuffer);
        return randomBuffer;
      },
    });
    const putKey = userKey();
    await f.make().put(INPUT, CREDENTIALS, putKey);
    expectZeroed(putKey);
    expect(randomBuffers).toHaveLength(1);
    expect([...randomBuffers[0]!]).toEqual(new Array(12).fill(0));

    const claimKey = userKey();
    const prompt = await f.make().claim(CONTEXT, claimKey, async () => UPDATE);
    expectZeroed(claimKey);
    expect(randomBuffers).toHaveLength(2);
    expect([...randomBuffers[1]!]).toEqual(new Array(12).fill(0));
    if (prompt.action !== 'update') throw new Error('expected update prompt');

    const takeKey = userKey();
    await f.make().take(prompt.promptId, CONTEXT, takeKey);
    expectZeroed(takeKey);

    const invalidKey = userKey();
    await expect(f.make().put(
      { ...INPUT, sourceUrl: 'not a URL' },
      CREDENTIALS,
      invalidKey,
    )).rejects.toMatchObject({ code: 'invalid_input' });
    expectZeroed(invalidKey);
  });

  it('rejects non-canonical runtime incarnations in capture and claim contexts', async () => {
    const f = fixture();
    const captureKey = userKey();
    await expect(f.make().put(
      { ...INPUT, runtimeIncarnation: RUNTIME_A.toUpperCase() },
      CREDENTIALS,
      captureKey,
    )).rejects.toMatchObject({ code: 'invalid_input' });
    expectZeroed(captureKey);

    const claimKey = userKey();
    await expect(f.make().claim(
      {
        ...CONTEXT,
        runtimeIncarnation: 'a0000000-0000-1000-8000-000000000001',
      },
      claimKey,
      async () => UPDATE,
    )).rejects.toMatchObject({ code: 'invalid_input' });
    expectZeroed(claimKey);
  });

  it('keeps the original pending entry when evaluation itself throws', async () => {
    const f = fixture();
    await put(f.make());
    const failure = new Error('vault snapshot unavailable');
    await expect(f.make().claim(CONTEXT, userKey(), async () => { throw failure; })).rejects.toBe(failure);
    await expect(claim(f.make())).resolves.toMatchObject({ action: 'update' });
  });

  it('owns an independent expiry scheduler without reclaiming a displayed prompt', async () => {
    let now = 1_000;
    const scheduled: number[] = [];
    let cancellations = 0;
    const f = fixture({
      now: () => now,
      ttlMs: 20,
      claimLeaseMs: 5,
      scheduler: {
        schedule: (when) => { scheduled.push(when); },
        cancel: () => { cancellations += 1; },
      },
    });
    await put(f.make());
    expect(scheduled.at(-1)).toBe(1_020);

    const prompt = await claim(f.make());
    if (prompt.action !== 'update') throw new Error('expected update prompt');
    expect(scheduled.at(-1)).toBe(1_020);

    now = 1_005;
    await f.make().reconcile();
    expect(rawEnvelope(f.store, f.storageKey).entries[0]).toMatchObject({
      state: 'claimed',
      promptId: prompt.promptId,
    });
    expect(scheduled.at(-1)).toBe(1_020);

    now = 1_020;
    await f.make().reconcile();
    expect(rawEnvelope(f.store, f.storageKey).entries).toEqual([]);
    expect(cancellations).toBeGreaterThan(0);
  });

  it('uses the exported default storage key', async () => {
    const store = createMemoryStore();
    await put(new AutofillPendingSaveStore({ store, createId: idGenerator() }));
    expect(store.peek(AUTOFILL_PENDING_SAVE_STORAGE_KEY)).toBeDefined();
  });
});
