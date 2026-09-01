import { describe, expect, it, vi } from 'vitest';
import type { ClientEventReceipt } from './client-event-service.js';
import {
  ClientEventAckRegistry,
  ClientEventAckRegistryError,
  type ClientEventAckOwner,
} from './client-event-ack-registry.js';

const NOW = 1_800_000_000_000;
const ACK_A = '11111111-1111-4111-8111-111111111111';
const ACK_B = '22222222-2222-4222-8222-222222222222';
const ACK_C = '33333333-3333-4333-8333-333333333333';

const POPUP: ClientEventAckOwner = Object.freeze({
  kind: 'popup',
  documentId: 'popup-document',
});
const CONTENT: ClientEventAckOwner = Object.freeze({
  kind: 'content',
  tabId: 7,
  frameId: 2,
  documentId: 'content-document',
});
const OPTIONS: ClientEventAckOwner = Object.freeze({
  kind: 'options',
  documentId: 'options-document',
});

function receipt(label = 'receipt'): ClientEventReceipt {
  return Object.freeze({ label }) as unknown as ClientEventReceipt;
}

function harness(options: {
  now?: () => number;
  createId?: () => string;
  maxEntries?: number;
  ttlMs?: number;
  commitResult?: 'enqueued' | 'failed' | 'not_pending';
} = {}) {
  const commit = vi.fn(async (_receipt: ClientEventReceipt) => ({
    kind: options.commitResult ?? 'enqueued',
  } as const));
  const onError = vi.fn();
  const registry = new ClientEventAckRegistry({
    committer: { commit },
    now: options.now ?? (() => NOW),
    createId: options.createId ?? (() => ACK_A),
    onError,
    ...(options.maxEntries === undefined ? {} : { maxEntries: options.maxEntries }),
    ...(options.ttlMs === undefined ? {} : { ttlMs: options.ttlMs }),
  });
  return { registry, commit, onError };
}

describe('ClientEventAckRegistry', () => {
  it('keeps the receipt private and commits it exactly once for the exact popup document', async () => {
    const h = harness();
    const expected = receipt();

    const id = h.registry.issue(POPUP, expected);

    expect(id).toBe(ACK_A);
    expect(JSON.stringify(id)).not.toContain('receipt');
    await expect(h.registry.consume(id, POPUP)).resolves.toEqual({ kind: 'committed' });
    await expect(h.registry.consume(id, POPUP)).resolves.toEqual({ kind: 'rejected' });
    expect(h.commit).toHaveBeenCalledOnce();
    expect(h.commit).toHaveBeenCalledWith(expected);
  });

  it.each([
    ['popup document', { kind: 'popup', documentId: 'other-popup' }],
    ['owner kind', { kind: 'popup', documentId: CONTENT.documentId }],
    ['content tab', { ...CONTENT, tabId: 8 }],
    ['content frame', { ...CONTENT, frameId: 3 }],
    ['content document', { ...CONTENT, documentId: 'other-document' }],
  ])('consumes before rejecting a wrong %s owner', async (_label, wrongOwner) => {
    const h = harness();
    const owner = 'tabId' in wrongOwner ? CONTENT : POPUP;
    const id = h.registry.issue(owner, receipt());

    await expect(h.registry.consume(id, wrongOwner)).resolves.toEqual({ kind: 'rejected' });
    await expect(h.registry.consume(id, owner)).resolves.toEqual({ kind: 'rejected' });
    expect(h.commit).not.toHaveBeenCalled();
  });

  it('never lets popup and content documents exchange acknowledgements', async () => {
    const h = harness();
    const id = h.registry.issue(CONTENT, receipt());

    await expect(h.registry.consume(id, {
      kind: 'popup',
      documentId: CONTENT.documentId,
    })).resolves.toEqual({ kind: 'rejected' });
    await expect(h.registry.consume(id, CONTENT)).resolves.toEqual({ kind: 'rejected' });
    expect(h.commit).not.toHaveBeenCalled();
  });

  it('keeps options export acknowledgements isolated from popup documents', async () => {
    const h = harness();
    const id = h.registry.issue(OPTIONS, receipt());

    await expect(h.registry.consume(id, {
      kind: 'popup',
      documentId: OPTIONS.documentId,
    })).resolves.toEqual({ kind: 'rejected' });
    await expect(h.registry.consume(id, OPTIONS)).resolves.toEqual({ kind: 'rejected' });
    expect(h.commit).not.toHaveBeenCalled();
  });

  it('consumes before rejecting a stale session or account authority fence', async () => {
    const h = harness();
    const assertCurrent = vi.fn(() => { throw new Error('stale account'); });
    const id = h.registry.issue(POPUP, receipt(), assertCurrent);

    await expect(h.registry.consume(id, POPUP)).resolves.toEqual({ kind: 'rejected' });
    await expect(h.registry.consume(id, POPUP)).resolves.toEqual({ kind: 'rejected' });
    expect(assertCurrent).toHaveBeenCalledOnce();
    expect(h.commit).not.toHaveBeenCalled();
  });

  it('rejects an expired acknowledgement and frees capacity', async () => {
    let now = NOW;
    const ids = [ACK_A, ACK_B];
    const h = harness({ now: () => now, createId: () => ids.shift()!, maxEntries: 1, ttlMs: 10 });
    const expired = h.registry.issue(POPUP, receipt('expired'));
    expect(() => h.registry.issue(POPUP, receipt('blocked')))
      .toThrowError(expect.objectContaining({ code: 'capacity' }));

    now += 10;
    const current = h.registry.issue(POPUP, receipt('current'));

    await expect(h.registry.consume(expired, POPUP)).resolves.toEqual({ kind: 'rejected' });
    await expect(h.registry.consume(current, POPUP)).resolves.toEqual({ kind: 'committed' });
  });

  it('prevents a retired ID from creating an owner ABA within the acknowledgement window', async () => {
    const ids = [ACK_A, ACK_A, ACK_B];
    const h = harness({ createId: () => ids.shift()! });
    const oldReceipt = receipt('old');
    const newReceipt = receipt('new');
    const oldId = h.registry.issue(CONTENT, oldReceipt);
    expect(h.registry.revokeDocument(CONTENT)).toBe(1);

    const newId = h.registry.issue(CONTENT, newReceipt);

    expect(oldId).toBe(ACK_A);
    expect(newId).toBe(ACK_B);
    await expect(h.registry.consume(oldId, CONTENT)).resolves.toEqual({ kind: 'rejected' });
    await expect(h.registry.consume(newId, CONTENT)).resolves.toEqual({ kind: 'committed' });
    expect(h.commit).toHaveBeenCalledWith(newReceipt);
  });

  it('revokes only matching tabs and exact documents', async () => {
    const ids = [ACK_A, ACK_B, ACK_C];
    const h = harness({ createId: () => ids.shift()! });
    const contentA = h.registry.issue(CONTENT, receipt('content-a'));
    const contentB = h.registry.issue({ ...CONTENT, tabId: 9 }, receipt('content-b'));
    const popup = h.registry.issue(POPUP, receipt('popup'));

    expect(h.registry.revokeTab(7)).toBe(1);
    expect(h.registry.revokeDocument({ ...CONTENT, tabId: 9 })).toBe(1);
    expect(h.registry.revokeAll()).toBe(1);

    await expect(h.registry.consume(contentA, CONTENT)).resolves.toEqual({ kind: 'rejected' });
    await expect(h.registry.consume(contentB, { ...CONTENT, tabId: 9 }))
      .resolves.toEqual({ kind: 'rejected' });
    await expect(h.registry.consume(popup, POPUP)).resolves.toEqual({ kind: 'rejected' });
  });

  it('does not invoke accessors while consuming a malformed owner', async () => {
    const h = harness();
    const id = h.registry.issue(POPUP, receipt());
    const getter = vi.fn(() => 'popup');
    const malformed = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(malformed, 'kind', { enumerable: true, get: getter });
    Object.defineProperty(malformed, 'documentId', { enumerable: true, value: POPUP.documentId });

    await expect(h.registry.consume(id, malformed)).resolves.toEqual({ kind: 'rejected' });
    expect(getter).not.toHaveBeenCalled();
    await expect(h.registry.consume(id, POPUP)).resolves.toEqual({ kind: 'rejected' });
  });

  it('maps contained commit outcomes without exposing the receipt', async () => {
    const failed = harness({ commitResult: 'failed' });
    await expect(failed.registry.consume(
      failed.registry.issue(POPUP, receipt()),
      POPUP,
    )).resolves.toEqual({ kind: 'failed' });

    const missing = harness({ commitResult: 'not_pending' });
    await expect(missing.registry.consume(
      missing.registry.issue(POPUP, receipt()),
      POPUP,
    )).resolves.toEqual({ kind: 'rejected' });
  });

  it('contains a throwing committer after consuming the acknowledgement', async () => {
    const failure = new Error('commit failed');
    const commit = vi.fn(async () => { throw failure; });
    const onError = vi.fn();
    const registry = new ClientEventAckRegistry({
      committer: { commit },
      now: () => NOW,
      createId: () => ACK_A,
      onError,
    });
    const id = registry.issue(POPUP, receipt());

    await expect(registry.consume(id, POPUP)).resolves.toEqual({ kind: 'failed' });
    await expect(registry.consume(id, POPUP)).resolves.toEqual({ kind: 'rejected' });
    expect(onError).toHaveBeenCalledWith(failure);
  });

  it('invalidates the token before surfacing a broken clock', async () => {
    let now = NOW;
    const h = harness({ now: () => now });
    const id = h.registry.issue(POPUP, receipt());
    now = Number.NaN;

    await expect(h.registry.consume(id, POPUP)).rejects.toThrow(/clock is invalid/i);
    now = NOW;
    await expect(h.registry.consume(id, POPUP)).resolves.toEqual({ kind: 'rejected' });
    expect(() => h.registry.issue(POPUP, receipt('replacement')))
      .toThrowError(expect.objectContaining({ code: 'id_generation' }));
  });

  it('rejects invalid construction bounds and exhausted UUID generation', () => {
    expect(() => new ClientEventAckRegistry({
      committer: { commit: vi.fn() },
      maxEntries: 0,
    })).toThrow(RangeError);

    const registry = new ClientEventAckRegistry({
      committer: { commit: vi.fn() },
      now: () => NOW,
      createId: () => ACK_A,
    });
    registry.issue(POPUP, receipt());
    expect(() => registry.issue(POPUP, receipt()))
      .toThrowError(new ClientEventAckRegistryError(
        'id_generation',
        'Unable to allocate a unique client event acknowledgement ID',
      ));
  });
});
