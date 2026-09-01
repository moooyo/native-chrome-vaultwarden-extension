import { describe, expect, it, vi } from 'vitest';
import {
  AutofillTotpCopyAckRegistry,
  type AutofillTotpCopyContentOwner,
} from './autofill-totp-copy-ack-registry.js';

const NOW = 1_800_000_000_000;
const ACK_A = '11111111-1111-4111-8111-111111111111';
const ACK_B = '22222222-2222-4222-8222-222222222222';
const OWNER: AutofillTotpCopyContentOwner = Object.freeze({
  tabId: 7,
  frameId: 2,
  documentId: 'document-a',
});

function harness(options: {
  now?: () => number;
  ids?: string[];
  write?: (value: string, assertCurrent?: () => void) => Promise<boolean>;
} = {}) {
  const writeAndScheduleClear = vi.fn(options.write ?? (async () => true));
  const ids = options.ids ?? [ACK_A];
  const registry = new AutofillTotpCopyAckRegistry({
    writer: { writeAndScheduleClear },
    now: options.now ?? (() => NOW),
    createId: () => ids.shift()!,
  });
  return { registry, writeAndScheduleClear };
}

describe('AutofillTotpCopyAckRegistry', () => {
  it('copies once only for the exact content document owner', async () => {
    const h = harness();
    const id = h.registry.issueContent(OWNER, '123456', () => {});

    await expect(h.registry.consumeContent(id, OWNER)).resolves.toEqual({ kind: 'copied' });
    await expect(h.registry.consumeContent(id, OWNER)).resolves.toEqual({ kind: 'rejected' });
    expect(h.writeAndScheduleClear).toHaveBeenCalledOnce();
    expect(h.writeAndScheduleClear).toHaveBeenCalledWith('123456', expect.any(Function));
  });

  it('consumes before rejecting a wrong owner or stale authority', async () => {
    const wrong = harness();
    const wrongId = wrong.registry.issueContent(OWNER, '123456', () => {});
    await expect(wrong.registry.consumeContent(wrongId, {
      ...OWNER,
      documentId: 'document-b',
    })).resolves.toEqual({ kind: 'rejected' });
    await expect(wrong.registry.consumeContent(wrongId, OWNER)).resolves.toEqual({ kind: 'rejected' });
    expect(wrong.writeAndScheduleClear).not.toHaveBeenCalled();

    const stale = harness();
    const staleId = stale.registry.issueContent(OWNER, '654321', () => {
      throw new Error('stale');
    });
    await expect(stale.registry.consumeContent(staleId, OWNER)).resolves.toEqual({ kind: 'rejected' });
    expect(stale.writeAndScheduleClear).not.toHaveBeenCalled();
  });

  it('supports one worker-only direct receipt without exposing its ID', async () => {
    const h = harness();
    const receipt = h.registry.prepareDirect('12345678', () => {}, 7);

    expect(JSON.stringify(receipt)).not.toContain('12345678');
    await expect(h.registry.commitDirect(receipt)).resolves.toEqual({ kind: 'copied' });
    await expect(h.registry.commitDirect(receipt)).resolves.toEqual({ kind: 'rejected' });
    expect(h.writeAndScheduleClear).toHaveBeenCalledWith('12345678', expect.any(Function));
  });

  it('accepts a Steam TOTP through the shared clipboard validator', async () => {
    const h = harness();
    const id = h.registry.issueContent(OWNER, 'B2CDX', () => {});

    await expect(h.registry.consumeContent(id, OWNER)).resolves.toEqual({ kind: 'copied' });
    expect(h.writeAndScheduleClear).toHaveBeenCalledWith('B2CDX', expect.any(Function));
  });

  it('revokes pending copies on document, tab, and global lifecycle changes', async () => {
    const h = harness({ ids: [ACK_A, ACK_B] });
    const first = h.registry.issueContent(OWNER, '123456', () => {});
    const second = h.registry.issueContent({ ...OWNER, tabId: 8 }, '654321', () => {});
    expect(h.registry.revokeDocument(OWNER)).toBe(1);
    expect(h.registry.revokeTab(8)).toBe(1);
    expect(h.registry.revokeAll()).toBe(0);
    await expect(h.registry.consumeContent(first, OWNER)).resolves.toEqual({ kind: 'rejected' });
    await expect(h.registry.consumeContent(second, { ...OWNER, tabId: 8 }))
      .resolves.toEqual({ kind: 'rejected' });
  });

  it('expires, validates bounded codes, and reports clipboard failures truthfully', async () => {
    let now = NOW;
    const failed = harness({ now: () => now, write: async () => false });
    const id = failed.registry.issueContent(OWNER, '123456', () => {});
    await expect(failed.registry.consumeContent(id, OWNER)).resolves.toEqual({ kind: 'failed' });

    const expired = harness({ now: () => now });
    const expiredId = expired.registry.issueContent(OWNER, '654321', () => {});
    now += 30_000;
    await expect(expired.registry.consumeContent(expiredId, OWNER))
      .resolves.toEqual({ kind: 'rejected' });
    expect(() => expired.registry.issueContent(OWNER, '12ab56', () => {})).toThrow(TypeError);
  });
});
