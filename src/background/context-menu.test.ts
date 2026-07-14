import { describe, it, expect, vi } from 'vitest';
import { createContextMenu, shouldRefreshMenu } from './context-menu.js';
import type { FillItemCandidate, FillCommand, FillErrorCommand } from '../messaging/protocol.js';

function makeDeps(state: 'loggedOut' | 'locked' | 'unlocked', cards: FillItemCandidate[] = [], identities: FillItemCandidate[] = []) {
  const created: Record<string, unknown>[] = [];
  const sent: Array<{ id: number; msg: FillCommand | FillErrorCommand; opts: { frameId?: number } | undefined }> = [];
  const deps = {
    getState: vi.fn(async () => state),
    findFillItems: vi.fn(async (kind: 'card' | 'identity') => (kind === 'card' ? cards : identities)),
    getFillData: vi.fn(async () => ({ number: '4111' })),
    menus: { removeAll: vi.fn(async () => {}), create: vi.fn((p: Record<string, unknown>) => { created.push(p); }) },
    tabs: { sendMessage: vi.fn(async (id: number, msg: FillCommand | FillErrorCommand, opts?: { frameId?: number }) => { sent.push({ id, msg, opts }); }) },
  };
  return { deps, created, sent };
}

describe('context menu', () => {
  it('builds nothing but a removeAll when locked', async () => {
    const { deps, created } = makeDeps('locked', [{ id: 'c1', name: 'Visa', favorite: false }]);
    await createContextMenu(deps).refresh();
    expect(deps.menus.removeAll).toHaveBeenCalled();
    expect(created).toHaveLength(0); // no vault item names leak when locked
  });

  it('builds root + form/field groups with one item per card/identity when unlocked', async () => {
    const { deps, created } = makeDeps('unlocked', [{ id: 'c1', name: 'Visa', favorite: false }], [{ id: 'i1', name: 'Ada', favorite: false }]);
    await createContextMenu(deps).refresh();
    const ids = created.map((c) => c.id);
    expect(ids).toContain('vw-root');
    // each card appears under a form-scope and a field-scope group:
    expect(ids).toContain('vw-fill|form|card|c1');
    expect(ids).toContain('vw-fill|field|card|c1');
    expect(ids).toContain('vw-fill|form|identity|i1');
    expect(ids).toContain('vw-fill|field|identity|i1');
  });

  it('marks reprompt items with a lock and omits empty kinds', async () => {
    const { deps, created } = makeDeps('unlocked', [{ id: 'c1', name: 'Amex', favorite: false, reprompt: true }], []);
    await createContextMenu(deps).refresh();
    const item = created.find((c) => c.id === 'vw-fill|form|card|c1');
    expect(item!.title).toContain('Amex');
    expect(item!.title).toContain('🔒');
    // no identity group when there are no identities
    expect(created.some((c) => c.id === 'vw-identity-form')).toBe(false);
  });

  it('on click: fetches fill data and sends a fill command to the clicked frame', async () => {
    const { deps, sent } = makeDeps('unlocked', [{ id: 'c1', name: 'Visa', favorite: false }]);
    await createContextMenu(deps).handleClick('vw-fill|field|card|c1', { id: 7 }, 3);
    expect(deps.getFillData).toHaveBeenCalledWith('c1', 'card');
    expect(sent[0]).toEqual({ id: 7, msg: { type: 'autofill.fill', scope: 'field', kind: 'card', data: { number: '4111' } }, opts: { frameId: 3 } });
  });

  it('on click of a reprompt item: sends a fillError instead of data', async () => {
    const { deps, sent } = makeDeps('unlocked');
    deps.getFillData = vi.fn(async () => { throw Object.assign(new Error('x'), { code: 'reprompt_required' }); });
    await createContextMenu(deps).handleClick('vw-fill|form|card|c9', { id: 7 }, 0);
    expect(sent[0]!.msg).toEqual({ type: 'autofill.fillError', code: 'reprompt_required' });
  });

  it('ignores clicks with no tab id or unrecognized menu id', async () => {
    const { deps, sent } = makeDeps('unlocked');
    await createContextMenu(deps).handleClick('vw-fill|form|card|c1', undefined, 0);
    await createContextMenu(deps).handleClick('something-else', { id: 7 }, 0);
    await createContextMenu(deps).handleClick('vw-fill|bogus|nope|c1', { id: 7 }, 0);
    expect(sent).toHaveLength(0);
    expect(deps.getFillData).not.toHaveBeenCalled();
  });

  it('builds nothing when logged out, even with items', async () => {
    const { deps, created } = makeDeps('loggedOut', [{ id: 'c1', name: 'Visa', favorite: false }]);
    await createContextMenu(deps).refresh();
    expect(created).toHaveLength(0);
  });

  it('serializes overlapping refreshes and coalesces them to a single trailing rebuild', async () => {
    const { deps } = makeDeps('unlocked', [{ id: 'c1', name: 'Visa', favorite: false }]);
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    let removeAllCount = 0;
    deps.menus.removeAll = vi.fn(async () => {
      removeAllCount += 1;
      if (removeAllCount === 1) await gate; // hold the first rebuild open while more refreshes queue
    });
    const menu = createContextMenu(deps);
    const p1 = menu.refresh();
    const p2 = menu.refresh();
    const p3 = menu.refresh();
    release();
    await Promise.all([p1, p2, p3]);
    // Without serialization all three rebuilds interleave (3 removeAlls, duplicate create ids);
    // newest-wins single-flight collapses them to the in-flight run plus one coalesced trailing run.
    expect(removeAllCount).toBe(2);
  });

  it('logs an unexpected fill error instead of silently swallowing it', async () => {
    const { deps, sent } = makeDeps('unlocked');
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    deps.getFillData = vi.fn(async () => { throw new Error('decrypt exploded'); });
    await createContextMenu(deps).handleClick('vw-fill|form|card|c9', { id: 7 }, 0);
    expect(spy).toHaveBeenCalled();
    expect(sent).toHaveLength(0);
    spy.mockRestore();
  });

  it('stays silent (no log, no message) for expected credential-release refusals', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    for (const code of ['denied', 'locked', 'sync_required'] as const) {
      const { deps, sent } = makeDeps('unlocked');
      deps.getFillData = vi.fn(async () => { throw Object.assign(new Error('x'), { code }); });
      await createContextMenu(deps).handleClick('vw-fill|form|card|c9', { id: 7 }, 0);
      expect(sent).toHaveLength(0);
    }
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('shouldRefreshMenu fires for sync/auth/cipher mutations, not for reads', () => {
    expect(shouldRefreshMenu('vault.sync')).toBe(true);
    expect(shouldRefreshMenu('auth.lock')).toBe(true);
    expect(shouldRefreshMenu('vault.createCipher')).toBe(true);
    expect(shouldRefreshMenu('auth.unlockWithPin')).toBe(true);
    expect(shouldRefreshMenu('vault.import')).toBe(true);
    expect(shouldRefreshMenu('vault.getField')).toBe(false);
    expect(shouldRefreshMenu('autofill.findFillItems')).toBe(false);
  });
});
