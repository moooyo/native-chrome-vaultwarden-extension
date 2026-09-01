import { describe, expect, it, vi } from 'vitest';
import {
  ToolbarMatchCountController,
  type ToolbarMatchContribution,
} from './toolbar-match-count.js';

function harness() {
  let authorityCurrent = true;
  const publish = vi.fn(async (_contribution: ToolbarMatchContribution) => undefined);
  const hasHostAccess = vi.fn(async () => true);
  const countMatches = vi.fn(async (
    _url: string,
    bind: (assertCurrent: () => void) => void,
  ) => {
    bind(() => {
      if (!authorityCurrent) throw new Error('stale');
    });
    return 12;
  });
  const forget = vi.fn();
  const logger = { warn: vi.fn() };
  const controller = new ToolbarMatchCountController({
    publish,
    hasHostAccess,
    countMatches,
    forget,
    logger,
  });
  return {
    controller,
    publish,
    hasHostAccess,
    countMatches,
    forget,
    logger,
    revokeAuthority() { authorityCurrent = false; },
  };
}

const TAB = Object.freeze({ id: 7, url: 'https://example.com/login' });

describe('ToolbarMatchCountController', () => {
  it('publishes zero first, then only a count for the browser-owned top-level URL', async () => {
    const h = harness();
    await h.controller.refresh(TAB, 'unlocked', true);

    expect(h.hasHostAccess).toHaveBeenCalledWith(TAB.url);
    expect(h.countMatches).toHaveBeenCalledWith(TAB.url, expect.any(Function));
    expect(h.publish.mock.calls.map(([value]) => value)).toEqual([
      { tabId: 7, url: TAB.url, count: 0 },
      { tabId: 7, url: TAB.url, count: 12 },
    ]);
  });

  it('clears and never scans while locked, disabled, non-web, or missing host access', async () => {
    const h = harness();
    await h.controller.refresh(TAB, 'locked', true);
    await h.controller.refresh(TAB, 'unlocked', false);
    await h.controller.refresh({ id: 7, url: 'chrome://settings/' }, 'unlocked', true);
    h.hasHostAccess.mockResolvedValueOnce(false);
    await h.controller.refresh(TAB, 'unlocked', true);

    expect(h.countMatches).not.toHaveBeenCalled();
    expect(h.publish).toHaveBeenCalledTimes(4);
    expect(h.publish.mock.calls.every(([value]) => value.count === 0)).toBe(true);
  });

  it('does not publish a stale A result after the tab navigates to B', async () => {
    const h = harness();
    let release!: (value: boolean) => void;
    h.hasHostAccess.mockImplementationOnce(() => new Promise<boolean>((resolve) => { release = resolve; }));
    const first = h.controller.refresh(TAB, 'unlocked', true);
    await vi.waitFor(() => expect(h.hasHostAccess).toHaveBeenCalledOnce());
    const second = h.controller.refresh({ id: 7, url: 'https://other.example/' }, 'unlocked', true);
    release(true);
    await Promise.all([first, second]);

    expect(h.countMatches).toHaveBeenCalledOnce();
    expect(h.countMatches).toHaveBeenCalledWith('https://other.example/', expect.any(Function));
    expect(h.publish).not.toHaveBeenCalledWith({ tabId: 7, url: TAB.url, count: 12 });
    expect(h.publish).toHaveBeenLastCalledWith({
      tabId: 7,
      url: 'https://other.example/',
      count: 12,
    });
  });

  it('refuses a count whose vault authority became stale', async () => {
    const h = harness();
    h.countMatches.mockImplementationOnce(async (_url, bind) => {
      bind(() => { throw new Error('stale'); });
      return 4;
    });
    await h.controller.refresh(TAB, 'unlocked', true);

    expect(h.publish).toHaveBeenCalledOnce();
    expect(h.publish).toHaveBeenLastCalledWith({ tabId: 7, url: TAB.url, count: 0 });
    expect(h.logger.warn).toHaveBeenCalledWith('toolbar_match_count_failed');
  });

  it('revokes tab and account-wide work without retaining a previous count', async () => {
    const h = harness();
    let release!: () => void;
    h.countMatches.mockImplementationOnce((_url, bind) => {
      bind(() => undefined);
      return new Promise<number>((resolve) => { release = () => resolve(5); });
    });
    const pending = h.controller.refresh(TAB, 'unlocked', true);
    await vi.waitFor(() => expect(h.countMatches).toHaveBeenCalledOnce());
    h.controller.revokeTab(7);
    h.controller.revokeAll();
    release();
    await pending;

    expect(h.forget).toHaveBeenCalledWith(7);
    expect(h.publish).not.toHaveBeenCalledWith({ tabId: 7, url: TAB.url, count: 5 });
  });

  it('fails closed on count errors and emits only a fixed diagnostic', async () => {
    const h = harness();
    h.countMatches.mockRejectedValueOnce(new Error('private vault value'));
    await h.controller.refresh(TAB, 'unlocked', true);
    expect(h.publish).toHaveBeenCalledOnce();
    expect(h.logger.warn).toHaveBeenCalledWith('toolbar_match_count_failed');
    expect(JSON.stringify(h.logger.warn.mock.calls)).not.toContain('private vault value');
  });
});
