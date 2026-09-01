// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  COMPOSED_TREE_AUTOFILL_ATTRIBUTE_FILTER,
  DEFAULT_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS,
  MAX_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS,
  MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS,
  getShadowRoot,
  observeOpenComposedTree,
  scanOpenComposedRoots,
  type ComposedTreeChange,
} from './composed-tree.js';
import { mountRenderSurface } from './ui/render-surface.js';

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  document.body.replaceChildren();
});

function openShadow(host: HTMLElement): ShadowRoot {
  return host.attachShadow({ mode: 'open' });
}

function closedShadow(host: HTMLElement): ShadowRoot {
  return host.attachShadow({ mode: 'closed' });
}

function rootGetter(entries: ReadonlyMap<Element, ShadowRoot>) {
  return (element: Element): ShadowRoot | null => entries.get(element) ?? null;
}

it('observes aria-labelledby changes that can alter field classification', () => {
  expect(COMPOSED_TREE_AUTOFILL_ATTRIBUTE_FILTER).toContain('aria-labelledby');
});

async function flushMutations(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe('scanOpenComposedRoots', () => {
  it('discovers nested open roots in stable order without duplicates', () => {
    const outerHost = document.createElement('div');
    const outer = openShadow(outerHost);
    const nestedHost = document.createElement('section');
    const nested = openShadow(nestedHost);
    outer.append(nestedHost);
    document.body.append(outerHost);

    const first = scanOpenComposedRoots(document);
    const second = scanOpenComposedRoots(document);

    expect(first.roots).toEqual([document, outer, nested]);
    expect(second.roots).toEqual(first.roots);
    expect(new Set(first.roots).size).toBe(first.roots.length);
    expect(first.truncated).toBe(false);
  });

  it('keeps a closed boundary when the Chrome DOM API is absent and never replaces attachShadow', () => {
    const originalAttachShadow = Element.prototype.attachShadow;
    const host = document.createElement('div');
    const closed = host.attachShadow({ mode: 'closed' });
    const hiddenHost = document.createElement('span');
    const hiddenNested = openShadow(hiddenHost);
    closed.append(hiddenHost);
    document.body.append(host);

    const snapshot = scanOpenComposedRoots(document);

    expect(host.shadowRoot).toBeNull();
    expect(snapshot.roots).toEqual([document]);
    expect(snapshot.roots).not.toContain(closed);
    expect(snapshot.roots).not.toContain(hiddenNested);
    expect(Element.prototype.attachShadow).toBe(originalAttachShadow);
  });

  it('uses the default Chrome DOM API to discover nested closed roots in BFS order', () => {
    const outerHost = document.createElement('div');
    const outer = closedShadow(outerHost);
    const nestedHost = document.createElement('section');
    const nested = closedShadow(nestedHost);
    outer.append(nestedHost);
    document.body.append(outerHost);
    const entries = new Map<Element, ShadowRoot>([[outerHost, outer], [nestedHost, nested]]);
    const openOrClosedShadowRoot = vi.fn(rootGetter(entries));
    vi.stubGlobal('chrome', { dom: { openOrClosedShadowRoot } });

    const snapshot = scanOpenComposedRoots(document);

    expect(snapshot.roots).toEqual([document, outer, nested]);
    expect(getShadowRoot(outerHost)).toBe(outer);
    expect(openOrClosedShadowRoot).toHaveBeenCalledWith(outerHost);
  });

  it('prefers a public open root without consulting the Chrome DOM API', () => {
    const host = document.createElement('div');
    const open = openShadow(host);
    document.body.append(host);
    const openOrClosedShadowRoot = vi.fn(() => { throw new Error('must not run'); });
    vi.stubGlobal('chrome', { dom: { openOrClosedShadowRoot } });

    expect(getShadowRoot(host)).toBe(open);
    expect(openOrClosedShadowRoot).not.toHaveBeenCalled();
  });

  it('fails closed when reading the Chrome DOM API method throws', () => {
    const host = document.createElement('div');
    const closed = closedShadow(host);
    document.body.append(host);
    const dom = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(dom, 'openOrClosedShadowRoot', {
      get: () => { throw new Error('blocked'); },
    });
    vi.stubGlobal('chrome', { dom });

    const snapshot = scanOpenComposedRoots(document);

    expect(host.shadowRoot).toBeNull();
    expect(snapshot.roots).toEqual([document]);
    expect(snapshot.roots).not.toContain(closed);
  });

  it('rejects non-roots, wrong hosts, foreign documents, and throwing adapters', () => {
    const host = document.createElement('div');
    const otherHost = document.createElement('div');
    const otherRoot = closedShadow(otherHost);
    document.body.append(host);
    const foreignDocument = document.implementation.createHTMLDocument('foreign');
    const foreignHost = foreignDocument.createElement('div');
    const foreignRoot = foreignHost.attachShadow({ mode: 'closed' });

    for (const getRoot of [
      () => document.createDocumentFragment(),
      () => otherRoot,
      () => foreignRoot,
      () => { throw new Error('unavailable'); },
    ]) {
      expect(scanOpenComposedRoots(document, { getShadowRoot: getRoot }).roots)
        .toEqual([document]);
    }
  });

  it('excludes an extension-owned closed surface and its nested roots without a DOM marker', () => {
    const surface = mountRenderSurface('');
    const nestedHost = document.createElement('div');
    const nestedRoot = closedShadow(nestedHost);
    surface.root.append(nestedHost);
    const entries = new Map<Element, ShadowRoot>([
      [surface.host, surface.root],
      [nestedHost, nestedRoot],
    ]);
    const getRoot = vi.fn(rootGetter(entries));
    vi.stubGlobal('chrome', { dom: { openOrClosedShadowRoot: getRoot } });

    const snapshot = scanOpenComposedRoots(document);

    expect(snapshot.roots).toEqual([document]);
    expect(getRoot).toHaveBeenCalledWith(surface.host);
    expect(getRoot.mock.calls.some(([element]) => element === nestedHost)).toBe(false);
    expect(surface.host.hasAttributes()).toBe(false);
    surface.remove();
  });

  it('applies root and element truncation bounds while discovering closed roots', () => {
    const firstHost = document.createElement('div');
    const secondHost = document.createElement('div');
    const first = closedShadow(firstHost);
    const second = closedShadow(secondHost);
    document.body.append(firstHost, secondHost);
    const getRoot = rootGetter(new Map([[firstHost, first], [secondHost, second]]));

    const rootLimited = scanOpenComposedRoots(document, { getShadowRoot: getRoot, maxRoots: 2 });
    const elementLimited = scanOpenComposedRoots(document, {
      getShadowRoot: getRoot,
      maxVisitedElements: 1,
    });

    expect(rootLimited.roots).toEqual([document, first]);
    expect(rootLimited.truncated).toBe(true);
    expect(elementLimited.roots).toEqual([document]);
    expect(elementLimited.visitedElements).toBe(1);
    expect(elementLimited.truncated).toBe(true);
  });

  it('reports truncation at configured root and element limits', () => {
    const firstHost = document.createElement('div');
    const secondHost = document.createElement('div');
    openShadow(firstHost);
    openShadow(secondHost);
    document.body.append(firstHost, secondHost);

    const rootLimited = scanOpenComposedRoots(document, { maxRoots: 2 });
    const elementLimited = scanOpenComposedRoots(document, { maxVisitedElements: 1 });

    expect(rootLimited.roots).toHaveLength(2);
    expect(rootLimited.truncated).toBe(true);
    expect(elementLimited.visitedElements).toBe(1);
    expect(elementLimited.truncated).toBe(true);
  });

  it('rejects invalid roots and bounds', () => {
    expect(() => scanOpenComposedRoots(document, { maxRoots: 0 })).toThrow(RangeError);
    expect(() => scanOpenComposedRoots(document, { maxVisitedElements: 0 })).toThrow(RangeError);
    expect(() => scanOpenComposedRoots(document.createDocumentFragment() as ShadowRoot)).toThrow(TypeError);
  });
});

describe('observeOpenComposedTree', () => {
  it('discovers a newly connected host and observes mutations inside its open root', async () => {
    const changes: ComposedTreeChange[] = [];
    const handle = observeOpenComposedTree(document, (change) => changes.push(change));
    const host = document.createElement('div');
    const shadow = openShadow(host);

    document.body.append(host);
    await flushMutations();
    expect(handle.snapshot().roots).toEqual([document, shadow]);
    expect(changes.some((change) => change.reason === 'roots')).toBe(true);

    changes.length = 0;
    shadow.append(document.createElement('input'));
    await flushMutations();
    expect(changes).toHaveLength(1);
    expect(changes[0]!.reason).toBe('mutation');
    expect(changes[0]!.records).toHaveLength(1);
    handle.disconnect();
  });

  it('discovers roots by scanning only the added subtree', async () => {
    const existingHost = document.createElement('div');
    const existingRoot = closedShadow(existingHost);
    document.body.append(existingHost);
    const entries = new Map<Element, ShadowRoot>([[existingHost, existingRoot]]);
    const getRoot = vi.fn(rootGetter(entries));
    const handle = observeOpenComposedTree(document, () => {}, { getShadowRoot: getRoot });
    getRoot.mockClear();

    const wrapper = document.createElement('section');
    const addedHost = document.createElement('div');
    const addedRoot = closedShadow(addedHost);
    entries.set(addedHost, addedRoot);
    wrapper.append(addedHost);
    document.body.append(wrapper);
    await flushMutations();

    expect(handle.snapshot().roots).toEqual([document, existingRoot, addedRoot]);
    expect(getRoot).toHaveBeenCalledWith(wrapper);
    expect(getRoot).toHaveBeenCalledWith(addedHost);
    expect(getRoot.mock.calls.some(([element]) => element === existingHost)).toBe(false);
    handle.disconnect();
  });

  it('visits overlapping added-node subtrees only once', async () => {
    const getRoot = vi.fn((_element: Element) => null);
    const handle = observeOpenComposedTree(document, () => {}, { getShadowRoot: getRoot });
    getRoot.mockClear();
    const parent = document.createElement('div');
    const child = document.createElement('span');

    document.body.append(parent);
    parent.append(child);
    await flushMutations();

    expect(getRoot.mock.calls.filter(([element]) => element === parent)).toHaveLength(1);
    expect(getRoot.mock.calls.filter(([element]) => element === child)).toHaveLength(1);
    handle.disconnect();
  });

  it('keeps extension-owned roots excluded when their hosts are added incrementally', async () => {
    const handle = observeOpenComposedTree(document, () => {});
    const surface = mountRenderSurface('');
    vi.stubGlobal('chrome', {
      dom: {
        openOrClosedShadowRoot: (element: Element) => element === surface.host ? surface.root : null,
      },
    });

    await flushMutations();

    expect(handle.snapshot().roots).toEqual([document]);
    handle.disconnect();
    surface.remove();
  });

  it('observes autofill-relevant attribute changes inside every open root', async () => {
    const host = document.createElement('div');
    const shadow = openShadow(host);
    const input = document.createElement('input');
    shadow.append(input);
    document.body.append(host);
    const changes: ComposedTreeChange[] = [];
    const handle = observeOpenComposedTree(document, (change) => changes.push(change));

    input.setAttribute('autocomplete', 'current-password');
    input.setAttribute('aria-label', 'Password');
    input.setAttribute('data-bwignore', '');
    await flushMutations();

    const attributes = changes.flatMap((change) => change.records)
      .map((record) => record.attributeName);
    expect(attributes).toEqual(expect.arrayContaining(['autocomplete', 'aria-label', 'data-bwignore']));
    handle.disconnect();
  });

  it('periodically discovers attachShadow on an already-connected host', async () => {
    vi.useFakeTimers();
    const host = document.createElement('div');
    document.body.append(host);
    const changes: ComposedTreeChange[] = [];
    const handle = observeOpenComposedTree(
      document,
      (change) => changes.push(change),
      { rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS },
    );

    const shadow = openShadow(host);
    expect(handle.snapshot().roots).toEqual([document]);
    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS);

    expect(handle.snapshot().roots).toEqual([document, shadow]);
    expect(changes.at(-1)?.reason).toBe('roots');
    handle.disconnect();
  });

  it('keeps canonical breadth-first order when a sibling root attaches late', async () => {
    vi.useFakeTimers();
    const firstHost = document.createElement('div');
    const firstRoot = openShadow(firstHost);
    const lateHost = document.createElement('div');
    const nestedHost = document.createElement('div');
    const nestedRoot = openShadow(nestedHost);
    firstRoot.append(nestedHost);
    document.body.append(firstHost, lateHost);
    const handle = observeOpenComposedTree(
      document,
      () => {},
      { rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS },
    );
    expect(handle.snapshot().roots).toEqual([document, firstRoot, nestedRoot]);

    const lateRoot = openShadow(lateHost);
    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS);

    expect(handle.snapshot().roots).toEqual([document, firstRoot, lateRoot, nestedRoot]);
    handle.disconnect();
  });

  it('keeps a late root inventory within the canonical root limit', async () => {
    vi.useFakeTimers();
    const baseHost = document.createElement('div');
    const baseRoot = openShadow(baseHost);
    document.body.append(baseHost);
    const lateHost = document.createElement('div');
    const existingHost = document.createElement('div');
    const existingRoot = openShadow(existingHost);
    baseRoot.append(lateHost, existingHost);
    const handle = observeOpenComposedTree(
      baseRoot,
      () => {},
      {
        maxRoots: 2,
        rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS,
      },
    );
    expect(handle.snapshot().roots).toEqual([baseRoot, existingRoot]);

    const lateRoot = openShadow(lateHost);
    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS);

    expect(handle.snapshot().roots).toEqual([baseRoot, lateRoot]);
    expect(handle.snapshot().roots).toHaveLength(2);
    expect(handle.snapshot().truncated).toBe(true);
    handle.disconnect();
  });

  it('retains the full canonical prefix when several roots overflow one mutation batch', async () => {
    const baseHost = document.createElement('div');
    const baseRoot = openShadow(baseHost);
    document.body.append(baseHost);
    const laterHost = document.createElement('div');
    const laterRoot = openShadow(laterHost);
    const lastHost = document.createElement('div');
    const lastRoot = openShadow(lastHost);
    baseRoot.append(laterHost, lastHost);
    const handle = observeOpenComposedTree(baseRoot, () => {}, { maxRoots: 3 });
    expect(handle.snapshot().roots).toEqual([baseRoot, laterRoot, lastRoot]);
    const firstHost = document.createElement('div');
    const firstRoot = openShadow(firstHost);
    const secondHost = document.createElement('div');
    const secondRoot = openShadow(secondHost);

    baseRoot.prepend(firstHost, secondHost);
    await flushMutations();

    expect(handle.snapshot().roots).toEqual([baseRoot, firstRoot, secondRoot]);
    expect(handle.snapshot().truncated).toBe(true);
    handle.disconnect();
  });

  it('resumes a late-root sweep across bounded idle slices', async () => {
    vi.useFakeTimers();
    const idleCallbacks: Array<(deadline: { didTimeout: boolean; timeRemaining(): number }) => void> = [];
    vi.stubGlobal('requestIdleCallback', vi.fn((callback: (typeof idleCallbacks)[number]) => {
      idleCallbacks.push(callback);
      return idleCallbacks.length;
    }));
    vi.stubGlobal('cancelIdleCallback', vi.fn());
    const baseHost = document.createElement('div');
    const baseRoot = openShadow(baseHost);
    document.body.append(baseHost);
    baseRoot.append(document.createElement('span'), document.createElement('span'));
    const lateHost = document.createElement('div');
    baseRoot.append(lateHost);
    const handle = observeOpenComposedTree(
      baseRoot,
      () => {},
      { rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS },
    );
    const lateRoot = openShadow(lateHost);

    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS);
    for (let slice = 0; slice < 3; slice += 1) {
      const callback = idleCallbacks.shift();
      expect(callback).toBeDefined();
      callback!({ didTimeout: false, timeRemaining: () => 0 });
      await vi.advanceTimersByTimeAsync(0);
    }

    expect(handle.snapshot().roots).toEqual([baseRoot, lateRoot]);
    expect(handle.snapshot().truncated).toBe(true);
    for (let slice = 0; slice < 3; slice += 1) {
      const completion = idleCallbacks.shift();
      expect(completion).toBeDefined();
      completion!({ didTimeout: false, timeRemaining: () => 0 });
      if (!handle.snapshot().truncated) break;
      await vi.advanceTimersByTimeAsync(0);
    }
    expect(handle.snapshot().truncated).toBe(false);
    handle.disconnect();
  });

  it('backs off empty late-root sweeps and resets after a child-list mutation', async () => {
    vi.useFakeTimers();
    const getRoot = vi.fn(() => null);
    const handle = observeOpenComposedTree(
      document,
      () => {},
      {
        getShadowRoot: getRoot,
        rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS,
      },
    );
    getRoot.mockClear();

    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS);
    expect(getRoot).toHaveBeenCalled();
    getRoot.mockClear();
    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS);
    expect(getRoot).not.toHaveBeenCalled();

    document.body.append(document.createElement('div'));
    await vi.advanceTimersByTimeAsync(0);
    getRoot.mockClear();
    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS);
    expect(getRoot).toHaveBeenCalled();
    handle.disconnect();
  });

  it('does not postpone a pending sweep during continuous child-list churn', async () => {
    vi.useFakeTimers();
    const host = document.createElement('div');
    document.body.append(host);
    const handle = observeOpenComposedTree(
      document,
      () => {},
      { rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS },
    );
    const shadow = openShadow(host);

    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS / 2);
    document.body.append(document.createElement('span'));
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync((MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS / 2) - 1);
    document.body.append(document.createElement('span'));
    await vi.advanceTimersByTimeAsync(0);
    expect(handle.snapshot().roots).toEqual([document]);

    await vi.advanceTimersByTimeAsync(1);
    expect(handle.snapshot().roots).toContain(shadow);
    handle.disconnect();
  });

  it('periodically discovers a late closed root and observes then cleans up its mutations', async () => {
    vi.useFakeTimers();
    const host = document.createElement('div');
    document.body.append(host);
    const entries = new Map<Element, ShadowRoot>();
    const changes: ComposedTreeChange[] = [];
    const handle = observeOpenComposedTree(
      document,
      (change) => changes.push(change),
      {
        getShadowRoot: rootGetter(entries),
        rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS,
      },
    );

    const closed = closedShadow(host);
    entries.set(host, closed);
    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS);
    expect(handle.snapshot().roots).toEqual([document, closed]);

    changes.length = 0;
    closed.append(document.createElement('input'));
    await vi.advanceTimersByTimeAsync(0);
    expect(changes.some((change) => change.reason === 'mutation')).toBe(true);

    host.remove();
    await vi.advanceTimersByTimeAsync(0);
    expect(handle.snapshot().roots).toEqual([document]);
    changes.length = 0;
    closed.append(document.createElement('input'));
    await vi.advanceTimersByTimeAsync(0);
    expect(changes).toHaveLength(0);
    handle.disconnect();
  });

  it('keeps nested roots deduplicated across mutation and periodic refreshes', async () => {
    vi.useFakeTimers();
    const outerHost = document.createElement('div');
    const outer = openShadow(outerHost);
    document.body.append(outerHost);
    const handle = observeOpenComposedTree(
      document,
      () => {},
      { rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS },
    );
    const nestedHost = document.createElement('div');
    const nested = openShadow(nestedHost);
    outer.append(nestedHost);

    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS * 3);
    const roots = handle.snapshot().roots;
    expect(roots).toEqual([document, outer, nested]);
    expect(new Set(roots).size).toBe(roots.length);
    handle.disconnect();
  });

  it('unobserves an open root after its host disconnects', async () => {
    const host = document.createElement('div');
    const shadow = openShadow(host);
    document.body.append(host);
    const changes: ComposedTreeChange[] = [];
    const handle = observeOpenComposedTree(document, (change) => changes.push(change));

    host.remove();
    await flushMutations();
    expect(handle.snapshot().roots).toEqual([document]);

    changes.length = 0;
    shadow.append(document.createElement('input'));
    await flushMutations();
    expect(changes).toHaveLength(0);
    handle.disconnect();
  });

  it('frees the root budget before processing same-batch replacements', async () => {
    const baseHost = document.createElement('div');
    const baseRoot = openShadow(baseHost);
    document.body.append(baseHost);
    const oldHost = document.createElement('div');
    const oldRoot = openShadow(oldHost);
    baseRoot.append(oldHost);
    const handle = observeOpenComposedTree(baseRoot, () => {}, {
      maxRoots: 2,
      maxVisitedElements: 1,
    });
    const newHost = document.createElement('div');
    const newRoot = openShadow(newHost);

    oldHost.remove();
    oldRoot.append(document.createElement('span'));
    baseRoot.append(newHost);
    await flushMutations();

    expect(handle.snapshot().roots).toEqual([baseRoot, newRoot]);
    expect(handle.snapshot().truncated).toBe(false);
    handle.disconnect();
  });

  it('keeps incremental truncation fail-closed until an authoritative refresh completes', async () => {
    const baseHost = document.createElement('div');
    const baseRoot = openShadow(baseHost);
    document.body.append(baseHost);
    const handle = observeOpenComposedTree(
      baseRoot,
      () => {},
      { maxVisitedElements: 1 },
    );
    expect(handle.snapshot().truncated).toBe(false);

    const wrapper = document.createElement('div');
    const child = document.createElement('span');
    wrapper.append(child);
    baseRoot.append(wrapper);
    await flushMutations();
    expect(handle.snapshot().truncated).toBe(true);

    child.remove();
    expect(handle.refresh().truncated).toBe(false);
    handle.disconnect();
  });

  it('does not recount mutation records already covered by an authoritative refresh', async () => {
    const baseHost = document.createElement('div');
    const baseRoot = openShadow(baseHost);
    document.body.append(baseHost);
    const handle = observeOpenComposedTree(
      baseRoot,
      () => {},
      { maxVisitedElements: 1 },
    );

    baseRoot.append(document.createElement('span'));
    expect(handle.refresh().truncated).toBe(false);
    await flushMutations();

    expect(handle.snapshot().truncated).toBe(false);
    expect(handle.snapshot().visitedElements).toBe(1);
    handle.disconnect();
  });

  it('accounts for the element budget across separate mutation batches', async () => {
    const baseHost = document.createElement('div');
    const baseRoot = openShadow(baseHost);
    document.body.append(baseHost);
    const handle = observeOpenComposedTree(
      baseRoot,
      () => {},
      { maxVisitedElements: 2 },
    );

    baseRoot.append(document.createElement('span'));
    await flushMutations();
    expect(handle.snapshot().truncated).toBe(false);
    baseRoot.append(document.createElement('span'));
    await flushMutations();
    expect(handle.snapshot().truncated).toBe(false);
    baseRoot.append(document.createElement('span'));
    await flushMutations();
    expect(handle.snapshot().truncated).toBe(true);
    handle.disconnect();
  });

  it('bounds the added-node work performed in one mutation flush', async () => {
    vi.useFakeTimers();
    const baseHost = document.createElement('div');
    const baseRoot = openShadow(baseHost);
    document.body.append(baseHost);
    const handle = observeOpenComposedTree(baseRoot, () => {});
    const additions = Array.from({ length: 2_049 }, () => document.createElement('span'));

    baseRoot.append(...additions);
    await vi.advanceTimersByTimeAsync(0);

    expect(handle.snapshot().truncated).toBe(true);
    expect(handle.snapshot().visitedElements).toBe(2_048);
    handle.disconnect();
  });

  it('re-probes known hosts after removed-node cleanup is truncated', async () => {
    vi.useFakeTimers();
    const baseHost = document.createElement('div');
    const baseRoot = openShadow(baseHost);
    document.body.append(baseHost);
    const container = document.createElement('div');
    container.append(...Array.from({ length: 2_048 }, () => document.createElement('span')));
    const shadowHost = document.createElement('div');
    const shadowRoot = openShadow(shadowHost);
    container.append(shadowHost);
    baseRoot.append(container);
    const handle = observeOpenComposedTree(baseRoot, () => {});
    expect(handle.snapshot().roots).toContain(shadowRoot);

    container.remove();
    await vi.advanceTimersByTimeAsync(0);
    expect(handle.snapshot().truncated).toBe(true);
    expect(handle.snapshot().roots).not.toContain(shadowRoot);

    baseRoot.append(shadowHost);
    await vi.advanceTimersByTimeAsync(0);
    expect(handle.snapshot().roots).toContain(shadowRoot);
    expect(handle.snapshot().truncated).toBe(true);
    handle.disconnect();
  });

  it('automatically tears down when a shadow base root disconnects', async () => {
    vi.useFakeTimers();
    const host = document.createElement('div');
    const shadow = openShadow(host);
    document.body.append(host);
    const onChange = vi.fn();
    observeOpenComposedTree(
      shadow,
      onChange,
      { rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS },
    );

    host.remove();
    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS);
    shadow.append(document.createElement('input'));
    await vi.advanceTimersByTimeAsync(DEFAULT_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS);

    expect(onChange).not.toHaveBeenCalled();
  });

  it('disconnect is idempotent and prevents future mutation or polling callbacks', async () => {
    vi.useFakeTimers();
    const onChange = vi.fn();
    const handle = observeOpenComposedTree(
      document,
      onChange,
      { rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS },
    );
    handle.disconnect();
    handle.disconnect();

    const host = document.createElement('div');
    openShadow(host);
    document.body.append(host);
    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS * 2);

    expect(onChange).not.toHaveBeenCalled();
    expect(handle.snapshot().roots).toEqual([document]);
  });

  it('cancels a pending platform idle callback on disconnect', async () => {
    vi.useFakeTimers();
    type TestIdleCallback = (deadline: { didTimeout: boolean; timeRemaining(): number }) => void;
    let idleCallback: TestIdleCallback | undefined;
    const requestIdleCallback = vi.fn((callback: TestIdleCallback) => {
      idleCallback = callback;
      return 17;
    });
    const cancelIdleCallback = vi.fn();
    vi.stubGlobal('requestIdleCallback', requestIdleCallback);
    vi.stubGlobal('cancelIdleCallback', cancelIdleCallback);
    const host = document.createElement('div');
    document.body.append(host);
    const handle = observeOpenComposedTree(
      document,
      () => {},
      { rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS },
    );
    const shadow = openShadow(host);

    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS);
    expect(requestIdleCallback).toHaveBeenCalledOnce();
    handle.disconnect();
    expect(cancelIdleCallback).toHaveBeenCalledWith(17);

    const staleCallback = idleCallback;
    expect(staleCallback).toBeDefined();
    (staleCallback as TestIdleCallback)({ didTimeout: true, timeRemaining: () => 0 });
    expect(handle.snapshot().roots).not.toContain(shadow);
  });

  it('validates the bounded rediscovery interval', () => {
    expect(() => observeOpenComposedTree(document, () => {}, {
      rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS - 1,
    })).toThrow(RangeError);
    expect(() => observeOpenComposedTree(document, () => {}, {
      rediscoveryIntervalMs: MAX_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS + 1,
    })).toThrow(RangeError);
  });
});
