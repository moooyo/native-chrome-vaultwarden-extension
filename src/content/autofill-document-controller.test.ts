// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createAutofillDocumentController,
  deepActiveElement,
  rootForElement,
  trustedComposedTarget,
} from './autofill-document-controller.js';
import { MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS } from './composed-tree.js';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  document.body.replaceChildren();
});

async function flushMutations(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe('autofill document controller', () => {
  it('discovers nested closed roots and follows their known deep focus chain', () => {
    const outerHost = document.createElement('div');
    const outer = outerHost.attachShadow({ mode: 'closed' });
    const innerHost = document.createElement('div');
    const inner = innerHost.attachShadow({ mode: 'closed' });
    const input = document.createElement('input');
    inner.append(input);
    outer.append(innerHost);
    document.body.append(outerHost);
    const entries = new Map<Element, ShadowRoot>([[outerHost, outer], [innerHost, inner]]);
    const controller = createAutofillDocumentController(document, {
      getShadowRoot: (element) => entries.get(element) ?? null,
    });

    expect(controller.roots()).toEqual([document, outer, inner]);
    vi.spyOn(document, 'activeElement', 'get').mockReturnValue(outerHost);
    vi.spyOn(outer, 'activeElement', 'get').mockReturnValue(innerHost);
    vi.spyOn(inner, 'activeElement', 'get').mockReturnValue(input);
    expect(controller.deepActiveElement()).toBe(input);
    expect(deepActiveElement(document, controller.roots())).toBe(input);
    controller.disconnect();
  });

  it('enters a closed root only after that exact root joins the controller inventory', () => {
    const host = document.createElement('div');
    const closed = host.attachShadow({ mode: 'closed' });
    const input = document.createElement('input');
    closed.append(input);
    document.body.append(host);
    const controller = createAutofillDocumentController(document, {
      observeInitially: false,
      getShadowRoot: (element) => element === host ? closed : null,
    });
    vi.spyOn(document, 'activeElement', 'get').mockReturnValue(host);
    vi.spyOn(closed, 'activeElement', 'get').mockReturnValue(input);

    expect(controller.deepActiveElement()).toBe(host);
    expect(controller.refresh().roots).toEqual([document, closed]);
    expect(controller.deepActiveElement()).toBe(input);
    controller.disconnect();
  });

  it('does not scan periodically while observation is initially paused', async () => {
    vi.useFakeTimers();
    const onChange = vi.fn();
    const controller = createAutofillDocumentController(document, {
      observeInitially: false,
      rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS,
      onChange,
    });
    const host = document.createElement('div');
    document.body.append(host);
    const shadow = host.attachShadow({ mode: 'open' });

    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS * 5);

    expect(controller.isObserving()).toBe(false);
    expect(controller.roots()).toEqual([document]);
    expect(controller.roots()).not.toContain(shadow);
    expect(onChange).not.toHaveBeenCalled();
    controller.disconnect();
  });

  it('resumes periodic discovery without missing a later attachShadow call', async () => {
    vi.useFakeTimers();
    const existingHost = document.createElement('div');
    const existingShadow = existingHost.attachShadow({ mode: 'open' });
    const lateHost = document.createElement('div');
    document.body.append(existingHost, lateHost);
    const controller = createAutofillDocumentController(document, {
      observeInitially: false,
      rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS,
    });

    expect(controller.resumeObservation().roots).toEqual([document, existingShadow]);
    expect(controller.isObserving()).toBe(true);
    const lateShadow = lateHost.attachShadow({ mode: 'open' });
    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS);
    expect(controller.roots()).toEqual([document, existingShadow, lateShadow]);
    controller.disconnect();
  });

  it('pauses background discovery while preserving explicit on-demand refresh', async () => {
    vi.useFakeTimers();
    const host = document.createElement('div');
    document.body.append(host);
    const controller = createAutofillDocumentController(document, {
      rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS,
    });
    controller.pauseObservation();
    const shadow = host.attachShadow({ mode: 'open' });

    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS * 3);
    expect(controller.isObserving()).toBe(false);
    expect(controller.roots()).not.toContain(shadow);

    expect(controller.refresh().roots).toContain(shadow);
    expect(controller.isObserving()).toBe(false);
    controller.disconnect();
  });

  it('keeps refresh as an immediate authoritative scan while observation is active', () => {
    const host = document.createElement('div');
    document.body.append(host);
    const controller = createAutofillDocumentController(document);
    const shadow = host.attachShadow({ mode: 'open' });

    expect(controller.roots()).toEqual([document]);
    expect(controller.refresh().roots).toEqual([document, shadow]);
    controller.disconnect();
  });

  it('exposes nested open roots and resolves the deepest focused control', () => {
    const outerHost = document.createElement('div');
    const outer = outerHost.attachShadow({ mode: 'open' });
    const innerHost = document.createElement('div');
    const inner = innerHost.attachShadow({ mode: 'open' });
    const input = document.createElement('input');
    inner.append(input);
    outer.append(innerHost);
    document.body.append(outerHost);

    const controller = createAutofillDocumentController(document);
    expect(controller.roots()).toEqual([document, outer, inner]);

    vi.spyOn(document, 'activeElement', 'get').mockReturnValue(outerHost);
    vi.spyOn(outer, 'activeElement', 'get').mockReturnValue(innerHost);
    vi.spyOn(inner, 'activeElement', 'get').mockReturnValue(input);
    expect(controller.deepActiveElement()).toBe(input);
    expect(deepActiveElement(document)).toBe(input);
    expect(rootForElement(input)).toBe(inner);
    controller.disconnect();
  });

  it('binds resources to dynamically attached roots and tears every binding down', async () => {
    vi.useFakeTimers();
    const host = document.createElement('div');
    document.body.append(host);
    const attached: Array<Document | ShadowRoot> = [];
    const detached: Array<Document | ShadowRoot> = [];
    const controller = createAutofillDocumentController(document, {
      rediscoveryIntervalMs: MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS,
    });
    controller.bindRoots((root) => {
      attached.push(root);
      return () => detached.push(root);
    });

    const shadow = host.attachShadow({ mode: 'open' });
    await vi.advanceTimersByTimeAsync(MIN_COMPOSED_TREE_REDISCOVERY_INTERVAL_MS);
    expect(attached).toEqual([document, shadow]);

    host.remove();
    controller.refresh();
    expect(detached).toEqual([shadow]);
    controller.disconnect();
    expect(detached).toEqual([shadow, document]);
  });

  it('reorders roots after a host move without rebinding existing resources', async () => {
    const firstHost = document.createElement('div');
    const firstRoot = firstHost.attachShadow({ mode: 'open' });
    const secondHost = document.createElement('div');
    const secondRoot = secondHost.attachShadow({ mode: 'open' });
    document.body.append(firstHost, secondHost);
    const attached: Array<Document | ShadowRoot> = [];
    const detached: Array<Document | ShadowRoot> = [];
    const controller = createAutofillDocumentController(document);
    controller.bindRoots((root) => {
      attached.push(root);
      return () => detached.push(root);
    });
    expect(controller.roots()).toEqual([document, firstRoot, secondRoot]);

    document.body.prepend(secondHost);
    await flushMutations();

    expect(controller.roots()).toEqual([document, secondRoot, firstRoot]);
    expect(attached).toEqual([document, firstRoot, secondRoot]);
    expect(detached).toEqual([]);
    controller.disconnect();
    expect(detached).toEqual(expect.arrayContaining([document, firstRoot, secondRoot]));
    expect(detached).toHaveLength(3);
  });

  it('returns the original open-shadow target only for trusted composed events', () => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    const button = document.createElement('button');
    shadow.append(button);
    document.body.append(host);
    let target: EventTarget | null = null;
    document.addEventListener('click', (event) => { target = trustedComposedTarget(event); }, { once: true });
    const event = new MouseEvent('click', { bubbles: true, composed: true });
    Object.defineProperty(event, 'isTrusted', { value: true });
    button.dispatchEvent(event);
    expect(target).toBe(button);

    const synthetic = new Event('click');
    expect(trustedComposedTarget(synthetic)).toBeNull();
  });
});
