// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAutofillDocumentController } from './autofill-document-controller.js';
import { bindTrustedRootCaptureEvent } from './root-event-dispatch.js';

afterEach(() => {
  vi.restoreAllMocks();
  document.body.replaceChildren();
});

describe('bindTrustedRootCaptureEvent', () => {
  it('dispatches one trusted open-root target before an outer capture listener stops propagation', () => {
    const host = document.createElement('div');
    const root = host.attachShadow({ mode: 'open' });
    const input = document.createElement('input');
    root.append(input);
    document.body.append(host);
    const controller = createAutofillDocumentController(document);
    let dispatchComplete = false;
    const onEvent = vi.fn((target: EventTarget) => {
      expect(dispatchComplete).toBe(false);
      expect(target).toBe(input);
    });
    const cleanup = bindTrustedRootCaptureEvent(controller, 'focusin', onEvent);
    host.addEventListener('focusin', (event) => event.stopPropagation(), true);

    dispatchTrusted(input, new FocusEvent('focusin', { bubbles: true, composed: true }));
    dispatchComplete = true;

    expect(onEvent).toHaveBeenCalledOnce();
    cleanup();
    controller.disconnect();
  });

  it('uses the deepest trusted target across nested closed roots', async () => {
    const outerHost = document.createElement('div');
    const outerRoot = outerHost.attachShadow({ mode: 'closed' });
    const innerHost = document.createElement('div');
    const innerRoot = innerHost.attachShadow({ mode: 'closed' });
    const input = document.createElement('input');
    innerRoot.append(input);
    outerRoot.append(innerHost);
    document.body.append(outerHost);
    const roots = new Map<Element, ShadowRoot>([
      [outerHost, outerRoot],
      [innerHost, innerRoot],
    ]);
    const controller = createAutofillDocumentController(document, {
      getShadowRoot: (element) => roots.get(element) ?? null,
    });
    let dispatchComplete = false;
    const onEvent = vi.fn((target: EventTarget) => {
      expect(dispatchComplete).toBe(false);
      expect(target).toBe(input);
    });
    const cleanup = bindTrustedRootCaptureEvent(controller, 'focusin', onEvent);
    input.addEventListener('focusin', (event) => event.stopImmediatePropagation());

    const event = new FocusEvent('focusin', { bubbles: true, composed: true });
    mockNestedClosedComposedPath(event, input, innerRoot, innerHost, outerRoot, outerHost);
    dispatchTrusted(input, event);
    dispatchComplete = true;

    expect(onEvent).toHaveBeenCalledOnce();
    await Promise.resolve();
    expect(onEvent).toHaveBeenCalledOnce();
    cleanup();
    controller.disconnect();
  });

  it('defers a direct shadow-host target to one microtask fallback', async () => {
    const host = document.createElement('div');
    host.attachShadow({ mode: 'open' });
    document.body.append(host);
    const controller = createAutofillDocumentController(document);
    const onEvent = vi.fn();
    const cleanup = bindTrustedRootCaptureEvent(controller, 'pointerdown', onEvent);
    host.addEventListener('pointerdown', (event) => event.stopPropagation());
    const event = new PointerEvent('pointerdown', { bubbles: true, composed: true });
    const composedPath = vi.spyOn(event, 'composedPath');

    dispatchTrusted(host, event);
    composedPath.mockImplementation(() => { throw new Error('The dispatch path is no longer available'); });

    expect(onEvent).not.toHaveBeenCalled();
    await Promise.resolve();
    expect(onEvent).toHaveBeenCalledOnce();
    expect(onEvent).toHaveBeenCalledWith(host);
    cleanup();
    controller.disconnect();
  });

  it('uses the deepest host when a nested host is the event target', async () => {
    const outerHost = document.createElement('div');
    const outerRoot = outerHost.attachShadow({ mode: 'closed' });
    const innerHost = document.createElement('div');
    const innerRoot = innerHost.attachShadow({ mode: 'closed' });
    outerRoot.append(innerHost);
    document.body.append(outerHost);
    const roots = new Map<Element, ShadowRoot>([
      [outerHost, outerRoot],
      [innerHost, innerRoot],
    ]);
    const controller = createAutofillDocumentController(document, {
      getShadowRoot: (element) => roots.get(element) ?? null,
    });
    const onEvent = vi.fn();
    const cleanup = bindTrustedRootCaptureEvent(controller, 'pointerdown', onEvent);
    const event = new PointerEvent('pointerdown', { bubbles: true, composed: true });
    mockNestedHostComposedPath(event, innerHost, outerRoot, outerHost);
    innerHost.addEventListener('pointerdown', (nestedEvent) => nestedEvent.stopPropagation(), true);

    dispatchTrusted(innerHost, event);

    expect(onEvent).not.toHaveBeenCalled();
    await Promise.resolve();
    expect(onEvent).toHaveBeenCalledOnce();
    expect(onEvent).toHaveBeenCalledWith(innerHost);
    cleanup();
    controller.disconnect();
  });

  it('keeps host fallbacks isolated by event identity', async () => {
    const firstHost = document.createElement('div');
    const secondHost = document.createElement('div');
    firstHost.attachShadow({ mode: 'open' });
    secondHost.attachShadow({ mode: 'open' });
    document.body.append(firstHost, secondHost);
    const controller = createAutofillDocumentController(document);
    const onEvent = vi.fn();
    const cleanup = bindTrustedRootCaptureEvent(controller, 'pointerdown', onEvent);

    dispatchTrusted(firstHost, new PointerEvent('pointerdown', { bubbles: true, composed: true }));
    dispatchTrusted(secondHost, new PointerEvent('pointerdown', { bubbles: true, composed: true }));

    expect(onEvent).not.toHaveBeenCalled();
    await Promise.resolve();
    expect(onEvent).toHaveBeenCalledTimes(2);
    expect(onEvent).toHaveBeenNthCalledWith(1, firstHost);
    expect(onEvent).toHaveBeenNthCalledWith(2, secondHost);
    cleanup();
    controller.disconnect();
  });

  it('ignores untrusted events and cancels a queued fallback during cleanup', async () => {
    const host = document.createElement('div');
    const root = host.attachShadow({ mode: 'open' });
    const input = document.createElement('input');
    root.append(input);
    document.body.append(host);
    const controller = createAutofillDocumentController(document);
    const onEvent = vi.fn();
    const cleanup = bindTrustedRootCaptureEvent(controller, 'pointerdown', onEvent);

    input.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, composed: true }));
    dispatchTrusted(host, new PointerEvent('pointerdown', { bubbles: true, composed: true }));
    cleanup();
    cleanup();
    await Promise.resolve();

    expect(onEvent).not.toHaveBeenCalled();
    controller.disconnect();
  });

  it('cancels a queued fallback when the controller disconnects first', async () => {
    const host = document.createElement('div');
    host.attachShadow({ mode: 'open' });
    document.body.append(host);
    const controller = createAutofillDocumentController(document);
    const onEvent = vi.fn();
    const cleanup = bindTrustedRootCaptureEvent(controller, 'pointerdown', onEvent);

    dispatchTrusted(host, new PointerEvent('pointerdown', { bubbles: true, composed: true }));
    controller.disconnect();
    await Promise.resolve();

    expect(onEvent).not.toHaveBeenCalled();
    cleanup();
  });

  it('follows dynamically refreshed roots and removes listeners from detached roots', async () => {
    const roots = new Map<Element, ShadowRoot>();
    const controller = createAutofillDocumentController(document, {
      observeInitially: false,
      getShadowRoot: (element) => roots.get(element) ?? null,
    });
    const onEvent = vi.fn();
    const cleanup = bindTrustedRootCaptureEvent(controller, 'contextmenu', onEvent);
    const host = document.createElement('div');
    const root = host.attachShadow({ mode: 'closed' });
    const input = document.createElement('input');
    root.append(input);
    document.body.append(host);
    roots.set(host, root);
    controller.refresh();

    const first = new MouseEvent('contextmenu', { bubbles: true, composed: true });
    mockClosedComposedPath(first, input, root, host);
    dispatchTrusted(input, first);
    expect(onEvent).toHaveBeenCalledOnce();
    await Promise.resolve();
    expect(onEvent).toHaveBeenCalledOnce();

    host.remove();
    controller.refresh();
    const second = new MouseEvent('contextmenu', { bubbles: true, composed: true });
    dispatchTrusted(input, second);
    expect(onEvent).toHaveBeenCalledOnce();

    cleanup();
    controller.disconnect();
  });
});

function dispatchTrusted(target: EventTarget, event: Event): void {
  Object.defineProperty(event, 'isTrusted', { value: true });
  target.dispatchEvent(event);
}

function mockClosedComposedPath(
  event: Event,
  target: Element,
  root: ShadowRoot,
  host: Element,
): void {
  const outerPath = documentPath(host);
  const fullPath = [target, root, ...outerPath];
  let dispatchPathRead = false;
  vi.spyOn(event, 'composedPath').mockImplementation(() => {
    if (event.currentTarget === null) {
      if (dispatchPathRead) return [];
      dispatchPathRead = true;
      return fullPath;
    }
    if (event.currentTarget === root || event.currentTarget === target) return fullPath;
    return outerPath;
  });
}

function mockNestedClosedComposedPath(
  event: Event,
  target: Element,
  innerRoot: ShadowRoot,
  innerHost: Element,
  outerRoot: ShadowRoot,
  outerHost: Element,
): void {
  const documentView = documentPath(outerHost);
  const outerRootView = [innerHost, outerRoot, ...documentView];
  const fullPath = [target, innerRoot, innerHost, outerRoot, ...documentView];
  let dispatchPathRead = false;
  vi.spyOn(event, 'composedPath').mockImplementation(() => {
    if (event.currentTarget === null) {
      if (dispatchPathRead) return [];
      dispatchPathRead = true;
      return fullPath;
    }
    if (event.currentTarget === innerRoot || event.currentTarget === target) return fullPath;
    if (event.currentTarget === outerRoot || event.currentTarget === innerHost) return outerRootView;
    return documentView;
  });
}

function mockNestedHostComposedPath(
  event: Event,
  target: Element,
  outerRoot: ShadowRoot,
  outerHost: Element,
): void {
  const documentView = documentPath(outerHost);
  const fullPath = [target, outerRoot, ...documentView];
  let dispatchPathRead = false;
  vi.spyOn(event, 'composedPath').mockImplementation(() => {
    if (event.currentTarget === null) {
      if (dispatchPathRead) return [];
      dispatchPathRead = true;
      return fullPath;
    }
    if (event.currentTarget === outerRoot || event.currentTarget === target) return fullPath;
    return documentView;
  });
}

function documentPath(target: Element): EventTarget[] {
  return [target, document.body, document.documentElement, document, window];
}
