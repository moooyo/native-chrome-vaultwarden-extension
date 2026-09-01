// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createWebsitePasskeyConditionalUi,
  type WebsitePasskeyConditionalUiBinding,
} from './conditional-passkey-ui.js';
import {
  claimInlineSurface,
  inlineSurfaceScope,
  releaseInlineSurface,
} from './inline-surface-coordinator.js';
import type { AutofillPopover, AutofillPopoverOptions } from './popover.js';

const BINDING: WebsitePasskeyConditionalUiBinding = {
  ceremonyId: '11111111-1111-4111-8111-111111111111',
  bridgeRequestId: '22222222-2222-4222-8222-222222222222',
  candidates: [{ id: 'Y3JlZGVudGlhbA', name: 'Work', username: 'alice@example.com' }],
};

describe('conditional Passkey inline UI', () => {
  let input: HTMLInputElement;
  let created: Array<{ readonly options: AutofillPopoverOptions; readonly popover: AutofillPopover }>;

  beforeEach(() => {
    document.body.innerHTML = '<form><input autocomplete="username webauthn"></form>';
    input = document.querySelector('input')!;
    created = [];
  });

  afterEach(() => {
    document.body.replaceChildren();
    vi.useRealTimers();
  });

  it('stays silent for already focused and later programmatically focused fields', () => {
    input.focus();
    const ui = createWebsitePasskeyConditionalUi(document, fakeFactory(created));
    ui.activate(BINDING, vi.fn());
    input.blur();
    input.focus();

    expect(created).toHaveLength(0);
    ui.dispose();
  });

  it('opens only after a trusted field interaction and submits only the selected credential', () => {
    const selected = vi.fn();
    const ui = createWebsitePasskeyConditionalUi(document, fakeFactory(created));
    ui.activate(BINDING, selected);

    trusted(input, new PointerEvent('pointerdown', { bubbles: true, composed: true }));
    expect(created).toHaveLength(1);
    expect(created[0]!.popover.open).toHaveBeenCalledWith(input);
    expect(created[0]!.popover.showCandidates).toHaveBeenCalledWith([
      { id: 'Y3JlZGVudGlhbA', name: 'Work', sub: 'alice@example.com', favorite: false },
    ]);

    created[0]!.options.onSelect('Y3JlZGVudGlhbA');
    expect(selected).toHaveBeenCalledWith('Y3JlZGVudGlhbA');
    expect(created[0]!.popover.remove).toHaveBeenCalledOnce();
    ui.dispose();
  });

  it('honors a bounded trusted receipt that occurred just before candidates arrived', () => {
    vi.useFakeTimers();
    const ui = createWebsitePasskeyConditionalUi(document, fakeFactory(created));
    trusted(input, new PointerEvent('pointerdown', { bubbles: true, composed: true }));
    input.focus();

    ui.activate(BINDING, vi.fn());
    expect(created).toHaveLength(1);
    ui.clear();
    vi.advanceTimersByTime(1_501);
    ui.activate(BINDING, vi.fn());
    expect(created).toHaveLength(1);
    ui.dispose();
  });

  it('owns the form scope over an ordinary autofill panel and releases it on teardown', () => {
    const ui = createWebsitePasskeyConditionalUi(document, fakeFactory(created));
    const scope = inlineSurfaceScope(input);
    const ordinaryOwner = {};
    const dismissOrdinary = vi.fn();
    expect(claimInlineSurface(scope, ordinaryOwner, dismissOrdinary)).toBe(true);
    ui.activate(BINDING, vi.fn());

    trusted(input, new PointerEvent('pointerdown', { bubbles: true, composed: true }));
    expect(dismissOrdinary).toHaveBeenCalledOnce();
    expect(claimInlineSurface(scope, ordinaryOwner, dismissOrdinary)).toBe(false);

    ui.clear(BINDING.ceremonyId, BINDING.bridgeRequestId);
    expect(claimInlineSurface(scope, ordinaryOwner, dismissOrdinary)).toBe(true);
    releaseInlineSurface(scope, ordinaryOwner);
    ui.dispose();
  });

  it('removes the visible surface on navigation and disposal', () => {
    const ui = createWebsitePasskeyConditionalUi(document, fakeFactory(created));
    ui.activate(BINDING, vi.fn());
    trusted(input, new PointerEvent('pointerdown', { bubbles: true, composed: true }));

    window.dispatchEvent(new PageTransitionEvent('pagehide'));
    expect(created[0]!.popover.remove).toHaveBeenCalledOnce();
    ui.dispose();
  });
});

function fakeFactory(
  created: Array<{ readonly options: AutofillPopoverOptions; readonly popover: AutofillPopover }>,
): (options: AutofillPopoverOptions) => AutofillPopover {
  return (options) => {
    const element = document.createElement('div');
    document.body.append(element);
    const popover: AutofillPopover = {
      element,
      root: {} as ShadowRoot,
      open: vi.fn(() => options.onOpen()),
      showStatus: vi.fn(),
      showCandidates: vi.fn(),
      showFilled: vi.fn(),
      hide: vi.fn(),
      remove: vi.fn(() => element.remove()),
    };
    created.push({ options, popover });
    return popover;
  };
}

function trusted(target: EventTarget, event: Event): void {
  Object.defineProperty(event, 'isTrusted', { value: true });
  target.dispatchEvent(event);
}
