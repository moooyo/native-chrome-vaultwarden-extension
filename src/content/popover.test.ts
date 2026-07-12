// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createAutofillPopover } from './popover.js';
import type { AutofillPopover } from './popover.js';
import type { VwAutofillPopover } from './ui/autofill-popover-element.js';

// The factory mounts the closed-shadow Lit element `vw-autofill-popover`. Its closed root is exposed
// only through the returned handle's `.root`; the host element's own `.shadowRoot` stays null so the
// page cannot reach it. These tests assert the factory wires the Lit element and drives its views.

describe('autofill popover factory', () => {
  beforeEach(() => {
    document.body.innerHTML = '<input id="pass" type="password">';
  });

  afterEach(() => {
    document.body.replaceChildren();
  });

  it('mounts the Lit element inside a closed shadow root the host does not expose', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn() });

    expect(customElements.get('vw-autofill-popover')).toBeDefined();
    expect(popover.element.shadowRoot).toBeNull();
    expect(popover.root.querySelector('vw-autofill-popover')).not.toBeNull();
  });

  it('renders status text in the element shadow DOM', async () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn() });
    popover.showStatus('Locked');
    expect((await content(popover)).textContent).toContain('Locked');
  });

  it('ignores untrusted open clicks', async () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const onOpen = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen, onSelect: vi.fn() });

    (await content(popover)).querySelector<HTMLButtonElement>('#vw-open')?.click();

    expect(onOpen).not.toHaveBeenCalled();
  });

  it('renders candidates (common shape) and calls onSelect when clicked', async () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const onSelect = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect });
    popover.showCandidates([{ id: '1', name: 'Example', sub: 'me@example.com', favorite: false }]);
    const root = await content(popover);
    trustedClick(root.querySelector<HTMLButtonElement>('button.candidate')!);
    expect(onSelect).toHaveBeenCalledWith('1');
    expect(root.textContent).toContain('me@example.com');
    expect(root.textContent).not.toContain('secret');
  });

  it('uses a card header when kind is card', async () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, kind: 'card', onOpen: vi.fn(), onSelect: vi.fn() });
    popover.showCandidates([{ id: '1', name: 'Visa', sub: '•••• 4242', favorite: false }]);
    expect((await content(popover)).textContent).toContain('填充银行卡');
  });

  it('uses an identity header when kind is identity', async () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, kind: 'identity', onOpen: vi.fn(), onSelect: vi.fn() });
    popover.showCandidates([{ id: '1', name: 'Ada Lovelace', sub: '1 Analytical Way', favorite: false }]);
    expect((await content(popover)).textContent).toContain('填充身份');
  });

  it('ignores untrusted candidate clicks', async () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const onSelect = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect });
    popover.showCandidates([{ id: '1', name: 'Example', sub: 'me@example.com', favorite: false }]);

    (await content(popover)).querySelector<HTMLButtonElement>('button.candidate')?.click();

    expect(onSelect).not.toHaveBeenCalled();
  });

  it('does not render cipher ids into DOM attributes or serialized HTML', async () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn() });
    popover.showCandidates([{
      id: 'cipher-secret-id',
      name: 'Example',
      sub: 'me@example.com',
      favorite: false,
    }]);
    const root = await content(popover);

    expect(root.querySelector('[data-cipher-id]')).toBeNull();
    expect(root.innerHTML).not.toContain('cipher-secret-id');
  });

  it('open() invokes onOpen without a DOM event', () => {
    const anchor = document.createElement('input');
    document.body.append(anchor);
    const onOpen = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen, onSelect: () => {} });
    popover.open();
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it('remove() detaches the host from the page', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn() });
    expect(popover.element.isConnected).toBe(true);
    popover.remove();
    expect(popover.element.isConnected).toBe(false);
  });
});

/** Resolves the open render root of the Lit element mounted inside the popover's closed root, after
 *  its latest scheduled render has flushed. */
async function content(popover: AutofillPopover): Promise<ShadowRoot> {
  const element = popover.root.querySelector('vw-autofill-popover') as VwAutofillPopover | null;
  if (!element) throw new Error('Popover element is unavailable');
  await element.updateComplete;
  if (!element.shadowRoot) throw new Error('Popover render root is unavailable');
  return element.shadowRoot;
}

function trustedClick(button: HTMLButtonElement): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  button.dispatchEvent(event);
}
