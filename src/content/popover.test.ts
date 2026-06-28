// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createAutofillPopover } from './popover.js';
import type { AutofillPopover } from './popover.js';

describe('autofill popover', () => {
  beforeEach(() => {
    document.body.innerHTML = '<input id="pass" type="password">';
  });

  it('renders status text in shadow DOM', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn() });
    popover.showStatus('Locked');
    expect(popoverRoot(popover).textContent).toContain('Locked');
  });

  it('does not expose its shadow root through the host element', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn() });

    expect(popover.element.shadowRoot).toBeNull();
  });

  it('ignores untrusted open clicks', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const onOpen = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen, onSelect: vi.fn() });

    popoverRoot(popover).querySelector<HTMLButtonElement>('#open')?.click();

    expect(onOpen).not.toHaveBeenCalled();
  });

  it('renders candidates and calls onSelect when clicked', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const onSelect = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect });
    popover.showCandidates([{
      id: '1',
      name: 'Example',
      username: 'me@example.com',
      matchedUri: 'https://example.com',
      matchType: 0,
      favorite: false,
    }]);

    trustedClick(popoverRoot(popover).querySelector<HTMLButtonElement>('button')!);

    expect(onSelect).toHaveBeenCalledWith('1');
    expect(popoverRoot(popover).textContent).not.toContain('secret');
  });

  it('ignores untrusted candidate clicks', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const onSelect = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect });
    popover.showCandidates([{
      id: '1',
      name: 'Example',
      username: 'me@example.com',
      matchedUri: 'https://example.com',
      matchType: 0,
      favorite: false,
    }]);

    popoverRoot(popover).querySelector<HTMLButtonElement>('button')?.click();

    expect(onSelect).not.toHaveBeenCalled();
  });

  it('does not render cipher ids into DOM attributes', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn() });
    popover.showCandidates([{
      id: 'cipher-secret-id',
      name: 'Example',
      username: 'me@example.com',
      matchedUri: 'https://example.com',
      matchType: 0,
      favorite: false,
    }]);

    expect(popoverRoot(popover).querySelector('[data-cipher-id]')).toBeNull();
    expect(popoverRoot(popover).innerHTML).not.toContain('cipher-secret-id');
  });
});

function popoverRoot(popover: AutofillPopover): ShadowRoot {
  const root = (popover as AutofillPopover & { root?: ShadowRoot }).root ?? popover.element.shadowRoot;
  if (!root) throw new Error('Popover root is unavailable');
  return root;
}

function trustedClick(button: HTMLButtonElement): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  button.dispatchEvent(event);
}
