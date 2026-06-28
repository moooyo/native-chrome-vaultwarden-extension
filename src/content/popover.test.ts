// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createAutofillPopover } from './popover.js';

describe('autofill popover', () => {
  beforeEach(() => {
    document.body.innerHTML = '<input id="pass" type="password">';
  });

  it('renders status text in shadow DOM', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect: vi.fn() });
    popover.showStatus('Locked');
    expect(popover.element.shadowRoot?.textContent).toContain('Locked');
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

    popover.element.shadowRoot?.querySelector<HTMLButtonElement>('[data-cipher-id="1"]')?.click();

    expect(onSelect).toHaveBeenCalledWith('1');
    expect(popover.element.shadowRoot?.textContent).not.toContain('secret');
  });
});
