// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { VwAutofillPopover } from './autofill-popover-element.js';
import './autofill-popover-element.js';

afterEach(() => {
  document.body.replaceChildren();
});

async function mount(configure: (element: VwAutofillPopover) => void): Promise<VwAutofillPopover> {
  const element = document.createElement('vw-autofill-popover') as VwAutofillPopover;
  configure(element);
  document.body.append(element);
  await element.updateComplete;
  return element;
}

function shadow(element: VwAutofillPopover): ShadowRoot {
  if (!element.shadowRoot) {
    throw new Error('element has no render root');
  }
  return element.shadowRoot;
}

function trustedClick(el: Element | null): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el?.dispatchEvent(event);
}

describe('vw-autofill-popover', () => {
  it('invokes onOpen only on a trusted trigger click', async () => {
    const onOpen = vi.fn();
    const element = await mount((el) => {
      el.view = 'trigger';
      el.onOpen = onOpen;
    });
    const trigger = shadow(element).querySelector('#vw-open');
    expect(trigger?.textContent).toContain('密屿');
    trigger?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(onOpen).not.toHaveBeenCalled();
    trustedClick(trigger);
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it('renders the status message inertly', async () => {
    const element = await mount((el) => {
      el.view = 'status';
      el.statusMessage = '<img src=x onerror=alert(1)> Locked';
    });
    const status = shadow(element).querySelector('.status');
    expect(status?.querySelector('img')).toBeNull();
    expect(status?.textContent).toContain('Locked');
  });

  it.each([
    ['login', '1 个匹配项', '没有匹配的登录项'] as const,
    ['card', '填充银行卡', '没有保存的银行卡'] as const,
    ['identity', '填充身份', '没有保存的身份'] as const,
  ])('renders the %s header and empty state', async (kind, header, empty) => {
    const withRows = await mount((el) => {
      el.kind = kind;
      el.view = 'list';
      el.candidates = [{ id: '1', name: 'Item', sub: 'sub', favorite: false }];
    });
    expect(shadow(withRows).textContent).toContain('密屿');
    expect(shadow(withRows).textContent).toContain(header);

    const emptyEl = await mount((el) => {
      el.kind = kind;
      el.view = 'list';
      el.candidates = [];
    });
    expect(shadow(emptyEl).textContent).toContain(empty);
  });

  it('renders each candidate as a MiYu row with a monogram tile and a 填充 action', async () => {
    const element = await mount((el) => {
      el.view = 'list';
      el.candidates = [{ id: '1', name: 'Alpha', sub: 'a@example.com', favorite: false }];
    });
    const root = shadow(element);
    expect(root.querySelector('.tile')?.textContent).toBe('A');
    expect(root.querySelector('.fill')?.textContent).toContain('填充');
    expect(root.textContent).toContain('Alpha');
    expect(root.textContent).toContain('a@example.com');
  });

  it('calls onSelect with the candidate id resolved from the in-memory index', async () => {
    const onSelect = vi.fn();
    const element = await mount((el) => {
      el.view = 'list';
      el.candidates = [
        { id: 'first', name: 'Alpha', sub: 'a@example.com', favorite: false },
        { id: 'second', name: 'Beta', sub: 'b@example.com', favorite: true },
      ];
      el.onSelect = onSelect;
    });
    const buttons = shadow(element).querySelectorAll('button.candidate');
    trustedClick(buttons[1] ?? null);
    expect(onSelect).toHaveBeenCalledWith('second');
  });

  it('ignores untrusted candidate clicks', async () => {
    const onSelect = vi.fn();
    const element = await mount((el) => {
      el.view = 'list';
      el.candidates = [{ id: '1', name: 'Alpha', sub: 'a@example.com', favorite: false }];
      el.onSelect = onSelect;
    });
    shadow(element).querySelector('button.candidate')?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(onSelect).not.toHaveBeenCalled();
  });

  it('never emits cipher ids into DOM attributes or serialized HTML', async () => {
    const element = await mount((el) => {
      el.view = 'list';
      el.candidates = [{ id: 'cipher-secret-id', name: 'Alpha', sub: 'a@example.com', favorite: false }];
    });
    const root = shadow(element);
    expect(root.querySelector('[data-cipher-id]')).toBeNull();
    expect(root.querySelector('[data-target]')).toBeNull();
    expect(root.innerHTML).not.toContain('cipher-secret-id');
  });

  it('uses selected-row semantics without exposing candidate ids', async () => {
    const element = await mount((el) => {
      el.view = 'list';
      el.candidates = [{ id: 'cipher-secret-id', name: 'Alpha', sub: 'a@example.com', favorite: false }];
    });
    const row = shadow(element).querySelector('[role="option"]')!;
    expect(row.getAttribute('aria-selected')).toBe('true');
    expect(shadow(element).innerHTML).not.toContain('cipher-secret-id');
  });

  it('caps the list height and marks long lists as locally scrollable', async () => {
    const element = await mount((el) => {
      el.view = 'list';
      el.candidates = Array.from({ length: 12 }, (_, index) => ({
        id: String(index),
        name: `Item ${index}`,
        sub: `sub ${index}`,
        favorite: false,
      }));
    });
    expect(shadow(element).querySelector('.list.scrollable')).not.toBeNull();
    const styleText = styleTextOf(VwAutofillPopover);
    expect(styleText).toContain('max-height');
    expect(styleText).toContain('overflow-y');
  });

  it('declares dark and reduced-motion tokens', () => {
    const styleText = styleTextOf(VwAutofillPopover);
    expect(styleText).toContain('prefers-color-scheme: dark');
    expect(styleText).toContain('prefers-reduced-motion: reduce');
  });
});

function styleTextOf(ctor: typeof VwAutofillPopover): string {
  const styles = ctor.styles;
  const list = Array.isArray(styles) ? styles : [styles];
  return list.map((style) => String((style as { cssText: string }).cssText)).join('\n');
}
