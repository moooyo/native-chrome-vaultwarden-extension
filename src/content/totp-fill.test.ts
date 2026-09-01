// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createTotpPanel } from './totp-fill.js';

// The factory mounts a render-based surface inside a CLOSED shadow root (no custom element — content
// scripts run in an isolated world with no custom-element registry, Chromium 41118431). The closed root
// is exposed only through the handle's `.root`; the host's own `.shadowRoot` stays null. Rendering is
// synchronous, so the latest view is present immediately after any drive call.

afterEach(() => document.body.replaceChildren());

function anchor(): HTMLElement {
  const el = document.createElement('input');
  document.body.append(el);
  return el;
}

describe('createTotpPanel', () => {
  it('mounts a closed-shadow host and pushes the live code via update()', () => {
    const panel = createTotpPanel({
      anchor: anchor(), onSelect: vi.fn(), onChooseOther: vi.fn(),
      onFill: vi.fn(), onCopy: vi.fn(), onUndo: vi.fn(),
    });
    expect(panel.element.shadowRoot).toBeNull(); // closed root — unreachable from the page
    panel.update({ itemName: 'Forge', itemUser: 'z', code: '445566', remaining: 9 });
    expect(panel.root.querySelector('.code')!.textContent!.replace(/\s/g, '')).toBe('445566');
    panel.remove();
  });

  it('switches to the filled view', () => {
    const panel = createTotpPanel({
      anchor: anchor(), onSelect: vi.fn(), onChooseOther: vi.fn(),
      onFill: vi.fn(), onCopy: vi.fn(), onUndo: vi.fn(),
    });
    panel.update({ itemName: 'Forge', itemUser: 'z', code: '111222', remaining: 20 });
    panel.showFilled();
    expect(panel.root.querySelector('.badge')).not.toBeNull();
    panel.remove();
  });

  it('shows bounded candidates without a code before trusted selection', () => {
    const onSelect = vi.fn();
    const panel = createTotpPanel({
      anchor: anchor(), onSelect, onChooseOther: vi.fn(),
      onFill: vi.fn(), onCopy: vi.fn(), onUndo: vi.fn(),
    });
    panel.showCandidates({
      candidates: [
        { key: 'candidate-0', name: 'Forge', username: 'ada@example.com', reprompt: false },
        { key: 'candidate-1', name: 'Forge', username: 'grace@example.com', reprompt: true },
      ],
      overflowCount: 3,
    });
    expect(panel.root.querySelector('.code')).toBeNull();
    expect(panel.root.textContent).toContain('ada@example.com');
    expect(panel.root.textContent).toContain('grace@example.com');
    expect(panel.root.textContent).toContain('另有 3 个匹配项未显示');
    const event = new MouseEvent('click', { bubbles: true });
    Object.defineProperty(event, 'isTrusted', { value: true });
    panel.root.querySelector<HTMLElement>('[data-candidate-key="candidate-1"]')!.dispatchEvent(event);
    expect(onSelect).toHaveBeenCalledWith('candidate-1');
    panel.remove();
  });
});
