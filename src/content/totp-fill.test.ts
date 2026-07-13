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
    const panel = createTotpPanel({ anchor: anchor(), onFill: vi.fn(), onCopy: vi.fn(), onUndo: vi.fn() });
    expect(panel.element.shadowRoot).toBeNull(); // closed root — unreachable from the page
    panel.update({ itemName: 'Forge', itemUser: 'z', code: '445566', remaining: 9 });
    expect(panel.root.querySelector('.code')!.textContent).toBe('445 566');
    panel.remove();
  });

  it('switches to the filled view', () => {
    const panel = createTotpPanel({ anchor: anchor(), onFill: vi.fn(), onCopy: vi.fn(), onUndo: vi.fn() });
    panel.update({ itemName: 'Forge', itemUser: 'z', code: '111222', remaining: 20 });
    panel.showFilled();
    expect(panel.root.querySelector('.badge')).not.toBeNull();
    panel.remove();
  });
});
