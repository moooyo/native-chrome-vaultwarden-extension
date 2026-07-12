// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createTotpPanel } from './totp-fill.js';

afterEach(() => document.body.replaceChildren());

function anchor(): HTMLElement {
  const el = document.createElement('input');
  document.body.append(el);
  return el;
}

describe('createTotpPanel', () => {
  it('mounts a closed-shadow host and pushes the live code via update()', async () => {
    const panel = createTotpPanel({ anchor: anchor(), onFill: vi.fn(), onCopy: vi.fn(), onUndo: vi.fn() });
    expect(panel.element.shadowRoot).toBeNull(); // closed root — unreachable from the page
    panel.update({ itemName: 'Forge', itemUser: 'z', code: '445566', remaining: 9 });
    await Promise.resolve();
    const el = panel.root.querySelector('vw-totp-panel')!;
    await (el as unknown as { updateComplete: Promise<unknown> }).updateComplete;
    expect(el.shadowRoot!.querySelector('.code')!.textContent).toBe('445 566');
    panel.remove();
  });

  it('switches to the filled view', async () => {
    const panel = createTotpPanel({ anchor: anchor(), onFill: vi.fn(), onCopy: vi.fn(), onUndo: vi.fn() });
    panel.update({ itemName: 'Forge', itemUser: 'z', code: '111222', remaining: 20 });
    panel.showFilled();
    const el = panel.root.querySelector('vw-totp-panel')!;
    await (el as unknown as { updateComplete: Promise<unknown> }).updateComplete;
    expect(el.shadowRoot!.querySelector('.badge')).not.toBeNull();
    panel.remove();
  });
});
