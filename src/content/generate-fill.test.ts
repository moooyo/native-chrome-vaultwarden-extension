// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createGeneratePanel } from './generate-fill.js';

afterEach(() => document.body.replaceChildren());

function anchor(): HTMLElement {
  const el = document.createElement('input');
  el.type = 'password';
  document.body.append(el);
  return el;
}

function opts() {
  return { anchor: anchor(), onRegenerate: vi.fn(), onLength: vi.fn(), onNumbers: vi.fn(), onSymbols: vi.fn(), onUse: vi.fn(), onUndo: vi.fn() };
}

describe('createGeneratePanel', () => {
  it('mounts a closed-shadow host and pushes the suggestion via update()', async () => {
    const panel = createGeneratePanel(opts());
    expect(panel.element.shadowRoot).toBeNull();
    panel.update({ password: 'Kp7$mn2Q', strength: '极强', length: 18, numbers: true, symbols: true });
    const el = panel.root.querySelector('vw-generate-panel')!;
    await (el as unknown as { updateComplete: Promise<unknown> }).updateComplete;
    expect(el.shadowRoot!.querySelector('.suggest')!.textContent).toBe('Kp7$mn2Q');
    panel.remove();
  });

  it('switches to the saved view', async () => {
    const panel = createGeneratePanel(opts());
    panel.showSaved({ name: 'quill.app', user: 'me@x.dev' });
    const el = panel.root.querySelector('vw-generate-panel')!;
    await (el as unknown as { updateComplete: Promise<unknown> }).updateComplete;
    expect(el.shadowRoot!.querySelector('.saved')).not.toBeNull();
    panel.remove();
  });
});
