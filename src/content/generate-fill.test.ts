// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createGeneratePanel } from './generate-fill.js';

// The factory mounts a render-based surface inside a CLOSED shadow root (no custom element — content
// scripts run in an isolated world with no custom-element registry, Chromium 41118431). The closed root
// is exposed only through the returned handle's `.root`; the host's own `.shadowRoot` stays null.
// Rendering is synchronous, so no update flush is needed between drive and assert.

afterEach(() => document.body.replaceChildren());

function anchor(): HTMLElement {
  const el = document.createElement('input');
  el.type = 'password';
  document.body.append(el);
  return el;
}

function opts() {
  return { anchor: anchor(), onUsername: vi.fn(), onRegenerate: vi.fn(), onLength: vi.fn(), onNumbers: vi.fn(), onSymbols: vi.fn(), onUse: vi.fn(), onUndo: vi.fn() };
}

describe('createGeneratePanel', () => {
  it('mounts a closed-shadow host and pushes the suggestion via update()', () => {
    const panel = createGeneratePanel(opts());
    expect(panel.element.shadowRoot).toBeNull();
    panel.update({ username: 'me@x.dev', password: 'Kp7$mn2Q', strength: '极强', length: 18, numbers: true, symbols: true });
    expect(panel.root.querySelector('.suggest')!.textContent).toBe('Kp7$mn2Q');
    expect(panel.root.querySelector<HTMLInputElement>('.user input')!.value).toBe('me@x.dev');
    panel.remove();
  });

  it('switches to the saved view', () => {
    const panel = createGeneratePanel(opts());
    panel.showSaved({ name: 'quill.app', user: 'me@x.dev' });
    expect(panel.root.querySelector('.saved')).not.toBeNull();
    expect(panel.root.querySelector('.saved .s')!.textContent).toContain('me@x.dev');
    panel.remove();
  });

  it('remove() detaches the host from the page', () => {
    const panel = createGeneratePanel(opts());
    expect(panel.element.isConnected).toBe(true);
    panel.remove();
    expect(panel.element.isConnected).toBe(false);
  });
});
