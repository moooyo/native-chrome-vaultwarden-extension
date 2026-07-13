// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, type TemplateResult } from 'lit';

// The factories render the closed-shadow passkey dialogs via lit-html (no custom element — content
// scripts run in an isolated world with no custom-element registry, Chromium 41118431). The dialogs'
// own template gating (trusted confirm/select, index-only target selection) is covered by
// passkey-dialog-element.test.ts. Here we verify each factory configures the dialog, wires the Escape /
// one-shot settling it now owns, resolves its promise from the chosen action, and removes the surface.
// We mock the mount seam to capture the template the factory would render into a closed root, then
// render it into an open container so we can drive the buttons the user would click.

const surfaces = vi.hoisted(
  () =>
    [] as Array<{
      styleText: string;
      template: TemplateResult | undefined;
      remove: ReturnType<typeof vi.fn>;
    }>,
);

vi.mock('./ui/render-surface.js', () => ({
  mountRenderSurface: vi.fn((styleText: string) => {
    const entry = { styleText, template: undefined as TemplateResult | undefined, remove: vi.fn() };
    surfaces.push(entry);
    return {
      host: document.createElement('div'),
      root: document.createElement('div'),
      render: (template: TemplateResult) => {
        entry.template = template;
      },
      remove: entry.remove,
    };
  }),
}));

import { mountRenderSurface } from './ui/render-surface.js';
import { confirmPasskeyUse, choosePasskeyTarget } from './passkey-consent.js';

afterEach(() => {
  surfaces.length = 0;
  vi.mocked(mountRenderSurface).mockClear();
  document.body.replaceChildren();
});

/** Render the latest surface's captured template into an open container so its buttons are clickable. */
function latest(): { container: HTMLElement; remove: ReturnType<typeof vi.fn> } {
  const entry = surfaces.at(-1);
  if (!entry?.template) {
    throw new Error('no surface template captured');
  }
  const container = document.createElement('div');
  document.body.append(container);
  render(entry.template, container);
  return { container, remove: entry.remove };
}

function trustedClick(el: Element | null): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el?.dispatchEvent(event);
}

describe('confirmPasskeyUse', () => {
  it('mounts a consent dialog for the rpId', () => {
    void confirmPasskeyUse('login.acme.com');
    expect(mountRenderSurface).toHaveBeenCalledTimes(1);
    expect(latest().container.querySelector('.domain')?.textContent).toContain('login.acme.com');
  });

  it('resolves true and removes the dialog when the user confirms', async () => {
    const promise = confirmPasskeyUse('example.com');
    const { container, remove } = latest();
    trustedClick(container.querySelector('#vw-pk-confirm'));
    await expect(promise).resolves.toBe(true);
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('resolves false and removes the dialog when the user cancels', async () => {
    const promise = confirmPasskeyUse('example.com');
    const { container, remove } = latest();
    trustedClick(container.querySelector('#vw-pk-cancel'));
    await expect(promise).resolves.toBe(false);
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('resolves false and removes the dialog on the Escape key', async () => {
    const promise = confirmPasskeyUse('example.com');
    const { remove } = latest();
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await expect(promise).resolves.toBe(false);
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('settles at most once', async () => {
    const promise = confirmPasskeyUse('example.com');
    const { container, remove } = latest();
    trustedClick(container.querySelector('#vw-pk-confirm'));
    trustedClick(container.querySelector('#vw-pk-cancel'));
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await expect(promise).resolves.toBe(true);
    expect(remove).toHaveBeenCalledTimes(1);
  });
});

describe('choosePasskeyTarget', () => {
  it('mounts a register dialog with the rpId and target list', () => {
    void choosePasskeyTarget('example.com', [{ id: 'c1', name: 'Example', username: 'me' }]);
    expect(mountRenderSurface).toHaveBeenCalledTimes(1);
    const { container } = latest();
    expect(container.querySelector('.domain')?.textContent).toContain('example.com');
    expect(container.textContent).toContain('Example');
  });

  it('resolves a new item and removes the dialog', async () => {
    const promise = choosePasskeyTarget('example.com', [{ id: 'c1', name: 'Example' }]);
    const { container, remove } = latest();
    trustedClick(container.querySelector('#vw-pk-new'));
    await expect(promise).resolves.toEqual({});
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('resolves the chosen target id (by index, not from the DOM) and removes the dialog', async () => {
    const promise = choosePasskeyTarget('example.com', [
      { id: 'c1', name: 'Example' },
      { id: 'c2', name: 'Second' },
    ]);
    const { container, remove } = latest();
    expect(container.innerHTML).not.toContain('c2');
    trustedClick(container.querySelectorAll('button.target')[1] ?? null);
    await expect(promise).resolves.toEqual({ targetCipherId: 'c2' });
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('resolves cancelled and removes the dialog on cancel', async () => {
    const promise = choosePasskeyTarget('example.com', []);
    const { container, remove } = latest();
    trustedClick(container.querySelector('#vw-pk-cancel'));
    await expect(promise).resolves.toEqual({ cancelled: true });
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('resolves cancelled and removes the dialog on the Escape key', async () => {
    const promise = choosePasskeyTarget('example.com', [{ id: 'c1', name: 'Example' }]);
    const { remove } = latest();
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await expect(promise).resolves.toEqual({ cancelled: true });
    expect(remove).toHaveBeenCalledTimes(1);
  });
});
