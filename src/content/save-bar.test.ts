// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render } from 'lit';

// The factory mounts a render-based surface inside a CLOSED shadow root (no custom element — content
// scripts run in an isolated world with no custom-element registry, Chromium 41118431). The bar's own
// trusted-click gating and inert message rendering are covered by save-bar-element.test.ts. Here we
// verify the factory's own job: it renders the surface with the message/label and, on the surface's
// action/dismiss, runs the caller's handler and removes the surface. We mock the render-surface seam so
// the template is rendered into a real container we can inspect and click.

const state = vi.hoisted(() => ({
  surfaces: [] as Array<{
    styleText: string;
    container: HTMLElement;
    render: ReturnType<typeof vi.fn>;
    remove: ReturnType<typeof vi.fn>;
  }>,
}));

vi.mock('./ui/render-surface.js', () => ({
  mountRenderSurface: vi.fn((styleText: string) => {
    const container = document.createElement('div');
    document.body.append(container);
    const surface = {
      host: document.createElement('div'),
      root: container as unknown as ShadowRoot,
      styleText,
      container,
      render: vi.fn((template) => render(template, container)),
      remove: vi.fn(() => container.remove()),
    };
    state.surfaces.push(surface);
    return surface;
  }),
}));

import { mountRenderSurface } from './ui/render-surface.js';
import { SAVE_BAR_STYLES } from './ui/save-bar-element.js';
import { createSaveBar } from './save-bar.js';

afterEach(() => {
  state.surfaces.length = 0;
  vi.mocked(mountRenderSurface).mockClear();
  document.body.replaceChildren();
});

function trustedClick(el: Element | null): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el?.dispatchEvent(event);
}

describe('createSaveBar', () => {
  it('mounts a render surface with the save-bar styles and the message and action label', () => {
    createSaveBar({ message: 'Save this login?', actionLabel: 'Save', onAction: () => {} });
    expect(mountRenderSurface).toHaveBeenCalledWith(SAVE_BAR_STYLES);
    const { container } = state.surfaces[0]!;
    expect(container.textContent).toContain('Save this login?');
    expect(container.querySelector('#vw-save-act')?.textContent).toContain('Save');
  });

  it('runs onAction then removes the bar on a trusted action click', () => {
    const onAction = vi.fn();
    createSaveBar({ message: 'm', actionLabel: 'Save', onAction });
    const { container, remove } = state.surfaces[0]!;
    trustedClick(container.querySelector('#vw-save-act'));
    expect(onAction).toHaveBeenCalledTimes(1);
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('runs onDismiss then removes the bar on a trusted dismiss click', () => {
    const onDismiss = vi.fn();
    createSaveBar({ message: 'm', actionLabel: 'Save', onAction: () => {}, onDismiss });
    const { container, remove } = state.surfaces[0]!;
    trustedClick(container.querySelector('#vw-save-dismiss'));
    expect(onDismiss).toHaveBeenCalledTimes(1);
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('tolerates a dismiss with no onDismiss handler and still removes the bar', () => {
    createSaveBar({ message: 'm', actionLabel: 'Save', onAction: () => {} });
    const { container, remove } = state.surfaces[0]!;
    expect(() => trustedClick(container.querySelector('#vw-save-dismiss'))).not.toThrow();
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('remove() detaches the mounted surface', () => {
    const bar = createSaveBar({ message: 'm', actionLabel: 'Save', onAction: () => {} });
    bar.remove();
    expect(state.surfaces[0]!.remove).toHaveBeenCalledTimes(1);
  });
});
