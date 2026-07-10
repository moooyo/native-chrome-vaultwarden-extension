// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';

// The factory mounts the closed-shadow Lit element `vw-save-bar` (its trusted-click gating and inert
// message rendering are covered by save-bar-element.test.ts). Here we verify the factory's own job:
// it configures the element with the message/label and, on the element's action/dismiss, runs the
// caller's handler and removes the closed surface. We mock the mount seam to observe the element the
// factory would otherwise hide inside a closed root.

interface FakeSaveBar {
  message?: string;
  actionLabel?: string;
  onAction?: () => void;
  onDismiss?: () => void;
}

const state = vi.hoisted(() => ({
  instances: [] as Array<{ tag: string; element: FakeSaveBar; remove: ReturnType<typeof vi.fn> }>,
}));

vi.mock('./ui/closed-surface.js', () => ({
  mountClosedSurface: vi.fn((tag: string, configure: (element: FakeSaveBar) => void) => {
    const element: FakeSaveBar = {};
    configure(element);
    const remove = vi.fn();
    state.instances.push({ tag, element, remove });
    return { host: document.createElement('div'), root: document.createElement('div'), element, remove };
  }),
}));

import { mountClosedSurface } from './ui/closed-surface.js';
import { createSaveBar } from './save-bar.js';

afterEach(() => {
  state.instances.length = 0;
  vi.mocked(mountClosedSurface).mockClear();
});

describe('createSaveBar', () => {
  it('mounts vw-save-bar configured with the message and action label', () => {
    createSaveBar({ message: 'Save this login?', actionLabel: 'Save', onAction: () => {} });
    expect(mountClosedSurface).toHaveBeenCalledWith('vw-save-bar', expect.any(Function));
    const { tag, element } = state.instances[0]!;
    expect(tag).toBe('vw-save-bar');
    expect(element.message).toBe('Save this login?');
    expect(element.actionLabel).toBe('Save');
  });

  it('runs onAction then removes the bar when the element acts', () => {
    const onAction = vi.fn();
    createSaveBar({ message: 'm', actionLabel: 'Save', onAction });
    const { element, remove } = state.instances[0]!;
    element.onAction?.();
    expect(onAction).toHaveBeenCalledTimes(1);
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('runs onDismiss then removes the bar when the element dismisses', () => {
    const onDismiss = vi.fn();
    createSaveBar({ message: 'm', actionLabel: 'Save', onAction: () => {}, onDismiss });
    const { element, remove } = state.instances[0]!;
    element.onDismiss?.();
    expect(onDismiss).toHaveBeenCalledTimes(1);
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('tolerates a dismiss with no onDismiss handler and still removes the bar', () => {
    createSaveBar({ message: 'm', actionLabel: 'Save', onAction: () => {} });
    const { element, remove } = state.instances[0]!;
    expect(() => element.onDismiss?.()).not.toThrow();
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('remove() detaches the mounted surface', () => {
    const bar = createSaveBar({ message: 'm', actionLabel: 'Save', onAction: () => {} });
    bar.remove();
    expect(state.instances[0]!.remove).toHaveBeenCalledTimes(1);
  });
});
