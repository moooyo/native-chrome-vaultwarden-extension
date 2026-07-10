// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { PasskeyRegisterResult, PasskeyRegisterTarget } from './ui/passkey-dialog-element.js';

// The factories mount the closed-shadow Lit dialogs `vw-passkey-consent` / `vw-passkey-register`
// (their Event.isTrusted gating, Escape/outside-click cancel, and index-only target selection are
// covered by passkey-dialog-element.test.ts). Here we verify each factory configures the dialog and
// resolves its promise from the element's one-shot result, then removes the closed surface. We mock
// the mount seam to reach the element the factory would otherwise hide inside a closed root.

interface FakePasskeyDialog {
  rpId?: string;
  targets?: PasskeyRegisterTarget[];
  onResult?: (result: boolean | PasskeyRegisterResult) => void;
}

const state = vi.hoisted(() => ({
  instances: [] as Array<{ tag: string; element: FakePasskeyDialog; remove: ReturnType<typeof vi.fn> }>,
}));

vi.mock('./ui/closed-surface.js', () => ({
  mountClosedSurface: vi.fn((tag: string, configure: (element: FakePasskeyDialog) => void) => {
    const element: FakePasskeyDialog = {};
    configure(element);
    const remove = vi.fn();
    state.instances.push({ tag, element, remove });
    return { host: document.createElement('div'), root: document.createElement('div'), element, remove };
  }),
}));

import { mountClosedSurface } from './ui/closed-surface.js';
import { confirmPasskeyUse, choosePasskeyTarget } from './passkey-consent.js';

afterEach(() => {
  state.instances.length = 0;
  vi.mocked(mountClosedSurface).mockClear();
});

describe('confirmPasskeyUse', () => {
  it('mounts vw-passkey-consent for the rpId', () => {
    void confirmPasskeyUse('login.acme.com');
    expect(mountClosedSurface).toHaveBeenCalledWith('vw-passkey-consent', expect.any(Function));
    const { tag, element } = state.instances[0]!;
    expect(tag).toBe('vw-passkey-consent');
    expect(element.rpId).toBe('login.acme.com');
  });

  it('resolves true and removes the dialog when the element confirms', async () => {
    const promise = confirmPasskeyUse('example.com');
    const { element, remove } = state.instances[0]!;
    element.onResult?.(true);
    await expect(promise).resolves.toBe(true);
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('resolves false and removes the dialog when the element cancels', async () => {
    const promise = confirmPasskeyUse('example.com');
    const { element, remove } = state.instances[0]!;
    element.onResult?.(false);
    await expect(promise).resolves.toBe(false);
    expect(remove).toHaveBeenCalledTimes(1);
  });
});

describe('choosePasskeyTarget', () => {
  it('mounts vw-passkey-register with the rpId and target list', () => {
    const targets: PasskeyRegisterTarget[] = [{ id: 'c1', name: 'Example', username: 'me' }];
    void choosePasskeyTarget('example.com', targets);
    expect(mountClosedSurface).toHaveBeenCalledWith('vw-passkey-register', expect.any(Function));
    const { tag, element } = state.instances[0]!;
    expect(tag).toBe('vw-passkey-register');
    expect(element.rpId).toBe('example.com');
    expect(element.targets).toEqual(targets);
  });

  it('resolves with the chosen target id and removes the dialog', async () => {
    const promise = choosePasskeyTarget('example.com', [{ id: 'c1', name: 'Example' }]);
    const { element, remove } = state.instances[0]!;
    element.onResult?.({ targetCipherId: 'c1' });
    await expect(promise).resolves.toEqual({ targetCipherId: 'c1' });
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('resolves cancelled and removes the dialog', async () => {
    const promise = choosePasskeyTarget('example.com', []);
    const { element, remove } = state.instances[0]!;
    element.onResult?.({ cancelled: true });
    await expect(promise).resolves.toEqual({ cancelled: true });
    expect(remove).toHaveBeenCalledTimes(1);
  });
});
