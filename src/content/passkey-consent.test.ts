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
//
// The mock host is a real (appended) light-DOM node so the factory's host-removal observer (which
// settles the promise as cancelled when the page removes the surface) and its post-mount arm delay
// (which ignores an approving click provoked the instant the dialog appears) can be exercised here.

const surfaces = vi.hoisted(
  () =>
    [] as Array<{
      styleText: string;
      template: TemplateResult | undefined;
      remove: ReturnType<typeof vi.fn>;
      host: HTMLElement;
    }>,
);

vi.mock('./ui/render-surface.js', () => ({
  mountRenderSurface: vi.fn((styleText: string) => {
    const host = document.createElement('div');
    document.body.append(host); // real, connected host so isConnected reflects page removal
    const entry = {
      styleText,
      template: undefined as TemplateResult | undefined,
      remove: vi.fn(() => host.remove()),
      host,
    };
    surfaces.push(entry);
    return {
      host,
      root: document.createElement('div'),
      render: (template: TemplateResult) => {
        entry.template = template;
      },
      remove: entry.remove,
    };
  }),
}));

import { mountRenderSurface } from './ui/render-surface.js';
import {
  confirmPasskeyUse,
  choosePasskeyLogin,
  choosePasskeyTarget,
  PASSKEY_CONSENT_ARM_MS,
} from './passkey-consent.js';

afterEach(() => {
  surfaces.length = 0;
  vi.mocked(mountRenderSurface).mockClear();
  document.body.replaceChildren();
  vi.useRealTimers();
});

/** Render the latest surface's captured template into an open container so its buttons are clickable. */
function latest(): { container: HTMLElement; remove: ReturnType<typeof vi.fn>; host: HTMLElement } {
  const entry = surfaces.at(-1);
  if (!entry?.template) {
    throw new Error('no surface template captured');
  }
  const container = document.createElement('div');
  document.body.append(container);
  render(entry.template, container);
  return { container, remove: entry.remove, host: entry.host };
}

function trustedClick(el: Element | null): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el?.dispatchEvent(event);
}

/** A user-originated Escape (isTrusted === true), unlike a page-synthesized KeyboardEvent. */
function trustedEscape(): void {
  const event = new KeyboardEvent('keydown', { key: 'Escape' });
  Object.defineProperty(event, 'isTrusted', { value: true });
  window.dispatchEvent(event);
}

/** Advance past the arm window so an approving click counts (uses fake timers, restored in afterEach). */
function pastArmWindow(): void {
  vi.advanceTimersByTime(PASSKEY_CONSENT_ARM_MS + 50);
}

describe('confirmPasskeyUse', () => {
  it('mounts a consent dialog for the rpId', () => {
    void confirmPasskeyUse('login.acme.com');
    expect(mountRenderSurface).toHaveBeenCalledTimes(1);
    expect(latest().container.querySelector('.domain')?.textContent).toContain('login.acme.com');
  });

  it('resolves true and removes the dialog when the user confirms', async () => {
    vi.useFakeTimers();
    const promise = confirmPasskeyUse('example.com');
    const { container, remove } = latest();
    pastArmWindow();
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
    trustedEscape();
    await expect(promise).resolves.toBe(false);
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('ignores a page-synthesized (untrusted) Escape, but a trusted one cancels', async () => {
    const promise = confirmPasskeyUse('example.com');
    const settled = vi.fn();
    void promise.then(settled);
    latest();
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' })); // untrusted
    await Promise.resolve();
    expect(settled).not.toHaveBeenCalled();
    trustedEscape();
    await expect(promise).resolves.toBe(false);
  });

  it('ignores an approving click provoked within the arm window, accepts it after', async () => {
    vi.useFakeTimers();
    const promise = confirmPasskeyUse('example.com');
    const settled = vi.fn();
    void promise.then(settled);
    const { container } = latest();
    trustedClick(container.querySelector('#vw-pk-confirm')); // clickjack: too soon
    await Promise.resolve();
    expect(settled).not.toHaveBeenCalled();
    pastArmWindow();
    trustedClick(container.querySelector('#vw-pk-confirm'));
    await expect(promise).resolves.toBe(true);
    expect(settled).toHaveBeenCalledTimes(1);
  });

  it('resolves false when the page removes the dialog host from the DOM', async () => {
    const promise = confirmPasskeyUse('example.com');
    const { host } = latest();
    host.remove(); // the page tears the light-DOM host out from under the ceremony
    await expect(promise).resolves.toBe(false);
  });

  it('settles at most once', async () => {
    vi.useFakeTimers();
    const promise = confirmPasskeyUse('example.com');
    const { container, remove } = latest();
    pastArmWindow();
    trustedClick(container.querySelector('#vw-pk-confirm'));
    trustedClick(container.querySelector('#vw-pk-cancel'));
    trustedEscape();
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
    vi.useFakeTimers();
    const promise = choosePasskeyTarget('example.com', [{ id: 'c1', name: 'Example' }]);
    const { container, remove } = latest();
    pastArmWindow();
    trustedClick(container.querySelector('#vw-pk-new'));
    await expect(promise).resolves.toEqual({});
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('resolves the chosen target id (by index, not from the DOM) and removes the dialog', async () => {
    vi.useFakeTimers();
    const promise = choosePasskeyTarget('example.com', [
      { id: 'c1', name: 'Example' },
      { id: 'c2', name: 'Second' },
    ]);
    const { container, remove } = latest();
    expect(container.innerHTML).not.toContain('c2');
    pastArmWindow();
    trustedClick(container.querySelectorAll('button.target')[1] ?? null);
    await expect(promise).resolves.toEqual({ targetCipherId: 'c2' });
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('ignores a target selection provoked within the arm window', async () => {
    vi.useFakeTimers();
    const promise = choosePasskeyTarget('example.com', [{ id: 'c1', name: 'Example' }]);
    const settled = vi.fn();
    void promise.then(settled);
    const { container } = latest();
    trustedClick(container.querySelectorAll('button.target')[0] ?? null); // too soon
    await Promise.resolve();
    expect(settled).not.toHaveBeenCalled();
    pastArmWindow();
    trustedClick(container.querySelectorAll('button.target')[0] ?? null);
    await expect(promise).resolves.toEqual({ targetCipherId: 'c1' });
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
    trustedEscape();
    await expect(promise).resolves.toEqual({ cancelled: true });
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('resolves cancelled when the page removes the dialog host from the DOM', async () => {
    const promise = choosePasskeyTarget('example.com', [{ id: 'c1', name: 'Example' }]);
    const { host } = latest();
    host.remove();
    await expect(promise).resolves.toEqual({ cancelled: true });
  });
});

describe('choosePasskeyLogin', () => {
  it('mounts a picker with the rpId and account names', () => {
    void choosePasskeyLogin('login.acme.com', [
      { credentialId: 'cred-a', name: 'Acme Work', username: 'work@acme.com' },
    ]);
    expect(mountRenderSurface).toHaveBeenCalledTimes(1);
    const { container } = latest();
    expect(container.querySelector('.domain')?.textContent).toContain('login.acme.com');
    expect(container.textContent).toContain('Acme Work');
    expect(container.textContent).toContain('work@acme.com');
  });

  it('resolves the chosen credentialId (by index, never from the DOM) and removes the dialog', async () => {
    vi.useFakeTimers();
    const promise = choosePasskeyLogin('acme.com', [
      { credentialId: 'cred-a', name: 'Work' },
      { credentialId: 'cred-b', name: 'Personal' },
    ]);
    const { container, remove } = latest();
    // The credentialId is selected by rendered index and must never reach the DOM.
    expect(container.innerHTML).not.toContain('cred-b');
    pastArmWindow();
    trustedClick(container.querySelectorAll('button.target')[1] ?? null);
    await expect(promise).resolves.toEqual({ credentialId: 'cred-b' });
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it('ignores an account selection provoked within the arm window', async () => {
    vi.useFakeTimers();
    const promise = choosePasskeyLogin('acme.com', [{ credentialId: 'cred-a', name: 'Work' }]);
    const settled = vi.fn();
    void promise.then(settled);
    const { container } = latest();
    trustedClick(container.querySelectorAll('button.target')[0] ?? null); // too soon
    await Promise.resolve();
    expect(settled).not.toHaveBeenCalled();
    pastArmWindow();
    trustedClick(container.querySelectorAll('button.target')[0] ?? null);
    await expect(promise).resolves.toEqual({ credentialId: 'cred-a' });
  });

  it('resolves cancelled on the cancel button and on Escape', async () => {
    const cancelPromise = choosePasskeyLogin('acme.com', [{ credentialId: 'cred-a', name: 'Work' }]);
    trustedClick(latest().container.querySelector('#vw-pk-cancel'));
    await expect(cancelPromise).resolves.toEqual({ cancelled: true });

    const escPromise = choosePasskeyLogin('acme.com', [{ credentialId: 'cred-a', name: 'Work' }]);
    latest();
    trustedEscape();
    await expect(escPromise).resolves.toEqual({ cancelled: true });
  });

  it('resolves cancelled when the page removes the dialog host from the DOM', async () => {
    const promise = choosePasskeyLogin('acme.com', [{ credentialId: 'cred-a', name: 'Work' }]);
    const { host } = latest();
    host.remove();
    await expect(promise).resolves.toEqual({ cancelled: true });
  });
});
