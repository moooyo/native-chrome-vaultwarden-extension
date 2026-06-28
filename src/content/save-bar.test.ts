// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { renderSaveBarInto } from './save-bar.js';

afterEach(() => { document.body.innerHTML = ''; });

function trustedClick(el: Element | null): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el!.dispatchEvent(event);
}

describe('save bar', () => {
  it('invokes onAction on a trusted action click and onDismiss on dismiss', () => {
    const root = document.createElement('div');
    document.body.append(root);
    const onAction = vi.fn();
    const onDismiss = vi.fn();
    renderSaveBarInto(root, { message: 'Save?', actionLabel: 'Save', onAction, onDismiss });
    trustedClick(root.querySelector('#vw-save-act'));
    expect(onAction).toHaveBeenCalledOnce();
    trustedClick(root.querySelector('#vw-save-dismiss'));
    expect(onDismiss).toHaveBeenCalledOnce();
  });

  it('ignores untrusted (page-synthesized) action clicks', () => {
    const root = document.createElement('div');
    document.body.append(root);
    const onAction = vi.fn();
    renderSaveBarInto(root, { message: 'm', actionLabel: 'Save', onAction });
    root.querySelector('#vw-save-act')!.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(onAction).not.toHaveBeenCalled();
  });

  it('renders site-controlled text inertly (no HTML injection)', () => {
    const root = document.createElement('div');
    renderSaveBarInto(root, { message: '<img src=x onerror=alert(1)> evil.test', actionLabel: 'Save', onAction: () => {} });
    const msg = root.querySelector('.msg')!;
    expect(msg.querySelector('img')).toBeNull(); // text, not markup
    expect(msg.textContent).toContain('evil.test');
  });
});
