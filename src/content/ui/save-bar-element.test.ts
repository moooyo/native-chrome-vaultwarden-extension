// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { VwSaveBar } from './save-bar-element.js';
import './save-bar-element.js';

afterEach(() => {
  document.body.replaceChildren();
});

async function mount(configure: (element: VwSaveBar) => void): Promise<VwSaveBar> {
  const element = document.createElement('vw-save-bar') as VwSaveBar;
  configure(element);
  document.body.append(element);
  await element.updateComplete;
  return element;
}

function shadow(element: VwSaveBar): ShadowRoot {
  if (!element.shadowRoot) {
    throw new Error('element has no render root');
  }
  return element.shadowRoot;
}

function trustedClick(el: Element | null): void {
  const event = new MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  el?.dispatchEvent(event);
}

describe('vw-save-bar', () => {
  it('invokes onAction and onDismiss only on trusted clicks', async () => {
    const onAction = vi.fn();
    const onDismiss = vi.fn();
    const element = await mount((el) => {
      el.message = 'Save this login?';
      el.actionLabel = 'Save';
      el.onAction = onAction;
      el.onDismiss = onDismiss;
    });
    const root = shadow(element);

    root.querySelector('#vw-save-act')?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(onAction).not.toHaveBeenCalled();

    trustedClick(root.querySelector('#vw-save-act'));
    expect(onAction).toHaveBeenCalledTimes(1);
    trustedClick(root.querySelector('#vw-save-dismiss'));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it('renders site-controlled text inertly', async () => {
    const element = await mount((el) => {
      el.message = '<img src=x onerror=alert(1)> evil.test';
      el.actionLabel = 'Save';
    });
    const message = shadow(element).querySelector('.msg');
    expect(message?.querySelector('img')).toBeNull();
    expect(message?.textContent).toContain('evil.test');
  });

  it('allows the message to wrap on narrow viewports', () => {
    const styleText = styleTextOf(VwSaveBar);
    expect(styleText).toContain('overflow-wrap');
    expect(styleText).toContain('prefers-color-scheme: dark');
    expect(styleText).toContain('prefers-reduced-motion: reduce');
  });
});

function styleTextOf(ctor: typeof VwSaveBar): string {
  const styles = ctor.styles;
  const list = Array.isArray(styles) ? styles : [styles];
  return list.map((style) => String((style as { cssText: string }).cssText)).join('\n');
}
