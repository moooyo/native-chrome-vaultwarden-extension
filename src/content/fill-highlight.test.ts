// @vitest-environment happy-dom
import { describe, it, expect, vi, afterEach } from 'vitest';
import { flashFill, flashFillCheck } from './fill-highlight.js';

describe('flashFill (mvFill)', () => {
  it('no-ops without throwing when Element.animate is unavailable', () => {
    const input = document.createElement('input');
    (input as unknown as { animate?: unknown }).animate = undefined;
    expect(() => flashFill(input)).not.toThrow();
  });

  it('runs a 600ms ease-out fill animation with the given delay when animate exists', () => {
    const input = document.createElement('input');
    const animate = vi.fn();
    (input as unknown as { animate: unknown }).animate = animate;
    flashFill(input, 130);
    expect(animate).toHaveBeenCalledTimes(1);
    const opts = animate.mock.calls[0]![1] as KeyframeAnimationOptions;
    expect(opts).toMatchObject({ duration: 600, delay: 130, easing: 'ease-out' });
  });
});

describe('flashFillCheck (mvPop corner badge)', () => {
  const proto = Element.prototype as { animate?: unknown };
  const orig = proto.animate;
  afterEach(() => { proto.animate = orig; document.body.replaceChildren(); });

  it('no-ops safely when the Web Animations API is unavailable', () => {
    proto.animate = undefined;
    const input = document.createElement('input');
    document.body.appendChild(input);
    expect(() => flashFillCheck(input)).not.toThrow();
    expect(document.querySelector('div[aria-hidden="true"]')).toBeNull();
  });

  it('pops a moss check badge at the filled input’s top-right corner', () => {
    proto.animate = vi.fn(() => ({ finished: Promise.resolve() }));
    const input = document.createElement('input');
    input.getBoundingClientRect = () => ({ right: 200, top: 50, width: 180, height: 34, left: 20, bottom: 84 } as DOMRect);
    document.body.appendChild(input);
    flashFillCheck(input);
    const badge = document.body.querySelector('div[aria-hidden="true"]') as HTMLElement | null;
    expect(badge).not.toBeNull();
    expect(badge!.textContent).toBe('✓');
    expect(badge!.style.left).toBe('176px'); // right(200) - 24
  });
});
