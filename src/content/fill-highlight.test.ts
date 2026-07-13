// @vitest-environment happy-dom
import { describe, it, expect, vi } from 'vitest';
import { flashFill } from './fill-highlight.js';

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
