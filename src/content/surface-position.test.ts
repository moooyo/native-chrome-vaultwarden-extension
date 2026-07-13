import { describe, expect, it } from 'vitest';
import {
  MODAL_VIEWPORT_MARGIN,
  POPOVER_VIEWPORT_MARGIN,
  positionModal,
  positionPopover,
} from './surface-position.js';

describe('positionPopover', () => {
  const viewport = { width: 1000, height: 800 };
  const surface = { width: 240, height: 160 };

  it('places the popover below the anchor when there is room', () => {
    const result = positionPopover({
      anchor: { top: 100, bottom: 120, left: 300, right: 360 },
      surface,
      viewport,
    });
    expect(result.placement).toBe('below');
    expect(result.top).toBe(120 + 4);
    expect(result.left).toBe(300);
  });

  it('flips above the anchor when there is no room below but room above', () => {
    const result = positionPopover({
      anchor: { top: 700, bottom: 740, left: 300, right: 360 },
      surface,
      viewport,
    });
    expect(result.placement).toBe('above');
    expect(result.top).toBe(700 - 4 - surface.height);
  });

  it('clamps vertically to the viewport margin when the surface fits neither side', () => {
    const tall = { width: 240, height: 900 };
    const result = positionPopover({
      anchor: { top: 380, bottom: 420, left: 300, right: 360 },
      surface: tall,
      viewport,
    });
    expect(result.placement).toBe('below');
    expect(result.top).toBe(POPOVER_VIEWPORT_MARGIN);
  });

  it('clamps horizontally so the popover stays within the 8px viewport margins', () => {
    const result = positionPopover({
      anchor: { top: 100, bottom: 120, left: 980, right: 995 },
      surface,
      viewport,
    });
    expect(result.left).toBe(viewport.width - surface.width - POPOVER_VIEWPORT_MARGIN);
    expect(result.left).toBeGreaterThanOrEqual(POPOVER_VIEWPORT_MARGIN);
  });

  it('is pure and does not read any global objects', () => {
    const anchor = { top: 10, bottom: 30, left: 10, right: 40 };
    const first = positionPopover({ anchor, surface, viewport });
    const second = positionPopover({ anchor, surface, viewport });
    expect(first).toEqual(second);
  });
});

describe('positionModal', () => {
  it('centres the modal within the viewport', () => {
    const result = positionModal({
      surface: { width: 360, height: 200 },
      viewport: { width: 1000, height: 800 },
    });
    expect(result.placement).toBe('center');
    expect(result.left).toBe((1000 - 360) / 2);
    expect(result.top).toBe((800 - 200) / 2);
  });

  it('clamps to the 16px viewport margin when the modal is larger than the viewport', () => {
    const result = positionModal({
      surface: { width: 1200, height: 900 },
      viewport: { width: 1000, height: 800 },
    });
    expect(result.left).toBe(MODAL_VIEWPORT_MARGIN);
    expect(result.top).toBe(MODAL_VIEWPORT_MARGIN);
  });
});
