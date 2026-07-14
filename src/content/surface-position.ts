// Pure, global-free viewport positioning for content surfaces. Callers supply every dimension so the
// functions can be exercised deterministically in tests and reused from the isolated content world.

import { clamp } from '../core/util/num.js';

export type PopoverPlacement = 'below' | 'above';

export interface AnchorRect {
  top: number;
  bottom: number;
  left: number;
  right: number;
}

export interface SurfaceSize {
  width: number;
  height: number;
}

export interface ViewportSize {
  width: number;
  height: number;
}

export interface PopoverPosition {
  left: number;
  top: number;
  placement: PopoverPlacement;
}

export interface ModalPosition {
  left: number;
  top: number;
  placement: 'center';
}

export interface PopoverPositionInput {
  anchor: AnchorRect;
  surface: SurfaceSize;
  viewport: ViewportSize;
  /** Vertical gap between anchor and surface. */
  gap?: number;
  /** Minimum distance the surface keeps from every viewport edge. */
  margin?: number;
}

export interface ModalPositionInput {
  surface: SurfaceSize;
  viewport: ViewportSize;
  margin?: number;
}

/** Distance a popover keeps from the viewport edges. */
export const POPOVER_VIEWPORT_MARGIN = 8;
/** Distance a modal keeps from the viewport edges. */
export const MODAL_VIEWPORT_MARGIN = 16;
/** Default gap between an anchor and its popover. */
export const POPOVER_ANCHOR_GAP = 4;

/**
 * Positions a popover under its anchor, flipping above when there is no room below, and clamping to
 * the viewport margins when it fits neither side. Returns viewport coordinates plus the chosen
 * placement. Reads no globals: every dimension comes from the caller.
 */
export function positionPopover(input: PopoverPositionInput): PopoverPosition {
  const gap = input.gap ?? POPOVER_ANCHOR_GAP;
  const margin = input.margin ?? POPOVER_VIEWPORT_MARGIN;
  const { anchor, surface, viewport } = input;

  const left = clamp(anchor.left, margin, viewport.width - surface.width - margin);

  const belowTop = anchor.bottom + gap;
  const aboveTop = anchor.top - gap - surface.height;
  const fitsBelow = belowTop + surface.height <= viewport.height - margin;
  const fitsAbove = aboveTop >= margin;

  let placement: PopoverPlacement;
  let top: number;
  if (fitsBelow) {
    placement = 'below';
    top = belowTop;
  } else if (fitsAbove) {
    placement = 'above';
    top = aboveTop;
  } else {
    placement = 'below';
    top = belowTop;
  }

  top = clamp(top, margin, viewport.height - surface.height - margin);
  return { left, top, placement };
}

/**
 * Centres a modal in the viewport, clamping to the viewport margins when the modal is larger than the
 * available space. Reads no globals.
 */
export function positionModal(input: ModalPositionInput): ModalPosition {
  const margin = input.margin ?? MODAL_VIEWPORT_MARGIN;
  const { surface, viewport } = input;
  const left = clamp((viewport.width - surface.width) / 2, margin, viewport.width - surface.width - margin);
  const top = clamp((viewport.height - surface.height) / 2, margin, viewport.height - surface.height - margin);
  return { left, top, placement: 'center' };
}
