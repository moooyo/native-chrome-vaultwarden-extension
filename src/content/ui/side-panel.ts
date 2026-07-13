// Shared side-mounted-panel treatment for the autofill surfaces that hang to the RIGHT of the focused
// input (design 2c login match, 3a 2FA) — connected to it by a short line + a moss dot, never occluding
// the form. The panel template is wrapped with `sideWrap`; the factory positions the host with
// `repositionSidePanel`. When there is no room on the right the panel falls back to below the input and
// the connector is hidden via `:host([data-pos="below"])`.
import { html, type TemplateResult } from 'lit';

/** Connector zone width (the gap the line spans) and the line's y within the surface. The host is placed
 *  so this y lands on the input's vertical centre, so the line appears to leave the input's right edge. */
const CONN_W = 22;
const CONN_Y = 20;

/** CSS for the connector, appended to each side-panel surface's own styles. Uses the surface's local
 *  `--mi-teal` for the dot; the line has its own light/dark neutral. */
export const SIDE_PANEL_CSS = `
    .side { display: flex; align-items: flex-start; }
    .conn { position: relative; flex: none; width: ${CONN_W}px; align-self: stretch; }
    .conn::before { content: ''; position: absolute; left: 0; top: ${CONN_Y}px; width: ${CONN_W}px; height: 1.5px; background: rgba(22,24,29,.22); }
    .conn-dot { position: absolute; left: 0; top: ${CONN_Y - 3.5}px; width: 7px; height: 7px; border-radius: 50%; background: var(--mi-teal); }
    :host([data-pos="below"]) .side { display: block; }
    :host([data-pos="below"]) .conn { display: none; }
    @media (prefers-color-scheme: dark) { .conn::before { background: rgba(255,255,255,.18); } }
  `;

/** Wrap a surface's `.box` template with the connector, so it renders as `[dot——line] [box]`. */
export function sideWrap(box: TemplateResult): TemplateResult {
  return html`<div class="side"><span class="conn"><span class="conn-dot"></span></span>${box}</div>`;
}

/** Position a side panel to the RIGHT of its anchor, aligning the connector line to the anchor's vertical
 *  centre. Falls back to below the anchor (connector hidden) when the right gutter can't fit the panel —
 *  it must never occlude the form. Call after each render, since it measures the host's final size. */
export function repositionSidePanel(host: HTMLElement, anchor: HTMLElement): void {
  const rect = anchor.getBoundingClientRect();
  const vw = window.innerWidth || document.documentElement.clientWidth || 0;
  const vh = window.innerHeight || document.documentElement.clientHeight || 0;
  const width = host.offsetWidth || 300;
  const height = host.offsetHeight || 0;

  const fitsRight = !vw || rect.right + width + 8 <= vw;
  if (fitsRight) {
    host.removeAttribute('data-pos');
    const centerY = rect.top + rect.height / 2;
    let top = centerY - CONN_Y;
    if (vh && height) top = Math.min(Math.max(8, top), Math.max(8, vh - height - 8));
    host.style.left = `${rect.right + window.scrollX}px`;
    host.style.top = `${top + window.scrollY}px`;
    return;
  }

  // No room on the right — drop below the input (connector hidden), clamped into the viewport.
  host.setAttribute('data-pos', 'below');
  let left = rect.left;
  if (vw) left = Math.min(Math.max(8, left), Math.max(8, vw - width - 8));
  const spaceBelow = vh ? vh - rect.bottom : Infinity;
  const placeAbove = height > 0 && spaceBelow < height + 4 && rect.top > height + 4;
  const top = placeAbove ? rect.top - height - 4 : rect.bottom + 4;
  host.style.left = `${left + window.scrollX}px`;
  host.style.top = `${Math.max(8, top) + window.scrollY}px`;
}
