// Mounts a content surface inside a CLOSED shadow root the page cannot reach, rendering its UI with
// lit-html's `render()` rather than a custom element. Content scripts run in an isolated world whose
// custom-element registry is unavailable — `customElements` is null and `document.createElement` never
// upgrades a defined tag (Chromium issue 41118431). LitElement-based surfaces therefore never render on
// a real page: the factory crashes on `undefined.updateComplete`. Rendering a plain lit-html template
// into the closed root sidesteps the registry entirely — it is ordinary DOM manipulation that works in
// every frame, including blank/synthetic ones.
//
// The closed root keeps `host.shadowRoot` null for page scripts, so they can neither read the surface's
// state nor forge its callbacks — the same security invariant the custom-element version held. Trusted-
// event gating stays in each surface's own click handlers.
import { render, type TemplateResult } from 'lit';

export interface RenderSurface {
  /** The positioned host element in the page tree (its shadow root is closed — `.shadowRoot` is null). */
  host: HTMLDivElement;
  /** The closed shadow root the surface renders into (not reachable via `host.shadowRoot`). */
  root: ShadowRoot;
  /** (Re)render the surface template into the closed root. Synchronous: the DOM is updated on return, so
   *  callers can measure/reposition the host immediately after. */
  render(template: TemplateResult): void;
  remove(): void;
}

/** Create a closed-shadow surface. `styleText` is applied once as a `<style>` sibling of the render
 *  container, so re-renders (view/state changes) never disturb the styles. */
export function mountRenderSurface(styleText: string): RenderSurface {
  const host = document.createElement('div');
  const root = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = styleText;
  root.append(style);
  const container = document.createElement('div');
  root.append(container);
  (document.body ?? document.documentElement).append(host);
  return {
    host,
    root,
    render: (template) => render(template, container),
    remove: () => host.remove(),
  };
}
