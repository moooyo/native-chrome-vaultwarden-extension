// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import { mountClosedSurface } from './closed-surface.js';

class ProbeSurface extends HTMLElement {
  label = '';
}
customElements.define('vw-probe-surface', ProbeSurface);

afterEach(() => {
  document.body.replaceChildren();
});

describe('mountClosedSurface', () => {
  it('mounts the element inside a closed root that the page cannot inspect', () => {
    const surface = mountClosedSurface<ProbeSurface>('vw-probe-surface', (element) => {
      element.label = 'ready';
    });

    expect(surface.host.shadowRoot).toBeNull();
    expect(surface.root.mode).toBe('closed');
    expect(surface.root.contains(surface.element)).toBe(true);
    expect(surface.element.label).toBe('ready');
    surface.remove();
  });

  it('retains an internal root reference even though host.shadowRoot stays null', () => {
    const surface = mountClosedSurface<ProbeSurface>('vw-probe-surface', () => {});
    expect(surface.host.shadowRoot).toBeNull();
    expect(surface.root.host).toBe(surface.host);
    surface.remove();
  });

  it('attaches the host to the document and removes it on remove()', () => {
    const surface = mountClosedSurface<ProbeSurface>('vw-probe-surface', () => {});
    expect(document.documentElement.contains(surface.host)).toBe(true);
    surface.remove();
    expect(document.documentElement.contains(surface.host)).toBe(false);
  });
});
