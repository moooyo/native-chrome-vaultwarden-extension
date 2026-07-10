// Mounts a custom element inside a CLOSED shadow root the page cannot reach. The returned handle keeps
// an internal reference to that root (so the extension can still render/update the surface) while
// `host.shadowRoot` stays null for page scripts — they can neither read component state nor forge its
// callbacks. Used behind every content surface in place of the imperative factories.

export interface ClosedSurface<T extends HTMLElement> {
  host: HTMLDivElement;
  root: ShadowRoot;
  element: T;
  remove(): void;
}

export function mountClosedSurface<T extends HTMLElement>(
  tagName: string,
  configure: (element: T) => void,
): ClosedSurface<T> {
  const host = document.createElement('div');
  const root = host.attachShadow({ mode: 'closed' });
  const element = document.createElement(tagName) as T;
  configure(element);
  root.append(element);
  (document.body ?? document.documentElement).append(host);
  return { host, root, element, remove: () => host.remove() };
}
