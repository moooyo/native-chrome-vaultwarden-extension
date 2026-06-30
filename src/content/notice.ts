// A small, self-dismissing notice bar in a closed shadow root — used to surface context-menu fill
// errors (e.g. a reprompt-protected item) without exposing anything to the page.
const STYLE = `
  :host { all: initial; }
  .bar {
    position: fixed; right: 16px; bottom: 16px; z-index: 2147483647;
    max-width: 320px; padding: 10px 14px;
    font: 13px/1.4 -apple-system, "Segoe UI", system-ui, Roboto, sans-serif;
    color: #fff; background: #1f2636; border-radius: 10px;
    box-shadow: 0 12px 32px rgba(0,0,0,.35);
  }
`;

export function showNotice(message: string): void {
  const host = document.createElement('div');
  host.dataset.vwNotice = '';
  const shadow = host.attachShadow({ mode: 'closed' });
  shadow.innerHTML = `<style>${STYLE}</style><div class="bar"></div>`;
  (shadow.querySelector('.bar') as HTMLElement).textContent = message;
  document.documentElement.append(host);
  const view = host.ownerDocument.defaultView;
  if (view) view.setTimeout(() => host.remove(), 4000);
}
