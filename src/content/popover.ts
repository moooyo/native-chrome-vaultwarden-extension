export interface PopoverCandidate {
  id: string;
  name: string;
  /** username / matched URI (login) or brand / full name (card / identity). */
  sub?: string;
  favorite: boolean;
  reprompt?: boolean;
}

export interface AutofillPopover {
  element: HTMLElement;
  root: ShadowRoot;
  showStatus(message: string): void;
  showCandidates(candidates: PopoverCandidate[]): void;
  remove(): void;
}

export interface AutofillPopoverOptions {
  anchor: HTMLElement;
  kind?: 'login' | 'card' | 'identity';
  onOpen(): void;
  onSelect(cipherId: string): void;
}

const STYLE = `
  :host { all: initial; }
  * { box-sizing: border-box; }
  .box {
    font: 13px/1.45 -apple-system, "Segoe UI", system-ui, Roboto, sans-serif;
    color: #181d2b;
    background: #ffffff;
    border: 1px solid #dee3ef;
    border-radius: 12px;
    box-shadow: 0 18px 48px rgba(20,27,45,.22), 0 4px 12px rgba(20,27,45,.12);
    min-width: 232px;
    max-width: 340px;
    overflow: hidden;
    animation: pop 140ms cubic-bezier(.2,.7,.2,1);
  }
  @keyframes pop { from { opacity: 0; transform: translateY(-4px) scale(.98); } to { opacity: 1; transform: none; } }
  .brandrow { display: flex; align-items: center; gap: 7px; padding: 8px 10px; border-bottom: 1px solid #eef1f8; }
  .mark { display: grid; place-items: center; width: 20px; height: 20px; border-radius: 6px; background: linear-gradient(150deg, #4f46e5, #4338ca); color: #fff; flex: none; }
  .mark svg { width: 13px; height: 13px; }
  .brandrow .label { font-weight: 650; font-size: 12px; letter-spacing: .01em; }
  .list { padding: 6px; display: block; }
  button.candidate {
    display: flex; align-items: center; gap: 10px;
    font: inherit; width: 100%; text-align: left;
    border: 1px solid transparent; background: transparent;
    padding: 8px; border-radius: 9px; cursor: pointer; color: inherit;
  }
  button.candidate:hover { background: #f3f5fb; border-color: #e7ebf5; }
  button.candidate:focus-visible { outline: none; box-shadow: 0 0 0 3px rgba(79,70,229,.32); }
  .mono-chip { display: grid; place-items: center; width: 30px; height: 30px; flex: none; border-radius: 8px; font-weight: 680; font-size: 13px; text-transform: uppercase; color: #fff; background: #4f46e5; }
  .meta { min-width: 0; flex: 1; }
  .name { display: flex; align-items: center; gap: 4px; font-weight: 600; }
  .name .t { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .star { width: 11px; height: 11px; color: #e0a400; flex: none; }
  .sub { display: block; font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 11px; color: #5b647a; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .open-trigger { display: flex; align-items: center; gap: 8px; width: 100%; font: inherit; text-align: left; border: 0; background: transparent; padding: 10px 12px; cursor: pointer; color: inherit; font-weight: 600; }
  .open-trigger:hover { background: #f3f5fb; }
  .open-trigger .chev { margin-left: auto; color: #8b93a7; width: 16px; height: 16px; }
  .status { display: flex; align-items: center; gap: 8px; padding: 11px 12px; color: #5b647a; }
  .status svg { width: 15px; height: 15px; flex: none; color: #8b93a7; }
  svg { stroke-width: 1.8; }
  @media (prefers-color-scheme: dark) {
    .box { color: #e9edf7; background: #151a26; border-color: #283041; box-shadow: 0 18px 48px rgba(0,0,0,.6); }
    .brandrow { border-bottom-color: #1f2636; }
    button.candidate:hover { background: #1b2230; border-color: #283041; }
    .sub { color: #9aa4b8; }
    .open-trigger:hover { background: #1b2230; }
    .status { color: #9aa4b8; }
  }
  @media (prefers-reduced-motion: reduce) { .box { animation: none; } }
`;

const SHIELD = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>';
const CHEVRON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>';
const LOCK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>';
const STAR = '<svg class="star" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" aria-hidden="true"><path d="M12 4l2.3 4.7 5.2.8-3.7 3.6.9 5.1L12 15.8 7.3 18.3l.9-5.1L4.5 9.5l5.2-.8z"/></svg>';

export function createAutofillPopover(options: AutofillPopoverOptions): AutofillPopover {
  const host = document.createElement('div');
  host.style.position = 'absolute';
  host.style.zIndex = '2147483647';
  const shadow = host.attachShadow({ mode: 'closed' });
  document.documentElement.append(host);

  const kind = options.kind ?? 'login';
  const HEADER = { login: 'Fill from Vaultwarden', card: 'Fill card', identity: 'Fill identity' }[kind];
  const EMPTY = { login: 'No matching logins', card: 'No saved cards', identity: 'No saved identities' }[kind];

  const render = (inner: string) => {
    shadow.innerHTML = `<style>${STYLE}</style><div class="box">${inner}</div>`;
    reposition(host, options.anchor);
  };

  render(`<button id="open" type="button" class="open-trigger"><span class="mark">${SHIELD}</span><span>Vaultwarden</span><span class="chev">${CHEVRON}</span></button>`);
  shadow.getElementById('open')?.addEventListener('click', (event) => {
    if (!event.isTrusted) return;
    options.onOpen();
  });

  return {
    element: host,
    root: shadow,
    showStatus(message: string) {
      render(`<div class="status">${LOCK}<span>${escapeHtml(message)}</span></div>`);
    },
    showCandidates(candidates: PopoverCandidate[]) {
      if (candidates.length === 0) {
        render(`<div class="status">${LOCK}<span>${EMPTY}</span></div>`);
        return;
      }
      // The brand row must contain no <button> so the first button in the shadow
      // tree is always the first candidate (relied on by tests and keyboard order).
      const rows = candidates.map((candidate) => `
        <button type="button" class="candidate">
          <span class="mono-chip" style="background:hsl(${hueFor(candidate.name)} 55% 48%)">${escapeHtml(monogramLetter(candidate.name))}</span>
          <span class="meta">
            <span class="name">${candidate.favorite ? STAR : ''}<span class="t">${escapeHtml(candidate.name)}</span></span>
            <span class="sub">${escapeHtml(candidate.sub ?? '')}</span>
          </span>
        </button>`).join('');
      render(`<div class="brandrow"><span class="mark">${SHIELD}</span><span class="label">${HEADER}</span></div><div class="list">${rows}</div>`);
      shadow.querySelectorAll<HTMLButtonElement>('button.candidate').forEach((button, index) => {
        button.addEventListener('click', (event) => {
          if (!event.isTrusted) return;
          options.onSelect(candidates[index]!.id);
        });
      });
    },
    remove() {
      host.remove();
    },
  };
}

/** Position the popover under the anchor, flipping above and clamping to the
 *  viewport when there isn't room — so it stays usable at any zoom or window size. */
function reposition(host: HTMLElement, anchor: HTMLElement): void {
  const rect = anchor.getBoundingClientRect();
  const vw = window.innerWidth || document.documentElement.clientWidth || 0;
  const vh = window.innerHeight || document.documentElement.clientHeight || 0;
  const width = host.offsetWidth || 240;
  const height = host.offsetHeight || 0;
  const gap = 4;

  let left = rect.left;
  if (vw) left = Math.min(Math.max(8, left), Math.max(8, vw - width - 8));

  const spaceBelow = vh ? vh - rect.bottom : Infinity;
  const placeAbove = height > 0 && spaceBelow < height + gap && rect.top > height + gap;
  const top = placeAbove ? rect.top - height - gap : rect.bottom + gap;

  host.style.left = `${left + window.scrollX}px`;
  host.style.top = `${Math.max(8, top) + window.scrollY}px`;
}

function monogramLetter(name: string): string {
  const match = name.match(/[\p{L}\p{N}]/u);
  return match ? match[0]!.toUpperCase() : '•';
}

function hueFor(name: string): number {
  let hash = 0;
  for (let i = 0; i < name.length; i++) hash = (hash * 31 + name.charCodeAt(i)) >>> 0;
  return hash % 360;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}
