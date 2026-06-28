// A top-of-page notification bar (closed shadow root, isolated world) offering to save a newly entered
// login or update a changed password. Mirrors the popover's isolation: the page cannot read or forge it,
// and only trusted clicks act. Nothing is saved until the user explicitly confirms.

const STYLE = `
  :host { all: initial; }
  * { box-sizing: border-box; }
  .bar {
    position: fixed; top: 12px; left: 50%; transform: translateX(-50%);
    display: flex; align-items: center; gap: 12px;
    max-width: min(560px, calc(100vw - 24px));
    font: 13px/1.45 -apple-system, "Segoe UI", system-ui, Roboto, sans-serif;
    color: #181d2b; background: #ffffff;
    border: 1px solid #dee3ef; border-radius: 12px;
    box-shadow: 0 18px 48px rgba(20,27,45,.22), 0 4px 12px rgba(20,27,45,.12);
    padding: 10px 12px; z-index: 2147483647;
    animation: drop 160ms cubic-bezier(.2,.7,.2,1);
  }
  @keyframes drop { from { opacity: 0; transform: translate(-50%, -8px); } to { opacity: 1; transform: translate(-50%, 0); } }
  .mark { display: grid; place-items: center; width: 22px; height: 22px; border-radius: 6px; background: linear-gradient(150deg, #4f46e5, #4338ca); color: #fff; flex: none; }
  .mark svg { width: 14px; height: 14px; }
  .msg { flex: 1; min-width: 0; }
  .msg .host { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
  button { font: inherit; border-radius: 8px; padding: 7px 12px; cursor: pointer; border: 1px solid transparent; font-weight: 620; flex: none; }
  .act { background: #4f46e5; color: #fff; }
  .act:hover { background: #4338ca; }
  .dismiss { background: transparent; color: #5b647a; padding: 7px 8px; }
  .dismiss:hover { color: #181d2b; }
  button:focus-visible { outline: none; box-shadow: 0 0 0 3px rgba(79,70,229,.35); }
  svg { stroke-width: 1.8; }
  @media (prefers-color-scheme: dark) {
    .bar { color: #e9edf7; background: #151a26; border-color: #283041; box-shadow: 0 18px 48px rgba(0,0,0,.6); }
    .dismiss { color: #9aa4b8; } .dismiss:hover { color: #e9edf7; }
  }
  @media (prefers-reduced-motion: reduce) { .bar { animation: none; } }
`;

const SHIELD = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>';

export interface SaveBar {
  remove(): void;
}

export interface SaveBarOptions {
  /** Plain-text message (no HTML); rendered as textContent so site data can't inject markup. */
  message: string;
  actionLabel: string;
  onAction(): void;
  onDismiss?(): void;
}

/** Render the bar's controls into `root` and wire them. Exported for testing. */
export function renderSaveBarInto(root: ShadowRoot | HTMLElement, options: SaveBarOptions): void {
  root.innerHTML = `
    <style>${STYLE}</style>
    <div class="bar" role="dialog" aria-label="Save login">
      <span class="mark">${SHIELD}</span>
      <span class="msg"></span>
      <button type="button" class="act" id="vw-save-act"></button>
      <button type="button" class="dismiss" id="vw-save-dismiss" aria-label="Dismiss">Not now</button>
    </div>`;
  // textContent (not innerHTML) keeps site-controlled strings inert.
  (root.querySelector('.msg') as HTMLElement).textContent = options.message;
  (root.querySelector('#vw-save-act') as HTMLElement).textContent = options.actionLabel;
  root.querySelector('#vw-save-act')?.addEventListener('click', (e) => { if (e.isTrusted) options.onAction(); });
  root.querySelector('#vw-save-dismiss')?.addEventListener('click', (e) => { if (e.isTrusted) options.onDismiss?.(); });
}

export function createSaveBar(options: SaveBarOptions): SaveBar {
  const host = document.createElement('div');
  const shadow = host.attachShadow({ mode: 'closed' });
  (document.body ?? document.documentElement).append(host);
  const remove = (): void => host.remove();
  renderSaveBarInto(shadow, {
    ...options,
    onAction: () => { options.onAction(); remove(); },
    onDismiss: () => { options.onDismiss?.(); remove(); },
  });
  return { remove };
}
