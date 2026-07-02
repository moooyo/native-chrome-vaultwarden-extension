// One-shot user-consent dialog shown (in the isolated content-script world, inside a CLOSED shadow
// root the page cannot reach) before a vault-stored passkey is used to sign a WebAuthn assertion.
// This supplies the user presence/consent that a silent worker assertion would otherwise skip: a
// malicious page can no longer obtain an assertion just because the vault happens to be unlocked.

const STYLE = `
  :host { all: initial; }
  * { box-sizing: border-box; }
  .overlay {
    position: fixed; inset: 0; display: grid; place-items: center;
    background: rgba(12,16,26,.45); z-index: 2147483647;
    font: 14px/1.5 -apple-system, "Segoe UI", system-ui, Roboto, sans-serif;
  }
  .card {
    width: min(360px, calc(100vw - 32px));
    background: #ffffff; color: #181d2b;
    border: 1px solid #dee3ef; border-radius: 14px;
    box-shadow: 0 24px 64px rgba(20,27,45,.32);
    padding: 18px; animation: pop 140ms cubic-bezier(.2,.7,.2,1);
  }
  @keyframes pop { from { opacity: 0; transform: translateY(-6px) scale(.98); } to { opacity: 1; transform: none; } }
  .head { display: flex; align-items: center; gap: 9px; margin-bottom: 10px; }
  .mark { display: grid; place-items: center; width: 26px; height: 26px; border-radius: 7px; background: linear-gradient(150deg, #4f46e5, #4338ca); color: #fff; flex: none; }
  .mark svg { width: 16px; height: 16px; }
  h1 { font-size: 14px; font-weight: 680; margin: 0; }
  p { margin: 0 0 14px; color: #5b647a; }
  .rp { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; color: #181d2b; word-break: break-all; }
  .row { display: flex; gap: 8px; }
  .col { display: flex; flex-direction: column; gap: 8px; margin-bottom: 10px; } .target { text-align: left; }
  button { font: inherit; flex: 1; padding: 9px 12px; border-radius: 9px; cursor: pointer; border: 1px solid transparent; font-weight: 620; }
  .confirm { background: #4f46e5; color: #fff; }
  .confirm:hover { background: #4338ca; }
  .cancel { background: #f3f5fb; color: #181d2b; border-color: #e7ebf5; }
  .cancel:hover { background: #e9edf7; }
  button:focus-visible { outline: none; box-shadow: 0 0 0 3px rgba(79,70,229,.35); }
  svg { stroke-width: 1.8; }
  @media (prefers-color-scheme: dark) {
    .card { background: #151a26; color: #e9edf7; border-color: #283041; box-shadow: 0 24px 64px rgba(0,0,0,.65); }
    p { color: #9aa4b8; } .rp { color: #e9edf7; }
    .cancel { background: #1b2230; color: #e9edf7; border-color: #283041; }
    .cancel:hover { background: #232c3d; }
  }
  @media (prefers-reduced-motion: reduce) { .card { animation: none; } }
`;

const SHIELD = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>';

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

/**
 * Render the consent dialog markup into `root` and wire its controls; `onResult` fires exactly once
 * with the user's choice. Exported for testing — production goes through confirmPasskeyUse, which wraps
 * this in a CLOSED shadow root (unreachable from page scripts). Only trusted (real) clicks count.
 */
export function renderConsentInto(
  root: ShadowRoot | HTMLElement,
  rpId: string,
  onResult: (confirmed: boolean) => void,
): void {
  let settled = false;
  const finish = (confirmed: boolean): void => { if (!settled) { settled = true; onResult(confirmed); } };
  root.innerHTML = `
    <style>${STYLE}</style>
    <div class="overlay">
      <div class="card" role="dialog" aria-modal="true" aria-label="Use passkey">
        <div class="head"><span class="mark">${SHIELD}</span><h1>Use a saved passkey?</h1></div>
        <p>Vaultwarden will sign in to <span class="rp">${escapeHtml(rpId)}</span> with a passkey from your vault.</p>
        <div class="row">
          <button type="button" class="cancel" id="vw-pk-cancel">Cancel</button>
          <button type="button" class="confirm" id="vw-pk-confirm">Use passkey</button>
        </div>
      </div>
    </div>`;
  root.querySelector('#vw-pk-confirm')?.addEventListener('click', (e) => { if (e.isTrusted) finish(true); });
  root.querySelector('#vw-pk-cancel')?.addEventListener('click', (e) => { if (e.isTrusted) finish(false); });
  root.querySelector('.overlay')?.addEventListener('click', (e) => {
    if (e.isTrusted && e.target === e.currentTarget) finish(false); // click outside the card cancels
  });
  (root.querySelector('#vw-pk-confirm') as HTMLButtonElement | null)?.focus();
}

/**
 * Prompt the user to approve using a stored passkey for `rpId`. Resolves true on confirm, false on
 * cancel / Escape / outside click. The dialog lives in a closed shadow root the page cannot reach.
 */
export function confirmPasskeyUse(rpId: string): Promise<boolean> {
  return new Promise((resolve) => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'closed' });
    (document.body ?? document.documentElement).append(host);
    let settled = false;
    const done = (confirmed: boolean): void => {
      if (settled) return;
      settled = true;
      window.removeEventListener('keydown', onKey, true);
      host.remove();
      resolve(confirmed);
    };
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') { e.preventDefault(); done(false); }
    };
    window.addEventListener('keydown', onKey, true);
    renderConsentInto(shadow, rpId, done);
  });
}

export type PasskeyPickerResult = { cancelled: true } | { targetCipherId?: string };

/** Render the registration picker (New item + existing same-domain items + Cancel) into `root`.
 *  `onResult` fires exactly once. Only trusted clicks count. Mirrors renderConsentInto. */
export function renderPasskeyPickerInto(
  root: ShadowRoot | HTMLElement,
  rpId: string,
  targets: Array<{ id: string; name: string; username?: string }>,
  onResult: (result: PasskeyPickerResult) => void,
): void {
  let settled = false;
  const finish = (r: PasskeyPickerResult): void => { if (!settled) { settled = true; onResult(r); } };
  const rows = targets.map((t) => `
    <button type="button" class="cancel target" data-target="${escapeHtml(t.id)}">
      ${escapeHtml(t.name)}${t.username ? ` <span class="rp">${escapeHtml(t.username)}</span>` : ''}
    </button>`).join('');
  root.innerHTML = `
    <style>${STYLE}</style>
    <div class="overlay">
      <div class="card" role="dialog" aria-modal="true" aria-label="Save passkey">
        <div class="head"><span class="mark">${SHIELD}</span><h1>Save a passkey for <span class="rp">${escapeHtml(rpId)}</span>?</h1></div>
        <p>Choose where to store this passkey in your vault.</p>
        <div class="col">
          <button type="button" class="confirm" id="vw-pk-new">New login item</button>
          ${rows}
        </div>
        <div class="row"><button type="button" class="cancel" id="vw-pk-cancel">Cancel</button></div>
      </div>
    </div>`;
  root.querySelector('#vw-pk-new')?.addEventListener('click', (e) => { if (e.isTrusted) finish({}); });
  root.querySelector('#vw-pk-cancel')?.addEventListener('click', (e) => { if (e.isTrusted) finish({ cancelled: true }); });
  for (const btn of root.querySelectorAll<HTMLButtonElement>('button[data-target]')) {
    btn.addEventListener('click', (e) => { if (e.isTrusted) finish({ targetCipherId: btn.dataset.target! }); });
  }
  root.querySelector('.overlay')?.addEventListener('click', (e) => {
    if (e.isTrusted && e.target === e.currentTarget) finish({ cancelled: true });
  });
}

/** Prompt the user to choose where to save a new passkey. Resolves cancelled on Cancel/Esc/outside click.
 *  Lives in a closed shadow root the page cannot reach. */
export function choosePasskeyTarget(
  rpId: string,
  targets: Array<{ id: string; name: string; username?: string }>,
): Promise<PasskeyPickerResult> {
  return new Promise((resolve) => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'closed' });
    (document.body ?? document.documentElement).append(host);
    let settled = false;
    const done = (r: PasskeyPickerResult): void => {
      if (settled) return;
      settled = true;
      window.removeEventListener('keydown', onKey, true);
      host.remove();
      resolve(r);
    };
    const onKey = (e: KeyboardEvent): void => { if (e.key === 'Escape') { e.preventDefault(); done({ cancelled: true }); } };
    window.addEventListener('keydown', onKey, true);
    renderPasskeyPickerInto(shadow, rpId, targets, done);
  });
}
