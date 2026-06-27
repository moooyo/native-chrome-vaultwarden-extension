import { sendRequest } from '../../messaging/protocol.js';
import type { AuthResult } from '../../core/session/auth-service.js';

type View =
  | { kind: 'loading' }
  | { kind: 'loggedOut'; error?: string }
  | { kind: 'twoFactor'; providers: Array<0 | 1>; error?: string }
  | { kind: 'locked'; error?: string }
  | { kind: 'unlocked'; error?: string };

const app = document.getElementById('app')!;
let twoFactorProviders: Array<0 | 1> = [];
// Track current view kind so handleAuthResult can route errors correctly.
let currentViewKind: View['kind'] = 'loading';
// Track pending operations to prevent double submission.
let isPending = false;

void init();

async function init() {
  render({ kind: 'loading' });
  const response = await sendRequest({ type: 'auth.getState' });
  if (!response.ok) return render({ kind: 'loggedOut', error: response.error.message });
  const { state } = response.data as { state: 'loggedOut' | 'locked' | 'unlocked' };
  render({ kind: state });
}

function render(view: View) {
  currentViewKind = view.kind;
  if (view.kind === 'loading') {
    app.innerHTML = '<p class="muted">Loading...</p>';
    return;
  }
  if (view.kind === 'loggedOut') return renderLogin(view.error);
  if (view.kind === 'twoFactor') return renderTwoFactor(view.providers, view.error);
  if (view.kind === 'locked') return renderLocked(view.error);
  return renderUnlockedShell(view.error);
}

function renderLogin(error?: string) {
  app.innerHTML = `
    <h1>Vaultwarden</h1>
    <form id="loginForm">
      <label>Email</label><input id="email" type="email" autocomplete="username" required />
      <label>Master password</label><input id="password" type="password" autocomplete="current-password" required />
      <button type="submit">Log in</button>
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
    </form>`;
  document.getElementById('loginForm')!.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (isPending) return;
    isPending = true;
    const button = document.querySelector('#loginForm button[type="submit"]') as HTMLButtonElement;
    const form = document.getElementById('loginForm') as HTMLFormElement;
    button.disabled = true;
    form.querySelectorAll('input').forEach(input => input.disabled = true);
    try {
      const email = (document.getElementById('email') as HTMLInputElement).value;
      const masterPassword = (document.getElementById('password') as HTMLInputElement).value;
      const result = await sendRequest({ type: 'auth.login', email, masterPassword });
      await handleAuthResult(result);
    } finally {
      isPending = false;
      if (currentViewKind === 'loggedOut') {
        button.disabled = false;
        form.querySelectorAll('input').forEach(input => input.disabled = false);
      }
    }
  });
}

function renderTwoFactor(providers: Array<0 | 1>, error?: string) {
  twoFactorProviders = providers;
  app.innerHTML = `
    <h1>Two-step login</h1>
    <form id="twoFactorForm">
      <label>Provider</label>
      <select id="provider">${providers.map((p) => `<option value="${p}">${p === 0 ? 'Authenticator app' : 'Email'}</option>`).join('')}</select>
      <label>Code</label><input id="code" inputmode="numeric" autocomplete="one-time-code" required />
      <button type="submit">Continue</button>
      ${providers.includes(1) ? '<button id="sendEmail" class="secondary" type="button">Send email code</button>' : ''}
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
    </form>`;
  document.getElementById('twoFactorForm')!.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (isPending) return;
    isPending = true;
    const button = document.querySelector('#twoFactorForm button[type="submit"]') as HTMLButtonElement;
    const form = document.getElementById('twoFactorForm') as HTMLFormElement;
    button.disabled = true;
    (form.querySelectorAll('input, select') as NodeListOf<HTMLInputElement | HTMLSelectElement>).forEach(el => el.disabled = true);
    try {
      const provider = Number((document.getElementById('provider') as HTMLSelectElement).value) as 0 | 1;
      const code = (document.getElementById('code') as HTMLInputElement).value;
      await handleAuthResult(await sendRequest({ type: 'auth.submitTwoFactor', provider, code }));
    } finally {
      isPending = false;
      if (currentViewKind === 'twoFactor') {
        button.disabled = false;
        (form.querySelectorAll('input, select') as NodeListOf<HTMLInputElement | HTMLSelectElement>).forEach(el => el.disabled = false);
      }
    }
  });
  document.getElementById('sendEmail')?.addEventListener('click', async () => {
    if (isPending) return;
    isPending = true;
    const button = document.getElementById('sendEmail') as HTMLButtonElement;
    const form = document.getElementById('twoFactorForm') as HTMLFormElement;
    button.disabled = true;
    (form.querySelectorAll('input, select, button[type="submit"]') as NodeListOf<HTMLInputElement | HTMLSelectElement | HTMLButtonElement>).forEach(el => el.disabled = true);
    try {
      const response = await sendRequest({ type: 'auth.sendEmailCode' });
      if (!response.ok) render({ kind: 'twoFactor', providers: twoFactorProviders, error: response.error.message });
    } finally {
      isPending = false;
      if (currentViewKind === 'twoFactor') {
        button.disabled = false;
        (form.querySelectorAll('input, select, button[type="submit"]') as NodeListOf<HTMLInputElement | HTMLSelectElement | HTMLButtonElement>).forEach(el => el.disabled = false);
      }
    }
  });
}

function renderLocked(error?: string) {
  app.innerHTML = `
    <h1>Unlock</h1>
    <form id="unlockForm">
      <label>Master password</label><input id="unlockPassword" type="password" autocomplete="current-password" required />
      <button type="submit">Unlock</button>
      <button id="logout" type="button" class="danger">Log out</button>
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
    </form>`;
  document.getElementById('unlockForm')!.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (isPending) return;
    isPending = true;
    const button = document.querySelector('#unlockForm button[type="submit"]') as HTMLButtonElement;
    const logoutBtn = document.getElementById('logout') as HTMLButtonElement;
    const form = document.getElementById('unlockForm') as HTMLFormElement;
    button.disabled = true;
    logoutBtn.disabled = true;
    form.querySelectorAll('input').forEach(input => input.disabled = true);
    try {
      const masterPassword = (document.getElementById('unlockPassword') as HTMLInputElement).value;
      const response = await sendRequest({ type: 'auth.unlock', masterPassword });
      render(response.ok ? { kind: 'unlocked' } : { kind: 'locked', error: response.error.message });
    } finally {
      isPending = false;
      if (currentViewKind === 'locked') {
        button.disabled = false;
        logoutBtn.disabled = false;
        form.querySelectorAll('input').forEach(input => input.disabled = false);
      }
    }
  });
  document.getElementById('logout')!.addEventListener('click', async () => {
    if (isPending) return;
    isPending = true;
    const logoutBtn = document.getElementById('logout') as HTMLButtonElement;
    const unlockBtn = document.querySelector('#unlockForm button[type="submit"]') as HTMLButtonElement;
    const form = document.getElementById('unlockForm') as HTMLFormElement;
    logoutBtn.disabled = true;
    unlockBtn.disabled = true;
    form.querySelectorAll('input').forEach(input => input.disabled = true);
    try {
      await sendRequest({ type: 'auth.logout' });
      render({ kind: 'loggedOut' });
    } finally {
      isPending = false;
    }
  });
}

function renderUnlockedShell(error?: string) {
  app.innerHTML = `<h1>Vault</h1><p class="muted">Unlocked. Vault list will be wired in Task 22.</p>${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}`;
}

async function handleAuthResult(response: Awaited<ReturnType<typeof sendRequest>>) {
  if (!response.ok) {
    // Route the error back to whichever auth view is currently active so the
    // user stays in context (e.g. a 2FA failure stays on the 2FA form).
    if (currentViewKind === 'twoFactor') {
      render({ kind: 'twoFactor', providers: twoFactorProviders, error: response.error.message });
    } else {
      render({ kind: 'loggedOut', error: response.error.message });
    }
    return;
  }
  const data = response.data as AuthResult;
  if (data.kind === 'twoFactor') render({ kind: 'twoFactor', providers: data.providers });
  else render({ kind: 'unlocked' });
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}
