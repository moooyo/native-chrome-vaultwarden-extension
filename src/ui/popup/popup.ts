import { sendRequest } from '../../messaging/protocol.js';
import type { AuthResult } from '../../core/session/auth-service.js';
import type { CipherSummary, DecryptedCipher, FolderSummary } from '../../core/vault/models.js';
import { filterSummariesByFolderAndQuery, NO_FOLDER } from '../../core/vault/search.js';
import { generatePassword, DEFAULT_PASSWORD_OPTIONS, type PasswordGenOptions } from '../../core/generator/password.js';
import { icon } from '../icons.js';

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
// Cached vault items for the current unlocked session.
let vaultItems: CipherSummary[] = [];
let vaultFolders: FolderSummary[] = [];
let selectedFolderId: string | null = null;
let skippedOrgCount = 0;
// Active TOTP countdown interval for the open login detail (cleared on any navigation).
let totpTimer: number | undefined;
// Password generator options, persisted while the popup stays open.
let genOptions: PasswordGenOptions = { ...DEFAULT_PASSWORD_OPTIONS };

function clearTotpTimer(): void {
  if (totpTimer !== undefined) {
    clearInterval(totpTimer);
    totpTimer = undefined;
  }
}

void init();

async function init() {
  render({ kind: 'loading' });
  const response = await sendRequest({ type: 'auth.getState' });
  if (!response.ok) return render({ kind: 'loggedOut', error: response.error.message });
  const { state } = response.data as { state: 'loggedOut' | 'locked' | 'unlocked' };
  render({ kind: state });
}

function render(view: View) {
  clearTotpTimer();
  currentViewKind = view.kind;
  if (view.kind === 'loading') {
    app.innerHTML = `<div class="center"><span class="spinner"></span><span class="muted">Loading vault…</span></div>`;
    return;
  }
  if (view.kind === 'loggedOut') return renderLogin(view.error);
  if (view.kind === 'twoFactor') return renderTwoFactor(view.providers, view.error);
  if (view.kind === 'locked') return renderLocked(view.error);
  return renderUnlockedShell(view.error);
}

/** Centered brand head shared by the auth screens. */
function authHead(title: string, subtitle: string): string {
  return `
    <div class="auth-head">
      <span class="brand-mark">${icon('shield')}</span>
      <h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(subtitle)}</p>
    </div>`;
}

function errorNote(error?: string): string {
  return error ? `<p class="note error">${icon('alert')}<span>${escapeHtml(error)}</span></p>` : '';
}

function renderLogin(error?: string) {
  app.innerHTML = `
    <div class="auth">
      ${authHead('Vaultwarden', 'Sign in to your self-hosted vault')}
      <form id="loginForm">
        <label class="field">
          <span class="field-label">Email</span>
          <input id="email" class="input" type="email" autocomplete="username" required />
        </label>
        <label class="field">
          <span class="field-label">Master password</span>
          <input id="password" class="input" type="password" autocomplete="current-password" required />
        </label>
        <button type="submit" class="btn btn-block">${icon('unlock')}<span>Log in</span></button>
        ${errorNote(error)}
      </form>
    </div>`;
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
        const liveButton = document.querySelector('#loginForm button[type="submit"]') as HTMLButtonElement | null;
        const liveForm = document.getElementById('loginForm') as HTMLFormElement | null;
        if (liveButton && liveForm) {
          liveButton.disabled = false;
          liveForm.querySelectorAll('input').forEach(input => input.disabled = false);
        }
      }
    }
  });
}

function renderTwoFactor(providers: Array<0 | 1>, error?: string) {
  twoFactorProviders = providers;
  app.innerHTML = `
    <div class="auth">
      ${authHead('Two-step login', 'Enter your verification code to continue')}
      <form id="twoFactorForm">
        <label class="field">
          <span class="field-label">Provider</span>
          <select id="provider" class="select">${providers.map((p) => `<option value="${p}">${p === 0 ? 'Authenticator app' : 'Email'}</option>`).join('')}</select>
        </label>
        <label class="field">
          <span class="field-label">Code</span>
          <input id="code" class="input mono" inputmode="numeric" autocomplete="one-time-code" required />
        </label>
        <button type="submit" class="btn btn-block">${icon('key')}<span>Continue</span></button>
        ${providers.includes(1) ? `<button id="sendEmail" class="btn btn-secondary btn-block" type="button">${icon('mail')}<span>Send email code</span></button>` : ''}
        ${errorNote(error)}
      </form>
    </div>`;
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
        const liveButton = document.querySelector('#twoFactorForm button[type="submit"]') as HTMLButtonElement | null;
        const liveForm = document.getElementById('twoFactorForm') as HTMLFormElement | null;
        if (liveButton && liveForm) {
          liveButton.disabled = false;
          (liveForm.querySelectorAll('input, select') as NodeListOf<HTMLInputElement | HTMLSelectElement>).forEach(el => el.disabled = false);
        }
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
        const liveButton = document.getElementById('sendEmail') as HTMLButtonElement | null;
        const liveForm = document.getElementById('twoFactorForm') as HTMLFormElement | null;
        if (liveButton && liveForm) {
          liveButton.disabled = false;
          (liveForm.querySelectorAll('input, select, button[type="submit"]') as NodeListOf<HTMLInputElement | HTMLSelectElement | HTMLButtonElement>).forEach(el => el.disabled = false);
        }
      }
    }
  });
}

function renderLocked(error?: string) {
  app.innerHTML = `
    <div class="auth">
      ${authHead('Vault locked', 'Enter your master password to unlock')}
      <form id="unlockForm">
        <label class="field">
          <span class="field-label">Master password</span>
          <input id="unlockPassword" class="input" type="password" autocomplete="current-password" required />
        </label>
        <button type="submit" class="btn btn-block">${icon('unlock')}<span>Unlock</span></button>
        <button id="logout" type="button" class="btn btn-danger btn-block">${icon('logout')}<span>Log out</span></button>
        ${errorNote(error)}
      </form>
    </div>`;
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
        const liveButton = document.querySelector('#unlockForm button[type="submit"]') as HTMLButtonElement | null;
        const liveLogoutBtn = document.getElementById('logout') as HTMLButtonElement | null;
        const liveForm = document.getElementById('unlockForm') as HTMLFormElement | null;
        if (liveButton && liveLogoutBtn && liveForm) {
          liveButton.disabled = false;
          liveLogoutBtn.disabled = false;
          liveForm.querySelectorAll('input').forEach(input => input.disabled = false);
        }
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
  app.innerHTML = `
    <div class="appbar">
      <div class="brand">
        <span class="brand-mark">${icon('shield')}</span>
        <span class="wordmark">Vaultwarden</span>
      </div>
      <span class="statechip" data-state="unlocked">${icon('unlock')}<span>Unlocked</span></span>
    </div>
    <div class="toolbar">
      <div class="search">${icon('search')}<input id="search" class="input" placeholder="Search vault" autocomplete="off" /></div>
      <button id="generate" class="icon-btn" type="button" title="Password generator" aria-label="Password generator">${icon('key')}</button>
      <button id="sync" class="icon-btn" type="button" title="Sync vault" aria-label="Sync vault">${icon('refresh')}</button>
      <button id="lock" class="icon-btn" type="button" title="Lock vault" aria-label="Lock vault">${icon('lock')}</button>
    </div>
    <div id="folderBar" class="folderbar"></div>
    <div id="orgBanner"></div>
    <div id="vaultList" class="list-wrap"></div>
    <div class="footer">
      <button id="logoutUnlocked" class="btn btn-danger btn-block" type="button">${icon('logout')}<span>Log out</span></button>
    </div>
    ${error ? `<div class="footer">${errorNote(error)}</div>` : ''}`;
  bindUnlockedControls();
  renderFolderFilter();
  renderOrgBanner();
  void loadCachedList();
}

/** Rebuild the folder <select>, preserving the current selection when the folder still exists. */
function renderFolderFilter() {
  const bar = document.getElementById('folderBar');
  if (!bar) return;
  if (vaultFolders.length === 0 && !vaultItems.some((i) => !i.folderId)) {
    bar.innerHTML = '';
    return;
  }
  const hasNoFolderItems = vaultItems.some((i) => !i.folderId);
  // Reset a stale selection so the dropdown and the filtered list never desync: a chosen folder
  // that no longer exists, or "No Folder" when every item now has a folder.
  if (selectedFolderId !== null && selectedFolderId !== NO_FOLDER && !vaultFolders.some((f) => f.id === selectedFolderId)) {
    selectedFolderId = null;
  }
  if (selectedFolderId === NO_FOLDER && !hasNoFolderItems) {
    selectedFolderId = null;
  }
  const options = [
    `<option value="">All folders</option>`,
    ...vaultFolders.map((f) => `<option value="${escapeHtml(f.id)}">${escapeHtml(f.name)}</option>`),
    hasNoFolderItems ? `<option value="${NO_FOLDER}">No Folder</option>` : '',
  ].join('');
  bar.innerHTML = `<div class="folder-select">${icon('folder')}<select id="folderFilter" class="select" aria-label="Filter by folder">${options}</select></div>`;
  const select = document.getElementById('folderFilter') as HTMLSelectElement | null;
  if (select) {
    select.value = selectedFolderId ?? '';
    select.addEventListener('change', () => {
      selectedFolderId = select.value || null;
      renderVaultList();
    });
  }
}

/** Show a muted notice when some organization ciphers could not be decrypted (e.g. an org key the
 *  account private key cannot unwrap). Decryptable org items appear inline in the list. */
function renderOrgBanner() {
  const banner = document.getElementById('orgBanner');
  if (!banner) return;
  banner.innerHTML = skippedOrgCount > 0
    ? `<p class="note muted org-note">${icon('shield')}<span>${skippedOrgCount} organization item${skippedOrgCount === 1 ? '' : 's'} could not be decrypted</span></p>`
    : '';
}

function bindUnlockedControls() {
  document.getElementById('lock')!.addEventListener('click', async () => {
    if (isPending) return;
    isPending = true;
    const lockBtn = document.getElementById('lock') as HTMLButtonElement;
    const syncBtn = document.getElementById('sync') as HTMLButtonElement;
    const logoutBtn = document.getElementById('logoutUnlocked') as HTMLButtonElement;
    lockBtn.disabled = true;
    syncBtn.disabled = true;
    logoutBtn.disabled = true;
    try {
      const response = await sendRequest({ type: 'auth.lock' });
      if (!response.ok) {
        render({ kind: 'unlocked', error: response.error.message });
      } else {
        render({ kind: 'locked' });
      }
    } finally {
      isPending = false;
      if (currentViewKind === 'unlocked') {
        const liveLockBtn = document.getElementById('lock') as HTMLButtonElement | null;
        const liveSyncBtn = document.getElementById('sync') as HTMLButtonElement | null;
        const liveLogoutBtn = document.getElementById('logoutUnlocked') as HTMLButtonElement | null;
        if (liveLockBtn) liveLockBtn.disabled = false;
        if (liveSyncBtn) liveSyncBtn.disabled = false;
        if (liveLogoutBtn) liveLogoutBtn.disabled = false;
      }
    }
  });

  document.getElementById('logoutUnlocked')!.addEventListener('click', async () => {
    if (isPending) return;
    isPending = true;
    const lockBtn = document.getElementById('lock') as HTMLButtonElement;
    const syncBtn = document.getElementById('sync') as HTMLButtonElement;
    const logoutBtn = document.getElementById('logoutUnlocked') as HTMLButtonElement;
    lockBtn.disabled = true;
    syncBtn.disabled = true;
    logoutBtn.disabled = true;
    try {
      const response = await sendRequest({ type: 'auth.logout' });
      if (!response.ok) {
        render({ kind: 'unlocked', error: response.error.message });
      } else {
        vaultItems = [];
        vaultFolders = [];
        selectedFolderId = null;
        skippedOrgCount = 0;
        render({ kind: 'loggedOut' });
      }
    } finally {
      isPending = false;
      if (currentViewKind === 'unlocked') {
        const liveLockBtn = document.getElementById('lock') as HTMLButtonElement | null;
        const liveSyncBtn = document.getElementById('sync') as HTMLButtonElement | null;
        const liveLogoutBtn = document.getElementById('logoutUnlocked') as HTMLButtonElement | null;
        if (liveLockBtn) liveLockBtn.disabled = false;
        if (liveSyncBtn) liveSyncBtn.disabled = false;
        if (liveLogoutBtn) liveLogoutBtn.disabled = false;
      }
    }
  });

  document.getElementById('sync')!.addEventListener('click', async () => {
    if (isPending) return;
    isPending = true;
    const lockBtn = document.getElementById('lock') as HTMLButtonElement;
    const syncBtn = document.getElementById('sync') as HTMLButtonElement;
    const logoutBtn = document.getElementById('logoutUnlocked') as HTMLButtonElement;
    lockBtn.disabled = true;
    syncBtn.disabled = true;
    logoutBtn.disabled = true;
    syncBtn.classList.add('is-spinning');
    try {
      const response = await sendRequest({ type: 'vault.sync' });
      if (!response.ok) {
        render({ kind: 'unlocked', error: response.error.message });
      } else {
        const data = response.data as { items: CipherSummary[]; folders: FolderSummary[] };
        vaultItems = data.items;
        vaultFolders = data.folders;
        await loadSkippedOrgCount();
        renderFolderFilter();
        renderOrgBanner();
        renderVaultList();
      }
    } finally {
      isPending = false;
      if (currentViewKind === 'unlocked') {
        const liveLockBtn = document.getElementById('lock') as HTMLButtonElement | null;
        const liveSyncBtn = document.getElementById('sync') as HTMLButtonElement | null;
        const liveLogoutBtn = document.getElementById('logoutUnlocked') as HTMLButtonElement | null;
        if (liveLockBtn) liveLockBtn.disabled = false;
        if (liveSyncBtn) { liveSyncBtn.disabled = false; liveSyncBtn.classList.remove('is-spinning'); }
        if (liveLogoutBtn) liveLogoutBtn.disabled = false;
      }
    }
  });

  document.getElementById('search')!.addEventListener('input', renderVaultList);
  document.getElementById('generate')!.addEventListener('click', () => renderGenerator());
}

/** Standalone password generator panel — runs locally; no vault secret involved. */
function renderGenerator(): void {
  clearTotpTimer();
  app.innerHTML = `
    <div class="detail">
      <div class="detail-head">
        <button id="back" class="icon-btn" type="button" title="Back" aria-label="Back">${icon('back')}</button>
        <div class="titles"><h1>Password generator</h1></div>
      </div>
      <div class="detail-body">
        <div class="readout">
          <div class="k">${icon('key')} Generated password</div>
          <div class="v-row">
            <code id="genOut" class="v mono"></code>
            <button id="genRegen" class="icon-btn" type="button" title="Regenerate" aria-label="Regenerate">${icon('refresh')}</button>
          </div>
        </div>
        <div class="gen-options">
          <label class="gen-row"><span>Length</span><input id="genLength" class="input" type="number" min="4" max="128" value="${genOptions.length}" /></label>
          <label class="gen-check"><input id="genLower" type="checkbox" ${genOptions.lowercase ? 'checked' : ''} /><span>Lowercase (a-z)</span></label>
          <label class="gen-check"><input id="genUpper" type="checkbox" ${genOptions.uppercase ? 'checked' : ''} /><span>Uppercase (A-Z)</span></label>
          <label class="gen-check"><input id="genNumbers" type="checkbox" ${genOptions.numbers ? 'checked' : ''} /><span>Numbers (0-9)</span></label>
          <label class="gen-check"><input id="genSpecial" type="checkbox" ${genOptions.special ? 'checked' : ''} /><span>Special (!@#$%^&amp;*)</span></label>
          <label class="gen-check"><input id="genAmbiguous" type="checkbox" ${genOptions.avoidAmbiguous ? 'checked' : ''} /><span>Avoid ambiguous (Il1O0)</span></label>
        </div>
        <div class="detail-actions">
          <button id="genCopy" type="button" class="btn btn-block">${icon('copy')}<span>Copy password</span></button>
        </div>
        <div id="detailStatus" class="detail-status"></div>
      </div>
    </div>`;
  document.getElementById('back')!.addEventListener('click', () => render({ kind: 'unlocked' }));

  const out = document.getElementById('genOut')!;
  let current = '';
  const readOptions = (): void => {
    const length = Number((document.getElementById('genLength') as HTMLInputElement).value);
    genOptions = {
      ...genOptions,
      length: Number.isFinite(length) ? Math.min(Math.max(Math.trunc(length), 4), 128) : genOptions.length,
      lowercase: (document.getElementById('genLower') as HTMLInputElement).checked,
      uppercase: (document.getElementById('genUpper') as HTMLInputElement).checked,
      numbers: (document.getElementById('genNumbers') as HTMLInputElement).checked,
      special: (document.getElementById('genSpecial') as HTMLInputElement).checked,
      avoidAmbiguous: (document.getElementById('genAmbiguous') as HTMLInputElement).checked,
    };
  };
  const regenerate = (): void => {
    readOptions();
    current = generatePassword(genOptions);
    out.textContent = current || 'Enable at least one character set';
  };
  for (const id of ['genLength', 'genLower', 'genUpper', 'genNumbers', 'genSpecial', 'genAmbiguous']) {
    document.getElementById(id)!.addEventListener('input', regenerate);
  }
  document.getElementById('genRegen')!.addEventListener('click', regenerate);
  document.getElementById('genCopy')!.addEventListener('click', () => void withDetailBusy(() => copyValue(current, 'Password')));
  regenerate();
}

async function loadCachedList() {
  const response = await sendRequest({ type: 'vault.listItems' });
  if (response.ok) {
    const data = response.data as { items: CipherSummary[]; folders: FolderSummary[] };
    vaultItems = data.items;
    vaultFolders = data.folders;
    await loadSkippedOrgCount();
    renderFolderFilter();
    renderOrgBanner();
    renderVaultList();
  }
}

async function loadSkippedOrgCount() {
  const response = await sendRequest({ type: 'vault.getSkippedOrgCount' });
  skippedOrgCount = response.ok ? (response.data as { count: number }).count : 0;
}

function renderVaultList() {
  const list = document.getElementById('vaultList');
  if (!list) return;
  const query = (document.getElementById('search') as HTMLInputElement | null)?.value ?? '';
  const filtered = filterSummariesByFolderAndQuery(vaultItems, selectedFolderId, query);
  if (filtered.length === 0) {
    const isSearch = query.trim().length > 0;
    list.innerHTML = `
      <div class="empty">
        <span class="glyph">${icon(isSearch ? 'search' : 'shield')}</span>
        <span>${isSearch ? 'No items match your search.' : 'Your vault is empty. Sync to load items.'}</span>
      </div>`;
    return;
  }
  list.innerHTML = filtered.map((item) => {
    const sub = item.username ?? item.uris[0] ?? item.subtitle ?? '';
    return `
    <button class="item" type="button" data-id="${escapeHtml(item.id)}">
      <span class="monogram" style="--mono-h:${hueFor(item.name)}">${escapeHtml(monogramLetter(item.name))}</span>
      <span class="item-body">
        <span class="item-name">
          ${item.favorite ? `<span class="fav" title="Favorite">${icon('star')}</span>` : ''}
          <span class="title">${escapeHtml(item.name)}</span>
          ${item.undecryptable ? '<span class="tag">Undecryptable</span>' : ''}
        </span>
        ${sub ? `<span class="item-sub">${escapeHtml(sub)}</span>` : ''}
      </span>
      <span class="chevron">${icon('chevron')}</span>
    </button>`;
  }).join('');
  for (const row of list.querySelectorAll<HTMLElement>('.item')) {
    row.addEventListener('click', () => renderDetail(row.dataset.id!));
  }
}

function renderDetail(id: string) {
  clearTotpTimer();
  const item = vaultItems.find((i) => i.id === id);
  if (!item) return;
  if (item.type === 2) return renderSecureNoteDetail(id, item);
  if (item.type === 3) return renderStructuredDetail(id, item, 'card');
  if (item.type === 4) return renderStructuredDetail(id, item, 'identity');
  return renderLoginDetail(id, item);
}

/** Standard detail header (back button + title + optional subtitle). */
function detailHead(item: CipherSummary): string {
  return `
    <div class="detail-head">
      <button id="back" class="icon-btn" type="button" title="Back" aria-label="Back">${icon('back')}</button>
      <div class="titles">
        <h1>${escapeHtml(item.name)}</h1>
        ${item.username ? `<span class="sub">${escapeHtml(item.username)}</span>` : ''}
      </div>
    </div>`;
}

function bindBack(): void {
  document.getElementById('back')!.addEventListener('click', () => render({ kind: 'unlocked' }));
}

/** Run a detail action with the busy guard, disabling/re-enabling every detail button. */
async function withDetailBusy(fn: () => Promise<void>): Promise<void> {
  if (isPending) return;
  isPending = true;
  document.querySelectorAll<HTMLButtonElement>('.detail button').forEach((b) => (b.disabled = true));
  try {
    await fn();
  } finally {
    isPending = false;
    document.querySelectorAll<HTMLButtonElement>('.detail button').forEach((b) => (b.disabled = false));
  }
}

/** Copy an in-memory non-sensitive value with the 60s clipboard clear. */
async function copyValue(value: string | undefined, label: string): Promise<void> {
  if (!value) return setDetailStatus(`${label} is empty`, true);
  try {
    await copyWithClear(value);
    setDetailStatus(`${label} copied. Clipboard clears in 60 s if unchanged and this popup stays open.`, false);
  } catch {
    setDetailStatus(`Failed to copy ${label.toLowerCase()} to clipboard`, true);
  }
}

/** Fetch a secret field on demand and copy it (never retained in the DOM/closure). */
async function copyField(id: string, field: 'password' | 'notes' | RevealableField, label: string): Promise<void> {
  const response = await sendRequest({ type: 'vault.getField', id, field });
  if (!response.ok) return setDetailStatus(response.error.message, true);
  await copyValue((response.data as { value?: string }).value, label);
}

/** Fields sensitive enough to mask behind an on-demand reveal toggle. */
type RevealableField = 'card.number' | 'card.code' | 'identity.ssn' | 'identity.passportNumber' | 'identity.licenseNumber';

function renderLoginDetail(id: string, item: CipherSummary) {
  let revealed: string | null = null;
  const uris = item.uris
    .map((u) => `<div class="v is-link"><a href="${safeHref(u)}" target="_blank" rel="noreferrer">${escapeHtml(u)}</a></div>`)
    .join('');
  app.innerHTML = `
    <div class="detail">
      ${detailHead(item)}
      <div class="detail-body">
        ${uris ? `<div class="readout"><div class="k">${icon('globe')} Website</div><div class="v-row">${uris}</div></div>` : ''}
        <div class="readout">
          <div class="k">${icon('lock')} Password</div>
          <div class="v-row">
            <code id="passwordReveal" class="v mono">••••••••</code>
            <button id="togglePassword" class="icon-btn" type="button" aria-pressed="false" title="Show password" aria-label="Show password">${icon('eye')}</button>
          </div>
        </div>
        ${item.hasTotp ? `
        <div class="readout">
          <div class="k">${icon('key')} Verification code</div>
          <div class="v-row">
            <code id="totpCode" class="v mono">······</code>
            <span id="totpCountdown" class="totp-countdown muted" aria-hidden="true"></span>
            <button id="copyTotp" class="icon-btn" type="button" title="Copy code" aria-label="Copy verification code">${icon('copy')}</button>
          </div>
        </div>` : ''}
        <div class="detail-actions">
          <button id="copyPassword" type="button" class="btn btn-block">${icon('copy')}<span>Copy password</span></button>
          <button id="copyUsername" type="button" class="btn btn-secondary btn-block">${icon('user')}<span>Copy username</span></button>
        </div>
        <div id="detailStatus" class="detail-status"></div>
      </div>
    </div>`;
  bindBack();
  document.getElementById('togglePassword')!.addEventListener('click', () => void withDetailBusy(async () => {
    const codeEl = document.getElementById('passwordReveal')!;
    const btn = document.getElementById('togglePassword') as HTMLButtonElement;
    if (revealed !== null) {
      revealed = null;
      codeEl.textContent = '••••••••';
      btn.innerHTML = icon('eye');
      btn.setAttribute('aria-pressed', 'false');
      btn.title = btn.ariaLabel = 'Show password';
      return;
    }
    const response = await sendRequest({ type: 'vault.getField', id, field: 'password' });
    if (!response.ok) return setDetailStatus(response.error.message, true);
    const value = (response.data as { value?: string }).value;
    if (!value) return setDetailStatus('Password is empty', true);
    revealed = value;
    codeEl.textContent = value; // textContent: real plaintext, auto-escaped, only present once revealed
    btn.innerHTML = icon('eyeOff');
    btn.setAttribute('aria-pressed', 'true');
    btn.title = btn.ariaLabel = 'Hide password';
  }));
  document.getElementById('copyPassword')!.addEventListener('click', () => void withDetailBusy(() => copyField(id, 'password', 'Password')));
  document.getElementById('copyUsername')!.addEventListener('click', () => void withDetailBusy(() => copyValue(item.username, 'Username')));

  if (item.hasTotp) {
    let currentCode: string | undefined;
    document.getElementById('copyTotp')!.addEventListener('click', () => void withDetailBusy(() => copyValue(currentCode, 'Verification code')));
    const loadTotp = async (): Promise<void> => {
      const codeEl = document.getElementById('totpCode');
      const countdownEl = document.getElementById('totpCountdown');
      if (!codeEl || !countdownEl) return clearTotpTimer();
      const response = await sendRequest({ type: 'vault.getTotp', id });
      if (!response.ok) {
        clearTotpTimer();
        return setDetailStatus(response.error.message, true);
      }
      const totp = (response.data as { totp: { code: string; period: number; remaining: number } | null }).totp;
      if (!totp) {
        clearTotpTimer();
        countdownEl.textContent = '';
        return setDetailStatus('No verification code for this item', true);
      }
      currentCode = totp.code;
      codeEl.textContent = formatTotp(totp.code);
      let remaining = totp.remaining;
      countdownEl.textContent = `${remaining}s`;
      clearTotpTimer();
      totpTimer = window.setInterval(() => {
        const cd = document.getElementById('totpCountdown');
        if (!cd) return clearTotpTimer();
        remaining -= 1;
        if (remaining <= 0) {
          clearTotpTimer();
          void loadTotp(); // fetch the next window's code
          return;
        }
        cd.textContent = `${remaining}s`;
      }, 1000);
    };
    void loadTotp();
  }
}

/** Group a TOTP code into two halves for readability (e.g. "081804" -> "081 804"). */
function formatTotp(code: string): string {
  if (code.length % 2 !== 0) return code;
  const half = code.length / 2;
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

function renderSecureNoteDetail(id: string, item: CipherSummary) {
  app.innerHTML = `
    <div class="detail">
      ${detailHead(item)}
      <div class="detail-body">
        <div class="readout"><div class="k">${icon('note')} Note</div><pre id="noteBody" class="note-body">Loading…</pre></div>
        <div class="detail-actions"><button id="copyNote" type="button" class="btn btn-block">${icon('copy')}<span>Copy note</span></button></div>
        <div id="detailStatus" class="detail-status"></div>
      </div>
    </div>`;
  bindBack();
  void (async () => {
    const response = await sendRequest({ type: 'vault.getField', id, field: 'notes' });
    const body = document.getElementById('noteBody');
    if (!body) return;
    if (!response.ok) {
      body.textContent = '';
      return setDetailStatus(response.error.message, true);
    }
    const value = (response.data as { value?: string }).value;
    body.textContent = value && value.length ? value : 'No note content';
  })();
  document.getElementById('copyNote')!.addEventListener('click', () => void withDetailBusy(() => copyField(id, 'notes', 'Note')));
}

function renderStructuredDetail(id: string, item: CipherSummary, kind: 'card' | 'identity') {
  app.innerHTML = `
    <div class="detail">
      ${detailHead(item)}
      <div class="detail-body">
        <div id="structuredFields"><div class="muted center">Loading…</div></div>
        <div id="detailStatus" class="detail-status"></div>
      </div>
    </div>`;
  bindBack();
  void (async () => {
    const response = await sendRequest({ type: 'vault.getCipherDetail', id });
    const container = document.getElementById('structuredFields');
    if (!container) return;
    if (!response.ok) {
      container.innerHTML = '';
      return setDetailStatus(response.error.message, true);
    }
    const cipher = (response.data as { cipher: DecryptedCipher | null }).cipher;
    if (!cipher) {
      container.innerHTML = '';
      return setDetailStatus('Item is unavailable', true);
    }
    if (kind === 'card') renderCardFields(id, container, cipher);
    else renderIdentityFields(id, container, cipher);
  })();
}

/** A non-sensitive readout row with a copy button (value already decrypted, no secrets). */
function plainRow(label: string, value: string): string {
  return `<div class="readout"><div class="k">${escapeHtml(label)}</div>
    <div class="v-row"><span class="v mono">${escapeHtml(value)}</span>
      <button class="icon-btn" type="button" data-copy="${escapeHtml(value)}" data-label="${escapeHtml(label)}" title="Copy ${escapeHtml(label)}" aria-label="Copy ${escapeHtml(label)}">${icon('copy')}</button>
    </div></div>`;
}

/** A masked secret row whose value is fetched on demand (card number/CVV, identity national IDs). */
function secretRow(label: string, field: RevealableField): string {
  return `<div class="readout"><div class="k">${escapeHtml(label)}</div>
    <div class="v-row"><code class="v mono" data-secret="${field}">••••••••</code>
      <button class="icon-btn" type="button" data-reveal="${field}" aria-pressed="false" title="Show ${escapeHtml(label)}" aria-label="Show ${escapeHtml(label)}">${icon('eye')}</button>
      <button class="icon-btn" type="button" data-copy-field="${field}" data-label="${escapeHtml(label)}" title="Copy ${escapeHtml(label)}" aria-label="Copy ${escapeHtml(label)}">${icon('copy')}</button>
    </div></div>`;
}

function bindStructuredHandlers(id: string, container: HTMLElement): void {
  const revealed = new Map<string, string>();
  container.querySelectorAll<HTMLButtonElement>('button[data-copy]').forEach((btn) => {
    btn.addEventListener('click', () => void withDetailBusy(() => copyValue(btn.dataset.copy, btn.dataset.label ?? 'Value')));
  });
  container.querySelectorAll<HTMLButtonElement>('button[data-copy-field]').forEach((btn) => {
    const field = btn.dataset.copyField as RevealableField;
    btn.addEventListener('click', () => void withDetailBusy(() => copyField(id, field, btn.dataset.label ?? 'Value')));
  });
  container.querySelectorAll<HTMLButtonElement>('button[data-reveal]').forEach((btn) => {
    const field = btn.dataset.reveal as RevealableField;
    const codeEl = container.querySelector<HTMLElement>(`[data-secret="${field}"]`)!;
    btn.addEventListener('click', () => void withDetailBusy(async () => {
      if (revealed.has(field)) {
        revealed.delete(field);
        codeEl.textContent = '••••••••';
        btn.innerHTML = icon('eye');
        btn.setAttribute('aria-pressed', 'false');
        return;
      }
      const response = await sendRequest({ type: 'vault.getField', id, field });
      if (!response.ok) return setDetailStatus(response.error.message, true);
      const value = (response.data as { value?: string }).value;
      if (!value) return setDetailStatus('Field is empty', true);
      revealed.set(field, value);
      codeEl.textContent = value;
      btn.innerHTML = icon('eyeOff');
      btn.setAttribute('aria-pressed', 'true');
    }));
  });
}

function renderCardFields(id: string, container: HTMLElement, cipher: DecryptedCipher): void {
  const card = cipher.card ?? {};
  const expiry = [card.expMonth, card.expYear].filter(Boolean).join(' / ');
  const rows: string[] = [];
  if (card.brand) rows.push(plainRow('Brand', card.brand));
  if (card.cardholderName) rows.push(plainRow('Cardholder name', card.cardholderName));
  rows.push(secretRow('Number', 'card.number'));
  if (expiry) rows.push(plainRow('Expires', expiry));
  rows.push(secretRow('Security code', 'card.code'));
  container.innerHTML = rows.join('') || `<div class="muted center">No card details</div>`;
  bindStructuredHandlers(id, container);
}

function renderIdentityFields(id: string, container: HTMLElement, cipher: DecryptedCipher): void {
  const i = cipher.identity ?? {};
  const fullName = [i.title, i.firstName, i.middleName, i.lastName].filter(Boolean).join(' ');
  const address = [i.address1, i.address2, i.address3, [i.city, i.state, i.postalCode].filter(Boolean).join(', '), i.country]
    .filter(Boolean).join('\n');
  const plainFields: Array<[string, string | undefined]> = [
    ['Name', fullName || undefined],
    ['Username', i.username],
    ['Company', i.company],
    ['Email', i.email],
    ['Phone', i.phone],
    ['Address', address || undefined],
  ];
  const rows = plainFields.filter(([, v]) => Boolean(v)).map(([label, v]) => plainRow(label, v!));
  // National-ID numbers are masked and fetched on demand, like a card's number/CVV.
  rows.push(secretRow('SSN', 'identity.ssn'));
  rows.push(secretRow('Passport number', 'identity.passportNumber'));
  rows.push(secretRow('License number', 'identity.licenseNumber'));
  container.innerHTML = rows.join('') || `<div class="muted center">No identity details</div>`;
  bindStructuredHandlers(id, container);
}

async function copyWithClear(value: string): Promise<void> {
  await navigator.clipboard.writeText(value);
  window.setTimeout(() => {
    void (async () => {
      const current = await navigator.clipboard.readText().catch(() => '');
      if (current === value) await navigator.clipboard.writeText('').catch(() => {/* no-op */});
    })();
  }, 60_000);
}

function setDetailStatus(message: string, isError: boolean) {
  const status = document.getElementById('detailStatus');
  if (!status) return;
  status.innerHTML = `<p class="note ${isError ? 'error' : 'success'}">${icon(isError ? 'alert' : 'checkCircle')}<span>${escapeHtml(message)}</span></p>`;
}

/** First alphanumeric character of a name, for the monogram chip. */
function monogramLetter(name: string): string {
  const match = name.match(/[\p{L}\p{N}]/u);
  return match ? match[0]!.toUpperCase() : '•';
}

/** Deterministic hue (0–359) from a name, so each item keeps a stable tint. */
function hueFor(name: string): number {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = (hash * 31 + name.charCodeAt(i)) >>> 0;
  }
  return hash % 360;
}

/** Allow only http: and https: URIs; return '#' for anything else. */
function safeHref(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
      return escapeHtml(url);
    }
  } catch {
    // not a valid URL
  }
  return '#';
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
