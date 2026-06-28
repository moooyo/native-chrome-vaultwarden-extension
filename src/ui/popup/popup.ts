import { sendRequest } from '../../messaging/protocol.js';
import type { AuthResult } from '../../core/session/auth-service.js';
import type { CipherInput, CipherSummary, CollectionSummary, DecryptedCipher, FolderSummary } from '../../core/vault/models.js';
import { filterSummariesByFolderCollectionAndQuery, NO_FOLDER } from '../../core/vault/search.js';
import { generatePassword, DEFAULT_PASSWORD_OPTIONS, type PasswordGenOptions } from '../../core/generator/password.js';
import { addPasswordToHistory } from '../../core/generator/history.js';
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
let vaultCollections: CollectionSummary[] = [];
let selectedFolderId: string | null = null;
let selectedCollectionId: string | null = null;
let skippedOrgCount = 0;
// Active TOTP countdown interval for the open login detail (cleared on any navigation).
let totpTimer: number | undefined;
// Password generator options, persisted while the popup stays open.
let genOptions: PasswordGenOptions = { ...DEFAULT_PASSWORD_OPTIONS };
// Generated-password history for this popup session only (never persisted — see core/generator/history).
let genHistory: string[] = [];

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
      <button id="addItem" class="icon-btn" type="button" title="Add item" aria-label="Add item">${icon('plus')}</button>
      <button id="generate" class="icon-btn" type="button" title="Password generator" aria-label="Password generator">${icon('key')}</button>
      <button id="sync" class="icon-btn" type="button" title="Sync vault" aria-label="Sync vault">${icon('refresh')}</button>
      <button id="lock" class="icon-btn" type="button" title="Lock vault" aria-label="Lock vault">${icon('lock')}</button>
    </div>
    <div id="folderBar" class="folderbar"></div>
    <div id="folderEditor" class="folder-editor"></div>
    <div id="collectionBar" class="folderbar"></div>
    <div id="orgBanner"></div>
    <div id="vaultList" class="list-wrap"></div>
    <div class="footer">
      <button id="logoutUnlocked" class="btn btn-danger btn-block" type="button">${icon('logout')}<span>Log out</span></button>
    </div>
    ${error ? `<div class="footer">${errorNote(error)}</div>` : ''}`;
  bindUnlockedControls();
  renderFolderFilter();
  renderCollectionFilter();
  renderOrgBanner();
  void loadCachedList();
}

/** Rebuild the folder filter + management controls, preserving a valid selection. */
function renderFolderFilter() {
  const bar = document.getElementById('folderBar');
  if (!bar) return;
  const hasNoFolderItems = vaultItems.some((i) => !i.folderId);
  // Reset a stale selection so the dropdown and the filtered list never desync: a chosen folder
  // that no longer exists, or "No Folder" when every item now has a folder.
  if (selectedFolderId !== null && selectedFolderId !== NO_FOLDER && !vaultFolders.some((f) => f.id === selectedFolderId)) {
    selectedFolderId = null;
  }
  if (selectedFolderId === NO_FOLDER && !hasNoFolderItems) {
    selectedFolderId = null;
  }
  const showSelect = vaultFolders.length > 0 || hasNoFolderItems;
  const options = [
    `<option value="">All folders</option>`,
    ...vaultFolders.map((f) => `<option value="${escapeHtml(f.id)}">${escapeHtml(f.name)}</option>`),
    hasNoFolderItems ? `<option value="${NO_FOLDER}">No Folder</option>` : '',
  ].join('');
  // Rename/Delete apply only to a concrete folder (not "All folders" or "No Folder").
  const concrete = selectedFolderId !== null && selectedFolderId !== NO_FOLDER;
  bar.innerHTML = `
    ${showSelect
      ? `<div class="folder-select">${icon('folder')}<select id="folderFilter" class="select" aria-label="Filter by folder">${options}</select></div>`
      : `<span class="folder-empty muted">${icon('folder')} No folders</span>`}
    <div class="folder-actions">
      <button id="folderNew" class="icon-btn" type="button" title="New folder" aria-label="New folder">${icon('plus')}</button>
      ${concrete ? `<button id="folderRename" class="icon-btn" type="button" title="Rename folder" aria-label="Rename folder">${icon('edit')}</button><button id="folderDelete" class="icon-btn" type="button" title="Delete folder" aria-label="Delete folder">${icon('trash')}</button>` : ''}
    </div>`;
  const select = document.getElementById('folderFilter') as HTMLSelectElement | null;
  if (select) {
    select.value = selectedFolderId ?? '';
    select.addEventListener('change', () => {
      selectedFolderId = select.value || null;
      closeFolderEditor();
      renderFolderFilter(); // refresh Rename/Delete affordances for the new selection
      renderVaultList();
    });
  }
  document.getElementById('folderNew')!.addEventListener('click', () => openFolderEditor('create'));
  if (concrete) {
    const folder = vaultFolders.find((f) => f.id === selectedFolderId);
    document.getElementById('folderRename')!.addEventListener('click', () => openFolderEditor('rename', folder));
    document.getElementById('folderDelete')!.addEventListener('click', () => openFolderEditor('delete', folder));
  }
}

/** Apply a fresh listing returned by a folder mutation, then re-render the filtered views. */
function applyListing(data: { items: CipherSummary[]; folders: FolderSummary[]; collections: CollectionSummary[] }): void {
  vaultItems = data.items;
  vaultFolders = data.folders;
  vaultCollections = data.collections;
  closeFolderEditor();
  renderFolderFilter();
  renderCollectionFilter();
  renderVaultList();
}

function closeFolderEditor(): void {
  const host = document.getElementById('folderEditor');
  if (host) host.innerHTML = '';
}

/** Inline create/rename/delete editor for folders, rendered under the folder bar. */
function openFolderEditor(mode: 'create' | 'rename' | 'delete', folder?: FolderSummary): void {
  const host = document.getElementById('folderEditor');
  if (!host) return;
  if (mode === 'delete' && folder) {
    host.innerHTML = `
      <div class="folder-edit-row">
        <span class="muted">Delete “${escapeHtml(folder.name)}”? Its items move to No Folder.</span>
        <button id="folderConfirm" class="btn btn-danger btn-sm" type="button">Delete</button>
        <button id="folderCancel" class="btn btn-secondary btn-sm" type="button">Cancel</button>
      </div>
      <div id="folderEditStatus" class="folder-edit-status"></div>`;
    document.getElementById('folderConfirm')!.addEventListener('click', () => void submitFolderMutation({ type: 'vault.deleteFolder', id: folder.id }));
    document.getElementById('folderCancel')!.addEventListener('click', closeFolderEditor);
    return;
  }
  const initial = mode === 'rename' && folder ? folder.name : '';
  host.innerHTML = `
    <div class="folder-edit-row">
      <input id="folderNameInput" class="input" placeholder="Folder name" value="${escapeHtml(initial)}" />
      <button id="folderConfirm" class="btn btn-sm" type="button">Save</button>
      <button id="folderCancel" class="btn btn-secondary btn-sm" type="button">Cancel</button>
    </div>
    <div id="folderEditStatus" class="folder-edit-status"></div>`;
  const input = document.getElementById('folderNameInput') as HTMLInputElement;
  input.focus();
  input.select();
  const submit = () => {
    const name = input.value.trim();
    if (!name) return setFolderEditStatus('Enter a folder name');
    if (mode === 'rename' && folder) void submitFolderMutation({ type: 'vault.renameFolder', id: folder.id, name });
    else void submitFolderMutation({ type: 'vault.createFolder', name });
  };
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); submit(); }
    if (e.key === 'Escape') closeFolderEditor();
  });
  document.getElementById('folderConfirm')!.addEventListener('click', submit);
  document.getElementById('folderCancel')!.addEventListener('click', closeFolderEditor);
}

function setFolderEditStatus(message: string): void {
  const status = document.getElementById('folderEditStatus');
  if (status) status.innerHTML = `<span class="error">${escapeHtml(message)}</span>`;
}

async function submitFolderMutation(
  request: { type: 'vault.createFolder'; name: string } | { type: 'vault.renameFolder'; id: string; name: string } | { type: 'vault.deleteFolder'; id: string },
): Promise<void> {
  if (isPending) return;
  isPending = true;
  document.querySelectorAll<HTMLButtonElement>('#folderEditor button').forEach((b) => (b.disabled = true));
  try {
    const response = await sendRequest(request);
    if (!response.ok) return setFolderEditStatus(response.error.message);
    applyListing(response.data as { items: CipherSummary[]; folders: FolderSummary[]; collections: CollectionSummary[] });
  } finally {
    isPending = false;
  }
}

/** Build the collection <select> from decrypted org collections, preserving a valid selection. */
function renderCollectionFilter() {
  const bar = document.getElementById('collectionBar');
  if (!bar) return;
  if (vaultCollections.length === 0) {
    bar.innerHTML = '';
    return;
  }
  // Drop a stale selection (e.g. a collection that no longer exists after a sync).
  if (selectedCollectionId !== null && !vaultCollections.some((c) => c.id === selectedCollectionId)) {
    selectedCollectionId = null;
  }
  const options = [
    `<option value="">All collections</option>`,
    ...vaultCollections.map((c) => `<option value="${escapeHtml(c.id)}">${escapeHtml(c.name)}</option>`),
  ].join('');
  bar.innerHTML = `<div class="folder-select">${icon('shield')}<select id="collectionFilter" class="select" aria-label="Filter by collection">${options}</select></div>`;
  const select = document.getElementById('collectionFilter') as HTMLSelectElement | null;
  if (select) {
    select.value = selectedCollectionId ?? '';
    select.addEventListener('change', () => {
      selectedCollectionId = select.value || null;
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
        vaultCollections = [];
        selectedFolderId = null;
        selectedCollectionId = null;
        skippedOrgCount = 0;
        genHistory = [];
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
        const data = response.data as { items: CipherSummary[]; folders: FolderSummary[]; collections: CollectionSummary[] };
        vaultItems = data.items;
        vaultFolders = data.folders;
        vaultCollections = data.collections;
        await loadSkippedOrgCount();
        renderFolderFilter();
        renderCollectionFilter();
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
  document.getElementById('addItem')!.addEventListener('click', () => renderTypePicker());
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
        <div id="genHistory"></div>
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
  // Update the displayed password (on option changes) without touching history.
  const regenerate = (): void => {
    readOptions();
    current = generatePassword(genOptions);
    out.textContent = current || 'Enable at least one character set';
  };
  // Generate a fresh password AND record the previous one in history (explicit Regenerate / open).
  const regenerateAndRecord = (): void => {
    if (current) genHistory = addPasswordToHistory(genHistory, current);
    regenerate();
    renderGenHistory();
  };
  for (const id of ['genLength', 'genLower', 'genUpper', 'genNumbers', 'genSpecial', 'genAmbiguous']) {
    document.getElementById(id)!.addEventListener('input', regenerate);
  }
  document.getElementById('genRegen')!.addEventListener('click', regenerateAndRecord);
  document.getElementById('genCopy')!.addEventListener('click', () => void withDetailBusy(async () => {
    if (current) {
      genHistory = addPasswordToHistory(genHistory, current);
      renderGenHistory();
    }
    await copyValue(current, 'Password');
  }));
  regenerate();
  renderGenHistory();
}

/** Render the in-memory generation history with per-entry copy and a clear-all control. */
function renderGenHistory(): void {
  const container = document.getElementById('genHistory');
  if (!container) return;
  if (genHistory.length === 0) {
    container.innerHTML = '';
    return;
  }
  const rows = genHistory.map((pw) => `
    <div class="gen-hist-row">
      <code class="gen-hist-val mono">${escapeHtml(pw)}</code>
      <button class="icon-btn" type="button" data-copy-hist="${escapeHtml(pw)}" title="Copy" aria-label="Copy password">${icon('copy')}</button>
    </div>`).join('');
  container.innerHTML = `
    <div class="gen-history">
      <div class="gen-hist-head">
        <span class="k">${icon('refresh')} History</span>
        <button id="genHistClear" class="link-btn" type="button">Clear</button>
      </div>
      <div class="gen-hist-list">${rows}</div>
    </div>`;
  for (const btn of container.querySelectorAll<HTMLButtonElement>('button[data-copy-hist]')) {
    btn.addEventListener('click', () => void withDetailBusy(() => copyValue(btn.dataset.copyHist, 'Password')));
  }
  document.getElementById('genHistClear')!.addEventListener('click', () => {
    genHistory = [];
    renderGenHistory();
  });
}

/** Cipher type names for editor headers. */
const CIPHER_TYPE_NAMES: Record<1 | 2 | 3 | 4, string> = { 1: 'Login', 2: 'Secure note', 3: 'Card', 4: 'Identity' };

interface EditorFieldSpec { key: string; label: string }
const CARD_FORM: EditorFieldSpec[] = [
  { key: 'cardholderName', label: 'Cardholder name' },
  { key: 'brand', label: 'Brand' },
  { key: 'number', label: 'Number' },
  { key: 'expMonth', label: 'Expiration month' },
  { key: 'expYear', label: 'Expiration year' },
  { key: 'code', label: 'Security code' },
];
const IDENTITY_FORM: EditorFieldSpec[] = [
  { key: 'title', label: 'Title' }, { key: 'firstName', label: 'First name' },
  { key: 'middleName', label: 'Middle name' }, { key: 'lastName', label: 'Last name' },
  { key: 'username', label: 'Username' }, { key: 'company', label: 'Company' },
  { key: 'email', label: 'Email' }, { key: 'phone', label: 'Phone' },
  { key: 'address1', label: 'Address 1' }, { key: 'address2', label: 'Address 2' },
  { key: 'address3', label: 'Address 3' }, { key: 'city', label: 'City' },
  { key: 'state', label: 'State' }, { key: 'postalCode', label: 'Postal code' },
  { key: 'country', label: 'Country' }, { key: 'ssn', label: 'SSN' },
  { key: 'passportNumber', label: 'Passport number' }, { key: 'licenseNumber', label: 'License number' },
];

/** Step 1 of "add item": choose a type, then open the editor. */
function renderTypePicker(): void {
  clearTotpTimer();
  app.innerHTML = `
    <div class="detail">
      <div class="detail-head">
        <button id="back" class="icon-btn" type="button" title="Back" aria-label="Back">${icon('back')}</button>
        <div class="titles"><h1>Add item</h1></div>
      </div>
      <div class="detail-body">
        <div class="type-grid">
          <button class="type-card" type="button" data-type="1">${icon('key')}<span>Login</span></button>
          <button class="type-card" type="button" data-type="2">${icon('note')}<span>Secure note</span></button>
          <button class="type-card" type="button" data-type="3">${icon('card')}<span>Card</span></button>
          <button class="type-card" type="button" data-type="4">${icon('idcard')}<span>Identity</span></button>
        </div>
      </div>
    </div>`;
  document.getElementById('back')!.addEventListener('click', () => render({ kind: 'unlocked' }));
  for (const btn of app.querySelectorAll<HTMLButtonElement>('.type-card')) {
    btn.addEventListener('click', () => renderEditor('create', Number(btn.dataset.type) as 1 | 2 | 3 | 4));
  }
}

function editorTextRow(id: string, label: string, value = ''): string {
  return `<label class="ed-field"><span class="ed-label">${escapeHtml(label)}</span><input id="${id}" class="input" value="${escapeHtml(value)}" /></label>`;
}

/** Render the create/edit form for a cipher type. */
function renderEditor(mode: 'create' | 'edit', type: 1 | 2 | 3 | 4, input?: CipherInput, id?: string): void {
  clearTotpTimer();
  const v = input ?? { type, name: '' };
  const folderOptions = [
    `<option value="">No folder</option>`,
    ...vaultFolders.map((f) => `<option value="${escapeHtml(f.id)}"${v.folderId === f.id ? ' selected' : ''}>${escapeHtml(f.name)}</option>`),
  ].join('');

  let typeFields = '';
  if (type === 1) {
    const login = v.login ?? {};
    typeFields = `
      ${editorTextRow('ed_username', 'Username', login.username ?? '')}
      <label class="ed-field"><span class="ed-label">Password</span>
        <div class="ed-password">
          <input id="ed_password" class="input mono" type="password" value="${escapeHtml(login.password ?? '')}" />
          <button id="ed_pwReveal" class="icon-btn" type="button" title="Show password" aria-label="Show password">${icon('eye')}</button>
          <button id="ed_pwGen" class="icon-btn" type="button" title="Generate password" aria-label="Generate password">${icon('refresh')}</button>
        </div>
      </label>
      ${editorTextRow('ed_totp', 'Authenticator key (TOTP)', login.totp ?? '')}
      ${editorTextRow('ed_uri', 'Website (URI)', login.uris?.[0]?.uri ?? '')}`;
  } else if (type === 3) {
    typeFields = CARD_FORM.map((f) => editorTextRow(`ed_${f.key}`, f.label, (v.card as Record<string, string> | undefined)?.[f.key] ?? '')).join('');
  } else if (type === 4) {
    typeFields = `<div class="ed-grid">${IDENTITY_FORM.map((f) => editorTextRow(`ed_${f.key}`, f.label, (v.identity as Record<string, string> | undefined)?.[f.key] ?? '')).join('')}</div>`;
  }

  app.innerHTML = `
    <div class="detail">
      <div class="detail-head">
        <button id="back" class="icon-btn" type="button" title="Back" aria-label="Back">${icon('back')}</button>
        <div class="titles"><h1>${mode === 'create' ? 'Add' : 'Edit'} ${escapeHtml(CIPHER_TYPE_NAMES[type].toLowerCase())}</h1></div>
      </div>
      <div class="detail-body">
        ${editorTextRow('ed_name', 'Name', v.name)}
        ${typeFields}
        <label class="ed-field"><span class="ed-label">Notes</span><textarea id="ed_notes" class="input ed-textarea">${escapeHtml(v.notes ?? '')}</textarea></label>
        <label class="ed-field"><span class="ed-label">Folder</span><select id="ed_folder" class="select">${folderOptions}</select></label>
        <label class="gen-check"><input id="ed_favorite" type="checkbox" ${v.favorite ? 'checked' : ''} /><span>Favorite</span></label>
        <div class="detail-actions">
          <button id="ed_save" type="button" class="btn btn-block">${icon('check')}<span>Save</span></button>
          ${mode === 'edit' ? `<button id="ed_delete" type="button" class="btn btn-danger btn-block">${icon('trash')}<span>Delete</span></button>` : ''}
        </div>
        <div id="detailStatus" class="detail-status"></div>
      </div>
    </div>`;
  document.getElementById('back')!.addEventListener('click', () => render({ kind: 'unlocked' }));
  if (type === 1) {
    document.getElementById('ed_pwReveal')!.addEventListener('click', () => {
      const pw = document.getElementById('ed_password') as HTMLInputElement;
      const btn = document.getElementById('ed_pwReveal') as HTMLButtonElement;
      const show = pw.type === 'password';
      pw.type = show ? 'text' : 'password';
      btn.innerHTML = icon(show ? 'eyeOff' : 'eye');
    });
    document.getElementById('ed_pwGen')!.addEventListener('click', () => {
      (document.getElementById('ed_password') as HTMLInputElement).value = generatePassword(genOptions);
    });
  }
  document.getElementById('ed_save')!.addEventListener('click', () => void saveEditor(mode, type, id));
  if (mode === 'edit' && id) {
    document.getElementById('ed_delete')!.addEventListener('click', () => confirmDeleteCipher(id, v.name));
  }
}

function collectEditorInput(type: 1 | 2 | 3 | 4): CipherInput {
  const val = (elId: string): string => (document.getElementById(elId) as HTMLInputElement | HTMLTextAreaElement | null)?.value ?? '';
  const input: CipherInput = {
    type,
    name: val('ed_name').trim(),
    favorite: (document.getElementById('ed_favorite') as HTMLInputElement).checked,
    folderId: val('ed_folder') || null,
  };
  const notes = val('ed_notes'); if (notes) input.notes = notes;
  if (type === 1) {
    const login: NonNullable<CipherInput['login']> = {};
    const u = val('ed_username'); if (u) login.username = u;
    const p = val('ed_password'); if (p) login.password = p;
    const t = val('ed_totp'); if (t) login.totp = t;
    const uri = val('ed_uri').trim(); if (uri) login.uris = [{ uri }];
    input.login = login;
  } else if (type === 3) {
    const card: Record<string, string> = {};
    for (const f of CARD_FORM) { const x = val(`ed_${f.key}`); if (x) card[f.key] = x; }
    input.card = card;
  } else if (type === 4) {
    const identity: Record<string, string> = {};
    for (const f of IDENTITY_FORM) { const x = val(`ed_${f.key}`); if (x) identity[f.key] = x; }
    input.identity = identity;
  }
  return input;
}

async function saveEditor(mode: 'create' | 'edit', type: 1 | 2 | 3 | 4, id?: string): Promise<void> {
  if (isPending) return;
  const input = collectEditorInput(type);
  if (!input.name) return setDetailStatus('Name is required', true);
  isPending = true;
  document.querySelectorAll<HTMLButtonElement>('.detail button').forEach((b) => (b.disabled = true));
  try {
    const response = mode === 'create'
      ? await sendRequest({ type: 'vault.createCipher', input })
      : await sendRequest({ type: 'vault.updateCipher', id: id!, input });
    if (!response.ok) {
      setDetailStatus(response.error.message, true);
      document.querySelectorAll<HTMLButtonElement>('.detail button').forEach((b) => (b.disabled = false));
      return;
    }
    render({ kind: 'unlocked' });
  } finally {
    isPending = false;
  }
}

/** Open the editor prefilled from the worker's decrypted plaintext. */
async function openEditorForEdit(id: string): Promise<void> {
  const response = await sendRequest({ type: 'vault.getCipherInput', id });
  if (!response.ok) return setDetailStatus(response.error.message, true);
  const input = (response.data as { input: CipherInput | null }).input;
  if (!input) return setDetailStatus('This item type cannot be edited yet', true);
  renderEditor('edit', input.type, input, id);
}

/** Inline two-step delete confirmation rendered into the detail status line. */
function confirmDeleteCipher(id: string, name: string): void {
  const status = document.getElementById('detailStatus');
  if (!status) return;
  status.innerHTML = `<div class="confirm-row">
    <span class="muted">Delete “${escapeHtml(name)}”?</span>
    <button id="ed_confirmDel" class="btn btn-danger btn-sm" type="button">Delete</button>
    <button id="ed_cancelDel" class="btn btn-secondary btn-sm" type="button">Cancel</button>
  </div>`;
  document.getElementById('ed_cancelDel')!.addEventListener('click', () => { status.innerHTML = ''; });
  document.getElementById('ed_confirmDel')!.addEventListener('click', async () => {
    if (isPending) return;
    isPending = true;
    status.querySelectorAll('button').forEach((b) => (b.disabled = true));
    try {
      const response = await sendRequest({ type: 'vault.deleteCipher', id });
      if (!response.ok) return setDetailStatus(response.error.message, true);
      render({ kind: 'unlocked' });
    } finally {
      isPending = false;
    }
  });
}

async function loadCachedList() {
  const response = await sendRequest({ type: 'vault.listItems' });
  if (response.ok) {
    const data = response.data as { items: CipherSummary[]; folders: FolderSummary[]; collections: CollectionSummary[] };
    vaultItems = data.items;
    vaultFolders = data.folders;
    vaultCollections = data.collections;
    await loadSkippedOrgCount();
    renderFolderFilter();
    renderCollectionFilter();
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
  const filtered = filterSummariesByFolderCollectionAndQuery(vaultItems, selectedFolderId, selectedCollectionId, query);
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

/** Standard detail header (back button + title + optional subtitle + edit/delete actions). */
function detailHead(item: CipherSummary): string {
  const editable = !item.undecryptable && item.type !== 5;
  return `
    <div class="detail-head">
      <button id="back" class="icon-btn" type="button" title="Back" aria-label="Back">${icon('back')}</button>
      <div class="titles">
        <h1>${escapeHtml(item.name)}</h1>
        ${item.username ? `<span class="sub">${escapeHtml(item.username)}</span>` : ''}
      </div>
      ${editable ? `<div class="detail-head-actions">
        <button id="detailEdit" class="icon-btn" type="button" title="Edit" aria-label="Edit">${icon('edit')}</button>
        <button id="detailDelete" class="icon-btn" type="button" title="Delete" aria-label="Delete">${icon('trash')}</button>
      </div>` : ''}
    </div>`;
}

function bindBack(): void {
  document.getElementById('back')!.addEventListener('click', () => render({ kind: 'unlocked' }));
}

/** Wire the edit/delete actions in a detail header (no-op when the item is not editable). */
function bindDetailActions(item: CipherSummary): void {
  document.getElementById('detailEdit')?.addEventListener('click', () => void openEditorForEdit(item.id));
  document.getElementById('detailDelete')?.addEventListener('click', () => confirmDeleteCipher(item.id, item.name));
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
  bindDetailActions(item);
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
  bindDetailActions(item);
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
  bindDetailActions(item);
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
