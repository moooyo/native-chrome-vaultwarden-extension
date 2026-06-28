import { sendRequest } from '../../messaging/protocol.js';
import type { AuthResult } from '../../core/session/auth-service.js';
import type { CipherInput, CipherSummary, CollectionSummary, CustomFieldType, DecryptedCipher, DecryptedField, FolderSummary } from '../../core/vault/models.js';
import { filterSummariesByFolderCollectionAndQuery, NO_FOLDER } from '../../core/vault/search.js';
import { generatePassword, DEFAULT_PASSWORD_OPTIONS, type PasswordGenOptions } from '../../core/generator/password.js';
import { generatePassphrase, DEFAULT_PASSPHRASE_OPTIONS, type PassphraseGenOptions } from '../../core/generator/passphrase.js';
import { addPasswordToHistory } from '../../core/generator/history.js';
import { icon } from '../icons.js';

type View =
  | { kind: 'loading' }
  | { kind: 'loggedOut'; error?: string }
  | { kind: 'register'; error?: string }
  | { kind: 'twoFactor'; providers: number[]; error?: string }
  | { kind: 'locked'; error?: string }
  | { kind: 'unlocked'; error?: string };

const app = document.getElementById('app')!;
let twoFactorProviders: number[] = [];

/** Friendly names for Bitwarden two-factor provider ids. */
const TWO_FACTOR_NAMES: Record<number, string> = {
  0: 'Authenticator app',
  1: 'Email',
  2: 'Duo',
  3: 'YubiKey OTP',
  6: 'Duo (organization)',
  7: 'Security key (FIDO2)',
};
// Providers whose token is a code/OTP string the user can type (handled by the shared token path).
const CODE_BASED_PROVIDERS = [0, 1, 2, 3, 6];
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
// When true, the vault list shows trashed (soft-deleted) items instead of active ones.
let showTrash = false;
let skippedOrgCount = 0;
// Active TOTP countdown interval for the open login detail (cleared on any navigation).
let totpTimer: number | undefined;

// Master-password reprompt: when the user clears the gate for a protected item, the verified master
// password is held ONLY in this popup's memory for the duration of that item's detail/editor view and
// is wiped on any navigation (render()) or when the popup closes. It is passed to the worker so it can
// enforce the reprompt at the trusted boundary; it is never persisted.
let repromptMp: string | null = null;
let repromptForId: string | null = null;
// Password generator options, persisted while the popup stays open.
let genOptions: PasswordGenOptions = { ...DEFAULT_PASSWORD_OPTIONS };
let genMode: 'password' | 'passphrase' = 'password';
let genPassphraseOptions: PassphraseGenOptions = { ...DEFAULT_PASSPHRASE_OPTIONS };
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
  // Navigating away from an item view wipes any retained reprompt master password.
  repromptMp = null;
  repromptForId = null;
  currentViewKind = view.kind;
  if (view.kind === 'loading') {
    app.innerHTML = `<div class="center"><span class="spinner"></span><span class="muted">Loading vault…</span></div>`;
    return;
  }
  if (view.kind === 'loggedOut') return renderLogin(view.error);
  if (view.kind === 'register') return renderRegister(view.error);
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
        <button id="goRegister" type="button" class="btn btn-secondary btn-block">${icon('user')}<span>Create account</span></button>
        ${errorNote(error)}
      </form>
    </div>`;
  document.getElementById('goRegister')!.addEventListener('click', () => render({ kind: 'register' }));
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

function renderRegister(error?: string) {
  app.innerHTML = `
    <div class="auth">
      ${authHead('Create account', 'Set up a new vault on your self-hosted server')}
      <form id="registerForm">
        <label class="field">
          <span class="field-label">Email</span>
          <input id="regEmail" class="input" type="email" autocomplete="username" required />
        </label>
        <label class="field">
          <span class="field-label">Name (optional)</span>
          <input id="regName" class="input" type="text" autocomplete="name" />
        </label>
        <label class="field">
          <span class="field-label">Master password</span>
          <input id="regPassword" class="input" type="password" autocomplete="new-password" required />
        </label>
        <label class="field">
          <span class="field-label">Confirm master password</span>
          <input id="regConfirm" class="input" type="password" autocomplete="new-password" required />
        </label>
        <p class="note muted"><span>Your master password can't be recovered. It never leaves this device.</span></p>
        <button type="submit" class="btn btn-block">${icon('shield')}<span>Create account</span></button>
        <button id="backToLogin" type="button" class="btn btn-secondary btn-block">${icon('back')}<span>Back to sign in</span></button>
        ${errorNote(error)}
      </form>
    </div>`;
  document.getElementById('backToLogin')!.addEventListener('click', () => render({ kind: 'loggedOut' }));
  document.getElementById('registerForm')!.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (isPending) return;
    const email = (document.getElementById('regEmail') as HTMLInputElement).value.trim();
    const name = (document.getElementById('regName') as HTMLInputElement).value.trim();
    const masterPassword = (document.getElementById('regPassword') as HTMLInputElement).value;
    const confirm = (document.getElementById('regConfirm') as HTMLInputElement).value;
    if (masterPassword.length < 8) return render({ kind: 'register', error: 'Master password must be at least 8 characters' });
    if (masterPassword !== confirm) return render({ kind: 'register', error: 'Passwords do not match' });
    isPending = true;
    const form = document.getElementById('registerForm') as HTMLFormElement;
    form.querySelectorAll('input, button').forEach((el) => ((el as HTMLInputElement | HTMLButtonElement).disabled = true));
    try {
      const result = await sendRequest(name ? { type: 'auth.register', email, masterPassword, name } : { type: 'auth.register', email, masterPassword });
      await handleAuthResult(result);
    } finally {
      isPending = false;
      if (currentViewKind === 'register') {
        const liveForm = document.getElementById('registerForm') as HTMLFormElement | null;
        liveForm?.querySelectorAll('input, button').forEach((el) => ((el as HTMLInputElement | HTMLButtonElement).disabled = false));
      }
    }
  });
}

/** Per-provider input hint for the code field. */
function twoFactorHint(provider: number): string {
  if (provider === 1) return 'Enter the code emailed to you.';
  if (provider === 3) return 'Touch your YubiKey to emit its one-time code.';
  if (provider === 2 || provider === 6) return 'Enter a passcode from the Duo Mobile app.';
  return 'Enter the 6-digit code from your authenticator app.';
}

function renderTwoFactor(providers: number[], error?: string) {
  twoFactorProviders = providers;
  const usable = providers.filter((p) => CODE_BASED_PROVIDERS.includes(p));
  // No code-based method we support (e.g. only a FIDO2 security key, which needs a hosted connector).
  if (usable.length === 0) {
    const names = providers.map((p) => TWO_FACTOR_NAMES[p] ?? `Method ${p}`).join(', ');
    app.innerHTML = `
      <div class="auth">
        ${authHead('Two-step login', 'This method is not supported here yet')}
        <p class="note error">${icon('alert')}<span>Your account requires: ${escapeHtml(names || 'an unsupported method')}. Use a Bitwarden client that supports it, or add an authenticator/email method.</span></p>
        <button id="tfBack" class="btn btn-secondary btn-block" type="button">${icon('back')}<span>Back to login</span></button>
        ${errorNote(error)}
      </div>`;
    document.getElementById('tfBack')!.addEventListener('click', () => render({ kind: 'loggedOut' }));
    return;
  }
  const first = usable[0]!;
  app.innerHTML = `
    <div class="auth">
      ${authHead('Two-step login', 'Enter your verification code to continue')}
      <form id="twoFactorForm">
        <label class="field">
          <span class="field-label">Provider</span>
          <select id="provider" class="select">${usable.map((p) => `<option value="${p}">${escapeHtml(TWO_FACTOR_NAMES[p] ?? `Method ${p}`)}</option>`).join('')}</select>
        </label>
        <label class="field">
          <span class="field-label">Code</span>
          <input id="code" class="input mono" autocomplete="one-time-code" required />
          <span id="tfHint" class="field-hint muted">${escapeHtml(twoFactorHint(first))}</span>
        </label>
        <button type="submit" class="btn btn-block">${icon('key')}<span>Continue</span></button>
        ${usable.includes(1) ? `<button id="sendEmail" class="btn btn-secondary btn-block" type="button">${icon('mail')}<span>Send email code</span></button>` : ''}
        ${errorNote(error)}
      </form>
    </div>`;
  const providerSel = document.getElementById('provider') as HTMLSelectElement;
  providerSel.addEventListener('change', () => {
    const hint = document.getElementById('tfHint');
    if (hint) hint.textContent = twoFactorHint(Number(providerSel.value));
  });
  document.getElementById('twoFactorForm')!.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (isPending) return;
    isPending = true;
    const button = document.querySelector('#twoFactorForm button[type="submit"]') as HTMLButtonElement;
    const form = document.getElementById('twoFactorForm') as HTMLFormElement;
    button.disabled = true;
    (form.querySelectorAll('input, select') as NodeListOf<HTMLInputElement | HTMLSelectElement>).forEach(el => el.disabled = true);
    try {
      const provider = Number((document.getElementById('provider') as HTMLSelectElement).value);
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
        <div id="pinUnlockSlot"></div>
        <button id="logout" type="button" class="btn btn-danger btn-block">${icon('logout')}<span>Log out</span></button>
        ${errorNote(error)}
      </form>
    </div>`;
  void populatePinUnlock();
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

/** On the locked screen, show a PIN unlock field when a PIN has been set. */
async function populatePinUnlock(): Promise<void> {
  const slot = document.getElementById('pinUnlockSlot');
  if (!slot) return;
  const status = await sendRequest({ type: 'auth.pinStatus' });
  if (!status.ok || !(status.data as { enabled: boolean }).enabled) return;
  if (!document.getElementById('pinUnlockSlot')) return; // view changed while awaiting
  slot.innerHTML = `
    <div class="pin-unlock">
      <input id="pinUnlockInput" class="input" inputmode="numeric" autocomplete="off" placeholder="PIN" />
      <button id="pinUnlockBtn" class="btn btn-secondary btn-block" type="button">${icon('unlock')}<span>Unlock with PIN</span></button>
    </div>`;
  const input = document.getElementById('pinUnlockInput') as HTMLInputElement;
  const submit = async () => {
    if (isPending) return;
    const pin = input.value.trim();
    if (!pin) return;
    isPending = true;
    try {
      const response = await sendRequest({ type: 'auth.unlockWithPin', pin });
      render(response.ok ? { kind: 'unlocked' } : { kind: 'locked', error: response.error.message });
    } finally {
      isPending = false;
    }
  };
  document.getElementById('pinUnlockBtn')!.addEventListener('click', () => void submit());
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); void submit(); } });
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
      <button id="health" class="icon-btn" type="button" title="Password health" aria-label="Password health">${icon('checkCircle')}</button>
      <button id="generate" class="icon-btn" type="button" title="Password generator" aria-label="Password generator">${icon('key')}</button>
      <button id="sync" class="icon-btn" type="button" title="Sync vault" aria-label="Sync vault">${icon('refresh')}</button>
      <button id="trashToggle" class="icon-btn" type="button" title="Trash" aria-label="Trash">${icon('trash')}</button>
      <button id="lock" class="icon-btn" type="button" title="Lock vault" aria-label="Lock vault">${icon('lock')}</button>
    </div>
    <div id="folderBar" class="folderbar"></div>
    <div id="folderEditor" class="folder-editor"></div>
    <div id="collectionBar" class="folderbar"></div>
    <div id="orgBanner"></div>
    <div id="vaultList" class="list-wrap"></div>
    <div class="footer">
      <div class="footer-tools">
        <button id="exportVault" class="btn btn-secondary btn-sm" type="button">${icon('logout')}<span>Export</span></button>
        <button id="importVault" class="btn btn-secondary btn-sm" type="button">${icon('plus')}<span>Import</span></button>
        <button id="pinBtn" class="btn btn-secondary btn-sm" type="button">${icon('lock')}<span>PIN</span></button>
        <button id="securityBtn" class="btn btn-secondary btn-sm" type="button">${icon('key')}<span>Password</span></button>
        <button id="accountsBtn" class="btn btn-secondary btn-sm" type="button">${icon('user')}<span>Accounts</span></button>
        <input id="importFile" type="file" accept="application/json,.json,text/csv,.csv" hidden />
      </div>
      <div id="footerStatus" class="detail-status"></div>
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
  document.getElementById('trashToggle')!.addEventListener('click', () => {
    showTrash = !showTrash;
    renderVaultList();
  });
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
  document.getElementById('health')!.addEventListener('click', () => void renderHealthReport());
  bindExportImport();
}

/** Export downloads decrypted plaintext (two-click confirm); import reads a JSON export file. */
function bindExportImport(): void {
  const setFooterStatus = (message: string, isError: boolean): void => {
    const status = document.getElementById('footerStatus');
    if (status) status.innerHTML = `<p class="note ${isError ? 'error' : 'success'}">${icon(isError ? 'alert' : 'checkCircle')}<span>${escapeHtml(message)}</span></p>`;
  };

  const exportBtn = document.getElementById('exportVault') as HTMLButtonElement;
  exportBtn.addEventListener('click', () => openExportPanel(setFooterStatus));

  const importBtn = document.getElementById('importVault') as HTMLButtonElement;
  const importFile = document.getElementById('importFile') as HTMLInputElement;
  importBtn.addEventListener('click', () => importFile.click());
  importFile.addEventListener('change', async () => {
    const file = importFile.files?.[0];
    importFile.value = '';
    if (!file || isPending) return;
    let text: string;
    try {
      text = await file.text();
    } catch {
      return setFooterStatus('Could not read the import file', true);
    }
    // A password-protected export needs its password; collect it first, otherwise import directly.
    if (/"encrypted"\s*:\s*true/.test(text) && /"passwordProtected"\s*:\s*true/.test(text)) {
      promptImportPassword(setFooterStatus, (password) => void doImport(text, setFooterStatus, password));
    } else {
      void doImport(text, setFooterStatus);
    }
  });

  document.getElementById('pinBtn')!.addEventListener('click', () => void openPinEditor(setFooterStatus));
  document.getElementById('securityBtn')!.addEventListener('click', () => openSecurityEditor(setFooterStatus));
  document.getElementById('accountsBtn')!.addEventListener('click', () => void openAccountSwitcher());
}

type FooterStatus = (message: string, isError: boolean) => void;

/** Inline editor to change the master password or the KDF iteration count. Rendered into #footerStatus. */
function openSecurityEditor(setFooterStatus: FooterStatus): void {
  const host = document.getElementById('footerStatus');
  if (!host) return;
  host.innerHTML = `
    <div class="inline-form">
      <span class="muted">Change master password</span>
      <input id="secCurrent" class="input" type="password" autocomplete="current-password" placeholder="Current master password" />
      <input id="secNew" class="input" type="password" autocomplete="new-password" placeholder="New master password" />
      <input id="secConfirm" class="input" type="password" autocomplete="new-password" placeholder="Confirm new password" />
      <button id="secSave" class="btn btn-sm btn-block" type="button">${icon('check')}<span>Change password</span></button>
      <span class="muted">Or change KDF iterations (PBKDF2)</span>
      <input id="secIters" class="input" type="number" min="600000" step="100000" placeholder="KDF iterations (e.g. 600000)" />
      <button id="secKdf" class="btn btn-secondary btn-sm btn-block" type="button">${icon('refresh')}<span>Change KDF iterations</span></button>
    </div>`;
  document.getElementById('secSave')!.addEventListener('click', () => void (async () => {
    if (isPending) return;
    const current = (document.getElementById('secCurrent') as HTMLInputElement).value;
    const next = (document.getElementById('secNew') as HTMLInputElement).value;
    const confirm = (document.getElementById('secConfirm') as HTMLInputElement).value;
    if (!current || !next) return setFooterStatus('Enter your current and new password', true);
    if (next.length < 8) return setFooterStatus('New master password must be at least 8 characters', true);
    if (next !== confirm) return setFooterStatus('New passwords do not match', true);
    isPending = true;
    try {
      const response = await sendRequest({ type: 'auth.changePassword', currentPassword: current, newPassword: next });
      setFooterStatus(response.ok ? 'Master password changed.' : response.error.message, !response.ok);
    } finally {
      isPending = false;
    }
  })());
  document.getElementById('secKdf')!.addEventListener('click', () => void (async () => {
    if (isPending) return;
    const current = (document.getElementById('secCurrent') as HTMLInputElement).value;
    const iterations = Number((document.getElementById('secIters') as HTMLInputElement).value);
    if (!current) return setFooterStatus('Enter your current master password', true);
    if (!Number.isFinite(iterations) || iterations < 600_000) return setFooterStatus('Use at least 600000 iterations', true);
    isPending = true;
    try {
      const response = await sendRequest({ type: 'auth.changeKdf', currentPassword: current, iterations });
      setFooterStatus(response.ok ? `KDF iterations changed to ${iterations}.` : response.error.message, !response.ok);
    } finally {
      isPending = false;
    }
  })());
  (document.getElementById('secCurrent') as HTMLInputElement).focus();
}

/** Inline export panel: choose a password-protected (encrypted) export, or an explicit plaintext one. */
function openExportPanel(setFooterStatus: FooterStatus): void {
  const host = document.getElementById('footerStatus');
  if (!host) return;
  host.innerHTML = `
    <div class="inline-form">
      <input id="exportPwd" class="input" type="password" autocomplete="new-password" placeholder="Password for encrypted export" />
      <button id="exportEnc" class="btn btn-sm btn-block" type="button">${icon('lock')}<span>Export encrypted</span></button>
      <button id="exportPlain" class="btn btn-danger btn-sm btn-block" type="button">${icon('alert')}<span>Export plaintext (unencrypted)</span></button>
    </div>`;
  const pwd = document.getElementById('exportPwd') as HTMLInputElement;
  document.getElementById('exportEnc')!.addEventListener('click', () => {
    if (!pwd.value) return setFooterStatus('Enter a password, or use plaintext export', true);
    void doExport(setFooterStatus, pwd.value);
  });
  document.getElementById('exportPlain')!.addEventListener('click', () => void doExport(setFooterStatus));
  pwd.focus();
}

async function doExport(setFooterStatus: FooterStatus, password?: string): Promise<void> {
  if (isPending) return;
  isPending = true;
  try {
    const response = await sendRequest(password ? { type: 'vault.export', password } : { type: 'vault.export' });
    if (!response.ok) return setFooterStatus(response.error.message, true);
    const json = (response.data as { json: string }).json;
    const stamp = new Date().toISOString().slice(0, 10);
    downloadTextFile(json, `vaultwarden-export-${password ? 'encrypted-' : ''}${stamp}.json`);
    setFooterStatus(password ? 'Exported an encrypted vault backup.' : 'Exported decrypted vault. Store the file securely.', false);
  } finally {
    isPending = false;
  }
}

/** Prompt for an encrypted-export password before importing it. */
function promptImportPassword(setFooterStatus: FooterStatus, onSubmit: (password: string) => void): void {
  const host = document.getElementById('footerStatus');
  if (!host) return;
  host.innerHTML = `
    <div class="inline-form">
      <span class="muted">This export is password-protected.</span>
      <input id="importPwd" class="input" type="password" autocomplete="off" placeholder="Export password" />
      <button id="importGo" class="btn btn-sm btn-block" type="button">${icon('unlock')}<span>Import</span></button>
    </div>`;
  const pwd = document.getElementById('importPwd') as HTMLInputElement;
  const go = (): void => { if (pwd.value) onSubmit(pwd.value); else setFooterStatus('Enter the export password', true); };
  document.getElementById('importGo')!.addEventListener('click', go);
  pwd.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); go(); } });
  pwd.focus();
}

async function doImport(content: string, setFooterStatus: FooterStatus, password?: string): Promise<void> {
  if (isPending) return;
  isPending = true;
  try {
    const response = await sendRequest(password ? { type: 'vault.import', content, password } : { type: 'vault.import', content });
    if (!response.ok) return setFooterStatus(response.error.message, true);
    const imported = (response.data as { imported: number }).imported;
    await loadCachedList();
    setFooterStatus(`Imported ${imported} item${imported === 1 ? '' : 's'}.`, false);
  } finally {
    isPending = false;
  }
}

/** Account switcher: list logged-in accounts, switch/remove, or add another. Rendered into #footerStatus. */
async function openAccountSwitcher(): Promise<void> {
  const host = document.getElementById('footerStatus');
  if (!host) return;
  const response = await sendRequest({ type: 'auth.listAccounts' });
  if (!response.ok) return;
  const accounts = (response.data as { accounts: Array<{ email: string; active: boolean }> }).accounts;
  const rows = accounts.map((a) => `
    <div class="account-row">
      <span class="account-email">${a.active ? icon('checkCircle') : icon('user')}<span>${escapeHtml(a.email)}</span></span>
      ${a.active ? '' : `<button class="link-btn" data-switch="${escapeHtml(a.email)}" type="button">Switch</button>`}
      <button class="link-btn account-remove" data-remove="${escapeHtml(a.email)}" type="button">Remove</button>
    </div>`).join('');
  host.innerHTML = `<div class="account-list">${rows}
    <button id="accountAdd" class="btn btn-secondary btn-sm btn-block" type="button">${icon('plus')}<span>Add account</span></button></div>`;
  document.getElementById('accountAdd')!.addEventListener('click', () => render({ kind: 'loggedOut' }));
  for (const btn of host.querySelectorAll<HTMLButtonElement>('button[data-switch]')) {
    btn.addEventListener('click', async () => {
      const r = await sendRequest({ type: 'auth.switchAccount', email: btn.dataset.switch! });
      if (r.ok) render({ kind: 'locked' });
    });
  }
  for (const btn of host.querySelectorAll<HTMLButtonElement>('button[data-remove]')) {
    btn.addEventListener('click', async () => {
      const r = await sendRequest({ type: 'auth.removeAccount', email: btn.dataset.remove! });
      if (!r.ok) return;
      const state = await sendRequest({ type: 'auth.getState' });
      if (state.ok) {
        vaultItems = []; vaultFolders = []; vaultCollections = []; selectedFolderId = null; selectedCollectionId = null;
        render({ kind: (state.data as { state: 'loggedOut' | 'locked' | 'unlocked' }).state });
      }
    });
  }
}

/** Manage the PIN unlock: set a new PIN, or remove an existing one. Rendered into #footerStatus. */
async function openPinEditor(setFooterStatus: (m: string, e: boolean) => void): Promise<void> {
  const host = document.getElementById('footerStatus');
  if (!host) return;
  const status = await sendRequest({ type: 'auth.pinStatus' });
  const enabled = status.ok && (status.data as { enabled: boolean }).enabled;
  if (enabled) {
    host.innerHTML = `<div class="confirm-row">
      <span class="muted">PIN unlock is on.</span>
      <button id="pinRemove" class="btn btn-danger btn-sm" type="button">Remove PIN</button>
      <button id="pinCancel" class="btn btn-secondary btn-sm" type="button">Cancel</button></div>`;
    document.getElementById('pinCancel')!.addEventListener('click', () => { host.innerHTML = ''; });
    document.getElementById('pinRemove')!.addEventListener('click', async () => {
      const response = await sendRequest({ type: 'auth.disablePin' });
      setFooterStatus(response.ok ? 'PIN unlock removed.' : (response as { error: { message: string } }).error.message, !response.ok);
    });
    return;
  }
  host.innerHTML = `<div class="confirm-row">
    <input id="pinInput" class="input" inputmode="numeric" autocomplete="off" placeholder="New PIN (4+ digits)" />
    <button id="pinSave" class="btn btn-sm" type="button">Set PIN</button>
    <button id="pinCancel" class="btn btn-secondary btn-sm" type="button">Cancel</button></div>`;
  const input = document.getElementById('pinInput') as HTMLInputElement;
  input.focus();
  document.getElementById('pinCancel')!.addEventListener('click', () => { host.innerHTML = ''; });
  const save = async () => {
    const pin = input.value.trim();
    if (pin.length < 4) return setFooterStatus('PIN must be at least 4 digits', true);
    const response = await sendRequest({ type: 'auth.setPin', pin });
    setFooterStatus(response.ok ? 'PIN unlock enabled.' : (response as { error: { message: string } }).error.message, !response.ok);
  };
  document.getElementById('pinSave')!.addEventListener('click', () => void save());
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); void save(); } });
}

/** Trigger a client-side download of a text file (used for vault export). */
function downloadTextFile(content: string, filename: string): void {
  const blob = new Blob([content], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Password options block markup for the generator panel. */
function passwordGenOptionsHtml(): string {
  return `
    <div class="gen-options">
      <label class="gen-row"><span>Length</span><input id="genLength" class="input" type="number" min="4" max="128" value="${genOptions.length}" /></label>
      <label class="gen-check"><input id="genLower" type="checkbox" ${genOptions.lowercase ? 'checked' : ''} /><span>Lowercase (a-z)</span></label>
      <label class="gen-check"><input id="genUpper" type="checkbox" ${genOptions.uppercase ? 'checked' : ''} /><span>Uppercase (A-Z)</span></label>
      <label class="gen-check"><input id="genNumbers" type="checkbox" ${genOptions.numbers ? 'checked' : ''} /><span>Numbers (0-9)</span></label>
      <label class="gen-check"><input id="genSpecial" type="checkbox" ${genOptions.special ? 'checked' : ''} /><span>Special (!@#$%^&amp;*)</span></label>
      <label class="gen-check"><input id="genAmbiguous" type="checkbox" ${genOptions.avoidAmbiguous ? 'checked' : ''} /><span>Avoid ambiguous (Il1O0)</span></label>
    </div>`;
}

/** Passphrase options block markup for the generator panel. */
function passphraseGenOptionsHtml(): string {
  const o = genPassphraseOptions;
  return `
    <div class="gen-options">
      <label class="gen-row"><span>Words</span><input id="genWords" class="input" type="number" min="3" max="20" value="${o.numWords}" /></label>
      <label class="gen-row"><span>Separator</span><input id="genSep" class="input" maxlength="3" value="${escapeHtml(o.separator)}" /></label>
      <label class="gen-check"><input id="genCap" type="checkbox" ${o.capitalize ? 'checked' : ''} /><span>Capitalize</span></label>
      <label class="gen-check"><input id="genNum" type="checkbox" ${o.includeNumber ? 'checked' : ''} /><span>Include number</span></label>
    </div>`;
}

/** Standalone password/passphrase generator panel — runs locally; no vault secret involved. */
function renderGenerator(): void {
  clearTotpTimer();
  const isPass = genMode === 'passphrase';
  app.innerHTML = `
    <div class="detail">
      <div class="detail-head">
        <button id="back" class="icon-btn" type="button" title="Back" aria-label="Back">${icon('back')}</button>
        <div class="titles"><h1>Generator</h1></div>
      </div>
      <div class="detail-body">
        <div class="seg" role="tablist">
          <button id="modePassword" type="button" class="seg-btn${isPass ? '' : ' is-active'}" role="tab" aria-selected="${!isPass}">Password</button>
          <button id="modePassphrase" type="button" class="seg-btn${isPass ? ' is-active' : ''}" role="tab" aria-selected="${isPass}">Passphrase</button>
        </div>
        <div class="readout">
          <div class="k">${icon('key')} Generated ${isPass ? 'passphrase' : 'password'}</div>
          <div class="v-row">
            <code id="genOut" class="v mono"></code>
            <button id="genRegen" class="icon-btn" type="button" title="Regenerate" aria-label="Regenerate">${icon('refresh')}</button>
          </div>
        </div>
        ${isPass ? passphraseGenOptionsHtml() : passwordGenOptionsHtml()}
        <div class="detail-actions">
          <button id="genCopy" type="button" class="btn btn-block">${icon('copy')}<span>Copy</span></button>
        </div>
        <div id="genHistory"></div>
        <div id="detailStatus" class="detail-status"></div>
      </div>
    </div>`;
  document.getElementById('back')!.addEventListener('click', () => render({ kind: 'unlocked' }));
  document.getElementById('modePassword')!.addEventListener('click', () => { genMode = 'password'; renderGenerator(); });
  document.getElementById('modePassphrase')!.addEventListener('click', () => { genMode = 'passphrase'; renderGenerator(); });

  const out = document.getElementById('genOut')!;
  let current = '';
  const readOptions = (): void => {
    if (isPass) {
      const numWords = Number((document.getElementById('genWords') as HTMLInputElement).value);
      genPassphraseOptions = {
        numWords: Number.isFinite(numWords) ? Math.min(Math.max(Math.trunc(numWords), 3), 20) : genPassphraseOptions.numWords,
        separator: (document.getElementById('genSep') as HTMLInputElement).value || '-',
        capitalize: (document.getElementById('genCap') as HTMLInputElement).checked,
        includeNumber: (document.getElementById('genNum') as HTMLInputElement).checked,
      };
      return;
    }
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
  // Update the displayed value (on option changes) without touching history.
  const regenerate = (): void => {
    readOptions();
    current = isPass ? generatePassphrase(genPassphraseOptions) : generatePassword(genOptions);
    out.textContent = current || 'Enable at least one character set';
  };
  // Generate a fresh value AND record the previous one in history (explicit Regenerate / open).
  const regenerateAndRecord = (): void => {
    if (current) genHistory = addPasswordToHistory(genHistory, current);
    regenerate();
    renderGenHistory();
  };
  const optionIds = isPass
    ? ['genWords', 'genSep', 'genCap', 'genNum']
    : ['genLength', 'genLower', 'genUpper', 'genNumbers', 'genSpecial', 'genAmbiguous'];
  for (const id of optionIds) {
    document.getElementById(id)!.addEventListener('input', regenerate);
  }
  document.getElementById('genRegen')!.addEventListener('click', regenerateAndRecord);
  document.getElementById('genCopy')!.addEventListener('click', () => void withDetailBusy(async () => {
    if (current) {
      genHistory = addPasswordToHistory(genHistory, current);
      renderGenHistory();
    }
    await copyValue(current, isPass ? 'Passphrase' : 'Password');
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

/** Password health report: weak and reused login passwords. Secrets stay in the worker. */
async function renderHealthReport(): Promise<void> {
  clearTotpTimer();
  app.innerHTML = `
    <div class="detail">
      <div class="detail-head">
        <button id="back" class="icon-btn" type="button" title="Back" aria-label="Back">${icon('back')}</button>
        <div class="titles"><h1>Password health</h1></div>
      </div>
      <div class="detail-body"><div id="healthBody"><div class="muted center">Checking…</div></div></div>
    </div>`;
  document.getElementById('back')!.addEventListener('click', () => render({ kind: 'unlocked' }));
  const body = document.getElementById('healthBody')!;
  const response = await sendRequest({ type: 'vault.getPasswordHealth' });
  if (!response.ok) {
    body.innerHTML = `<p class="note error">${icon('alert')}<span>${escapeHtml(response.error.message)}</span></p>`;
    return;
  }
  const entries = (response.data as { entries: Array<{ id: string; name: string; weak: boolean; reuseCount: number }> }).entries;
  if (entries.length === 0) {
    body.innerHTML = `<div class="empty"><span class="glyph">${icon('checkCircle')}</span><span>No weak or reused passwords found.</span></div>`;
    return;
  }
  body.innerHTML = entries.map((e) => {
    const tags = [
      e.weak ? '<span class="tag tag-warn">Weak</span>' : '',
      e.reuseCount > 1 ? `<span class="tag tag-warn">Reused &times;${e.reuseCount}</span>` : '',
    ].join(' ');
    return `<button class="item" type="button" data-id="${escapeHtml(e.id)}">
      <span class="monogram" style="--mono-h:${hueFor(e.name)}">${escapeHtml(monogramLetter(e.name))}</span>
      <span class="item-body"><span class="item-name"><span class="title">${escapeHtml(e.name)}</span></span><span class="item-sub">${tags}</span></span>
      <span class="chevron">${icon('chevron')}</span>
    </button>`;
  }).join('');
  for (const row of body.querySelectorAll<HTMLElement>('.item')) {
    row.addEventListener('click', () => renderDetail(row.dataset.id!));
  }
}

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

/** One URI input row for the login editor. The per-URI match strategy rides along in data-match so a
 *  save preserves it (the editor doesn't expose a match picker), and extra URIs are no longer dropped. */
function uriEditorRow(uri: string, match?: number | null): string {
  const matchAttr = match != null ? ` data-match="${escapeHtml(String(match))}"` : '';
  return `<input class="input mono ed-uri-input" value="${escapeHtml(uri)}" placeholder="https://example.com"${matchAttr} />`;
}

const CF_EDITOR_TYPES: ReadonlyArray<readonly [CustomFieldType, string]> = [[0, 'Text'], [1, 'Hidden'], [2, 'Boolean']];

/** One custom-field editor row. Linked fields (type 3) are read-only so a round-trip never drops them. */
function customFieldEditorRow(f?: DecryptedField): string {
  const type = f?.type ?? 0;
  const name = escapeHtml(f?.name ?? '');
  if (type === 3) {
    return `<div class="ed-cfield" data-cf-type="3" data-cf-linked="${escapeHtml(String(f?.linkedId ?? ''))}">
      <input class="input ed-cf-name" value="${name}" readonly />
      <span class="ed-cf-linked muted">${escapeHtml(linkedLabel(f?.linkedId))}</span>
      <button class="icon-btn ed-cf-remove" type="button" title="Remove field" aria-label="Remove field">${icon('trash')}</button>
    </div>`;
  }
  const opts = CF_EDITOR_TYPES.map(([t, l]) => `<option value="${t}"${t === type ? ' selected' : ''}>${l}</option>`).join('');
  const valueControl = type === 2
    ? `<label class="ed-cf-bool"><input class="ed-cf-value" type="checkbox"${f?.value === 'true' ? ' checked' : ''} /></label>`
    : `<input class="input ed-cf-value" type="${type === 1 ? 'password' : 'text'}" value="${escapeHtml(f?.value ?? '')}" placeholder="Value" />`;
  return `<div class="ed-cfield" data-cf-type="${type}">
    <select class="select ed-cf-typesel" aria-label="Field type">${opts}</select>
    <input class="input ed-cf-name" value="${name}" placeholder="Name" />
    ${valueControl}
    <button class="icon-btn ed-cf-remove" type="button" title="Remove field" aria-label="Remove field">${icon('trash')}</button>
  </div>`;
}

/** Wire the custom-field editor: add button, plus per-row remove and type switching. */
function bindCustomFieldEditor(): void {
  const list = document.getElementById('ed_fields');
  const add = document.getElementById('ed_addField');
  if (!list || !add) return;
  add.addEventListener('click', () => {
    list.insertAdjacentHTML('beforeend', customFieldEditorRow());
    bindCustomFieldRow(list.lastElementChild as HTMLElement);
  });
  list.querySelectorAll<HTMLElement>('.ed-cfield').forEach((row) => bindCustomFieldRow(row));
}

function bindCustomFieldRow(row: HTMLElement): void {
  row.querySelector('.ed-cf-remove')?.addEventListener('click', () => row.remove());
  const typeSel = row.querySelector<HTMLSelectElement>('.ed-cf-typesel');
  typeSel?.addEventListener('change', () => {
    const name = (row.querySelector('.ed-cf-name') as HTMLInputElement).value;
    const tmp = document.createElement('div');
    tmp.innerHTML = customFieldEditorRow({ type: Number(typeSel.value) as CustomFieldType, name });
    const next = tmp.firstElementChild as HTMLElement;
    row.replaceWith(next);
    bindCustomFieldRow(next); // switching type drops the old value control, so re-wire
  });
}

/** Collect editor custom fields. Nameless Text/Hidden/Boolean rows are dropped; Linked rows preserved. */
function collectEditorFields(): DecryptedField[] {
  const out: DecryptedField[] = [];
  for (const row of document.querySelectorAll<HTMLElement>('#ed_fields .ed-cfield')) {
    const type = Number(row.dataset.cfType) as CustomFieldType;
    const name = (row.querySelector('.ed-cf-name') as HTMLInputElement).value.trim();
    if (type === 3) {
      const field: DecryptedField = { type, name };
      const linkedId = row.dataset.cfLinked ? Number(row.dataset.cfLinked) : NaN;
      if (!Number.isNaN(linkedId)) field.linkedId = linkedId;
      out.push(field);
      continue;
    }
    if (!name) continue; // a Text/Hidden/Boolean field needs a name to be meaningful
    const valueEl = row.querySelector<HTMLInputElement>('.ed-cf-value');
    const value = type === 2 ? (valueEl?.checked ? 'true' : 'false') : (valueEl?.value ?? '');
    const field: DecryptedField = { type, name };
    if (value) field.value = value;
    out.push(field);
  }
  return out;
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
      <label class="ed-field"><span class="ed-label">Websites (URIs)</span>
        <div id="ed_uris" class="ed-uris">
          ${(login.uris?.length ? login.uris : [{ uri: '' }]).map((u) => uriEditorRow(u.uri, u.match)).join('')}
        </div>
        <button id="ed_addUri" class="btn btn-secondary btn-sm" type="button">${icon('plus')}<span>Add URI</span></button>
      </label>`;
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
        <label class="gen-check"><input id="ed_reprompt" type="checkbox" ${v.reprompt ? 'checked' : ''} /><span>Require master password to view</span></label>
        <div class="ed-field"><span class="ed-label">Custom fields</span>
          <div id="ed_fields" class="ed-cfields">${(v.fields ?? []).map((f) => customFieldEditorRow(f)).join('')}</div>
          <button id="ed_addField" class="btn btn-secondary btn-sm" type="button">${icon('plus')}<span>Add field</span></button>
        </div>
        ${mode === 'edit' && id ? `<label class="ed-field"><span class="ed-label">Add attachment</span>
          <div class="ed-attach"><input id="ed_attachFile" type="file" class="input" />
          <button id="ed_attachAdd" class="btn btn-secondary btn-sm" type="button">${icon('plus')}<span>Upload</span></button></div></label>` : ''}
        <div class="detail-actions">
          <button id="ed_save" type="button" class="btn btn-block">${icon('check')}<span>Save</span></button>
          ${mode === 'edit' && id && canMoveToOrg(id) ? `<button id="ed_move" type="button" class="btn btn-secondary btn-block">${icon('folder')}<span>Move to organization</span></button>` : ''}
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
    document.getElementById('ed_addUri')!.addEventListener('click', () => {
      document.getElementById('ed_uris')!.insertAdjacentHTML('beforeend', uriEditorRow(''));
    });
  }
  bindCustomFieldEditor();
  document.getElementById('ed_save')!.addEventListener('click', () => void saveEditor(mode, type, id));
  if (mode === 'edit' && id) {
    document.getElementById('ed_delete')!.addEventListener('click', () => confirmDeleteCipher(id, v.name));
    document.getElementById('ed_move')?.addEventListener('click', () => renderMoveToOrg(id, v.name));
    document.getElementById('ed_attachAdd')?.addEventListener('click', () => void uploadAttachmentFromEditor(id));
  }
}

/** Read the chosen file, encrypt+upload it as an attachment on the cipher being edited, then report. */
async function uploadAttachmentFromEditor(id: string): Promise<void> {
  if (isPending) return;
  const fileInput = document.getElementById('ed_attachFile') as HTMLInputElement | null;
  const file = fileInput?.files?.[0];
  if (!file) return setDetailStatus('Choose a file to upload', true);
  isPending = true;
  document.querySelectorAll<HTMLButtonElement>('.detail button').forEach((b) => (b.disabled = true));
  try {
    const dataB64 = await fileToBase64(file);
    const response = await sendRequest({ type: 'vault.addAttachment', cipherId: id, fileName: file.name, dataB64, ...mpArg(id) });
    if (!response.ok) return setDetailStatus(response.error.message, true);
    fileInput!.value = '';
    setDetailStatus(`Uploaded ${file.name}`, false);
  } finally {
    isPending = false;
    document.querySelectorAll<HTMLButtonElement>('.detail button').forEach((b) => (b.disabled = false));
  }
}

/** Read a File into base64 (the worker re-encrypts it under a fresh attachment key). */
async function fileToBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

/** A personal (non-org) item can be moved into an organization when collections are available. */
function canMoveToOrg(id: string): boolean {
  const item = vaultItems.find((i) => i.id === id);
  return Boolean(item && !item.organizationId && vaultCollections.length > 0);
}

/** Screen to move a personal cipher into an organization by selecting one or more collections. */
function renderMoveToOrg(id: string, name: string): void {
  clearTotpTimer();
  const collections = vaultCollections;
  app.innerHTML = `
    <div class="detail">
      <div class="detail-head">
        <button id="back" class="icon-btn" type="button" title="Back" aria-label="Back">${icon('back')}</button>
        <div class="titles"><h1>Move to organization</h1></div>
      </div>
      <div class="detail-body">
        <p class="muted">Choose the collection(s) to move “${escapeHtml(name)}” into. All selected collections must belong to the same organization.</p>
        ${collections.length
          ? `<div class="ed-cfields">${collections.map((c) => `<label class="gen-check"><input type="checkbox" class="move-col" value="${escapeHtml(c.id)}" data-org="${escapeHtml(c.organizationId)}" /><span>${escapeHtml(c.name)}</span></label>`).join('')}</div>`
          : `<div class="muted center">No organization collections available</div>`}
        <div class="detail-actions">
          <button id="moveConfirm" type="button" class="btn btn-block"${collections.length ? '' : ' disabled'}>${icon('check')}<span>Move</span></button>
        </div>
        <div id="detailStatus" class="detail-status"></div>
      </div>
    </div>`;
  document.getElementById('back')!.addEventListener('click', () => void openEditorForEdit(id));
  document.getElementById('moveConfirm')?.addEventListener('click', () => void withDetailBusy(async () => {
    const checked = [...document.querySelectorAll<HTMLInputElement>('.move-col:checked')];
    if (!checked.length) return setDetailStatus('Select at least one collection', true);
    if (new Set(checked.map((c) => c.dataset.org)).size > 1) {
      return setDetailStatus('All collections must be in the same organization', true);
    }
    const organizationId = checked[0]!.dataset.org!;
    const collectionIds = checked.map((c) => c.value);
    const response = await sendRequest({ type: 'vault.shareCipher', id, organizationId, collectionIds, ...mpArg(id) });
    if (!response.ok) return setDetailStatus(response.error.message, true);
    render({ kind: 'unlocked' });
  }));
}

function collectEditorInput(type: 1 | 2 | 3 | 4): CipherInput {
  const val = (elId: string): string => (document.getElementById(elId) as HTMLInputElement | HTMLTextAreaElement | null)?.value ?? '';
  const input: CipherInput = {
    type,
    name: val('ed_name').trim(),
    favorite: (document.getElementById('ed_favorite') as HTMLInputElement).checked,
    reprompt: (document.getElementById('ed_reprompt') as HTMLInputElement).checked,
    folderId: val('ed_folder') || null,
  };
  const notes = val('ed_notes'); if (notes) input.notes = notes;
  if (type === 1) {
    const login: NonNullable<CipherInput['login']> = {};
    const u = val('ed_username'); if (u) login.username = u;
    const p = val('ed_password'); if (p) login.password = p;
    const t = val('ed_totp'); if (t) login.totp = t;
    const uris: NonNullable<NonNullable<CipherInput['login']>['uris']> = [];
    for (const el of document.querySelectorAll<HTMLInputElement>('#ed_uris .ed-uri-input')) {
      const uri = el.value.trim();
      if (!uri) continue;
      const m = el.dataset.match;
      uris.push(m !== undefined && m !== '' ? { uri, match: Number(m) } : { uri });
    }
    if (uris.length) login.uris = uris;
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
  input.fields = collectEditorFields(); // always present so removing all fields clears them server-side
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
  // A protected item must clear the master-password gate before the editor can reveal its secrets.
  const item = vaultItems.find((i) => i.id === id);
  if (item?.reprompt && repromptForId !== id) {
    return renderRepromptGate(item, () => void openEditorForEdit(id));
  }
  const response = await sendRequest({ type: 'vault.getCipherInput', id, ...mpArg(id) });
  if (!response.ok) return setDetailStatus(response.error.message, true);
  const input = (response.data as { input: CipherInput | null }).input;
  if (!input) return setDetailStatus('This item type cannot be edited yet', true);
  renderEditor('edit', input.type, input, id);
}

/** Inline two-step delete confirmation. Soft-deletes (to trash) by default; permanent=true hard-deletes. */
function confirmDeleteCipher(id: string, name: string, permanent = false): void {
  const status = document.getElementById('detailStatus');
  if (!status) return;
  const prompt = permanent ? `Delete “${escapeHtml(name)}” forever? This cannot be undone.` : `Move “${escapeHtml(name)}” to trash?`;
  const label = permanent ? 'Delete forever' : 'Move to trash';
  status.innerHTML = `<div class="confirm-row">
    <span class="muted">${prompt}</span>
    <button id="ed_confirmDel" class="btn btn-danger btn-sm" type="button">${label}</button>
    <button id="ed_cancelDel" class="btn btn-secondary btn-sm" type="button">Cancel</button>
  </div>`;
  document.getElementById('ed_cancelDel')!.addEventListener('click', () => { status.innerHTML = ''; });
  document.getElementById('ed_confirmDel')!.addEventListener('click', async () => {
    if (isPending) return;
    isPending = true;
    status.querySelectorAll('button').forEach((b) => (b.disabled = true));
    try {
      const response = await sendRequest(permanent ? { type: 'vault.deleteCipher', id } : { type: 'vault.softDeleteCipher', id });
      if (!response.ok) return setDetailStatus(response.error.message, true);
      render({ kind: 'unlocked' });
    } finally {
      isPending = false;
    }
  });
}

/** Restore a soft-deleted cipher from the trash, then return to the list. */
async function restoreCipherAction(id: string): Promise<void> {
  if (isPending) return;
  isPending = true;
  try {
    const response = await sendRequest({ type: 'vault.restoreCipher', id });
    if (!response.ok) return setDetailStatus(response.error.message, true);
    render({ kind: 'unlocked' });
  } finally {
    isPending = false;
  }
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
  const trashToggle = document.getElementById('trashToggle');
  const trashedCount = vaultItems.filter((i) => i.deletedDate).length;
  if (trashToggle) {
    trashToggle.classList.toggle('active', showTrash);
    trashToggle.setAttribute('title', showTrash ? 'Exit trash' : `Trash${trashedCount ? ` (${trashedCount})` : ''}`);
  }
  const query = (document.getElementById('search') as HTMLInputElement | null)?.value ?? '';
  // The trash view shows only soft-deleted items; the main list excludes them.
  const scope = vaultItems.filter((item) => (showTrash ? Boolean(item.deletedDate) : !item.deletedDate));
  const filtered = filterSummariesByFolderCollectionAndQuery(scope, selectedFolderId, selectedCollectionId, query);
  if (filtered.length === 0) {
    const isSearch = query.trim().length > 0;
    const message = showTrash
      ? (isSearch ? 'No trashed items match your search.' : 'Trash is empty.')
      : (isSearch ? 'No items match your search.' : 'Your vault is empty. Sync to load items.');
    list.innerHTML = `
      <div class="empty">
        <span class="glyph">${icon(isSearch ? 'search' : (showTrash ? 'trash' : 'shield'))}</span>
        <span>${message}</span>
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

/** Spread the retained reprompt master password for `id` into a request, or nothing when none is held. */
function mpArg(id: string): { masterPassword: string } | Record<string, never> {
  return repromptForId === id && repromptMp ? { masterPassword: repromptMp } : {};
}

function renderDetail(id: string) {
  clearTotpTimer();
  const item = vaultItems.find((i) => i.id === id);
  if (!item) return;
  // Master-password reprompt gate: protected items require re-verification before any view that can
  // reveal/copy their secrets. The worker also enforces this, so this gate is the UX, not the boundary.
  if (item.reprompt && repromptForId !== id) {
    return renderRepromptGate(item, () => renderDetail(id));
  }
  if (item.type === 2) return renderSecureNoteDetail(id, item);
  if (item.type === 3) return renderStructuredDetail(id, item, 'card');
  if (item.type === 4) return renderStructuredDetail(id, item, 'identity');
  return renderLoginDetail(id, item);
}

/**
 * Render a master-password gate for a reprompt-protected item. On success the verified password is
 * held in popup memory for this item's view (see repromptMp) and `onPass` re-renders the real view.
 */
function renderRepromptGate(item: CipherSummary, onPass: () => void): void {
  clearTotpTimer();
  app.innerHTML = `
    <div class="detail">
      <div class="detail-head">
        <button id="back" class="icon-btn" type="button" title="Back" aria-label="Back">${icon('back')}</button>
        <div class="titles"><h1>${escapeHtml(item.name)}</h1></div>
      </div>
      <div class="detail-body">
        <div class="readout">
          <div class="k">${icon('lock')} Protected item</div>
          <div class="v-row"><span class="v">Re-enter your master password to view this item.</span></div>
        </div>
        <label class="ed-field"><span class="ed-label">Master password</span>
          <input id="rp_pw" class="input" type="password" autocomplete="off" /></label>
        <div class="detail-actions">
          <button id="rp_go" type="button" class="btn btn-block">${icon('unlock')}<span>Unlock item</span></button>
        </div>
        <div id="detailStatus" class="detail-status"></div>
      </div>
    </div>`;
  document.getElementById('back')!.addEventListener('click', () => render({ kind: 'unlocked' }));
  const pwInput = document.getElementById('rp_pw') as HTMLInputElement;
  const submit = async (): Promise<void> => {
    if (isPending) return;
    const pw = pwInput.value;
    if (!pw) return;
    await withDetailBusy(async () => {
      const response = await sendRequest({ type: 'auth.verifyMasterPassword', masterPassword: pw });
      if (!response.ok) return setDetailStatus(response.error.message, true);
      if (!(response.data as { verified: boolean }).verified) {
        return setDetailStatus('Incorrect master password', true);
      }
      repromptMp = pw;
      repromptForId = item.id;
      onPass();
    });
  };
  document.getElementById('rp_go')!.addEventListener('click', () => void submit());
  pwInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); void submit(); } });
  pwInput.focus();
}

/** Standard detail header (back button + title + optional subtitle + edit/delete actions). */
function detailHead(item: CipherSummary): string {
  const trashed = Boolean(item.deletedDate);
  const editable = !item.undecryptable && item.type !== 5 && !trashed;
  const actions = trashed
    ? `<div class="detail-head-actions">
        <button id="detailRestore" class="icon-btn" type="button" title="Restore" aria-label="Restore">${icon('refresh')}</button>
        <button id="detailDelete" class="icon-btn" type="button" title="Delete forever" aria-label="Delete forever">${icon('trash')}</button>
      </div>`
    : editable
    ? `<div class="detail-head-actions">
        <button id="detailEdit" class="icon-btn" type="button" title="Edit" aria-label="Edit">${icon('edit')}</button>
        <button id="detailDelete" class="icon-btn" type="button" title="Delete" aria-label="Delete">${icon('trash')}</button>
      </div>`
    : '';
  return `
    <div class="detail-head">
      <button id="back" class="icon-btn" type="button" title="Back" aria-label="Back">${icon('back')}</button>
      <div class="titles">
        <h1>${escapeHtml(item.name)}</h1>
        ${item.username ? `<span class="sub">${escapeHtml(item.username)}</span>` : ''}
      </div>
      ${actions}
    </div>`;
}

function bindBack(): void {
  document.getElementById('back')!.addEventListener('click', () => render({ kind: 'unlocked' }));
}

/** Wire the edit/delete (or restore/delete-forever, for trashed items) actions in a detail header. */
function bindDetailActions(item: CipherSummary): void {
  if (item.deletedDate) {
    document.getElementById('detailRestore')?.addEventListener('click', () => void restoreCipherAction(item.id));
    document.getElementById('detailDelete')?.addEventListener('click', () => confirmDeleteCipher(item.id, item.name, true));
    return;
  }
  document.getElementById('detailEdit')?.addEventListener('click', () => void openEditorForEdit(item.id));
  document.getElementById('detailDelete')?.addEventListener('click', () => confirmDeleteCipher(item.id, item.name, false));
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
  const response = await sendRequest({ type: 'vault.getField', id, field, ...mpArg(id) });
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
        ${item.hasPasskey ? `
        <div class="readout">
          <div class="k">${icon('shield')} Passkey</div>
          <div class="v-row"><span class="v">Passkey saved — sign in with it on this site.</span></div>
        </div>` : ''}
        ${item.passwordHistoryCount ? `
        <div class="readout">
          <div class="k">${icon('refresh')} Password history</div>
          <div class="v-row">
            <span class="v">${item.passwordHistoryCount} previous password${item.passwordHistoryCount > 1 ? 's' : ''}</span>
            <button id="viewHistory" class="icon-btn" type="button" aria-pressed="false" title="View history" aria-label="View password history">${icon('eye')}</button>
          </div>
          <div id="historyList"></div>
        </div>` : ''}
        <div id="customFields" class="custom-fields"></div>
        <div class="detail-actions">
          <button id="copyPassword" type="button" class="btn btn-block">${icon('copy')}<span>Copy password</span></button>
          <button id="copyUsername" type="button" class="btn btn-secondary btn-block">${icon('user')}<span>Copy username</span></button>
        </div>
        <div id="detailStatus" class="detail-status"></div>
      </div>
    </div>`;
  bindBack();
  bindDetailActions(item);
  void loadDetailExtras(id);
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
    const response = await sendRequest({ type: 'vault.getField', id, field: 'password', ...mpArg(id) });
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

  if (item.passwordHistoryCount) {
    let shown = false;
    document.getElementById('viewHistory')?.addEventListener('click', () => void withDetailBusy(async () => {
      const listEl = document.getElementById('historyList');
      const btn = document.getElementById('viewHistory') as HTMLButtonElement;
      if (!listEl) return;
      if (shown) {
        shown = false; listEl.innerHTML = '';
        btn.innerHTML = icon('eye'); btn.setAttribute('aria-pressed', 'false');
        return;
      }
      const response = await sendRequest({ type: 'vault.getPasswordHistory', id, ...mpArg(id) });
      if (!response.ok) return setDetailStatus(response.error.message, true);
      renderPasswordHistory(listEl, (response.data as { history: Array<{ password: string; lastUsedDate?: string }> }).history);
      shown = true;
      btn.innerHTML = icon('eyeOff'); btn.setAttribute('aria-pressed', 'true');
    }));
  }

  if (item.hasTotp) {
    let currentCode: string | undefined;
    document.getElementById('copyTotp')!.addEventListener('click', () => void withDetailBusy(() => copyValue(currentCode, 'Verification code')));
    const loadTotp = async (): Promise<void> => {
      const codeEl = document.getElementById('totpCode');
      const countdownEl = document.getElementById('totpCountdown');
      if (!codeEl || !countdownEl) return clearTotpTimer();
      const response = await sendRequest({ type: 'vault.getTotp', id, ...mpArg(id) });
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
        <div id="customFields" class="custom-fields"></div>
        <div class="detail-actions"><button id="copyNote" type="button" class="btn btn-block">${icon('copy')}<span>Copy note</span></button></div>
        <div id="detailStatus" class="detail-status"></div>
      </div>
    </div>`;
  bindBack();
  bindDetailActions(item);
  void loadDetailExtras(id);
  void (async () => {
    const response = await sendRequest({ type: 'vault.getField', id, field: 'notes', ...mpArg(id) });
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
        <div id="customFields" class="custom-fields"></div>
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
    // Custom fields + attachments ride along on the same detail fetch (no second round-trip).
    const extrasEl = document.getElementById('customFields');
    if (extrasEl) renderDetailExtras(id, extrasEl, cipher);
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
      const response = await sendRequest({ type: 'vault.getField', id, field, ...mpArg(id) });
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

/** Render decrypted password-history entries (most-recent first) with per-entry copy. */
function renderPasswordHistory(container: HTMLElement, history: Array<{ password: string; lastUsedDate?: string }>): void {
  if (!history.length) {
    container.innerHTML = `<div class="muted">No previous passwords</div>`;
    return;
  }
  container.innerHTML = history.map((h) => {
    const when = h.lastUsedDate ? new Date(h.lastUsedDate).toLocaleDateString() : '';
    return `<div class="hist-row">
      <code class="v mono">${escapeHtml(h.password)}</code>
      ${when ? `<span class="muted hist-when">${escapeHtml(when)}</span>` : ''}
      <button class="icon-btn" type="button" data-hist-copy="${escapeHtml(h.password)}" title="Copy" aria-label="Copy previous password">${icon('copy')}</button>
    </div>`;
  }).join('');
  container.querySelectorAll<HTMLButtonElement>('button[data-hist-copy]').forEach((btn) => {
    btn.addEventListener('click', () => void withDetailBusy(() => copyValue(btn.dataset.histCopy, 'Previous password')));
  });
}

/** Bitwarden LinkedId labels (login: 100 username, 101 password). */
function linkedLabel(linkedId?: number): string {
  if (linkedId === 100) return 'Linked → Username';
  if (linkedId === 101) return 'Linked → Password';
  return 'Linked field';
}

/** Fetch a cipher's detail (custom fields + attachments) and render the extras section. */
async function loadDetailExtras(id: string): Promise<void> {
  const container = document.getElementById('customFields');
  if (!container) return;
  const response = await sendRequest({ type: 'vault.getCipherDetail', id });
  if (!response.ok) return;
  const cipher = (response.data as { cipher: DecryptedCipher | null }).cipher;
  if (cipher) renderDetailExtras(id, container, cipher);
}

/** Render the custom-field + attachment sections into `container` and wire their handlers. */
function renderDetailExtras(id: string, container: HTMLElement, cipher: DecryptedCipher): void {
  const parts: string[] = [];
  if (cipher.fields?.length) parts.push(customFieldsHtml(cipher.fields));
  if (cipher.attachments?.length) parts.push(attachmentsHtml(cipher.attachments));
  container.innerHTML = parts.join('');
  if (cipher.fields?.length) bindCustomFieldHandlers(id, container);
  if (cipher.attachments?.length) bindAttachmentHandlers(id, container);
}

/** Custom-field readout rows: Text/Boolean/Linked inline, Hidden masked with reveal + copy. */
function customFieldsHtml(fields: DecryptedField[]): string {
  const rows = fields.map((f, index) => {
    const label = f.name || 'Field';
    if (f.type === 1) {
      return `<div class="readout"><div class="k">${escapeHtml(label)}</div>
        <div class="v-row"><code class="v mono" data-cf-secret="${index}">••••••••</code>
          <button class="icon-btn" type="button" data-cf-reveal="${index}" aria-pressed="false" title="Show ${escapeHtml(label)}" aria-label="Show ${escapeHtml(label)}">${icon('eye')}</button>
          <button class="icon-btn" type="button" data-cf-copy="${index}" data-label="${escapeHtml(label)}" title="Copy ${escapeHtml(label)}" aria-label="Copy ${escapeHtml(label)}">${icon('copy')}</button>
        </div></div>`;
    }
    const value = f.type === 2 ? (f.value === 'true' ? 'Yes' : 'No') : f.type === 3 ? linkedLabel(f.linkedId) : (f.value ?? '');
    return plainRow(label, value);
  });
  return `<div class="cf-head">Custom fields</div>${rows.join('')}`;
}

function bindCustomFieldHandlers(id: string, container: HTMLElement): void {
  // Inline copy for non-hidden fields (value already present in the data-copy attribute).
  container.querySelectorAll<HTMLButtonElement>('button[data-copy]').forEach((btn) => {
    btn.addEventListener('click', () => void withDetailBusy(() => copyValue(btn.dataset.copy, btn.dataset.label ?? 'Value')));
  });
  bindHiddenCustomFields(id, container);
}

/** Attachment rows: name + size with download and delete actions (fetched/decrypted on demand). */
function attachmentsHtml(attachments: NonNullable<DecryptedCipher['attachments']>): string {
  const rows = attachments.map((a) => `<div class="readout"><div class="k">${icon('note')} ${escapeHtml(a.fileName)}</div>
    <div class="v-row"><span class="v">${escapeHtml(a.sizeName ?? '')}</span>
      <button class="icon-btn" type="button" data-att-download="${escapeHtml(a.id)}" title="Download" aria-label="Download attachment">${icon('logout')}</button>
      <button class="icon-btn" type="button" data-att-delete="${escapeHtml(a.id)}" data-att-name="${escapeHtml(a.fileName)}" title="Delete" aria-label="Delete attachment">${icon('trash')}</button>
    </div></div>`).join('');
  return `<div class="cf-head">Attachments</div>${rows}`;
}

function bindAttachmentHandlers(id: string, container: HTMLElement): void {
  container.querySelectorAll<HTMLButtonElement>('button[data-att-download]').forEach((btn) => {
    btn.addEventListener('click', () => void withDetailBusy(async () => {
      const response = await sendRequest({ type: 'vault.getAttachment', cipherId: id, attachmentId: btn.dataset.attDownload!, ...mpArg(id) });
      if (!response.ok) return setDetailStatus(response.error.message, true);
      const { fileName, dataB64 } = response.data as { fileName: string; dataB64: string };
      downloadBase64File(dataB64, fileName);
      setDetailStatus(`Downloaded ${fileName}`, false);
    }));
  });
  container.querySelectorAll<HTMLButtonElement>('button[data-att-delete]').forEach((btn) => {
    btn.addEventListener('click', () => void withDetailBusy(async () => {
      const response = await sendRequest({ type: 'vault.deleteAttachment', cipherId: id, attachmentId: btn.dataset.attDelete! });
      if (!response.ok) return setDetailStatus(response.error.message, true);
      await loadCachedList();
      renderDetail(id); // refresh the detail (and its attachment list)
    }));
  });
}

/** Trigger a download of decrypted attachment bytes (base64 → Blob). */
function downloadBase64File(base64: string, fileName: string): void {
  const bin = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const url = URL.createObjectURL(new Blob([bytes]));
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Reveal/copy handlers for Hidden custom fields, fetched on demand by index (reprompt-aware). */
function bindHiddenCustomFields(id: string, container: HTMLElement): void {
  const revealed = new Map<number, string>();
  container.querySelectorAll<HTMLButtonElement>('button[data-cf-copy]').forEach((btn) => {
    const index = Number(btn.dataset.cfCopy);
    btn.addEventListener('click', () => void withDetailBusy(async () => {
      const response = await sendRequest({ type: 'vault.getCustomField', id, index, ...mpArg(id) });
      if (!response.ok) return setDetailStatus(response.error.message, true);
      await copyValue((response.data as { value?: string }).value, btn.dataset.label ?? 'Field');
    }));
  });
  container.querySelectorAll<HTMLButtonElement>('button[data-cf-reveal]').forEach((btn) => {
    const index = Number(btn.dataset.cfReveal);
    const codeEl = container.querySelector<HTMLElement>(`[data-cf-secret="${index}"]`)!;
    btn.addEventListener('click', () => void withDetailBusy(async () => {
      if (revealed.has(index)) {
        revealed.delete(index);
        codeEl.textContent = '••••••••';
        btn.innerHTML = icon('eye');
        btn.setAttribute('aria-pressed', 'false');
        return;
      }
      const response = await sendRequest({ type: 'vault.getCustomField', id, index, ...mpArg(id) });
      if (!response.ok) return setDetailStatus(response.error.message, true);
      const value = (response.data as { value?: string }).value;
      if (value === undefined) return setDetailStatus('Field is empty', true);
      revealed.set(index, value);
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
    } else if (currentViewKind === 'register') {
      render({ kind: 'register', error: response.error.message });
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
