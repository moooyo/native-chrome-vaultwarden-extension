import type { LitElement } from 'lit';
import { UriMatchStrategy } from '../../src/core/vault/uri-match.js';
import type { TabAutofillSuggestion } from '../../src/messaging/protocol.js';
import type {
  CipherSummary,
  CollectionSummary,
  DecryptedCipher,
  FolderSummary,
} from '../../src/core/vault/models.js';
import type { AccountInfo } from '../../src/ui/popup/types.js';
import type { SettingsRailItem } from '../../src/ui/components/page-shell.js';
import type { EditorContext } from '../../src/ui/popup/editor/editor-types.js';
import type { ReceiveState } from '../../src/ui/receive/types.js';
import type { PopoverCandidate } from '../../src/content/ui/autofill-popover-element.js';
import type { PasskeyRegisterTarget } from '../../src/content/ui/passkey-dialog-element.js';

import { VwPopupHeader } from '../../src/ui/popup/vault/popup-header.js';
import { VwPopupFrame } from '../../src/ui/popup/popup-frame.js';
import { VwVaultView } from '../../src/ui/popup/vault/vault-view.js';
import { VwItemDetail } from '../../src/ui/popup/item/item-detail.js';
import { VwCipherEditor } from '../../src/ui/popup/editor/cipher-editor.js';
import { VwGeneratorView } from '../../src/ui/popup/tools/generator-view.js';
import { VwAuthViews } from '../../src/ui/popup/auth/auth-views.js';
import { VwPageShell } from '../../src/ui/components/page-shell.js';
import { VwConnectionSection } from '../../src/ui/options/sections/connection-section.js';
import { VwReceiveApp } from '../../src/ui/receive/receive-app.js';
import { VwDialog } from '../../src/ui/components/dialog.js';
import { VwAutofillPopover } from '../../src/content/ui/autofill-popover-element.js';
import { VwSaveBar } from '../../src/content/ui/save-bar-element.js';
import { VwNotice } from '../../src/content/ui/notice-element.js';
import { VwPasskeyConsent, VwPasskeyRegister } from '../../src/content/ui/passkey-dialog-element.js';

type Theme = 'light' | 'dark';

interface Palette {
  panel: string;
  canvas: string;
  ink: string;
}

const params = new URLSearchParams(location.search);
const surface = params.get('surface') ?? 'popup';
const state = params.get('state') ?? 'suggestions';
const theme: Theme = params.get('theme') === 'dark' ? 'dark' : 'light';
const parsedCount = Number.parseInt(params.get('count') ?? '', 10);
const itemCount = Number.isFinite(parsedCount) && parsedCount > 0 ? parsedCount : 12;
const layout = params.get('layout') === 'single' ? 'single' : 'double';

const palette: Palette = theme === 'dark'
  ? { panel: '#171e2b', canvas: '#0f1420', ink: '#edf2fb' }
  : { panel: '#ffffff', canvas: '#f6f8fb', ink: '#172033' };

const root = document.getElementById('vw-root')!;
document.documentElement.style.colorScheme = theme;
document.body.style.background = palette.canvas;
document.body.style.color = palette.ink;

/** Lit elements whose first render must settle before the fixture reports itself ready. */
const pending: LitElement[] = [];

function track<T extends LitElement>(element: T): T {
  pending.push(element);
  return element;
}

const RAIL: SettingsRailItem[] = [
  { id: 'connection', label: 'Connection', icon: 'globe' },
  { id: 'security', label: 'Security', icon: 'lock' },
  { id: 'autofill', label: 'Autofill', icon: 'key' },
  { id: 'data', label: 'Data', icon: 'note' },
  { id: 'about', label: 'About', icon: 'shield' },
];

const ACCOUNTS: AccountInfo[] = [
  { email: 'test@winvaultwarden.local', active: true },
  { email: 'work@example.com', active: false },
];

const SITES = ['GitHub', 'GitLab', 'Fastmail', 'Proton', 'Cloudflare', 'Vercel', 'Stripe', 'Linear', 'Notion', 'Figma'];

function siteHost(index: number): string {
  return SITES[index % SITES.length]!.toLowerCase();
}

function buildSuggestions(total: number): TabAutofillSuggestion[] {
  return Array.from({ length: total }, (_unused, index) => {
    const site = SITES[index % SITES.length]!;
    const suffix = index >= SITES.length ? ` ${Math.floor(index / SITES.length) + 1}` : '';
    return {
      id: `sugg-${index}`,
      name: `${site}${suffix}`,
      username: `user.${index}@example.com`,
      matchedUri: `https://accounts.${siteHost(index)}.example.com`,
      matchType: UriMatchStrategy.Domain,
      favorite: index % 6 === 0,
      target: { frameId: 0, formId: `form-${index}` },
    };
  });
}

function buildItems(total: number): CipherSummary[] {
  return Array.from({ length: total }, (_unused, index) => {
    const site = SITES[index % SITES.length]!;
    const suffix = index >= SITES.length ? ` ${Math.floor(index / SITES.length) + 1}` : '';
    return {
      id: `item-${index}`,
      name: `${site}${suffix}`,
      username: `user.${index}@example.com`,
      uris: [`https://${siteHost(index)}.example.com`],
      loginUris: [{ uri: `https://${siteHost(index)}.example.com` }],
      type: 1,
      favorite: index % 6 === 0,
      folderId: index % 2 === 0 ? 'folder-personal' : 'folder-work',
    };
  });
}

const FOLDERS: FolderSummary[] = [
  { id: 'folder-personal', name: 'Personal' },
  { id: 'folder-work', name: 'Work' },
];
const COLLECTIONS: CollectionSummary[] = [];

function popupHeader(): VwPopupHeader {
  const header = track(new VwPopupHeader());
  header.accounts = ACCOUNTS;
  header.pinEnabled = true;
  header.deviceRemembered = false;
  header.style.cssText = 'display:block;flex:none;padding:4px 12px;box-sizing:border-box;';
  return header;
}

function popupShell(header: HTMLElement | null, list: HTMLElement | null, detail: HTMLElement): VwPopupFrame {
  const frame = track(new VwPopupFrame());
  frame.id = 'vw-surface';
  frame.mode = layout;
  if (layout === 'single') {
    frame.append(detail);
    return frame;
  }
  if (header) {
    const toolbar = document.createElement('div');
    toolbar.slot = 'toolbar';
    toolbar.style.height = '100%';
    toolbar.append(header);
    frame.append(toolbar);
  }
  if (list) {
    const listSlot = document.createElement('div');
    listSlot.slot = 'list';
    listSlot.setAttribute('data-scroll-region', 'list');
    listSlot.append(list);
    frame.append(listSlot);
  }
  const detailSlot = document.createElement('div');
  detailSlot.slot = 'detail';
  detailSlot.setAttribute('data-scroll-region', 'detail');
  detailSlot.style.cssText = 'height:100%;min-height:0;overflow:auto;';
  detailSlot.append(detail);
  frame.append(detailSlot);
  return frame;
}

function emptyDetail(): HTMLElement {
  const empty = document.createElement('div');
  empty.style.cssText = 'height:100%;display:grid;place-items:center;padding:24px;box-sizing:border-box;color:#666;text-align:center;';
  empty.textContent = 'Select an item to view its details.';
  return empty;
}

function pageSurface(content: HTMLElement): HTMLElement {
  const wrap = document.createElement('div');
  wrap.id = 'vw-surface';
  wrap.style.cssText = `min-height:100%;box-sizing:border-box;padding:16px;overflow-x:hidden;background:${palette.canvas};color:${palette.ink};`;
  wrap.appendChild(content);
  return wrap;
}

function overlayHost(...children: HTMLElement[]): HTMLElement {
  const wrap = document.createElement('div');
  wrap.style.cssText = 'position:relative;height:100%;';
  for (const child of children) wrap.appendChild(child);
  return wrap;
}

function suggestionsView(scope: 'suggestions' | 'all', suggestions: TabAutofillSuggestion[], filled: boolean): VwVaultView {
  const view = track(new VwVaultView());
  view.scope = scope;
  view.suggestionsState = { status: 'ready', suggestions };
  if (filled) view.fill = { outcome: 'filled' };
  view.style.cssText = 'display:block;';
  return view;
}

function listView(): VwVaultView {
  const view = track(new VwVaultView());
  view.scope = 'all';
  view.items = buildItems(itemCount);
  view.folders = FOLDERS;
  view.collections = COLLECTIONS;
  view.style.cssText = 'display:block;';
  return view;
}

function detailView(): VwItemDetail {
  const summary: CipherSummary = {
    id: 'cipher-1',
    name: 'GitHub',
    username: 'octocat',
    uris: ['https://github.com/login'],
    loginUris: [{ uri: 'https://github.com' }],
    type: 1,
    favorite: true,
    hasTotp: true,
    passwordHistoryCount: 2,
  };
  const cipher: DecryptedCipher = {
    ...summary,
    notes: 'Backup recovery codes are stored offline.',
    fields: [
      { type: 0, name: 'Security question', value: 'First pet name' },
      { type: 2, name: 'Work account', value: 'true' },
    ],
  };
  const detail = track(new VwItemDetail());
  detail.summary = summary;
  detail.cipher = cipher;
  detail.style.cssText = 'display:block;';
  return detail;
}

function editorView(): VwCipherEditor {
  const context: EditorContext = {
    mode: 'edit',
    type: 1,
    cipherId: 'cipher-1',
    input: {
      type: 1,
      name: 'GitHub',
      notes: '',
      login: { username: 'octocat', password: '', uris: [{ uri: 'https://github.com' }] },
    },
    folders: FOLDERS,
    collections: COLLECTIONS,
    orgPermissions: [],
  };
  const editor = track(new VwCipherEditor());
  editor.context = context;
  editor.summary = {
    id: 'cipher-1',
    name: 'GitHub',
    username: 'octocat',
    uris: [],
    loginUris: [],
    type: 1,
    favorite: false,
  };
  editor.style.cssText = 'display:block;';
  return editor;
}

function toolsView(): VwGeneratorView {
  const generator = track(new VwGeneratorView());
  generator.accountEmail = 'test@winvaultwarden.local';
  generator.style.cssText = 'display:block;';
  return generator;
}

function authView(): VwAuthViews {
  const auth = track(new VwAuthViews());
  auth.mode = 'login';
  auth.error = 'That email or master password was not recognized.';
  auth.pending = false;
  auth.providers = [];
  auth.style.cssText = 'display:block;';
  return auth;
}

function longTextView(): VwVaultView {
  const long = 'unbreakablesegment'.repeat(8);
  const suggestions: TabAutofillSuggestion[] = [
    {
      id: 'long-1',
      name: long,
      username: `${long}@example.com`,
      matchedUri: `https://${long}.example.com/${long}`,
      matchType: UriMatchStrategy.Domain,
      favorite: false,
      target: { frameId: 0, formId: 'long-form' },
    },
  ];
  return suggestionsView('suggestions', suggestions, false);
}

function mountPopup(): void {
  if (layout === 'single') {
    const content = state === 'auth'
      ? authView()
      : state === 'editor'
        ? editorView()
        : state === 'detail'
          ? detailView()
          : state === 'tools'
            ? toolsView()
            : state === 'longtext'
              ? longTextView()
              : state === 'list'
                ? listView()
                : suggestionsView('suggestions', buildSuggestions(itemCount), state === 'filled');
    root.appendChild(popupShell(null, null, content));
    return;
  }
  switch (state) {
    case 'suggestions': {
      const list = suggestionsView('suggestions', buildSuggestions(itemCount), false);
      root.appendChild(popupShell(popupHeader(), list, emptyDetail()));
      return;
    }
    case 'filled': {
      const list = suggestionsView('suggestions', buildSuggestions(itemCount), true);
      root.appendChild(popupShell(popupHeader(), list, emptyDetail()));
      return;
    }
    case 'longtext':
      root.appendChild(popupShell(popupHeader(), longTextView(), longTextView()));
      return;
    case 'list':
      root.appendChild(popupShell(popupHeader(), listView(), detailView()));
      return;
    case 'detail':
      root.appendChild(popupShell(popupHeader(), suggestionsView('suggestions', buildSuggestions(itemCount), false), detailView()));
      return;
    case 'editor':
      root.appendChild(popupShell(popupHeader(), suggestionsView('suggestions', buildSuggestions(itemCount), false), editorView()));
      return;
    case 'tools':
      root.appendChild(popupShell(popupHeader(), suggestionsView('suggestions', buildSuggestions(itemCount), false), toolsView()));
      return;
    case 'auth':
      root.appendChild(popupShell(null, null, authView()));
      return;
    default:
      root.appendChild(popupShell(popupHeader(), suggestionsView('suggestions', buildSuggestions(itemCount), false), emptyDetail()));
  }
}

function mountOptions(): void {
  const shell = track(new VwPageShell());
  shell.items = RAIL;
  shell.selected = 'connection';
  shell.narrow = window.innerWidth <= 640;
  const section = track(new VwConnectionSection());
  section.serverUrl = 'http://10.0.1.20:8080';
  shell.appendChild(section);
  root.appendChild(pageSurface(shell));
}

function mountReceive(): void {
  const receive = track(new VwReceiveApp());
  const receiveState: ReceiveState = {
    status: 'textReady',
    name: 'Launch checklist',
    text: 'Rotate the deploy keys, then ship, then celebrate.',
  };
  receive.state = receiveState;
  root.appendChild(pageSurface(receive));
}

function mountPopover(): void {
  const popover = track(new VwAutofillPopover());
  popover.kind = 'login';
  popover.view = 'list';
  const candidates: PopoverCandidate[] = [
    { id: 'p1', name: 'GitHub', sub: 'octocat', favorite: true },
    { id: 'p2', name: 'Fastmail', sub: 'me@fastmail.com', favorite: false },
    { id: 'p3', name: 'Proton Mail', sub: 'me@proton.me', favorite: false },
  ];
  popover.candidates = candidates;
  popover.style.cssText = 'position:absolute;top:24px;left:24px;';
  root.appendChild(overlayHost(popover));
}

function mountSave(): void {
  const bar = track(new VwSaveBar());
  bar.message = 'Save this login for github.com?';
  bar.actionLabel = 'Save';
  root.appendChild(overlayHost(bar));
}

function mountNotice(): void {
  const notice = track(new VwNotice());
  notice.message = 'Copied password to clipboard.';
  root.appendChild(overlayHost(notice));
}

function mountConsent(): void {
  const consent = track(new VwPasskeyConsent());
  consent.rpId = 'example.com';
  const result = document.createElement('div');
  result.id = 'vw-consent-result';
  result.textContent = 'pending';
  result.style.cssText = 'position:absolute;top:0;left:0;';
  consent.onResult = (confirmed: boolean): void => {
    result.textContent = confirmed ? 'confirmed' : 'cancelled';
  };
  root.appendChild(overlayHost(result, consent));
}

function mountRegistration(): void {
  const register = track(new VwPasskeyRegister());
  register.rpId = 'example.com';
  const targets: PasskeyRegisterTarget[] = [
    { id: 't1', name: 'GitHub', username: 'octocat' },
    { id: 't2', name: 'Personal site' },
  ];
  register.targets = targets;
  register.onResult = (): void => {};
  root.appendChild(overlayHost(register));
}

function mountDialog(): void {
  const opener = document.createElement('button');
  opener.id = 'vw-open-dialog';
  opener.type = 'button';
  opener.textContent = 'Open dialog';
  opener.style.cssText = 'margin:16px;';

  const dialog = track(new VwDialog());
  dialog.heading = 'Move to trash?';
  const body = document.createElement('p');
  body.textContent = 'This item will move to the trash.';
  const confirm = document.createElement('button');
  confirm.id = 'vw-dialog-confirm';
  confirm.type = 'button';
  confirm.textContent = 'Move to trash';
  confirm.setAttribute('slot', 'actions');
  confirm.setAttribute('autofocus', '');
  confirm.addEventListener('click', () => dialog.requestClose('confirm'));
  dialog.append(body, confirm);
  opener.addEventListener('click', () => {
    dialog.open = true;
  });

  root.appendChild(pageSurface(overlayHost(opener, dialog)));
}

function mount(): void {
  switch (surface) {
    case 'popup':
      mountPopup();
      return;
    case 'options':
      mountOptions();
      return;
    case 'receive':
      mountReceive();
      return;
    case 'popover':
      mountPopover();
      return;
    case 'save':
      mountSave();
      return;
    case 'notice':
      mountNotice();
      return;
    case 'consent':
      mountConsent();
      return;
    case 'registration':
      mountRegistration();
      return;
    case 'dialog':
      mountDialog();
      return;
    default:
      mountPopup();
  }
}

async function ready(): Promise<void> {
  mount();
  await Promise.all(pending.map((element) => element.updateComplete));
  await new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve())));
  document.body.setAttribute('data-ready', 'true');
}

void ready();
