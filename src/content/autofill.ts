import browser from 'webextension-polyfill';
import { sendRequest, type AutofillCandidate, type AutofillCredentials } from '../messaging/protocol.js';
import type { FillItemCandidate, CardFillData, IdentityFillData, FillKind } from '../messaging/protocol.js';
import type { ContentCommand, FillCommand } from '../messaging/protocol.js';
import type { SaveLoginPrompt } from '../core/vault/vault-service.js';
import { fillLoginForm } from './fill.js';
import { fillCardForm, fillIdentityForm } from './fill-card-identity.js';
import type { DetectedLoginForm } from './form-detection.js';
import { detectCardForms, detectIdentityForms, isFillableField, type DetectedFillForm } from './field-detection.js';
import type { FillFieldElement } from './field-detection.js';
import { classifyCardField, classifyIdentityField, type CardRole, type IdentityRole } from './field-map.js';
import { computeFillExclusion } from './focused-fill.js';
import { createAutofillPopover } from './popover.js';
import type { PopoverCandidate } from './popover.js';
import { startSaveCapture, type CapturedLogin } from './capture.js';
import { createSaveBar } from './save-bar.js';
import { showNotice } from './notice.js';

type FrameUrlProvider = () => string;

export function startAutofill(frameUrlOrProvider: string | FrameUrlProvider = () => window.location.href): void {
  const getFrameUrl = typeof frameUrlOrProvider === 'function' ? frameUrlOrProvider : () => frameUrlOrProvider;
  if (!isHttpUrl(getFrameUrl())) return;
  const attach = () => attachPopovers(getFrameUrl);
  attach();
  const observer = new MutationObserver(debounce(attach, 250));
  observer.observe(document.documentElement, { childList: true, subtree: true });
  startSaveCapture((login) => void handleCapture(getFrameUrl, login));
}

// Track the last credential we acted on (and the ones the user dismissed) so a submit doesn't
// re-prompt for the same value. Keyed by frame URL + username + password.
let lastCaptureKey = '';
const dismissedCaptures = new Set<string>();

function captureKey(frameUrl: string, login: CapturedLogin): string {
  return `${frameUrl}\n${login.username ?? ''}\n${login.password}`;
}

async function handleCapture(getFrameUrl: FrameUrlProvider, login: CapturedLogin): Promise<void> {
  const frameUrl = getFrameUrl();
  if (!isHttpUrl(frameUrl)) return;
  const key = captureKey(frameUrl, login);
  if (key === lastCaptureKey || dismissedCaptures.has(key)) return;
  lastCaptureKey = key;
  const response = await sendRequest({
    type: 'autofill.checkSaveLogin',
    frameUrl,
    ...(login.username ? { username: login.username } : {}),
    password: login.password,
  });
  if (!response.ok || !isSaveLoginPrompt(response.data)) return;
  const prompt = response.data;
  if (prompt.action === 'none') return;
  showSaveBar(frameUrl, login, prompt, key);
}

function showSaveBar(frameUrl: string, login: CapturedLogin, prompt: Exclude<SaveLoginPrompt, { action: 'none' }>, key: string): void {
  const onDismiss = () => dismissedCaptures.add(key);
  if (prompt.action === 'save') {
    createSaveBar({
      message: `Save this login for ${hostLabel(frameUrl)} in Vaultwarden?`,
      actionLabel: 'Save',
      onAction: () => void sendRequest({
        type: 'autofill.saveLogin',
        frameUrl,
        ...(login.username ? { username: login.username } : {}),
        password: login.password,
      }),
      onDismiss,
    });
  } else {
    createSaveBar({
      message: `Update the saved password for “${prompt.name}”?`,
      actionLabel: 'Update',
      onAction: () => void sendRequest({ type: 'autofill.updateLogin', cipherId: prompt.cipherId, frameUrl, password: login.password }),
      onDismiss,
    });
  }
}

function isSaveLoginPrompt(data: unknown): data is SaveLoginPrompt {
  return isRecord(data) && typeof data.action === 'string' && ['none', 'save', 'update'].includes(data.action);
}

function hostLabel(frameUrl: string): string {
  try {
    return new URL(frameUrl).hostname || frameUrl;
  } catch {
    return frameUrl;
  }
}

function attachPopovers(getFrameUrl: FrameUrlProvider): void {
  if (!isHttpUrl(getFrameUrl())) return;
  const { loginForms, exclude } = computeFillExclusion(document);
  for (const form of loginForms) {
    attachIfNew(form.id, () => attachPopover(getFrameUrl, form));
  }
  for (const form of [...detectCardForms(document, exclude), ...detectIdentityForms(document, exclude)]) {
    attachIfNew(form.id, () => attachFillPopover(form));
  }
}

function attachIfNew(id: string, attach: () => void): void {
  const selector = `[data-vw-popover-for="${CSS.escape(id)}"]`;
  if (document.querySelector(selector)) return;
  attach();
}

function attachPopover(getFrameUrl: FrameUrlProvider, form: DetectedLoginForm): void {
  const popover = createAutofillPopover({
    anchor: form.anchor,
    onOpen: () => {
      void loadCandidates(getFrameUrl(), popover);
    },
    onSelect: (cipherId) => {
      void fillSelected(getFrameUrl, form, cipherId, popover);
    },
  });
  popover.element.dataset.vwPopoverFor = form.id;
}

function attachFillPopover(form: DetectedFillForm): void {
  const popover = createAutofillPopover({
    anchor: form.anchor,
    kind: form.kind,
    onOpen: () => void loadFillCandidates(form.kind, popover),
    onSelect: (cipherId) => void fillSelectedFillItem(form, cipherId, popover),
  });
  popover.element.dataset.vwPopoverFor = form.id;
}

async function loadFillCandidates(kind: FillKind, popover: ReturnType<typeof createAutofillPopover>): Promise<void> {
  const response = await sendRequest({ type: 'autofill.findFillItems', kind });
  if (!response.ok) {
    popover.showStatus(messageForError(response.error.code, response.error.message));
    return;
  }
  if (Array.isArray(response.data) && isFillItemCandidates(response.data)) {
    popover.showCandidates(response.data.map(toPopoverCandidate));
  } else {
    popover.showStatus('Unexpected autofill response');
  }
}

async function fillSelectedFillItem(
  form: DetectedFillForm,
  cipherId: string,
  popover: ReturnType<typeof createAutofillPopover>,
): Promise<void> {
  const response = await sendRequest({ type: 'autofill.getFillData', cipherId, kind: form.kind });
  if (!response.ok) {
    popover.showStatus(messageForError(response.error.code, response.error.message));
    return;
  }
  if (!isFillData(response.data)) {
    popover.showStatus('Unexpected autofill response');
    return;
  }
  const filled = form.kind === 'card'
    ? fillCardForm(form, response.data as CardFillData)
    : fillIdentityForm(form, response.data as IdentityFillData);
  popover.showStatus(filled ? 'Filled' : 'No fillable fields');
}

function toPopoverCandidate(c: FillItemCandidate): PopoverCandidate {
  return { id: c.id, name: c.name, favorite: c.favorite, ...(c.subtitle ? { sub: c.subtitle } : {}), ...(c.reprompt ? { reprompt: true } : {}) };
}

function isFillItemCandidates(data: unknown[]): data is FillItemCandidate[] {
  return data.every((d) => isRecord(d) && typeof d.id === 'string' && typeof d.name === 'string' && typeof d.favorite === 'boolean' && isOptionalString(d.subtitle)
      && (d.reprompt === undefined || typeof d.reprompt === 'boolean'));
}

function isFillData(data: unknown): data is CardFillData & IdentityFillData {
  return isRecord(data) && Object.values(data).every((v) => v === undefined || typeof v === 'string');
}

async function loadCandidates(frameUrl: string, popover: ReturnType<typeof createAutofillPopover>): Promise<void> {
  const response = await sendRequest({ type: 'autofill.findCandidates', frameUrl });
  if (!response.ok) {
    popover.showStatus(messageForError(response.error.code, response.error.message));
    return;
  }
  if (Array.isArray(response.data) && isAutofillCandidates(response.data)) {
    popover.showCandidates(response.data.map((c) => ({
      id: c.id, name: c.name, favorite: c.favorite,
      ...(c.username ?? c.matchedUri ? { sub: c.username ?? c.matchedUri } : {}),
      ...(c.reprompt ? { reprompt: true } : {}),
    })));
  } else {
    popover.showStatus('Unexpected autofill response');
  }
}

async function fillSelected(
  getFrameUrl: FrameUrlProvider,
  form: DetectedLoginForm,
  cipherId: string,
  popover: ReturnType<typeof createAutofillPopover>,
): Promise<void> {
  const pwOk = !form.passwordInput || form.passwordInput.isConnected;
  const userOk = !form.usernameInput || form.usernameInput.isConnected;
  const totpOk = !form.totpInput || form.totpInput.isConnected;
  const anyField = Boolean(form.passwordInput || form.usernameInput || form.totpInput);
  if (!anyField || !pwOk || !userOk || !totpOk) {
    popover.showStatus('Form is no longer available');
    return;
  }
  const frameUrl = getFrameUrl();
  const response = await sendRequest({ type: 'autofill.getCredentials', cipherId, frameUrl });
  if (!response.ok) {
    popover.showStatus(messageForError(response.error.code, response.error.message));
    return;
  }
  if (getFrameUrl() !== frameUrl) {
    popover.showStatus('Page changed before autofill');
    return;
  }
  if (isAutofillCredentials(response.data)) {
    const filled = fillLoginForm(form, response.data);
    popover.showStatus(filled ? 'Filled' : 'No fillable fields');
  } else {
    popover.showStatus('Unexpected autofill response');
  }
}

function isAutofillCandidates(data: unknown[]): data is AutofillCandidate[] {
  return data.every(isAutofillCandidate);
}

function isAutofillCandidate(data: unknown): data is AutofillCandidate {
  if (!isRecord(data)) return false;
  return (
    typeof data.id === 'string'
    && typeof data.name === 'string'
    && isOptionalString(data.username)
    && typeof data.matchedUri === 'string'
    && isUriMatchStrategySetting(data.matchType)
    && typeof data.favorite === 'boolean'
  );
}

function isAutofillCredentials(data: unknown): data is AutofillCredentials {
  return isRecord(data) && isOptionalString(data.username) && isOptionalString(data.password) && isOptionalString(data.totp);
}

function isUriMatchStrategySetting(value: unknown): value is AutofillCandidate['matchType'] {
  return Number.isInteger(value) && Number(value) >= 0 && Number(value) <= 5;
}

function isOptionalString(value: unknown): value is string | undefined {
  return value === undefined || typeof value === 'string';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isHttpUrl(value: string): boolean {
  return value.startsWith('http://') || value.startsWith('https://');
}

function messageForError(code: string, fallback: string): string {
  switch (code) {
    case 'locked':
      return 'Vault is locked';
    case 'sync_required':
      return 'Sync required';
    case 'no_match':
      return 'No matching logins';
    case 'reprompt_required':
      return 'Protected item — open the extension to verify';
    case 'denied':
      return 'Autofill denied for this page';
    default:
      return fallback;
  }
}

function debounce(fn: () => void, ms: number): () => void {
  let timer: number | undefined;
  return () => {
    if (timer !== undefined) window.clearTimeout(timer);
    timer = window.setTimeout(fn, ms);
  };
}

// Remember the most recently right-clicked element so a field-scope context-menu fill knows its target.
let lastContextElement: Element | null = null;
document.addEventListener('contextmenu', (event) => { lastContextElement = event.target as Element | null; }, true);

browser.runtime.onMessage.addListener((message: unknown) => {
  if (isContentCommand(message)) handleContentCommand(message);
  // No response needed; return nothing (a non-Promise) so the channel closes immediately.
});

export function handleContentCommand(command: ContentCommand): void {
  if (command.type === 'autofill.fillError') {
    showNotice('Protected item — open the extension to verify');
    return;
  }
  if (command.scope === 'field') {
    fillSingleField(command);
  } else {
    fillWholeForm(command);
  }
}

function fillWholeForm(command: FillCommand): void {
  const forms = command.kind === 'card' ? detectCardForms(document) : detectIdentityForms(document);
  if (forms.length === 0) return;
  // Prefer the form containing the right-clicked element; otherwise the first detected form.
  const form = forms.find((f) => lastContextElement && containsField(f, lastContextElement)) ?? forms[0]!;
  if (command.kind === 'card') fillCardForm(form, command.data as CardFillData);
  else fillIdentityForm(form, command.data as IdentityFillData);
}

function fillSingleField(command: FillCommand): void {
  const el = lastContextElement;
  if (!el || !el.isConnected || !(el instanceof HTMLInputElement || el instanceof HTMLSelectElement)) return;
  if (!isFillableField(el)) return;
  const hints = {
    autocomplete: el.getAttribute('autocomplete') ?? '', name: el.getAttribute('name') ?? '', id: el.id,
    ariaLabel: el.getAttribute('aria-label') ?? '', placeholder: el.getAttribute('placeholder') ?? '',
    type: el instanceof HTMLInputElement ? el.type : 'select',
  };
  if (command.kind === 'card') {
    const role = classifyCardField(hints);
    if (!role) return;
    const form = { kind: 'card' as const, id: 'vw-ctx', fields: new Map([[role as CardRole, el as FillFieldElement]]), anchor: el };
    fillCardForm(form, command.data as CardFillData);
  } else {
    const role = classifyIdentityField(hints);
    if (!role) return;
    const form = { kind: 'identity' as const, id: 'vw-ctx', fields: new Map([[role as IdentityRole, el as FillFieldElement]]), anchor: el };
    fillIdentityForm(form, command.data as IdentityFillData);
  }
}

function containsField(form: DetectedFillForm, el: Element): boolean {
  for (const field of form.fields.values()) if (field === el) return true;
  return false;
}

function isContentCommand(value: unknown): value is ContentCommand {
  if (!isRecord(value)) return false;
  if (value.type === 'autofill.fillError') return value.code === 'reprompt_required';
  return value.type === 'autofill.fill'
    && (value.scope === 'form' || value.scope === 'field')
    && (value.kind === 'card' || value.kind === 'identity')
    && isRecord(value.data);
}

startAutofill();
