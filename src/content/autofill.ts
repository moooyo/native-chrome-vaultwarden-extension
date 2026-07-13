import browser from 'webextension-polyfill';
import { sendRequest, type AutofillCandidate, type AutofillCredentials } from '../messaging/protocol.js';
import type { FillItemCandidate, CardFillData, IdentityFillData, FillKind } from '../messaging/protocol.js';
import type { ContentCommand, FillCommand } from '../messaging/protocol.js';
import type { FrameAutofillMessage, FrameInspection, TabFillOutcome } from '../messaging/protocol.js';
import type { SaveLoginPrompt } from '../core/vault/vault-service.js';
import { fillLoginForm, setInputValue } from './fill.js';
import { createFrameAutofillController, type FrameAutofillController } from './frame-autofill.js';
import { fillCardForm, fillIdentityForm } from './fill-card-identity.js';
import { isFillableInput, isTotpCandidate, type DetectedLoginForm } from './form-detection.js';
import { detectCardForms, detectIdentityForms, isFillableField, type DetectedFillForm } from './field-detection.js';
import type { FillFieldElement } from './field-detection.js';
import { classifyCardField, classifyIdentityField, type CardRole, type IdentityRole } from './field-map.js';
import { computeFillExclusion, resolveFocusedFill, runFocusedFill, type FocusedFillDeps } from './focused-fill.js';
import { createAutofillPopover } from './popover.js';
import type { PopoverCandidate } from './popover.js';
import { startSaveCapture, type CapturedLogin } from './capture.js';
import { createSaveBar } from './save-bar.js';
import { showNotice } from './notice.js';
import { ensureMiyuFonts } from './ui/fonts.js';
import { createTotpPanel, type TotpPanel } from './totp-fill.js';
import { createGeneratePanel, type GeneratePanel } from './generate-fill.js';
import { matchRegistrationField, type DetectedRegistrationField } from './registration-detection.js';
import { generatePassword } from '../core/generator/password.js';

type FrameUrlProvider = () => string;

/** The current frame's URL provider and its login-form inspection/commit controller. Both are set
 *  from `startAutofill` and are also used by the runtime listener that answers the background's
 *  current-tab-fill inspect/commit messages. */
let frameUrlProvider: FrameUrlProvider = () => window.location.href;
let frameController: FrameAutofillController | undefined;

/** Lazily build (once) the per-frame login-form controller, reading the live frame URL through the
 *  module-level provider so it always reflects the latest same-document navigation. */
function ensureFrameController(): FrameAutofillController {
  if (!frameController) {
    frameController = createFrameAutofillController({ frameUrl: () => frameUrlProvider(), now: () => Date.now() });
  }
  return frameController;
}

export function startAutofill(frameUrlOrProvider: string | FrameUrlProvider = () => window.location.href): void {
  const getFrameUrl = typeof frameUrlOrProvider === 'function' ? frameUrlOrProvider : () => frameUrlOrProvider;
  frameUrlProvider = getFrameUrl;
  if (!isHttpUrl(getFrameUrl())) return;
  ensureMiyuFonts();
  ensureFrameController();
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
      message: `在密屿中保存 ${hostLabel(frameUrl)} 的登录？`,
      actionLabel: '保存',
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
      message: `更新“${prompt.name}”的已保存密码？`,
      actionLabel: '更新',
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
    sidePanel: true,
    onOpen: () => {
      void loadCandidates(getFrameUrl(), popover);
    },
    onSelect: (cipherId) => {
      void fillSelected(getFrameUrl, form, cipherId, popover);
    },
  });
  popover.element.dataset.vwPopoverFor = form.id;
  popoverRegistry.set(form.id, popover);
}

function attachFillPopover(form: DetectedFillForm): void {
  const popover = createAutofillPopover({
    anchor: form.anchor,
    kind: form.kind,
    onOpen: () => void loadFillCandidates(form.kind, popover),
    onSelect: (cipherId) => void fillSelectedFillItem(form, cipherId, popover),
  });
  popover.element.dataset.vwPopoverFor = form.id;
  popoverRegistry.set(form.id, popover);
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
    if (filled) popover.showFilled();
    else popover.showStatus('No fillable fields');
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

// Record which login form was most recently focused so the background's frame inspection can rank
// the recently-used form first. Metadata only — the controller never reads or retains field values.
document.addEventListener('focusin', (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) return;
  ensureFrameController().noteFocus(target);
  maybeOpenLoginPanel(target);
  maybeAttachTotpPanel(target);
  maybeAttachGeneratePanel(target);
}, true);

/** Design 2c: the login match panel hangs to the right of the focused field and opens on focus (no
 *  click-to-open trigger). Find the login form the focused input belongs to and open its side panel,
 *  attaching it first if a freshly-added form hasn't been picked up by the mutation observer yet. */
function maybeOpenLoginPanel(input: HTMLInputElement): void {
  const { loginForms } = computeFillExclusion(document);
  const form = loginForms.find((f) => f.usernameInput === input || f.passwordInput === input);
  if (!form) return;
  let pop = popoverRegistry.get(form.id);
  if (!pop || !pop.element.isConnected) {
    attachPopovers(frameUrlProvider); // idempotent (attachIfNew de-dupes) — ensure the panel exists
    pop = popoverRegistry.get(form.id);
  }
  if (pop && pop.element.isConnected) pop.open();
}

/** form.id → its hover popover, so the keyboard shortcut can open the right picker on a multi-match. */
export const popoverRegistry = new Map<string, ReturnType<typeof createAutofillPopover>>();

// --- 2FA verification-code panel (design 3a) ---------------------------------------------------
// A standalone verification-code step (a one-time-code field with no password in scope) gets a
// dedicated panel showing the live TOTP for the top matching login plus a fill action. Mounted on
// focus of the code field so it never appears unbidden.

interface ActiveTotpPanel { panel: TotpPanel; timer: number; }
const totpPanels = new Map<string, ActiveTotpPanel>();
const pendingTotp = new Set<string>();
let totpSeq = 0;

function isStandaloneTotpField(input: HTMLInputElement): boolean {
  if (!isTotpCandidate(input) || !isFillableInput(input)) return false;
  const container = input.form ?? input.closest('form, section, main, article') ?? document;
  return !Array.from(container.querySelectorAll<HTMLInputElement>('input[type="password"]')).some(isFillableInput);
}

function totpFieldId(input: HTMLInputElement): string {
  if (!input.dataset.vwAutofillId) input.dataset.vwAutofillId = `vw-form-totp-${totpSeq++}`;
  return input.dataset.vwAutofillId;
}

function maybeAttachTotpPanel(input: HTMLInputElement): void {
  if (!isStandaloneTotpField(input)) return;
  const id = totpFieldId(input);
  if (totpPanels.has(id) || pendingTotp.has(id)) return;
  void attachTotpPanel(id, input);
}

async function attachTotpPanel(id: string, totpInput: HTMLInputElement): Promise<void> {
  pendingTotp.add(id);
  try {
    const frameUrl = frameUrlProvider();
    const candResp = await sendRequest({ type: 'autofill.findCandidates', frameUrl });
    if (!candResp.ok || !Array.isArray(candResp.data) || !isAutofillCandidates(candResp.data) || candResp.data.length === 0) return;
    const top = candResp.data[0]!;
    const credResp = await sendRequest({ type: 'autofill.getCredentials', cipherId: top.id, frameUrl });
    if (!credResp.ok || !isAutofillCredentials(credResp.data) || !credResp.data.totp) return;
    if (!totpInput.isConnected) return;

    let code = credResp.data.totp;
    const cipherId = top.id;
    const panel = createTotpPanel({
      anchor: totpInput,
      onFill: () => {
        if (isFillableInput(totpInput)) setInputValue(totpInput, code);
        panel.showFilled();
        stopTotp(id);
      },
      onCopy: () => { void navigator.clipboard?.writeText?.(code); },
      onUndo: () => {
        if (isFillableInput(totpInput)) setInputValue(totpInput, '');
        removeTotp(id);
      },
    });
    panel.element.dataset.vwPopoverFor = id;

    let last = -1;
    const render = (): void => {
      const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
      panel.update({ itemName: top.name, itemUser: top.username ?? '', code, remaining });
      last = remaining;
    };
    render();
    const timer = window.setInterval(() => {
      if (!totpInput.isConnected) { removeTotp(id); return; }
      const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
      if (remaining > last) {
        // Period rolled over — refresh the code from the worker, then re-render.
        void sendRequest({ type: 'autofill.getCredentials', cipherId, frameUrl: frameUrlProvider() }).then((r) => {
          if (r.ok && isAutofillCredentials(r.data) && r.data.totp) code = r.data.totp;
          render();
        });
      } else {
        render();
      }
    }, 1000);
    totpPanels.set(id, { panel, timer });
  } finally {
    pendingTotp.delete(id);
  }
}

function stopTotp(id: string): void {
  const active = totpPanels.get(id);
  if (active) window.clearInterval(active.timer);
}

function removeTotp(id: string): void {
  const active = totpPanels.get(id);
  if (!active) return;
  window.clearInterval(active.timer);
  active.panel.remove();
  totpPanels.delete(id);
}

// --- Inline registration password generation (design 2e) ---------------------------------------
// On focus of a registration new-password field, suggest a strong password with in-place rule
// tuning; "使用此密码" fills the field and saves the login. The generator runs locally (pure core
// function over crypto.getRandomValues) so no plaintext round-trips the worker to be generated.

interface GenState { password: string; length: number; numbers: boolean; symbols: boolean; }
const genPanels = new Map<string, { panel: GeneratePanel }>();

function maybeAttachGeneratePanel(input: HTMLInputElement): void {
  const target = matchRegistrationField(input);
  if (!target || genPanels.has(target.id)) return;
  attachGeneratePanel(target);
}

function attachGeneratePanel(target: DetectedRegistrationField): void {
  const state: GenState = { password: '', length: 18, numbers: true, symbols: true };
  const regen = (): void => {
    state.password = generatePassword({
      length: state.length,
      lowercase: true,
      uppercase: true,
      numbers: state.numbers,
      special: state.symbols,
      minNumbers: state.numbers ? 1 : 0,
      minSpecial: state.symbols ? 1 : 0,
      avoidAmbiguous: true,
    });
  };
  regen();

  const panel = createGeneratePanel({
    anchor: target.anchor,
    onRegenerate: () => { regen(); push(); },
    onLength: (n) => { state.length = clampLength(n); regen(); push(); },
    onNumbers: (on) => { state.numbers = on; regen(); push(); },
    onSymbols: (on) => { state.symbols = on; regen(); push(); },
    onUse: () => { void useGenerated(); },
    onUndo: () => {
      if (isFillableInput(target.input)) setInputValue(target.input, '');
      panel.remove();
      genPanels.delete(target.id);
    },
  });
  panel.element.dataset.vwPopoverFor = target.id;

  const push = (): void => panel.update({
    password: state.password,
    strength: strengthLabel(state.length),
    length: state.length,
    numbers: state.numbers,
    symbols: state.symbols,
  });
  push();

  async function useGenerated(): Promise<void> {
    if (!isFillableInput(target.input)) return;
    setInputValue(target.input, state.password);
    const frameUrl = frameUrlProvider();
    const username = target.usernameInput?.value?.trim() || undefined;
    await sendRequest({ type: 'autofill.saveLogin', frameUrl, ...(username ? { username } : {}), password: state.password });
    panel.showSaved({ name: hostLabel(frameUrl), user: username ?? '' });
  }

  genPanels.set(target.id, { panel });
}

function clampLength(n: number): number {
  return Math.max(8, Math.min(40, Math.round(n)));
}

function strengthLabel(len: number): string {
  if (len >= 16) return '极强';
  if (len >= 12) return '强';
  if (len >= 10) return '中等';
  return '较弱';
}

browser.runtime.onMessage.addListener((message: unknown): Promise<FrameInspection | TabFillOutcome> | undefined => {
  // Frame inspect/commit are the only content messages that return a value: the background awaits a
  // typed response (metadata for inspect, a fill outcome for commit). A Promise return tells the
  // polyfill to use it as the async response; content commands return nothing so the channel closes.
  if (isFrameAutofillMessage(message)) return Promise.resolve(handleFrameAutofillMessage(message));
  if (isContentCommand(message)) handleContentCommand(message);
  return undefined;
});

/** Answer a background current-tab-fill message: report this frame's login-form metadata, or commit
 *  a fill after the controller re-validates the frame URL and form identity (TOCTOU guard). */
export function handleFrameAutofillMessage(message: FrameAutofillMessage): FrameInspection | TabFillOutcome {
  const controller = ensureFrameController();
  if (message.type === 'autofill.inspectFrame') return controller.inspect();
  return controller.commit({
    formId: message.formId,
    expectedFrameUrl: message.expectedFrameUrl,
    credentials: message.credentials,
  });
}

export function handleContentCommand(command: ContentCommand): void {
  if (command.type === 'autofill.focusedFill') { void handleFocusedFill(); return; }
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

export function openPickerFor(getFrameUrl: FrameUrlProvider, formId: string): void {
  let pop = popoverRegistry.get(formId);
  if (pop && pop.element.isConnected) { pop.open(); return; }
  popoverRegistry.delete(formId);
  attachPopovers(getFrameUrl); // idempotent (attachIfNew de-dupes) — re-attach for the current form
  pop = popoverRegistry.get(formId);
  if (pop && pop.element.isConnected) pop.open();
  else showNotice('多个匹配项——点击输入框的密屿图标选择');
}

function focusedFillDeps(getFrameUrl: FrameUrlProvider): FocusedFillDeps {
  return {
    frameUrl: () => getFrameUrl(),
    loginCandidates: async (frameUrl) => {
      const r = await sendRequest({ type: 'autofill.findCandidates', frameUrl });
      if (!r.ok) return { ok: false, message: messageForError(r.error.code, r.error.message) };
      return Array.isArray(r.data) && isAutofillCandidates(r.data) ? { ok: true, data: r.data } : { ok: false, message: 'Unexpected autofill response' };
    },
    loginCredentials: async (cipherId, frameUrl) => {
      const r = await sendRequest({ type: 'autofill.getCredentials', cipherId, frameUrl });
      if (!r.ok) return { ok: false, message: messageForError(r.error.code, r.error.message) };
      return isAutofillCredentials(r.data) ? { ok: true, data: r.data } : { ok: false, message: 'Unexpected autofill response' };
    },
    fillItems: async (kind) => {
      const r = await sendRequest({ type: 'autofill.findFillItems', kind });
      if (!r.ok) return { ok: false, message: messageForError(r.error.code, r.error.message) };
      return Array.isArray(r.data) && isFillItemCandidates(r.data) ? { ok: true, data: r.data } : { ok: false, message: 'Unexpected autofill response' };
    },
    fillData: async (cipherId, kind) => {
      const r = await sendRequest({ type: 'autofill.getFillData', cipherId, kind });
      if (!r.ok) return { ok: false, message: messageForError(r.error.code, r.error.message) };
      return isFillData(r.data) ? { ok: true, data: r.data } : { ok: false, message: 'Unexpected autofill response' };
    },
    fillLogin: (form, creds) => { fillLoginForm(form, creds); },
    fillCard: (form, data) => { fillCardForm(form, data); },
    fillIdentity: (form, data) => { fillIdentityForm(form, data); },
    openPicker: (formId) => openPickerFor(getFrameUrl, formId),
    notify: (message) => showNotice(message),
  };
}

export async function handleFocusedFill(getFrameUrl: FrameUrlProvider = () => window.location.href): Promise<void> {
  if (!document.hasFocus()) return;                                   // non-focused frame
  const el = document.activeElement;
  // Ancestor frame — focus is in a child. HTMLFrameElement is obsolete (no <frameset> in modern
  // pages) and isn't defined in every DOM implementation (e.g. happy-dom in tests), so guard it.
  if (el instanceof HTMLIFrameElement || (typeof HTMLFrameElement !== 'undefined' && el instanceof HTMLFrameElement)) return;
  const target = resolveFocusedFill(el, document);
  await runFocusedFill(target, focusedFillDeps(getFrameUrl));
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
  if (value.type === 'autofill.focusedFill') return true;
  if (value.type === 'autofill.fillError') return value.code === 'reprompt_required';
  return value.type === 'autofill.fill'
    && (value.scope === 'form' || value.scope === 'field')
    && (value.kind === 'card' || value.kind === 'identity')
    && isRecord(value.data);
}

function isFrameAutofillMessage(value: unknown): value is FrameAutofillMessage {
  if (!isRecord(value)) return false;
  if (value.type === 'autofill.inspectFrame') return true;
  return value.type === 'autofill.commitLoginFill'
    && typeof value.formId === 'string'
    && typeof value.expectedFrameUrl === 'string'
    && isAutofillCredentials(value.credentials);
}

startAutofill();
