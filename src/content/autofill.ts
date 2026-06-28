import { sendRequest, type AutofillCandidate, type AutofillCredentials } from '../messaging/protocol.js';
import { fillLoginForm } from './fill.js';
import { detectLoginForms, type DetectedLoginForm } from './form-detection.js';
import { createAutofillPopover } from './popover.js';

export function startAutofill(frameUrl = window.location.href): void {
  if (!frameUrl.startsWith('http://') && !frameUrl.startsWith('https://')) return;
  const attach = () => attachPopovers(frameUrl);
  attach();
  const observer = new MutationObserver(debounce(attach, 250));
  observer.observe(document.documentElement, { childList: true, subtree: true });
}

function attachPopovers(frameUrl: string): void {
  for (const form of detectLoginForms()) {
    const selector = `[data-vw-popover-for="${CSS.escape(form.id)}"]`;
    if (document.querySelector(selector)) continue;
    attachPopover(frameUrl, form);
  }
}

function attachPopover(frameUrl: string, form: DetectedLoginForm): void {
  const popover = createAutofillPopover({
    anchor: form.anchor,
    onOpen: () => {
      void loadCandidates(frameUrl, popover);
    },
    onSelect: (cipherId) => {
      void fillSelected(frameUrl, form, cipherId, popover);
    },
  });
  popover.element.dataset.vwPopoverFor = form.id;
}

async function loadCandidates(frameUrl: string, popover: ReturnType<typeof createAutofillPopover>): Promise<void> {
  const response = await sendRequest({ type: 'autofill.findCandidates', frameUrl });
  if (!response.ok) {
    popover.showStatus(messageForError(response.error.code, response.error.message));
    return;
  }
  if (Array.isArray(response.data) && isAutofillCandidates(response.data)) {
    popover.showCandidates(response.data);
  } else {
    popover.showStatus('Unexpected autofill response');
  }
}

async function fillSelected(
  frameUrl: string,
  form: DetectedLoginForm,
  cipherId: string,
  popover: ReturnType<typeof createAutofillPopover>,
): Promise<void> {
  if (!form.passwordInput.isConnected || (form.usernameInput && !form.usernameInput.isConnected)) {
    popover.showStatus('Form is no longer available');
    return;
  }
  const response = await sendRequest({ type: 'autofill.getCredentials', cipherId, frameUrl });
  if (!response.ok) {
    popover.showStatus(messageForError(response.error.code, response.error.message));
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
  return isRecord(data) && isOptionalString(data.username) && isOptionalString(data.password);
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

function messageForError(code: string, fallback: string): string {
  switch (code) {
    case 'locked':
      return 'Vault is locked';
    case 'sync_required':
      return 'Sync required';
    case 'no_match':
      return 'No matching logins';
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

startAutofill();
