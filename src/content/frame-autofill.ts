import type { AutofillCredentials, FrameInspection, FrameLoginForm, TabFillOutcome } from '../messaging/protocol.js';
import type { DetectedLoginForm } from './form-detection.js';
import { detectLoginForms, isFillableInput, isVisibleInTree } from './form-detection.js';
import { fillLoginForm } from './fill.js';

export interface FrameAutofillControllerOptions {
  /** The document (or a detached subtree, for tests) to scan for login forms. Defaults to `document`. */
  root?: ParentNode;
  /** Returns the frame's current URL. Injected so tests and iframes can control/observe it. */
  frameUrl: () => string;
  /** Returns the current time (ms). Injected for deterministic tests. */
  now: () => number;
}

export interface FrameAutofillCommitRequest {
  formId: string;
  expectedFrameUrl: string;
  credentials: AutofillCredentials;
}

export interface FrameAutofillController {
  /** Record which detected form owns `input`, so the next `inspect()` can report `focusedAt`. */
  noteFocus(input: HTMLInputElement): void;
  /** Re-detect forms and return metadata only (formId/visible/focusedAt) — never field values. */
  inspect(): FrameInspection;
  /** Re-detect forms and fill `formId` only if the frame URL and form still match (TOCTOU guard). */
  commit(request: FrameAutofillCommitRequest): TabFillOutcome;
}

/** Builds a per-frame controller that inspects login forms for the current-tab suggestions UI and
 *  commits a fill only after re-validating the frame hasn't navigated and the form still exists.
 *  Holds no credentials and no field values: only `lastFocusedFormId`/`focusedAt` are retained
 *  across calls, and forms are always re-detected live rather than cached. */
export function createFrameAutofillController(options: FrameAutofillControllerOptions): FrameAutofillController {
  const root = options.root ?? document;
  let lastFocusedFormId: string | undefined;
  let focusedAt: number | undefined;

  function noteFocus(input: HTMLInputElement): void {
    const owner = detectLoginForms(root).find((form) => ownsInput(form, input));
    if (!owner) return;
    lastFocusedFormId = owner.id;
    focusedAt = options.now();
  }

  function inspect(): FrameInspection {
    const forms = detectLoginForms(root).map((form) => toFrameLoginForm(form));
    return { frameUrl: options.frameUrl(), forms };
  }

  function commit(request: FrameAutofillCommitRequest): TabFillOutcome {
    if (options.frameUrl() !== request.expectedFrameUrl) return { status: 'target_changed' };
    const target = detectLoginForms(root).find((form) => form.id === request.formId);
    if (!target) return { status: 'target_changed' };
    if (!hasConnectedFillableField(target)) return { status: 'no_fillable_target' };
    return fillLoginForm(target, request.credentials) ? { status: 'filled' } : { status: 'no_fillable_target' };
  }

  function toFrameLoginForm(form: DetectedLoginForm): FrameLoginForm {
    return {
      formId: form.id,
      visible: isVisibleInTree(form.anchor),
      ...(form.id === lastFocusedFormId && focusedAt !== undefined ? { focusedAt } : {}),
    };
  }

  return { noteFocus, inspect, commit };
}

function ownsInput(form: DetectedLoginForm, input: HTMLInputElement): boolean {
  return form.usernameInput === input || form.passwordInput === input || form.totpInput === input;
}

/** At least one of the form's fields must still be a live, connected, fillable element — guards
 *  against a stale form reference (e.g. removed from the DOM) between inspect and commit. */
function hasConnectedFillableField(form: DetectedLoginForm): boolean {
  const fields = [form.usernameInput, form.passwordInput, form.totpInput];
  return fields.some((field) => field !== undefined && field.isConnected && isFillableInput(field));
}
