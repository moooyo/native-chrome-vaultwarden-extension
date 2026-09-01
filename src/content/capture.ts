// Capture credentials the user enters so the extension can offer to save or update them. Listens for
// real (trusted) submit, Enter, and submit-button clicks, then snapshots the current login form's
// username/password from the live DOM. The decision to prompt happens in the worker; this only watches.

import {
  detectFormlessSubmission,
  detectFormlessUsernameSubmission,
  detectNativeFormSubmission,
  detectNativeUsernameSubmission,
  isExplicitRoleSubmit,
  type SubmittedCredentials,
  type SubmittedUsername,
} from './submission-detection.js';
import { trustedComposedTarget } from './autofill-document-controller.js';
import type { ComposedTreeRoot } from './composed-tree.js';
import type { AutofillSaveCaptureSubmission } from '../messaging/protocol.js';

export type CapturedLogin = SubmittedCredentials;
export type CapturedUsername = SubmittedUsername;

export interface SaveCaptureRootInventory {
  readonly ownerDocument: Document;
  bindRoots(binding: (root: ComposedTreeRoot) => void | (() => void)): () => void;
}

/**
 * Watch the page for credential submissions. `onCapture` fires with the current username/password
 * whenever the user submits a form that has a filled password. Returns a teardown function.
 */
export function startSaveCapture(
  onCapture: (login: CapturedLogin, submission: AutofillSaveCaptureSubmission) => void,
  inventory?: SaveCaptureRootInventory,
  onUsernameStage?: (submitted: CapturedUsername) => void,
): () => void {
  let stopped = false;
  const pendingNativeFallbacks = new WeakMap<HTMLFormElement, { cancelled: boolean }>();
  const capture = (
    captured: CapturedLogin | undefined,
    submission: AutofillSaveCaptureSubmission,
  ): void => {
    if (!stopped && captured) onCapture(captured, submission);
  };

  const captureNative = (form: HTMLFormElement): void => {
    const credentials = detectNativeFormSubmission(form);
    if (credentials) capture(credentials, nativeSubmission(form));
    else {
      const username = detectNativeUsernameSubmission(form);
      if (username) onUsernameStage?.(username);
    }
  };
  const captureFormless = (control: HTMLElement): void => {
    const credentials = detectFormlessSubmission(control);
    if (credentials) capture(credentials, { kind: 'formless' });
    else {
      const username = detectFormlessUsernameSubmission(control);
      if (username) onUsernameStage?.(username);
    }
  };

  const cancelNativeFallback = (form: HTMLFormElement): void => {
    const pending = pendingNativeFallbacks.get(form);
    if (pending) pending.cancelled = true;
    pendingNativeFallbacks.delete(form);
  };
  const scheduleNativeFallback = (form: HTMLFormElement): void => {
    cancelNativeFallback(form);
    const pending = { cancelled: false };
    pendingNativeFallbacks.set(form, pending);
    queueMicrotask(() => {
      if (stopped || pending.cancelled || pendingNativeFallbacks.get(form) !== pending) return;
      pendingNativeFallbacks.delete(form);
      captureNative(form);
    });
  };

  const onSubmit = (e: Event): void => {
    const target = trustedComposedTarget(e);
    if (!(target instanceof HTMLFormElement)) return;
    cancelNativeFallback(target);
    captureNative(target);
  };
  const onClick = (e: Event): void => {
    const control = submitControl(trustedComposedTarget(e));
    if (!control) return;
    const owner = control instanceof HTMLButtonElement || control instanceof HTMLInputElement
      ? control.form
      : control.closest('form');
    if (owner) scheduleNativeFallback(owner);
    else captureFormless(control);
  };
  const onKey = (e: KeyboardEvent): void => {
    if (
      !e.isTrusted || e.key !== 'Enter' || e.isComposing || e.repeat
      || e.altKey || e.ctrlKey || e.metaKey || e.shiftKey
    ) return;
    const target = trustedComposedTarget(e);
    if (!(target instanceof HTMLInputElement)) return;
    const input = target;
    if (input.form) scheduleNativeFallback(input.form);
    else captureFormless(input);
  };

  const ownerDocument = inventory?.ownerDocument ?? document;
  const stopSubmitListeners = inventory
    ? inventory.bindRoots((root) => {
        root.addEventListener('submit', onSubmit, true);
        return () => root.removeEventListener('submit', onSubmit, true);
      })
    : (() => {
        ownerDocument.addEventListener('submit', onSubmit, true);
        return () => ownerDocument.removeEventListener('submit', onSubmit, true);
      })();

  // Click and keyboard events are composed. One document listener avoids duplicate capture across
  // nested roots while composedPath()[0] preserves the originating open-shadow control.
  ownerDocument.addEventListener('click', onClick, true);
  ownerDocument.addEventListener('keydown', onKey, true);

  return () => {
    stopped = true;
    stopSubmitListeners();
    ownerDocument.removeEventListener('click', onClick, true);
    ownerDocument.removeEventListener('keydown', onKey, true);
  };
}

function nativeSubmission(form: HTMLFormElement): AutofillSaveCaptureSubmission {
  const method = (form.getAttribute('method') ?? '').trim().toUpperCase();
  if (method !== 'POST' && method !== 'PUT' && method !== 'PATCH') return { kind: 'formless' };
  try {
    const action = new URL(form.action || form.ownerDocument.URL);
    action.hash = '';
    if ((action.protocol === 'https:' || action.protocol === 'http:') && !action.username && !action.password) {
      return { kind: 'native', actionUrl: action.href, method };
    }
  } catch {
    // A malformed action cannot narrow browser-owned network evidence.
  }
  return { kind: 'formless' };
}

/** Snapshot a submitted native form with the same rules used by the event watcher. */
export function snapshotLogin(form: HTMLFormElement): CapturedLogin | undefined {
  return detectNativeFormSubmission(form);
}

function submitControl(target: EventTarget | null): HTMLElement | undefined {
  if (!(target instanceof Element)) return undefined;
  const control = target.closest<HTMLElement>('button, input, [role="button"]');
  if (control instanceof HTMLButtonElement) return control.type === 'submit' ? control : undefined;
  if (control instanceof HTMLInputElement && (control.type === 'submit' || control.type === 'image')) return control;
  return isExplicitRoleSubmit(control) ? control : undefined;
}
