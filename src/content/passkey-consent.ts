// User-consent surfaces shown before a vault-stored passkey is used or registered. Both render a
// centered overlay dialog into a CLOSED shadow root the page cannot reach (content scripts run in an
// isolated world with no custom-element registry — `customElements` is null, Chromium 41118431 — so
// these surfaces render via lit-html rather than as custom elements). The page cannot reach the closed
// root or forge the choice: the templates gate confirm/select on Event.isTrusted, and cancel resolves
// on Escape / outside click. This supplies the user presence/consent a silent worker assertion skips.

import { mountRenderSurface } from './ui/render-surface.js';
import {
  DIALOG_STYLES,
  renderPasskeyConsent,
  renderPasskeyRegister,
  type PasskeyConsentHandlers,
  type PasskeyConsentState,
  type PasskeyRegisterHandlers,
  type PasskeyRegisterResult,
  type PasskeyRegisterState,
  type PasskeyRegisterTarget,
} from './ui/passkey-dialog-element.js';

export type { PasskeyRegisterResult, PasskeyRegisterTarget } from './ui/passkey-dialog-element.js';

export type PasskeyPickerResult = PasskeyRegisterResult;

/**
 * Prompt the user to approve using a stored passkey for `rpId`. Resolves true on confirm, false on
 * cancel / Escape / outside click. The dialog lives in a closed shadow root the page cannot reach.
 */
export function confirmPasskeyUse(rpId: string): Promise<boolean> {
  return new Promise((resolve) => {
    const surface = mountRenderSurface(DIALOG_STYLES);
    let settled = false;
    const finish = (confirmed: boolean): void => {
      if (settled) return;
      settled = true;
      window.removeEventListener('keydown', handleKeydown, true);
      surface.remove();
      resolve(confirmed);
    };
    const handleKeydown = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        event.preventDefault();
        finish(false);
      }
    };
    const state: PasskeyConsentState = { rpId };
    const handlers: PasskeyConsentHandlers = {
      onConfirm: () => finish(true),
      onCancel: () => finish(false),
      onOverlay: () => finish(false),
    };
    window.addEventListener('keydown', handleKeydown, true);
    surface.render(renderPasskeyConsent(state, handlers));
  });
}

/**
 * Prompt the user to choose where to save a new passkey. Resolves cancelled on Cancel / Escape /
 * outside click. Lives in a closed shadow root the page cannot reach; target ids stay in the
 * in-memory array and are selected by rendered index, never emitted into the DOM.
 */
export function choosePasskeyTarget(
  rpId: string,
  targets: PasskeyRegisterTarget[],
): Promise<PasskeyPickerResult> {
  return new Promise((resolve) => {
    const surface = mountRenderSurface(DIALOG_STYLES);
    let settled = false;
    const finish = (result: PasskeyRegisterResult): void => {
      if (settled) return;
      settled = true;
      window.removeEventListener('keydown', handleKeydown, true);
      surface.remove();
      resolve(result);
    };
    const handleKeydown = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        event.preventDefault();
        finish({ cancelled: true });
      }
    };
    const state: PasskeyRegisterState = { rpId, targets };
    const handlers: PasskeyRegisterHandlers = {
      onNew: () => finish({}),
      onCancel: () => finish({ cancelled: true }),
      onSelectTarget: (index) => {
        const target = state.targets[index];
        if (target) {
          finish({ targetCipherId: target.id });
        }
      },
      onOverlay: () => finish({ cancelled: true }),
    };
    window.addEventListener('keydown', handleKeydown, true);
    surface.render(renderPasskeyRegister(state, handlers));
  });
}
