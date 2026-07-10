// User-consent surfaces shown before a vault-stored passkey is used or registered. Both are the
// closed-shadow Lit elements `vw-passkey-consent` / `vw-passkey-register`, mounted here and removed
// once the user chooses. The page cannot reach the closed root or forge the choice: the elements
// gate confirm on Event.isTrusted and resolve cancel on Escape / outside click. This supplies the
// user presence/consent a silent worker assertion would otherwise skip.

import { mountClosedSurface } from './ui/closed-surface.js';
import {
  VwPasskeyConsent,
  VwPasskeyRegister,
  type PasskeyRegisterResult,
  type PasskeyRegisterTarget,
} from './ui/passkey-dialog-element.js';

export type PasskeyPickerResult = PasskeyRegisterResult;

/**
 * Prompt the user to approve using a stored passkey for `rpId`. Resolves true on confirm, false on
 * cancel / Escape / outside click. The dialog lives in a closed shadow root the page cannot reach.
 */
export function confirmPasskeyUse(rpId: string): Promise<boolean> {
  return new Promise((resolve) => {
    const surface = mountClosedSurface<VwPasskeyConsent>('vw-passkey-consent', (element) => {
      element.rpId = rpId;
    });
    surface.element.onResult = (confirmed) => {
      surface.remove();
      resolve(confirmed);
    };
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
    const surface = mountClosedSurface<VwPasskeyRegister>('vw-passkey-register', (element) => {
      element.rpId = rpId;
      element.targets = targets;
    });
    surface.element.onResult = (result) => {
      surface.remove();
      resolve(result);
    };
  });
}
