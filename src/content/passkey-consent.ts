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
  renderPasskeyLoginPicker,
  renderPasskeyRegister,
  type PasskeyConsentHandlers,
  type PasskeyConsentState,
  type PasskeyLoginPickerHandlers,
  type PasskeyLoginPickerState,
  type PasskeyRegisterHandlers,
  type PasskeyRegisterResult,
  type PasskeyRegisterState,
  type PasskeyRegisterTarget,
} from './ui/passkey-dialog-element.js';
import type { PasskeyCandidate } from '../core/vault/models.js';

export type { PasskeyRegisterResult, PasskeyRegisterTarget } from './ui/passkey-dialog-element.js';

export type PasskeyPickerResult = PasskeyRegisterResult;

/** The result of the login (assertion) account picker: the chosen credential, or a cancel. */
export type PasskeyLoginResult = { credentialId: string } | { cancelled: true };

/**
 * Grace period after a consent surface mounts during which an *approving* action (confirm / select /
 * create-new) is ignored. Guards against a page that provokes a real click at the dialog's fixed
 * center the instant it appears (clickjacking): only actions that land after the surface has settled
 * can approve. Cancel / Escape / outside-click are never delayed — dismissing early is harmless.
 */
export const PASSKEY_CONSENT_ARM_MS = 300;

/** Whether the arming grace period has elapsed since `mountedAt`. */
function isArmed(mountedAt: number): boolean {
  return Date.now() - mountedAt >= PASSKEY_CONSENT_ARM_MS;
}

/**
 * Settle a consent promise as cancelled if the page removes the surface host from the DOM. The host is
 * a light-DOM `<div>` the page can reach and remove; without this the ceremony would hang, resolving
 * only via an unlikely window Escape. Returns a teardown that disconnects the observer.
 */
function observeHostRemoval(host: HTMLElement, onRemoved: () => void): () => void {
  const observer = new MutationObserver(() => {
    if (!host.isConnected) onRemoved();
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
  return () => observer.disconnect();
}

/**
 * Prompt the user to approve using a stored passkey for `rpId`. Resolves true on confirm, false on
 * cancel / Escape / outside click. The dialog lives in a closed shadow root the page cannot reach.
 */
export function confirmPasskeyUse(rpId: string): Promise<boolean> {
  return new Promise((resolve) => {
    const surface = mountRenderSurface(DIALOG_STYLES);
    const mountedAt = Date.now();
    let settled = false;
    let disconnectObserver = (): void => {};
    const finish = (confirmed: boolean): void => {
      if (settled) return;
      settled = true;
      window.removeEventListener('keydown', handleKeydown, true);
      disconnectObserver();
      surface.remove();
      resolve(confirmed);
    };
    const handleKeydown = (event: KeyboardEvent): void => {
      if (!event.isTrusted) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        finish(false);
      }
    };
    const state: PasskeyConsentState = { rpId };
    const handlers: PasskeyConsentHandlers = {
      onConfirm: () => { if (isArmed(mountedAt)) finish(true); },
      onCancel: () => finish(false),
      onOverlay: () => finish(false),
    };
    window.addEventListener('keydown', handleKeydown, true);
    disconnectObserver = observeHostRemoval(surface.host, () => finish(false));
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
    const mountedAt = Date.now();
    let settled = false;
    let disconnectObserver = (): void => {};
    const finish = (result: PasskeyRegisterResult): void => {
      if (settled) return;
      settled = true;
      window.removeEventListener('keydown', handleKeydown, true);
      disconnectObserver();
      surface.remove();
      resolve(result);
    };
    const handleKeydown = (event: KeyboardEvent): void => {
      if (!event.isTrusted) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        finish({ cancelled: true });
      }
    };
    const state: PasskeyRegisterState = { rpId, targets };
    const handlers: PasskeyRegisterHandlers = {
      onNew: () => { if (isArmed(mountedAt)) finish({}); },
      onCancel: () => finish({ cancelled: true }),
      onSelectTarget: (index) => {
        if (!isArmed(mountedAt)) return;
        const target = state.targets[index];
        if (target) {
          finish({ targetCipherId: target.id });
        }
      },
      onOverlay: () => finish({ cancelled: true }),
    };
    window.addEventListener('keydown', handleKeydown, true);
    disconnectObserver = observeHostRemoval(surface.host, () => finish({ cancelled: true }));
    surface.render(renderPasskeyRegister(state, handlers));
  });
}

/**
 * Prompt the user to choose which stored passkey to sign in with when a site has more than one.
 * Resolves the chosen credentialId, or cancelled on Cancel / Escape / outside click. Lives in a closed
 * shadow root the page cannot reach; credentialIds stay in this in-memory array and are selected by
 * rendered index, never emitted into the DOM.
 */
export function choosePasskeyLogin(
  rpId: string,
  candidates: PasskeyCandidate[],
): Promise<PasskeyLoginResult> {
  return new Promise((resolve) => {
    const surface = mountRenderSurface(DIALOG_STYLES);
    const mountedAt = Date.now();
    let settled = false;
    let disconnectObserver = (): void => {};
    const finish = (result: PasskeyLoginResult): void => {
      if (settled) return;
      settled = true;
      window.removeEventListener('keydown', handleKeydown, true);
      disconnectObserver();
      surface.remove();
      resolve(result);
    };
    const handleKeydown = (event: KeyboardEvent): void => {
      if (!event.isTrusted) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        finish({ cancelled: true });
      }
    };
    // Render only display fields — the credentialId stays in the `candidates` closure, mapped by index.
    const state: PasskeyLoginPickerState = {
      rpId,
      accounts: candidates.map((c) => (c.username ? { name: c.name, username: c.username } : { name: c.name })),
    };
    const handlers: PasskeyLoginPickerHandlers = {
      onSelect: (index) => {
        if (!isArmed(mountedAt)) return;
        const chosen = candidates[index];
        if (chosen) finish({ credentialId: chosen.credentialId });
      },
      onCancel: () => finish({ cancelled: true }),
      onOverlay: () => finish({ cancelled: true }),
    };
    window.addEventListener('keydown', handleKeydown, true);
    disconnectObserver = observeHostRemoval(surface.host, () => finish({ cancelled: true }));
    surface.render(renderPasskeyLoginPicker(state, handlers));
  });
}
