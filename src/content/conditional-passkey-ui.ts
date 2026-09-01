import {
  createAutofillPopover,
  type AutofillPopover,
  type AutofillPopoverOptions,
} from './popover.js';
import type { WebsitePasskeyDisplayChoice } from '../messaging/website-passkey-port.js';
import {
  claimInlineSurface,
  inlineSurfaceScope,
  releaseInlineSurface,
} from './inline-surface-coordinator.js';

export interface WebsitePasskeyConditionalUiBinding {
  readonly ceremonyId: string;
  readonly bridgeRequestId: string;
  readonly candidates: readonly WebsitePasskeyDisplayChoice[];
}

export interface WebsitePasskeyConditionalUi {
  activate(
    binding: WebsitePasskeyConditionalUiBinding,
    onSelect: (credentialId: string) => void,
  ): void;
  clear(ceremonyId?: string, bridgeRequestId?: string): void;
  dispose(): void;
}

type PopoverFactory = (options: AutofillPopoverOptions) => AutofillPopover;
const TRUSTED_FOCUS_RECEIPT_MS = 1_500;

interface ActiveConditionalUi extends WebsitePasskeyConditionalUiBinding {
  readonly onSelect: (credentialId: string) => void;
}

/**
 * Keeps conditional mediation dormant until an eligible WebAuthn field receives trusted user input.
 * Credential ids remain inside the closed-shadow popover and closure-owned callbacks.
 */
export function createWebsitePasskeyConditionalUi(
  ownerDocument: Document = document,
  createPopover: PopoverFactory = createAutofillPopover,
): WebsitePasskeyConditionalUi {
  let active: ActiveConditionalUi | undefined;
  let popover: AutofillPopover | undefined;
  let anchor: HTMLInputElement | undefined;
  let claimedScope: HTMLElement | undefined;
  let recentReceipt: { readonly input: HTMLInputElement; readonly expiresAt: number } | undefined;
  let keyboardFocusReceiptUntil = 0;
  let disposed = false;

  const removeSurface = (): void => {
    const current = popover;
    if (current && claimedScope) releaseInlineSurface(claimedScope, current.element);
    current?.remove();
    popover = undefined;
    anchor = undefined;
    claimedScope = undefined;
  };

  const showFor = (input: HTMLInputElement): void => {
    const current = active;
    if (!current || disposed || !isConditionalField(input, ownerDocument)) return;
    if (popover && anchor === input) {
      popover.open(input);
      return;
    }
    removeSurface();
    const nextPopover = createPopover({
      anchor: input,
      kind: 'login',
      sidePanel: true,
      candidates: current.candidates.map((candidate) => ({
        id: candidate.id,
        name: candidate.name,
        ...(candidate.username === undefined ? {} : { sub: candidate.username }),
        favorite: false,
      })),
      onOpen: () => {
        if (active !== current) return;
        nextPopover.showCandidates(current.candidates.map((candidate) => ({
          id: candidate.id,
          name: candidate.name,
          ...(candidate.username === undefined ? {} : { sub: candidate.username }),
          favorite: false,
        })));
      },
      onSelect: (credentialId) => {
        if (active !== current) return;
        active = undefined;
        removeSurface();
        current.onSelect(credentialId);
      },
    });
    popover = nextPopover;
    anchor = input;
    const scope = inlineSurfaceScope(input);
    claimedScope = scope;
    const granted = claimInlineSurface(scope, nextPopover.element, () => {
      if (popover !== nextPopover) return;
      popover = undefined;
      anchor = undefined;
      claimedScope = undefined;
      nextPopover.remove();
    }, 10);
    if (!granted) {
      popover = undefined;
      anchor = undefined;
      claimedScope = undefined;
      nextPopover.remove();
      return;
    }
    nextPopover.open(input);
  };

  const onPointerDown = (event: Event): void => {
    if (!event.isTrusted || disposed) return;
    const path = event.composedPath();
    if (popover && path.includes(popover.element)) return;
    const target = path[0];
    if (isConditionalField(target, ownerDocument)) {
      recentReceipt = { input: target, expiresAt: Date.now() + TRUSTED_FOCUS_RECEIPT_MS };
      if (active) showFor(target);
    }
    else removeSurface();
  };

  const onKeyDown = (event: Event): void => {
    if (!event.isTrusted || disposed || !(event instanceof KeyboardEvent)) return;
    const target = event.composedPath()[0];
    if (isConditionalField(target, ownerDocument)) {
      recentReceipt = { input: target, expiresAt: Date.now() + TRUSTED_FOCUS_RECEIPT_MS };
      if (active) showFor(target);
      return;
    }
    if (event.key === 'Tab') keyboardFocusReceiptUntil = Date.now() + TRUSTED_FOCUS_RECEIPT_MS;
  };

  const onFocusIn = (event: Event): void => {
    if (!event.isTrusted || disposed) return;
    const target = event.composedPath()[0];
    if (!isConditionalField(target, ownerDocument)) return;
    const now = Date.now();
    const hasRecentTargetReceipt = recentReceipt?.input === target && recentReceipt.expiresAt >= now;
    if (!hasRecentTargetReceipt && keyboardFocusReceiptUntil < now) return;
    recentReceipt = { input: target, expiresAt: now + TRUSTED_FOCUS_RECEIPT_MS };
    keyboardFocusReceiptUntil = 0;
    if (active) showFor(target);
  };

  const onPageHide = (): void => {
    active = undefined;
    recentReceipt = undefined;
    keyboardFocusReceiptUntil = 0;
    removeSurface();
  };
  ownerDocument.addEventListener('focusin', onFocusIn, true);
  ownerDocument.addEventListener('keydown', onKeyDown, true);
  ownerDocument.addEventListener('pointerdown', onPointerDown, true);
  ownerDocument.defaultView?.addEventListener('pagehide', onPageHide);

  return Object.freeze({
    activate(
      binding: WebsitePasskeyConditionalUiBinding,
      onSelect: (credentialId: string) => void,
    ) {
      if (disposed) return;
      active = Object.freeze({ ...binding, onSelect });
      removeSurface();
      const receipt = recentReceipt;
      if (receipt && receipt.expiresAt >= Date.now() && deepActiveElement(ownerDocument) === receipt.input) {
        showFor(receipt.input);
      }
    },
    clear(ceremonyId?: string, bridgeRequestId?: string) {
      if (!active) {
        removeSurface();
        return;
      }
      if (ceremonyId !== undefined && active.ceremonyId !== ceremonyId) return;
      if (bridgeRequestId !== undefined && active.bridgeRequestId !== bridgeRequestId) return;
      active = undefined;
      removeSurface();
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      active = undefined;
      removeSurface();
      ownerDocument.removeEventListener('focusin', onFocusIn, true);
      ownerDocument.removeEventListener('keydown', onKeyDown, true);
      ownerDocument.removeEventListener('pointerdown', onPointerDown, true);
      ownerDocument.defaultView?.removeEventListener('pagehide', onPageHide);
    },
  });
}

function deepActiveElement(ownerDocument: Document): Element | null {
  let active = ownerDocument.activeElement;
  const seen = new Set<Element>();
  while (active?.shadowRoot?.activeElement && !seen.has(active)) {
    seen.add(active);
    active = active.shadowRoot.activeElement;
  }
  return active;
}

function isConditionalField(
  value: EventTarget | Element | null | undefined,
  ownerDocument: Document,
): value is HTMLInputElement {
  const Input = ownerDocument.defaultView?.HTMLInputElement;
  if (!Input || !(value instanceof Input)) return false;
  if (!value.isConnected || value.disabled || value.readOnly || value.closest('[inert]')) return false;
  if (!['email', 'search', 'tel', 'text', 'url'].includes(value.type)) return false;
  return value.autocomplete.toLowerCase().split(/\s+/).includes('webauthn');
}
