export const AUTOFILL_IGNORE_ATTRIBUTE = 'data-bwignore';

/** Bitwarden-compatible per-control opt-out. Attribute presence is authoritative. */
export function isAutofillIgnored(element: Element): boolean {
  return element.hasAttribute(AUTOFILL_IGNORE_ATTRIBUTE);
}
