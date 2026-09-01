import {
  detectLoginForms,
  captureControlOwner,
  composedParentElement,
  hasCurrentPasswordAutocomplete,
  hasSameControlOwner,
  inputControlsInScope,
  isFillableInput,
  isVisibleInTree,
  type DetectedLoginForm,
  type ControlOwnerSnapshot,
} from './form-detection.js';

export interface PageLoadLoginTarget {
  readonly form: DetectedLoginForm;
  readonly formId: string;
  readonly root: ParentNode;
  readonly passwordInput: HTMLInputElement;
  readonly passwordOwner: ControlOwnerSnapshot;
  readonly usernameInput?: HTMLInputElement;
  readonly usernameOwner?: ControlOwnerSnapshot;
}

export type PageLoadRoots = ParentNode | readonly ParentNode[];

export interface PageLoadRootSnapshot {
  readonly roots: readonly ParentNode[];
  readonly truncated: boolean;
}

/** Automatic fill must never act on a partial composed-tree inventory. */
export function selectPageLoadLoginTargetFromSnapshot(
  snapshot: PageLoadRootSnapshot,
  ownerDocument: Document = document,
): PageLoadLoginTarget | undefined {
  return snapshot.truncated ? undefined : selectPageLoadLoginTarget(snapshot.roots, ownerDocument);
}

/** Return the sole safe automatic-fill target, or undefined on any ambiguity. */
export function selectPageLoadLoginTarget(
  root: PageLoadRoots = document,
  ownerDocument: Document = document,
): PageLoadLoginTarget | undefined {
  if (ownerDocument.visibilityState !== 'visible') return undefined;
  const roots = normalizeRoots(root);
  const documentPasswords = fillablePasswords(roots);
  const matches = roots.flatMap((candidateRoot) => detectLoginForms(candidateRoot)).flatMap((form) => {
    const passwordInput = form.passwordInput;
    if (
      !passwordInput
      || !hasCurrentPasswordAutocomplete(passwordInput)
      || passwordInput.value
      || (form.form
        ? !hasSingleFillablePassword(form.form)
        : documentPasswords.length !== 1 || documentPasswords[0] !== passwordInput)
      || !isStrictlyVisible(passwordInput, ownerDocument)
    ) return [];
    const usernameInput = form.usernameInput;
    if (usernameInput && (usernameInput.value || !isStrictlyVisible(usernameInput, ownerDocument))) return [];
    const passwordOwner = captureControlOwner(passwordInput);
    const usernameOwner = usernameInput ? captureControlOwner(usernameInput) : undefined;
    return [{
      form,
      formId: form.id,
      root: passwordInput.getRootNode() as ParentNode,
      passwordInput,
      passwordOwner,
      ...(usernameInput ? { usernameInput } : {}),
      ...(usernameOwner ? { usernameOwner } : {}),
    }];
  });
  return matches.length === 1 ? matches[0] : undefined;
}

/** Re-detect after every worker round trip and require the exact same empty, live field objects. */
export function isPageLoadLoginTargetCurrent(
  target: PageLoadLoginTarget,
  root: PageLoadRoots = document,
  ownerDocument: Document = document,
  options: { allowUsernameValue?: boolean; allowPasswordValue?: boolean } = {},
): boolean {
  if (!target.passwordInput.isConnected || target.passwordInput.ownerDocument !== ownerDocument) return false;
  if (target.usernameInput && (!target.usernameInput.isConnected || target.usernameInput.ownerDocument !== ownerDocument)) return false;
  if (ownerDocument.visibilityState !== 'visible' || (!options.allowPasswordValue && target.passwordInput.value)) return false;
  if (target.usernameInput && !options.allowUsernameValue && target.usernameInput.value) return false;
  if (!hasSameControlOwner(target.passwordOwner, captureControlOwner(target.passwordInput))) return false;
  if (target.usernameInput && (
    !target.usernameOwner
    || !hasSameControlOwner(target.usernameOwner, captureControlOwner(target.usernameInput))
  )) return false;
  const roots = normalizeRoots(root);
  const documentPasswords = fillablePasswords(roots);
  const current = roots.flatMap((candidateRoot) => detectLoginForms(candidateRoot)).filter((form) => (
    form.form === target.form.form
    && form.id === target.formId
    && form.anchor.getRootNode() === target.root
    && form.passwordInput === target.passwordInput
    && form.usernameInput === target.usernameInput
    && hasCurrentPasswordAutocomplete(target.passwordInput)
    && (form.form
      ? hasSingleFillablePassword(form.form)
      : documentPasswords.length === 1 && documentPasswords[0] === target.passwordInput)
    && isStrictlyVisible(target.passwordInput, ownerDocument)
    && (!target.usernameInput || isStrictlyVisible(target.usernameInput, ownerDocument))
  ));
  return current.length === 1;
}

function fillablePasswords(roots: readonly ParentNode[]): readonly HTMLInputElement[] {
  const passwords = new Set<HTMLInputElement>();
  for (const root of roots) {
    for (const input of root.querySelectorAll<HTMLInputElement>('input[type="password"]')) {
      if (isFillableInput(input)) passwords.add(input);
    }
  }
  return [...passwords];
}

function hasSingleFillablePassword(form: HTMLFormElement): boolean {
  return inputControlsInScope(form)
    .filter((input) => input.type === 'password' && isFillableInput(input)).length === 1;
}

function isStrictlyVisible(input: HTMLInputElement, ownerDocument: Document): boolean {
  if (!isFillableInput(input) || !isVisibleInTree(input)) return false;
  const view = ownerDocument.defaultView;
  if (!view || view.innerWidth <= 0 || view.innerHeight <= 0) return false;
  for (let element: Element | null = input; element; element = composedParentElement(element)) {
    if (element.hasAttribute('inert') || element.getAttribute('aria-hidden') === 'true') return false;
    const style = view.getComputedStyle(element);
    const opacity = Number(style.opacity || '1');
    if (Number.isFinite(opacity) && opacity <= 0) return false;
    if (style.contentVisibility === 'hidden') return false;
  }
  return Array.from(input.getClientRects()).some((rect) => (
    rect.width > 0
    && rect.height > 0
    && rect.right > 0
    && rect.bottom > 0
    && rect.left < view.innerWidth
    && rect.top < view.innerHeight
  ));
}

function normalizeRoots(roots: PageLoadRoots): readonly ParentNode[] {
  return Array.isArray(roots) ? roots : [roots as ParentNode];
}
