export interface DetectedLoginForm {
  id: string;
  form: HTMLFormElement | null;
  usernameInput?: HTMLInputElement;
  passwordInput: HTMLInputElement;
  anchor: HTMLElement;
}

let nextFormId = 0;

export function detectLoginForms(root: ParentNode = document): DetectedLoginForm[] {
  const passwords = Array.from(root.querySelectorAll<HTMLInputElement>('input[type="password"]'))
    .filter(isFillableInput);

  return passwords.map((passwordInput) => {
    const form = passwordInput.form;
    const container = form ?? nearestContainer(passwordInput);
    const usernameInput = findUsernameInput(container, passwordInput);
    const entry: DetectedLoginForm = {
      id: passwordInput.dataset.vwAutofillId ?? assignFormId(passwordInput),
      form,
      passwordInput,
      anchor: passwordInput,
      ...(usernameInput !== undefined ? { usernameInput } : {}),
    };
    return entry;
  });
}

export function isFillableInput(input: HTMLInputElement): boolean {
  const editable = input.type !== 'hidden' && !input.hidden && !input.disabled && !input.readOnly;
  if (!editable) return false;
  if (!isVisibleInTree(input)) return false;
  if (input.offsetParent != null) return true;
  return input.isConnected;
}

function assignFormId(input: HTMLInputElement): string {
  const id = `vw-form-${nextFormId++}`;
  input.dataset.vwAutofillId = id;
  return id;
}

function nearestContainer(input: HTMLInputElement): ParentNode {
  return input.closest('form, section, main, article') ?? document;
}

function findUsernameInput(container: ParentNode, passwordInput: HTMLInputElement): HTMLInputElement | undefined {
  const candidates = Array.from(container.querySelectorAll<HTMLInputElement>('input'))
    .filter((input) => input !== passwordInput)
    .filter(isFillableInput)
    .filter((input) => ['email', 'text', 'search', 'tel', 'url'].includes(input.type))
    .filter((input) => {
      const hint = `${input.name} ${input.id} ${input.autocomplete} ${input.getAttribute('aria-label') ?? ''}`.toLowerCase();
      return hint.includes('user') || hint.includes('email') || hint.includes('login') || input.type === 'email';
    });
  return candidates.at(-1);
}

function isVisibleInTree(input: HTMLInputElement): boolean {
  if (!input.isConnected) return false;
  const view = input.ownerDocument.defaultView;
  if (!view) return false;
  for (let element: HTMLElement | null = input; element; element = element.parentElement) {
    const style = view.getComputedStyle(element);
    if (element.hidden || style.display === 'none' || style.visibility === 'hidden') return false;
  }
  return true;
}
