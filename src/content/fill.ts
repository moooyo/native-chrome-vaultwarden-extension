import type { AutofillLoginData } from '../messaging/protocol.js';
import type { DetectedLoginForm } from './form-detection.js';
import {
  composedParentElement,
  isFillableInput,
  isNewPasswordField,
  isSingleCharacterInput,
  resolveTotpInputs,
} from './form-detection.js';
import { flashFill, flashFillCheck } from './fill-highlight.js';
import { setElementValue } from './native-set-value.js';
import { createStagedFillCommit, type StagedFillCommit } from './staged-fill.js';
import type { AutofillDetectionContext } from './autofill-detection-context.js';

interface TotpFillBinding {
  readonly code: string;
  readonly ownerDocument: Document;
  readonly root: Node;
  readonly form: HTMLFormElement | null;
  readonly inputs: readonly HTMLInputElement[];
  readonly composedPaths: readonly (readonly Element[])[];
}

const totpFillReceipts = new WeakMap<HTMLInputElement, TotpFillBinding>();

export function fillLoginForm(
  form: DetectedLoginForm,
  login: AutofillLoginData,
  staged: StagedFillCommit = createStagedFillCommit(),
): boolean {
  let filled = false;
  if (login.username && form.usernameInput && isFillableInput(form.usernameInput)) {
    const usernameInput = form.usernameInput;
    const wrote = staged.write(() => {
      if (!isFillableInput(usernameInput)) return false;
      setInputValue(usernameInput, login.username!);
      return true;
    });
    if (wrote && !staged.stale) {
      flashFill(usernameInput);
      flashFillCheck(usernameInput);
      filled = true;
    }
  }
  if (staged.stale) return filled;
  // Defense-in-depth: never write the stored password into a new-password field.
  if (login.password && form.passwordInput && isFillableInput(form.passwordInput) && !isNewPasswordField(form.passwordInput)) {
    const passwordInput = form.passwordInput;
    const wrote = staged.write(() => {
      if (!isFillableInput(passwordInput) || isNewPasswordField(passwordInput)) return false;
      setInputValue(passwordInput, login.password!);
      return true;
    });
    if (wrote && !staged.stale) {
      flashFill(passwordInput, 130); // slight delay after the username for a sequential-fill feel
      flashFillCheck(passwordInput);
      filled = true;
    }
  }
  return filled;
}

export function setInputValue(input: HTMLInputElement, value: string): void {
  setElementValue(input, value);
}

/** Fill a one-time code, distributing it only across an exact, stable split-input group. */
export function fillTotpCode(
  input: HTMLInputElement,
  code: string,
  revalidate: () => boolean = () => true,
  context?: AutofillDetectionContext,
): boolean {
  totpFillReceipts.delete(input);
  const characters = Array.from(code);
  if (characters.length === 0) return false;
  const inputs = resolveTotpInputs(input, context);
  if (!inputs) return false;
  const binding = captureTotpFillBinding(input, inputs, code);
  const staged = createStagedFillCommit(() => (
    revalidate() && totpBindingCurrent(input, binding)
  ));
  if (inputs.length === 1) {
    if (isSingleCharacterInput(input) && characters.length !== 1) return false;
    if (input.maxLength > 0 && characters.length > input.maxLength) return false;
    if (!staged.write(() => {
      setInputValue(input, code);
      return true;
    }) || staged.stale || !staged.isCurrent()) return false;
    totpFillReceipts.set(input, binding);
    return true;
  }
  if (inputs.length !== characters.length) return false;
  for (let index = 0; index < inputs.length; index += 1) {
    if (!staged.write(() => {
      setInputValue(inputs[index]!, characters[index]!);
      return true;
    }) || staged.stale) return false;
  }
  if (!staged.isCurrent()) return false;
  totpFillReceipts.set(input, binding);
  return true;
}

/** Clear unchanged values from a prior TOTP fill without expanding to a new group or erasing edits. */
export function clearTotpCode(input: HTMLInputElement, code: string): boolean {
  const binding = totpFillReceipts.get(input);
  totpFillReceipts.delete(input);
  if (!binding || binding.code !== code || !totpBindingCurrent(input, binding)) return false;
  const writtenValues = binding.inputs.length === 1 ? [binding.code] : Array.from(binding.code);
  let cleared = false;
  for (const [index, target] of binding.inputs.entries()) {
    if (!totpBindingCurrent(input, binding)) return false;
    // A later user edit, including edits triggered by an earlier undo event, owns this field now.
    if (target.value !== writtenValues[index]) continue;
    setInputValue(target, '');
    cleared = true;
    if (!totpBindingCurrent(input, binding)) return false;
  }
  return cleared;
}

function sameInputs(first: readonly HTMLInputElement[], second: readonly HTMLInputElement[]): boolean {
  return first.length === second.length && first.every((candidate, index) => candidate === second[index]);
}

function captureTotpFillBinding(
  input: HTMLInputElement,
  inputs: readonly HTMLInputElement[],
  code: string,
): TotpFillBinding {
  return {
    code,
    ownerDocument: input.ownerDocument,
    root: input.getRootNode(),
    form: input.form,
    inputs: [...inputs],
    composedPaths: inputs.map(composedElementPath),
  };
}

function totpBindingCurrent(input: HTMLInputElement, binding: TotpFillBinding): boolean {
  const current = resolveTotpInputs(input);
  return input.ownerDocument === binding.ownerDocument
    && input.getRootNode() === binding.root
    && input.form === binding.form
    && current !== undefined
    && sameInputs(binding.inputs, current)
    && binding.inputs.every((candidate, index) => (
      candidate.ownerDocument === binding.ownerDocument
      && candidate.getRootNode() === binding.root
      && candidate.form === binding.form
      && sameElements(binding.composedPaths[index] ?? [], composedElementPath(candidate))
    ));
}

function composedElementPath(element: Element): readonly Element[] {
  const path: Element[] = [];
  for (let current: Element | null = element; current; current = composedParentElement(current)) {
    path.push(current);
  }
  return path;
}

function sameElements(first: readonly Element[], second: readonly Element[]): boolean {
  return first.length === second.length && first.every((element, index) => element === second[index]);
}
