import type { AutofillCredentials } from '../messaging/protocol.js';
import type { DetectedLoginForm } from './form-detection.js';
import { isFillableInput, isNewPasswordField } from './form-detection.js';

export function fillLoginForm(form: DetectedLoginForm, credentials: AutofillCredentials): boolean {
  let filled = false;
  if (credentials.username && form.usernameInput && isFillableInput(form.usernameInput)) {
    setInputValue(form.usernameInput, credentials.username);
    filled = true;
  }
  // Defense-in-depth: never write the stored password into a new-password field.
  if (credentials.password && form.passwordInput && isFillableInput(form.passwordInput) && !isNewPasswordField(form.passwordInput)) {
    setInputValue(form.passwordInput, credentials.password);
    filled = true;
  }
  return filled;
}

function setInputValue(input: HTMLInputElement, value: string): void {
  input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
}
