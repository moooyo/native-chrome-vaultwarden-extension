import type { AutofillCredentials } from '../messaging/protocol.js';
import type { DetectedLoginForm } from './form-detection.js';
import { isFillableInput, isNewPasswordField } from './form-detection.js';
import { flashFill, flashFillCheck } from './fill-highlight.js';

export function fillLoginForm(form: DetectedLoginForm, credentials: AutofillCredentials): boolean {
  let filled = false;
  if (credentials.username && form.usernameInput && isFillableInput(form.usernameInput)) {
    setInputValue(form.usernameInput, credentials.username);
    flashFill(form.usernameInput);
    flashFillCheck(form.usernameInput);
    filled = true;
  }
  // Defense-in-depth: never write the stored password into a new-password field.
  if (credentials.password && form.passwordInput && isFillableInput(form.passwordInput) && !isNewPasswordField(form.passwordInput)) {
    setInputValue(form.passwordInput, credentials.password);
    flashFill(form.passwordInput, 130); // slight delay after the username for a sequential-fill feel
    flashFillCheck(form.passwordInput);
    filled = true;
  }
  if (credentials.totp && form.totpInput && isFillableInput(form.totpInput)) {
    setInputValue(form.totpInput, credentials.totp);
    flashFill(form.totpInput, 130);
    filled = true;
  }
  return filled;
}

export function setInputValue(input: HTMLInputElement, value: string): void {
  input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
}
