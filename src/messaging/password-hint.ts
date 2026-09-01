export interface PasswordHintRequest {
  readonly type: 'auth.requestPasswordHint';
  readonly email: string;
}

/** Accept only the destination-free password-hint command carried by the Popup. */
export function isExactPasswordHintRequest(input: unknown): input is PasswordHintRequest {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) return false;
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return false;
  const keys = Reflect.ownKeys(input);
  if (keys.length !== 2 || keys.some((key) => key !== 'type' && key !== 'email')) return false;
  const typeDescriptor = Object.getOwnPropertyDescriptor(input, 'type');
  const emailDescriptor = Object.getOwnPropertyDescriptor(input, 'email');
  return typeDescriptor?.enumerable === true
    && 'value' in typeDescriptor
    && typeDescriptor.value === 'auth.requestPasswordHint'
    && emailDescriptor?.enumerable === true
    && 'value' in emailDescriptor
    && typeof emailDescriptor.value === 'string';
}
