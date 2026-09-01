/**
 * PIN length is measured in UTF-16 code units, matching JavaScript `string.length` and the HTML
 * `maxlength` algorithm. This keeps the protocol, worker, and DOM boundary deterministic without
 * allocating a UTF-8 copy before rejecting oversized input.
 */
export const MIN_PIN_UTF16_CODE_UNITS = 4;
export const MAX_PIN_UTF16_CODE_UNITS = 256;

export type PinConstraintViolation = 'not_string' | 'blank' | 'too_short' | 'too_long';

export function pinConstraintViolation(value: unknown): PinConstraintViolation | undefined {
  if (typeof value !== 'string') return 'not_string';
  // Reject by the allocation-free code-unit length check before trimming or encoding input.
  if (value.length > MAX_PIN_UTF16_CODE_UNITS) return 'too_long';
  if (!value.trim()) return 'blank';
  if (value.length < MIN_PIN_UTF16_CODE_UNITS) return 'too_short';
  return undefined;
}

export function isValidPinInput(value: unknown): value is string {
  return pinConstraintViolation(value) === undefined;
}

export function pinConstraintMessage(violation: PinConstraintViolation): string {
  return violation === 'too_long'
    ? `PIN must contain at most ${MAX_PIN_UTF16_CODE_UNITS} characters (measured as UTF-16 code units).`
    : `PIN must contain at least ${MIN_PIN_UTF16_CODE_UNITS} characters (measured as UTF-16 code units).`;
}
