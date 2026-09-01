import { describe, expect, it } from 'vitest';

import {
  MAX_PIN_UTF16_CODE_UNITS,
  MIN_PIN_UTF16_CODE_UNITS,
  isValidPinInput,
  pinConstraintViolation,
} from './pin-constraints.js';

describe('PIN input constraints', () => {
  it('accepts the inclusive UTF-16 boundaries', () => {
    expect(isValidPinInput('a'.repeat(MIN_PIN_UTF16_CODE_UNITS))).toBe(true);
    expect(isValidPinInput('a'.repeat(MAX_PIN_UTF16_CODE_UNITS))).toBe(true);
  });

  it('rejects blank, short, oversized, and non-string input', () => {
    expect(pinConstraintViolation('    ')).toBe('blank');
    expect(pinConstraintViolation('abc')).toBe('too_short');
    expect(pinConstraintViolation('a'.repeat(MAX_PIN_UTF16_CODE_UNITS + 1))).toBe('too_long');
    expect(pinConstraintViolation(null)).toBe('not_string');
  });

  it('counts astral characters as two UTF-16 code units like DOM maxlength', () => {
    expect('😀'.length).toBe(2);
    expect(isValidPinInput('😀'.repeat(MAX_PIN_UTF16_CODE_UNITS / 2))).toBe(true);
    expect(pinConstraintViolation('😀'.repeat((MAX_PIN_UTF16_CODE_UNITS / 2) + 1)))
      .toBe('too_long');
  });
});
