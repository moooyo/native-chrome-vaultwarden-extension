import { describe, expect, it } from 'vitest';
import { isIsoTimestamp, isOptionalNullableIsoTimestamp } from './iso-date.js';

describe('ISO timestamp validation', () => {
  it.each([
    '2024-02-29T23:59:59Z',
    '2000-02-29T00:00:00.1234567+14:00',
    '2026-08-30T01:02:03.1-05:30',
  ])('accepts a valid bounded timestamp: %s', (value) => {
    expect(isIsoTimestamp(value)).toBe(true);
  });

  it.each([
    '2026-02-30T03:04:05Z',
    '2025-02-29T03:04:05Z',
    '1900-02-29T03:04:05Z',
    '2026-01-01T00:00:00+14:01',
    '2026-01-01T00:00:00-15:00',
    '2026-01-01T24:00:00Z',
    '2026-01-01',
  ])('rejects an invalid calendar or offset timestamp: %s', (value) => {
    expect(isIsoTimestamp(value)).toBe(false);
  });

  it('accepts absent and null optional values without accepting other scalar types', () => {
    expect(isOptionalNullableIsoTimestamp(undefined)).toBe(true);
    expect(isOptionalNullableIsoTimestamp(null)).toBe(true);
    expect(isOptionalNullableIsoTimestamp(false)).toBe(false);
  });
});
