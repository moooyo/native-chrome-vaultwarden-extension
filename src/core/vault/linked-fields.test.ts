import { describe, expect, it } from 'vitest';
import { isSupportedLinkedFieldId, linkedFieldOptionsForCipherType } from './linked-fields.js';

describe('linked field catalog', () => {
  it('exposes only official targets for linkable cipher types', () => {
    expect(linkedFieldOptionsForCipherType(1)).toEqual([
      { id: 100, source: 'username' },
      { id: 101, source: 'password' },
    ]);
    expect(linkedFieldOptionsForCipherType(3).map(({ id }) => id)).toEqual([300, 305, 304, 301, 302, 303]);
    expect(linkedFieldOptionsForCipherType(4).map(({ id }) => id)).toEqual([
      400, 416, 401, 418, 417, 413, 409, 412, 414, 415, 410, 411, 402, 403, 404, 405, 406, 407, 408,
    ]);
    expect(linkedFieldOptionsForCipherType(2)).toEqual([]);
    expect(linkedFieldOptionsForCipherType(5)).toEqual([]);
  });

  it('rejects cross-type, unknown, fractional, and non-number identifiers', () => {
    expect(isSupportedLinkedFieldId(1, 100)).toBe(true);
    expect(isSupportedLinkedFieldId(1, 300)).toBe(false);
    expect(isSupportedLinkedFieldId(3, 300)).toBe(true);
    expect(isSupportedLinkedFieldId(4, 418)).toBe(true);
    expect(isSupportedLinkedFieldId(4, 999)).toBe(false);
    expect(isSupportedLinkedFieldId(4, 410.5)).toBe(false);
    expect(isSupportedLinkedFieldId(4, '410')).toBe(false);
  });
});
