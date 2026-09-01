import { describe, expect, it } from 'vitest';
import {
  GENERATOR_HISTORY_ENTRY_TYPES,
  isGeneratorHistoryEntryType,
  parseGeneratorHistoryEntries,
} from './history.js';

describe('generator history wire model', () => {
  it('accepts every closed entry type including PIN', () => {
    expect(GENERATOR_HISTORY_ENTRY_TYPES).toEqual(['password', 'passphrase', 'pin', 'username']);
    expect(GENERATOR_HISTORY_ENTRY_TYPES.every(isGeneratorHistoryEntryType)).toBe(true);
  });

  it('strictly parses and freezes exact worker entries', () => {
    const parsed = parseGeneratorHistoryEntries([
      { generatedAt: 2, type: 'pin', value: '123456' },
      { generatedAt: 1, type: 'password', value: 'secret' },
    ]);
    expect(parsed).toEqual([
      { generatedAt: 2, type: 'pin', value: '123456' },
      { generatedAt: 1, type: 'password', value: 'secret' },
    ]);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed?.[0])).toBe(true);
  });

  it.each([
    [{ generatedAt: 1, type: 'password', value: '' }],
    [{ generatedAt: 1, type: 'password', value: 'line\nbreak' }],
    [{ generatedAt: 1, type: 'email', value: 'value' }],
    [{ generatedAt: -1, type: 'password', value: 'value' }],
    [{ generatedAt: 1, type: 'password', value: 'value', extra: true }],
    [
      { generatedAt: 2, type: 'password', value: 'duplicate' },
      { generatedAt: 1, type: 'pin', value: 'duplicate' },
    ],
  ])('rejects malformed or duplicate entry data: %j', (...entries) => {
    expect(parseGeneratorHistoryEntries(entries)).toBeNull();
  });
});
