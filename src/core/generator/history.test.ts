import { describe, it, expect } from 'vitest';
import { addPasswordToHistory, MAX_PASSWORD_HISTORY } from './history.js';

describe('addPasswordToHistory', () => {
  it('prepends the new password as the most recent entry', () => {
    expect(addPasswordToHistory(['a'], 'b')).toEqual(['b', 'a']);
  });

  it('moves an existing entry to the front instead of duplicating it', () => {
    expect(addPasswordToHistory(['a', 'b', 'c'], 'b')).toEqual(['b', 'a', 'c']);
  });

  it('caps the history at the maximum length, dropping the oldest', () => {
    const full = Array.from({ length: MAX_PASSWORD_HISTORY }, (_, i) => `p${i}`);
    const next = addPasswordToHistory(full, 'newest');
    expect(next).toHaveLength(MAX_PASSWORD_HISTORY);
    expect(next[0]).toBe('newest');
    expect(next).not.toContain(`p${MAX_PASSWORD_HISTORY - 1}`);
  });

  it('honors a custom maximum', () => {
    expect(addPasswordToHistory(['a', 'b'], 'c', 2)).toEqual(['c', 'a']);
  });

  it('ignores an empty password and returns a copy of the history', () => {
    const history = ['a'];
    const result = addPasswordToHistory(history, '');
    expect(result).toEqual(['a']);
    expect(result).not.toBe(history);
  });

  it('does not mutate the input history', () => {
    const history = ['a', 'b'];
    addPasswordToHistory(history, 'c');
    expect(history).toEqual(['a', 'b']);
  });
});
