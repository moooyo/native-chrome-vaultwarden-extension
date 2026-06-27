import { describe, it, expect, vi } from 'vitest';
import { createMemoryStore } from './store.js';

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: {
        get: vi.fn(),
        set: vi.fn(),
        remove: vi.fn(),
        clear: vi.fn(),
      },
      session: {
        get: vi.fn(),
        set: vi.fn(),
        remove: vi.fn(),
        clear: vi.fn(),
      },
    },
  },
}));

describe('memory store', () => {
  it('round-trips values and isolates keys', async () => {
    const s = createMemoryStore();
    expect(await s.get('missing')).toBeUndefined();
    await s.set('a', { n: 1 });
    expect(await s.get<{ n: number }>('a')).toEqual({ n: 1 });
    await s.remove('a');
    expect(await s.get('a')).toBeUndefined();
  });

  it('clear empties the store', async () => {
    const s = createMemoryStore();
    await s.set('a', 1);
    await s.set('b', 2);
    await s.clear();
    expect(await s.get('a')).toBeUndefined();
    expect(await s.get('b')).toBeUndefined();
  });

  it('deep-clones on write so later mutation does not leak in', async () => {
    const s = createMemoryStore();
    const obj = { n: 1 };
    await s.set('a', obj);
    obj.n = 99;
    expect(await s.get<{ n: number }>('a')).toEqual({ n: 1 });
  });
});
