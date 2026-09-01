import { describe, expect, it, vi } from 'vitest';
import {
  createContextMenuCreateIntent,
  parseContextMenuCreateIntent,
} from './context-menu-create.js';

describe('context menu create intent', () => {
  it('maps each supported kind and carries a browser-owned URI only for logins', () => {
    vi.spyOn(crypto, 'randomUUID').mockReturnValue('11111111-1111-4111-8111-111111111111');
    expect(createContextMenuCreateIntent('login', 'https://example.com/login?step=2')).toEqual({
      type: 'contextMenu.openCreateCipher',
      intentId: '11111111-1111-4111-8111-111111111111',
      cipherType: 1,
      loginUri: 'https://example.com/login?step=2',
    });
    expect(createContextMenuCreateIntent('card', 'https://example.com/')).toMatchObject({ cipherType: 3 });
    expect(createContextMenuCreateIntent('identity', 'https://example.com/')).toMatchObject({ cipherType: 4 });
    expect(createContextMenuCreateIntent('card', 'https://example.com/')).not.toHaveProperty('loginUri');
  });

  it('strictly parses exact intents and rejects injected or non-web values', () => {
    const valid = {
      type: 'contextMenu.openCreateCipher',
      intentId: '11111111-1111-4111-8111-111111111111',
      cipherType: 1,
      loginUri: 'https://example.com/',
    };
    expect(parseContextMenuCreateIntent(valid)).toEqual(valid);
    expect(parseContextMenuCreateIntent({ ...valid, extra: true })).toBeUndefined();
    expect(parseContextMenuCreateIntent({ ...valid, loginUri: 'javascript:alert(1)' })).toBeUndefined();
    expect(parseContextMenuCreateIntent({ ...valid, cipherType: 3 })).toBeUndefined();
    expect(parseContextMenuCreateIntent({ ...valid, intentId: 'not-a-uuid' })).toBeUndefined();
  });
});
