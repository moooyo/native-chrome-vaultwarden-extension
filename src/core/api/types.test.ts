import { describe, it, expect } from 'vitest';
import type { LoginSuccessResponse, PreloginResponse, SyncResponse, CipherResponse } from './types.js';

describe('api types casing', () => {
  it('keeps prelogin camelCase and login PascalCase distinct', () => {
    const prelogin: PreloginResponse = { kdf: 0, kdfIterations: 600000 };
    const login: LoginSuccessResponse = {
      access_token: 'a',
      expires_in: 3600,
      refresh_token: 'r',
      token_type: 'Bearer',
      Key: '2.iv|ct|mac',
      Kdf: 0,
      KdfIterations: 600000,
    };
    expect(prelogin.kdfIterations).toBe(600000);
    expect(login.Key).toBe('2.iv|ct|mac');
  });

  it('models camelCase sync ciphers', () => {
    const cipher: CipherResponse = {
      id: 'cipher-1',
      type: 1,
      name: '2.n|c|m',
      favorite: false,
      organizationId: null,
      login: { username: '2.u|c|m', password: '2.p|c|m', uris: [{ uri: '2.uri|c|m' }] },
    };
    const sync: SyncResponse = { profile: { id: 'user-1', email: 'user@example.com' }, ciphers: [cipher] };
    expect(sync.ciphers[0]?.login?.uris?.[0]?.uri).toBe('2.uri|c|m');
  });
});
