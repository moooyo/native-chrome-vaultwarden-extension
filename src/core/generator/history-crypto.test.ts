import { describe, expect, it } from 'vitest';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { createUserKeyGeneratorHistoryCrypto } from './history-crypto.js';

const SCOPE_A = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const SCOPE_B = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

function userKey() {
  return symmetricKeyFromBytes(Uint8Array.from({ length: 64 }, (_, index) => index + 1));
}

describe('generator history UserKey crypto', () => {
  it('round-trips bytes under an account-and-purpose-separated key without mutating the UserKey', async () => {
    const key = userKey();
    const beforeEnc = key.encKey.slice();
    const beforeMac = key.macKey.slice();
    const crypto = createUserKeyGeneratorHistoryCrypto(key);
    const plaintext = new TextEncoder().encode('{"secret":"correct horse"}');

    const ciphertext = await crypto.encrypt(SCOPE_A, plaintext);
    const recovered = await crypto.decrypt(SCOPE_A, ciphertext);

    expect(new TextDecoder().decode(recovered)).toBe('{"secret":"correct horse"}');
    expect(ciphertext).not.toContain('correct horse');
    expect(key.encKey).toEqual(beforeEnc);
    expect(key.macKey).toEqual(beforeMac);
    plaintext.fill(0);
    recovered.fill(0);
  });

  it('does not permit ciphertext substitution between scope digests', async () => {
    const crypto = createUserKeyGeneratorHistoryCrypto(userKey());
    const plaintext = new TextEncoder().encode('scope-bound');
    const ciphertext = await crypto.encrypt(SCOPE_A, plaintext);
    plaintext.fill(0);

    await expect(crypto.decrypt(SCOPE_B, ciphertext)).rejects.toThrow();
  });

  it('rejects malformed scope digests, keys, plaintext, and ciphertext', async () => {
    expect(() => createUserKeyGeneratorHistoryCrypto({
      encKey: new Uint8Array(31),
      macKey: new Uint8Array(32),
    })).toThrow(/64-byte UserKey/);

    const crypto = createUserKeyGeneratorHistoryCrypto(userKey());
    await expect(crypto.encrypt('not-a-digest', new Uint8Array())).rejects.toThrow(/scope digest/);
    await expect(crypto.encrypt(SCOPE_A, 'plaintext' as never)).rejects.toThrow(/bytes/);
    await expect(crypto.decrypt(SCOPE_A, '')).rejects.toThrow(/non-empty/);
  });
});
