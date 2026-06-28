import { describe, it, expect } from 'vitest';
import { buildRegistration } from './registration.js';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey } from './kdf.js';
import { unwrapSymmetricKey, decryptPrivateKey } from './keys.js';
import { base64ToBytes } from './encoding.js';

const subtle = globalThis.crypto.subtle;

describe('buildRegistration', () => {
  const email = 'newuser@example.com';
  const password = 'Sup3r-Secret-Master!';
  const iterations = 600000;

  it('produces a master password hash matching the KDF derivation', async () => {
    const reg = await buildRegistration(email, password, iterations);
    const masterKey = await deriveMasterKey(password, email, iterations);
    expect(reg.masterPasswordHash).toBe(await deriveMasterPasswordHash(masterKey, password));
    expect(reg.kdf).toBe(0);
    expect(reg.kdfIterations).toBe(iterations);
  });

  it('wraps a 64-byte UserKey under the stretched master key (unwraps back cleanly)', async () => {
    const reg = await buildRegistration(email, password, iterations);
    const masterKey = await deriveMasterKey(password, email, iterations);
    const stretched = await stretchMasterKey(masterKey);
    const userKey = await unwrapSymmetricKey(reg.key, stretched);
    expect(userKey.encKey.length).toBe(32);
    expect(userKey.macKey.length).toBe(32);
  });

  it('wraps an RSA private key that decrypts under the UserKey and matches the public key', async () => {
    const reg = await buildRegistration(email, password, iterations);
    const masterKey = await deriveMasterKey(password, email, iterations);
    const userKey = await unwrapSymmetricKey(reg.key, await stretchMasterKey(masterKey));
    const pkcs8 = await decryptPrivateKey(reg.keys.encryptedPrivateKey, userKey);

    // The decrypted private key and the published public key form a working RSA-OAEP pair.
    const priv = await subtle.importKey('pkcs8', pkcs8 as BufferSource, { name: 'RSA-OAEP', hash: 'SHA-1' }, false, ['decrypt']);
    const pub = await subtle.importKey('spki', base64ToBytes(reg.keys.publicKey) as BufferSource, { name: 'RSA-OAEP', hash: 'SHA-1' }, false, ['encrypt']);
    const msg = new TextEncoder().encode('hello');
    const ct = await subtle.encrypt({ name: 'RSA-OAEP' }, pub, msg as BufferSource);
    const pt = new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, priv, ct));
    expect(new TextDecoder().decode(pt)).toBe('hello');
  });

  it('generates a fresh UserKey each call', async () => {
    const a = await buildRegistration(email, password, iterations);
    const b = await buildRegistration(email, password, iterations);
    expect(a.key).not.toBe(b.key);
  });
});
