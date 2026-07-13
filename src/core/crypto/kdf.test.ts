import { describe, it, expect } from 'vitest';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey, assertKdfIterationsFloor, MIN_PBKDF2_ITERATIONS } from './kdf.js';
import { symmetricKeyFromBytes } from './keys.js';
import { bytesToHex, hexToBytes } from './encoding.js';
import { KDF_VECTOR, STRETCH_VECTOR } from '../../../test/vectors.js';

describe('kdf', () => {
  it('derives the master key from password + email salt', async () => {
    const mk = await deriveMasterKey(KDF_VECTOR.password, KDF_VECTOR.email, KDF_VECTOR.iterations);
    expect(bytesToHex(mk)).toBe(KDF_VECTOR.masterKeyHex);
  });

  it('uppercase email yields the same master key (salt is lowercased)', async () => {
    const mk = await deriveMasterKey(KDF_VECTOR.password, 'USER@EXAMPLE.COM', KDF_VECTOR.iterations);
    expect(bytesToHex(mk)).toBe(KDF_VECTOR.masterKeyHex);
  });

  it('derives the master password hash (base64, salt=password, one iteration)', async () => {
    const mk = hexToBytes(KDF_VECTOR.masterKeyHex);
    expect(await deriveMasterPasswordHash(mk, KDF_VECTOR.password)).toBe(KDF_VECTOR.masterPasswordHashB64);
  });

  it('stretches the master key via HKDF-Expand into enc+mac halves', async () => {
    const stretched = await stretchMasterKey(hexToBytes(KDF_VECTOR.masterKeyHex));
    expect(bytesToHex(stretched.encKey)).toBe(STRETCH_VECTOR.encKeyHex);
    expect(bytesToHex(stretched.macKey)).toBe(STRETCH_VECTOR.macKeyHex);
  });

  it('symmetricKeyFromBytes splits 64 bytes into 32/32', () => {
    const sk = symmetricKeyFromBytes(hexToBytes('aa'.repeat(32) + 'bb'.repeat(32)));
    expect(bytesToHex(sk.encKey)).toBe('aa'.repeat(32));
    expect(bytesToHex(sk.macKey)).toBe('bb'.repeat(32));
    expect(() => symmetricKeyFromBytes(hexToBytes('aa'.repeat(32)))).toThrow('symmetric key must be 64 bytes');
  });

  it('MIN_PBKDF2_ITERATIONS equals 5000', () => {
    expect(MIN_PBKDF2_ITERATIONS).toBe(5000);
  });

  it('assertKdfIterationsFloor throws below MIN and on non-integer, passes at/above MIN', () => {
    expect(() => assertKdfIterationsFloor(4999)).toThrow(/unsafe KDF iteration count/);
    expect(() => assertKdfIterationsFloor(1.5)).toThrow(/unsafe KDF iteration count/);
    expect(() => assertKdfIterationsFloor(Number.NaN)).toThrow(/unsafe KDF iteration count/);
    expect(() => assertKdfIterationsFloor(5000)).not.toThrow();
    expect(() => assertKdfIterationsFloor(600000)).not.toThrow();
  });
});
