import { describe, expect, it } from 'vitest';
import {
  assertKdfConfig,
  assertKdfConfigForSetting,
  deriveKdfMaterial,
  deriveMasterKey,
  deriveMasterPasswordHash,
  MAX_ARGON2_ITERATIONS,
  MAX_ARGON2_MEMORY_MIB,
  MAX_ARGON2_PARALLELISM,
  MAX_PBKDF2_ITERATIONS,
  MIN_ARGON2_ITERATIONS,
  MIN_ARGON2_MEMORY_MIB,
  MIN_ARGON2_PARALLELISM,
  MIN_PBKDF2_ITERATIONS,
  parseKdfConfig,
  sameKdfConfig,
  stretchMasterKey,
} from './kdf.js';
import { symmetricKeyFromBytes } from './keys.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from './encoding.js';
import {
  ARGON2_EXPORT_KDF_VECTOR,
  ARGON2_KDF_VECTOR,
  KDF_VECTOR,
  KDF_VECTOR_600K,
  STRETCH_VECTOR,
} from '../../../test/vectors.js';

describe('kdf', () => {
  const pbkdf2 = { kdf: 0, kdfIterations: KDF_VECTOR_600K.iterations } as const;

  it('derives a PBKDF2 master key from the normalized email salt', async () => {
    const mk = await deriveMasterKey(KDF_VECTOR_600K.password, KDF_VECTOR_600K.email, pbkdf2);
    expect(bytesToHex(mk)).toBe(KDF_VECTOR_600K.masterKeyHex);
    const upper = await deriveMasterKey(KDF_VECTOR_600K.password, 'USER@EXAMPLE.COM', pbkdf2);
    expect(bytesToHex(upper)).toBe(KDF_VECTOR_600K.masterKeyHex);
  });

  it('matches the official Bitwarden Argon2id master-key and password-hash vectors', async () => {
    const mk = await deriveMasterKey(
      ARGON2_KDF_VECTOR.password,
      ARGON2_KDF_VECTOR.email,
      ARGON2_KDF_VECTOR.config,
    );
    expect(bytesToHex(mk)).toBe(ARGON2_KDF_VECTOR.masterKeyHex);
    expect(await deriveMasterPasswordHash(mk, ARGON2_KDF_VECTOR.password))
      .toBe(ARGON2_KDF_VECTOR.masterPasswordHashB64);
  });

  it('pre-hashes arbitrary Argon2 salt bytes for password-protected exports', async () => {
    const material = await deriveKdfMaterial(
      ARGON2_EXPORT_KDF_VECTOR.password,
      utf8ToBytes(ARGON2_EXPORT_KDF_VECTOR.salt),
      ARGON2_EXPORT_KDF_VECTOR.config,
    );
    expect(bytesToHex(material)).toBe(ARGON2_EXPORT_KDF_VECTOR.materialHex);
  });

  it('derives the master password hash with the password as the one-round PBKDF2 salt', async () => {
    const mk = hexToBytes(KDF_VECTOR.masterKeyHex);
    expect(await deriveMasterPasswordHash(mk, KDF_VECTOR.password)).toBe(KDF_VECTOR.masterPasswordHashB64);
  });

  it('stretches the master key via HKDF-Expand into enc and mac halves', async () => {
    const stretched = await stretchMasterKey(hexToBytes(KDF_VECTOR.masterKeyHex));
    expect(bytesToHex(stretched.encKey)).toBe(STRETCH_VECTOR.encKeyHex);
    expect(bytesToHex(stretched.macKey)).toBe(STRETCH_VECTOR.macKeyHex);
  });

  it('parses canonical, PascalCase, rotation, and legacy PBKDF2 wire shapes', () => {
    expect(parseKdfConfig({ kdf: 0, kdfIterations: 600_000 }))
      .toEqual({ kdf: 0, kdfIterations: 600_000 });
    expect(parseKdfConfig({ Kdf: 1, KdfIterations: 3, KdfMemory: 64, KdfParallelism: 4 }))
      .toEqual({ kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 });
    expect(parseKdfConfig({ KdfType: 1, Iterations: 3, Memory: 64, Parallelism: 4 }))
      .toEqual({ kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 });
    expect(parseKdfConfig({ kdfType: 1, iterations: 3, memory: 64, parallelism: 4 }))
      .toEqual({ kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 });
    expect(parseKdfConfig({ kdfIterations: 600_000 }))
      .toEqual({ kdf: 0, kdfIterations: 600_000 });
  });

  it('rejects conflicting aliases and PBKDF2 configurations carrying Argon2 fields', () => {
    expect(() => parseKdfConfig({ kdf: 0, Kdf: 1, kdfIterations: 600_000 }))
      .toThrow(/Conflicting KDF fields/);
    expect(() => parseKdfConfig({ kdf: 0, kdfIterations: 600_000, kdfMemory: 64 }))
      .toThrow(/must not include Argon2/);
  });

  it('enforces the complete Bitwarden setting boundaries', () => {
    expect(() => assertKdfConfig({ kdf: 0, kdfIterations: MIN_PBKDF2_ITERATIONS })).not.toThrow();
    expect(() => assertKdfConfigForSetting({ kdf: 0, kdfIterations: MAX_PBKDF2_ITERATIONS })).not.toThrow();
    expect(() => assertKdfConfig({ kdf: 0, kdfIterations: MIN_PBKDF2_ITERATIONS - 1 })).toThrow();
    expect(() => assertKdfConfigForSetting({ kdf: 0, kdfIterations: MAX_PBKDF2_ITERATIONS + 1 })).toThrow();

    const minimum = {
      kdf: 1,
      kdfIterations: MIN_ARGON2_ITERATIONS,
      kdfMemory: MIN_ARGON2_MEMORY_MIB,
      kdfParallelism: MIN_ARGON2_PARALLELISM,
    };
    const maximum = {
      kdf: 1,
      kdfIterations: MAX_ARGON2_ITERATIONS,
      kdfMemory: MAX_ARGON2_MEMORY_MIB,
      kdfParallelism: MAX_ARGON2_PARALLELISM,
    };
    expect(() => assertKdfConfigForSetting(minimum)).not.toThrow();
    expect(() => assertKdfConfigForSetting(maximum)).not.toThrow();
    expect(() => assertKdfConfigForSetting({ ...minimum, kdfIterations: 1 })).toThrow(/iteration/);
    expect(() => assertKdfConfigForSetting({ ...minimum, kdfMemory: 15 })).toThrow(/memory/);
    expect(() => assertKdfConfigForSetting({ ...minimum, kdfParallelism: 17 })).toThrow(/parallelism/);
  });

  it('accepts historical Vaultwarden read parameters outside the current settings range', () => {
    expect(() => assertKdfConfig({ kdf: 0, kdfIterations: 2_500_000 })).not.toThrow();
    expect(() => assertKdfConfig({
      kdf: 1,
      kdfIterations: 1,
      kdfMemory: 15,
      kdfParallelism: 1,
    })).not.toThrow();
    expect(() => assertKdfConfig({
      kdf: 1,
      kdfIterations: 11,
      kdfMemory: 64,
      kdfParallelism: 2,
    })).not.toThrow();
  });

  it('rejects historical parameters that exceed the explicit derivation resource budget', () => {
    expect(() => assertKdfConfig({ kdf: 0, kdfIterations: 10_000_001 })).toThrow(/10000000/);
    expect(() => assertKdfConfig({
      kdf: 1,
      kdfIterations: 11,
      kdfMemory: 1_024,
      kdfParallelism: 1,
    })).toThrow(/resource limit/);
  });

  it('uses the current 600000 floor when setting PBKDF2 while accepting historical accounts', () => {
    expect(() => assertKdfConfig({ kdf: 0, kdfIterations: 5_000 })).not.toThrow();
    expect(() => assertKdfConfigForSetting({ kdf: 0, kdfIterations: 5_000 })).toThrow(/600000/);
    expect(() => assertKdfConfigForSetting({ kdf: 0, kdfIterations: 600_000 })).not.toThrow();
  });

  it('compares all discriminated KDF fields', () => {
    expect(sameKdfConfig(pbkdf2, { ...pbkdf2 })).toBe(true);
    expect(sameKdfConfig(pbkdf2, { kdf: 0, kdfIterations: 700_000 })).toBe(false);
    expect(sameKdfConfig(ARGON2_KDF_VECTOR.config, { ...ARGON2_KDF_VECTOR.config })).toBe(true);
    expect(sameKdfConfig(ARGON2_KDF_VECTOR.config, {
      ...ARGON2_KDF_VECTOR.config,
      kdfMemory: 64,
    })).toBe(false);
  });

  it('symmetricKeyFromBytes splits 64 bytes into 32-byte halves', () => {
    const sk = symmetricKeyFromBytes(hexToBytes('aa'.repeat(32) + 'bb'.repeat(32)));
    expect(bytesToHex(sk.encKey)).toBe('aa'.repeat(32));
    expect(bytesToHex(sk.macKey)).toBe('bb'.repeat(32));
    expect(() => symmetricKeyFromBytes(hexToBytes('aa'.repeat(32)))).toThrow('symmetric key must be 64 bytes');
  });
});
