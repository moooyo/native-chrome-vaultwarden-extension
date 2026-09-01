import { describe, expect, it, vi } from 'vitest';
import {
  validateIgnoredUserDecryption,
  validateIgnoredUserDecryptionProperty,
} from './vault-transfer-control-plane.js';

describe('validateIgnoredUserDecryption', () => {
  it('accepts bounded JSON account control-plane metadata without returning its contents', () => {
    const result = validateIgnoredUserDecryption({
      masterPasswordUnlock: {
        kdf: { kdfType: 1, iterations: 3, memory: 64, parallelism: 4 },
        masterKeyEncryptedUserKey: '2.encrypted-key-material',
        salt: 'account@example.com',
        containedKeyId: null,
      },
      webAuthnPrfOptions: [{ encryptedUserKey: '2.wrapped', transports: [] }],
      v2UpgradeToken: null,
      userKeyId: '00112233',
    });

    expect(result).toEqual({ ok: true });
    expect(JSON.stringify(result)).not.toContain('encrypted-key-material');
  });

  it('accepts absent and null metadata for older compatible servers', () => {
    expect(validateIgnoredUserDecryption(undefined)).toEqual({ ok: true });
    expect(validateIgnoredUserDecryption(null)).toEqual({ ok: true });
  });

  it('rejects accessors without invoking them', () => {
    const getter = vi.fn(() => '2.secret');
    const value = Object.defineProperty({}, 'masterPasswordUnlock', {
      enumerable: true,
      get: getter,
    });

    expect(validateIgnoredUserDecryption(value)).toEqual({
      ok: false,
      code: 'invalid_control_plane_metadata',
    });
    expect(getter).not.toHaveBeenCalled();

    const root = Object.defineProperty({}, 'userDecryption', {
      enumerable: true,
      get: getter,
    });
    expect(validateIgnoredUserDecryptionProperty(root)).toEqual({
      ok: false,
      code: 'invalid_control_plane_metadata',
    });
    expect(getter).not.toHaveBeenCalled();
  });

  it('rejects cycles, sparse arrays, non-JSON values, and non-plain records', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    const sparse = new Array<unknown>(2);
    sparse[1] = 'x';
    for (const value of [cyclic, sparse, { value: undefined }, new Date()]) {
      expect(validateIgnoredUserDecryption(value)).toEqual({
        ok: false,
        code: 'invalid_control_plane_metadata',
      });
    }
  });

  it('fails with a fixed resource code for excessive depth, entries, or text', () => {
    let deep: Record<string, unknown> = {};
    const root = deep;
    for (let index = 0; index < 14; index++) {
      const next: Record<string, unknown> = {};
      deep.next = next;
      deep = next;
    }
    for (const value of [root, new Array(513).fill(null), { value: 'x'.repeat(128 * 1024 + 1) }]) {
      expect(validateIgnoredUserDecryption(value)).toEqual({
        ok: false,
        code: 'control_plane_metadata_too_large',
      });
    }
  });
});
