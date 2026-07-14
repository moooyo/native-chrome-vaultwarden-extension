import { describe, it, expect, vi } from 'vitest';
import {
  utf8ToBytes, bytesToUtf8, base64ToBytes, bytesToBase64,
  hexToBytes, bytesToHex, constantTimeEqual,
} from './encoding.js';

describe('encoding', () => {
  it('utf8 round-trips', () => {
    expect(bytesToUtf8(utf8ToBytes('Hello, 世界'))).toBe('Hello, 世界');
  });

  it('base64 round-trips and matches known value', () => {
    expect(bytesToBase64(utf8ToBytes('Hello, Vault!'))).toBe('SGVsbG8sIFZhdWx0IQ==');
    expect(bytesToUtf8(base64ToBytes('SGVsbG8sIFZhdWx0IQ=='))).toBe('Hello, Vault!');
  });

  it('rejects malformed base64', () => {
    expect(() => base64ToBytes('*')).toThrow('invalid base64');
  });

  it('hex round-trips', () => {
    expect(bytesToHex(hexToBytes('00ff10'))).toBe('00ff10');
  });

  it('rejects malformed hex', () => {
    expect(() => hexToBytes('0')).toThrow('invalid hex length');
    expect(() => hexToBytes('zz')).toThrow('invalid hex byte');
    expect(() => hexToBytes('0z')).toThrow('invalid hex byte');
  });

  it('constantTimeEqual compares contents', () => {
    expect(constantTimeEqual(hexToBytes('0011'), hexToBytes('0011'))).toBe(true);
    expect(constantTimeEqual(hexToBytes('0011'), hexToBytes('0012'))).toBe(false);
    expect(constantTimeEqual(hexToBytes('00'), hexToBytes('0000'))).toBe(false);
  });
});

describe('bytesToBase64 (fast path + large blobs)', () => {
  it('encodes a known small vector to the exact same standard base64 as before', () => {
    // Covers all-zero, high bytes (>127), 0xFF and a 2-byte tail (single padding char).
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 255, 65, 66]);
    expect(bytesToBase64(bytes)).toBe('AAEC+vv/QUI=');
  });

  it('round-trips a large varied buffer to byte-identical standard base64', () => {
    const n = 300_000;
    const bytes = new Uint8Array(n);
    for (let i = 0; i < n; i++) bytes[i] = (i * 31 + 7) & 0xff;
    const b64 = bytesToBase64(bytes);
    // Standard base64 alphabet only (not base64url), with correct padding.
    expect(/^[A-Za-z0-9+/]+={0,2}$/.test(b64)).toBe(true);
    expect(base64ToBytes(b64)).toEqual(bytes);
  });

  it.skipIf(typeof (Uint8Array.prototype as { toBase64?: unknown }).toBase64 !== 'function')(
    'uses the native Uint8Array#toBase64 fast path when available',
    () => {
      const proto = Uint8Array.prototype as unknown as { toBase64: () => string };
      const spy = vi.spyOn(proto, 'toBase64');
      const out = bytesToBase64(new Uint8Array([1, 2, 3, 4]));
      expect(spy).toHaveBeenCalled();
      expect(out).toBe('AQIDBA==');
      spy.mockRestore();
    },
  );
});
