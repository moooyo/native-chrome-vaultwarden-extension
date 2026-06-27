import { describe, it, expect } from 'vitest';
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

  it('hex round-trips', () => {
    expect(bytesToHex(hexToBytes('00ff10'))).toBe('00ff10');
  });

  it('rejects malformed hex', () => {
    expect(() => hexToBytes('0')).toThrow('invalid hex length');
    expect(() => hexToBytes('zz')).toThrow('invalid hex byte');
  });

  it('constantTimeEqual compares contents', () => {
    expect(constantTimeEqual(hexToBytes('0011'), hexToBytes('0011'))).toBe(true);
    expect(constantTimeEqual(hexToBytes('0011'), hexToBytes('0012'))).toBe(false);
    expect(constantTimeEqual(hexToBytes('00'), hexToBytes('0000'))).toBe(false);
  });
});
