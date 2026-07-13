import { describe, it, expect } from 'vitest';
import { cborUint, cborNegInt, cborBytes, cborText, cborMap, cborDecode } from './cbor.js';

describe('cbor encoder', () => {
  it('encodes unsigned ints across size boundaries', () => {
    expect(cborUint(0)).toEqual([0x00]);
    expect(cborUint(23)).toEqual([0x17]);
    expect(cborUint(24)).toEqual([0x18, 24]);
    expect(cborUint(255)).toEqual([0x18, 255]);
    expect(cborUint(256)).toEqual([0x19, 0x01, 0x00]);
    expect(cborUint(65536)).toEqual([0x1a, 0x00, 0x01, 0x00, 0x00]);
  });
  it('encodes negative COSE keys -1,-2,-3', () => {
    expect(cborNegInt(-1)).toEqual([0x20]);
    expect(cborNegInt(-2)).toEqual([0x21]);
    expect(cborNegInt(-3)).toEqual([0x22]);
    expect(cborNegInt(-7)).toEqual([0x26]);
  });
  it('encodes byte and text strings with length prefix', () => {
    expect(cborBytes(new Uint8Array([1, 2, 3]))).toEqual([0x43, 1, 2, 3]);
    expect(cborText('fmt')).toEqual([0x63, 0x66, 0x6d, 0x74]);
    expect(cborText('none')).toEqual([0x64, 0x6e, 0x6f, 0x6e, 0x65]);
  });
  it('encodes an empty map and a small map', () => {
    expect(cborMap([])).toEqual([0xa0]);
    expect(cborMap([[...cborText('fmt'), ...cborText('none')]])).toEqual([0xa1, 0x63, 0x66, 0x6d, 0x74, 0x64, 0x6e, 0x6f, 0x6e, 0x65]);
  });
  it('round-trips a COSE-shaped map through the decoder', () => {
    const x = new Uint8Array(32).fill(7);
    const y = new Uint8Array(32).fill(9);
    const cose = new Uint8Array(cborMap([
      [...cborUint(1), ...cborUint(2)],
      [...cborUint(3), ...cborNegInt(-7)],
      [...cborNegInt(-1), ...cborUint(1)],
      [...cborNegInt(-2), ...cborBytes(x)],
      [...cborNegInt(-3), ...cborBytes(y)],
    ]));
    const decoded = cborDecode(cose) as Map<number, unknown>;
    expect(decoded.get(1)).toBe(2);
    expect(decoded.get(3)).toBe(-7);
    expect(decoded.get(-1)).toBe(1);
    expect(decoded.get(-2)).toEqual(x);
    expect(decoded.get(-3)).toEqual(y);
  });
  it('decodes fmt/attStmt/authData attestation map', () => {
    const authData = new Uint8Array([0xaa, 0xbb]);
    const att = new Uint8Array(cborMap([
      [...cborText('fmt'), ...cborText('none')],
      [...cborText('attStmt'), ...cborMap([])],
      [...cborText('authData'), ...cborBytes(authData)],
    ]));
    const decoded = cborDecode(att) as Map<string, unknown>;
    expect(decoded.get('fmt')).toBe('none');
    expect(decoded.get('attStmt')).toBeInstanceOf(Map);
    expect(decoded.get('authData')).toEqual(authData);
  });
});
