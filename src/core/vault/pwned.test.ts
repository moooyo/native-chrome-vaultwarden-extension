import { describe, it, expect, vi } from 'vitest';
import { sha1Hex, pwnedCount } from './pwned.js';

describe('sha1Hex', () => {
  it('is the uppercase hex of SHA-1', async () => {
    expect(await sha1Hex('password')).toBe('5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
  });
});

describe('pwnedCount', () => {
  it('sends ONLY the 5-char prefix (+Add-Padding) and returns the matching suffix count', async () => {
    const suffix = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'.slice(5); // 35 chars
    const fetchFn = vi.fn(async (url: string, init: RequestInit) => {
      expect(String(url)).toBe('https://api.pwnedpasswords.com/range/5BAA6');
      expect((init.headers as Record<string, string>)['Add-Padding']).toBe('true');
      return new Response(`0000000000000000000000000000000000A:5\r\n${suffix}:12345\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0`);
    }) as unknown as typeof fetch;
    expect(await pwnedCount('password', fetchFn)).toBe(12345);
  });
  it('returns 0 when the suffix is absent', async () => {
    const fetchFn = (async () => new Response('ABCDEF:3\nFEDCBA:0')) as unknown as typeof fetch;
    expect(await pwnedCount('x', fetchFn, async () => '11111' + 'Z'.repeat(35))).toBe(0);
  });
  it('throws on a non-2xx response', async () => {
    const fetchFn = (async () => new Response('', { status: 503 })) as unknown as typeof fetch;
    await expect(pwnedCount('x', fetchFn)).rejects.toThrow();
  });
});
