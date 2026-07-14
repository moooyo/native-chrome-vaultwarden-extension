import { describe, it, expect } from 'vitest';
import { generateTotpCode, parseTotp, getTotp } from './totp.js';

// RFC 6238 Appendix B test vectors. The SHA1 seed is ASCII "12345678901234567890",
// which is base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ". Codes are the 8-digit variant.
const SHA1_SECRET_B32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
// SHA256 seed is ASCII "12345678901234567890123456789012".
const SHA256_SECRET_B32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====';

describe('generateTotpCode (RFC 6238 Appendix B)', () => {
  const cases: Array<[number, string]> = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ];

  for (const [time, expected] of cases) {
    it(`SHA1 8-digit code at T=${time}`, async () => {
      const code = await generateTotpCode(
        { secret: SHA1_SECRET_B32, digits: 8, period: 30, algorithm: 'SHA1' },
        time,
      );
      expect(code).toBe(expected);
    });
  }

  it('produces SHA256 8-digit codes', async () => {
    const code = await generateTotpCode(
      { secret: SHA256_SECRET_B32, digits: 8, period: 30, algorithm: 'SHA256' },
      59,
    );
    expect(code).toBe('46119246');
  });

  it('left-pads short codes to the requested digit count', async () => {
    const code = await generateTotpCode({ secret: SHA1_SECRET_B32, digits: 6, period: 30, algorithm: 'SHA1' }, 1111111109);
    expect(code).toBe('081804');
    expect(code).toHaveLength(6);
  });
});

describe('parseTotp', () => {
  it('parses a bare base32 secret with default 6 digits / 30s / SHA1', () => {
    expect(parseTotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')).toEqual({
      secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
      digits: 6,
      period: 30,
      algorithm: 'SHA1',
    });
  });

  it('ignores spaces and lowercase in a bare secret', () => {
    expect(parseTotp('gezd gnbv gy3t qojq')).toMatchObject({ secret: 'GEZDGNBVGY3TQOJQ' });
  });

  it('parses an otpauth:// URI with secret, digits, period, and algorithm', () => {
    const uri = 'otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=8&period=60&algorithm=SHA256';
    expect(parseTotp(uri)).toEqual({
      secret: 'JBSWY3DPEHPK3PXP',
      digits: 8,
      period: 60,
      algorithm: 'SHA256',
    });
  });

  it('defaults otpauth digits/period/algorithm when omitted', () => {
    expect(parseTotp('otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP')).toEqual({
      secret: 'JBSWY3DPEHPK3PXP',
      digits: 6,
      period: 30,
      algorithm: 'SHA1',
    });
  });

  it('returns undefined for empty or secretless input', () => {
    expect(parseTotp('')).toBeUndefined();
    expect(parseTotp('   ')).toBeUndefined();
    expect(parseTotp('otpauth://totp/Example?issuer=Example')).toBeUndefined();
  });
});

describe('getTotp', () => {
  it('returns the code, period, and seconds remaining for the current window', async () => {
    // T=1111111109 sits 29s into a 30s window (1111111109 % 30 = 29), so 1s remains.
    const result = await getTotp(SHA1_SECRET_B32, 1111111109_000);
    expect(result).toEqual({ code: '081804', period: 30, remaining: 1 });
  });

  it('reports a full period of remaining time at a window boundary', async () => {
    const result = await getTotp(SHA1_SECRET_B32, 1111111110_000);
    expect(result?.remaining).toBe(30);
  });

  it('returns undefined for an unparseable secret', async () => {
    expect(await getTotp('', 0)).toBeUndefined();
  });
});

describe('Steam TOTP', () => {
  // Known-answer vectors from the Bitwarden SDK (bitwarden-vault/src/totp.rs test_generate_totp)
  // at 2023-01-01T00:00:00Z (epoch 1672531200s). Steam maps the 31-bit truncation onto a 5-char
  // alphabet instead of RFC 6238 decimal digits.
  const STEAM_EPOCH_MS = 1672531200_000;

  it('generates the 5-char Steam code (SDK parity)', async () => {
    expect((await getTotp('steam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ', STEAM_EPOCH_MS))?.code).toBe('7W6CJ');
    expect((await getTotp('steam://ABCD123', STEAM_EPOCH_MS))?.code).toBe('N26DF');
  });

  it('is case-insensitive on the steam:// scheme', async () => {
    expect((await getTotp('StEam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ', STEAM_EPOCH_MS))?.code).toBe('7W6CJ');
  });

  it('parses steam:// as 5-char / 30s / SHA1 / steam', () => {
    expect(parseTotp('steam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ')).toEqual({
      secret: 'HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ', digits: 5, period: 30, algorithm: 'SHA1', steam: true,
    });
  });

  it('honors otpauth encoder=steam', async () => {
    const uri = 'otpauth://totp/Steam:me?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=Steam&encoder=steam';
    expect((await getTotp(uri, STEAM_EPOCH_MS))?.code).toBe('7W6CJ');
  });

  it('clamps absurd otpauth digits instead of crashing', async () => {
    const r = await getTotp('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=99999999999', 0);
    expect(typeof r?.code).toBe('string');
    expect((r?.code.length ?? 0)).toBeLessThanOrEqual(10);
  });
});
