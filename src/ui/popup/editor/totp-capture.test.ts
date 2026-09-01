import { describe, expect, it, vi } from 'vitest';
import { decodeTotpQr } from './totp-capture.js';

describe('decodeTotpQr', () => {
  it('returns a valid TOTP provisioning URI unchanged', async () => {
    const uri = 'otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example';
    const decode = vi.fn(async () => uri);

    await expect(decodeTotpQr('data:image/png;base64,AA==', decode)).resolves.toBe(uri);
    expect(decode).toHaveBeenCalledOnce();
  });

  it.each([
    'https://example.test/',
    'otpauth://hotp/Example?secret=JBSWY3DPEHPK3PXP',
    'otpauth://totp/Example',
    'not a URL',
  ])('rejects a non-TOTP QR payload: %s', async (payload) => {
    await expect(decodeTotpQr('data:image/png;base64,AA==', async () => payload))
      .resolves.toBeUndefined();
  });

  it('does not invoke the decoder for an empty or unreasonably large screenshot', async () => {
    const decode = vi.fn(async () => 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP');

    await expect(decodeTotpQr('', decode)).resolves.toBeUndefined();
    await expect(decodeTotpQr('x'.repeat(32 * 1024 * 1024 + 1), decode)).resolves.toBeUndefined();
    expect(decode).not.toHaveBeenCalled();
  });
});
