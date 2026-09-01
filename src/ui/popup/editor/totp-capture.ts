import qrcodeParser from 'qrcode-parser';
import { parseTotp } from '../../../core/vault/totp.js';

export type QrDecoder = (input: string) => Promise<string>;

const MAX_QR_PAYLOAD_LENGTH = 8_192;

/** Decode one screenshot QR payload and accept only a valid TOTP provisioning URI. */
export async function decodeTotpQr(
  screenshot: string,
  decode: QrDecoder = qrcodeParser,
): Promise<string | undefined> {
  if (!screenshot || screenshot.length > 32 * 1024 * 1024) return undefined;
  const value = (await decode(screenshot)).trim();
  if (!value || value.length > MAX_QR_PAYLOAD_LENGTH) return undefined;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'otpauth:' || url.hostname.toLowerCase() !== 'totp') return undefined;
  return parseTotp(value) ? value : undefined;
}
