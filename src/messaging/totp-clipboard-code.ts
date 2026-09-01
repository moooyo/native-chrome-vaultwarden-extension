const NUMERIC_TOTP_CODE = /^[0-9]{1,10}$/u;
const STEAM_TOTP_CODE = /^[23456789BCDFGHJKMNPQRTVWXY]{5}$/u;

/** The only clipboard ownership values a web content script may submit. */
export function isContentTotpClipboardCode(value: unknown): value is string {
  return typeof value === 'string'
    && (NUMERIC_TOTP_CODE.test(value) || STEAM_TOTP_CODE.test(value));
}
