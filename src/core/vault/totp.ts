// RFC 6238 TOTP generation. The TOTP secret stays in the worker; only the short numeric code
// (and timing metadata) ever crosses the messaging boundary to the popup.

const subtle = globalThis.crypto.subtle;

export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

export interface TotpConfig {
  secret: string;
  digits: number;
  period: number;
  algorithm: TotpAlgorithm;
}

export interface TotpResult {
  code: string;
  period: number;
  /** Whole seconds left before the current code rolls over. */
  remaining: number;
}

const DEFAULT_DIGITS = 6;
const DEFAULT_PERIOD = 30;
const DEFAULT_ALGORITHM: TotpAlgorithm = 'SHA1';

/** Parse a stored TOTP secret, accepting both a bare base32 secret and an `otpauth://` URI. */
export function parseTotp(input: string): TotpConfig | undefined {
  const trimmed = input.trim();
  if (!trimmed) return undefined;
  if (/^otpauth:\/\//i.test(trimmed)) return parseOtpauth(trimmed);
  const secret = normalizeBase32(trimmed);
  if (!secret) return undefined;
  return { secret, digits: DEFAULT_DIGITS, period: DEFAULT_PERIOD, algorithm: DEFAULT_ALGORITHM };
}

/** Compute the TOTP code for a given Unix time (in seconds). */
export async function generateTotpCode(config: TotpConfig, epochSeconds: number): Promise<string> {
  const counter = Math.floor(epochSeconds / config.period);
  const key = await subtle.importKey(
    'raw',
    base32ToBytes(config.secret) as BufferSource,
    { name: 'HMAC', hash: hashName(config.algorithm) },
    false,
    ['sign'],
  );
  const hmac = new Uint8Array(await subtle.sign('HMAC', key, counterToBytes(counter) as BufferSource));
  // Dynamic truncation (RFC 4226 §5.3).
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const binary =
    ((hmac[offset]! & 0x7f) * 0x1000000) +
    ((hmac[offset + 1]! & 0xff) * 0x10000) +
    ((hmac[offset + 2]! & 0xff) * 0x100) +
    (hmac[offset + 3]! & 0xff);
  return (binary % 10 ** config.digits).toString().padStart(config.digits, '0');
}

/** Parse + generate the code for the current window, with the seconds remaining until rollover. */
export async function getTotp(input: string, epochMs: number): Promise<TotpResult | undefined> {
  const config = parseTotp(input);
  if (!config) return undefined;
  const epochSeconds = Math.floor(epochMs / 1000);
  const code = await generateTotpCode(config, epochSeconds);
  const remaining = config.period - (epochSeconds % config.period);
  return { code, period: config.period, remaining };
}

function parseOtpauth(uri: string): TotpConfig | undefined {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return undefined;
  }
  const secret = normalizeBase32(url.searchParams.get('secret') ?? '');
  if (!secret) return undefined;
  return {
    secret,
    digits: toPositiveInt(url.searchParams.get('digits'), DEFAULT_DIGITS),
    period: toPositiveInt(url.searchParams.get('period'), DEFAULT_PERIOD),
    algorithm: normalizeAlgorithm(url.searchParams.get('algorithm')),
  };
}

function normalizeBase32(value: string): string {
  return value.replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
}

function normalizeAlgorithm(value: string | null): TotpAlgorithm {
  switch ((value ?? '').toUpperCase()) {
    case 'SHA256':
      return 'SHA256';
    case 'SHA512':
      return 'SHA512';
    default:
      return DEFAULT_ALGORITHM;
  }
}

function hashName(algorithm: TotpAlgorithm): string {
  return algorithm === 'SHA1' ? 'SHA-1' : algorithm === 'SHA256' ? 'SHA-256' : 'SHA-512';
}

function toPositiveInt(value: string | null, fallback: number): number {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

function counterToBytes(counter: number): Uint8Array {
  const buf = new Uint8Array(8);
  let n = counter;
  for (let i = 7; i >= 0; i--) {
    buf[i] = n & 0xff;
    n = Math.floor(n / 256);
  }
  return buf;
}

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32ToBytes(value: string): Uint8Array {
  const clean = value.toUpperCase().replace(/[^A-Z2-7]/g, '');
  const out: number[] = [];
  let bits = 0;
  let acc = 0;
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx < 0) continue;
    acc = (acc << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((acc >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}
