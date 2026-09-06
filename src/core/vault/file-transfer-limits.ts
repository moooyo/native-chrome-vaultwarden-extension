import { AppError } from '../errors.js';

/** Chromium's JSON-serialized extension message limit, including the complete message envelope. */
export const LEGACY_FILE_MESSAGE_MAX_JSON_BYTES = 64 * 1024 * 1024;

/** Base64 is ASCII and needs no JSON escaping, so its contribution can be budgeted before encoding. */
export function assertLegacyFileMessageBudget(envelopeWithoutData: unknown, encodedDataLength: number): void {
  const envelopeBytes = new TextEncoder().encode(JSON.stringify(envelopeWithoutData)).byteLength;
  if (!Number.isSafeInteger(encodedDataLength) || encodedDataLength < 0
    || encodedDataLength + envelopeBytes > LEGACY_FILE_MESSAGE_MAX_JSON_BYTES) {
    throw new AppError('error', 'This file requires the chunked file transfer channel.');
  }
}

export function base64EncodedLength(byteLength: number): number {
  return 4 * Math.ceil(byteLength / 3);
}
