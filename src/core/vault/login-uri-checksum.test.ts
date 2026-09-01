import { describe, expect, it } from 'vitest';
import { computeLoginUriChecksum, validateLoginUriChecksum } from './login-uri-checksum.js';

describe('Bitwarden login URI checksum', () => {
  it('uses the upstream standard-Base64 SHA-256 vector including padding', async () => {
    await expect(computeLoginUriChecksum('https://example.com')).resolves.toBe(
      'EAaArVRs5qV39C9S3zO0z9ynVoWeZkuNfeMpsVDQnOk=',
    );
  });

  it('hashes UTF-8 bytes and requires the exact canonical checksum text', async () => {
    const checksum = await computeLoginUriChecksum('https://example.com/雪');
    await expect(validateLoginUriChecksum('https://example.com/雪', checksum)).resolves.toBe(true);
    await expect(validateLoginUriChecksum('https://example.com/雪', checksum.slice(0, -1))).resolves.toBe(false);
    await expect(validateLoginUriChecksum('https://example.com/x', checksum)).resolves.toBe(false);
  });
});
