import { getKeys, PrivateExport } from 'micro-key-producer/ssh.js';
import { describe, expect, it } from 'vitest';
import { base64UrlToBytes, bytesToBase64, hexToBytes } from '../crypto/encoding.js';
import {
  generateSshKey,
  importSshPrivateKey,
  MAX_SSH_PRIVATE_KEY_INPUT_BYTES,
  SshKeyCodecError,
} from './ssh-key-codec.js';

const SEED = new Uint8Array(32).fill(1);
const CHECK = new Uint8Array([1, 2, 3, 4]);
const PUBLIC_BYTES = hexToBytes('8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c');
const PUBLIC_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29c';
const FINGERPRINT = 'SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8';
const PRIVATE_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----

b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCKiOPddAnxlf1S2y08ul1yymcJvx2UEhvzdIgBtA9vXAAAAIgBAgMEAQID
BAAAAAtzc2gtZWQyNTUxOQAAACCKiOPddAnxlf1S2y08ul1yymcJvx2UEhvzdIgBtA9vXA
AAAEABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAYqI4910CfGV/VLbLTy6XXLK
Zwm/HZQSG/N0iAG0D29cAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
`;

// Generated once by Windows OpenSSH ssh-keygen and independently fingerprinted with
// `ssh-keygen -lf <key> -E sha256`. This is intentionally not produced by the library under test.
const SSH_KEYGEN_PRIVATE_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBLDh1aaC7Xji82qjvRlKZ4P5X8X3ueXpBjlZ5N5o7O1AAAAIhQZ9z/UGfc
/wAAAAtzc2gtZWQyNTUxOQAAACBLDh1aaC7Xji82qjvRlKZ4P5X8X3ueXpBjlZ5N5o7O1A
AAAEDGG4kf3oBvTD4b9yGcjnHgrEP9WiSNknKs4W8rLmleQEsOHVpoLteOLzaqO9GUpng/
lfxfe55ekGOVnk3mjs7UAAAABXByb2Jl
-----END OPENSSH PRIVATE KEY-----
`;
const SSH_KEYGEN_PUBLIC_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEsOHVpoLteOLzaqO9GUpng/lfxfe55ekGOVnk3mjs7U probe';
const SSH_KEYGEN_FINGERPRINT = 'SHA256:AryyaH/4XoHHXFQyC7R0I1+p+uj1wdFSB9AfBq9yi3M';

const ENCRYPTED_OPENSSH_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDU+lehYI
j+ywe1dOS3rnFpAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBqNqaRLMa3dpm1f
MxAoNkj788we4mML/Bj3bRa0NyyQAAAAkE+vlriomQkUM4iwXcYkR/GjfvWzsAdiQ49hAo
s+Q+YZZQsgAucNmoKLZGL/KIwPNSP+C6rtkpo+UWsn5zo5tKZfJ/NGeZgYQVfFUK4weoxV
xNxfLZvvETYOqNDf3hXR/oo91oJlkRSZ2eg26eRLCgHufivd+hfBhyLz7be5ciH6AKtZG4
fgDP6rajAqoGq5Gw==
-----END OPENSSH PRIVATE KEY-----
`;

const PKCS8_DER = hexToBytes(`302e020100300506032b657004220420${'01'.repeat(32)}`);
const PKCS8_PRIVATE_KEY = pem('PRIVATE KEY', PKCS8_DER);

describe('SSH key codec generation', () => {
  it('matches a deterministic OpenSSH Ed25519 vector and clears every owned byte buffer', () => {
    const seed = SEED.slice();
    const check = CHECK.slice();
    const randomBuffers = [seed, check];
    let producedPublic: Uint8Array | undefined;
    const result = generateSshKey({
      randomBytes(length) {
        const value = randomBuffers.shift();
        expect(value?.byteLength).toBe(length);
        return value!;
      },
      produceKeys(seed, comment, checkBytes) {
        const produced = getKeys(seed, comment, checkBytes);
        producedPublic = produced.publicKeyBytes;
        return produced;
      },
    });

    expect(result).toEqual({
      privateKey: PRIVATE_KEY,
      publicKey: PUBLIC_KEY,
      keyFingerprint: FINGERPRINT,
    });
    expect(Object.isFrozen(result)).toBe(true);
    expect(randomBuffers).toHaveLength(0);
    expect(seed).toEqual(new Uint8Array(32));
    expect(check).toEqual(new Uint8Array(4));
    expect(producedPublic).toEqual(new Uint8Array(32));
  });

  it('fails closed and clears CSPRNG material when a dependency returns malformed output', () => {
    const seed = SEED.slice();
    const check = CHECK.slice();
    let caught: unknown;
    try {
      generateSshKey({
        randomBytes: (length) => length === 32 ? seed : check,
        produceKeys: () => ({
          privateKey: 'secret-output',
          publicKey: 'bad',
          fingerprint: 'bad',
          publicKeyBytes: PUBLIC_BYTES.slice(),
        }),
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toMatchObject({ code: 'invalid_key' });
    expect(seed).toEqual(new Uint8Array(32));
    expect(check).toEqual(new Uint8Array(4));
  });
});

describe('SSH key codec import', () => {
  it('imports an ssh-keygen-compatible Ed25519 key and derives the official public fields', async () => {
    const result = await importSshPrivateKey(SSH_KEYGEN_PRIVATE_KEY);
    expect(result.publicKey).toBe(SSH_KEYGEN_PUBLIC_KEY);
    expect(result.keyFingerprint).toBe(SSH_KEYGEN_FINGERPRINT);
    expect(PrivateExport.decode(result.privateKey).keys).toHaveLength(1);
  });

  it('normalizes generated keys without changing their derived identity', async () => {
    const generated = generateSshKey({ randomBytes: deterministicRandom() });
    const imported = await importSshPrivateKey(generated.privateKey);
    expect(imported).toEqual(generated);
  });

  it('clears the full decoded OpenSSH tree and producer public bytes after import', async () => {
    let decoded: unknown;
    let producedPublic: Uint8Array | undefined;
    await importSshPrivateKey(PRIVATE_KEY, {
      decodeOpenSshPrivateKey(value) {
        const parsed = PrivateExport.decode(value);
        decoded = parsed;
        return parsed as never;
      },
      produceKeys(seed, comment, checkBytes) {
        const produced = getKeys(seed, comment, checkBytes);
        producedPublic = produced.publicKeyBytes;
        return produced;
      },
    });

    expect(allByteArrays(decoded).length).toBeGreaterThan(4);
    expect(allByteArrays(decoded).every((bytes) => bytes.every((value) => value === 0))).toBe(true);
    expect(producedPublic).toEqual(new Uint8Array(32));
  });

  it('imports canonical PKCS#8 Ed25519 through WebCrypto and emits normalized OpenSSH', async () => {
    const check = CHECK.slice();
    const result = await importSshPrivateKey(PKCS8_PRIVATE_KEY, {
      randomBytes: () => check,
    });
    expect(result).toEqual({
      privateKey: PRIVATE_KEY,
      publicKey: PUBLIC_KEY,
      keyFingerprint: FINGERPRINT,
    });
    expect(check).toEqual(new Uint8Array(4));
  });

  it('clears PKCS#8 DER, JWK-derived bytes, check bytes, and producer public bytes', async () => {
    let importedDer: Uint8Array | undefined;
    let exportedJwk: JsonWebKey | undefined;
    let producedPublic: Uint8Array | undefined;
    const check = CHECK.slice();
    const fakeKey = { type: 'private', algorithm: { name: 'Ed25519' } } as CryptoKey;
    const subtle = {
      async importKey(_format: string, keyData: BufferSource) {
        const view = keyData as Uint8Array;
        importedDer = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
        return fakeKey;
      },
      async exportKey(format: string) {
        if (format === 'pkcs8') return PKCS8_DER.slice().buffer;
        exportedJwk = {
          kty: 'OKP', crv: 'Ed25519', d: toBase64Url(SEED), x: toBase64Url(PUBLIC_BYTES),
        };
        return exportedJwk;
      },
    } as unknown as Pick<SubtleCrypto, 'importKey' | 'exportKey'>;

    await importSshPrivateKey(PKCS8_PRIVATE_KEY, {
      subtle,
      randomBytes: () => check,
      produceKeys(seed, comment, checkBytes) {
        const produced = getKeys(seed, comment, checkBytes);
        producedPublic = produced.publicKeyBytes;
        return produced;
      },
    });

    expect(importedDer).toEqual(new Uint8Array(PKCS8_DER.byteLength));
    expect(exportedJwk).toMatchObject({ d: undefined, x: undefined });
    expect(check).toEqual(new Uint8Array(4));
    expect(producedPublic).toEqual(new Uint8Array(32));
  });

  it('clears decoded PKCS#8 bytes when WebCrypto rejects the import', async () => {
    let importedDer: Uint8Array | undefined;
    const subtle = {
      async importKey(_format: string, keyData: BufferSource): Promise<CryptoKey> {
        const view = keyData as Uint8Array;
        importedDer = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
        throw new DOMException('private marker from native crypto', 'DataError');
      },
      async exportKey(): Promise<JsonWebKey> {
        throw new Error('unreachable');
      },
    } as unknown as Pick<SubtleCrypto, 'importKey' | 'exportKey'>;

    await expect(importSshPrivateKey(PKCS8_PRIVATE_KEY, { subtle }))
      .rejects.toMatchObject({ code: 'unsupported_key_type' });
    expect(importedDer).toEqual(new Uint8Array(PKCS8_DER.byteLength));
  });

  it.each([
    ['outer public key', 0],
    ['inner public key', 1],
    ['private blob public suffix', 2],
  ])('rejects a mismatched %s', async (_name, occurrence) => {
    const raw = rawPemBytes(PRIVATE_KEY);
    const offsets = findOccurrences(raw, PUBLIC_BYTES);
    expect(offsets).toHaveLength(3);
    const publicOffset = offsets[occurrence]!;
    raw[publicOffset] = raw[publicOffset]! ^ 1;
    await expect(importSshPrivateKey(pem('OPENSSH PRIVATE KEY', raw)))
      .rejects.toMatchObject({ code: 'invalid_key' });
  });

  it('rejects checkint mismatches, malformed padding, and multi-key envelopes', async () => {
    const checkMismatch = rawPemBytes(PRIVATE_KEY);
    const checkOffsets = findOccurrences(checkMismatch, CHECK);
    expect(checkOffsets.length).toBeGreaterThanOrEqual(2);
    const checkOffset = checkOffsets[0]!;
    checkMismatch[checkOffset] = checkMismatch[checkOffset]! ^ 1;

    const badPadding = rawPemBytes(PRIVATE_KEY);
    const paddingOffset = badPadding.length - 1;
    badPadding[paddingOffset] = badPadding[paddingOffset]! ^ 1;

    const one = rawPemBytes(PRIVATE_KEY);
    const pairOffset = 39;
    const multi = new Uint8Array(one.byteLength + one.byteLength - pairOffset);
    multi.set(one);
    multi.set(one.subarray(pairOffset), one.byteLength);
    new DataView(multi.buffer).setUint32(35, 2, false);

    for (const raw of [checkMismatch, badPadding, multi]) {
      await expect(importSshPrivateKey(pem('OPENSSH PRIVATE KEY', raw)))
        .rejects.toMatchObject({ code: 'invalid_key' });
    }
  });

  it.each([
    'ssh-rsa',
    'ecdsa-sha2-nistp256',
    'ssh-dss',
    'sk-ssh-ed25519@openssh.com',
    'sk-ecdsa-sha2-nistp256@openssh.com',
    'ssh-unknown',
  ])('rejects unsupported OpenSSH key type %s with a stable code', async (algorithm) => {
    await expect(importSshPrivateKey(unsupportedOpenSshKey(algorithm)))
      .rejects.toMatchObject({ code: 'unsupported_key_type' });
  });

  it('reports encrypted OpenSSH and PKCS#8 keys without accepting a password', async () => {
    await expect(importSshPrivateKey(ENCRYPTED_OPENSSH_KEY))
      .rejects.toMatchObject({ code: 'password_required' });
    await expect(importSshPrivateKey(pem('ENCRYPTED PRIVATE KEY', new Uint8Array([1, 2, 3]))))
      .rejects.toMatchObject({ code: 'password_required' });
  });

  it('rejects legacy, PKCS#8 non-Ed25519, and unavailable WebCrypto paths', async () => {
    await expect(importSshPrivateKey(pem('RSA PRIVATE KEY', new Uint8Array([1, 2, 3]))))
      .rejects.toMatchObject({ code: 'unsupported_key_type' });
    await expect(importSshPrivateKey(PKCS8_PRIVATE_KEY, { subtle: null }))
      .rejects.toMatchObject({ code: 'unsupported_key_type' });

    const rsaPair = await crypto.subtle.generateKey(
      { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    );
    const rsaPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', rsaPair.privateKey));
    try {
      await expect(importSshPrivateKey(pem('PRIVATE KEY', rsaPkcs8)))
        .rejects.toMatchObject({ code: 'unsupported_key_type' });
    } finally {
      rsaPkcs8.fill(0);
    }

    const ecdsaPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const ecdsaPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', ecdsaPair.privateKey));
    try {
      await expect(importSshPrivateKey(pem('PRIVATE KEY', ecdsaPkcs8)))
        .rejects.toMatchObject({ code: 'unsupported_key_type' });
    } finally {
      ecdsaPkcs8.fill(0);
    }
  });

  it('rejects malformed armor, canonical-base64 violations, and non-canonical DER', async () => {
    const trailingDer = new Uint8Array(PKCS8_DER.byteLength + 1);
    trailingDer.set(PKCS8_DER);
    const cases = [
      'not a private key',
      `prefix${PRIVATE_KEY}`,
      PRIVATE_KEY.replace('-----END', 'junk\n-----END'),
      PRIVATE_KEY.replace('b3Bl', 'b3B='),
      pem('PRIVATE KEY', trailingDer),
    ];
    for (const value of cases) {
      await expect(importSshPrivateKey(value)).rejects.toBeInstanceOf(SshKeyCodecError);
    }
  });

  it('enforces the exact UTF-8 byte limit and rejects NUL before parsing', async () => {
    const exactAscii = 'x'.repeat(MAX_SSH_PRIVATE_KEY_INPUT_BYTES);
    const exactUtf8 = '\u00e9'.repeat(MAX_SSH_PRIVATE_KEY_INPUT_BYTES / 2);
    await expect(importSshPrivateKey(exactAscii)).rejects.toMatchObject({ code: 'invalid_key' });
    await expect(importSshPrivateKey(exactUtf8)).rejects.toMatchObject({ code: 'invalid_key' });
    await expect(importSshPrivateKey(`${exactAscii}x`)).rejects.toMatchObject({ code: 'input_too_large' });
    await expect(importSshPrivateKey(`${exactUtf8}\u00e9`)).rejects.toMatchObject({ code: 'input_too_large' });
    await expect(importSshPrivateKey(`${PRIVATE_KEY}\0private-marker`))
      .rejects.toMatchObject({ code: 'invalid_key' });
  });

  it('never includes private input or library parser details in public errors', async () => {
    const marker = 'PRIVATE-MARKER-DO-NOT-LEAK';
    let caught: unknown;
    try {
      await importSshPrivateKey(`-----BEGIN OPENSSH PRIVATE KEY-----\n${marker}\n-----END OPENSSH PRIVATE KEY-----`);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(SshKeyCodecError);
    expect(String(caught)).not.toContain(marker);
    expect(JSON.stringify(caught)).not.toContain(marker);
    expect((caught as Error).message).toBe('SSH private key is invalid');
  });
});

function deterministicRandom(): (length: number) => Uint8Array {
  const queue = [SEED.slice(), CHECK.slice()];
  return (length) => {
    const value = queue.shift();
    if (!value || value.byteLength !== length) throw new Error('unexpected random request');
    return value;
  };
}

function pem(label: string, bytes: Uint8Array): string {
  const encoded = bytesToBase64(bytes);
  const lines = encoded.match(/.{1,70}/g)?.join('\n') ?? '';
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

function rawPemBytes(value: string): Uint8Array {
  const body = value.split(/\r?\n/)
    .filter((line) => line !== '' && !line.startsWith('-----'))
    .join('');
  return Uint8Array.from(Buffer.from(body, 'base64'));
}

function findOccurrences(haystack: Uint8Array, needle: Uint8Array): number[] {
  const found: number[] = [];
  for (let index = 0; index <= haystack.byteLength - needle.byteLength; index++) {
    let matches = true;
    for (let offset = 0; offset < needle.byteLength; offset++) {
      if (haystack[index + offset] !== needle[offset]) {
        matches = false;
        break;
      }
    }
    if (matches) found.push(index);
  }
  return found;
}

function unsupportedOpenSshKey(algorithm: string): string {
  const magic = new TextEncoder().encode('openssh-key-v1\0');
  const none = sshString(new TextEncoder().encode('none'));
  const empty = sshString(new Uint8Array());
  const algorithmBytes = sshString(new TextEncoder().encode(algorithm));
  const publicBlob = sshString(algorithmBytes);
  const count = new Uint8Array([0, 0, 0, 1]);
  return pem('OPENSSH PRIVATE KEY', concatBytes(magic, none, none, empty, count, publicBlob));
}

function sshString(bytes: Uint8Array): Uint8Array {
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, bytes.byteLength, false);
  return concatBytes(length, bytes);
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(arrays.reduce((sum, value) => sum + value.byteLength, 0));
  let offset = 0;
  for (const value of arrays) {
    result.set(value, offset);
    offset += value.byteLength;
  }
  return result;
}

function allByteArrays(value: unknown, seen = new WeakSet<object>()): Uint8Array[] {
  if (value instanceof Uint8Array) return [value];
  if (typeof value !== 'object' || value === null || seen.has(value)) return [];
  seen.add(value);
  return Object.values(value).flatMap((nested) => allByteArrays(nested, seen));
}

function toBase64Url(value: Uint8Array): string {
  const encoded = bytesToBase64(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  expect(base64UrlToBytes(encoded)).toEqual(value);
  return encoded;
}
