import { PrivateExport, getKeys } from 'micro-key-producer/ssh.js';
import { base64ToBytes, base64UrlToBytes, bytesToBase64, bytesToBase64Url } from '../crypto/encoding.js';
import type { CompleteDecryptedSshKey } from './models.js';

export const MAX_SSH_PRIVATE_KEY_INPUT_BYTES = 16 * 1024;

export type SshKeyCodecErrorCode =
  | 'invalid_key'
  | 'unsupported_key_type'
  | 'password_required'
  | 'input_too_large';

const ERROR_MESSAGES: Readonly<Record<SshKeyCodecErrorCode, string>> = Object.freeze({
  invalid_key: 'SSH private key is invalid',
  unsupported_key_type: 'SSH private key type is not supported',
  password_required: 'Encrypted SSH private keys are not supported',
  input_too_large: 'SSH private key exceeds the 16384-byte limit',
});

const OPENSSH_LABEL = 'OPENSSH PRIVATE KEY';
const PKCS8_LABEL = 'PRIVATE KEY';
const ENCRYPTED_PKCS8_LABEL = 'ENCRYPTED PRIVATE KEY';
const ED25519_PUBLIC_PREFIX = 'ssh-ed25519 ';
const SHA256_FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{43}$/;
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// These are the existing vault plaintext limits. Keeping the codec output inside them prevents
// a valid key with an oversized comment from failing only after encryption.
const OUTPUT_LIMITS = Object.freeze({ privateKey: 3_695, publicKey: 3_695, keyFingerprint: 687 });

interface DecodedOpenSshPrivateKey {
  readonly keys: Array<{
    readonly pubKey: { readonly pubKey: Uint8Array };
    readonly privKey: {
      readonly check1: Uint8Array;
      readonly check2: Uint8Array;
      readonly pubKey: Uint8Array;
      readonly privKey: Uint8Array;
      readonly comment: string;
    };
  }>;
}

export interface SshKeyProducerResult {
  readonly privateKey: string;
  readonly publicKey: string;
  readonly fingerprint: string;
  readonly publicKeyBytes: Uint8Array;
}

export interface SshKeyCodecDependencies {
  /** Returns a fresh, caller-owned CSPRNG buffer. Ownership transfers to the codec. */
  readonly randomBytes?: (length: number) => Uint8Array;
  readonly produceKeys?: (
    seed: Uint8Array,
    comment?: string,
    checkBytes?: Uint8Array,
  ) => SshKeyProducerResult;
  readonly decodeOpenSshPrivateKey?: (privateKey: string) => DecodedOpenSshPrivateKey;
  readonly subtle?: Pick<SubtleCrypto, 'importKey' | 'exportKey'> | null;
}

export class SshKeyCodecError extends Error {
  constructor(readonly code: SshKeyCodecErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.name = 'SshKeyCodecError';
  }
}

/** Generate a complete, unencrypted OpenSSH Ed25519 key triple in the current worker. */
export function generateSshKey(dependencies: SshKeyCodecDependencies = {}): CompleteDecryptedSshKey {
  let seed: Uint8Array | undefined;
  let checkBytes: Uint8Array | undefined;
  try {
    seed = randomBytes(32, dependencies);
    checkBytes = randomBytes(4, dependencies);
    return produceCompleteKey(seed, undefined, checkBytes, dependencies);
  } catch (error) {
    if (error instanceof SshKeyCodecError) throw error;
    throw new SshKeyCodecError('invalid_key');
  } finally {
    zeroBytes(checkBytes);
    zeroBytes(seed);
  }
}

/**
 * Import an unencrypted OpenSSH or canonical PKCS#8 Ed25519 private key and derive every public
 * field from its private seed. Caller-supplied public-key and fingerprint text is never accepted.
 */
export async function importSshPrivateKey(
  privateKeyText: string,
  dependencies: SshKeyCodecDependencies = {},
): Promise<CompleteDecryptedSshKey> {
  assertBoundedPrivateKeyInput(privateKeyText);
  const envelope = readPemEnvelope(privateKeyText);

  if (envelope.label === ENCRYPTED_PKCS8_LABEL) {
    throw new SshKeyCodecError('password_required');
  }
  if (envelope.label === OPENSSH_LABEL) {
    return importOpenSshPrivateKey(privateKeyText, dependencies);
  }
  if (envelope.label === PKCS8_LABEL) {
    return importPkcs8PrivateKey(envelope.body, dependencies);
  }
  throw new SshKeyCodecError('unsupported_key_type');
}

function importOpenSshPrivateKey(
  privateKeyText: string,
  dependencies: SshKeyCodecDependencies,
): CompleteDecryptedSshKey {
  const decode = dependencies.decodeOpenSshPrivateKey
    ?? ((privateKey: string) => PrivateExport.decode(privateKey) as unknown as DecodedOpenSshPrivateKey);
  let decoded: DecodedOpenSshPrivateKey | undefined;
  try {
    decoded = decode(privateKeyText);
  } catch (error) {
    throw classifyOpenSshDecodeError(error);
  }

  try {
    if (!decoded) throw new SshKeyCodecError('invalid_key');
    const entry = decoded.keys[0];
    if (!entry || decoded.keys.length !== 1) throw new SshKeyCodecError('invalid_key');
    const privateBlob = entry.privKey.privKey;
    if (privateBlob.byteLength !== 64) throw new SshKeyCodecError('invalid_key');
    const seed = privateBlob.subarray(0, 32);
    return produceCompleteKey(
      seed,
      entry.privKey.comment,
      entry.privKey.check1,
      dependencies,
      (derivedPublicKey) => {
        if (!equalBytes(derivedPublicKey, entry.pubKey.pubKey)) {
          throw new SshKeyCodecError('invalid_key');
        }
      },
    );
  } catch (error) {
    if (error instanceof SshKeyCodecError) throw error;
    throw new SshKeyCodecError('invalid_key');
  } finally {
    deepZeroBytes(decoded);
  }
}

async function importPkcs8PrivateKey(
  base64Body: string,
  dependencies: SshKeyCodecDependencies,
): Promise<CompleteDecryptedSshKey> {
  let der: Uint8Array | undefined;
  let canonicalDer: Uint8Array | undefined;
  let seed: Uint8Array | undefined;
  let expectedPublicKey: Uint8Array | undefined;
  let checkBytes: Uint8Array | undefined;
  let jwk: JsonWebKey | undefined;

  try {
    der = decodeCanonicalBase64(base64Body);
    const subtle = dependencies.subtle === undefined ? globalThis.crypto?.subtle : dependencies.subtle;
    if (!subtle) throw new SshKeyCodecError('unsupported_key_type');

    let key: CryptoKey;
    try {
      key = await subtle.importKey(
        'pkcs8',
        der as BufferSource,
        { name: 'Ed25519' },
        true,
        ['sign'],
      );
    } catch {
      throw new SshKeyCodecError('unsupported_key_type');
    }
    if (key.type !== 'private' || key.algorithm.name !== 'Ed25519') {
      throw new SshKeyCodecError('unsupported_key_type');
    }

    let exportedPkcs8: ArrayBuffer;
    try {
      const exported = await subtle.exportKey('pkcs8', key);
      if (!(exported instanceof ArrayBuffer)) throw new Error('unexpected export type');
      exportedPkcs8 = exported;
      jwk = await subtle.exportKey('jwk', key);
    } catch {
      throw new SshKeyCodecError('unsupported_key_type');
    }

    canonicalDer = new Uint8Array(exportedPkcs8);
    if (!equalBytes(der, canonicalDer)) throw new SshKeyCodecError('invalid_key');
    if (
      jwk.kty !== 'OKP'
      || jwk.crv !== 'Ed25519'
      || typeof jwk.d !== 'string'
      || typeof jwk.x !== 'string'
    ) {
      throw new SshKeyCodecError('unsupported_key_type');
    }

    seed = decodeCanonicalBase64Url32(jwk.d);
    expectedPublicKey = decodeCanonicalBase64Url32(jwk.x);
    checkBytes = randomBytes(4, dependencies);
    return produceCompleteKey(seed, undefined, checkBytes, dependencies, (derivedPublicKey) => {
      if (!equalBytes(derivedPublicKey, expectedPublicKey!)) {
        throw new SshKeyCodecError('invalid_key');
      }
    });
  } catch (error) {
    if (error instanceof SshKeyCodecError) throw error;
    throw new SshKeyCodecError('invalid_key');
  } finally {
    if (jwk) {
      try {
        const mutable = jwk as Record<string, unknown>;
        mutable.d = undefined;
        mutable.x = undefined;
      } catch {
        // WebCrypto normally returns a mutable dictionary; a frozen injected object is only dereferenced.
      }
    }
    zeroBytes(checkBytes);
    zeroBytes(expectedPublicKey);
    zeroBytes(seed);
    zeroBytes(canonicalDer);
    zeroBytes(der);
  }
}

function produceCompleteKey(
  seed: Uint8Array,
  comment: string | undefined,
  checkBytes: Uint8Array,
  dependencies: SshKeyCodecDependencies,
  verifyPublicKey?: (publicKey: Uint8Array) => void,
): CompleteDecryptedSshKey {
  const produce = dependencies.produceKeys ?? getKeys;
  let produced: SshKeyProducerResult | undefined;
  let publicKeyBytes: Uint8Array | undefined;
  try {
    produced = produce(seed, comment, checkBytes);
    publicKeyBytes = produced.publicKeyBytes;
    if (!(publicKeyBytes instanceof Uint8Array) || publicKeyBytes.byteLength !== 32) {
      throw new SshKeyCodecError('invalid_key');
    }
    verifyPublicKey?.(publicKeyBytes);
    assertGeneratedText(produced);
    return Object.freeze({
      privateKey: produced.privateKey,
      publicKey: produced.publicKey,
      keyFingerprint: produced.fingerprint,
    });
  } catch (error) {
    if (error instanceof SshKeyCodecError) throw error;
    throw new SshKeyCodecError('invalid_key');
  } finally {
    zeroBytes(publicKeyBytes);
  }
}

function assertGeneratedText(produced: SshKeyProducerResult): void {
  if (
    typeof produced.privateKey !== 'string'
    || typeof produced.publicKey !== 'string'
    || typeof produced.fingerprint !== 'string'
    || !produced.publicKey.startsWith(ED25519_PUBLIC_PREFIX)
    || /[\r\n\0]/.test(produced.publicKey)
    || !SHA256_FINGERPRINT.test(produced.fingerprint)
  ) {
    throw new SshKeyCodecError('invalid_key');
  }
  const envelope = readPemEnvelope(produced.privateKey);
  if (envelope.label !== OPENSSH_LABEL) throw new SshKeyCodecError('invalid_key');
  assertBoundedOutput(produced.privateKey, OUTPUT_LIMITS.privateKey);
  assertBoundedOutput(produced.publicKey, OUTPUT_LIMITS.publicKey);
  assertBoundedOutput(produced.fingerprint, OUTPUT_LIMITS.keyFingerprint);
}

function assertBoundedPrivateKeyInput(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    throw new SshKeyCodecError('invalid_key');
  }
  if (value.length > MAX_SSH_PRIVATE_KEY_INPUT_BYTES) {
    throw new SshKeyCodecError('input_too_large');
  }
  let encoded: Uint8Array | undefined;
  try {
    encoded = new TextEncoder().encode(value);
    if (encoded.byteLength > MAX_SSH_PRIVATE_KEY_INPUT_BYTES) {
      throw new SshKeyCodecError('input_too_large');
    }
  } finally {
    zeroBytes(encoded);
  }
}

function assertBoundedOutput(value: string, maximumBytes: number): void {
  if (value.length === 0 || value.includes('\0')) throw new SshKeyCodecError('invalid_key');
  let encoded: Uint8Array | undefined;
  try {
    encoded = new TextEncoder().encode(value);
    if (encoded.byteLength > maximumBytes) throw new SshKeyCodecError('invalid_key');
  } finally {
    zeroBytes(encoded);
  }
}

function readPemEnvelope(value: string): { readonly label: string; readonly body: string } {
  if (value.includes('\r') && /\r(?!\n)/.test(value)) throw new SshKeyCodecError('invalid_key');
  const lines = value.split(/\r?\n/);
  if (lines.at(-1) === '') lines.pop();
  if (lines.length < 3 || lines.some((line, index) => index > 0 && index < lines.length - 1 && line.includes('\r'))) {
    throw new SshKeyCodecError('invalid_key');
  }

  const begin = lines[0] ?? '';
  const labelMatch = /^-----BEGIN ([A-Z0-9 -]*PRIVATE KEY)-----$/.exec(begin);
  if (!labelMatch) throw new SshKeyCodecError('invalid_key');
  const label = labelMatch[1]!;
  if (lines.at(-1) !== `-----END ${label}-----`) throw new SshKeyCodecError('invalid_key');

  const bodyLines = lines.slice(1, -1);
  if (bodyLines[0] === '') bodyLines.shift();
  if (bodyLines.length === 0 || bodyLines.some((line) => line.length === 0 || !/^[A-Za-z0-9+/=]+$/.test(line))) {
    throw new SshKeyCodecError('invalid_key');
  }
  const body = bodyLines.join('');
  if (body.length === 0 || body.length % 4 !== 0 || !CANONICAL_BASE64.test(body)) {
    throw new SshKeyCodecError('invalid_key');
  }
  return { label, body };
}

function decodeCanonicalBase64(value: string): Uint8Array {
  let decoded: Uint8Array | undefined;
  try {
    decoded = base64ToBytes(value);
    if (bytesToBase64(decoded) !== value) throw new Error('non-canonical base64');
    return decoded;
  } catch {
    zeroBytes(decoded);
    throw new SshKeyCodecError('invalid_key');
  }
}

function decodeCanonicalBase64Url32(value: string): Uint8Array {
  let decoded: Uint8Array | undefined;
  try {
    if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw new Error('invalid base64url');
    decoded = base64UrlToBytes(value);
    if (decoded.byteLength !== 32 || bytesToBase64Url(decoded) !== value) {
      throw new Error('non-canonical base64url');
    }
    return decoded;
  } catch {
    zeroBytes(decoded);
    throw new SshKeyCodecError('invalid_key');
  }
}

function classifyOpenSshDecodeError(error: unknown): SshKeyCodecError {
  const message = error instanceof Error ? error.message : '';
  if (message.includes('Reader(ciphername): magic: invalid value:')) {
    return new SshKeyCodecError('password_required');
  }
  if (message.includes('Reader(keyType): magic: invalid value:')) {
    return new SshKeyCodecError('unsupported_key_type');
  }
  return new SshKeyCodecError('invalid_key');
}

function randomBytes(length: number, dependencies: SshKeyCodecDependencies): Uint8Array {
  let bytes: Uint8Array | undefined;
  try {
    bytes = dependencies.randomBytes
      ? dependencies.randomBytes(length)
      : globalThis.crypto.getRandomValues(new Uint8Array(length));
    if (!(bytes instanceof Uint8Array) || bytes.byteLength !== length) {
      throw new SshKeyCodecError('invalid_key');
    }
    return bytes;
  } catch (error) {
    zeroBytes(bytes);
    if (error instanceof SshKeyCodecError) throw error;
    throw new SshKeyCodecError('invalid_key');
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function deepZeroBytes(value: unknown, seen = new WeakSet<object>()): void {
  if (value instanceof Uint8Array) {
    zeroBytes(value);
    return;
  }
  if (typeof value !== 'object' || value === null || seen.has(value)) return;
  seen.add(value);
  for (const nested of Object.values(value)) deepZeroBytes(nested, seen);
}

function zeroBytes(value: Uint8Array | undefined): void {
  if (!value) return;
  try {
    Uint8Array.prototype.fill.call(value, 0);
  } catch {
    // A detached or hostile injected view is already unusable; cleanup remains best-effort.
  }
}
