import { argon2id } from 'hash-wasm';
import { pbkdf2Sha256, hkdfExpandSha256 } from './primitives.js';
import { utf8ToBytes, bytesToBase64 } from './encoding.js';
import type { SymmetricKey } from './keys.js';

export const MIN_PBKDF2_ITERATIONS = 5_000;
export const MIN_PBKDF2_SETTING_ITERATIONS = 600_000;
export const MAX_PBKDF2_ITERATIONS = 2_000_000;
export const MIN_ARGON2_ITERATIONS = 2;
export const MAX_ARGON2_ITERATIONS = 10;
export const MIN_ARGON2_MEMORY_MIB = 16;
export const MAX_ARGON2_MEMORY_MIB = 1_024;
export const MIN_ARGON2_PARALLELISM = 1;
export const MAX_ARGON2_PARALLELISM = 16;

// Read compatibility is intentionally wider than the settings UI. Vaultwarden historically accepted
// parameters outside Bitwarden's current setting range, but unbounded values from prelogin or an import
// would be a trivial resource-exhaustion vector.
const MAX_PBKDF2_DERIVATION_ITERATIONS = 10_000_000;
const MIN_ARGON2_DERIVATION_ITERATIONS = 1;
const MAX_ARGON2_DERIVATION_ITERATIONS = 100;
const MIN_ARGON2_DERIVATION_MEMORY_MIB = 15;
const MAX_ARGON2_WORK_MIB_PASSES = MAX_ARGON2_MEMORY_MIB * MAX_ARGON2_ITERATIONS;

export interface Pbkdf2KdfConfig {
  kdf: 0;
  kdfIterations: number;
  kdfMemory?: never;
  kdfParallelism?: never;
}

export interface Argon2idKdfConfig {
  kdf: 1;
  kdfIterations: number;
  /** Memory cost in MiB, matching the Bitwarden API representation. */
  kdfMemory: number;
  kdfParallelism: number;
}

export type KdfConfig = Pbkdf2KdfConfig | Argon2idKdfConfig;

/**
 * Normalize the KDF fields used by prelogin, token, persisted-auth, export, and key-rotation
 * payloads. A missing type is accepted only as the legacy PBKDF2 representation.
 */
export function parseKdfConfig(value: unknown): KdfConfig {
  if (!isRecord(value)) throw new Error('Invalid KDF configuration');
  const kdf = readConsistentField(value, ['kdf', 'Kdf', 'kdfType', 'KdfType']) ?? 0;
  const kdfIterations = readConsistentField(
    value,
    ['kdfIterations', 'KdfIterations', 'iterations', 'Iterations'],
  );
  const kdfMemory = nullToUndefined(
    readConsistentField(value, ['kdfMemory', 'KdfMemory', 'memory', 'Memory']),
  );
  const kdfParallelism = nullToUndefined(
    readConsistentField(
      value,
      ['kdfParallelism', 'KdfParallelism', 'parallelism', 'Parallelism'],
    ),
  );

  const config: unknown = kdf === 1
    ? { kdf, kdfIterations, kdfMemory, kdfParallelism }
    : {
        kdf,
        kdfIterations,
        ...(kdfMemory !== undefined ? { kdfMemory } : {}),
        ...(kdfParallelism !== undefined ? { kdfParallelism } : {}),
      };
  assertKdfConfig(config);
  return config;
}

/** Validate a canonical KDF configuration before any expensive key derivation is started. */
export function assertKdfConfig(value: unknown): asserts value is KdfConfig {
  if (!isRecord(value) || (value.kdf !== 0 && value.kdf !== 1)) {
    throw new Error('Unsupported KDF type');
  }

  if (value.kdf === 0) {
    assertIntegerInRange(
      'PBKDF2 iteration count',
      value.kdfIterations,
      MIN_PBKDF2_ITERATIONS,
      MAX_PBKDF2_DERIVATION_ITERATIONS,
    );
    if (value.kdfMemory !== undefined || value.kdfParallelism !== undefined) {
      throw new Error('PBKDF2 KDF must not include Argon2 parameters');
    }
    return;
  }

  assertIntegerInRange(
    'Argon2 iteration count',
    value.kdfIterations,
    MIN_ARGON2_DERIVATION_ITERATIONS,
    MAX_ARGON2_DERIVATION_ITERATIONS,
  );
  assertIntegerInRange(
    'Argon2 memory',
    value.kdfMemory,
    MIN_ARGON2_DERIVATION_MEMORY_MIB,
    MAX_ARGON2_MEMORY_MIB,
  );
  assertIntegerInRange(
    'Argon2 parallelism',
    value.kdfParallelism,
    MIN_ARGON2_PARALLELISM,
    MAX_ARGON2_PARALLELISM,
  );
  if ((value.kdfIterations as number) * (value.kdfMemory as number) > MAX_ARGON2_WORK_MIB_PASSES) {
    throw new Error('Argon2 work factor exceeds this client resource limit');
  }
}

/** Apply Bitwarden's current range when creating or changing an account's KDF settings. */
export function assertKdfConfigForSetting(value: unknown): asserts value is KdfConfig {
  assertKdfConfig(value);
  if (value.kdf === 0) {
    assertIntegerInRange(
      'PBKDF2 iteration count',
      value.kdfIterations,
      MIN_PBKDF2_SETTING_ITERATIONS,
      MAX_PBKDF2_ITERATIONS,
    );
    return;
  }
  assertIntegerInRange('Argon2 iteration count', value.kdfIterations, MIN_ARGON2_ITERATIONS, MAX_ARGON2_ITERATIONS);
  assertIntegerInRange('Argon2 memory', value.kdfMemory, MIN_ARGON2_MEMORY_MIB, MAX_ARGON2_MEMORY_MIB);
  assertIntegerInRange('Argon2 parallelism', value.kdfParallelism, MIN_ARGON2_PARALLELISM, MAX_ARGON2_PARALLELISM);
}

/** Compare complete KDF settings, including every Argon2 cost parameter. */
export function sameKdfConfig(left: KdfConfig, right: KdfConfig): boolean {
  if (left.kdf !== right.kdf || left.kdfIterations !== right.kdfIterations) return false;
  if (left.kdf === 0 || right.kdf === 0) return left.kdf === right.kdf;
  return left.kdfMemory === right.kdfMemory && left.kdfParallelism === right.kdfParallelism;
}

/**
 * Derive 32 bytes from arbitrary password and salt bytes using a validated Bitwarden KDF config.
 * Argon2 calls are serialized process-wide so concurrent account operations cannot multiply the
 * configured WASM memory cost.
 */
export async function deriveKdfMaterial(
  password: string | Uint8Array,
  salt: Uint8Array,
  config: KdfConfig,
): Promise<Uint8Array> {
  assertKdfConfig(config);
  const passwordBytes = typeof password === 'string' ? utf8ToBytes(password) : password;
  if (config.kdf === 0) {
    return pbkdf2Sha256(passwordBytes, salt, config.kdfIterations, 32);
  }

  const argonSalt = new Uint8Array(
    await globalThis.crypto.subtle.digest('SHA-256', salt as BufferSource),
  );
  return enqueueArgon2(() => argon2id({
    password: passwordBytes,
    salt: argonSalt,
    iterations: config.kdfIterations,
    memorySize: config.kdfMemory * 1_024,
    parallelism: config.kdfParallelism,
    hashLength: 32,
    outputType: 'binary',
  }));
}

export async function deriveMasterKey(
  password: string,
  email: string,
  config: KdfConfig,
): Promise<Uint8Array> {
  const emailBytes = utf8ToBytes(email.trim().toLowerCase());
  return deriveKdfMaterial(password, emailBytes, config);
}

export async function deriveMasterPasswordHash(
  masterKey: Uint8Array,
  password: string,
): Promise<string> {
  const hash = await pbkdf2Sha256(masterKey, utf8ToBytes(password), 1, 32);
  return bytesToBase64(hash);
}

export async function stretchMasterKey(masterKey: Uint8Array): Promise<SymmetricKey> {
  const encKey = await hkdfExpandSha256(masterKey, 'enc', 32);
  const macKey = await hkdfExpandSha256(masterKey, 'mac', 32);
  return { encKey, macKey };
}

let argon2Tail: Promise<void> = Promise.resolve();

function enqueueArgon2<T>(work: () => Promise<T>): Promise<T> {
  const run = argon2Tail.then(work, work);
  argon2Tail = run.then(() => undefined, () => undefined);
  return run;
}

function assertIntegerInRange(name: string, value: unknown, minimum: number, maximum: number): void {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
}

function readConsistentField(value: Record<string, unknown>, names: string[]): unknown {
  const entries = names
    .filter((name) => value[name] !== undefined)
    .map((name) => value[name]);
  if (entries.length > 1 && entries.some((entry) => !Object.is(entry, entries[0]))) {
    throw new Error(`Conflicting KDF fields: ${names.join(', ')}`);
  }
  return entries[0];
}

function nullToUndefined(value: unknown): unknown {
  return value === null ? undefined : value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
