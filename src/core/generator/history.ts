export const GENERATOR_HISTORY_ENTRY_TYPES = Object.freeze([
  'password', 'passphrase', 'pin', 'username',
] as const);

export type GeneratorHistoryEntryType = (typeof GENERATOR_HISTORY_ENTRY_TYPES)[number];

export interface GeneratorHistoryEntry {
  readonly generatedAt: number;
  readonly type: GeneratorHistoryEntryType;
  readonly value: string;
}

export interface GeneratorHistoryTrackInput {
  readonly generatedAt?: number;
  readonly type: GeneratorHistoryEntryType;
  readonly value: string;
}

const MAX_ENTRY_COUNT = 200;
const MAX_VALUE_UTF8_BYTES = 32 * 1_024;
const MAX_TIMESTAMP = 8_640_000_000_000_000;
const ENCODER = new TextEncoder();
const DECODER = new TextDecoder('utf-8', { fatal: true });

export function isGeneratorHistoryEntryType(value: unknown): value is GeneratorHistoryEntryType {
  return GENERATOR_HISTORY_ENTRY_TYPES.some((candidate) => candidate === value);
}

/** Strictly parse worker history data before plaintext enters Popup state. */
export function parseGeneratorHistoryEntries(value: unknown): readonly GeneratorHistoryEntry[] | null {
  if (!Array.isArray(value) || !hasDenseArrayShape(value) || value.length > MAX_ENTRY_COUNT) return null;
  const entries: GeneratorHistoryEntry[] = [];
  const seen = new Set<string>();
  for (const raw of value) {
    if (!isPlainRecord(raw) || !hasExactDataKeys(raw, ['generatedAt', 'type', 'value'])) return null;
    const generatedAt = ownData(raw, 'generatedAt');
    const type = ownData(raw, 'type');
    const entryValue = ownData(raw, 'value');
    if (!Number.isSafeInteger(generatedAt) || (generatedAt as number) < 0
      || (generatedAt as number) > MAX_TIMESTAMP
      || !isGeneratorHistoryEntryType(type) || !isBoundedValue(entryValue)
      || seen.has(entryValue)) return null;
    seen.add(entryValue);
    entries.push(Object.freeze({ generatedAt: generatedAt as number, type, value: entryValue }));
  }
  return Object.freeze(entries);
}

function isBoundedValue(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || containsControlCharacter(value)) return false;
  const bytes = ENCODER.encode(value);
  try {
    return bytes.byteLength <= MAX_VALUE_UTF8_BYTES && DECODER.decode(bytes) === value;
  } catch {
    return false;
  } finally {
    bytes.fill(0);
  }
}

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function hasExactDataKeys(record: object, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(record);
  if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) return false;
  const expectedKeys = new Set(expected);
  return keys.every((key) => expectedKeys.has(key as string)) && expected.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    return descriptor !== undefined && descriptor.enumerable && 'value' in descriptor;
  });
}

function hasDenseArrayShape(value: readonly unknown[]): boolean {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || keys.at(-1) !== 'length') return false;
  return Array.from({ length: value.length }, (_, index) => String(index)).every((key, index) => {
    if (keys[index] !== key) return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined && descriptor.enumerable && 'value' in descriptor;
  });
}

function ownData(record: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}
