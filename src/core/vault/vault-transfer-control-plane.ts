export type IgnoredControlPlaneValidation =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: 'invalid_control_plane_metadata' | 'control_plane_metadata_too_large' };

const MAX_DEPTH = 12;
const MAX_NODES = 4_096;
const MAX_PROPERTIES = 2_048;
const MAX_ARRAY_ITEMS = 512;
const MAX_STRING_CHARS = 128 * 1024;
const MAX_TOTAL_STRING_CHARS = 512 * 1024;

interface Budget {
  nodes: number;
  properties: number;
  stringChars: number;
}

class InvalidMetadataError extends Error {}
class MetadataLimitError extends Error {}

/**
 * Validate opaque account control-plane metadata without copying, serializing, or exposing any
 * contained key material. The vault export intentionally discards the validated value.
 */
export function validateIgnoredUserDecryption(value: unknown): IgnoredControlPlaneValidation {
  if (value === undefined) return { ok: true };
  try {
    visitJsonValue(value, 0, { nodes: 0, properties: 0, stringChars: 0 }, new Set<object>());
    if (value !== null && !isPlainRecord(value)) throw new InvalidMetadataError();
    return { ok: true };
  } catch (error) {
    return {
      ok: false,
      code: error instanceof MetadataLimitError
        ? 'control_plane_metadata_too_large'
        : 'invalid_control_plane_metadata',
    };
  }
}

/** Read the control-plane member as a data property so hostile accessors are never evaluated. */
export function validateIgnoredUserDecryptionProperty(
  sync: object,
): IgnoredControlPlaneValidation {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(sync, 'userDecryption');
    if (!descriptor) return { ok: true };
    if (!descriptor.enumerable || !('value' in descriptor)) {
      return { ok: false, code: 'invalid_control_plane_metadata' };
    }
    return validateIgnoredUserDecryption(descriptor.value);
  } catch {
    return { ok: false, code: 'invalid_control_plane_metadata' };
  }
}

function visitJsonValue(
  value: unknown,
  depth: number,
  budget: Budget,
  ancestors: Set<object>,
): void {
  budget.nodes++;
  if (budget.nodes > MAX_NODES || depth > MAX_DEPTH) throw new MetadataLimitError();
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new InvalidMetadataError();
    return;
  }
  if (typeof value === 'string') {
    if (value.length > MAX_STRING_CHARS) throw new MetadataLimitError();
    budget.stringChars += value.length;
    if (budget.stringChars > MAX_TOTAL_STRING_CHARS) throw new MetadataLimitError();
    return;
  }
  if (typeof value !== 'object') throw new InvalidMetadataError();
  if (ancestors.has(value)) throw new InvalidMetadataError();
  ancestors.add(value);
  try {
    if (Array.isArray(value)) visitArray(value, depth, budget, ancestors);
    else visitRecord(value, depth, budget, ancestors);
  } finally {
    ancestors.delete(value);
  }
}

function visitArray(
  value: unknown[],
  depth: number,
  budget: Budget,
  ancestors: Set<object>,
): void {
  if (value.length > MAX_ARRAY_ITEMS) throw new MetadataLimitError();
  const descriptors = safeDescriptors(value);
  rejectSymbols(value);
  const keys = Object.keys(descriptors).filter((key) => key !== 'length');
  if (keys.length !== value.length) throw new InvalidMetadataError();
  budget.properties += keys.length;
  if (budget.properties > MAX_PROPERTIES) throw new MetadataLimitError();
  for (let index = 0; index < value.length; index++) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) {
      throw new InvalidMetadataError();
    }
    visitJsonValue(descriptor.value, depth + 1, budget, ancestors);
  }
}

function visitRecord(
  value: object,
  depth: number,
  budget: Budget,
  ancestors: Set<object>,
): void {
  if (!isPlainRecord(value)) throw new InvalidMetadataError();
  rejectSymbols(value);
  const descriptors = safeDescriptors(value);
  const keys = Object.keys(descriptors);
  budget.properties += keys.length;
  if (budget.properties > MAX_PROPERTIES) throw new MetadataLimitError();
  for (const key of keys) {
    const descriptor = descriptors[key]!;
    if (!descriptor.enumerable || !('value' in descriptor)) throw new InvalidMetadataError();
    visitJsonValue(descriptor.value, depth + 1, budget, ancestors);
  }
}

function safeDescriptors(value: object): Record<string, PropertyDescriptor> {
  try {
    return Object.getOwnPropertyDescriptors(value);
  } catch {
    throw new InvalidMetadataError();
  }
}

function rejectSymbols(value: object): void {
  try {
    if (Object.getOwnPropertySymbols(value).length > 0) throw new InvalidMetadataError();
  } catch (error) {
    if (error instanceof InvalidMetadataError) throw error;
    throw new InvalidMetadataError();
  }
}

function isPlainRecord(value: object): boolean {
  try {
    const prototype = Object.getPrototypeOf(value) as unknown;
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}
