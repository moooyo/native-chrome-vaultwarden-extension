export interface CipherFavoriteRequest {
  readonly type: 'vault.setCipherFavorite';
  readonly id: string;
  readonly favorite: boolean;
}

function containsAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

/** Accept only the semantic favorite command emitted by an exact Popup document. */
export function isExactCipherFavoriteRequest(input: unknown): input is CipherFavoriteRequest {
  try {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) return false;
    const prototype = Object.getPrototypeOf(input) as unknown;
    if (prototype !== Object.prototype && prototype !== null) return false;
    const keys = Reflect.ownKeys(input);
    if (keys.length !== 3 || keys.some((key) => (
      key !== 'type' && key !== 'id' && key !== 'favorite'
    ))) return false;
    const type = Object.getOwnPropertyDescriptor(input, 'type');
    const id = Object.getOwnPropertyDescriptor(input, 'id');
    const favorite = Object.getOwnPropertyDescriptor(input, 'favorite');
    return type?.enumerable === true
      && 'value' in type
      && type.value === 'vault.setCipherFavorite'
      && id?.enumerable === true
      && 'value' in id
      && typeof id.value === 'string'
      && id.value.length > 0
      && id.value.length <= 4_096
      && id.value === id.value.trim()
      && !containsAsciiControl(id.value)
      && favorite?.enumerable === true
      && 'value' in favorite
      && typeof favorite.value === 'boolean';
  } catch {
    return false;
  }
}
