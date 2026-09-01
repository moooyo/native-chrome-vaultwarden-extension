export type ContextMenuCreateKind = 'login' | 'card' | 'identity';
export type ContextMenuCreateCipherType = 1 | 3 | 4;

export interface ContextMenuCreateIntent {
  readonly type: 'contextMenu.openCreateCipher';
  readonly intentId: string;
  readonly cipherType: ContextMenuCreateCipherType;
  readonly loginUri?: string;
}

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

export function createContextMenuCreateIntent(
  kind: ContextMenuCreateKind,
  topUrl: string,
): ContextMenuCreateIntent {
  const cipherType = kind === 'login' ? 1 : kind === 'card' ? 3 : 4;
  const loginUri = cipherType === 1 ? safeLoginUri(topUrl) : undefined;
  return Object.freeze({
    type: 'contextMenu.openCreateCipher',
    intentId: crypto.randomUUID(),
    cipherType,
    ...(loginUri ? { loginUri } : {}),
  });
}

export function parseContextMenuCreateIntent(value: unknown): ContextMenuCreateIntent | undefined {
  if (!plainRecord(value)) return undefined;
  const baseKeys = ['cipherType', 'intentId', 'type'];
  const expected = value.cipherType === 1 && value.loginUri !== undefined
    ? [...baseKeys, 'loginUri']
    : baseKeys;
  if (!exactDataKeys(value, expected)
      || value.type !== 'contextMenu.openCreateCipher'
      || !UUID_V4.test(String(value.intentId))
      || (value.cipherType !== 1 && value.cipherType !== 3 && value.cipherType !== 4)) return undefined;
  if (value.cipherType === 1) {
    if (value.loginUri === undefined) {
      return Object.freeze({
        type: value.type,
        intentId: value.intentId as string,
        cipherType: value.cipherType,
      });
    }
    const loginUri = safeLoginUri(value.loginUri);
    if (!loginUri || loginUri !== value.loginUri) return undefined;
    return Object.freeze({
      type: value.type,
      intentId: value.intentId as string,
      cipherType: value.cipherType,
      loginUri,
    });
  }
  return Object.freeze({
    type: value.type,
    intentId: value.intentId as string,
    cipherType: value.cipherType,
  });
}

function safeLoginUri(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2_048) return undefined;
  try {
    const url = new URL(value);
    if ((url.protocol !== 'https:' && url.protocol !== 'http:')
        || url.username || url.password || url.href !== value) return undefined;
    return url.href;
  } catch {
    return undefined;
  }
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function exactDataKeys(value: object, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string')) return false;
  const wanted = new Set(expected);
  return keys.every((key) => wanted.has(key as string)) && expected.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return Boolean(descriptor?.enumerable && 'value' in descriptor);
  });
}
