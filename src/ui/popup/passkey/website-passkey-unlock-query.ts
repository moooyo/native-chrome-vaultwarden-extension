export const WEBSITE_PASSKEY_UNLOCK_QUERY = 'websitePasskeyUnlock';

const POPUP_PATH = '/ui/popup/popup.html';
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export type WebsitePasskeyUnlockQuery =
  | Readonly<{ kind: 'none' }>
  | Readonly<{ kind: 'invalid' }>
  | Readonly<{ kind: 'continuation'; continuationId: string }>;

/** Parse only the fixed unlock-popout URL; duplicate, mixed, and fragment forms fail closed. */
export function parseWebsitePasskeyUnlockQuery(href: string): WebsitePasskeyUnlockQuery {
  let url: URL;
  try { url = new URL(href); } catch { return Object.freeze({ kind: 'none' as const }); }
  const entries = [...url.searchParams.entries()];
  if (!entries.some(([name]) => name === WEBSITE_PASSKEY_UNLOCK_QUERY)) {
    return Object.freeze({ kind: 'none' as const });
  }
  if (url.pathname !== POPUP_PATH || url.hash || entries.length !== 1) {
    return Object.freeze({ kind: 'invalid' as const });
  }
  const [name, continuationId] = entries[0]!;
  return name === WEBSITE_PASSKEY_UNLOCK_QUERY && UUID_V4.test(continuationId)
    ? Object.freeze({ kind: 'continuation' as const, continuationId })
    : Object.freeze({ kind: 'invalid' as const });
}

export function parseWebsitePasskeyLockedStatus(
  value: unknown,
): Readonly<{ status: 'none' }>
  | Readonly<{ status: 'unlock_required'; continuationId: string; expiresAt: number }>
  | undefined {
  if (!plainRecord(value)) return undefined;
  const status = dataValue(value, 'status');
  if (status === 'none' && exactKeys(value, ['status'])) {
    return Object.freeze({ status: 'none' as const });
  }
  if (status !== 'unlock_required'
      || !exactKeys(value, ['continuationId', 'expiresAt', 'status'])) return undefined;
  const continuationId = dataValue(value, 'continuationId');
  const expiresAt = dataValue(value, 'expiresAt');
  if (typeof continuationId !== 'string' || !UUID_V4.test(continuationId)
      || !Number.isSafeInteger(expiresAt) || (expiresAt as number) <= 0) return undefined;
  return Object.freeze({
    status: 'unlock_required' as const,
    continuationId,
    expiresAt: expiresAt as number,
  });
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== expected.length
      || keys.some((key) => typeof key !== 'string' || !expected.includes(key))) return false;
  return keys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return Boolean(descriptor?.enumerable && 'value' in descriptor && descriptor.value !== undefined);
  });
}

function dataValue(value: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor?.enumerable && 'value' in descriptor ? descriptor.value : undefined;
}
