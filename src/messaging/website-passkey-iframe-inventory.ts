export const MAX_WEBSITE_PASSKEY_IFRAME_INVENTORY = 128;
export const MAX_WEBSITE_PASSKEY_IFRAME_SRC_LENGTH = 8_192;
export const MAX_WEBSITE_PASSKEY_IFRAME_ALLOW_LENGTH = 4_096;

export const WEBSITE_PASSKEY_IFRAME_INVENTORY_REQUEST =
  'websitePasskey.reportIframeInventory' as const;

export interface WebsitePasskeyIframeInventoryEntry {
  readonly src: string;
  readonly allow: string;
  readonly srcdoc: boolean;
}

export interface WebsitePasskeyIframeInventory {
  readonly iframes: readonly WebsitePasskeyIframeInventoryEntry[];
}

export interface WebsitePasskeyIframeInventoryRequest extends WebsitePasskeyIframeInventory {
  readonly type: typeof WEBSITE_PASSKEY_IFRAME_INVENTORY_REQUEST;
}

/** Parse an exact, accessor-free content report before it crosses the document trust boundary. */
export function parseWebsitePasskeyIframeInventoryRequest(
  input: unknown,
): Readonly<WebsitePasskeyIframeInventoryRequest> {
  const request = exactRecord(input, ['type', 'iframes']);
  if (dataValue(request, 'type') !== WEBSITE_PASSKEY_IFRAME_INVENTORY_REQUEST) invalidInventory();
  return Object.freeze({
    type: WEBSITE_PASSKEY_IFRAME_INVENTORY_REQUEST,
    ...parseWebsitePasskeyIframeInventoryValue(dataValue(request, 'iframes')),
  });
}

export function parseWebsitePasskeyIframeInventory(
  input: unknown,
): Readonly<WebsitePasskeyIframeInventory> {
  const report = exactRecord(input, ['iframes']);
  return parseWebsitePasskeyIframeInventoryValue(dataValue(report, 'iframes'));
}

function parseWebsitePasskeyIframeInventoryValue(
  input: unknown,
): Readonly<WebsitePasskeyIframeInventory> {
  if (!Array.isArray(input)
      || input.length > MAX_WEBSITE_PASSKEY_IFRAME_INVENTORY
      || !hasDenseArrayShape(input)) invalidInventory();

  const iframes = input.map((value) => {
    const entry = exactRecord(value, ['src', 'allow', 'srcdoc']);
    const src = boundedText(dataValue(entry, 'src'), MAX_WEBSITE_PASSKEY_IFRAME_SRC_LENGTH);
    const allow = boundedText(dataValue(entry, 'allow'), MAX_WEBSITE_PASSKEY_IFRAME_ALLOW_LENGTH);
    const srcdoc = dataValue(entry, 'srcdoc');
    if (typeof srcdoc !== 'boolean' || (srcdoc && src !== '')) invalidInventory();
    if (src !== '') {
      let parsed: URL;
      try { parsed = new URL(src); } catch { return invalidInventory(); }
      if (parsed.href !== src || parsed.username || parsed.password) invalidInventory();
    }
    return Object.freeze({ src, allow, srcdoc });
  });
  return Object.freeze({ iframes: Object.freeze(iframes) });
}

function exactRecord(input: unknown, expected: readonly string[]): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) invalidInventory();
  const prototype = Object.getPrototypeOf(input) as unknown;
  const keys = Reflect.ownKeys(input);
  if ((prototype !== Object.prototype && prototype !== null)
      || keys.length !== expected.length
      || keys.some((key) => typeof key !== 'string' || !expected.includes(key))) invalidInventory();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      invalidInventory();
    }
  }
  return input as Record<string, unknown>;
}

function dataValue(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

function boundedText(input: unknown, maximum: number): string {
  if (typeof input !== 'string' || input.length > maximum || /[\r\n\0]/u.test(input)) {
    invalidInventory();
  }
  return input;
}

function hasDenseArrayShape(input: readonly unknown[]): boolean {
  const keys = Reflect.ownKeys(input);
  if (keys.length !== input.length + 1 || !keys.includes('length')) return false;
  for (let index = 0; index < input.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (!descriptor?.enumerable || !('value' in descriptor)) return false;
  }
  return keys.every((key) => key === 'length'
    || (typeof key === 'string' && /^(0|[1-9]\d*)$/u.test(key) && Number(key) < input.length));
}

function invalidInventory(): never {
  throw new TypeError('Invalid website passkey iframe inventory');
}
