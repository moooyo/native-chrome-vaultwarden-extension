export const WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_REQUEST =
  'websitePasskey.featurePolicyProbe' as const;
export const WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_VERSION = 1 as const;

const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export interface WebsitePasskeyFeaturePolicyProbeRequest {
  readonly type: typeof WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_REQUEST;
  readonly version: typeof WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_VERSION;
  readonly challenge: string;
}

/** Exact isolated-world response. An absent response means that no policy API is available. */
export interface WebsitePasskeyFeaturePolicyProbeResponse {
  readonly challenge: string;
  readonly get: boolean;
  readonly create: boolean;
}

export function createWebsitePasskeyFeaturePolicyProbeRequest(
  challenge: string,
): Readonly<WebsitePasskeyFeaturePolicyProbeRequest> {
  return Object.freeze({
    type: WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_REQUEST,
    version: WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_VERSION,
    challenge: canonicalChallenge(challenge),
  });
}

export function parseWebsitePasskeyFeaturePolicyProbeRequest(
  input: unknown,
): Readonly<WebsitePasskeyFeaturePolicyProbeRequest> {
  const value = exactRecord(input, ['type', 'version', 'challenge']);
  if (dataValue(value, 'type') !== WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_REQUEST
      || dataValue(value, 'version') !== WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_VERSION) {
    invalidProbe();
  }
  return createWebsitePasskeyFeaturePolicyProbeRequest(
    canonicalChallenge(dataValue(value, 'challenge')),
  );
}

export function createWebsitePasskeyFeaturePolicyProbeResponse(
  challenge: string,
  get: boolean,
  create: boolean,
): Readonly<WebsitePasskeyFeaturePolicyProbeResponse> {
  if (typeof get !== 'boolean' || typeof create !== 'boolean') invalidProbe();
  return Object.freeze({ challenge: canonicalChallenge(challenge), get, create });
}

export function parseWebsitePasskeyFeaturePolicyProbeResponse(
  input: unknown,
  expectedChallenge?: string,
): Readonly<WebsitePasskeyFeaturePolicyProbeResponse> {
  const value = exactRecord(input, ['challenge', 'get', 'create']);
  const challenge = canonicalChallenge(dataValue(value, 'challenge'));
  if (expectedChallenge !== undefined && challenge !== canonicalChallenge(expectedChallenge)) {
    invalidProbe();
  }
  const get = dataValue(value, 'get');
  const create = dataValue(value, 'create');
  if (typeof get !== 'boolean' || typeof create !== 'boolean') invalidProbe();
  return Object.freeze({ challenge, get, create });
}

function exactRecord(input: unknown, expected: readonly string[]): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) invalidProbe();
  const prototype = Object.getPrototypeOf(input) as unknown;
  const keys = Reflect.ownKeys(input);
  if ((prototype !== Object.prototype && prototype !== null)
      || keys.length !== expected.length
      || keys.some((key) => typeof key !== 'string' || !expected.includes(key))) invalidProbe();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      invalidProbe();
    }
  }
  return input as Record<string, unknown>;
}

function dataValue(value: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor?.enumerable && 'value' in descriptor ? descriptor.value : undefined;
}

function canonicalChallenge(value: unknown): string {
  if (typeof value !== 'string' || !UUID_V4_PATTERN.test(value)) invalidProbe();
  return value;
}

function invalidProbe(): never {
  throw new TypeError('Invalid website passkey feature-policy probe message');
}
