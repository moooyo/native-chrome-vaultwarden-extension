import {
  createWebsitePasskeyFeaturePolicyProbeResponse,
  parseWebsitePasskeyFeaturePolicyProbeRequest,
  type WebsitePasskeyFeaturePolicyProbeResponse,
} from '../messaging/website-passkey-feature-policy.js';

type NativePolicyBinding = Readonly<{
  getPolicy: (this: Document) => unknown;
  allowsFeature: (this: object, feature: string) => unknown;
}>;

export type WebsitePasskeyFeaturePolicyResponder = (
  request: unknown,
) => Readonly<WebsitePasskeyFeaturePolicyProbeResponse> | undefined;

// Captured at module evaluation in the isolated world, before any runtime probe can be requested.
const NATIVE_PERMISSIONS_POLICY = captureNativePolicyBinding('permissionsPolicy');
const NATIVE_FEATURE_POLICY = captureNativePolicyBinding('featurePolicy');

/** Answer only exact runtime probe messages. Undefined means neither browser policy API exists. */
export const answerWebsitePasskeyFeaturePolicyProbe: WebsitePasskeyFeaturePolicyResponder = (
  input,
) => {
  let request;
  try { request = parseWebsitePasskeyFeaturePolicyProbeRequest(input); } catch { return undefined; }
  const binding = NATIVE_PERMISSIONS_POLICY ?? NATIVE_FEATURE_POLICY;
  if (!binding) return undefined;

  let policy: object;
  try {
    const value = Reflect.apply(binding.getPolicy, document, []);
    if (typeof value !== 'object' || value === null) throw new TypeError('Invalid policy object');
    policy = value;
  } catch {
    return createWebsitePasskeyFeaturePolicyProbeResponse(request.challenge, false, false);
  }

  return createWebsitePasskeyFeaturePolicyProbeResponse(
    request.challenge,
    allows(binding, policy, 'publickey-credentials-get'),
    allows(binding, policy, 'publickey-credentials-create'),
  );
};

function captureNativePolicyBinding(
  property: 'permissionsPolicy' | 'featurePolicy',
): NativePolicyBinding | undefined {
  const DocumentConstructor = (globalThis as unknown as {
    Document?: { readonly prototype?: object };
  }).Document;
  const prototype = DocumentConstructor?.prototype;
  if (!prototype) return undefined;
  const getter = findGetter(prototype, property);
  if (!getter || typeof document !== 'object') return undefined;

  let policy: unknown;
  try { policy = Reflect.apply(getter, document, []); } catch { return undefined; }
  if (typeof policy !== 'object' || policy === null) return undefined;
  const method = findMethod(policy, 'allowsFeature');
  if (!method) return undefined;
  return Object.freeze({ getPolicy: getter, allowsFeature: method });
}

function findGetter(owner: object, property: string): ((this: Document) => unknown) | undefined {
  let current: object | null = owner;
  while (current) {
    const descriptor = Object.getOwnPropertyDescriptor(current, property);
    if (descriptor) return typeof descriptor.get === 'function'
      ? descriptor.get as (this: Document) => unknown
      : undefined;
    current = Object.getPrototypeOf(current) as object | null;
  }
  return undefined;
}

function findMethod(
  owner: object,
  property: string,
): ((this: object, feature: string) => unknown) | undefined {
  let current: object | null = owner;
  while (current) {
    const descriptor = Object.getOwnPropertyDescriptor(current, property);
    if (descriptor) return 'value' in descriptor && typeof descriptor.value === 'function'
      ? descriptor.value as (this: object, feature: string) => unknown
      : undefined;
    current = Object.getPrototypeOf(current) as object | null;
  }
  return undefined;
}

function allows(binding: NativePolicyBinding, policy: object, feature: string): boolean {
  try { return Reflect.apply(binding.allowsFeature, policy, [feature]) === true; } catch { return false; }
}
