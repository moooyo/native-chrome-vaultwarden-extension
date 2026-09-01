export interface TwoFactorRecoveryRequest {
  readonly type: 'auth.openTwoFactorRecovery';
}

/** The recovery deep-link command deliberately carries no page-controlled destination. */
export function isExactTwoFactorRecoveryRequest(
  value: unknown,
): value is TwoFactorRecoveryRequest {
  try {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value) as unknown;
    if (prototype !== Object.prototype && prototype !== null) return false;
    const keys = Reflect.ownKeys(value);
    const descriptor = Object.getOwnPropertyDescriptor(value, 'type');
    return keys.length === 1
      && keys[0] === 'type'
      && descriptor !== undefined
      && descriptor.enumerable === true
      && 'value' in descriptor
      && descriptor.value === 'auth.openTwoFactorRecovery';
  } catch {
    return false;
  }
}
