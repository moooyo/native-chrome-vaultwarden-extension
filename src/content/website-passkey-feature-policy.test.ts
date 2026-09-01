// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_REQUEST,
  WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_VERSION,
} from '../messaging/website-passkey-feature-policy.js';

const CHALLENGE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const documentPrototype = Document.prototype as unknown as Record<string, unknown>;
const originalFeaturePolicy = Object.getOwnPropertyDescriptor(documentPrototype, 'featurePolicy');
const originalPermissionsPolicy = Object.getOwnPropertyDescriptor(documentPrototype, 'permissionsPolicy');

afterEach(() => {
  restore('featurePolicy', originalFeaturePolicy);
  restore('permissionsPolicy', originalPermissionsPolicy);
  vi.resetModules();
});

describe('isolated website passkey feature-policy responder', () => {
  it('uses module-load native getter and method after later realm monkeypatches', async () => {
    const nativeAllows = vi.fn(function (this: object, feature: string) {
      return feature === 'publickey-credentials-get';
    });
    const policyPrototype = {};
    Object.defineProperty(policyPrototype, 'allowsFeature', {
      configurable: true,
      value: nativeAllows,
    });
    const policy = Object.create(policyPrototype) as object;
    const nativeGetter = vi.fn(() => policy);
    delete documentPrototype.permissionsPolicy;
    Object.defineProperty(documentPrototype, 'featurePolicy', {
      configurable: true,
      get: nativeGetter,
    });
    vi.resetModules();
    const { answerWebsitePasskeyFeaturePolicyProbe } =
      await import('./website-passkey-feature-policy.js');

    Object.defineProperty(documentPrototype, 'featurePolicy', {
      configurable: true,
      get: () => ({ allowsFeature: () => false }),
    });
    Object.defineProperty(policyPrototype, 'allowsFeature', {
      configurable: true,
      value: () => false,
    });

    expect(answerWebsitePasskeyFeaturePolicyProbe(request())).toEqual({
      challenge: CHALLENGE,
      get: true,
      create: false,
    });
    expect(nativeGetter).toHaveBeenCalledTimes(2);
    expect(nativeAllows).toHaveBeenCalledTimes(2);
  });

  it('returns explicit denial when a captured native getter throws later', async () => {
    let fail = false;
    const policy = Object.create({ allowsFeature: () => true }) as object;
    delete documentPrototype.permissionsPolicy;
    Object.defineProperty(documentPrototype, 'featurePolicy', {
      configurable: true,
      get: () => {
        if (fail) throw new Error('revoked');
        return policy;
      },
    });
    vi.resetModules();
    const { answerWebsitePasskeyFeaturePolicyProbe } =
      await import('./website-passkey-feature-policy.js');
    fail = true;

    expect(answerWebsitePasskeyFeaturePolicyProbe(request())).toEqual({
      challenge: CHALLENGE,
      get: false,
      create: false,
    });
  });

  it('returns no response only when neither native API was captured', async () => {
    delete documentPrototype.featurePolicy;
    delete documentPrototype.permissionsPolicy;
    vi.resetModules();
    const { answerWebsitePasskeyFeaturePolicyProbe } =
      await import('./website-passkey-feature-policy.js');

    expect(answerWebsitePasskeyFeaturePolicyProbe(request())).toBeUndefined();
  });
});

function request() {
  return {
    type: WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_REQUEST,
    version: WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_VERSION,
    challenge: CHALLENGE,
  };
}

function restore(property: string, descriptor: PropertyDescriptor | undefined): void {
  if (descriptor) Object.defineProperty(documentPrototype, property, descriptor);
  else delete documentPrototype[property];
}
