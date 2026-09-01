import { describe, expect, it, vi } from 'vitest';
import {
  createWebsitePasskeyFeaturePolicyProbeRequest,
  createWebsitePasskeyFeaturePolicyProbeResponse,
  parseWebsitePasskeyFeaturePolicyProbeRequest,
  parseWebsitePasskeyFeaturePolicyProbeResponse,
  WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_REQUEST,
  WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_VERSION,
} from './website-passkey-feature-policy.js';

const CHALLENGE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

describe('website passkey feature-policy probe protocol', () => {
  it('round-trips exact requests and responses', () => {
    const request = createWebsitePasskeyFeaturePolicyProbeRequest(CHALLENGE);
    expect(parseWebsitePasskeyFeaturePolicyProbeRequest(request)).toEqual({
      type: WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_REQUEST,
      version: WEBSITE_PASSKEY_FEATURE_POLICY_PROBE_VERSION,
      challenge: CHALLENGE,
    });
    expect(parseWebsitePasskeyFeaturePolicyProbeResponse(
      createWebsitePasskeyFeaturePolicyProbeResponse(CHALLENGE, true, false),
      CHALLENGE,
    )).toEqual({ challenge: CHALLENGE, get: true, create: false });
  });

  it.each([
    { challenge: CHALLENGE, get: true, create: true, extra: true },
    { challenge: CHALLENGE, get: 1, create: true },
    { challenge: 'not-a-uuid', get: true, create: true },
    { challenge: CHALLENGE, get: true },
  ])('rejects non-exact response %#', (response) => {
    expect(() => parseWebsitePasskeyFeaturePolicyProbeResponse(response)).toThrow();
  });

  it('rejects accessors without invoking them', () => {
    const getter = vi.fn(() => CHALLENGE);
    const response = { get: true, create: true } as Record<string, unknown>;
    Object.defineProperty(response, 'challenge', { enumerable: true, get: getter });

    expect(() => parseWebsitePasskeyFeaturePolicyProbeResponse(response)).toThrow();
    expect(getter).not.toHaveBeenCalled();
  });

  it('binds a response to the exact expected challenge', () => {
    expect(() => parseWebsitePasskeyFeaturePolicyProbeResponse(
      { challenge: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', get: true, create: true },
      CHALLENGE,
    )).toThrow();
  });
});
