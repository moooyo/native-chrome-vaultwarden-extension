import { describe, expect, it, vi } from 'vitest';
import type { WebsitePasskeyDocumentContext } from './website-passkey-coordinator.js';
import {
  WebsitePasskeyFeaturePolicyProbeClient,
  WebsitePasskeyFeaturePolicyProbeRegistry,
  type WebsitePasskeyFeaturePolicyProbeOwner,
} from './website-passkey-feature-policy-probe.js';

const FIRST = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const SECOND = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const OWNER: WebsitePasskeyFeaturePolicyProbeOwner = {
  tabId: 7,
  frameId: 2,
  documentId: 'document-a',
  url: 'https://child.example/frame',
};
const CONTEXT: WebsitePasskeyDocumentContext = {
  ...OWNER,
  origin: 'https://child.example',
};

describe('WebsitePasskeyFeaturePolicyProbeRegistry', () => {
  it('consumes before rejecting a wrong owner and rejects replay', () => {
    const registry = new WebsitePasskeyFeaturePolicyProbeRegistry({ createChallenge: () => FIRST });
    const receipt = registry.issue(OWNER);

    expect(registry.consume(receipt.challenge, { ...OWNER, documentId: 'document-b' })).toBe(false);
    expect(registry.consume(receipt.challenge, OWNER)).toBe(false);
    expect(() => registry.issue(OWNER)).toThrow(/collision/);
  });

  it('bounds active plus retired capacity and reclaims expired tombstones', () => {
    let now = 100;
    const challenges = [FIRST, SECOND];
    const registry = new WebsitePasskeyFeaturePolicyProbeRegistry({
      ttlMs: 10,
      maxEntries: 1,
      now: () => now,
      createChallenge: () => challenges.shift() ?? SECOND,
    });
    const first = registry.issue(OWNER);
    expect(registry.consume(first.challenge, OWNER)).toBe(true);
    expect(() => registry.issue(OWNER)).toThrow(/capacity/);

    now = 110;
    expect(registry.issue(OWNER).challenge).toBe(SECOND);
  });

  it('retires an expired challenge even though its owner matches', () => {
    let now = 100;
    const registry = new WebsitePasskeyFeaturePolicyProbeRegistry({
      ttlMs: 10,
      now: () => now,
      createChallenge: () => FIRST,
    });
    const receipt = registry.issue(OWNER);
    now = receipt.expiresAt;

    expect(registry.consume(receipt.challenge, OWNER)).toBe(false);
    expect(() => registry.issue(OWNER)).toThrow(/collision/);
  });
});

describe('WebsitePasskeyFeaturePolicyProbeClient', () => {
  it('sends to the exact browser document and returns an exact effective policy', async () => {
    const sendMessage = vi.fn(async (_tabId, request) => ({
      challenge: request.challenge,
      get: true,
      create: false,
    }));
    const registry = new WebsitePasskeyFeaturePolicyProbeRegistry({ createChallenge: () => FIRST });
    const client = new WebsitePasskeyFeaturePolicyProbeClient({ tabs: { sendMessage }, registry });

    await expect(client.probe(CONTEXT)).resolves.toEqual({
      status: 'available',
      get: true,
      create: false,
    });
    expect(sendMessage).toHaveBeenCalledWith(
      OWNER.tabId,
      expect.objectContaining({ challenge: FIRST }),
      { frameId: OWNER.frameId, documentId: OWNER.documentId },
    );
  });

  it('uses an absent response only for the API-unavailable fallback', async () => {
    const registry = new WebsitePasskeyFeaturePolicyProbeRegistry({ createChallenge: () => FIRST });
    const client = new WebsitePasskeyFeaturePolicyProbeClient({
      tabs: { sendMessage: vi.fn(async () => undefined) },
      registry,
    });

    await expect(client.probe(CONTEXT)).resolves.toEqual({ status: 'unavailable' });
  });

  it('fails closed when transport rejects with an undefined reason', async () => {
    const registry = new WebsitePasskeyFeaturePolicyProbeRegistry({ createChallenge: () => FIRST });
    const client = new WebsitePasskeyFeaturePolicyProbeClient({
      tabs: { sendMessage: vi.fn(async () => Promise.reject()) },
      registry,
    });

    await expect(client.probe(CONTEXT)).rejects.toThrow(/probe failed/);
    expect(() => registry.issue(OWNER)).toThrow(/collision/);
  });

  it('consumes before rejecting an accessor response and prevents challenge ABA', async () => {
    const getter = vi.fn(() => FIRST);
    const response = { get: true, create: true } as Record<string, unknown>;
    Object.defineProperty(response, 'challenge', { enumerable: true, get: getter });
    const registry = new WebsitePasskeyFeaturePolicyProbeRegistry({ createChallenge: () => FIRST });
    const client = new WebsitePasskeyFeaturePolicyProbeClient({
      tabs: { sendMessage: vi.fn(async () => response) },
      registry,
    });

    await expect(client.probe(CONTEXT)).rejects.toThrow(/invalid response/);
    expect(getter).not.toHaveBeenCalled();
    expect(() => registry.issue(OWNER)).toThrow(/collision/);
  });
});
