import { describe, expect, it } from 'vitest';
import { base64ToBytes, bytesToUtf8 } from '../crypto/encoding.js';
import {
  createInteractiveTwoFactorChallenge,
  createInteractiveTwoFactorLaunch,
  createInteractiveTwoFactorOwner,
  interactiveTwoFactorConnectorUrl,
  parseInteractiveTwoFactorDocumentId,
  sameInteractiveTwoFactorOwner,
} from './interactive-two-factor.js';

const SERVER_URL = 'https://vault.example/tenant/';
const CONNECTOR_DATA = JSON.stringify({
  challenge: 'AQIDBAUGBwgJCgsMDQ4PEA',
  rpId: 'vault.example',
  allowCredentials: [{ type: 'public-key', id: 'AQID' }],
});

function owner(overrides: Record<string, unknown> = {}) {
  return {
    flow: 'deviceLogin' as const,
    generation: 7,
    serverUrl: SERVER_URL,
    bindingId: 'f4b47b53-a174-4a40-bbd6-08b2bb6f9d34',
    ...overrides,
  };
}

describe('interactive two-factor owner and connector helpers', () => {
  it('canonicalizes the owner and derives the one shared self-hosted connector endpoint', () => {
    const value = createInteractiveTwoFactorOwner(owner({ serverUrl: ' HTTPS://VAULT.example/tenant ' }));

    expect(value).toEqual(owner());
    expect(Object.isFrozen(value)).toBe(true);
    expect(interactiveTwoFactorConnectorUrl(value.serverUrl))
      .toBe('https://vault.example/tenant/webauthn-fallback-connector.html');
    expect(sameInteractiveTwoFactorOwner(value, owner())).toBe(true);
    expect(sameInteractiveTwoFactorOwner(value, owner({ generation: 8 }))).toBe(false);
  });

  it.each([
    owner({ flow: 'device' }),
    owner({ generation: 0 }),
    owner({ bindingId: ' bad ' }),
    { ...owner(), extra: true },
  ])('rejects malformed or non-exact owners', (value) => {
    expect(() => createInteractiveTwoFactorOwner(value as never)).toThrow(/owner|flow|generation|binding/i);
  });

  it('accepts only canonical JSON at the exact owner-bound connector URL', () => {
    const canonicalOwner = createInteractiveTwoFactorOwner(owner());
    const challenge = createInteractiveTwoFactorChallenge({
      owner: canonicalOwner,
      connectorData: CONNECTOR_DATA,
      connectorUrl: interactiveTwoFactorConnectorUrl(SERVER_URL),
    });

    expect(challenge.owner).toEqual(canonicalOwner);
    expect(Object.isFrozen(challenge)).toBe(true);
    expect(() => createInteractiveTwoFactorChallenge({
      ...challenge,
      connectorData: '{ "rpId": "vault.example" }',
    })).toThrow(/canonical JSON/);
    expect(() => createInteractiveTwoFactorChallenge({
      ...challenge,
      connectorUrl: 'https://evil.example/webauthn-fallback-connector.html',
    })).toThrow(/connector URL/);
  });

  it('builds the official V1 launch without retaining the parent in durable challenge data', () => {
    const challenge = createInteractiveTwoFactorChallenge({
      owner: createInteractiveTwoFactorOwner(owner()),
      connectorData: CONNECTOR_DATA,
      connectorUrl: interactiveTwoFactorConnectorUrl(SERVER_URL),
    });
    const replacement = {
      tabId: 42,
      documentId: 'connector-document-42',
      url: 'https://vault.example/tenant/webauthn-fallback-connector.html?data=old',
    };
    const launch = createInteractiveTwoFactorLaunch(challenge, {
      parentUrl: 'chrome-extension://extension-id/ui/popup/popup.html?flow=device',
      locale: 'zh-CN',
    }, replacement);
    const url = new URL(launch.url);

    expect(launch.owner).toEqual(challenge.owner);
    expect(launch.replace).toEqual(replacement);
    expect(bytesToUtf8(base64ToBytes(url.searchParams.get('data')!))).toBe(CONNECTOR_DATA);
    expect(decodeURIComponent(url.searchParams.get('parent')!))
      .toBe('chrome-extension://extension-id/ui/popup/popup.html?flow=device');
    expect(url.searchParams.get('v')).toBe('1');
    expect(url.searchParams.get('locale')).toBe('zh-CN');
    expect([...url.searchParams.keys()].sort()).toEqual(['data', 'locale', 'parent', 'v']);
    expect(launch.url).not.toContain(challenge.owner.bindingId);
    expect(launch.url).not.toContain('deviceLogin');
    expect(JSON.stringify(challenge)).not.toContain('popup.html');
  });

  it('accepts only a bounded non-control browser document id', () => {
    expect(parseInteractiveTwoFactorDocumentId('document-1')).toBe('document-1');
    for (const value of ['', ' ', 'document\u0000id', 'd'.repeat(513)]) {
      expect(() => parseInteractiveTwoFactorDocumentId(value)).toThrow(/document id/);
    }
  });

  it('rejects web parents, unsupported locales, and invalid replacement tabs', () => {
    const challenge = createInteractiveTwoFactorChallenge({
      owner: createInteractiveTwoFactorOwner(owner()),
      connectorData: CONNECTOR_DATA,
      connectorUrl: interactiveTwoFactorConnectorUrl(SERVER_URL),
    });
    expect(() => createInteractiveTwoFactorLaunch(challenge, {
      parentUrl: 'https://evil.example/', locale: 'en',
    })).toThrow(/parent URL/);
    expect(() => createInteractiveTwoFactorLaunch(challenge, {
      parentUrl: 'chrome-extension://extension-id/popup.html', locale: 'fr' as never,
    })).toThrow(/locale/);
    expect(() => createInteractiveTwoFactorLaunch(challenge, {
      parentUrl: 'chrome-extension://extension-id/popup.html', locale: 'en',
    }, {
      tabId: -1,
      documentId: 'connector-document',
      url: 'https://vault.example/tenant/webauthn-fallback-connector.html?data=old',
    })).toThrow(/tab/);
  });
});
