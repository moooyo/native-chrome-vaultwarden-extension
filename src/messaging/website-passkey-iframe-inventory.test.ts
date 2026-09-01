import { describe, expect, it, vi } from 'vitest';
import {
  MAX_WEBSITE_PASSKEY_IFRAME_INVENTORY,
  parseWebsitePasskeyIframeInventoryRequest,
} from './website-passkey-iframe-inventory.js';

describe('website passkey iframe inventory protocol', () => {
  it('accepts only the exact dense bounded content snapshot', () => {
    expect(parseWebsitePasskeyIframeInventoryRequest({
      type: 'websitePasskey.reportIframeInventory',
      iframes: [{
        src: 'https://child.example/frame',
        allow: 'publickey-credentials-get',
        srcdoc: false,
      }],
    })).toEqual({
      type: 'websitePasskey.reportIframeInventory',
      iframes: [{
        src: 'https://child.example/frame',
        allow: 'publickey-credentials-get',
        srcdoc: false,
      }],
    });

    const sparse = new Array(1);
    expect(() => parseWebsitePasskeyIframeInventoryRequest({
      type: 'websitePasskey.reportIframeInventory',
      iframes: sparse,
    })).toThrow(TypeError);
    expect(() => parseWebsitePasskeyIframeInventoryRequest({
      type: 'websitePasskey.reportIframeInventory',
      iframes: Array.from(
        { length: MAX_WEBSITE_PASSKEY_IFRAME_INVENTORY + 1 },
        () => ({ src: '', allow: '', srcdoc: false }),
      ),
    })).toThrow(TypeError);
  });

  it('rejects accessors and unexpected ownership fields without invoking them', () => {
    const getter = vi.fn(() => []);
    const request = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(request, 'type', {
      enumerable: true,
      value: 'websitePasskey.reportIframeInventory',
    });
    Object.defineProperty(request, 'iframes', { enumerable: true, get: getter });

    expect(() => parseWebsitePasskeyIframeInventoryRequest(request)).toThrow(TypeError);
    expect(getter).not.toHaveBeenCalled();
    expect(() => parseWebsitePasskeyIframeInventoryRequest({
      type: 'websitePasskey.reportIframeInventory',
      iframes: [],
      tabId: 7,
    })).toThrow(TypeError);
  });
});
