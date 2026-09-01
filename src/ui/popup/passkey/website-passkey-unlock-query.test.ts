import { describe, expect, it, vi } from 'vitest';
import {
  parseWebsitePasskeyLockedStatus,
  parseWebsitePasskeyUnlockQuery,
} from './website-passkey-unlock-query.js';

const ID = '11111111-1111-4111-8111-111111111111';
const BASE = 'chrome-extension://test/ui/popup/popup.html';

describe('website passkey unlock query', () => {
  it('accepts only one exact continuation query on the fixed popup path', () => {
    expect(parseWebsitePasskeyUnlockQuery(`${BASE}?websitePasskeyUnlock=${ID}`)).toEqual({
      kind: 'continuation',
      continuationId: ID,
    });
    for (const href of [
      `${BASE}?websitePasskeyUnlock=${ID}&extra=1`,
      `${BASE}?websitePasskeyUnlock=${ID}#fragment`,
      `${BASE}.evil?websitePasskeyUnlock=${ID}`,
      `${BASE}?websitePasskeyUnlock=invalid`,
      `${BASE}?websitePasskeyUnlock=${ID}&websitePasskeyUnlock=${ID}`,
    ]) expect(parseWebsitePasskeyUnlockQuery(href)).toEqual({ kind: 'invalid' });
    expect(parseWebsitePasskeyUnlockQuery(BASE)).toEqual({ kind: 'none' });
  });

  it('projects only exact accessor-free status data', () => {
    expect(parseWebsitePasskeyLockedStatus({ status: 'none' })).toEqual({ status: 'none' });
    expect(parseWebsitePasskeyLockedStatus({
      status: 'unlock_required', continuationId: ID, expiresAt: 12_345,
    })).toEqual({ status: 'unlock_required', continuationId: ID, expiresAt: 12_345 });
    expect(parseWebsitePasskeyLockedStatus({
      status: 'unlock_required', continuationId: ID, expiresAt: 12_345, request: {},
    })).toBeUndefined();

    const getter = vi.fn(() => ID);
    const unsafe = { status: 'unlock_required', expiresAt: 12_345 } as Record<string, unknown>;
    Object.defineProperty(unsafe, 'continuationId', { enumerable: true, get: getter });
    expect(parseWebsitePasskeyLockedStatus(unsafe)).toBeUndefined();
    expect(getter).not.toHaveBeenCalled();
  });
});
