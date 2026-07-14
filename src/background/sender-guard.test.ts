import { describe, it, expect } from 'vitest';
import { isMessageAllowed } from './sender-guard.js';

const ORIGIN = 'chrome-extension://abcdefghijklmnop/';
const ID = 'abcdefghijklmnop';

describe('isMessageAllowed', () => {
  it('trusts internal dispatch with no sender', () => {
    expect(isMessageAllowed('vault.export', undefined, ORIGIN, ID)).toBe(true);
  });

  it('rejects a message from a different extension', () => {
    expect(isMessageAllowed('autofill.getFillData', { id: 'other-ext', url: `${ORIGIN}x.html` }, ORIGIN, ID)).toBe(false);
  });

  it('allows the extension own pages (popup / options / receive) to send any verb', () => {
    expect(isMessageAllowed('vault.export', { id: ID, url: `${ORIGIN}ui/popup/popup.html` }, ORIGIN, ID)).toBe(true);
    expect(isMessageAllowed('settings.save', { id: ID, url: `${ORIGIN}ui/options/options.html` }, ORIGIN, ID)).toBe(true);
    expect(isMessageAllowed('auth.unlock', { id: ID, url: `${ORIGIN}ui/popup/popup.html` }, ORIGIN, ID)).toBe(true);
  });

  it('allows a content script only the autofill + passkey verbs it needs', () => {
    const cs = { id: ID, url: 'https://site.example/login', tab: { id: 5 } };
    expect(isMessageAllowed('autofill.getFillData', cs, ORIGIN, ID)).toBe(true);
    expect(isMessageAllowed('autofill.checkSaveLogin', cs, ORIGIN, ID)).toBe(true);
    expect(isMessageAllowed('vault.getPasskeyAssertion', cs, ORIGIN, ID)).toBe(true);
    expect(isMessageAllowed('vault.createPasskey', cs, ORIGIN, ID)).toBe(true);
    expect(isMessageAllowed('vault.hasPasskey', cs, ORIGIN, ID)).toBe(true);
  });

  it('rejects a content script sending a privileged verb (confused-deputy defense)', () => {
    const cs = { id: ID, url: 'https://evil.example/', tab: { id: 9 } };
    expect(isMessageAllowed('vault.export', cs, ORIGIN, ID)).toBe(false);
    expect(isMessageAllowed('auth.unlock', cs, ORIGIN, ID)).toBe(false);
    expect(isMessageAllowed('auth.verifyMasterPassword', cs, ORIGIN, ID)).toBe(false);
    expect(isMessageAllowed('vault.getField', cs, ORIGIN, ID)).toBe(false);
    expect(isMessageAllowed('settings.saveSecurity', cs, ORIGIN, ID)).toBe(false);
  });
});
