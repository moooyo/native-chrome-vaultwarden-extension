import { describe, it, expect } from 'vitest';
import { createRequestContext, isMessageAllowed } from './sender-guard.js';
import type { MessageSenderInfo, RequestContext } from './sender-guard.js';

const ORIGIN = 'chrome-extension://abcdefghijklmnop/';
const ID = 'abcdefghijklmnop';

const CONTENT_CONTEXT: RequestContext = {
  kind: 'content',
  tabId: 5,
  frameId: 0,
  documentId: 'doc-1',
  url: 'https://site.example/login',
  origin: 'https://site.example',
};

function contentSender(overrides: Partial<MessageSenderInfo> = {}): MessageSenderInfo {
  return {
    id: ID,
    url: 'https://site.example/login',
    origin: 'https://site.example',
    tab: { id: 5 },
    frameId: 0,
    documentId: 'doc-1',
    ...overrides,
  };
}

describe('createRequestContext', () => {
  it('requires the sender id to exist and exactly match this extension', () => {
    expect(createRequestContext(undefined, ORIGIN, ID)).toBeUndefined();
    expect(createRequestContext({ url: `${ORIGIN}ui/popup/popup.html` }, ORIGIN, ID)).toBeUndefined();
    expect(createRequestContext({ id: 'other-ext', url: `${ORIGIN}ui/popup/popup.html` }, ORIGIN, ID)).toBeUndefined();
  });

  it('recognizes extension pages by exact URL authority', () => {
    expect(createRequestContext({ id: ID, url: `${ORIGIN}ui/options/options.html` }, ORIGIN, ID)).toEqual({
      kind: 'extensionPage',
      url: `${ORIGIN}ui/options/options.html`,
      origin: 'chrome-extension://abcdefghijklmnop',
    });
    expect(createRequestContext({ id: ID, url: 'chrome-extension://abcdefghijklmnop.evil/popup.html' }, ORIGIN, ID)).toBeUndefined();
  });

  it('preserves a valid browser-owned extension document identity and rejects malformed values', () => {
    expect(createRequestContext({
      id: ID,
      url: ORIGIN + 'ui/popup/popup.html',
      documentId: 'popup-doc-1',
    }, ORIGIN, ID)).toMatchObject({
      kind: 'extensionPage',
      documentId: 'popup-doc-1',
    });
    expect(createRequestContext({
      id: ID,
      url: ORIGIN + 'ui/popup/popup.html',
      documentId: '',
    }, ORIGIN, ID)).toBeUndefined();
  });

  it('builds content context from complete browser-owned frame metadata', () => {
    expect(createRequestContext(contentSender(), ORIGIN, ID)).toEqual(CONTENT_CONTEXT);
  });

  it('requires a valid tab id, frame id, URL, and matching origin for content', () => {
    expect(createRequestContext(contentSender({ tab: {} }), ORIGIN, ID)).toBeUndefined();
    expect(createRequestContext(contentSender({ tab: { id: -1 } }), ORIGIN, ID)).toBeUndefined();
    expect(createRequestContext(contentSender({ frameId: -1 }), ORIGIN, ID)).toBeUndefined();
    expect(createRequestContext(contentSender({ url: 'not a URL' }), ORIGIN, ID)).toBeUndefined();
    expect(createRequestContext(contentSender({ url: 'file:///tmp/page.html', origin: 'null' }), ORIGIN, ID)).toBeUndefined();
    expect(createRequestContext(contentSender({ origin: 'https://site.example/claimed/path' }), ORIGIN, ID)).toBeUndefined();
    expect(createRequestContext(contentSender({ origin: 'https://other.example' }), ORIGIN, ID)).toBeUndefined();
  });

  it('requires sender.origin instead of deriving it from an untrusted request payload', () => {
    const sender = contentSender();
    delete sender.origin;
    expect(createRequestContext(sender, ORIGIN, ID)).toBeUndefined();
  });
});

describe('isMessageAllowed', () => {
  it('allows extension pages to send supported privileged verbs', () => {
    const context: RequestContext = {
      kind: 'extensionPage',
      url: `${ORIGIN}ui/popup/popup.html`,
      origin: 'chrome-extension://abcdefghijklmnop',
    };
    expect(isMessageAllowed('vault.listItems', context)).toBe(true);
    expect(isMessageAllowed('settings.save', context)).toBe(true);
    expect(isMessageAllowed('auth.unlock', context)).toBe(true);
  });

  it('allows document-bound Popup commands only from the exact browser-owned document', () => {
    const popup: RequestContext = {
      kind: 'extensionPage',
      url: `${ORIGIN}ui/popup/popup.html`,
      origin: 'chrome-extension://abcdefghijklmnop',
      documentId: 'popup-doc-1',
    };
    const { documentId: _documentId, ...popupWithoutDocument } = popup;
    for (const type of [
      'auth.requestPasswordHint',
      'vault.setCipherFavorite',
      'generator.history.list', 'generator.history.track', 'generator.history.clear',
      'websitePasskey.lockedStatus',
      'websitePasskey.resumeLocked',
      'websitePasskey.cancelLocked',
    ]) {
      expect(isMessageAllowed(type, popup)).toBe(true);
      expect(isMessageAllowed(type, popupWithoutDocument)).toBe(false);
      expect(isMessageAllowed(type, {
        ...popup, url: `${ORIGIN}ui/options/options.html`,
      })).toBe(false);
      expect(isMessageAllowed(type, CONTENT_CONTEXT)).toBe(false);
    }
  });

  it.each(['vault.export', 'vault.import'])('rejects removed legacy transfer verb %s everywhere', (type) => {
    const extensionContext: RequestContext = {
      kind: 'extensionPage',
      url: `${ORIGIN}ui/options/options.html`,
      origin: 'chrome-extension://abcdefghijklmnop',
    };
    expect(isMessageAllowed(type, extensionContext)).toBe(false);
    expect(isMessageAllowed(type, CONTENT_CONTEXT)).toBe(false);
  });

  it.each([
    'autofill.findCandidates',
    'autofill.findStructuredCandidates',
    'autofill.claimKeyboardGrant',
    'autofill.keyboard.findCandidates',
    'autofill.keyboard.issueIntent',
    'autofill.keyboard.redeemLoginIntent',
    'autofill.keyboard.redeemTotpIntent',
    'autofill.keyboard.redeemStructuredIntent',
    'autofill.issueIntent',
    'autofill.issueStructuredIntent',
    'autofill.redeemLoginIntent',
    'autofill.redeemTotpIntent',
    'autofill.redeemStructuredIntent',
    'autofill.getClientConfig',
    'autofill.issuePageLoadIntent',
    'autofill.redeemPageLoadIntent',
    'clientEvent.ack',
    'autofill.captureSubmission',
    'autofill.claimSavePrompt',
    'autofill.commitSavePrompt',
    'autofill.dismissSavePrompt',
    'clipboard.scheduleClear',
    'auth.completeFido2',
  ])('allows the exact content-script verb %s', (type) => {
    expect(isMessageAllowed(type, CONTENT_CONTEXT)).toBe(true);
  });

  it.each([
    'websitePasskey.reportIframeInventory',
    'autofill.ackTotpCopy',
    'autofill.authorizeGeneratorUse',
    'autofill.trackGeneratedValue',
    'autofill.discardBfcacheCapture',
  ])('allows %s only from a browser-owned content document', (type) => {
    const { documentId: _documentId, ...withoutDocument } = CONTENT_CONTEXT;
    expect(isMessageAllowed(type, CONTENT_CONTEXT)).toBe(true);
    expect(isMessageAllowed(type, withoutDocument)).toBe(false);
    expect(isMessageAllowed(type, {
      kind: 'extensionPage',
      url: `${ORIGIN}ui/popup/popup.html`,
      origin: 'chrome-extension://abcdefghijklmnop',
      documentId: 'popup-document',
    })).toBe(false);
  });

  it.each([
    'auth.completeFido2',
  ])('rejects passkey verb %s outside the top frame', (type) => {
    expect(isMessageAllowed(type, { ...CONTENT_CONTEXT, frameId: 2 })).toBe(false);
  });

  it.each([
    'autofill.getCredentials',
    'autofill.saveLogin',
    'autofill.updateLogin',
    'autofill.getTabSuggestions',
    'autofill.fillTabSuggestion',
    'autofill.findFillItems',
    'autofill.getFillData',
    'autofill.futureVerb',
    'vault.hasPasskey',
    'vault.getPasskeyCandidates',
    'vault.getPasskeyAssertion',
    'vault.getPasskeyTargets',
    'vault.createPasskey',
    'vault.getPasskeySecrets',
    'vault.export',
    'auth.unlock',
    'auth.beginFido2',
    'auth.accountPasskey.begin',
    'auth.accountPasskey.status',
    'auth.accountPasskey.cancel',
    'auth.sso.begin',
    'auth.sso.requirement',
    'auth.sso.status',
    'auth.sso.cancel',
    'auth.duo.begin',
    'auth.duo.cancel',
    'auth.deviceLogin.begin',
    'auth.deviceLogin.status',
    'auth.deviceLogin.retry',
    'auth.deviceLogin.submitTwoFactor',
    'auth.deviceLogin.sendEmailCode',
    'auth.deviceLogin.cancel',
    'auth.deviceLogin.approvals.list',
    'auth.deviceLogin.approvals.get',
    'auth.deviceLogin.approvals.approve',
    'auth.deviceLogin.approvals.deny',
    'settings.saveSecurity',
    'settings.saveHttpAuth',
    'clipboard.writeText',
    'clipboard.readText',
    'generator.history.list',
    'generator.history.track',
    'generator.history.clear',
  ])('rejects content-script verb %s', (type) => {
    expect(isMessageAllowed(type, CONTENT_CONTEXT)).toBe(false);
  });
});
