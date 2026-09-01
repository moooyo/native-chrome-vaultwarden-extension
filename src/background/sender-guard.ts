// Trust boundary for runtime messages. The background router exposes privileged verbs that must
// only be reachable from the extension's own pages. Content scripts receive a deliberately small,
// exact surface and their page identity is carried separately in RequestContext.

export interface MessageSenderInfo {
  id?: string;
  url?: string;
  origin?: string;
  frameId?: number;
  documentId?: string;
  tab?: { id?: number } | null;
}

export type RequestContext =
  | {
      kind: 'extensionPage';
      url: string;
      origin: string;
      documentId?: string;
    }
  | {
      kind: 'content';
      tabId: number;
      frameId: number;
      url: string;
      origin: string;
      documentId?: string;
    };

const CONTENT_SCRIPT_VERBS = new Set<string>([
  'autofill.findCandidates',
  'autofill.findStructuredCandidates',
  'autofill.claimKeyboardGrant',
  'autofill.keyboard.findCandidates',
  'autofill.keyboard.issueIntent',
  'autofill.continuation.redeemKeyboardReprompt',
  'autofill.keyboard.redeemLoginIntent',
  'autofill.keyboard.redeemTotpIntent',
  'autofill.keyboard.redeemStructuredIntent',
  'autofill.issueIntent',
  'autofill.issueStructuredIntent',
  'autofill.redeemLoginIntent',
  'autofill.redeemTotpIntent',
  'autofill.redeemStructuredIntent',
  'autofill.getClientConfig',
  'autofill.authorizeGeneratorUse',
  'autofill.trackGeneratedValue',
  'autofill.issuePageLoadIntent',
  'autofill.redeemPageLoadIntent',
  'clientEvent.ack',
  'autofill.captureSubmission',
  'autofill.discardBfcacheCapture',
  'autofill.claimSavePrompt',
  'autofill.commitSavePrompt',
  'autofill.dismissSavePrompt',
  // Router restricts this generic extension-page verb to a bounded TOTP code for content callers.
  'clipboard.scheduleClear',
  'auth.completeFido2',
  'websitePasskey.reportIframeInventory',
  'autofill.ackTotpCopy',
]);

const TOP_FRAME_ONLY_CONTENT_VERBS = new Set<string>([
  'auth.completeFido2',
]);

const CONTENT_DOCUMENT_ONLY_VERBS = new Set<string>([
  'websitePasskey.reportIframeInventory',
  'autofill.ackTotpCopy',
  'autofill.authorizeGeneratorUse',
  'autofill.trackGeneratedValue',
  'autofill.discardBfcacheCapture',
]);

const POPUP_DOCUMENT_ONLY_VERBS = new Set<string>([
  'auth.requestPasswordHint',
  'vault.setCipherFavorite',
  'generator.history.list',
  'generator.history.track',
  'generator.history.clear',
  'websitePasskey.lockedStatus',
  'websitePasskey.resumeLocked',
  'websitePasskey.cancelLocked',
]);
const POPUP_DOCUMENT_PATH = '/ui/popup/popup.html';

// These legacy whole-string transfer verbs were replaced by the bounded, backpressured Options
// Port protocol. Reject them before routing so an old extension page cannot revive the bypass.
const REMOVED_LEGACY_VERBS = new Set<string>([
  'vault.export',
  'vault.import',
]);

function parseUrl(value: string): URL | undefined {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

function sameUrlAuthority(left: URL, right: URL): boolean {
  return left.protocol === right.protocol
    && left.host === right.host
    && left.username === right.username
    && left.password === right.password;
}

function serializedAuthority(url: URL): string {
  return `${url.protocol}//${url.host}`;
}

function isOpaqueDocumentId(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= 4_096
    && value.trim() === value;
}

/**
 * Normalize browser-owned sender metadata into the only two caller identities accepted by the
 * background. Missing or contradictory metadata fails closed instead of being treated as content.
 */
export function createRequestContext(
  sender: MessageSenderInfo | undefined,
  extensionOrigin: string,
  extensionId: string,
): RequestContext | undefined {
  if (!sender || sender.id !== extensionId || typeof sender.url !== 'string') return undefined;

  const senderUrl = parseUrl(sender.url);
  const extensionUrl = parseUrl(extensionOrigin);
  if (!senderUrl || !extensionUrl) return undefined;

  if (sameUrlAuthority(senderUrl, extensionUrl)) {
    const context = {
      kind: 'extensionPage',
      url: sender.url,
      origin: serializedAuthority(extensionUrl),
    } as const;
    if (sender.documentId === undefined) return context;
    return isOpaqueDocumentId(sender.documentId)
      ? { ...context, documentId: sender.documentId }
      : undefined;
  }

  const tabId = sender.tab?.id;
  if (typeof tabId !== 'number' || !Number.isSafeInteger(tabId) || tabId < 0) return undefined;
  if (typeof sender.frameId !== 'number' || !Number.isSafeInteger(sender.frameId) || sender.frameId < 0) return undefined;
  if (senderUrl.protocol !== 'https:' && senderUrl.protocol !== 'http:') return undefined;
  if (typeof sender.origin !== 'string') return undefined;

  const senderOrigin = parseUrl(sender.origin);
  if (!senderOrigin || sender.origin !== senderOrigin.origin || sender.origin !== senderUrl.origin) return undefined;

  const context = {
    kind: 'content' as const,
    tabId,
    frameId: sender.frameId,
    url: sender.url,
    origin: senderUrl.origin,
  };
  if (sender.documentId === undefined) return context;
  return isOpaqueDocumentId(sender.documentId)
    ? { ...context, documentId: sender.documentId }
    : undefined;
}

/** Decide whether an already-authenticated caller may invoke a runtime message verb. */
export function isMessageAllowed(type: string, context: RequestContext): boolean {
  if (REMOVED_LEGACY_VERBS.has(type)) return false;
  if (CONTENT_DOCUMENT_ONLY_VERBS.has(type)) {
    return context.kind === 'content'
      && Boolean(context.documentId)
      && CONTENT_SCRIPT_VERBS.has(type);
  }
  if (POPUP_DOCUMENT_ONLY_VERBS.has(type)) {
    if (context.kind !== 'extensionPage' || !context.documentId) return false;
    const url = parseUrl(context.url);
    return Boolean(url
      && !url.username
      && !url.password
      && serializedAuthority(url) === context.origin
      && url.pathname === POPUP_DOCUMENT_PATH);
  }
  if (context.kind === 'extensionPage') return true;
  return CONTENT_SCRIPT_VERBS.has(type)
    && (!TOP_FRAME_ONLY_CONTENT_VERBS.has(type) || context.frameId === 0);
}
