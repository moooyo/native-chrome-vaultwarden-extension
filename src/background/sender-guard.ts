// Trust boundary for runtime messages. The background router exposes privileged verbs (vault.export,
// auth.unlock, settings.*, …) that must not be reachable from a content script injected into every
// http(s) frame — only from the extension's own pages (popup / options / receive). A content script may
// send only the autofill + passkey verbs it actually needs. Defense-in-depth: there is no
// externally_connectable today, so this guards against a future content-script relay bug or compromise
// inheriting the whole vault rather than the narrow autofill surface.

export interface MessageSenderInfo {
  id?: string;
  url?: string;
  tab?: unknown;
}

/** Verbs a content script (running in a web page) is permitted to send. */
function isContentScriptVerb(type: string): boolean {
  return type.startsWith('autofill.')
    || type === 'vault.createPasskey'
    || type === 'vault.hasPasskey'
    || type.startsWith('vault.getPasskey');
}

/**
 * Decide whether a runtime message of `type` from `sender` may be handled.
 * - No sender → internal dispatch (background self-call): trusted.
 * - A different extension id → rejected.
 * - The extension's own pages (sender.url under `extensionOrigin`) → full surface. NOTE: the options
 *   page opens in a tab (open_in_tab), so we key on the extension-origin URL, not sender.tab.
 * - Anything else (a content script, or an unrecognized context) → only the autofill/passkey verbs.
 */
export function isMessageAllowed(
  type: string,
  sender: MessageSenderInfo | undefined,
  extensionOrigin: string,
  extensionId: string,
): boolean {
  if (!sender) return true;
  if (sender.id && sender.id !== extensionId) return false;
  const fromOwnPage = typeof sender.url === 'string' && sender.url.startsWith(extensionOrigin);
  if (fromOwnPage) return true;
  return isContentScriptVerb(type);
}
