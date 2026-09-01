import type {
  CanonicalWebsitePasskeyRequest,
  WebsitePasskeyAcceptedMessage,
  WebsitePasskeyOutcomeMessage,
  WebsitePasskeyPreflightOutcomeMessage,
} from '../messaging/website-passkey-port.js';

// These fixed strings route same-document messages; they are not authentication tokens. The
// background Port sender and its document, origin, policy, session, and cache leases remain the
// authorization boundary because page scripts can observe and forge window messages.

export const WEBSITE_PASSKEY_WINDOW_VERSION = 1 as const;
export const WEBSITE_PASSKEY_PAGE_SOURCE = 'miyu-website-passkey-page-v1';
export const WEBSITE_PASSKEY_BRIDGE_SOURCE = 'miyu-website-passkey-bridge-v1';

export interface WebsitePasskeyPageBeginMessage {
  readonly source: typeof WEBSITE_PASSKEY_PAGE_SOURCE;
  readonly version: typeof WEBSITE_PASSKEY_WINDOW_VERSION;
  readonly type: 'begin';
  readonly request: CanonicalWebsitePasskeyRequest;
}

export interface WebsitePasskeyPageCancelMessage {
  readonly source: typeof WEBSITE_PASSKEY_PAGE_SOURCE;
  readonly version: typeof WEBSITE_PASSKEY_WINDOW_VERSION;
  readonly type: 'cancel';
  readonly bridgeRequestId: string;
  /** True when the RP promise is already rejected and no terminal outcome should be redelivered. */
  readonly settled: boolean;
}

export interface WebsitePasskeyPageDeliveredMessage {
  readonly source: typeof WEBSITE_PASSKEY_PAGE_SOURCE;
  readonly version: typeof WEBSITE_PASSKEY_WINDOW_VERSION;
  readonly type: 'delivered';
  readonly ceremonyId: string;
  readonly bridgeRequestId: string;
  readonly outcomeId: string;
}

export type WebsitePasskeyPageMessage =
  | WebsitePasskeyPageBeginMessage
  | WebsitePasskeyPageCancelMessage
  | WebsitePasskeyPageDeliveredMessage;

export interface WebsitePasskeyBridgeConfigMessage {
  readonly source: typeof WEBSITE_PASSKEY_BRIDGE_SOURCE;
  readonly version: typeof WEBSITE_PASSKEY_WINDOW_VERSION;
  readonly type: 'config';
  readonly enabled: boolean;
}

export type WebsitePasskeyBridgeAcceptedMessage = WebsitePasskeyAcceptedMessage & {
  readonly source: typeof WEBSITE_PASSKEY_BRIDGE_SOURCE;
};

export type WebsitePasskeyBridgePreflightOutcomeMessage = WebsitePasskeyPreflightOutcomeMessage & {
  readonly source: typeof WEBSITE_PASSKEY_BRIDGE_SOURCE;
};

export type WebsitePasskeyBridgeOutcomeMessage = WebsitePasskeyOutcomeMessage & {
  readonly source: typeof WEBSITE_PASSKEY_BRIDGE_SOURCE;
};

export type WebsitePasskeyBridgeMessage =
  | WebsitePasskeyBridgeConfigMessage
  | WebsitePasskeyBridgePreflightOutcomeMessage
  | WebsitePasskeyBridgeAcceptedMessage
  | WebsitePasskeyBridgeOutcomeMessage;
