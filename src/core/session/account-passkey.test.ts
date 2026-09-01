import { describe, expect, it } from 'vitest';
import {
  accountPasskeyConnectorUrl,
  parseAccountPasskeyConnectorContext,
} from './account-passkey.js';

const SERVER = 'https://vault.example/base/';

function rawConnector() {
  return {
    tabId: 7,
    frameId: 0,
    documentId: 'document-a',
    url: accountPasskeyConnectorUrl(SERVER),
  };
}

describe('account passkey connector context', () => {
  it('is idempotent over its own origin-bearing parsed output', () => {
    const parsed = parseAccountPasskeyConnectorContext(rawConnector(), SERVER);

    expect(parseAccountPasskeyConnectorContext(parsed, SERVER)).toEqual(parsed);
  });

  it('rejects a caller-supplied origin unless it is the exact URL-derived origin', () => {
    expect(() => parseAccountPasskeyConnectorContext({
      ...rawConnector(),
      origin: 'https://other.example',
    }, SERVER)).toThrow(/origin/u);
    expect(() => parseAccountPasskeyConnectorContext({
      ...rawConnector(),
      origin: 'https://vault.example',
      extra: true,
    }, SERVER)).toThrow(/unsupported fields/u);
  });
});
