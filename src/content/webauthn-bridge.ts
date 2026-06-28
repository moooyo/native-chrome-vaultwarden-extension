// Isolated-world content script bridging the MAIN-world page-webauthn shim to the worker. It relays
// passkey assertion requests to the background service (which holds the unlocked vault and signs)
// and posts the result back to the page. Only assertion (get) is bridged; creation falls back to native.

import { sendRequest } from '../messaging/protocol.js';

const REQUEST = 'vw-webauthn-request';
const RESPONSE = 'vw-webauthn-response';

interface AssertionPayload {
  rpId: string;
  origin: string;
  challenge: string;
  allowedCredentialIds: string[];
}

window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  const data = event.data as { source?: string; id?: string; payload?: AssertionPayload };
  if (data?.source !== REQUEST || typeof data.id !== 'string' || !data.payload) return;
  void relay(data.id, data.payload);
});

async function relay(id: string, payload: AssertionPayload): Promise<void> {
  try {
    const response = await sendRequest({
      type: 'vault.getPasskeyAssertion',
      rpId: payload.rpId,
      origin: payload.origin,
      challenge: payload.challenge,
      allowedCredentialIds: payload.allowedCredentialIds,
    });
    if (response.ok && response.data && 'assertion' in response.data) {
      window.postMessage({ source: RESPONSE, id, assertion: response.data.assertion }, location.origin);
    } else {
      window.postMessage({ source: RESPONSE, id, error: true }, location.origin);
    }
  } catch {
    window.postMessage({ source: RESPONSE, id, error: true }, location.origin);
  }
}
