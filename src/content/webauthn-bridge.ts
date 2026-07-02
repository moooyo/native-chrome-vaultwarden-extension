// Isolated-world content script bridging the MAIN-world page-webauthn shim to the worker. It relays
// passkey assertion requests to the background service (which holds the unlocked vault and signs) and
// posts the result back to the page. Only assertion (get) is bridged; creation falls back to native.
//
// Security: before any assertion is signed, the user must (1) have a matching stored passkey and
// (2) explicitly consent via a dialog in a closed shadow root the page cannot reach. We never sign
// silently, and we report user-verification (UV) honestly from the RP's requirement + that consent.

import { sendRequest } from '../messaging/protocol.js';
import { confirmPasskeyUse } from './passkey-consent.js';

const REQUEST = 'vw-webauthn-request';
const RESPONSE = 'vw-webauthn-response';

interface AssertionPayload {
  rpId: string;
  origin: string;
  challenge: string;
  allowedCredentialIds: string[];
  /** RP's UserVerificationRequirement: 'required' | 'preferred' | 'discouraged'. */
  userVerification?: string;
}

window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  const data = event.data as { source?: string; id?: string; payload?: AssertionPayload };
  if (data?.source !== REQUEST || typeof data.id !== 'string' || !data.payload) return;
  void relay(data.id, data.payload);
});

function fallback(id: string): void {
  // Signals the MAIN-world shim to use the native authenticator (or fail the ceremony there).
  window.postMessage({ source: RESPONSE, id, error: true }, location.origin);
}

async function relay(id: string, payload: AssertionPayload): Promise<void> {
  try {
    if (!window.isSecureContext) return fallback(id);
    const origin = location.origin; // trust boundary: never use page-supplied origin

    // 1) Only engage when the vault actually holds a matching passkey (no signing, no key material).
    const probe = await sendRequest({
      type: 'vault.hasPasskey',
      rpId: payload.rpId,
      origin,
      allowedCredentialIds: payload.allowedCredentialIds,
    });
    if (!(probe.ok && probe.data && 'matches' in probe.data && probe.data.matches)) return fallback(id);

    // 2) Require explicit user consent before signing. Declining falls back to the native authenticator.
    if (!(await confirmPasskeyUse(payload.rpId))) return fallback(id);

    // 3) Report UV honestly: the unlocked vault + this explicit consent is the user verification, so
    //    UV is asserted only when the RP did not say 'discouraged'.
    const userVerified = payload.userVerification !== 'discouraged';
    const response = await sendRequest({
      type: 'vault.getPasskeyAssertion',
      rpId: payload.rpId,
      origin,
      challenge: payload.challenge,
      allowedCredentialIds: payload.allowedCredentialIds,
      userVerified,
    });
    if (response.ok && response.data && 'assertion' in response.data) {
      window.postMessage({ source: RESPONSE, id, assertion: response.data.assertion }, location.origin);
    } else {
      fallback(id);
    }
  } catch {
    fallback(id);
  }
}
