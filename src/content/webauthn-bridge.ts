// Isolated-world content script bridging the MAIN-world page-webauthn shim to the worker. It relays
// passkey assertion (get) AND registration (create) requests to the background service (which holds the
// unlocked vault, signs, and stores) and posts the result back to the page.
//
// Security: this bridge — not the MAIN world — is the trust boundary. It derives `origin` from its own
// `location.origin` (never the page-supplied payload) so the worker binds the ceremony to the real
// frame; the worker re-validates rpId against that origin via the Public Suffix List. Before any
// assertion is signed or passkey is created, the user must explicitly consent via a dialog in a closed
// shadow root the page cannot reach. We never sign/create silently, and report user-verification (UV)
// honestly from the RP's requirement + that consent.

import { sendRequest } from '../messaging/protocol.js';
import { confirmPasskeyUse, choosePasskeyLogin, choosePasskeyTarget } from './passkey-consent.js';

const REQUEST = 'vw-webauthn-request';
const RESPONSE = 'vw-webauthn-response';
const CREATE_REQUEST = 'vw-webauthn-create-request';
const CREATE_RESPONSE = 'vw-webauthn-create-response';

interface AssertionPayload {
  rpId: string;
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

window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  const data = event.data as { source?: string; id?: string; payload?: CreatePayload };
  if (data?.source !== CREATE_REQUEST || typeof data.id !== 'string' || !data.payload) return;
  void relayCreate(data.id, data.payload);
});

function fallback(id: string): void {
  // Signals the MAIN-world shim to use the native authenticator (or fail the ceremony there).
  window.postMessage({ source: RESPONSE, id, error: true }, location.origin);
}

async function relay(id: string, payload: AssertionPayload): Promise<void> {
  try {
    if (!window.isSecureContext) return fallback(id);
    const origin = location.origin; // trust boundary: never use page-supplied origin

    // 1) Gather every stored passkey matching this rpId (and the RP's allowCredentials, if any). No
    //    signing, no key material — just the public credentialId + display name/username per account.
    const candResp = await sendRequest({
      type: 'vault.getPasskeyCandidates',
      rpId: payload.rpId,
      origin,
      allowedCredentialIds: payload.allowedCredentialIds,
    });
    const candidates = candResp.ok && candResp.data && 'candidates' in candResp.data ? candResp.data.candidates : [];
    if (candidates.length === 0) return fallback(id); // no stored passkey → native authenticator

    // 2) One passkey → the simple yes/no consent. More than one → an account picker so the user chooses
    //    which login to sign in with. Declining / cancelling falls back to the native authenticator.
    let chosenCredentialId: string;
    if (candidates.length === 1) {
      if (!(await confirmPasskeyUse(payload.rpId))) return fallback(id);
      chosenCredentialId = candidates[0]!.credentialId;
    } else {
      const choice = await choosePasskeyLogin(payload.rpId, candidates);
      if ('cancelled' in choice) return fallback(id);
      chosenCredentialId = choice.credentialId;
    }

    // 3) Report UV honestly: the unlocked vault + this explicit consent is the user verification, so
    //    UV is asserted only when the RP did not say 'discouraged'.
    const userVerified = payload.userVerification !== 'discouraged';
    const response = await sendRequest({
      type: 'vault.getPasskeyAssertion',
      rpId: payload.rpId,
      origin,
      challenge: payload.challenge,
      allowedCredentialIds: [chosenCredentialId], // sign with exactly the chosen credential
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

interface CreatePayload {
  rpId: string; rpName?: string; userHandle?: string; userName?: string; userDisplayName?: string;
  challenge: string; excludeCredentialIds: string[]; userVerification?: string;
}

function createFallback(id: string): void {
  window.postMessage({ source: CREATE_RESPONSE, id, error: true }, location.origin);
}

async function relayCreate(id: string, payload: CreatePayload): Promise<void> {
  try {
    if (!window.isSecureContext) return createFallback(id);
    const origin = location.origin; // trust boundary
    // Best-effort duplicate avoidance: if the RP excludes a credential we already hold, defer to native.
    if (payload.excludeCredentialIds.length) {
      const probe = await sendRequest({ type: 'vault.hasPasskey', rpId: payload.rpId, origin, allowedCredentialIds: payload.excludeCredentialIds });
      if (probe.ok && probe.data && 'matches' in probe.data && probe.data.matches) return createFallback(id);
    }
    const targetsResp = await sendRequest({ type: 'vault.getPasskeyTargets', rpId: payload.rpId, origin });
    if (!(targetsResp.ok && targetsResp.data && 'targets' in targetsResp.data)) return createFallback(id);
    const choice = await choosePasskeyTarget(payload.rpId, targetsResp.data.targets);
    if ('cancelled' in choice) return createFallback(id);
    const userVerified = payload.userVerification !== 'discouraged';
    const resp = await sendRequest({
      type: 'vault.createPasskey',
      rpId: payload.rpId,
      challenge: payload.challenge,
      origin,
      userVerified,
      ...(payload.rpName ? { rpName: payload.rpName } : {}),
      ...(payload.userHandle ? { userHandle: payload.userHandle } : {}),
      ...(payload.userName ? { userName: payload.userName } : {}),
      ...(payload.userDisplayName ? { userDisplayName: payload.userDisplayName } : {}),
      ...(choice.targetCipherId ? { targetCipherId: choice.targetCipherId } : {}),
    });
    if (resp.ok && resp.data && 'registration' in resp.data) {
      window.postMessage({ source: CREATE_RESPONSE, id, registration: resp.data.registration }, location.origin);
    } else {
      createFallback(id);
    }
  } catch {
    createFallback(id);
  }
}
